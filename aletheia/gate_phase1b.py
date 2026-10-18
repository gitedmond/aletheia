"""Fail-closed Phase 1B gate over hash-bound experimental evidence."""

import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, cast

from aletheia.grade.context import GradingContext
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import REGISTRY, RunManifest
from aletheia.schema.taxonomy import Taxonomy
from aletheia.verify.engine import DEFAULT_PACK_DIRECTORY

# Human labels are evidence, not an engineering review that delegation can replace.
REVIEWS = {
    "T40",
    "F8",
    "T44",
    "F9",
    "F11",
    "F17",
    "F10",
    "F13",
    "F12",
    "T55",
    "F20",
    "F19",
    "F14",
    "T58",
    "F18",
    "F15",
    "T62",
    "F16",
    "T65",
    "T68",
}


def _package_hash() -> str:
    package = Path(__file__).parent
    return content_hash(
        {p.relative_to(package).as_posix(): file_hash(p) for p in sorted(package.rglob("*.py"))}
    )


def package_hash() -> str:
    return _package_hash()


def validate_plan(rows: list[dict[str, Any]]) -> dict[str, Counter[str]]:
    """Validate the Cartesian experiment, not just its cardinality."""
    programs: dict[str, set[str]] = {"dev": set(), "heldout": set()}
    configs: dict[str, Counter[str]] = {}
    identities: set[tuple[str, str, str, str, int]] = set()
    runs: set[str] = set()
    for row in rows:
        split, program, variant, source, sample = (
            row[key] for key in ("split", "program", "variant", "source", "sample")
        )
        if split not in programs or not isinstance(program, str) or not program:
            raise ValueError("invalid split or program")
        if variant not in {"baseline", "hardened"} or type(sample) is not int:
            raise ValueError("invalid variant or sample")
        identity = (split, program, variant, source, sample)
        if identity in identities:
            raise ValueError("duplicate experiment slot")
        identities.add(identity)
        programs[split].add(program)
        if row["status"] == "skipped":
            if not row.get("reason") or row.get("runs"):
                raise ValueError("skipped slot needs a reason and no acquired runs")
        elif row["status"] != "executed" or not row.get("runs"):
            raise ValueError("slot must be executed with runs or explicitly skipped")
        for run in row.get("runs", []):
            if not isinstance(run, str) or not run or run in runs:
                raise ValueError("run identity reused across experiment slots")
            runs.add(run)
        if source.startswith("agent:"):
            counts = configs.setdefault(source, Counter())
            counts["planned"] += 1
            counts["infrastructure_failures"] += row.get("reason") in {
                "provider_unavailable",
                "ghidra_crash",
                "sandbox_error",
                "internal",
            }
            counts["model_protocol"] += row.get("reason") == "model_protocol"
    if (
        len(programs["dev"]) != 12
        or len(programs["heldout"]) != 8
        or programs["dev"] & programs["heldout"]
        or len(configs) != 3
    ):
        raise ValueError("wrong program split or agent configuration cohort")
    expected: set[tuple[str, str, str, str, int]] = set()
    for split, names in programs.items():
        for program in names:
            for variant in ("baseline", "hardened"):
                expected.update(
                    (split, program, variant, source, 0)
                    for source in ("scripted", "capa", "findcrypt")
                )
                expected.update(
                    (split, program, variant, source, sample)
                    for source in configs
                    for sample in range(3 if variant == "baseline" else 1)
                )
    if identities != expected:
        raise ValueError("experiment slots differ from the required Cartesian cohort")
    if any(c["infrastructure_failures"] / c["planned"] >= 0.05 for c in configs.values()):
        raise ValueError("infrastructure failure rate reaches 5 percent")
    return configs


def evaluate(benchmark: Benchmark) -> dict[str, Any]:
    """A missing/stale receipt fails its criterion; no threshold is silently waived."""
    root = benchmark.root / "phase1b"
    criteria: dict[str, dict[str, Any]] = {}
    evidence: dict[str, Any]
    try:
        evidence = json.loads((root / "evidence.json").read_bytes())
        if evidence["package_source_hash"] != _package_hash():
            raise ValueError("evidence source scope changed")
    except (OSError, ValueError, KeyError, TypeError):
        evidence = {}

    def path(name: str) -> Path:
        record: Any = evidence.get("receipts", {}).get(name)
        if not isinstance(record, dict):
            raise ValueError("missing evidence: " + name)
        record = cast(dict[str, Any], record)
        target = (root / record["path"]).resolve()
        if not target.is_relative_to(root.resolve()) or file_hash(target) != record["sha256"]:
            raise ValueError("changed or invalid evidence: " + name)
        return target

    def receipt(name: str) -> Any:
        return json.loads(path(name).read_bytes())

    def check(key: str, function: Any) -> None:
        try:
            passed, details = function()
            criteria[key] = {"passed": bool(passed), "details": details}
        except (OSError, ValueError, KeyError, TypeError, AttributeError, ET.ParseError):
            criteria[key] = {
                "passed": False,
                "details": "Missing, stale or invalid required evidence",
            }

    def tests(name: str, fragment: str) -> bool:
        cases = list(ET.parse(path(name)).getroot().iter("testcase"))
        selected = [c for c in cases if fragment in c.get("classname", "") + c.get("name", "")]
        return bool(selected) and all(
            not any(c.find(tag) is not None for tag in ("failure", "error", "skipped"))
            for c in selected
        )

    def builds():
        rows = receipt("builds")["builds"]
        programs = Counter(row["program"] for row in rows)
        pairs = {(row["program"], row["variant"]) for row in rows}
        clean = all(
            row["first_sha256"] == row["second_sha256"]
            and len(row["first_sha256"]) == 64
            and not row["leakage_hits"]
            for row in rows
        )
        history = receipt("history")
        return (
            len(rows) == len(pairs) == 40
            and len(programs) == 20
            and set(programs.values()) == {2}
            and clean
            and history["status"] == "clean"
            and history["scanned_commits"] > 0
        ), {"builds": len(rows), "programs": len(programs)}

    def scripted():
        data = receipt("scripted")
        rows = data["heldout_algorithm_identity"]
        total = sum(rows.values())
        decisive = rows.get("VERIFIED", 0) + rows.get("CONTRADICTED", 0)
        return total > 0 and decisive / total >= 0.5, {
            "claims": total,
            "decisive": decisive,
            "threshold": 0.5,
        }

    def alarms():
        data = receipt("scripted")
        correct = data["correct_e2_algorithm_identity"]
        rows = [
            row
            for row in receipt("selftest")["cases"]
            if ":reference:" in row["name"]
            and row["expected"] == "VERIFIED"
            and row["family"] in REGISTRY
        ]
        n = correct["total"] + len(rows)
        false = correct["contradicted"] + sum(row["actual"] == "CONTRADICTED" for row in rows)
        return n > 0 and false / n <= 0.01, {
            "correct_e2": n,
            "false_alarms": false,
            "threshold": 0.01,
        }

    def coverage():
        row = receipt("coverage")
        n, covered = row["scorable_functions"], row["decidable_functions"]
        return row[
            "program_count"
        ] == 20 and n > 0 and 0 <= covered <= n and covered / n >= 0.4 and row[
            "variant"
        ] == "baseline" and row["strength"] == "E2", {
            "scorable": n,
            "potential_e2": covered,
            "threshold": 0.4,
        }

    def selftest():
        row = receipt("selftest")
        installed = {p.stem for p in DEFAULT_PACK_DIRECTORY.glob("*.yaml")}
        cases = row["cases"]
        families = {case["family"] for case in cases if case.get("passed") is True}
        composites = {
            family
            for family in ("md5", "sha1", "sha256")
            if any(
                "composite" in c["name"] and c.get("passed") and family in c["name"] for c in cases
            )
        }
        return row["status"] == "ok" and bool(cases) and all(
            c["passed"] for c in cases
        ) and installed <= families and len(composites) == 3, {
            "installed_pack_files": len(installed),
            "composite_families": len(composites),
            "cases": len(cases),
        }

    def agreement():
        context = GradingContext.model_validate(receipt("agreement"))
        nodes = {leaf.split(".")[0] for leaf in Taxonomy.bundled().leaves}
        # X7 reports agreement; the annotation amendment keeps human validation separate.
        return set(context.taxonomy_kappa) == nodes, {
            "method": context.method,
            "human_validated": context.human_validated,
            "nodes": len(context.taxonomy_kappa),
            "required_nodes": len(nodes),
            "undefined_nodes": sorted(
                node for node, value in context.taxonomy_kappa.items() if value is None
            ),
        }

    def plan():
        rows = receipt("plan")["slots"]
        configs = validate_plan(rows)
        return True, {"slots": len(rows), "expected": 360, "configurations": configs}

    def replays():
        slots = receipt("plan")["slots"]
        planned = {run for row in slots for run in row.get("runs", [])}
        agent_runs = {
            run
            for row in slots
            if row["source"].startswith("agent:")
            for run in row.get("runs", [])
        }
        rows = receipt("replays")["runs"]
        return bool(planned) and set(rows) == planned and all(
            row["exit_code"] == 0
            and (
                run not in agent_runs
                or row.get("agent_replay") is True
                or (
                    isinstance(row.get("agent_replay"), dict)
                    and row["agent_replay"].get("status") == "passed"
                )
            )
            for run, row in rows.items()
        ), {"planned_runs": len(planned), "replayed_runs": len(rows)}

    def fit():
        row = receipt("fit")
        dev = set(row["input_run_ids"])
        manifests = receipt("fit_manifests")
        report = receipt("report")
        return bool(dev) and set(manifests) == dev and all(
            RunManifest.model_validate(m).source_config.get("split") == "dev"
            for m in manifests.values()
        ) and report["split"] == "heldout" and report["calibration_sha256"] == row[
            "calibration_hash"
        ] and report["likelihoods_sha256"] == row["likelihoods_hash"], {
            "dev_runs": len(dev),
            "headline_split": report["split"],
        }

    def exposures():
        rows = receipt("exposures")["counts"]
        return tests("guard_tests", "heldout") and all(0 <= row["count"] < 30 for row in rows), {
            "hosted_binary_config_pairs": len(rows),
            "maximum": max((r["count"] for r in rows), default=0),
        }

    def report():
        row = receipt("report")
        populations = row["populations"]
        return row["split"] == "heldout" and row["cluster_count"] == 8 and {
            "RQ1",
            "RQ5",
            "RQ9",
        } <= set(row["sections"]) and bool(populations) and all(
            bool(p["intervals"]) for p in populations
        ), {"clusters": row["cluster_count"], "populations": len(populations)}

    def reviews():
        row = receipt("reviews")
        dispositions = row["dispositions"]
        return bool(row["authorization"]) and REVIEWS <= set(dispositions) and all(
            d["decision"] == "accepted"
            and d["authority"] in {"author", "author_delegated"}
            and d["references"]
            and len(d["scope_sha256"]) == 64
            for d in dispositions.values()
        ), {"required": len(REVIEWS), "recorded": len(dispositions)}

    check("X1", builds)
    check(
        "X2",
        lambda: (
            tests("golden_tests", "golden") and tests("golden_tests", "abi"),
            "Ground-truth/ABI golden tests",
        ),
    )
    check("X3", scripted)
    check("X4", alarms)
    check("X5", coverage)
    check("X6", selftest)
    check("X7", agreement)
    check("X8", plan)
    check("X9", replays)
    check("X10", fit)
    check("X11", lambda: (tests("mcp_tests", "mcp"), "MCP contracts"))
    check("X12", exposures)
    check("X13", report)
    check("X14", reviews)
    result = {
        "phase": "1b",
        "status": "passed" if all(c["passed"] for c in criteria.values()) else "failed",
        "criteria": criteria,
    }
    write_json(root / "gate.json", result)
    return result
