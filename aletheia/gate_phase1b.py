"""Fail-closed Phase 1B gate over hash-bound experimental evidence."""

import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, cast

from aletheia.grade.context import GradingContext
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import RunManifest
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
            if ":reference:" in row["name"] and row["expected"] == "VERIFIED"
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
        return context.human_validated and bool(context.taxonomy_kappa) and all(
            v is not None for v in context.taxonomy_kappa.values()
        ), {
            "method": context.method,
            "human_validated": context.human_validated,
            "nodes": len(context.taxonomy_kappa),
        }

    def plan():
        rows = receipt("plan")["slots"]
        identities = {
            content_hash({k: r[k] for k in ("split", "program", "variant", "source", "sample")})
            for r in rows
        }
        configs: dict[str, Counter[str]] = {}
        for row in rows:
            if row["status"] == "skipped":
                if not row.get("reason"):
                    raise ValueError("skip requires reason")
            elif not row.get("runs"):
                raise ValueError("executed slot requires run IDs")
            if row["source"].startswith("agent:"):
                counts = configs.setdefault(row["source"], Counter())
                counts["planned"] += 1
                counts["infrastructure_failures"] += row.get("reason") in {
                    "provider_unavailable",
                    "ghidra_crash",
                    "sandbox_error",
                    "internal",
                }
                counts["model_protocol"] += row.get("reason") == "model_protocol"
        # 20 programs x (3 local configs x (3 baseline + 1 hardened) + 3 other sources x 2).
        expected = 20 * (3 * 4 + 3 * 2)
        return len(rows) == len(identities) == expected and len(configs) == 3 and all(
            c["planned"] == 80 and c["infrastructure_failures"] / c["planned"] < 0.05
            for c in configs.values()
        ), {"slots": len(rows), "expected": expected, "configurations": configs}

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
