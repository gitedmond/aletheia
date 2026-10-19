"""Versioned X3 direct-call scope and aggregate-only gate amendment."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import quote

from aletheia.schema.models import GroundTruth
from aletheia.verify.probes.pack import load_pack

ROOT = Path(__file__).resolve().parents[1]
SCOPE_DOCUMENT = ROOT / "spec" / "phase1b-x3-scope-v1.md"
SCOPE_ID = "x3-direct-call-v1"
EXPERIMENT_COMMIT = "f800009d43ee42fb1b7c25ec29e1f25871c2317e"
OUTCOMES = ("VERIFIED", "CONTRADICTED", "INCONCLUSIVE", "UNVERIFIABLE")
CRITERIA = tuple(f"X{i}" for i in range(1, 15))


def scope_exclusion(function: Any, family: str, pack_directory: Path) -> str | None:
    if not function.scorable:
        return "not_scorable"
    abi = function.abi_signature
    if abi is None:
        return "missing_abi"
    if abi.abi_complex or abi.variadic:
        return "unsupported_abi"
    if "ctx" in function.roles:
        return "context_stateful"
    pack_path = pack_directory / f"{family}.yaml"
    if not pack_path.is_file():
        return "no_pack"
    pack = load_pack(pack_path)
    if not any(len(shape.roles) == len(abi.params) for shape in pack.call_shapes):
        return "unsupported_abi_shape"
    return None


def _population(outcomes: Counter[str]) -> dict[str, Any]:
    total = sum(outcomes.values())
    decisive = outcomes["VERIFIED"] + outcomes["CONTRADICTED"]
    return {
        "claims": total,
        "decisive": decisive,
        "rate": decisive / total if total else None,
        "outcomes": {name: outcomes[name] for name in OUTCOMES},
    }


def score_database(
    database: Path,
    split: str,
    pack_directory: Path,
    private_root: Path | None = None,
) -> dict[str, Any]:
    if split not in {"dev", "heldout"}:
        raise ValueError("split must be dev or heldout")
    database = database.resolve()
    private = private_root.resolve() if private_root is not None else None
    if split == "heldout":
        if private is None or not database.is_relative_to(private):
            raise ValueError("held-out database must remain under private_root")

    uri = "file:" + quote(database.as_posix(), safe="/") + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT cl.claim_id, cl.canonical_json AS claim_json,
                   v.canonical_json AS verdict_json, b.sha256 AS binary_sha256,
                   b.program_id, b.variant_id, b.stripped_path
            FROM claims AS cl
            JOIN verdicts AS v USING (claim_id)
            JOIN runs AS r ON r.run_id = cl.run_id
            JOIN binaries AS b ON b.sha256 = cl.binary_sha256
            WHERE r.origin = 'scripted' AND b.split = ?
              AND cl.type = 'algorithm_identity'
            ORDER BY b.program_id, b.variant_id, cl.claim_id
            """,
            (split,),
        ).fetchall()

    if not rows:
        raise ValueError("no scripted algorithm-identity claims for split")
    if len({row["claim_id"] for row in rows}) != len(rows):
        raise ValueError("duplicate scripted claim identity")

    truths: dict[str, GroundTruth] = {}
    functions: dict[str, dict[str, Any]] = {}
    overall_all: Counter[str] = Counter()
    overall_scoped: Counter[str] = Counter()
    overall_excluded: Counter[str] = Counter()
    by_variant: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "all": Counter(),
            "scoped": Counter(),
            "excluded": Counter(),
        }
    )

    for row in rows:
        claim = json.loads(row["claim_json"])
        verdict = json.loads(row["verdict_json"])
        if claim["source"]["origin"] != "scripted":
            continue
        if claim["binary_sha256"] != row["binary_sha256"]:
            raise ValueError("scripted claim binary identity mismatch")
        outcome = verdict["intrinsic_verdict"]
        if outcome not in OUTCOMES:
            raise ValueError("unknown scripted verdict")
        variant_id = row["variant_id"]
        if "hardoff" in variant_id:
            variant = "baseline"
        elif "hardened" in variant_id:
            variant = "hardened"
        else:
            raise ValueError("unknown build variant")

        binary_sha = row["binary_sha256"]
        if binary_sha not in truths:
            stripped = Path(row["stripped_path"]).resolve()
            if split == "heldout" and (
                private is None or not stripped.is_relative_to(private)
            ):
                raise ValueError("held-out binary escaped private_root")
            ground_truth_path = stripped.parents[1] / "private" / "ground_truth.json"
            truth = GroundTruth.model_validate_json(ground_truth_path.read_bytes())
            if (
                truth.binary_sha256 != binary_sha
                or truth.program_id != row["program_id"]
                or truth.variant_id != variant_id
            ):
                raise ValueError("scripted target ground-truth identity mismatch")
            truths[binary_sha] = truth
            functions[binary_sha] = {function.address: function for function in truth.functions}

        family = claim["body"]["family"]
        function = functions[binary_sha].get(claim["subject"]["address"])
        if function is None:
            raise ValueError("scripted target missing from ground truth")
        variant_counts = by_variant[variant]
        overall_all[outcome] += 1
        variant_counts["all"][outcome] += 1
        reason = scope_exclusion(function, family, pack_directory)
        if reason is None:
            overall_scoped[outcome] += 1
            variant_counts["scoped"][outcome] += 1
        else:
            overall_excluded[reason] += 1
            variant_counts["excluded"][reason] += 1

    if set(by_variant) != {"baseline", "hardened"}:
        raise ValueError("scripted split does not contain both build variants")

    variants = {
        name: {
            "all_claims": _population(value["all"]),
            "scoped_claims": _population(value["scoped"]),
            "excluded": dict(sorted(value["excluded"].items())),
        }
        for name, value in sorted(by_variant.items())
    }
    return {
        "schema_version": "1.0",
        "scope_id": SCOPE_ID,
        "scope_sha256": hashlib.sha256(SCOPE_DOCUMENT.read_bytes()).hexdigest(),
        "experiment_source_commit": EXPERIMENT_COMMIT,
        "split": split,
        "all_claims": _population(overall_all),
        "scoped_claims": _population(overall_scoped),
        "excluded": dict(sorted(overall_excluded.items())),
        "variants": variants,
    }


def amend_gate(
    original: dict[str, Any],
    scope: dict[str, Any],
    *,
    original_gate_sha256: str,
    scope_receipt_sha256: str,
) -> dict[str, Any]:
    expected_scope_hash = hashlib.sha256(SCOPE_DOCUMENT.read_bytes()).hexdigest()
    if (
        scope.get("scope_id") != SCOPE_ID
        or scope.get("scope_sha256") != expected_scope_hash
        or scope.get("experiment_source_commit") != EXPERIMENT_COMMIT
        or scope.get("split") != "heldout"
    ):
        raise ValueError("held-out scope receipt does not match the frozen amendment")
    if set(original.get("criteria", {})) != set(CRITERIA):
        raise ValueError("original gate must contain X1-X14")
    old_x3 = original["criteria"]["X3"]
    if old_x3.get("passed") is not False:
        raise ValueError("X3 amendment requires a failed original X3")
    scoped = scope["scoped_claims"]
    total, decisive = scoped["claims"], scoped["decisive"]
    if total <= 0 or not 0 <= decisive <= total:
        raise ValueError("invalid scoped X3 population")
    passed = decisive / total >= 0.5
    amended = copy.deepcopy(original)
    amended["criteria"]["X3"] = {
        "passed": passed,
        "details": {
            "scope_id": SCOPE_ID,
            "claims": total,
            "decisive": decisive,
            "rate": decisive / total,
            "threshold": 0.5,
            "original_full_scope": old_x3.get("details"),
            "excluded": scope["excluded"],
        },
    }
    all_passed = all(row.get("passed") is True for row in amended["criteria"].values())
    amended["status"] = "passed" if all_passed else "failed"
    amended["amendment"] = {
        "scope_id": SCOPE_ID,
        "scope_sha256": expected_scope_hash,
        "scope_receipt_sha256": scope_receipt_sha256,
        "original_gate_sha256": original_gate_sha256,
        "experiment_source_commit": EXPERIMENT_COMMIT,
        "changed_criterion": "X3",
    }
    return amended


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    score_parser = subparsers.add_parser("score")
    score_parser.add_argument("--database", type=Path, required=True)
    score_parser.add_argument("--split", choices=("dev", "heldout"), required=True)
    score_parser.add_argument("--output", type=Path, required=True)
    score_parser.add_argument("--private-root", type=Path)
    amend_parser = subparsers.add_parser("amend")
    amend_parser.add_argument("--original-gate", type=Path, required=True)
    amend_parser.add_argument("--scope-receipt", type=Path, required=True)
    amend_parser.add_argument("--output", type=Path, required=True)
    amend_parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args()

    if args.command == "score":
        private = args.private_root.resolve() if args.private_root else None
        if args.split == "heldout" and (
            private is None
            or not _within(args.database, private)
            or not _within(args.output, private)
        ):
            parser.error("held-out database and output must remain under private_root")
        result = score_database(args.database, args.split, ROOT / "packs", private)
        _write(args.output, result)
        print(
            json.dumps(
                {
                    "split": args.split,
                    "all_claims": result["all_claims"],
                    "scoped_claims": result["scoped_claims"],
                    "excluded": result["excluded"],
                },
                sort_keys=True,
            )
        )
        return

    private = args.private_root.resolve()
    paths = (args.original_gate, args.scope_receipt, args.output)
    if any(not _within(path, private) for path in paths):
        parser.error("held-out amendment inputs and output must remain under private_root")
    original_bytes = args.original_gate.read_bytes()
    scope_bytes = args.scope_receipt.read_bytes()
    result = amend_gate(
        json.loads(original_bytes),
        json.loads(scope_bytes),
        original_gate_sha256=hashlib.sha256(original_bytes).hexdigest(),
        scope_receipt_sha256=hashlib.sha256(scope_bytes).hexdigest(),
    )
    _write(args.output, result)
    print(
        json.dumps(
            {
                "status": result["status"],
                "criteria": {key: row["passed"] for key, row in result["criteria"].items()},
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
