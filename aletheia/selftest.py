"""Trusted calibration driver. Only stripped binaries and public Ghidra facts reach probes."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Literal, cast

import yaml
from pydantic import Field, JsonValue, TypeAdapter

from aletheia.analysis.ghidra_session import GhidraAnalysis, GhidraAnalysisCache
from aletheia.config import Budgets, Config
from aletheia.corpus.build import FLAGS, Variant, build_program, check_no_symlinks
from aletheia.sandbox.policy import container_args
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.canonical import content_hash
from aletheia.schema.models import (
    Address,
    Claim,
    ClaimSubmission,
    Outcome,
    Record,
    Sha256,
    Strict,
)
from aletheia.sources.base import BinaryRef
from aletheia.store.artifacts import ArtifactStore
from aletheia.verify.probes.client import ProbeClient
from aletheia.verify.probes.pack import SHAPES, HexInput, Identifier, Pack, load_pack
from aletheia.verify.static.arity import infer_arity
from aletheia.verify.static.edges import verify_edges


class Reference(Strict):
    name: Identifier
    variant: str
    call_shape: Literal["seed_buf_len", "buf_len", "cstr", "buf_len_out"]


class NearMiss(Reference):
    witness_hex: HexInput
    matches_variant: str | None = None


class ConservativeCase(Strict):
    name: Identifier
    family: str | None = None
    variant: str | None
    expected: Outcome
    reason: str
    instructions_per_invocation: int | None = Field(default=None, gt=0)


class Fixture(Record):
    family: str
    binary_sha256: Sha256
    references: list[Reference] = Field(min_length=1)
    near_miss: list[NearMiss] = Field(min_length=1)
    conservative_cases: list[ConservativeCase] = Field(
        default_factory=lambda: list[ConservativeCase]()
    )


def build_fixture(
    family: str, cfg: Config, root: Path
) -> tuple[BinaryRef, dict[str, Address], Fixture]:
    source = Path("tests/fixtures/near_miss") / family
    check_no_symlinks(source)
    fixture = Fixture.model_validate_json((source / "cases.json").read_bytes())
    if fixture.family != family:
        raise ValueError("calibration fixture family mismatch")
    work = Path(tempfile.mkdtemp(prefix=family + "-", dir=root))
    inputs, outputs = work / "private/in", work / "private/out"
    (inputs / family).mkdir(parents=True)
    outputs.mkdir()
    shutil.copyfile(source / "calibration.c", inputs / family / "calibration.c")
    script = """
import hashlib,json,subprocess
from pathlib import Path
source=next(Path('/job/in').glob('*/calibration.c'))
binary='/job/out/unstripped.bin'
subprocess.run(['clang',*FLAGS,str(source),'-o',binary],check=True)
text=subprocess.check_output(['llvm-nm','--defined-only',binary],text=True)
symbols={line.split()[2]:f'0x{int(line.split()[0],16):08x}' for line in text.splitlines()
         if len(line.split())==3}
Path('/job/out/symbols.json').write_text(json.dumps(symbols,sort_keys=True))
subprocess.run(['llvm-strip','--strip-all',binary,'-o','/job/out/public.bin'],check=True)
""".replace("FLAGS", repr(list(FLAGS)))
    command = [
        "docker",
        "run",
        "--rm",
        *container_args(cfg.sandbox, inputs, outputs, os.getuid(), os.getgid()),
        "--entrypoint",
        "python",
        cfg.sandbox.image_build,
        "-c",
        script,
    ]
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=cfg.sandbox.wall_timeout_s
    )
    if result.returncode:
        raise RuntimeError("selftest fixture compilation failed: " + result.stderr[-1500:])
    payload = (outputs / "public.bin").read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != fixture.binary_sha256:
        raise ValueError(
            "calibration fixture differs from its reviewed reproducible hash: " + family
        )
    public = work / "stripped" / (digest + ".bin")
    public.parent.mkdir()
    public.write_bytes(payload)
    symbols = TypeAdapter(dict[str, Address]).validate_json((outputs / "symbols.json").read_bytes())
    return BinaryRef(digest, public, Variant(image=cfg.sandbox.image_build).id), symbols, fixture


def _claim(binary: BinaryRef, address: Address, family: str, variant: str | None) -> Claim:
    return Claim.intake(
        ClaimSubmission.model_validate(
            {
                "run_id": "r_" + "2" * 16,
                "source": {"origin": "human", "source_id": "human:selftest"},
                "binary_sha256": binary.binary_sha256,
                "subject": {"address": address},
                "type": "algorithm_identity",
                "body": {"family": family, "variant": variant},
                "confidence": 1.0,
                "confidence_source": "stated",
            }
        )
    )


def static_cases(cfg: Config, root: Path, cache: GhidraAnalysisCache) -> list[dict[str, JsonValue]]:
    arity = yaml.safe_load(Path("tests/golden/arity.yaml").read_text())
    edges = json.loads(Path("tests/golden/static-edges.json").read_bytes())
    rows: list[dict[str, JsonValue]] = []
    for program in arity["programs"]:
        built = build_program(
            Path("corpus/tierA") / program["program"],
            Variant(image=cfg.sandbox.image_build, output_root=root / "programs"),
        )
        if built.binary_sha256 != program["binary_sha256"]:
            raise ValueError("arity selftest binary/golden identity mismatch")
        binary = BinaryRef(built.binary_sha256, built.stripped, built.variant_id)
        subjects = [case["address"] for case in program["cases"]]
        if program["program"] == "crc32tool":
            subjects += [case["subject"] for case in edges["cases"]]
        analysis = cache.analyze(binary, Path(cfg.ghidra.analysis_options), subjects=subjects)
        for case in program["cases"]:
            actual = infer_arity(case["address"], analysis).model_dump(mode="json")
            expected = {key: case[key] for key in ("arity", "decisive", "reason")}
            rows.append(
                {
                    "name": "static.arity:" + program["program"] + ":" + case["name"],
                    "family": "static",
                    "expected": cast(JsonValue, expected),
                    "actual": actual,
                    "reason": actual["reason"],
                    "passed": actual == expected,
                }
            )
        if program["program"] != "crc32tool":
            continue
        if built.binary_sha256 != edges["binary_sha256"]:
            raise ValueError("static selftest binary/golden identity mismatch")
        for case in edges["cases"]:
            claim = Claim.intake(
                ClaimSubmission.model_validate(
                    {
                        "run_id": "r_" + "2" * 16,
                        "source": {"origin": "human", "source_id": "human:selftest"},
                        "binary_sha256": built.binary_sha256,
                        "subject": {"address": case["subject"]},
                        "type": "call_relation",
                        "body": {"callee": case["callee"], "kind": case["kind"]},
                        "confidence": 1.0,
                        "confidence_source": "stated",
                    }
                )
            )
            verdict = verify_edges(claim, analysis, cfg.sandbox.image_analysis)
            rows.append(
                {
                    "name": "static.edges:" + case["name"],
                    "family": "static",
                    "expected": case["verdict"],
                    "actual": verdict.intrinsic_verdict,
                    "reason": verdict.reason,
                    "passed": (verdict.intrinsic_verdict, verdict.reason)
                    == (case["verdict"], case["reason"]),
                }
            )
    return rows


def run_selftest(cfg: Config, family: str | None = None) -> dict[str, JsonValue]:
    packs = {path.stem: load_pack(path) for path in sorted(Path("packs").glob("*.yaml"))}
    if family is not None and family not in packs:
        raise ValueError("unknown selftest family: " + family)
    selected = [family] if family is not None else sorted(packs)
    if not selected:
        raise ValueError("no installed probe packs")
    root = Path(cfg.paths.build) / "selftest"
    check_no_symlinks(root)
    root.mkdir(parents=True, exist_ok=True)
    artifacts = ArtifactStore(root / "artifacts")
    runner = JobRunner(cfg.sandbox, root / "public", root / "jobs", artifacts)
    cache = GhidraAnalysisCache(runner, root / "analysis-cache")
    client = ProbeClient(runner)
    rows: list[dict[str, JsonValue]] = []
    for current in selected:
        pack: Pack = packs[current]
        binary, symbols, fixture = build_fixture(current, cfg, root)
        if {ref.variant for ref in fixture.references} != set(pack.variants):
            raise ValueError("reference fixtures must cover every supported variant")
        if [case.name for case in fixture.near_miss] != pack.near_miss:
            raise ValueError("near-miss fixture/pack coverage mismatch")
        fixed = {value.encode().hex() for value in pack.inputs.fixed} | set(pack.inputs.fixed_hex)
        if any(case.witness_hex not in fixed for case in fixture.near_miss):
            raise ValueError("near-miss witnesses must be declared fixed vectors")
        subjects = [
            symbols[case.name]
            for case in [*fixture.references, *fixture.near_miss, *fixture.conservative_cases]
        ]
        analysis = cache.analyze(binary, Path(cfg.ghidra.analysis_options), subjects=subjects)
        env_digest = "sha256:" + content_hash(
            {
                "image": cfg.sandbox.image_analysis,
                "budgets": cfg.budgets.model_dump(mode="json"),
                "analysis": content_hash(analysis),
                "packs": {
                    name: hashlib.sha256(
                        (Path("packs") / (name + ".yaml")).read_bytes()
                    ).hexdigest()
                    for name in sorted(packs)
                },
            }
        )

        def check(
            name: str,
            address: Address,
            claimed_family: str,
            variant: str | None,
            expected: Outcome,
            reason: str | None = None,
            shape: str | None = None,
            matches_variant: str | None = None,
            budget: Budgets | None = None,
            binary: BinaryRef = binary,
            analysis: GhidraAnalysis = analysis,
            env_digest: str = env_digest,
            current: str = current,
        ) -> None:
            claim = _claim(binary, address, claimed_family, variant)
            pack_path = Path("packs") / (claimed_family + ".yaml")
            verdict = client.probe(
                binary,
                claim,
                analysis,
                pack_path if pack_path.is_file() else None,
                budget or cfg.budgets,
                "sha256:"
                + content_hash(
                    {
                        "environment": env_digest,
                        "budgets": (budget or cfg.budgets).model_dump(mode="json"),
                    }
                ),
            )
            binding = infer_arity(address, analysis)
            passed = verdict.intrinsic_verdict == expected and verdict.reason == reason
            if expected in ("VERIFIED", "CONTRADICTED"):
                passed = passed and binding.decisive
            if shape is not None:
                passed = passed and binding.arity == len(SHAPES[shape])
            if expected == "CONTRADICTED":
                passed = passed and verdict.counterexample is not None
            if matches_variant is not None:
                passed = (
                    passed
                    and verdict.counterexample is not None
                    and verdict.counterexample.matches_variant == matches_variant
                )
            rows.append(
                {
                    "name": current + ":" + name,
                    "family": current,
                    "expected": expected,
                    "actual": verdict.intrinsic_verdict,
                    "reason": verdict.reason,
                    "passed": passed,
                    "arity": binding.model_dump(mode="json"),
                    "counterexample": verdict.counterexample.model_dump(mode="json")
                    if verdict.counterexample
                    else None,
                }
            )

        for ref in fixture.references:
            check(
                "reference:" + ref.name,
                symbols[ref.name],
                current,
                ref.variant,
                "VERIFIED",
                shape=ref.call_shape,
            )
        for near in fixture.near_miss:
            check(
                "near:" + near.name,
                symbols[near.name],
                current,
                near.variant,
                "CONTRADICTED",
                shape=near.call_shape,
                matches_variant=near.matches_variant,
            )
        for variant in sorted(pack.variants):
            if any(case.variant == variant for case in fixture.near_miss):
                continue
            other = next((ref for ref in fixture.references if ref.variant != variant), None)
            if other is not None:
                check(
                    "cross:" + other.name + ":" + variant,
                    symbols[other.name],
                    current,
                    variant,
                    "CONTRADICTED",
                    shape=other.call_shape,
                    matches_variant=other.variant,
                )
        for index, case in enumerate(fixture.conservative_cases):
            budget = cfg.budgets
            if case.instructions_per_invocation is not None:
                budget = budget.model_copy(
                    update={"instructions_per_invocation": case.instructions_per_invocation}
                )
            check(
                f"conservative:{index}:{case.name}",
                symbols[case.name],
                case.family or current,
                case.variant,
                case.expected,
                case.reason,
                budget=budget,
            )
    static_passed: bool | None = None
    if family is None:
        static = static_cases(cfg, root, cache)
        static_passed = bool(static) and all(case["passed"] is True for case in static)
        rows.extend(static)
    failed = sum(row["passed"] is False for row in rows)
    return {
        "status": "ok" if not failed else "failed",
        "families": cast(JsonValue, selected),
        "cases": cast(JsonValue, sorted(rows, key=lambda row: str(row["name"]))),
        "failed": failed,
        "static_fixtures_passed": static_passed,
    }
