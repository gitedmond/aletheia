"""PC-local resumable experiment driver; all mixed-split ledgers stay private.

Stages: preflight, dev-sources, dev-agents, dev-fit, heldout-sources,
heldout-agents, replay, receipts, gate. `all` additionally requires
ALETHEIA_MATRIX_ALL=1 because it launches the full 360-slot acquisition.
"""

import argparse
import base64
import fcntl
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from aletheia.agent.batch import fit_dev, provider_for, run_agent
from aletheia.agent.replay import replay_agent
from aletheia.config import Config
from aletheia.corpus.build import Variant
from aletheia.doctor import read_lock
from aletheia.gate_phase1b import package_hash
from aletheia.llm.provider import AgentConfig
from aletheia.llm.windows_loopback import windows_working_directory
from aletheia.orchestrate import Benchmark, file_hash, write_json
from aletheia.replay import replay

STAGES = (
    "preflight",
    "dev-calibration",
    "dev-sources",
    "dev-agents",
    "dev-fit",
    "heldout-calibration",
    "heldout-sources",
    "heldout-agents",
    "replay",
    "receipts",
    "gate",
    "all",
)
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("stage", choices=STAGES)
args = parser.parse_args()
stage = args.stage
if stage == "all" and os.environ.get("ALETHEIA_MATRIX_ALL") != "1":
    parser.error("all launches the full matrix; set ALETHEIA_MATRIX_ALL=1")

private = Path("/home/edmond/src/aletheia-private")
state_root = private / "phase1b-execution-codex-v2"
state_root.mkdir(exist_ok=True)
lock = (state_root / "matrix.lock").open("a")
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
config = Config.read(Path("aletheia.toml"))
runtime_version = str(read_lock(Path("versions.lock.md"))["host"]["ollama"])
config.grading.agreement = "configs/grading-phase1b.json"
config.paths.private_root = str(private)
config.paths.build = "/home/edmond/src/aletheia-phase1b-data/build"
config.paths.runs = "/home/edmond/src/aletheia-phase1b-data/runs-phase1b-v2"
config.paths.artifacts = "/home/edmond/src/aletheia-phase1b-data/artifacts-phase1b-v2"
held = config.for_split("heldout")
# Distinct experiment namespaces: dev results stay public, held-out results private.
held.paths.runs = str(private / "runs-phase1b-v2")
held.paths.artifacts = str(private / "artifacts-phase1b-v2")
configs = {
    key: AgentConfig.model_validate(yaml.safe_load(Path(f"configs/agents/{key}.yaml").read_bytes()))
    for key in ("local-a", "local-b", "local-c")
}
benchmarks = {}
for split, cfg in (("dev", config), ("heldout", held)):
    for variant in ("baseline", "hardened"):
        build_variant = Variant(
            cfg.sandbox.image_build,
            hardening="hardoff" if variant == "baseline" else "hardened",
            ground_truth_version="2.0",
        ).id
        benchmarks[(split, variant)] = Benchmark(
            cfg, variant=build_variant, algorithms_version="2.0"
        )
baseline_id = Variant(
    config.sandbox.image_build, hardening="hardoff", ground_truth_version="2.0"
).id
programs = {split: benchmarks[(split, "baseline")].programs() for split in ("dev", "heldout")}
assert len(programs["dev"]) == 12 and len(programs["heldout"]) == 8


def freeze_scope():
    files = {}
    for root in ("configs", "packs", "mappings", "prompts", "tests"):
        for path in sorted(Path(root).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                files[path.as_posix()] = file_hash(path)
    for path in sorted(Path("aletheia").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files[path.as_posix()] = file_hash(path)
    for name in (
        "algorithms.yaml",
        "taxonomy.yaml",
        "versions.lock.md",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "LICENSE",
        "tools/check.py",
    ):
        files[name] = file_hash(Path(name))
    files["aletheia.toml"] = file_hash(Path("aletheia.toml"))
    files["driver"] = file_hash(Path(__file__))
    return {
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "package_source_hash": package_hash(),
        "files": files,
        "programs": programs,
        "builds": {
            split: {
                variant: {
                    program: {
                        "metadata": file_hash(bench.bundle(program)[2] / "build.json"),
                        "ground_truth": file_hash(
                            bench.bundle(program)[2] / "private/ground_truth.json"
                        ),
                        "binary": bench.bundle(program)[0].binary_sha256,
                    }
                    for program in programs[split]
                }
                for (current_split, variant), bench in benchmarks.items()
                if current_split == split
            }
            for split in ("dev", "heldout")
        },
        "configs": {key: value.model_dump(mode="json") for key, value in configs.items()},
        "images": config.sandbox.model_dump(mode="json"),
    }


scope = freeze_scope()
ledger_path = state_root / "plan.json"
if ledger_path.exists():
    ledger = json.loads(ledger_path.read_bytes())
    if ledger["scope"] != scope:
        raise ValueError(
            "Frozen matrix scope changed; preserve prior results and use a new namespace"
        )
else:
    slots = []
    for split in ("dev", "heldout"):
        for program in programs[split]:
            for variant in ("baseline", "hardened"):
                for source in ("scripted", "capa", "findcrypt"):
                    slots.append(
                        dict(
                            split=split,
                            program=program,
                            variant=variant,
                            source=source,
                            sample=0,
                            status="pending",
                            runs=[],
                        )
                    )
                for key in configs:
                    for index in range(3 if variant == "baseline" else 1):
                        slots.append(
                            dict(
                                split=split,
                                program=program,
                                variant=variant,
                                source="agent:" + key,
                                sample=index,
                                status="pending",
                                runs=[],
                            )
                        )
    ledger = {"scope": scope, "slots": slots}
    write_json(ledger_path, ledger)


def save():
    write_json(ledger_path, ledger)


def image_digest(image):
    return (
        subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        .decode()
        .strip()
    )


SHOW_SCRIPT = """
$ErrorActionPreference = 'Stop'
$body = '{"model":"%s"}'
$params = @{ Uri = 'http://127.0.0.1:11434/api/show'; Method = 'Post' }
$show = Invoke-RestMethod @params -ContentType 'application/json' -Body $body -TimeoutSec 15
if (!$show.modelfile.Contains('sha256-%s')) { exit 3 }
if ($show.parameters -notmatch 'num_ctx\\s+32768') { exit 4 }
$runtime = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/version' -TimeoutSec 15
if ($runtime.version -ne '%s') { exit 5 }
exit 0
"""


def provider_preflight(agent):
    url = urlsplit(agent.base_url)
    if agent.transport != "windows-loopback":
        with socket.create_connection((url.hostname, url.port or 80), timeout=5):
            pass
        return
    script = SHOW_SCRIPT % (agent.model, agent.model_file_sha256, runtime_version)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    check = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True,
        cwd=windows_working_directory(),
        timeout=60,
    )
    if check.returncode:
        raise ValueError(
            f"agent endpoint or model pin failed: {agent.config_id} (exit {check.returncode})"
        )


def preflight(check_providers=True):
    if subprocess.check_output(["git", "status", "--porcelain"]).strip():
        raise ValueError("Commit the reviewed source/configuration before freezing acquisition")
    for image in (config.sandbox.image_build, config.sandbox.image_analysis):
        if image_digest(image) != image:
            raise ValueError("required image is not present locally: " + image)
    check = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            config.sandbox.image_analysis,
            "-c",
            "import aletheia.agent.ghidra_mcp",
        ],
        capture_output=True,
        text=True,
    )
    if check.returncode:
        raise ValueError("analysis image lacks the Ghidra worker")
    for split in ("dev", "heldout"):
        for variant in ("baseline", "hardened"):
            benchmark = benchmarks[(split, variant)]
            build_root = Path(benchmark.config.paths.build)
            expected = (
                baseline_id if variant == "baseline" else baseline_id.replace("hardoff", "hardened")
            )
            for program in benchmark.programs():
                records = sorted((build_root / program).glob(f"{expected}/build.json"))
                if (
                    len(records) != 1
                    or json.loads(records[0].read_bytes())["image"] != config.sandbox.image_build
                ):
                    raise ValueError(
                        f"built binary lacks the pinned image: {split}/{program}/{variant}"
                    )
    if check_providers:
        for agent in configs.values():
            provider_preflight(agent)
    print(
        json.dumps({"stage": "preflight", "programs": {k: len(v) for k, v in programs.items()}}),
        flush=True,
    )


def run_slots(split, agents):
    selected = [
        s
        for s in ledger["slots"]
        if s["split"] == split and s["source"].startswith("agent:") == agents
    ]
    # Keep one model resident rather than swapping GPU weights between programs.
    if agents:
        selected.sort(
            key=lambda row: (row["source"], row["program"], row["variant"], row["sample"])
        )
    for index, slot in enumerate(selected, 1):
        if slot["status"] == "executed":
            continue
        if freeze_scope() != scope:
            raise ValueError("Source/config/build changed during frozen acquisition")
        bench = benchmarks[(split, slot["variant"])]
        start = time.monotonic()
        try:
            if agents:
                agent = configs[slot["source"].split(":", 1)[1]]
                provider_preflight(agent)
                run, result = run_agent(
                    bench, agent, provider_for(agent), slot["program"], slot["sample"]
                )
                slot.update(runs=[run], state=result.status, reason=result.reason)
            else:
                slot.update(
                    runs=bench.run(slot["program"], slot["source"]), state="completed", reason=None
                )
            slot["status"] = "executed"
            slot["elapsed_seconds"] = round(time.monotonic() - start, 3)
            save()
            print(
                json.dumps(
                    {
                        "stage": split + ("-agents" if agents else "-sources"),
                        "slot": index,
                        "of": len(selected),
                        "state": slot["state"],
                        "reason": slot["reason"],
                        "elapsed_seconds": slot["elapsed_seconds"],
                    }
                ),
                flush=True,
            )
        except Exception as exc:
            slot.update(status="error", error=type(exc).__name__ + ": " + str(exc)[:600])
            save()
            print(
                json.dumps(
                    {
                        "stage": split,
                        "slot": index,
                        "status": "error",
                        "error_type": type(exc).__name__,
                    }
                ),
                flush=True,
            )
            raise


def all_runs(split):
    return sorted({r for s in ledger["slots"] if s["split"] == split for r in s["runs"]})


def replay_stage():
    record_path = state_root / "replays.json"
    records = json.loads(record_path.read_bytes()) if record_path.exists() else {"runs": {}}
    failures = []
    for split in ("dev", "heldout"):
        benchmark = benchmarks[(split, "baseline")]
        for index, run in enumerate(all_runs(split), 1):
            agent_root = benchmark.directory(run) / "agent"
            row = records["runs"].get(run)
            replays_agent = agent_root.exists()
            agent_replay = row.get("agent_replay") if row else None
            complete = (
                row is not None
                and row["exit_code"] == 0
                and (
                    not replays_agent
                    or agent_replay is True
                    or (isinstance(agent_replay, dict) and agent_replay.get("status") == "passed")
                )
            )
            if complete:
                continue
            result = replay(benchmark, run)
            if replays_agent:
                destination = Path(benchmark.config.paths.runs) / "agent-replays" / run
                transcript = replay_agent(agent_root, destination, benchmark.config.guard)
                result["agent_replay"] = transcript["status"] == "passed"
            records["runs"][run] = result
            write_json(record_path, records)
            print(
                json.dumps(
                    {
                        "stage": "replay",
                        "split": split,
                        "index": index,
                        "exit_code": result["exit_code"],
                        "agent_replay": result.get("agent_replay"),
                    }
                ),
                flush=True,
            )
            if result["exit_code"] or result.get("agent_replay") is False:
                failures.append(run)
    if failures:
        raise ValueError("Replay mismatch; retained private receipt: " + ",".join(failures))


def fit_stage():
    receipt = fit_dev(benchmarks[("dev", "baseline")], all_runs("dev"))
    print(
        json.dumps(
            {
                "stage": "dev-fit",
                "eligible_rows": receipt["eligible_rows"],
                "maps": receipt["calibrated_sources"],
                "unfitted": receipt["unfitted"],
            }
        ),
        flush=True,
    )


def receipts_stage():
    preflight(check_providers=False)
    from aletheia import phase1b

    benchmark = benchmarks[("heldout", "baseline")]
    directory = benchmark.root / "phase1b"
    directory.mkdir(parents=True, exist_ok=True)
    plan_payload = phase1b.plan(ledger)
    replays_payload = phase1b.replays(
        plan_payload, json.loads((state_root / "replays.json").read_bytes())
    )
    truth_records = phase1b.truths(Path(config.paths.build), baseline_id) + phase1b.truths(
        Path(held.paths.build), baseline_id
    )
    scripted_runs = [
        r
        for s in ledger["slots"]
        if s["split"] == "heldout" and s["source"] == "scripted"
        for r in s["runs"]
    ]
    fit_payload, manifests = phase1b.fit(benchmarks[("dev", "baseline")], all_runs("dev"))
    files = {}
    tests_path = directory / "full_tests.xml"
    test_scope_path = directory / "tests_scope.json"
    prior_tests = json.loads(test_scope_path.read_bytes()) if test_scope_path.exists() else {}
    if (
        not tests_path.exists()
        or prior_tests.get("scope") != scope
        or prior_tests.get("junit_sha256") != file_hash(tests_path)
    ):
        tests_path = phase1b.junit(directory, "full_tests", ["tests", "-m", "not slow"])
        write_json(test_scope_path, {"scope": scope, "junit_sha256": file_hash(tests_path)})
    for name in ("golden_tests", "mcp_tests", "guard_tests"):
        files[name] = tests_path
    payloads = {
        "builds": phase1b.builds(benchmarks),
        "history": phase1b.history(held.guard),
        "scripted": phase1b.scripted(benchmark, scripted_runs),
        "selftest": phase1b.selftest(config),
        "coverage": phase1b.coverage(truth_records, variant_id=baseline_id),
        "plan": plan_payload,
        "replays": replays_payload,
        "fit": fit_payload,
        "fit_manifests": manifests,
        "report": phase1b.report(
            benchmark, all_runs("heldout"), Path(config.paths.runs) / "confidence"
        ),
        "exposures": phase1b.exposures(held.guard),
        "agreement": phase1b.agreement(config),
        "corpus_targets_dev": json.loads(
            (Path(config.paths.runs) / "phase1b/corpus_targets.json").read_bytes()
        ),
        "corpus_targets_heldout": json.loads(
            (Path(held.paths.runs) / "phase1b/corpus_targets.json").read_bytes()
        ),
    }
    reviews = state_root / "reviews.json"
    if reviews.exists():
        payloads["reviews"] = json.loads(reviews.read_bytes())
    evidence = phase1b.assemble(benchmark, payloads, files)
    print(json.dumps({"stage": "receipts", "evidence": str(evidence)}), flush=True)


def gate_stage():
    from aletheia.gate_phase1b import evaluate

    result = evaluate(benchmarks[("heldout", "baseline")])
    print(
        json.dumps(
            {
                "stage": "gate",
                "status": result["status"],
                "criteria": {key: row["passed"] for key, row in result["criteria"].items()},
            }
        ),
        flush=True,
    )


if stage in ("all", "preflight"):
    preflight()
if stage in ("all", "dev-calibration"):
    from aletheia.phase1b import corpus_targets

    result = corpus_targets(
        benchmarks[("dev", "hardened")],
        expected_abstentions={("crc32tool", "crc32_update_rt"): "state_dependent"},
    )
    print(
        json.dumps(
            {
                "stage": "dev-calibration",
                "status": result["status"],
                "targets": len(result["targets"]),
            }
        ),
        flush=True,
    )
if stage in ("all", "dev-sources"):
    run_slots("dev", False)
if stage in ("all", "dev-agents"):
    run_slots("dev", True)
if stage in ("all", "dev-fit"):
    fit_stage()
if stage in ("all", "heldout-calibration"):
    from aletheia.phase1b import corpus_targets

    result = corpus_targets(benchmarks[("heldout", "hardened")])
    print(
        json.dumps(
            {
                "stage": "heldout-calibration",
                "status": result["status"],
                "targets": len(result["targets"]),
            }
        ),
        flush=True,
    )
if stage in ("all", "heldout-sources"):
    run_slots("heldout", False)
if stage in ("all", "heldout-agents"):
    run_slots("heldout", True)
if stage in ("all", "replay"):
    replay_stage()
if stage in ("all", "receipts"):
    receipts_stage()
if stage in ("all", "gate"):
    gate_stage()
