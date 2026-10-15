"""T19: actual FindCrypt labels, xrefs and adapted claims match protected F4/F5."""

import json
from pathlib import Path

import pytest

from aletheia.config import Config
from aletheia.corpus.build import Variant, build_program
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Job, JobResult, Targets
from aletheia.sources.base import BinaryRef
from aletheia.sources.findcrypt import FindcryptMapping, FindcryptReport, FindcryptSource
from aletheia.store.artifacts import ArtifactStore

pytestmark = pytest.mark.integration


def test_findcrypt_raw_and_adapter_equal_protected_golden(tmp_path):
    cfg = Config.read(Path("aletheia.toml"))
    golden = json.loads(Path("tests/golden/adapters/findcrypt-crc32tool.json").read_bytes())
    built = build_program(
        Path("corpus/tierA/crc32tool"),
        Variant(image=cfg.sandbox.image_build, output_root=tmp_path / "build"),
    )
    assert built.binary_sha256 == golden["binary_sha256"]
    targets = Targets.model_validate_json((built.metadata.parent / "targets.json").read_bytes())
    artifacts = ArtifactStore(tmp_path / "artifacts")
    runner = JobRunner(cfg.sandbox, tmp_path / "public", tmp_path / "jobs", artifacts)
    source = FindcryptSource(
        FindcryptMapping.read(Path("mappings/findcrypt.yaml")),
        "r_" + "2" * 16,
        runner,
        Path("configs/ghidra-analysis.json"),
    )
    raw_results = []
    for _ in range(2):
        claims = source.produce(
            BinaryRef(built.binary_sha256, built.stripped, built.variant_id), targets
        )
        assert [claim.model_dump(mode="json") for claim in claims] == golden["claims"]
        assert source.last_result is not None and source.last_artifact is not None
        assert source.last_result.unmapped_label == golden["unmapped_label"]
        assert source.last_result.deduplicated_label == golden["deduplicated_label"]
        job = JobResult.model_validate_json(artifacts.get(source.last_artifact))
        raw = FindcryptReport.model_validate(job.output["findcrypt"]).model_dump(mode="json")
        assert raw == golden["raw"]
        raw_results.append(raw)
    assert raw_results[0] == raw_results[1]

    baseline = Job.model_validate_json(next((tmp_path / "jobs").glob("*/in/job.json")).read_bytes())
    unexpected = Job.create("findcrypt_scan", baseline.inputs, {**baseline.params, "subjects": []})
    rejected = runner.wait(runner.submit(unexpected))
    assert (rejected.status, rejected.error_code) == ("error", "bad_input")
