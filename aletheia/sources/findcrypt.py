"""Pinned FindCrypt normalization; binary parsing stays in a separate Ghidra job."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from aletheia.analysis.ghidra_session import GhidraOptions, publish_immutable
from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import (
    Address,
    Algorithm,
    Claim,
    ClaimSubmission,
    Job,
    Record,
    Sha256,
    Source,
    Strict,
    Subject,
    Targets,
)
from aletheia.sources.base import BinaryRef


class FindcryptLabel(Strict):
    name: str = Field(pattern=r"^CRYPT_.+")
    address: Address
    xrefs_to: list[Address]


class FindcryptReport(Record):
    binary_sha256: Sha256
    ghidra_version: Literal["11.4.3"] = "11.4.3"
    findcrypt_version: Literal["3.1.10"] = "3.1.10"
    image_base: Literal["0x00000000"] = "0x00000000"
    labels: list[FindcryptLabel]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        keys = [(int(label.address, 16), label.name) for label in self.labels]
        if keys != sorted(set(keys)):
            raise ValueError("FindCrypt labels must be sorted and unique")
        for label in self.labels:
            if label.xrefs_to != sorted(set(label.xrefs_to), key=lambda a: int(a, 16)):
                raise ValueError("FindCrypt xrefs must be sorted and unique")
        return self


class FindcryptMapping(Strict):
    findcrypt_version: Literal["3.1.10"]
    ghidra_version: Literal["11.4.3"]
    map: dict[str, Algorithm]

    @classmethod
    def read(cls, path: Path) -> Self:
        import yaml

        class UniqueLoader(yaml.SafeLoader):
            def construct_mapping(self, node: yaml.MappingNode, deep: bool = False):
                keys: list[str] = []
                for key, _ in node.value:
                    if not isinstance(key, yaml.ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                        raise ValueError("FindCrypt mapping keys must be unique strings")
                    keys.append(key.value)
                if len(keys) != len(set(keys)):
                    raise ValueError("FindCrypt mapping keys must be unique strings")
                return super().construct_mapping(node, deep=deep)

        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("FindCrypt mapping cannot be a symlink")
        return cls.model_validate(yaml.load(path.read_text(), Loader=UniqueLoader))


@dataclass(frozen=True)
class FindcryptResult:
    claims: list[Claim]
    unmapped_label: dict[str, int]
    deduplicated_label: dict[str, int]


class FindcryptAdapter:
    def __init__(self, mapping: FindcryptMapping, run_id: str):
        self.mapping, self.run_id = mapping, run_id

    def adapt(self, report: FindcryptReport, binary_sha256: str) -> FindcryptResult:
        if report.binary_sha256 != binary_sha256:
            raise ValueError("FindCrypt binary identity mismatch")
        selected: dict[tuple[int, str], tuple[Algorithm, str]] = {}
        unmapped: dict[str, int] = {}
        duplicates: dict[str, int] = {}
        for label in report.labels:
            algorithm = self.mapping.map.get(label.name)
            if algorithm is None:
                unmapped[label.name] = unmapped.get(label.name, 0) + 1
                continue
            for address in label.xrefs_to:
                key = (int(address, 16), algorithm.family)
                previous = selected.get(key)
                if previous is not None:
                    if previous[0] != algorithm:
                        raise ValueError("conflicting FindCrypt variants for function/family")
                    duplicates[label.name] = duplicates.get(label.name, 0) + 1
                else:
                    selected[key] = (algorithm, label.name)
        source = Source(
            origin="tool", source_id="tool:findcrypt@3.1.10+ghidra@11.4.3", shares_backend=True
        )
        claims = [
            Claim.intake(
                ClaimSubmission(
                    run_id=self.run_id,
                    source=source,
                    binary_sha256=binary_sha256,
                    subject=Subject(address=f"0x{address:08x}"),
                    type="algorithm_identity",
                    body=algorithm,
                    confidence=1.0,
                    confidence_source="tool_default",
                    derived_from="constant_xref",
                    tool_label=label,
                )
            )
            for (address, _), (algorithm, label) in sorted(selected.items())
        ]
        return FindcryptResult(claims, unmapped, duplicates)


def scan_findcrypt(
    binary: BinaryRef, options: Path, runner: JobRunner
) -> tuple[FindcryptReport, str]:
    import hashlib

    config = GhidraOptions.read(options)
    payload = binary.stripped.read_bytes()
    if hashlib.sha256(payload).hexdigest() != binary.binary_sha256:
        raise ValueError("FindCrypt binary content/hash mismatch")
    option_bytes = options.read_bytes()
    option_hash = hashlib.sha256(option_bytes).hexdigest()
    root = runner.input_root / "in"
    publish_immutable(root / (binary.binary_sha256 + ".bin"), payload)
    publish_immutable(root / (option_hash + ".json"), option_bytes)
    job = Job.create(
        "findcrypt_scan",
        {"binary": "in/" + binary.binary_sha256 + ".bin", "options": "in/" + option_hash + ".json"},
        {
            "ghidra_version": config.ghidra_version,
            "options_sha256": option_hash,
            "env_digest": runner.config.image_analysis,
            "findcrypt_version": "3.1.10",
        },
    )
    handle = runner.submit(job)
    result = runner.wait(handle)
    if result.status != "ok":
        raise RuntimeError(
            f"findcrypt_scan failed: {result.error_code}: {result.output.get('detail', '')}"
        )
    report = FindcryptReport.model_validate(result.output["findcrypt"])
    if report.binary_sha256 != binary.binary_sha256:
        raise ValueError("FindCrypt result identity mismatch")
    if handle.result_artifact is None:
        raise RuntimeError("FindCrypt job result artifact missing")
    return report, handle.result_artifact


class FindcryptSource:
    origin = "tool"
    source_id = "tool:findcrypt@3.1.10+ghidra@11.4.3"

    def __init__(self, mapping: FindcryptMapping, run_id: str, runner: JobRunner, options: Path):
        self.mapping, self.run_id, self.runner, self.options = mapping, run_id, runner, options
        self.last_result: FindcryptResult | None = None
        self.last_artifact: str | None = None

    def produce(self, binary: BinaryRef, targets: Targets) -> list[Claim]:
        self.last_result, self.last_artifact = None, None
        if targets.binary_sha256 != binary.binary_sha256 or targets.variant_id != binary.variant_id:
            raise ValueError("FindCrypt public targets/binary identity mismatch")
        report, self.last_artifact = scan_findcrypt(binary, self.options, self.runner)
        self.last_result = FindcryptAdapter(self.mapping, self.run_id).adapt(
            report, binary.binary_sha256
        )
        return self.last_result.claims
