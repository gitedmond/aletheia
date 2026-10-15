"""Pinned capa JSON normalization. The host consumes JSON, never ELF bytes."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import JsonValue

from aletheia.schema.models import (
    Algorithm,
    Claim,
    ClaimSubmission,
    Source,
    Strict,
    Subject,
    Targets,
)

if TYPE_CHECKING:
    from pathlib import Path

    from aletheia.sandbox.runner import JobRunner
    from aletheia.sources.base import BinaryRef


class CapaMapping(Strict):
    capa_version: Literal["9.4.0"]
    rules_tag: Literal["9.4.0"]
    address_base_field: Literal["meta.analysis.base_address.value"]
    map: dict[str, Algorithm]

    @classmethod
    def read(cls, path: "Path") -> "CapaMapping":
        import yaml

        class UniqueLoader(yaml.SafeLoader):
            def construct_mapping(self, node: yaml.MappingNode, deep: bool = False):
                keys: list[str] = []
                for key, _ in node.value:
                    if not isinstance(key, yaml.ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                        raise ValueError("capa mapping keys must be unique strings")
                    keys.append(key.value)
                if len(keys) != len(set(keys)):
                    raise ValueError("capa mapping keys must be unique strings")
                return super().construct_mapping(node, deep=deep)

        if any(part.is_symlink() for part in (path, *path.parents)):
            raise ValueError("capa mapping cannot be a symlink")
        return cls.model_validate(yaml.load(path.read_text(), Loader=UniqueLoader))


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("capa report requires a JSON object")
    return value


def _array(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ValueError("capa report requires a JSON array")
    return value


def _address(value: JsonValue) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 0xFFFFFFFFFFFFFFFF
    ):
        raise ValueError("capa requires an unsigned absolute address")
    return value


@dataclass(frozen=True)
class CapaResult:
    claims: list[Claim]
    unmapped_scope: int
    unmapped_label: dict[str, int]
    deduplicated_label: dict[str, int]


class CapaAdapter:
    def __init__(self, mapping: CapaMapping, run_id: str):
        self.mapping = mapping
        self.run_id = run_id

    def adapt(self, report: dict[str, JsonValue], binary_sha256: str) -> CapaResult:
        """Normalize the observed 9.4 static ELF format without truth or target filtering."""
        try:
            meta = _object(report["meta"])
            sample = _object(meta["sample"])
            analysis = _object(meta["analysis"])
            base_record = _object(analysis["base_address"])
            if (
                meta["version"] != self.mapping.capa_version
                or sample["sha256"] != binary_sha256
                or analysis["format"] != "elf"
                or analysis["arch"] != "amd64"
                or base_record["type"] != "absolute"
            ):
                raise ValueError("capa version, sample or analysis identity mismatch")
            base = _address(base_record["value"])
            rules = _object(report["rules"])
            unmapped_scope = 0
            unmapped_label: dict[str, int] = {}
            duplicates: dict[str, int] = {}
            selected: dict[int, tuple[Algorithm, str]] = {}
            for label, raw in sorted(rules.items()):
                rule = _object(raw)
                scope = _object(_object(rule["meta"])["scopes"])["static"]
                matches = _array(rule["matches"])
                if scope != "function":
                    unmapped_scope += len(matches)
                    continue
                algorithm = self.mapping.map.get(label)
                if algorithm is None:
                    unmapped_label[label] = len(matches)
                    continue
                for raw_match in matches:
                    match = _array(raw_match)
                    if len(match) != 2 or _object(match[1]).get("success") is not True:
                        raise ValueError("malformed capa match")
                    location = _object(match[0])
                    if location["type"] != "absolute":
                        raise ValueError("capa function location is not absolute")
                    absolute = _address(location["value"])
                    if absolute < base:
                        raise ValueError("capa function location precedes image base")
                    address = absolute - base
                    previous = selected.get(address)
                    if previous is not None:
                        if previous[0] != algorithm:
                            raise ValueError(f"conflicting_algorithm_labels: {address:#x}")
                        duplicates[label] = duplicates.get(label, 0) + 1
                    else:
                        selected[address] = (algorithm, label)
            source = Source(
                origin="tool",
                source_id=f"tool:capa@{self.mapping.capa_version}+rules@{self.mapping.rules_tag}",
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
                        derived_from="capa_rule",
                        tool_label=label,
                    )
                )
                for address, (algorithm, label) in sorted(selected.items())
            ]
            return CapaResult(claims, unmapped_scope, unmapped_label, duplicates)
        except (KeyError, TypeError) as error:
            raise ValueError(f"malformed pinned capa report: {error}") from error


class CapaSource:
    origin = "tool"

    def __init__(self, mapping: CapaMapping, run_id: str, runner: "JobRunner"):
        self.mapping = mapping
        self.run_id = run_id
        self.runner = runner
        self.source_id = f"tool:capa@{mapping.capa_version}+rules@{mapping.rules_tag}"
        self.last_result: CapaResult | None = None
        self.last_artifact: str | None = None

    def produce(self, binary: "BinaryRef", targets: "Targets") -> list[Claim]:
        import hashlib
        import os
        import shutil
        import tempfile
        from pathlib import Path

        from aletheia.doctor import read_lock
        from aletheia.schema.models import Job

        self.last_result = None
        self.last_artifact = None
        if targets.binary_sha256 != binary.binary_sha256 or targets.variant_id != binary.variant_id:
            raise ValueError("capa public targets/binary identity mismatch")
        lock = read_lock(Path(__file__).resolve().parents[2] / "versions.lock.md")
        if (
            lock["packages"]["flare-capa"] != self.mapping.capa_version
            or lock["pins"]["capa_rules"]["version"] != self.mapping.rules_tag
        ):
            raise ValueError("capa mapping does not match locked tool versions")
        inputs = self.runner.input_root / "in"
        inputs.mkdir(parents=True, exist_ok=True)
        destination = inputs / (binary.binary_sha256 + ".bin")
        if any(p.is_symlink() for p in (destination, *destination.parents)):
            raise ValueError("capa public input cannot be a symlink")
        fd, name = tempfile.mkstemp(prefix=".capa-", dir=inputs)
        try:
            with os.fdopen(fd, "wb") as stream, binary.stripped.open("rb") as source:
                shutil.copyfileobj(source, stream)
            staged = Path(name)
            if hashlib.sha256(staged.read_bytes()).hexdigest() != binary.binary_sha256:
                raise ValueError("capa binary content/hash mismatch")
            if (
                destination.exists()
                and hashlib.sha256(destination.read_bytes()).hexdigest() != binary.binary_sha256
            ):
                raise ValueError("capa public input collision")
            os.replace(staged, destination)
        finally:
            Path(name).unlink(missing_ok=True)
        job = Job.create(
            "capa_scan",
            {"binary": "in/" + destination.name},
            {
                "capa_version": self.mapping.capa_version,
                "rules_sha256": str(lock["pins"]["capa_rules"]["sha256"]),
            },
        )
        handle = self.runner.submit(job)
        result = self.runner.wait(handle)
        self.last_artifact = handle.result_artifact
        if result.status != "ok":
            raise RuntimeError(
                f"capa_scan failed: {result.error_code}: {result.output.get('detail', '')}"
            )
        raw = _object(result.output["capa"])
        self.last_result = CapaAdapter(self.mapping, self.run_id).adapt(raw, binary.binary_sha256)
        return self.last_result.claims
