"""Pinned analysis records and host-side opaque transport/cache; no binary parsing."""

import hashlib
import math
import os
import tempfile
from pathlib import Path
from typing import Literal, Self, cast

from pydantic import Field, JsonValue, TypeAdapter, model_validator

from aletheia.sandbox.runner import JobRunner
from aletheia.schema.models import Address, Job, JobResult, Kind, Record, Sha256, Strict, Target
from aletheia.sources.base import BinaryRef


class AnalyzerOption(Strict):
    name: str = Field(min_length=1)
    type: Literal[
        "BOOLEAN_TYPE",
        "INT_TYPE",
        "LONG_TYPE",
        "FLOAT_TYPE",
        "STRING_TYPE",
        "ENUM_TYPE",
        "FILE_TYPE",
    ]
    value: JsonValue

    @model_validator(mode="after")
    def typed_value(self) -> Self:
        value = self.value
        if self.type == "BOOLEAN_TYPE":
            valid = type(value) is bool
        elif self.type in ("INT_TYPE", "LONG_TYPE"):
            bits = 32 if self.type == "INT_TYPE" else 64
            valid = type(value) is int and -(2 ** (bits - 1)) <= value < 2 ** (bits - 1)
        elif self.type == "FLOAT_TYPE":
            valid = type(value) is float and math.isfinite(value)
        elif self.type == "FILE_TYPE":
            valid = value is None
        elif self.type == "ENUM_TYPE":
            valid = isinstance(value, str)
        else:
            valid = value is None or isinstance(value, str)
        if not valid:
            raise ValueError(f"invalid typed analyzer value: {self.name}")
        return self


class GhidraOptions(Record):
    ghidra_version: Literal["11.4.3"]
    pyghidra_version: Literal["2.2.1"]
    language_id: Literal["x86:LE:64:default"]
    compiler_spec_id: Literal["gcc"]
    executable_format: Literal["Executable and Linking Format (ELF)"]
    image_base: Literal["0x00000000"]
    options: list[AnalyzerOption]

    @model_validator(mode="after")
    def pinned_analyzers(self) -> Self:
        names = [item.name for item in self.options]
        if names != sorted(set(names)):
            raise ValueError("analyzer options must be sorted and unique")
        values = {item.name: item.value for item in self.options}
        if any(values.get(name) is not False for name in ("Function ID", "Find Crypt")):
            raise ValueError("Function ID and Find Crypt must be disabled")
        if any(
            values.get(name) != 1
            for name in ("Stack.Max Threads", "x86 Constant Reference Analyzer.Max Threads")
        ):
            raise ValueError("analyzer thread counts must be one")
        return self

    @classmethod
    def read(cls, path: Path) -> Self:
        if any(component.is_symlink() for component in (path, *path.parents)):
            raise ValueError("analysis options cannot be a symlink")
        return cls.model_validate_json(path.read_bytes())


class BodyRange(Strict):
    start: Address
    end: Address

    @model_validator(mode="after")
    def positive_range(self) -> Self:
        if int(self.start, 16) >= int(self.end, 16):
            raise ValueError("function body range must be nonempty and half-open")
        return self


class CallSite(Strict):
    address: Address
    kind: Kind
    target: Target | None
    argument_registers: list[Literal["rdi", "rsi", "rdx", "rcx", "r8", "r9"]] | None = None


class ConstantMatch(Strict):
    kind: Literal["constant_match"] = "constant_match"
    family: Literal["crc32", "adler32", "fnv", "djb2", "base64"]
    name: str = Field(min_length=1)
    address: Address
    location: Literal["immediate", "readonly_table"]


class FunctionInfo(Strict):
    entry: Address
    body_ranges: list[BodyRange] = Field(min_length=1)
    is_thunk: bool
    import_name: str | None = None
    decompiler_param_count: int | None = Field(default=None, ge=0)
    is_variadic_like: bool = False
    body_complete: bool = False
    call_sites: list[CallSite] = Field(default_factory=lambda: list[CallSite]())

    constants: list[ConstantMatch] = Field(default_factory=lambda: list[ConstantMatch]())


class GhidraAnalysis(Record):
    binary_sha256: Sha256
    options_sha256: Sha256
    ghidra_version: Literal["11.4.3"] = "11.4.3"
    pyghidra_version: Literal["2.2.1"] = "2.2.1"
    image_base: Literal["0x00000000"] = "0x00000000"
    functions: list[FunctionInfo] = Field(max_length=2000)
    missing_subjects: list[Address] = Field(default_factory=lambda: list[Address]())

    @model_validator(mode="after")
    def ordered(self) -> Self:
        entries = [function.entry for function in self.functions]
        if entries != sorted(set(entries), key=lambda address: int(address, 16)):
            raise ValueError("function entries must be sorted and unique")
        if self.missing_subjects != sorted(set(self.missing_subjects), key=lambda a: int(a, 16)):
            raise ValueError("missing subjects must be sorted and unique")
        for function in self.functions:
            site_keys = [(int(s.address, 16), s.kind, s.target or "") for s in function.call_sites]
            if site_keys != sorted(set(site_keys)):
                raise ValueError("call sites must be sorted and unique")

            keys = [(int(m.address, 16), m.family, m.name, m.location) for m in function.constants]
            if keys != sorted(set(keys)):
                raise ValueError("constant matches must be sorted and unique")
            previous = -1
            for region in function.body_ranges:
                if int(region.start, 16) < previous:
                    raise ValueError("function body ranges must be ordered and disjoint")
                previous = int(region.end, 16)
        return self


def publish_immutable(path: Path, payload: bytes) -> None:
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError("analysis input/cache cannot be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(name, path)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise ValueError("non-deterministic analysis input/cache collision") from None
    finally:
        Path(name).unlink(missing_ok=True)


class GhidraAnalysisCache:
    def __init__(self, runner: JobRunner, root: Path):
        self.runner = runner
        self.root = root
        self.last_measurement: dict[str, int] | None = None
        self.last_artifact: str | None = None

    def analyze(
        self,
        binary: BinaryRef,
        options_path: Path,
        *,
        no_cache: bool = False,
        subjects: list[str] | None = None,
    ) -> GhidraAnalysis:
        self.last_measurement = None
        self.last_artifact = None
        options = GhidraOptions.read(options_path)
        inputs = self.runner.input_root / "in"
        if any(component.is_symlink() for component in (binary.stripped, *binary.stripped.parents)):
            raise ValueError("public binary cannot be a symlink")
        with binary.stripped.open("rb") as stream:
            payload = stream.read(20 * 1024 * 1024 + 1)
        if len(payload) > 20 * 1024 * 1024:
            raise ValueError("binary exceeds the Phase 1A size limit")
        if hashlib.sha256(payload).hexdigest() != binary.binary_sha256:
            raise ValueError("public binary content/hash mismatch")
        publish_immutable(inputs / (binary.binary_sha256 + ".bin"), payload)
        option_bytes = options_path.read_bytes()
        if GhidraOptions.model_validate_json(option_bytes) != options:
            raise ValueError("analysis options changed while staging")
        option_hash = hashlib.sha256(option_bytes).hexdigest()
        publish_immutable(inputs / (option_hash + ".json"), option_bytes)
        params: dict[str, JsonValue] = {
            "ghidra_version": options.ghidra_version,
            "options_sha256": option_hash,
            "env_digest": self.runner.config.image_analysis,
        }
        if subjects:
            entries = TypeAdapter(list[Address]).validate_python(subjects)
            if len(entries) > 2000:
                raise ValueError("too many requested subjects")
            params["subjects"] = cast(JsonValue, sorted(set(entries), key=lambda a: int(a, 16)))
        job = Job.create(
            "ghidra_analyze",
            {
                "binary": "in/" + binary.binary_sha256 + ".bin",
                "options": "in/" + option_hash + ".json",
            },
            params,
        )
        pointer = self.root / (job.job_id + ".artifact")
        if any(component.is_symlink() for component in (pointer, *pointer.parents)):
            raise ValueError("analysis cache cannot be a symlink")
        if not no_cache and pointer.exists():
            self.last_artifact = pointer.read_text()
            result = JobResult.model_validate_json(self.runner.artifacts.get(self.last_artifact))
        else:
            handle = self.runner.submit(job)
            result = self.runner.wait(handle)
            self.last_artifact = handle.result_artifact
            if result.status == "ok":
                import json

                measurement = json.loads((handle.directory / "out/measurement.json").read_bytes())
                peak = measurement["peak_rss_bytes"]
                if type(peak) is not int or peak <= 0:
                    raise ValueError("invalid analysis peak-RAM measurement")
                self.last_measurement = {"peak_rss_bytes": peak}
        if result.job_id != job.job_id or result.status != "ok":
            raise RuntimeError(f"ghidra_analyze failed: {result.error_code}: {result.output}")
        analysis = GhidraAnalysis.model_validate(result.output["analysis"])
        if (analysis.binary_sha256, analysis.options_sha256) != (binary.binary_sha256, option_hash):
            raise ValueError("cached analysis input identity mismatch")
        if self.last_artifact is None:
            raise RuntimeError("analysis result artifact is missing")
        publish_immutable(pointer, self.last_artifact.encode())
        return analysis
