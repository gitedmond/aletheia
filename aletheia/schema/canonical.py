"""Canonical JSON is a wire contract, independent of analysis code."""

import hashlib
import json
import math
from typing import cast

from pydantic import BaseModel, JsonValue

type CanonicalInput = JsonValue | BaseModel


def _rounded(value: JsonValue) -> JsonValue:
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        number = round(value, 6)
        return 0.0 if number == 0 else number
    if isinstance(value, list):
        return [_rounded(item) for item in value]
    if isinstance(value, dict):
        return {key: _rounded(item) for key, item in value.items()}
    return value


def canonical_bytes(value: CanonicalInput) -> bytes:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        _rounded(raw), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def content_hash(value: CanonicalInput) -> str:
    if isinstance(value, BaseModel):
        informational: set[str] = set()
        for name, field in type(value).model_fields.items():
            extra: object = field.json_schema_extra
            if isinstance(extra, dict):
                metadata = cast(dict[str, JsonValue], extra)
                if metadata.get("informational") is True:
                    informational.add(name)
        value = value.model_dump(mode="json", exclude=informational)
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
