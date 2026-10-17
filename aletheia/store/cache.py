"""Explicit semantic keys. Provenance and requesting identity never participate."""

from pydantic import Field, JsonValue

from aletheia.schema.canonical import content_hash
from aletheia.schema.models import Claim, Digest, Sha256, Strict


class CacheContext(Strict):
    verifier_version: str
    method_versions: list[str]
    pack_hashes: dict[str, Sha256]
    env_digest: Digest
    analysis_options_hash: Sha256
    taxonomy_version: str = "1.0"
    purpose_packs_hash: Sha256 | None = None
    harness: dict[str, JsonValue] = Field(min_length=1)


def verdict_cache_key(claim: Claim, context: CacheContext) -> str:
    value = claim.model_dump(
        mode="json",
        include={
            "binary_sha256",
            "schema_version",
            "subject",
            "type",
            "body",
            "algorithms_version",
        },
    )
    config = context.model_dump(mode="json")
    config["method_versions"] = sorted(set(context.method_versions))
    return content_hash({"claim": value, "configuration": config})
