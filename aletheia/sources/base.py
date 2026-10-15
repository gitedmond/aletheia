"""Public binary references accepted by claim sources; never private corpus data."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aletheia.schema.models import Claim, Targets


@dataclass(frozen=True)
class BinaryRef:
    binary_sha256: str
    stripped: Path
    variant_id: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256) is None or not self.variant_id:
            raise ValueError("invalid public binary identity")
        if (
            self.stripped.name != self.binary_sha256 + ".bin"
            or self.stripped.parent.name != "stripped"
            or any(p in ("private", "corpus", "tests") for p in self.stripped.parts)
        ):
            raise ValueError("source requires a hash-named stripped public binary")
        if any(p.is_symlink() for p in (self.stripped, *self.stripped.parents)):
            raise ValueError("public binary cannot be a symlink")


class ClaimSource(Protocol):
    origin: str
    source_id: str

    def produce(self, binary: BinaryRef, targets: Targets) -> list[Claim]: ...
