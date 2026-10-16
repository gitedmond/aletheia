"""Resolve paths before allowing access to the configured private corpus."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

Split = Literal["dev", "heldout"]


class PrivateAccessError(ValueError):
    """A private operation lacks an explicit held-out scope (CLI exit 7)."""


@dataclass(frozen=True)
class PrivateGuard:
    root: Path | None
    split: Split = "dev"

    def __post_init__(self) -> None:
        if self.split == "heldout" and self.root is None:
            raise PrivateAccessError("private_root is required for --split heldout")
        if self.root is not None:
            if not self.root.is_absolute():
                raise PrivateAccessError("private_root must be absolute")
            object.__setattr__(self, "root", self.root.resolve())

    def access(self, path: Path) -> Path:
        resolved = path.resolve()
        if self.root is not None and resolved.is_relative_to(self.root) and self.split != "heldout":
            raise PrivateAccessError("private path requires --split heldout")
        return resolved

    def public_path(self, path: Path) -> Path:
        resolved = path.resolve()
        if self.root is not None and (
            resolved.is_relative_to(self.root) or self.root.is_relative_to(resolved)
        ):
            raise PrivateAccessError("public and private storage paths must not overlap")
        return resolved

    def private_output(self, path: Path) -> Path:
        resolved = self.access(path)
        if self.root is None or not resolved.is_relative_to(self.root) or self.split != "heldout":
            raise PrivateAccessError(
                "private output must be under private_root with --split heldout"
            )
        return resolved
