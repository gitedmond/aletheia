"""Opaque content-addressed bytes. Never parses binaries."""

import hashlib
import os
import re
import tempfile
from pathlib import Path


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("artifact requires full sha256 digest")
        value = digest[7:]
        path = self.root / value[:2] / value
        if not path.parent.resolve().is_relative_to(self.root) or path.is_symlink():
            raise ValueError("artifact path escapes store")
        return path

    def put(self, data: bytes) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        path = self._path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                self.get(digest)
            # fsync(file) does not persist the link or a newly created fanout directory.
            for directory in (path.parent, self.root):
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)
        return digest

    def get(self, digest: str) -> bytes:
        data = self._path(digest).read_bytes()
        if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("artifact content hash mismatch")
        return data
