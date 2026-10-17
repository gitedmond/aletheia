"""Opaque host-side MCP stdio client with the production container policy."""

import hashlib
import os
import select
import subprocess
import time
from pathlib import Path
from typing import Any

from pydantic import JsonValue, TypeAdapter

from aletheia.analysis.ghidra_session import publish_immutable, read_public_binary
from aletheia.config import Sandbox
from aletheia.heldout.guard import PrivateGuard
from aletheia.llm.provider import ToolFunction, ToolSpec
from aletheia.sandbox.policy import container_args
from aletheia.schema.canonical import canonical_bytes
from aletheia.sources.base import BinaryRef


class UpstreamCrash(RuntimeError):
    """The isolated upstream process stopped; the loop may restart it once."""


class GhidraUpstream:
    def __init__(
        self, config: Sandbox, binary: BinaryRef, options: Path, root: Path, *, guard: PrivateGuard
    ):
        root = guard.private_output(root) if guard.split == "heldout" else guard.public_path(root)
        if any(p.is_symlink() for p in (root, *root.parents)):
            raise ValueError("upstream root cannot be a symlink")
        self.config, self.root = config.model_copy(deep=True), root
        self.inputs, self.outputs = root / "in", root / "out"
        self.inputs.mkdir(parents=True, exist_ok=True)
        self.outputs.mkdir(parents=True, exist_ok=True)
        self.binary_name = binary.binary_sha256 + ".bin"
        publish_immutable(self.inputs / self.binary_name, read_public_binary(binary))
        if any(p.is_symlink() for p in (options, *options.parents)):
            raise ValueError("analysis options cannot be a symlink")
        payload = options.read_bytes()
        self.options_name = hashlib.sha256(payload).hexdigest() + ".json"
        publish_immutable(self.inputs / self.options_name, payload)
        self.sequence = 0
        self.process: subprocess.Popen[bytes] | None = None
        try:
            self.start()
        except Exception:
            self.close()
            raise

    def start(self) -> None:
        self.close()
        args = [
            "docker",
            "run",
            "--rm",
            "-i",
            *container_args(self.config, self.inputs, self.outputs, os.getuid(), os.getgid()),
            "--entrypoint",
            "python",
            self.config.image_analysis,
            "-m",
            "aletheia.agent.ghidra_mcp",
            "/job/in/" + self.binary_name,
            "/job/in/" + self.options_name,
        ]
        with (self.outputs / "upstream.stderr.log").open("ab") as stderr:
            self.process = subprocess.Popen(
                args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, bufsize=0
            )
        self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "aletheia", "version": "0.1.0"},
            },
            timeout=300,
        )
        self.write({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def write(self, message: dict[str, JsonValue]) -> None:
        if self.process is None or self.process.stdin is None or self.process.poll() is not None:
            raise UpstreamCrash("ghidra_crash")
        try:
            self.process.stdin.write(canonical_bytes(message) + b"\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise UpstreamCrash("ghidra_crash") from exc

    def rpc(self, method: str, params: dict[str, JsonValue], *, timeout: int = 60) -> JsonValue:
        self.sequence += 1
        self.write({"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params})
        assert self.process is not None and self.process.stdout is not None
        deadline, line = time.monotonic() + timeout, bytearray()
        while time.monotonic() < deadline:
            ready, _, _ = select.select(
                [self.process.stdout], [], [], max(0, deadline - time.monotonic())
            )
            if not ready:
                break
            byte = self.process.stdout.read(1)
            if not byte:
                raise UpstreamCrash("ghidra_crash")
            line.extend(byte)
            if len(line) > 8 * 1024 * 1024:
                raise UpstreamCrash("upstream response exceeds limit")
            if byte != b"\n":
                continue
            data = TypeAdapter(dict[str, Any]).validate_json(bytes(line))
            line.clear()
            if data.get("id") != self.sequence:
                continue
            if "error" in data:
                raise ValueError("upstream_tool_error")
            return TypeAdapter(JsonValue).validate_python(data["result"])
        raise TimeoutError("upstream_timeout")

    def tools(self) -> list[ToolSpec]:
        listing = TypeAdapter(dict[str, Any]).validate_python(self.rpc("tools/list", {}))
        return [
            ToolSpec(
                function=ToolFunction(
                    name=tool["name"],
                    description=tool.get("description", ""),
                    parameters=tool["inputSchema"],
                )
            )
            for tool in listing["tools"]
        ]

    def call(self, name: str, arguments: dict[str, JsonValue]) -> JsonValue:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self.process is not None:
            if self.process.stdin:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
            self.process = None
