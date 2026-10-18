"""WSL transport to the existing Windows-only local runtime; no listener changes."""

import base64
import shutil
import subprocess
from pathlib import Path

from aletheia.llm.provider import (
    ChatRequest,
    ChatResponse,
    OpenAICompatibleProvider,
    ProviderRejected,
    ProviderUnavailable,
)
from aletheia.schema.canonical import canonical_bytes

# No request text is interpolated into code. The fixed endpoint cannot select a hosted model.
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
$envelope = [Console]::In.ReadToEnd() | ConvertFrom-Json
$body = $envelope.request | ConvertTo-Json -Depth 100 -Compress
$showBody = @{ model = $envelope.request.model } | ConvertTo-Json -Compress
$show = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/show' -Method Post `
    -ContentType 'application/json' -Body $showBody -TimeoutSec 15
$weight = 'sha256-' + $envelope.model_file_sha256
if (!$show.modelfile.Contains($weight) -or $show.parameters -notmatch 'num_ctx\s+32768') {
    exit 3
}
$parameters = @{
    Uri = 'http://127.0.0.1:11434/v1/chat/completions'
    Method = 'Post'
    ContentType = 'application/json'
    Body = [Text.Encoding]::UTF8.GetBytes($body)
    TimeoutSec = 115
    MaximumRedirection = 0
}
$response = Invoke-WebRequest -UseBasicParsing @parameters
[Console]::Out.Write($response.Content)
} catch {
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
        if (@(408, 425, 429) -contains $statusCode) { exit 1 }
        if ($statusCode -ge 400 -and $statusCode -lt 500) { exit 4 }
    }
    exit 1
}

"""


def windows_working_directory() -> Path | None:
    # Windows may not be able to resolve another WSL user's Linux working directory.
    executable = shutil.which("powershell.exe")
    return Path(executable).parent if executable else None


class WindowsLoopbackProvider(OpenAICompatibleProvider):
    id = "openai-compatible-windows-loopback"

    def send(self, req: ChatRequest) -> ChatResponse:
        if self.config.hosted or self.config.base_url != "http://127.0.0.1:11434/v1":
            raise ValueError("Windows bridge requires the fixed local Ollama endpoint")
        encoded = base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")
        try:
            response = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-EncodedCommand",
                    encoded,
                ],
                input=canonical_bytes(
                    {
                        "request": self.payload(req),
                        "model_file_sha256": self.config.model_file_sha256,
                    }
                ),
                capture_output=True,
                cwd=windows_working_directory(),
                timeout=120,
                check=False,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise ProviderUnavailable("local runtime transport unavailable") from exc
        if response.returncode == 3:
            raise ProviderRejected("model_pin_mismatch")
        if response.returncode == 4:
            raise ProviderRejected("provider_request_rejected")
        if response.returncode:
            # Never include request contents or PowerShell's echoed command in errors.
            raise ProviderUnavailable("local runtime request failed")
        if len(response.stdout) > 32 * 1024 * 1024:
            raise ValueError("provider response too large")
        return self.parse(response.stdout)
