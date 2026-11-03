from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class CommandResult:
    output: str
    exit_code: int | None
    cwd: str
    truncated: bool
    timed_out: bool


class ShellRunner:
    def __init__(self, max_output_bytes: int, timeout_seconds: int) -> None:
        self.max_output_bytes = max_output_bytes
        self.timeout_seconds = timeout_seconds
        self._is_windows = os.name == "nt"
        if self._is_windows:
            self._shell = shutil.which("powershell.exe") or shutil.which("pwsh")
        else:
            self._shell = "/bin/bash" if Path("/bin/bash").exists() else "/bin/sh"

    async def run(self, command: str, cwd: Path) -> CommandResult:
        change = self._change_directory(command, cwd)
        if change is not None:
            target, error = change
            if error is not None:
                return CommandResult(error, 1, str(cwd), False, False)
            return CommandResult("", 0, str(target), False, False)
        if self._is_windows:
            prefix = (
                "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                "$OutputEncoding=[System.Text.Encoding]::UTF8; "
            )
            arguments = [
                self._shell or "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                prefix + command,
            ]
        else:
            arguments = [self._shell, "-lc", command]
        environment = {
            key: value for key, value in os.environ.items() if not key.upper().startswith("RSB_")
        }
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        process = await asyncio.create_subprocess_exec(
            *arguments,
            cwd=str(cwd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=environment,
            start_new_session=not self._is_windows,
            creationflags=creationflags if self._is_windows else 0,
        )
        assert process.stdout is not None
        reader = asyncio.create_task(self._read_output(process.stdout))
        timed_out = False
        try:
            await asyncio.wait_for(process.wait(), timeout=self.timeout_seconds)
        except TimeoutError:
            timed_out = True
            await self._terminate(process)
            await process.wait()
        output, truncated = await reader
        text = output.decode("utf-8", errors="replace")
        return CommandResult(
            output=text,
            exit_code=None if timed_out else process.returncode,
            cwd=str(cwd),
            truncated=truncated,
            timed_out=timed_out,
        )

    async def _read_output(self, stream: asyncio.StreamReader) -> tuple[bytes, bool]:
        buffer = bytearray()
        truncated = False
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            remaining = self.max_output_bytes - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
            else:
                truncated = True
        return bytes(buffer), truncated

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        try:
            if self._is_windows:
                await asyncio.to_thread(
                    subprocess.run,
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except ProcessLookupError:
                return

    def _change_directory(self, command: str, cwd: Path) -> tuple[Path, str | None] | None:
        try:
            tokens = shlex.split(command, posix=not self._is_windows)
        except ValueError:
            return None
        if not tokens or tokens[0].lower() not in {"cd", "chdir"}:
            return None
        if len(tokens) == 1:
            target = Path.home()
        elif len(tokens) == 2:
            target = Path(tokens[1].strip("'\""))
        else:
            return None
        expanded = Path(os.path.expandvars(str(target))).expanduser()
        resolved = expanded if expanded.is_absolute() else (cwd / expanded)
        try:
            resolved = Path(os.path.normpath(str(resolved)))
        except OSError:
            return None
        if not resolved.is_dir():
            return resolved, f"cd: directory not found: {resolved}"
        return resolved, None
