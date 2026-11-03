from __future__ import annotations

import os

import pytest

from rsb.agent.executor import ShellRunner


def _runner() -> ShellRunner:
    return ShellRunner(max_output_bytes=4096, timeout_seconds=30)


async def test_command_output(tmp_path) -> None:
    command = "Write-Output ok" if os.name == "nt" else "printf ok"
    result = await _runner().run(command, tmp_path)
    assert result.exit_code == 0
    assert "ok" in result.output
    assert str(tmp_path) == result.cwd


async def test_change_directory_is_tracked(tmp_path) -> None:
    target = tmp_path / "sub"
    target.mkdir()
    result = await _runner().run(f'cd "{target}"', tmp_path)
    assert result.exit_code == 0
    assert result.cwd == str(target)
    assert result.output == ""


async def test_missing_directory_reports_error(tmp_path) -> None:
    missing = tmp_path / "missing"
    result = await _runner().run(f'cd "{missing}"', tmp_path)
    assert result.exit_code == 1
    assert "not found" in result.output
    assert result.cwd == str(tmp_path)


async def test_timeout_is_enforced(tmp_path) -> None:
    command = "Start-Sleep -Seconds 10" if os.name == "nt" else "sleep 10"
    runner = ShellRunner(max_output_bytes=1024, timeout_seconds=1)
    result = await runner.run(command, tmp_path)
    assert result.timed_out
    assert result.exit_code is None


async def test_windows_utf8_output(tmp_path) -> None:
    if os.name != "nt":
        pytest.skip("windows only")
    result = await _runner().run("Write-Output 'привет мир'", tmp_path)
    assert result.exit_code == 0
    assert "привет мир" in result.output


async def test_output_is_truncated(tmp_path) -> None:
    command = (
        "1..200 | ForEach-Object { 'x' * 40 }"
        if os.name == "nt"
        else "for i in $(seq 1 200); do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n'; done"
    )
    runner = ShellRunner(max_output_bytes=256, timeout_seconds=30)
    result = await runner.run(command, tmp_path)
    assert result.truncated
    assert len(result.output.encode("utf-8")) <= 256
