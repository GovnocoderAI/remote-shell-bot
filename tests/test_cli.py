from __future__ import annotations

from typer.testing import CliRunner

from rsb.cli import app

runner = CliRunner()


def test_help_lists_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "server" in result.output
    assert "agent" in result.output
    assert "enroll" in result.output


def test_agent_requires_enrollment(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["agent", "--data-dir", str(tmp_path / "data")])
    assert result.exit_code == 2
    assert "configuration not found" in result.output


def test_server_requires_configuration(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    for variable in ("RSB_BOT_TOKEN", "RSB_ADMIN_IDS", "RSB_SECRET_KEY"):
        monkeypatch.delenv(variable, raising=False)
    result = runner.invoke(app, ["server", "--host", "127.0.0.1"])
    assert result.exit_code == 2
    assert "Configuration error" in result.output
