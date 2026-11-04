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


def test_netcheck_help() -> None:
    result = runner.invoke(app, ["netcheck", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.output
    assert "--no-telegram" in result.output


def test_connect_help() -> None:
    result = runner.invoke(app, ["connect", "--help"])
    assert result.exit_code == 0
    assert "--no-public-proxies" in result.output
    assert "--vpn" in result.output
    assert "--proxy" in result.output


def test_vpn_status(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["vpn", "status", "--data-dir", str(tmp_path / "data")])
    assert result.exit_code == 0
    assert "WireGuard" in result.output
    assert "Активные VPN" in result.output


def test_network_settings(tmp_path) -> None:
    from rsb.config import Settings

    settings = Settings(
        data_dir=tmp_path,
        public_proxy_sources="https://a.example/list, https://b.example/list",
        vpn_sources="https://c.example/vpn",
    )
    assert settings.public_source_urls == [
        "https://a.example/list",
        "https://b.example/list",
    ]
    assert settings.vpn_source_urls == ["https://c.example/vpn"]
    assert settings.resolved_proxy_file == tmp_path / "proxies.txt"
    assert settings.resolved_vpn_dir == tmp_path / "vpn"
