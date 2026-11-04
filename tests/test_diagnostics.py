from __future__ import annotations

from rsb.net.diagnostics import (
    detect_vpn_interfaces,
    is_vpn_name,
    relay_health_url,
    relay_parts,
    run_diagnostics,
    system_proxy_env,
)


def test_relay_parts_for_wss() -> None:
    host, port, secure = relay_parts("wss://support.example.com")
    assert host == "support.example.com"
    assert port == 443
    assert secure is True


def test_relay_parts_for_ws_with_port() -> None:
    host, port, secure = relay_parts("ws://127.0.0.1:8080")
    assert host == "127.0.0.1"
    assert port == 8080
    assert secure is False


def test_relay_health_url() -> None:
    assert relay_health_url("wss://support.example.com") == "https://support.example.com/healthz"
    assert relay_health_url("ws://127.0.0.1:8080") == "http://127.0.0.1:8080/healthz"


def test_vpn_name_detection() -> None:
    assert is_vpn_name("wg0")
    assert is_vpn_name("WireGuard Tunnel")
    assert is_vpn_name("tailscale0")
    assert not is_vpn_name("Ethernet")
    assert not is_vpn_name("Teredo Tunneling Pseudo-Interface")


def test_system_proxy_env_is_redacted(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@127.0.0.1:8080")
    values = system_proxy_env()
    assert values["HTTPS_PROXY"] == "http://user:***@127.0.0.1:8080"


async def test_run_diagnostics_marks_unreachable(monkeypatch) -> None:
    from rsb.net.diagnostics import ProbeResult

    def failing(name):
        async def probe(*args, **kwargs):
            return ProbeResult(name, False, "unreachable")

        return probe

    monkeypatch.setattr("rsb.net.diagnostics.probe_tcp", failing("relay.tcp"))
    monkeypatch.setattr("rsb.net.diagnostics.probe_tls", failing("relay.tls"))
    monkeypatch.setattr("rsb.net.diagnostics.probe_http", failing("relay.health"))
    monkeypatch.setattr("rsb.net.diagnostics.probe_websocket", failing("relay.websocket"))
    monkeypatch.setattr("rsb.net.diagnostics.detect_vpn_interfaces", lambda: ["wg0"])
    report = await run_diagnostics(
        "wss://support.example.com", wait_seconds=0.1, include_telegram=False
    )
    assert report.host == "support.example.com"
    assert report.vpn_interfaces == ["wg0"]
    assert "недоступен" in report.verdict
    names = {item.name for item in report.results}
    assert {"relay.tcp", "relay.tls", "relay.health", "relay.websocket"} <= names


def test_detect_vpn_interfaces_returns_list() -> None:
    interfaces = detect_vpn_interfaces()
    assert isinstance(interfaces, list)
