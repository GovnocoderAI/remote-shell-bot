from __future__ import annotations

from pathlib import Path

from rsb.net.vpn import (
    WireGuardConfig,
    is_admin,
    parse_wireguard_configs,
    read_local_configs,
    read_source_urls,
)

SAMPLE = """
[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32
DNS = 1.1.1.1
# Name = office

[Peer]
PublicKey = bbbb
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
"""


def test_parse_single_config() -> None:
    configs = parse_wireguard_configs(SAMPLE, "test")
    assert len(configs) == 1
    assert configs[0].endpoint == "vpn.example.com:51820"
    assert "PrivateKey" in configs[0].text
    assert configs[0].name.startswith("office-")


def test_parse_skips_incomplete_blocks() -> None:
    text = "[Interface]\nPrivateKey = aaaa\n"
    assert parse_wireguard_configs(text) == []


def test_parse_multiple_configs_and_dedupe() -> None:
    text = SAMPLE + SAMPLE.replace("vpn.example.com", "second.example.com")
    configs = parse_wireguard_configs(text)
    assert len(configs) == 2
    assert {config.endpoint for config in configs} == {
        "vpn.example.com:51820",
        "second.example.com:51820",
    }


def test_read_local_configs(tmp_path: Path) -> None:
    (tmp_path / "one.conf").write_text(SAMPLE, encoding="utf-8")
    (tmp_path / "bad.conf").write_text("not a config", encoding="utf-8")
    configs = read_local_configs(tmp_path)
    assert len(configs) == 1


def test_read_source_urls(tmp_path: Path) -> None:
    path = tmp_path / "sources.txt"
    path.write_text("# comment\nhttps://example.com/list.txt\nftp://bad\n", encoding="utf-8")
    assert read_source_urls(path) == ["https://example.com/list.txt"]


def test_wireguard_config_keeps_endpoint() -> None:
    config = WireGuardConfig("name", SAMPLE, "vpn.example.com:51820")
    assert config.endpoint == "vpn.example.com:51820"


def test_admin_detection_returns_bool() -> None:
    assert isinstance(is_admin(), bool)


async def test_active_vpn_is_detected(monkeypatch, settings) -> None:
    from rsb.net.diagnostics import ProbeResult
    from rsb.net.vpn import ensure_vpn

    async def fake_probe(url, wait_seconds=6.0, name="vpn.health"):
        return ProbeResult(name, True, "HTTP 200", 5.0)

    monkeypatch.setattr("rsb.net.vpn.detect_vpn_interfaces", lambda: ["wg0"])
    monkeypatch.setattr("rsb.net.vpn.probe_http", fake_probe)
    session = await ensure_vpn(settings, "https://relay.example/healthz")
    assert session.connected
    assert session.temporary is False
    assert session.adapter == "wg0"


async def test_missing_wireguard_is_reported(monkeypatch, settings) -> None:
    from rsb.net.vpn import ensure_vpn

    monkeypatch.setattr("rsb.net.vpn.detect_vpn_interfaces", lambda: [])
    monkeypatch.setattr("rsb.net.vpn.wireguard_binary", lambda: None)
    session = await ensure_vpn(settings, "https://relay.example/healthz")
    assert not session.connected
    assert "WireGuard" in session.detail
