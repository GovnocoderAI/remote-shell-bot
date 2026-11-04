from __future__ import annotations

from pathlib import Path

import pytest

from rsb.errors import ConfigError
from rsb.net.pool import FallbackResolver, StaticResolver, select_proxy
from rsb.net.proxy import ProxyCandidate

HEALTH = "https://relay.example/healthz"


def _probe(ok_proxies: set[str | None], latency: float = 10.0):
    async def fake_probe(url, proxy=None, wait_seconds=4.0, name="probe"):
        from rsb.net.diagnostics import ProbeResult

        ok = proxy in ok_proxies
        return ProbeResult(name, ok, "HTTP 200" if ok else "failed", latency if ok else None)

    return fake_probe


async def test_direct_connection_is_preferred(monkeypatch) -> None:
    from rsb.net.diagnostics import ProbeResult

    fake = _probe({None})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)

    async def ws_ok(*args, **kwargs):
        return ProbeResult("direct.websocket", True, "ok", 5.0)

    monkeypatch.setattr("rsb.net.pool.probe_websocket", ws_ok)
    selection = await select_proxy(HEALTH, allow_public=False, relay_url="wss://relay.example")
    assert selection.source == "direct"
    assert selection.proxy is None
    assert isinstance(selection.resolver, StaticResolver)


async def test_direct_http_without_websocket_falls_back(monkeypatch) -> None:
    from rsb.net.diagnostics import ProbeResult

    fake = _probe({None, "http://127.0.0.1:3128"})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)

    async def ws_fail(*args, **kwargs):
        return ProbeResult("direct.websocket", False, "blocked", None)

    monkeypatch.setattr("rsb.net.pool.probe_websocket", ws_fail)
    selection = await select_proxy(
        HEALTH,
        explicit=["http://127.0.0.1:3128"],
        allow_public=False,
        relay_url="wss://relay.example",
    )
    assert selection.source == "explicit"
    assert selection.proxy == "http://127.0.0.1:3128"


async def test_configured_proxy_is_selected(monkeypatch) -> None:
    fake = _probe({"http://127.0.0.1:3128"})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)
    selection = await select_proxy(
        HEALTH,
        explicit=["http://127.0.0.1:3128"],
        allow_public=False,
    )
    assert selection.source == "explicit"
    assert selection.proxy == "http://127.0.0.1:3128"
    assert await selection.resolver.next_proxy() == "http://127.0.0.1:3128"


async def test_proxy_file_is_used(monkeypatch, tmp_path: Path) -> None:
    proxy_file = tmp_path / "proxies.txt"
    proxy_file.write_text("socks5://127.0.0.1:1080\n", encoding="utf-8")
    fake = _probe({"socks5://127.0.0.1:1080"})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)
    selection = await select_proxy(HEALTH, proxy_file=proxy_file, allow_public=False)
    assert selection.proxy == "socks5://127.0.0.1:1080"


async def test_public_discovery_is_used_when_enabled(monkeypatch) -> None:
    fake = _probe(set())
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)

    async def fake_discover(health_url, **kwargs):
        from rsb.net.discovery import DiscoveryReport

        return [ProxyCandidate("http://public.example:8080", "public")], DiscoveryReport()

    monkeypatch.setattr("rsb.net.pool.discover_public", fake_discover)
    selection = await select_proxy(HEALTH, allow_public=True)
    assert selection.public_used is True
    assert selection.proxy == "http://public.example:8080"
    assert selection.warnings


async def test_no_working_proxy_raises(monkeypatch) -> None:
    fake = _probe(set())
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)
    with pytest.raises(ConfigError):
        await select_proxy(HEALTH, allow_public=False)


async def test_fallback_resolver_rotates_on_failure() -> None:
    resolver = FallbackResolver(
        [
            ProxyCandidate("http://a.example:8080"),
            ProxyCandidate("http://b.example:8080"),
        ],
        health_url=HEALTH,
        allow_public=False,
    )
    first = await resolver.next_proxy()
    assert first == "http://a.example:8080"
    resolver.report_failure(first)
    second = await resolver.next_proxy()
    assert second == "http://b.example:8080"
    resolver.report_failure(second)
    assert await resolver.next_proxy() is None


async def test_forced_proxy_mode_skips_direct(monkeypatch) -> None:
    fake = _probe({None, "http://127.0.0.1:3128"})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)
    selection = await select_proxy(
        HEALTH,
        explicit=["http://127.0.0.1:3128"],
        allow_direct=False,
        allow_public=False,
    )
    assert selection.source == "explicit"
    assert selection.proxy == "http://127.0.0.1:3128"


async def test_invalid_explicit_proxy_raises() -> None:
    with pytest.raises(ConfigError):
        await select_proxy(
            HEALTH,
            explicit=["ftp://proxy.example:21"],
            allow_direct=False,
            allow_public=False,
        )


async def test_proxy_websocket_precheck_prefers_working(monkeypatch) -> None:
    from rsb.net.diagnostics import ProbeResult

    good = "http://b.example:8080"
    fake = _probe({"http://a.example:8080", good})
    monkeypatch.setattr("rsb.net.pool.probe_http", fake)
    monkeypatch.setattr("rsb.net.discovery.probe_http", fake)

    async def ws_probe(relay_url, proxy=None, wait_seconds=4.0, name="proxy.websocket"):
        ok = proxy == good
        return ProbeResult(name, ok, "ok" if ok else "failed", 5.0 if ok else None)

    monkeypatch.setattr("rsb.net.pool.probe_websocket", ws_probe)
    selection = await select_proxy(
        HEALTH,
        explicit=["http://a.example:8080", good],
        allow_direct=False,
        allow_public=False,
        relay_url="wss://relay.example",
    )
    assert selection.proxy == good
