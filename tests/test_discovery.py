from __future__ import annotations

from pathlib import Path

from rsb.net.discovery import (
    is_public_host,
    load_cache,
    probe_candidates,
    save_cache,
)
from rsb.net.proxy import ProxyCandidate
from rsb.util import iso_in, parse_iso, to_iso, utcnow


def test_public_host_detection() -> None:
    assert is_public_host("8.8.8.8")
    assert is_public_host("example.com")
    assert not is_public_host("127.0.0.1")
    assert not is_public_host("10.0.0.1")
    assert not is_public_host("192.168.1.1")
    assert not is_public_host("::1")
    assert not is_public_host("printer.local")


async def test_probe_candidates_sorts_by_latency(monkeypatch) -> None:
    async def fake_probe(url, proxy=None, wait_seconds=4.0, name="proxy.health"):
        from rsb.net.diagnostics import ProbeResult

        latency = 10.0 if "fast" in str(proxy) else 200.0
        return ProbeResult(name, True, "HTTP 200", latency)

    monkeypatch.setattr("rsb.net.discovery.probe_http", fake_probe)
    candidates = [
        ProxyCandidate("http://slow.example:8080"),
        ProxyCandidate("http://fast.example:8080"),
    ]
    working = await probe_candidates(candidates, "https://relay.example/healthz")
    assert [candidate.url for candidate in working] == [
        "http://fast.example:8080",
        "http://slow.example:8080",
    ]


async def test_probe_candidates_filters_failures(monkeypatch) -> None:
    async def fake_probe(url, proxy=None, wait_seconds=4.0, name="proxy.health"):
        from rsb.net.diagnostics import ProbeResult

        ok = "good" in str(proxy)
        return ProbeResult(name, ok, "HTTP 200" if ok else "failed", 10.0 if ok else None)

    monkeypatch.setattr("rsb.net.discovery.probe_http", fake_probe)
    working = await probe_candidates(
        [
            ProxyCandidate("http://good.example:8080"),
            ProxyCandidate("http://bad.example:8080"),
        ],
        "https://relay.example/healthz",
    )
    assert [candidate.url for candidate in working] == ["http://good.example:8080"]


def test_cache_roundtrip(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    candidates = [
        ProxyCandidate("http://127.0.0.1:3128", "test", 12.5),
        ProxyCandidate("socks5://127.0.0.1:1080", "test", 30.0),
    ]
    save_cache(cache, candidates)
    loaded = load_cache(cache, 3600)
    assert [candidate.url for candidate in loaded] == [candidate.url for candidate in candidates]
    assert loaded[0].latency_ms == 12.5


def test_cache_expiration(tmp_path: Path) -> None:
    cache = tmp_path / "cache.json"
    save_cache(cache, [ProxyCandidate("http://127.0.0.1:3128")])
    assert load_cache(cache, 0) == []


def test_cache_ignores_missing_and_corrupt(tmp_path: Path) -> None:
    assert load_cache(tmp_path / "missing.json", 60) == []
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{broken", encoding="utf-8")
    assert load_cache(corrupt, 60) == []


def test_cache_accepts_fresh_timestamp(tmp_path: Path) -> None:
    import json

    cache = tmp_path / "cache.json"
    cache.write_text(
        json.dumps(
            {
                "version": 1,
                "updated_at": to_iso(utcnow()),
                "proxies": [{"url": "http://127.0.0.1:3128", "source": "test"}],
            }
        ),
        encoding="utf-8",
    )
    loaded = load_cache(cache, 3600)
    assert len(loaded) == 1
    assert parse_iso(to_iso(utcnow())) <= utcnow()
    assert iso_in(60)
