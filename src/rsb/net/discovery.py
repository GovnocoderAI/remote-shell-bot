from __future__ import annotations

import asyncio
import ipaddress
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from rsb.net.diagnostics import USER_AGENT, probe_http
from rsb.net.proxy import ProxyCandidate, dedupe, from_text
from rsb.util import ensure_private_file, now_iso, parse_iso, utcnow

CACHE_VERSION = 1


@dataclass(frozen=True, slots=True)
class ProxySource:
    name: str
    url: str


PUBLIC_PROXY_SOURCES: tuple[ProxySource, ...] = (
    ProxySource(
        "TheSpeedX/http",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    ),
    ProxySource(
        "TheSpeedX/socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    ),
    ProxySource(
        "monosans/http",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    ),
    ProxySource(
        "monosans/socks5",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    ),
    ProxySource(
        "proxifly/http",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    ),
    ProxySource(
        "proxifly/socks5",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    ),
)


@dataclass(slots=True)
class DiscoveryReport:
    candidates: list[ProxyCandidate] = field(default_factory=list)
    tested: int = 0
    errors: dict[str, str] = field(default_factory=dict)


def is_public_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return not host.lower().endswith(".local")
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def _proxy_host(url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


async def fetch_sources(
    sources: Iterable[ProxySource] = PUBLIC_PROXY_SOURCES,
    wait_seconds: float = 12.0,
    max_candidates: int = 800,
) -> DiscoveryReport:
    report = DiscoveryReport()
    async with httpx.AsyncClient(
        timeout=wait_seconds,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:

        async def load(source: ProxySource) -> tuple[str, str | None, list[ProxyCandidate]]:
            try:
                response = await client.get(source.url)
                response.raise_for_status()
            except Exception as exc:
                return source.name, f"{type(exc).__name__}: {exc}"[:200], []
            candidates = [
                candidate
                for candidate in from_text(response.text, source.name)
                if is_public_host(_proxy_host(candidate.url))
            ]
            return source.name, None, candidates

        results = await asyncio.gather(*(load(source) for source in sources))
    collected: list[ProxyCandidate] = []
    for name, error, candidates in results:
        if error:
            report.errors[name] = error
        collected.extend(candidates)
    report.candidates = dedupe(collected)[:max_candidates]
    return report


async def probe_candidates(
    candidates: list[ProxyCandidate],
    health_url: str,
    wait_seconds: float = 4.0,
    concurrency: int = 20,
    limit: int = 200,
) -> list[ProxyCandidate]:
    selected = dedupe(candidates)[:limit]
    if not selected:
        return []
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def check(candidate: ProxyCandidate) -> ProxyCandidate | None:
        async with semaphore:
            result = await probe_http(
                health_url,
                proxy=candidate.url,
                wait_seconds=wait_seconds,
                name="proxy.health",
            )
        if not result.ok or result.latency_ms is None:
            return None
        return candidate.with_latency(result.latency_ms)

    checked = await asyncio.gather(*(check(candidate) for candidate in selected))
    working = [candidate for candidate in checked if candidate is not None]
    working.sort(key=lambda candidate: candidate.latency_ms or 999999)
    return working


def load_cache(path: Path, ttl_seconds: int) -> list[ProxyCandidate]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != CACHE_VERSION:
            return []
        updated = parse_iso(str(data.get("updated_at", "")))
        if (utcnow() - updated).total_seconds() > ttl_seconds:
            return []
        return [
            ProxyCandidate(
                url=str(item["url"]),
                source=str(item.get("source", "cache")),
                latency_ms=item.get("latency_ms"),
            )
            for item in data.get("proxies", [])
            if isinstance(item, dict) and item.get("url")
        ]
    except (OSError, ValueError, KeyError, TypeError):
        return []


def save_cache(path: Path, candidates: list[ProxyCandidate]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": CACHE_VERSION,
        "updated_at": now_iso(),
        "proxies": [
            {
                "url": candidate.url,
                "source": candidate.source,
                "latency_ms": candidate.latency_ms,
            }
            for candidate in candidates
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    ensure_private_file(path)


async def discover_public(
    health_url: str,
    *,
    wait_seconds: float = 4.0,
    fetch_timeout: float = 12.0,
    concurrency: int = 20,
    max_test: int = 200,
    extra_sources: Iterable[ProxySource] = (),
) -> tuple[list[ProxyCandidate], DiscoveryReport]:
    sources = list(PUBLIC_PROXY_SOURCES) + list(extra_sources)
    report = await fetch_sources(sources, wait_seconds=fetch_timeout)
    working = await probe_candidates(
        report.candidates,
        health_url,
        wait_seconds=wait_seconds,
        concurrency=concurrency,
        limit=max_test,
    )
    report.tested = min(len(report.candidates), max_test)
    return working, report
