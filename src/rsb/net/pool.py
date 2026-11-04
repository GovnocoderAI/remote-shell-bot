from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rsb.errors import ConfigError
from rsb.net.diagnostics import probe_http, probe_websocket
from rsb.net.discovery import (
    DiscoveryReport,
    ProxySource,
    discover_public,
    load_cache,
    save_cache,
)
from rsb.net.proxy import (
    ProxyCandidate,
    ProxyFormatError,
    dedupe,
    from_env,
    from_file,
    normalize_proxy,
    redact_proxy,
)


class ProxyResolver(Protocol):
    @property
    def display(self) -> str: ...

    async def next_proxy(self) -> str | None: ...

    def report_failure(self, proxy: str | None) -> None: ...

    def report_success(self, proxy: str | None) -> None: ...


class StaticResolver:
    def __init__(self, proxy: str | None = None) -> None:
        self.proxy = proxy

    @property
    def display(self) -> str:
        return redact_proxy(self.proxy) if self.proxy else "direct"

    async def next_proxy(self) -> str | None:
        return self.proxy

    def report_failure(self, proxy: str | None) -> None:
        return None

    def report_success(self, proxy: str | None) -> None:
        return None


@dataclass(slots=True)
class Selection:
    resolver: ProxyResolver
    proxy: str | None
    source: str
    tested: int = 0
    public_used: bool = False
    public_report: DiscoveryReport | None = None
    direct_checked: bool = False
    warnings: list[str] = field(default_factory=list)


class FallbackResolver:
    def __init__(
        self,
        candidates: list[ProxyCandidate],
        *,
        health_url: str,
        allow_public: bool,
        wait_seconds: float = 4.0,
        concurrency: int = 20,
        max_test: int = 200,
        cache_path: Path | None = None,
        cache_ttl: int = 1800,
        extra_sources: Iterable[ProxySource] = (),
    ) -> None:
        self._queue = deque(candidates)
        self._failed: set[str] = set()
        self._health_url = health_url
        self._allow_public = allow_public
        self._timeout = wait_seconds
        self._concurrency = concurrency
        self._max_test = max_test
        self._cache_path = cache_path
        self._cache_ttl = cache_ttl
        self._extra_sources = list(extra_sources)
        self._public_loaded = False
        self._current: str | None = None

    @property
    def display(self) -> str:
        return redact_proxy(self._current) if self._current else "direct"

    @property
    def current(self) -> str | None:
        return self._current

    async def next_proxy(self) -> str | None:
        while True:
            while self._queue:
                candidate = self._queue.popleft()
                if candidate.url in self._failed:
                    continue
                self._current = candidate.url
                return candidate.url
            if not self._allow_public or self._public_loaded:
                self._current = None
                return None
            self._public_loaded = True
            working, _ = await discover_public(
                self._health_url,
                wait_seconds=self._timeout,
                concurrency=self._concurrency,
                max_test=self._max_test,
                extra_sources=self._extra_sources,
            )
            if working and self._cache_path is not None:
                save_cache(self._cache_path, working)
            self._queue.extend(working)

    def report_failure(self, proxy: str | None) -> None:
        if proxy:
            self._failed.add(proxy)

    def report_success(self, proxy: str | None) -> None:
        self._current = proxy


def _custom_sources(urls: Iterable[str]) -> list[ProxySource]:
    result: list[ProxySource] = []
    for index, url in enumerate(urls, start=1):
        value = url.strip()
        if value.startswith(("http://", "https://")):
            result.append(ProxySource(f"custom-{index}", value))
    return result


async def select_proxy(
    health_url: str,
    *,
    explicit: Iterable[str] = (),
    proxy_file: Path | None = None,
    allow_direct: bool = True,
    allow_public: bool = True,
    relay_url: str | None = None,
    wait_seconds: float = 4.0,
    concurrency: int = 20,
    max_test: int = 200,
    cache_path: Path | None = None,
    cache_ttl: int = 1800,
    extra_source_urls: Iterable[str] = (),
) -> Selection:
    warnings: list[str] = []
    explicit_candidates: list[ProxyCandidate] = []
    for value in explicit:
        try:
            normalized = normalize_proxy(value)
        except ProxyFormatError as exc:
            raise ConfigError(f"invalid proxy '{value}': {exc}") from exc
        explicit_candidates.append(ProxyCandidate(url=normalized, source="explicit"))
    initial = dedupe(
        explicit_candidates
        + (from_file(proxy_file) if proxy_file else [])
        + from_env()
        + (load_cache(cache_path, cache_ttl) if cache_path else [])
    )

    if allow_direct:
        direct = await probe_http(health_url, wait_seconds=wait_seconds, name="direct.health")
        direct_ok = direct.ok
        if direct_ok and relay_url:
            websocket = await probe_websocket(
                relay_url,
                wait_seconds=wait_seconds,
                name="direct.websocket",
            )
            if not websocket.ok:
                direct_ok = False
                warnings.append("HTTP relay доступен, но WebSocket не проходит; нужен прокси")
        if direct_ok:
            return Selection(
                resolver=StaticResolver(None),
                proxy=None,
                source="direct",
                direct_checked=True,
                warnings=warnings,
            )

    from rsb.net.discovery import probe_candidates

    working = await probe_candidates(
        initial,
        health_url,
        wait_seconds=wait_seconds,
        concurrency=concurrency,
        limit=max_test,
    )
    public_used = False
    public_report: DiscoveryReport | None = None
    if not working and allow_public:
        working, public_report = await discover_public(
            health_url,
            wait_seconds=wait_seconds,
            concurrency=concurrency,
            max_test=max_test,
            extra_sources=_custom_sources(extra_source_urls),
        )
        public_used = True
        if working and cache_path is not None:
            save_cache(cache_path, working)
        if public_report.errors:
            warnings.append(
                "часть публичных источников недоступна: " + ", ".join(sorted(public_report.errors))
            )

    if not working:
        raise ConfigError(
            "не удалось найти рабочий прокси: прямое подключение не проходит, "
            "настроенные прокси и публичные списки не дали результата. "
            "Проверьте relay или добавьте рабочий прокси в proxies.txt."
        )

    selected = working[0]
    resolver = FallbackResolver(
        working,
        health_url=health_url,
        allow_public=allow_public and not public_used,
        wait_seconds=wait_seconds,
        concurrency=concurrency,
        max_test=max_test,
        cache_path=cache_path,
        cache_ttl=cache_ttl,
        extra_sources=_custom_sources(extra_source_urls),
    )
    if public_used:
        warnings.append(
            "используются публичные бесплатные прокси: они нестабильны "
            "и не являются доверенной инфраструктурой"
        )
    return Selection(
        resolver=resolver,
        proxy=selected.url,
        source=selected.source,
        tested=len(working),
        public_used=public_used,
        public_report=public_report,
        direct_checked=allow_direct,
        warnings=warnings,
    )
