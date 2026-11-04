from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
import psutil
import websockets

from rsb.net.proxy import (
    ProxyFormatError,
    normalize_proxy,
    redact_proxy,
    scrub_proxy_secrets,
)
from rsb.protocol import MAX_FRAME_BYTES
from rsb.util import http_base, relay_endpoint

USER_AGENT = "RemoteShellBot/0.1 connectivity-check"
VPN_NAME_PATTERNS = (
    r"\bwg\d*\b",
    r"\bwireguard\b",
    r"\btun\d+\b",
    r"\btap\d+\b",
    r"\btailscale\d*\b",
    r"\bwarp\b",
    r"\bopenvpn\w*\b",
    r"\bnordlynx\w*\b",
    r"\bproton\w*\b",
    r"\bmullvad\w*\b",
)


@dataclass(slots=True)
class ProbeResult:
    name: str
    ok: bool
    detail: str = ""
    latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
        }


@dataclass(slots=True)
class DiagnosticsReport:
    relay: str
    health_url: str
    host: str
    port: int
    secure: bool
    results: list[ProbeResult] = field(default_factory=list)
    proxies: dict[str, str] = field(default_factory=dict)
    vpn_interfaces: list[str] = field(default_factory=list)
    proxy: str | None = None

    def result(self, name: str) -> ProbeResult | None:
        for item in self.results:
            if item.name == name:
                return item
        return None

    @property
    def relay_ok(self) -> bool:
        health = self.result("relay.websocket")
        return bool(health and health.ok)

    @property
    def proxy_ok(self) -> bool:
        if not self.proxy:
            return False
        proxy_result = self.result("proxy.websocket")
        return bool(proxy_result and proxy_result.ok)

    @property
    def verdict(self) -> str:
        if self.proxy:
            if self.proxy_ok:
                return "прокси работает, relay доступен"
            proxy_health = self.result("proxy.health")
            if proxy_health and proxy_health.ok:
                return "прокси отвечает, но WebSocket не проходит"
            if proxy_health:
                return f"прокси не работает: {proxy_health.detail}"
        if self.relay_ok:
            return "прямое подключение к relay работает"
        tcp = self.result("relay.tcp")
        if tcp and tcp.ok:
            return "TCP и DNS работают, приложение не отвечает"
        return "relay недоступен: проверьте адрес, сеть или нужен прокси/VPN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "relay": self.relay,
            "health_url": self.health_url,
            "host": self.host,
            "port": self.port,
            "secure": self.secure,
            "proxy": redact_proxy(self.proxy) if self.proxy else None,
            "proxies": self.proxies,
            "vpn_interfaces": self.vpn_interfaces,
            "verdict": self.verdict,
            "results": [item.to_dict() for item in self.results],
        }


def relay_parts(relay_url: str) -> tuple[str, int, bool]:
    parts = urlsplit(relay_endpoint(relay_url))
    host = parts.hostname or ""
    secure = parts.scheme == "wss"
    port = parts.port or (443 if secure else 80)
    return host, port, secure


def relay_health_url(relay_url: str) -> str:
    return http_base(relay_url).rstrip("/") + "/healthz"


def is_vpn_name(name: str) -> bool:
    return any(re.search(pattern, name, re.IGNORECASE) for pattern in VPN_NAME_PATTERNS)


def detect_vpn_interfaces() -> list[str]:
    try:
        statistics = psutil.net_if_stats()
    except Exception:
        return []
    return sorted(name for name, stats in statistics.items() if stats.isup and is_vpn_name(name))


def system_proxy_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        raw = os.environ.get(name)
        if raw:
            values[name] = redact_proxy(raw)
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
    if no_proxy:
        values["NO_PROXY"] = no_proxy
    return values


def _error_detail(exc: BaseException, proxy: str | None) -> str:
    detail = f"{type(exc).__name__}: {exc}"
    return scrub_proxy_secrets(detail[:240], proxy)


async def probe_tcp(host: str, port: int, wait_seconds: float = 6.0) -> ProbeResult:
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=wait_seconds
        )
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        return ProbeResult("relay.tcp", False, _error_detail(exc, None))
    return ProbeResult("relay.tcp", True, f"{host}:{port}", (time.perf_counter() - start) * 1000)


async def probe_tls(host: str, port: int, wait_seconds: float = 6.0) -> ProbeResult:
    context = ssl.create_default_context()
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=wait_seconds,
        )
        writer.close()
        await writer.wait_closed()
    except Exception as exc:
        return ProbeResult("relay.tls", False, _error_detail(exc, None))
    return ProbeResult(
        "relay.tls", True, "TLS verification passed", (time.perf_counter() - start) * 1000
    )


async def probe_http(
    url: str,
    proxy: str | None = None,
    wait_seconds: float = 6.0,
    name: str = "relay.health",
) -> ProbeResult:
    start = time.perf_counter()

    async def request():
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=wait_seconds,
            follow_redirects=True,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            return await client.get(url)

    try:
        response = await asyncio.wait_for(request(), timeout=wait_seconds)
        latency = (time.perf_counter() - start) * 1000
        ok = response.status_code < 500
        return ProbeResult(name, ok, f"HTTP {response.status_code}", latency)
    except Exception as exc:
        return ProbeResult(name, False, _error_detail(exc, proxy))


async def probe_websocket(
    relay_url: str,
    proxy: str | None = None,
    wait_seconds: float = 6.0,
    name: str = "relay.websocket",
) -> ProbeResult:
    endpoint = relay_endpoint(relay_url).rstrip("/") + "/agent"
    start = time.perf_counter()
    try:
        async with websockets.connect(
            endpoint,
            proxy=proxy,
            open_timeout=wait_seconds,
            close_timeout=2,
            ping_interval=None,
            max_size=MAX_FRAME_BYTES,
        ):
            latency = (time.perf_counter() - start) * 1000
            return ProbeResult(name, True, "WebSocket opened and closed", latency)
    except Exception as exc:
        return ProbeResult(name, False, _error_detail(exc, proxy))


async def probe_telegram(proxy: str | None = None, wait_seconds: float = 6.0) -> ProbeResult:
    start = time.perf_counter()

    async def request():
        async with httpx.AsyncClient(
            proxy=proxy,
            timeout=wait_seconds,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            return await client.get("https://api.telegram.org/")

    try:
        response = await asyncio.wait_for(request(), timeout=wait_seconds)
        latency = (time.perf_counter() - start) * 1000
        ok = response.status_code < 500
        return ProbeResult("telegram.api", ok, f"HTTP {response.status_code}", latency)
    except Exception as exc:
        return ProbeResult("telegram.api", False, _error_detail(exc, proxy))


def validate_proxy_url(proxy: str) -> None:
    try:
        normalize_proxy(proxy)
    except ProxyFormatError as exc:
        raise ProxyFormatError(f"invalid proxy: {exc}") from exc


async def run_diagnostics(
    relay_url: str,
    proxy: str | None = None,
    wait_seconds: float = 6.0,
    include_telegram: bool = True,
) -> DiagnosticsReport:
    host, port, secure = relay_parts(relay_url)
    health_url = relay_health_url(relay_url)
    report = DiagnosticsReport(
        relay=relay_url,
        health_url=health_url,
        host=host,
        port=port,
        secure=secure,
        proxy=proxy,
        proxies=system_proxy_env(),
        vpn_interfaces=detect_vpn_interfaces(),
    )
    report.results.append(await probe_tcp(host, port, wait_seconds))
    if secure:
        report.results.append(await probe_tls(host, port, wait_seconds))
    report.results.append(await probe_http(health_url, wait_seconds=wait_seconds))
    report.results.append(await probe_websocket(relay_url, wait_seconds=wait_seconds))
    if proxy:
        report.results.append(
            await probe_http(
                health_url, proxy=proxy, wait_seconds=wait_seconds, name="proxy.health"
            )
        )
        report.results.append(
            await probe_websocket(
                relay_url, proxy=proxy, wait_seconds=wait_seconds, name="proxy.websocket"
            )
        )
    if include_telegram:
        report.results.append(await probe_telegram(proxy=proxy, wait_seconds=wait_seconds))
    return report


def socket_host_port(relay_url: str) -> tuple[str, int]:
    host, port, _ = relay_parts(relay_url)
    if not host:
        raise ValueError("relay host is empty")
    return host, port


def is_port_open(host: str, port: int, wait_seconds: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=wait_seconds):
            return True
    except OSError:
        return False
