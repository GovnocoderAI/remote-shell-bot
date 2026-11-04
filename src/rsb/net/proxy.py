from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from rsb.errors import ConfigError

SUPPORTED_PROXY_SCHEMES = frozenset({"http", "https", "socks5", "socks5h"})
TOKEN_SPLIT = re.compile(r"[\s,]+")


class ProxyFormatError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class ProxyCandidate:
    url: str
    source: str = "manual"
    latency_ms: float | None = None

    def redacted(self) -> str:
        return redact_proxy(self.url)

    def with_latency(self, latency_ms: float) -> ProxyCandidate:
        return ProxyCandidate(self.url, self.source, latency_ms)


def normalize_proxy(raw: str, default_scheme: str = "http") -> str:
    value = raw.strip()
    if not value:
        raise ProxyFormatError("empty proxy value")
    if any(character.isspace() for character in value):
        raise ProxyFormatError("proxy value contains whitespace")
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in SUPPORTED_PROXY_SCHEMES:
            raise ProxyFormatError(f"unsupported proxy scheme: {scheme}")
        if not parts.hostname:
            raise ProxyFormatError("proxy host is required")
        port = parts.port
        if port is None:
            raise ProxyFormatError("proxy port is required")
        if not 1 <= port <= 65535:
            raise ProxyFormatError("proxy port is out of range")
        if parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise ProxyFormatError("proxy URL must not contain a path, query or fragment")
    except ValueError as exc:
        raise ProxyFormatError(str(exc)) from exc
    netloc = parts.netloc
    if parts.username is None and parts.password is not None:
        raise ProxyFormatError("proxy password requires a username")
    return urlunsplit((scheme, netloc, "", "", ""))


def redact_proxy(url: str) -> str:
    try:
        parts = urlsplit(url if "://" in url else f"http://{url}")
    except ValueError:
        return "<invalid proxy>"
    netloc = parts.netloc
    if "@" in netloc:
        credentials, host = netloc.rsplit("@", 1)
        username = credentials.split(":", 1)[0]
        netloc = f"{username}:***@{host}"
    scheme = parts.scheme.lower() or "http"
    return urlunsplit((scheme, netloc, "", "", ""))


def scrub_proxy_secrets(text: str, proxy: str | None) -> str:
    if not proxy:
        return text
    scrubbed = text.replace(proxy, redact_proxy(proxy))
    try:
        parts = urlsplit(proxy)
    except ValueError:
        return scrubbed
    if parts.password:
        scrubbed = scrubbed.replace(parts.password, "***")
    return scrubbed


def from_text(text: str, source: str = "text") -> list[ProxyCandidate]:
    candidates: list[ProxyCandidate] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        for token in TOKEN_SPLIT.split(line):
            if not token or token.startswith("#"):
                continue
            try:
                url = normalize_proxy(token)
            except ProxyFormatError:
                continue
            if url in seen:
                continue
            seen.add(url)
            candidates.append(ProxyCandidate(url=url, source=source))
    return candidates


def from_file(path: Path, source: str | None = None) -> list[ProxyCandidate]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return from_text(text, source or str(path))


def from_env() -> list[ProxyCandidate]:
    candidates: list[ProxyCandidate] = []
    seen: set[str] = set()
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        value = os.environ.get(name, "").strip()
        if not value:
            continue
        try:
            url = normalize_proxy(value)
        except ProxyFormatError:
            continue
        if url in seen:
            continue
        seen.add(url)
        candidates.append(ProxyCandidate(url=url, source=f"env:{name}"))
    return candidates


def dedupe(candidates: list[ProxyCandidate]) -> list[ProxyCandidate]:
    result: list[ProxyCandidate] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.url in seen:
            continue
        seen.add(candidate.url)
        result.append(candidate)
    return result


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    value = host.lower().strip("[]")
    return value in {"localhost", "::1"} or value.startswith("127.")


def validate_relay_transport(relay_url: str, proxy: str | None) -> None:
    if not proxy:
        return
    try:
        parts = urlsplit(relay_url if "://" in relay_url else f"ws://{relay_url}")
    except ValueError as exc:
        raise ProxyFormatError(str(exc)) from exc
    if parts.scheme.lower() == "ws" and not is_loopback_host(parts.hostname):
        raise ConfigError(
            "proxied connections require wss:// (TLS); plain ws:// is allowed only on loopback"
        )
