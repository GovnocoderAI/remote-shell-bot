from __future__ import annotations

import os
import re
import secrets
import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="seconds")


def now_iso() -> str:
    return to_iso(utcnow())


def iso_in(seconds: int) -> str:
    return to_iso(utcnow() + timedelta(seconds=seconds))


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


def new_nonce() -> str:
    return secrets.token_hex(16)


def short_id(length: int = 8) -> str:
    return secrets.token_hex((length + 1) // 2)[:length]


def chunk_text(text: str, limit: int = 3800) -> list[str]:
    if not text:
        return [""]
    chunks: list[str] = []
    remaining = text
    while len(remaining) > limit:
        cut = remaining.rfind("\n", 0, limit)
        if cut < limit // 2:
            cut = limit
        chunks.append(remaining[:cut])
        remaining = remaining[cut:].lstrip("\n")
    chunks.append(remaining)
    return chunks


def human_seconds(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def ensure_private_file(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        return


def sanitize_filename(name: str, fallback: str = "device") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-._")
    return cleaned[:64] or fallback


def http_base(relay_url: str) -> str:
    base = relay_url.strip().rstrip("/")
    if base.startswith("wss://"):
        return "https://" + base[len("wss://") :]
    if base.startswith("ws://"):
        return "http://" + base[len("ws://") :]
    if base.startswith(("https://", "http://")):
        return base
    return "https://" + base


def relay_endpoint(relay_url: str) -> str:
    base = relay_url.strip().rstrip("/")
    if base.startswith(("ws://", "wss://")):
        return base
    if base.startswith("https://"):
        return "wss://" + base[len("https://") :]
    if base.startswith("http://"):
        return "ws://" + base[len("http://") :]
    return "wss://" + base


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]
