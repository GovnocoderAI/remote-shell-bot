from __future__ import annotations

import asyncio
import ctypes
import hashlib
import os
import re
import shutil
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from rsb.config import Settings
from rsb.net.diagnostics import USER_AGENT, detect_vpn_interfaces, probe_http
from rsb.util import ensure_private_file, sanitize_filename

SECTION_INTERFACE = re.compile(r"(?im)^\s*\[Interface\]\s*$")
ENDPOINT = re.compile(r"(?im)^\s*Endpoint\s*=\s*(\S+)")
DISPLAY_NAME = re.compile(r"(?im)^\s*#\s*(?:Name|Remark)\s*=\s*(.+)$")
SOURCE_URL = re.compile(r"(?i)^https?://\S+$")


@dataclass(frozen=True, slots=True)
class WireGuardConfig:
    name: str
    text: str
    endpoint: str | None = None


@dataclass(slots=True)
class VpnSession:
    connected: bool
    detail: str
    name: str | None = None
    adapter: str | None = None
    temporary: bool = False
    controller: WireGuardController | None = None
    config_path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    async def close(self) -> None:
        if self.temporary and self.controller is not None and self.name:
            await self.controller.down(self.name, self.config_path)
            self.connected = False


def parse_wireguard_configs(text: str, prefix: str = "vpn") -> list[WireGuardConfig]:
    starts = [match.start() for match in SECTION_INTERFACE.finditer(text)]
    configs: list[WireGuardConfig] = []
    seen: set[str] = set()
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(text)
        block = text[start:end].strip() + "\n"
        if "PrivateKey" not in block or "[Peer]" not in block:
            continue
        digest = hashlib.sha256(block.encode("utf-8")).hexdigest()[:10]
        if digest in seen:
            continue
        seen.add(digest)
        name_match = DISPLAY_NAME.search(block)
        raw_name = name_match.group(1).strip() if name_match else f"{prefix}-{index + 1}"
        name = sanitize_filename(raw_name, f"{prefix}-{index + 1}")
        endpoint_match = ENDPOINT.search(block)
        configs.append(
            WireGuardConfig(
                name=f"{name}-{digest}",
                text=block,
                endpoint=endpoint_match.group(1) if endpoint_match else None,
            )
        )
    return configs


def read_local_configs(directory: Path) -> list[WireGuardConfig]:
    if not directory.exists():
        return []
    configs: list[WireGuardConfig] = []
    for path in sorted(directory.glob("*.conf")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parsed = parse_wireguard_configs(text, prefix=path.stem)
        if parsed:
            configs.extend(parsed)
        else:
            endpoint = ENDPOINT.search(text)
            if "PrivateKey" in text and "[Peer]" in text:
                configs.append(
                    WireGuardConfig(
                        name=sanitize_filename(path.stem, "vpn"),
                        text=text,
                        endpoint=endpoint.group(1) if endpoint else None,
                    )
                )
    return configs


def read_source_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#") and SOURCE_URL.match(line.strip())
    ]


async def fetch_public_configs(
    urls: Iterable[str], wait_seconds: float = 12.0
) -> tuple[list[WireGuardConfig], dict[str, str]]:
    configs: list[WireGuardConfig] = []
    errors: dict[str, str] = {}
    async with httpx.AsyncClient(
        timeout=wait_seconds,
        follow_redirects=True,
        trust_env=False,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for index, url in enumerate(urls, start=1):
            try:
                response = await client.get(url)
                response.raise_for_status()
            except Exception as exc:
                errors[url] = f"{type(exc).__name__}: {exc}"[:200]
                continue
            configs.extend(parse_wireguard_configs(response.text, prefix=f"public-{index}"))
    unique: dict[str, WireGuardConfig] = {}
    for config in configs:
        unique.setdefault(config.name, config)
    return list(unique.values()), errors


def is_admin() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def wireguard_binary() -> str | None:
    if os.name == "nt":
        candidate = (
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
            / "WireGuard"
            / "wireguard.exe"
        )
        if candidate.exists():
            return str(candidate)
    return shutil.which("wg-quick")


class WireGuardController:
    def __init__(self, work_dir: Path) -> None:
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.work_dir, 0o700)
        except OSError:
            pass
        self._cleanup_stale()

    def _cleanup_stale(self) -> None:
        cutoff = time.time() - 86400
        for path in self.work_dir.glob("*.conf"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            except OSError:
                continue

    @property
    def available(self) -> bool:
        return wireguard_binary() is not None

    async def _run(self, command: list[str], wait_seconds: float = 30.0) -> tuple[int, str]:
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            output, _ = await asyncio.wait_for(process.communicate(), timeout=wait_seconds)
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"
        return process.returncode or 0, output.decode("utf-8", errors="replace")[:400]

    async def up(self, config: WireGuardConfig) -> tuple[bool, str, str | None, Path | None]:
        binary = wireguard_binary()
        if binary is None:
            return False, "WireGuard не установлен", None, None
        if not is_admin():
            return False, "для подключения VPN нужны права администратора/root", None, None
        self.work_dir.mkdir(parents=True, exist_ok=True)
        name = sanitize_filename(config.name, "vpn")
        path = self.work_dir / f"{name}.conf"
        path.write_text(config.text, encoding="utf-8")
        ensure_private_file(path)
        if os.name == "nt":
            command = [binary, "/installtunnelservice", str(path)]
        else:
            command = [binary, "up", str(path)]
            if not (hasattr(os, "geteuid") and os.geteuid() == 0):
                command = ["sudo", "-n", *command]
        code, output = await self._run(command)
        if code != 0:
            path.unlink(missing_ok=True)
            return False, output or "WireGuard завершился с ошибкой", None, None
        return True, "", name, path

    async def down(self, name: str, path: Path | None) -> None:
        binary = wireguard_binary()
        if binary is None:
            return
        if os.name == "nt":
            command = [binary, "/uninstalltunnelservice", name]
        else:
            command = [binary, "down", str(path or "")]
            if not (hasattr(os, "geteuid") and os.geteuid() == 0):
                command = ["sudo", "-n", *command]
        await self._run(command)
        if path is not None:
            await asyncio.to_thread(path.unlink, missing_ok=True)

    async def try_configs(
        self,
        configs: list[WireGuardConfig],
        health_url: str,
        wait_seconds: float,
    ) -> VpnSession:
        last_error = "нет доступных конфигураций WireGuard"
        for config in configs[:20]:
            ok, detail, name, path = await self.up(config)
            if not ok:
                last_error = detail
                continue
            await asyncio.sleep(1.2)
            probe = await probe_http(health_url, wait_seconds=wait_seconds, name="vpn.health")
            if probe.ok:
                adapters = detect_vpn_interfaces()
                return VpnSession(
                    connected=True,
                    detail=f"WireGuard подключён: {config.endpoint or config.name}",
                    name=name,
                    adapter=adapters[0] if adapters else None,
                    temporary=True,
                    controller=self,
                    config_path=path,
                )
            last_error = probe.detail
            if name:
                await self.down(name, path)
        return VpnSession(connected=False, detail=last_error)


async def ensure_vpn(
    settings: Settings,
    health_url: str,
    *,
    allow_public: bool = False,
    wait_seconds: float = 6.0,
) -> VpnSession:
    adapters = detect_vpn_interfaces()
    if adapters:
        probe = await probe_http(health_url, wait_seconds=wait_seconds, name="vpn.health")
        if probe.ok:
            return VpnSession(
                connected=True,
                detail="активный VPN уже пропускает relay: " + ", ".join(adapters),
                adapter=adapters[0],
                temporary=False,
            )
    binary = wireguard_binary()
    if binary is None:
        return VpnSession(
            connected=False,
            detail=(
                "WireGuard не установлен. Установите WireGuard или используйте прокси: rsb connect"
            ),
        )
    if not is_admin():
        return VpnSession(
            connected=False,
            detail=(
                "для VPN требуются права администратора/root. Запустите терминал "
                "от имени администратора или используйте прокси."
            ),
        )
    configs = read_local_configs(settings.resolved_vpn_dir)
    warnings: list[str] = []
    if allow_public:
        urls = list(settings.vpn_source_urls)
        urls.extend(read_source_urls(settings.resolved_vpn_sources_file))
        if urls:
            fetched, errors = await fetch_public_configs(urls, wait_seconds=wait_seconds)
            configs.extend(fetched)
            if errors:
                warnings.append("часть источников VPN недоступна: " + ", ".join(sorted(errors)))
            if fetched:
                warnings.append(
                    "используются публичные WireGuard-конфиги: это недоверенная "
                    "инфраструктура, трафик проходит через чужие узлы"
                )
    if not configs:
        return VpnSession(
            connected=False,
            detail=(
                f"нет конфигураций WireGuard в {settings.resolved_vpn_dir} "
                "и не заданы публичные источники"
            ),
            warnings=warnings,
        )
    controller = WireGuardController(settings.data_dir / "vpn_runtime")
    session = await controller.try_configs(configs, health_url, wait_seconds)
    session.warnings.extend(warnings)
    return session
