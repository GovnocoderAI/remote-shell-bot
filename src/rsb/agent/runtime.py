from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import logging
import platform
import random
import socket
import time
import webbrowser
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import websockets

from rsb.agent.config import AgentConfig, verify_password
from rsb.agent.executor import ShellRunner
from rsb.agent.screenshot import capture_screenshot
from rsb.config import Settings
from rsb.errors import (
    AgentError,
    AuthenticationError,
    ConfigError,
    DeviceOfflineError,
    NotFoundError,
)
from rsb.net.pool import ProxyResolver, StaticResolver
from rsb.net.proxy import (
    ProxyFormatError,
    from_env,
    normalize_proxy,
    redact_proxy,
    validate_relay_transport,
)
from rsb.protocol import MAX_FRAME_BYTES, Envelope, Msg, decode
from rsb.security import device_message, sign
from rsb.server import policy
from rsb.server.policy import CapabilityError
from rsb.util import new_nonce, now_iso, relay_endpoint

log = logging.getLogger("rsb.agent")

HISTORY_LIMIT = 50
EVENT_LIMIT = 200


@dataclass(slots=True)
class PendingSession:
    id: str
    operator_id: int
    operator_username: str | None
    purpose: str
    requested_capabilities: list[str]
    previous_capabilities: list[str] | None
    requested_at: str
    expires_at: str
    decision: str | None = None


@dataclass(slots=True)
class ActiveSession:
    id: str
    account_id: str
    account_token: str
    operator_id: int
    operator_username: str | None
    purpose: str
    capabilities: list[str]
    created_at: str
    expires_at: str
    cwd: Path
    history: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=HISTORY_LIMIT))
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    screenshot: bytes | None = None
    screenshot_meta: dict[str, Any] = field(default_factory=dict)
    closing: bool = False


class AgentRuntime:
    def __init__(
        self,
        settings: Settings,
        config: AgentConfig,
        config_path: Path,
        proxy_resolver: ProxyResolver | None = None,
    ) -> None:
        self.settings = settings
        self.config = config
        self.config_path = config_path
        if proxy_resolver is not None:
            self._resolver: ProxyResolver = proxy_resolver
        else:
            configured = settings.agent_proxy.strip()
            if configured:
                try:
                    configured = normalize_proxy(configured)
                except ProxyFormatError as exc:
                    raise ConfigError(f"invalid agent proxy: {exc}") from exc
            else:
                environment = from_env()
                configured = environment[0].url if environment else ""
            self._resolver = StaticResolver(configured or None)
        self._current_proxy: str | None = None
        self.runner = ShellRunner(
            max_output_bytes=settings.command_max_output_bytes,
            timeout_seconds=settings.command_timeout_seconds,
        )
        self.device: dict[str, Any] = {
            "id": config.device_id,
            "name": config.name,
            "hostname": platform.node(),
            "os_name": platform.system(),
            "capabilities": [],
        }
        self.grants: dict[int, dict[str, Any]] = {}
        self.pending: dict[str, PendingSession] = {}
        self.sessions: dict[str, ActiveSession] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=EVENT_LIMIT)
        self.connected = False
        self.unlocked = False
        self.last_activity = 0.0
        self._socket: Any = None
        self._send_lock = asyncio.Lock()
        self._ui_task: asyncio.Task[None] | None = None
        self._ui_server: Any = None

    @property
    def ui_url(self) -> str:
        return f"http://127.0.0.1:{self.config.ui_port}/?token={self.config.ui_token}"

    def _check_ui_binding(self) -> None:
        host = self.settings.agent_ui_host
        if host not in {"127.0.0.1", "localhost", "::1"}:
            log.warning(
                "local control panel is bound to %s and is reachable from the network",
                host,
            )
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((host, self.config.ui_port))
        except OSError as exc:
            raise AgentError(
                f"порт локальной панели {self.config.ui_port} недоступен: {exc}"
            ) from exc

    async def run(self, open_ui: bool = False) -> None:
        self._check_ui_binding()
        self._ui_task = asyncio.create_task(self._serve_ui(open_ui))
        self._ui_task.add_done_callback(self._log_ui_failure)
        try:
            await self._connection_loop()
        finally:
            if self._ui_server is not None:
                self._ui_server.should_exit = True
            if self._ui_task is not None:
                try:
                    await asyncio.wait_for(self._ui_task, timeout=10)
                except Exception:
                    self._ui_task.cancel()
                    with contextlib.suppress(BaseException):
                        await self._ui_task

    def _log_ui_failure(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log.error("local control panel stopped: %s", error, exc_info=error)

    async def _serve_ui(self, open_ui: bool) -> None:
        import uvicorn

        from rsb.agent.ui import create_ui_app

        server = uvicorn.Server(
            uvicorn.Config(
                create_ui_app(self),
                host=self.settings.agent_ui_host,
                port=self.config.ui_port,
                log_level="warning",
                access_log=False,
                lifespan="off",
            )
        )
        self._ui_server = server
        if open_ui:
            asyncio.get_running_loop().call_later(0.8, webbrowser.open, self.ui_url)
        log.info("local control panel: %s", self.ui_url)
        await server.serve()

    async def _connection_loop(self) -> None:
        delay = 1.0
        while True:
            try:
                await self._connect_and_serve()
                self._resolver.report_failure(self._current_proxy)
                delay = 1.0
            except asyncio.CancelledError:
                raise
            except ConfigError as exc:
                log.error("proxy configuration rejected: %s", exc)
                self._log_event("relay.config_error", str(exc))
                return
            except AuthenticationError as exc:
                log.error("relay rejected device credentials: %s", exc)
                self._log_event("relay.auth_failed", str(exc))
                return
            except Exception as exc:
                log.warning("relay connection lost: %s", exc)
                self._resolver.report_failure(self._current_proxy)
            self.connected = False
            self._socket = None
            self._reset_sessions("relay_disconnected")
            await asyncio.sleep(delay + random.uniform(0, 0.75))
            delay = min(delay * 2, 30.0)

    async def _connect_and_serve(self) -> None:
        endpoint = relay_endpoint(self.config.relay_url).rstrip("/") + "/agent"
        proxy = await self._resolver.next_proxy()
        self._current_proxy = proxy
        validate_relay_transport(self.config.relay_url, proxy)
        if proxy:
            log.info("connecting to relay via proxy %s", redact_proxy(proxy))
            self._log_event("relay.proxy", redact_proxy(proxy))
        else:
            log.info("connecting to relay directly")
        async with websockets.connect(
            endpoint,
            proxy=proxy,
            max_size=MAX_FRAME_BYTES,
            ping_interval=20,
            ping_timeout=20,
            open_timeout=15,
        ) as socket:
            self._socket = socket
            nonce = new_nonce()
            timestamp = int(time.time())
            signature = sign(
                self.config.device_secret,
                device_message(self.config.device_id, nonce, timestamp),
            )
            await socket.send(
                Envelope(
                    type=Msg.HELLO,
                    payload={
                        "device_id": self.config.device_id,
                        "nonce": nonce,
                        "timestamp": timestamp,
                        "signature": signature,
                    },
                ).to_json()
            )
            raw = await asyncio.wait_for(socket.recv(), timeout=20)
            response = decode(raw)
            if response.type == Msg.HELLO_ERROR:
                raise AuthenticationError(
                    str(response.payload.get("message", "handshake rejected"))
                )
            if response.type != Msg.HELLO_OK:
                raise AgentError(f"unexpected handshake response {response.type}")
            self._apply_hello(response.payload)
            self._resolver.report_success(proxy)
            heartbeat = asyncio.create_task(self._heartbeat(socket))
            try:
                async for frame in socket:
                    try:
                        envelope = decode(frame)
                    except Exception as exc:
                        log.warning("invalid frame from relay: %s", exc)
                        continue
                    await self._handle(envelope)
            except websockets.exceptions.ConnectionClosed as exc:
                if exc.code == 4001:
                    raise AuthenticationError("устройство отозвано") from exc
                raise
            finally:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat

    async def _heartbeat(self, socket: Any) -> None:
        while True:
            await asyncio.sleep(25)
            try:
                await socket.send(
                    Envelope(type=Msg.HEARTBEAT, payload={"sent_at": int(time.time())}).to_json()
                )
            except Exception:
                return

    def _apply_hello(self, payload: dict[str, Any]) -> None:
        device = payload.get("device") or {}
        self.device.update(
            {
                "id": device.get("id", self.config.device_id),
                "name": device.get("name", self.config.name),
                "hostname": device.get("hostname"),
                "os_name": device.get("os_name"),
                "capabilities": policy.normalize(device.get("capabilities", [])),
            }
        )
        self.grants = {
            int(item["operator_id"]): {
                "operator_id": int(item["operator_id"]),
                "capabilities": policy.normalize(item.get("capabilities", [])),
                "updated_at": item.get("updated_at"),
            }
            for item in payload.get("grants", [])
            if isinstance(item, dict) and "operator_id" in item
        }
        self.pending.clear()
        self.sessions.clear()
        self.connected = True
        self._log_event("relay.connected", self.config.relay_url)

    def _reset_sessions(self, reason: str) -> None:
        if self.pending or self.sessions:
            self._log_event("sessions.reset", reason)
        self.pending.clear()
        self.sessions.clear()

    def _log_event(self, action: str, detail: str = "") -> None:
        self.events.appendleft({"ts": now_iso(), "action": action, "detail": detail})

    def _check_lock(self) -> None:
        if not self.unlocked:
            return
        timeout = self.settings.agent_lock_timeout_seconds
        if self.last_activity and time.monotonic() - self.last_activity > timeout:
            self.unlocked = False
            self._log_event("panel.locked", "idle timeout")

    def _ensure_unlocked(self) -> None:
        self._check_lock()
        if not self.unlocked:
            raise AgentError("Панель заблокирована. Введите пароль хоста.")

    def unlock(self, password: str) -> bool:
        if not verify_password(password, self.config.password_hash):
            self._log_event("panel.unlock_failed", "wrong password")
            return False
        self.unlocked = True
        self.last_activity = time.monotonic()
        self._log_event("panel.unlocked")
        return True

    def lock(self) -> None:
        self.unlocked = False
        self._log_event("panel.locked", "manual")

    def _touch(self) -> None:
        self.last_activity = time.monotonic()

    async def _send(
        self,
        message_type: str,
        payload: dict[str, Any],
        ref: str | None = None,
    ) -> None:
        socket = self._socket
        if socket is None or not self.connected:
            raise DeviceOfflineError("нет соединения с relay")
        envelope = Envelope(type=message_type, payload=payload, ref=ref)
        try:
            async with self._send_lock:
                await socket.send(envelope.to_json())
        except Exception as exc:
            self.connected = False
            raise DeviceOfflineError("соединение с relay потеряно") from exc

    async def approve(self, session_id: str, capabilities: list[str]) -> None:
        self._ensure_unlocked()
        pending = self.pending.get(session_id)
        if pending is None:
            raise NotFoundError("запрос не найден")
        granted = policy.normalize(
            [item for item in capabilities if item in pending.requested_capabilities]
        )
        if not granted:
            raise CapabilityError("выберите хотя бы одно право из запрошенных")
        await self._send(
            Msg.SESSION_DECISION,
            {"session_id": session_id, "approved": True, "capabilities": granted},
        )
        pending.decision = "approved"
        self._touch()
        self._log_event(
            "session.approved",
            f"{pending.operator_username or pending.operator_id}: {policy.describe(granted)}",
        )

    async def deny(self, session_id: str, reason: str = "host_denied") -> None:
        self._ensure_unlocked()
        pending = self.pending.get(session_id)
        if pending is None:
            raise NotFoundError("запрос не найден")
        await self._send(
            Msg.SESSION_DECISION,
            {"session_id": session_id, "approved": False, "reason": reason},
        )
        pending.decision = "denied"
        self._touch()
        self._log_event("session.denied", pending.operator_username or str(pending.operator_id))

    async def close_session(self, session_id: str) -> None:
        self._ensure_unlocked()
        if session_id in self.pending:
            await self.deny(session_id, "host_cancelled")
            return
        session = self.sessions.get(session_id)
        if session is None:
            raise NotFoundError("сессия не найдена")
        await self._send(
            Msg.SESSION_CLOSE_REQUEST,
            {"session_id": session_id, "reason": "host_closed"},
        )
        session.closing = True
        self._touch()
        self._log_event(
            "session.close_requested", session.operator_username or str(session.operator_id)
        )

    async def update_policy(self, capabilities: list[str]) -> list[str]:
        self._ensure_unlocked()
        normalized = policy.sanitize(capabilities, allow_empty=True)
        await self._send(Msg.POLICY_UPDATE, {"capabilities": normalized})
        self.device["capabilities"] = normalized
        self._touch()
        self._log_event("policy.updated", policy.describe(normalized))
        return normalized

    async def revoke_grant(self, operator_id: int) -> None:
        self._ensure_unlocked()
        await self._send(Msg.GRANT_REVOKE, {"operator_id": operator_id})
        self.grants.pop(operator_id, None)
        self._touch()
        self._log_event("grant.revoked", str(operator_id))

    async def set_session_capabilities(self, session_id: str, capabilities: list[str]) -> None:
        self._ensure_unlocked()
        session = self.sessions.get(session_id)
        if session is None:
            raise NotFoundError("сессия не найдена")
        requested = set(capabilities)
        if not requested <= set(session.capabilities):
            raise CapabilityError("права можно только сократить")
        if not requested:
            raise CapabilityError("для полного запрета завершите сессию")
        await self._send(
            Msg.SESSION_CAPABILITIES,
            {"session_id": session_id, "capabilities": list(requested)},
        )
        self._touch()
        self._log_event("session.capabilities_requested", policy.describe(list(requested)))

    def state(self) -> dict[str, Any]:
        self._check_lock()
        sessions = []
        for session in self.sessions.values():
            sessions.append(
                {
                    "id": session.id,
                    "operator_id": session.operator_id,
                    "operator_username": session.operator_username,
                    "purpose": session.purpose,
                    "capabilities": session.capabilities,
                    "created_at": session.created_at,
                    "expires_at": session.expires_at,
                    "cwd": str(session.cwd),
                    "closing": session.closing,
                    "has_screenshot": session.screenshot is not None,
                    "history": list(session.history),
                }
            )
        pending = [
            {
                "id": item.id,
                "operator_id": item.operator_id,
                "operator_username": item.operator_username,
                "purpose": item.purpose,
                "requested_capabilities": item.requested_capabilities,
                "previous_capabilities": item.previous_capabilities,
                "requested_at": item.requested_at,
                "expires_at": item.expires_at,
                "decision": item.decision,
            }
            for item in self.pending.values()
        ]
        return {
            "device": {
                "id": self.device.get("id"),
                "name": self.device.get("name"),
                "hostname": self.device.get("hostname"),
                "os_name": self.device.get("os_name"),
                "capabilities": self.device.get("capabilities", []),
            },
            "connected": self.connected,
            "locked": not self.unlocked,
            "proxy": self._resolver.display,
            "lock_timeout": self.settings.agent_lock_timeout_seconds,
            "pending": pending,
            "sessions": sessions,
            "grants": list(self.grants.values()),
            "events": list(self.events),
        }

    def screenshot(self, session_id: str) -> tuple[bytes, dict[str, Any]]:
        session = self.sessions.get(session_id)
        if session is None or session.screenshot is None:
            raise NotFoundError("снимок не найден")
        return session.screenshot, session.screenshot_meta

    async def _handle(self, envelope: Envelope) -> None:
        try:
            if envelope.type == Msg.SESSION_REQUEST:
                self._on_session_request(envelope.payload)
            elif envelope.type == Msg.SESSION_APPROVED:
                self._on_session_approved(envelope.payload)
            elif envelope.type == Msg.SESSION_DENIED:
                session_id = str(envelope.payload.get("session_id", ""))
                pending = self.pending.pop(session_id, None)
                if pending is not None:
                    self._log_event("session.denied_by_server", pending.operator_username or "")
            elif envelope.type == Msg.SESSION_CLOSE:
                session_id = str(envelope.payload.get("session_id", ""))
                self.pending.pop(session_id, None)
                session = self.sessions.pop(session_id, None)
                if session is not None:
                    self._log_event(
                        "session.closed",
                        f"{session.operator_username or session.operator_id}: "
                        f"{envelope.payload.get('reason', 'closed')}",
                    )
            elif envelope.type == Msg.SESSION_UPDATE:
                session_id = str(envelope.payload.get("session_id", ""))
                session = self.sessions.get(session_id)
                if session is not None:
                    capabilities = policy.normalize(envelope.payload.get("capabilities", []))
                    if policy.CAP_SCREENSHOT not in capabilities:
                        session.screenshot = None
                        session.screenshot_meta = {}
                    session.capabilities = capabilities
                    self._log_event("session.rights_changed", policy.describe(capabilities))
            elif envelope.type == Msg.COMMAND_EXEC:
                await self._run_command(envelope)
            elif envelope.type == Msg.SCREENSHOT_REQUEST:
                await self._run_screenshot(envelope)
            elif envelope.type == Msg.POLICY_UPDATED:
                capabilities = policy.normalize(envelope.payload.get("capabilities", []))
                self.device["capabilities"] = capabilities
                self._log_event("policy.confirmed", policy.describe(capabilities))
            elif envelope.type == Msg.GRANT_REVOKED:
                operator_id = int(envelope.payload.get("operator_id", 0))
                self.grants.pop(operator_id, None)
                self._log_event("grant.revoked_confirmed", str(operator_id))
            elif envelope.type == Msg.ERROR:
                session_id = envelope.payload.get("session_id")
                if isinstance(session_id, str):
                    self.pending.pop(session_id, None)
                self._log_event("relay.error", str(envelope.payload.get("message", "")))
                log.warning("relay error: %s", envelope.payload.get("message"))
            else:
                log.debug("unhandled relay message %s", envelope.type)
        except Exception:
            log.exception("failed to handle %s", envelope.type)

    def _on_session_request(self, payload: dict[str, Any]) -> None:
        operator = payload.get("operator") or {}
        session = PendingSession(
            id=str(payload.get("session_id", "")),
            operator_id=int(operator.get("id", 0)),
            operator_username=operator.get("username"),
            purpose=str(payload.get("purpose", "support")),
            requested_capabilities=policy.normalize(payload.get("requested_capabilities", [])),
            previous_capabilities=(
                policy.normalize(payload.get("previous_capabilities", []))
                if payload.get("previous_capabilities") is not None
                else None
            ),
            requested_at=str(payload.get("requested_at", now_iso())),
            expires_at=str(payload.get("expires_at", "")),
        )
        self.pending[session.id] = session
        self._log_event(
            "session.requested",
            f"{session.operator_username or session.operator_id}: "
            f"{policy.describe(session.requested_capabilities)}",
        )

    def _on_session_approved(self, payload: dict[str, Any]) -> None:
        session_id = str(payload.get("session_id", ""))
        account = payload.get("account") or {}
        operator = payload.get("operator") or {}
        capabilities = policy.normalize(payload.get("capabilities", []))
        self.sessions[session_id] = ActiveSession(
            id=session_id,
            account_id=str(account.get("id", "")),
            account_token=str(account.get("token", "")),
            operator_id=int(operator.get("id", 0)),
            operator_username=operator.get("username"),
            purpose=str(payload.get("purpose", "support")),
            capabilities=capabilities,
            created_at=now_iso(),
            expires_at=str(payload.get("expires_at", "")),
            cwd=Path.home(),
        )
        self.pending.pop(session_id, None)
        operator_id = int(operator.get("id", 0))
        self.grants[operator_id] = {
            "operator_id": operator_id,
            "capabilities": capabilities,
            "updated_at": now_iso(),
        }
        self._log_event(
            "session.active",
            f"{operator.get('username') or operator_id}: {policy.describe(capabilities)}",
        )

    async def _run_command(self, envelope: Envelope) -> None:
        payload = envelope.payload
        session_id = str(payload.get("session_id", ""))
        session = self.sessions.get(session_id)
        account_token = str(payload.get("account_token", ""))
        result: dict[str, Any]
        if session is None:
            result = {"error": "неизвестная сессия"}
        elif not hmac.compare_digest(session.account_token, account_token):
            result = {"error": "неверная учётная запись сессии"}
        elif policy.CAP_SHELL not in session.capabilities:
            result = {"error": "право shell не выдано"}
        elif len(str(payload.get("command", ""))) > 8000:
            result = {"error": "команда слишком длинная"}
        else:
            command = str(payload.get("command", ""))
            started_at = now_iso()
            try:
                async with session.lock:
                    outcome = await self.runner.run(command, session.cwd)
                    session.cwd = Path(outcome.cwd)
                    session.history.appendleft(
                        {
                            "command": command,
                            "output": outcome.output[:600],
                            "exit_code": outcome.exit_code,
                            "truncated": outcome.truncated,
                            "timed_out": outcome.timed_out,
                            "started_at": started_at,
                        }
                    )
                result = {
                    "output": outcome.output,
                    "exit_code": outcome.exit_code,
                    "cwd": outcome.cwd,
                    "truncated": outcome.truncated,
                    "timed_out": outcome.timed_out,
                }
                self._log_event("command.executed", command[:120])
            except Exception as exc:
                log.exception("command execution failed")
                result = {"error": f"ошибка выполнения: {exc}"}
        await self._send(Msg.COMMAND_RESULT, result, ref=envelope.id)

    async def _run_screenshot(self, envelope: Envelope) -> None:
        payload = envelope.payload
        session_id = str(payload.get("session_id", ""))
        session = self.sessions.get(session_id)
        account_token = str(payload.get("account_token", ""))
        if session is None:
            await self._send(
                Msg.SCREENSHOT_RESULT, {"error": "неизвестная сессия"}, ref=envelope.id
            )
            return
        if not hmac.compare_digest(session.account_token, account_token):
            await self._send(
                Msg.SCREENSHOT_RESULT,
                {"error": "неверная учётная запись сессии"},
                ref=envelope.id,
            )
            return
        if policy.CAP_SCREENSHOT not in session.capabilities:
            await self._send(
                Msg.SCREENSHOT_RESULT,
                {"error": "право на снимок экрана не выдано"},
                ref=envelope.id,
            )
            return
        try:
            shot = await asyncio.to_thread(capture_screenshot, self.settings.screenshot_max_bytes)
        except Exception as exc:
            await self._send(Msg.SCREENSHOT_RESULT, {"error": str(exc)}, ref=envelope.id)
            return
        session.screenshot = shot.image
        session.screenshot_meta = {
            "width": shot.width,
            "height": shot.height,
            "taken_at": shot.taken_at,
        }
        self._log_event(
            "screenshot.shared",
            f"{session.operator_username or session.operator_id}: {len(shot.image)} bytes",
        )
        await self._send(
            Msg.SCREENSHOT_RESULT,
            {
                "image": base64.b64encode(shot.image).decode("ascii"),
                "width": shot.width,
                "height": shot.height,
                "taken_at": shot.taken_at,
            },
            ref=envelope.id,
        )
