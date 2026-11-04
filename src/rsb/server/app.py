from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import socket
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Any

import psutil
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode
from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, Field

from rsb import __version__
from rsb.config import Settings
from rsb.db.database import Database
from rsb.errors import (
    AuthorizationError,
    ConfigError,
    DeviceOfflineError,
    NotFoundError,
    ProtocolError,
    RsbError,
)
from rsb.logging import configure_logging
from rsb.net.proxy import ProxyFormatError, normalize_proxy, redact_proxy
from rsb.protocol import Msg, decode, encode
from rsb.server.bot import build_router
from rsb.server.bot.notifier import TelegramNotifier
from rsb.server.hub import AgentConnection
from rsb.server.service import Service

log = logging.getLogger("rsb.server")


async def _run_bot(
    dispatcher: Dispatcher,
    bot: Bot,
    stop: asyncio.Event,
    retry_delay: float = 1.0,
) -> None:
    delay = retry_delay
    while not stop.is_set():
        try:
            await dispatcher.start_polling(bot, handle_signals=False, close_bot_session=False)
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("telegram polling failed: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
            return
        except TimeoutError:
            delay = min(delay * 2, 60.0)


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        bucket = self._hits.setdefault(key, deque())
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True


class EnrollRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    name: str = Field(default="", max_length=64)
    hostname: str | None = Field(default=None, max_length=128)
    os_name: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=64)


class ConsoleSessionRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=64)
    capabilities: list[str] = Field(default_factory=lambda: ["shell"])
    purpose: str = Field(default="console", max_length=120)


class ConsoleCommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=4000)


def _public_device(device: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in device.items() if key not in {"secret_encrypted"}}


def _local_console_addresses() -> set[str]:
    addresses = {"127.0.0.1", "::1", "localhost", "testclient"}
    try:
        for entries in psutil.net_if_addrs().values():
            for entry in entries:
                if entry.family == socket.AF_INET:
                    addresses.add(entry.address)
    except Exception:
        pass
    return addresses


def create_app(settings: Settings | None = None) -> FastAPI:
    current = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging(current.log_level)
        current.ensure_dirs()
        database = Database(current.db_path)
        await database.open()
        service = Service(database, current)
        await service.startup_cleanup()
        app.state.service = service
        stop = asyncio.Event()
        maintenance = asyncio.create_task(service.maintenance_loop(stop))
        bot: Bot | None = None
        polling: asyncio.Task[None] | None = None
        token = current.bot_token.get_secret_value().strip()
        if token:
            session = None
            telegram_proxy = current.telegram_proxy.strip()
            if telegram_proxy.lower() in {"auto", "public"}:
                from rsb.net.pool import select_proxy

                selection = await select_proxy(
                    "https://api.telegram.org/",
                    allow_direct=True,
                    allow_public=True,
                    wait_seconds=max(current.proxy_timeout_seconds, 20.0),
                    concurrency=current.proxy_concurrency,
                    max_test=min(current.public_proxy_max_test, 120),
                    cache_path=current.proxy_cache_path,
                    cache_ttl=current.proxy_cache_ttl_seconds,
                    extra_source_urls=current.public_source_urls,
                )
                telegram_proxy = selection.proxy or ""
                if not telegram_proxy:
                    raise ConfigError("no working proxy for the Telegram Bot API")
                log.info("telegram proxy auto-selected: %s", redact_proxy(telegram_proxy))
            if telegram_proxy:
                try:
                    telegram_proxy = normalize_proxy(telegram_proxy)
                except ProxyFormatError as exc:
                    raise ConfigError(f"RSB_TELEGRAM_PROXY is invalid: {exc}") from exc
                session = AiohttpSession(proxy=telegram_proxy)
                log.info("telegram proxy enabled: %s", redact_proxy(telegram_proxy))
            bot = Bot(
                token,
                session=session,
                default=DefaultBotProperties(parse_mode=ParseMode.HTML),
            )
            dispatcher = Dispatcher()
            dispatcher.include_router(build_router(service, current))
            service.notifier = TelegramNotifier(bot)
            polling = asyncio.create_task(_run_bot(dispatcher, bot, stop))
            log.info("telegram polling started")
        else:
            log.warning("RSB_BOT_TOKEN is not set, relay is running without Telegram")
        try:
            yield
        finally:
            stop.set()
            maintenance.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await maintenance
            if polling is not None:
                polling.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await polling
            if bot is not None:
                await bot.session.close()
            await service.shutdown()
            await database.close()

    app = FastAPI(
        title="RemoteShellBot",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    enroll_attempts = SlidingWindow(limit=10, window_seconds=60)

    console_requests = SlidingWindow(10, 60)
    console_commands = SlidingWindow(60, 60)

    def console_operator_id() -> int:
        if current.console_operator_id:
            return current.console_operator_id
        return min(current.admin_ids_set) if current.admin_ids_set else 0

    def console_auth(request: Request) -> int:
        token = current.console_token.get_secret_value().strip()
        if not token:
            raise HTTPException(status_code=404, detail="console api is disabled")
        provided = request.headers.get("X-RSB-Console-Token", "")
        if not provided or not hmac.compare_digest(provided, token):
            raise HTTPException(status_code=401, detail="invalid console token")
        host = request.client.host if request.client else ""
        if not current.console_allow_remote and host not in _local_console_addresses():
            raise HTTPException(status_code=403, detail="console api is local-only")
        operator_id = console_operator_id()
        if not operator_id:
            raise HTTPException(status_code=503, detail="console operator is not configured")
        return operator_id

    async def ensure_console_operator(service: Service, operator_id: int) -> dict:
        operator = await service.repo.get_operator(operator_id)
        if operator is None:
            operator = await service.repo.ensure_operator(operator_id, "console")
        return operator

    def console_error(exc: Exception) -> HTTPException:
        if isinstance(exc, NotFoundError):
            status = 404
        elif isinstance(exc, AuthorizationError):
            status = 403
        elif isinstance(exc, DeviceOfflineError):
            status = 503
        else:
            status = 400
        return HTTPException(status_code=status, detail=str(exc))

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "time": int(time.time())}

    @app.get("/readyz")
    async def readyz() -> dict[str, Any]:
        service: Service = app.state.service
        try:
            stats = await service.repo.stats()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="database unavailable") from exc
        return {"status": "ready", "time": int(time.time()), **stats}

    @app.post("/api/enroll")
    async def enroll(body: EnrollRequest, request: Request) -> dict[str, Any]:
        service: Service = app.state.service
        client_host = request.client.host if request.client else "unknown"
        if not enroll_attempts.allow(client_host):
            raise HTTPException(status_code=429, detail="too many enrollment attempts")
        try:
            device, secret = await service.enroll_device(
                body.token, body.name, body.hostname, body.os_name, body.os_version
            )
        except RsbError as exc:
            await service.repo.add_audit(
                "enrollment.rejected",
                actor_type="anonymous",
                detail={"ip": client_host, "reason": str(exc)},
            )
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {
            "device_id": device["id"],
            "device_secret": secret,
            "name": device["name"],
            "capabilities": device["capabilities"],
        }

    @app.get("/api/console/overview")
    async def console_overview(
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        service: Service = app.state.service
        operator = await ensure_console_operator(service, operator_id)
        return {
            "operator": {
                "id": operator_id,
                "username": operator.get("username"),
            },
            "stats": await service.repo.stats(),
            "devices": [_public_device(device) for device in await service.repo.list_devices()],
            "session": await service.repo.get_open_session_for_operator(operator_id),
            "audit": await service.repo.list_audit(10),
        }

    @app.get("/api/console/devices")
    async def console_devices(
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        service: Service = app.state.service
        return {"devices": [_public_device(device) for device in await service.repo.list_devices()]}

    @app.post("/api/console/sessions")
    async def console_request_session(
        body: ConsoleSessionRequest,
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        if not console_requests.allow(str(operator_id)):
            raise HTTPException(status_code=429, detail="too many session requests")
        service: Service = app.state.service
        await ensure_console_operator(service, operator_id)
        try:
            session = await service.request_session(
                operator_id, body.device_id, body.purpose, body.capabilities
            )
        except RsbError as exc:
            raise console_error(exc) from exc
        return {"session": session}

    @app.get("/api/console/sessions/current")
    async def console_current_session(
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        service: Service = app.state.service
        session = await service.repo.get_open_session_for_operator(operator_id)
        if session is None:
            return {"session": None, "commands": []}
        commands = await service.repo.list_commands(session["id"], 30)
        return {"session": session, "commands": commands}

    @app.get("/api/console/sessions/{session_id}")
    async def console_session(
        session_id: str,
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        service: Service = app.state.service
        session = await service.repo.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        if session["operator_id"] != operator_id:
            raise HTTPException(status_code=403, detail="session belongs to another operator")
        return {
            "session": session,
            "commands": await service.repo.list_commands(session_id, 30),
        }

    @app.post("/api/console/sessions/{session_id}/command")
    async def console_command(
        session_id: str,
        body: ConsoleCommandRequest,
        operator_id: int = Depends(console_auth),
    ) -> dict[str, Any]:
        if not console_commands.allow(str(operator_id)):
            raise HTTPException(status_code=429, detail="too many commands")
        service: Service = app.state.service
        try:
            result = await service.execute_command(session_id, operator_id, body.command)
        except RsbError as exc:
            raise console_error(exc) from exc
        return {"result": result}

    @app.get("/api/console/sessions/{session_id}/screenshot")
    async def console_screenshot(
        session_id: str,
        operator_id: int = Depends(console_auth),
    ) -> Response:
        service: Service = app.state.service
        try:
            image, meta = await service.capture_screenshot(session_id, operator_id, notify=False)
        except RsbError as exc:
            raise console_error(exc) from exc
        return Response(
            content=image,
            media_type="image/jpeg",
            headers={
                "Cache-Control": "no-store",
                "X-RSB-Width": str(meta.get("width") or ""),
                "X-RSB-Height": str(meta.get("height") or ""),
                "X-RSB-Taken-At": str(meta.get("taken_at") or ""),
            },
        )

    @app.post("/api/console/sessions/{session_id}/close")
    async def console_close_session(
        session_id: str,
        operator_id: int = Depends(console_auth),
    ) -> dict[str, str]:
        service: Service = app.state.service
        try:
            await service.close_session(
                session_id,
                actor_type="console",
                actor_id=operator_id,
                reason="console_closed",
                operator_id=operator_id,
            )
        except RsbError as exc:
            raise console_error(exc) from exc
        return {"status": "closed"}

    @app.get("/api/console/audit")
    async def console_audit(
        operator_id: int = Depends(console_auth),
        limit: int = 20,
    ) -> dict[str, Any]:
        service: Service = app.state.service
        bounded = max(1, min(limit, 100))
        return {"audit": await service.repo.list_audit(bounded)}

    @app.websocket("/agent")
    async def agent_socket(websocket: WebSocket) -> None:
        service: Service = app.state.service
        await websocket.accept()
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=15)
            envelope = decode(raw)
            if envelope.type != Msg.HELLO:
                raise ProtocolError("first frame must be hello")
            payload = envelope.payload
            device = await service.authenticate_device(
                device_id=str(payload["device_id"]),
                nonce=str(payload["nonce"]),
                timestamp=int(payload["timestamp"]),
                signature=str(payload["signature"]),
            )
        except WebSocketDisconnect:
            return
        except (TimeoutError, KeyError, TypeError, ValueError, ProtocolError, RsbError) as exc:
            log.warning("handshake rejected: %s", exc)
            with contextlib.suppress(Exception):
                await websocket.send_text(encode(Msg.HELLO_ERROR, {"message": str(exc)}))
                await websocket.close(code=1008)
            return
        connection = AgentConnection(device["id"], websocket, service.handle_agent_message)
        try:
            hello = await service.attach_device(device, connection)
            await connection.send(Msg.HELLO_OK, hello)
            while True:
                raw = await websocket.receive_text()
                try:
                    incoming = decode(raw)
                except ProtocolError as exc:
                    log.warning("invalid frame from %s: %s", device["id"], exc)
                    await websocket.close(code=1009)
                    break
                await connection.dispatch(incoming)
        except WebSocketDisconnect:
            pass
        except Exception:
            log.exception("agent connection failed for %s", device["id"])
        finally:
            connection.fail(DeviceOfflineError("connection closed"))
            if service.hub.unregister(device["id"], connection):
                await service.detach_device(device["id"])

    return app
