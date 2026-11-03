from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from rsb.config import Settings
from rsb.db.database import Database
from rsb.errors import DeviceOfflineError, ProtocolError, RsbError
from rsb.logging import configure_logging
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


class EnrollRequest(BaseModel):
    token: str = Field(min_length=16, max_length=256)
    name: str = Field(default="", max_length=64)
    hostname: str | None = Field(default=None, max_length=128)
    os_name: str | None = Field(default=None, max_length=64)
    os_version: str | None = Field(default=None, max_length=64)


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
            bot = Bot(token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
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
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        service: Service = app.state.service
        stats = await service.repo.stats()
        return {"status": "ok", "time": int(time.time()), **stats}

    @app.post("/api/enroll")
    async def enroll(body: EnrollRequest) -> dict[str, Any]:
        service: Service = app.state.service
        try:
            device, secret = await service.enroll_device(
                body.token, body.name, body.hostname, body.os_name, body.os_version
            )
        except RsbError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {
            "device_id": device["id"],
            "device_secret": secret,
            "name": device["name"],
            "capabilities": device["capabilities"],
        }

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
