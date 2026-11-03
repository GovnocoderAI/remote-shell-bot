from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from rsb.errors import DeviceOfflineError
from rsb.protocol import Envelope

if TYPE_CHECKING:
    from fastapi import WebSocket

log = logging.getLogger("rsb.hub")


class AgentConnection:
    def __init__(self, device_id: str, websocket: WebSocket, on_message) -> None:
        self.device_id = device_id
        self.websocket = websocket
        self._on_message = on_message
        self._pending: dict[str, asyncio.Future[Envelope]] = {}
        self._send_lock = asyncio.Lock()
        self.closed = False

    async def send_envelope(self, envelope: Envelope) -> None:
        if self.closed:
            raise DeviceOfflineError("agent connection is closed")
        async with self._send_lock:
            await self.websocket.send_text(envelope.to_json())

    async def send(
        self,
        message_type: str,
        payload: dict[str, Any] | None = None,
        ref: str | None = None,
    ) -> None:
        await self.send_envelope(Envelope(type=message_type, payload=payload or {}, ref=ref))

    async def request(
        self, message_type: str, payload: dict[str, Any], wait_seconds: float
    ) -> Envelope:
        envelope = Envelope(type=message_type, payload=payload)
        future: asyncio.Future[Envelope] = asyncio.get_running_loop().create_future()
        self._pending[envelope.id] = future
        try:
            await self.send_envelope(envelope)
            return await asyncio.wait_for(future, wait_seconds)
        finally:
            self._pending.pop(envelope.id, None)

    async def dispatch(self, envelope: Envelope) -> None:
        if envelope.ref is not None:
            future = self._pending.get(envelope.ref)
            if future is not None and not future.done():
                future.set_result(envelope)
                return
        await self._on_message(self, envelope)

    def fail(self, error: BaseException) -> None:
        self.closed = True
        for future in self._pending.values():
            if not future.done():
                future.set_exception(error)
        self._pending.clear()


class Hub:
    def __init__(self) -> None:
        self._connections: dict[str, AgentConnection] = {}

    def get(self, device_id: str) -> AgentConnection | None:
        return self._connections.get(device_id)

    def is_online(self, device_id: str) -> bool:
        connection = self._connections.get(device_id)
        return connection is not None and not connection.closed

    def device_ids(self) -> list[str]:
        return list(self._connections)

    def register(self, connection: AgentConnection) -> AgentConnection | None:
        previous = self._connections.get(connection.device_id)
        self._connections[connection.device_id] = connection
        return previous

    def unregister(self, device_id: str, connection: AgentConnection) -> bool:
        current = self._connections.get(device_id)
        if current is connection:
            self._connections.pop(device_id, None)
            return True
        return False

    async def send(
        self,
        device_id: str,
        message_type: str,
        payload: dict[str, Any],
        ref: str | None = None,
    ) -> bool:
        connection = self._connections.get(device_id)
        if connection is None or connection.closed:
            return False
        try:
            await connection.send(message_type, payload, ref)
            return True
        except Exception:
            log.warning("failed to send %s to device %s", message_type, device_id, exc_info=True)
            return False

    async def request(
        self,
        device_id: str,
        message_type: str,
        payload: dict[str, Any],
        wait_seconds: float,
    ) -> Envelope:
        connection = self._connections.get(device_id)
        if connection is None or connection.closed:
            raise DeviceOfflineError("device is offline")
        return await connection.request(message_type, payload, wait_seconds)

    async def shutdown(self) -> None:
        connections = list(self._connections.values())
        self._connections.clear()
        for connection in connections:
            connection.fail(DeviceOfflineError("server is shutting down"))
            try:
                await connection.websocket.close(code=1001)
            except Exception:
                continue
