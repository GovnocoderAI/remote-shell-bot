from __future__ import annotations

import asyncio

import websockets

from rsb.net.diagnostics import probe_websocket
from tests.proxy_helpers import proxy_url, start_http_proxy


async def _echo(socket) -> None:
    async for message in socket:
        await socket.send(message)


async def test_websocket_through_http_connect_proxy() -> None:
    ws_server = await websockets.serve(_echo, "127.0.0.1", 0)
    proxy_server = await start_http_proxy()
    ws_port = ws_server.sockets[0].getsockname()[1]
    proxy = proxy_url(proxy_server)
    try:
        async with websockets.connect(f"ws://127.0.0.1:{ws_port}", proxy=proxy) as socket:
            await socket.send("ping")
            assert await asyncio.wait_for(socket.recv(), timeout=2) == "ping"

        result = await probe_websocket(
            f"ws://127.0.0.1:{ws_port}",
            proxy=proxy,
            wait_seconds=2,
        )
        assert result.ok
    finally:
        proxy_server.close()
        await proxy_server.wait_closed()
        ws_server.close()
        await ws_server.wait_closed()
