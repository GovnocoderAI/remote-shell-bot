from __future__ import annotations

import asyncio
import contextlib


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def handle_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await reader.readline()
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        method, target, _ = request.decode("latin-1").split()
        if method != "CONNECT":
            return
        host, port = target.rsplit(":", 1)
        remote_reader, remote_writer = await asyncio.open_connection(host, int(port))
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(_pipe(reader, remote_writer), _pipe(remote_reader, writer))
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def start_http_proxy() -> asyncio.Server:
    return await asyncio.start_server(handle_connect, "127.0.0.1", 0)


def proxy_url(server: asyncio.Server) -> str:
    port = server.sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}"
