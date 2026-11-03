from __future__ import annotations

import asyncio
import base64
import socket
import time

import httpx
import uvicorn
import websockets

from rsb.config import Settings
from rsb.protocol import Msg, decode, encode
from rsb.security import device_message, sign
from rsb.server.app import create_app
from rsb.util import new_nonce


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _wait_started(server: uvicorn.Server, wait_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + wait_seconds
    while not server.started:
        if time.monotonic() > deadline:
            raise TimeoutError("relay did not start")
        await asyncio.sleep(0.02)


async def test_end_to_end_session_flow(tmp_path) -> None:
    port = _free_port()
    settings = Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "relay.sqlite3",
        secret_key="integration-secret-key-material-0123456789",
        admin_ids="100",
        public_url=f"ws://127.0.0.1:{port}",
    )
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    )
    serve_task = asyncio.create_task(server.serve())
    try:
        await _wait_started(server)
        service = app.state.service
        await service.repo.ensure_operator(100, "admin")
        token, _ = await service.issue_enrollment(100, "integration")

        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            health = await client.get("/healthz")
            assert health.status_code == 200
            enrolled = await client.post(
                "/api/enroll",
                json={
                    "token": token,
                    "name": "integration-pc",
                    "hostname": "integration.local",
                    "os_name": "Linux",
                    "os_version": "6.8",
                },
            )
        assert enrolled.status_code == 200
        credentials = enrolled.json()
        device_id = credentials["device_id"]
        secret = credentials["device_secret"]

        nonce = new_nonce()
        timestamp = int(time.time())
        signature = sign(secret, device_message(device_id, nonce, timestamp))
        async with websockets.connect(f"ws://127.0.0.1:{port}/agent") as socket:
            await socket.send(
                encode(
                    Msg.HELLO,
                    {
                        "device_id": device_id,
                        "nonce": nonce,
                        "timestamp": timestamp,
                        "signature": signature,
                    },
                )
            )
            hello = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert hello.type == Msg.HELLO_OK
            assert hello.payload["device"]["id"] == device_id

            session = await service.request_session(100, device_id, "support", ["shell"])
            request = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert request.type == Msg.SESSION_REQUEST
            assert request.payload["session_id"] == session["id"]

            await socket.send(
                encode(
                    Msg.SESSION_DECISION,
                    {
                        "session_id": session["id"],
                        "approved": True,
                        "capabilities": ["shell"],
                    },
                )
            )
            approved = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert approved.type == Msg.SESSION_APPROVED
            assert approved.payload["capabilities"] == ["shell"]

            command_task = asyncio.create_task(
                service.execute_command(session["id"], 100, "uname -a")
            )
            execution = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert execution.type == Msg.COMMAND_EXEC
            await socket.send(
                encode(
                    Msg.COMMAND_RESULT,
                    {
                        "output": "Linux integration\n",
                        "exit_code": 0,
                        "cwd": "/home/user",
                        "truncated": False,
                        "timed_out": False,
                    },
                    ref=execution.id,
                )
            )
            result = await asyncio.wait_for(command_task, timeout=5)
            assert result["output"] == "Linux integration\n"
            assert result["exit_code"] == 0

            await service.close_session(
                session["id"],
                actor_type="operator",
                actor_id=100,
                operator_id=100,
            )
            closing = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert closing.type == Msg.SESSION_CLOSE
    finally:
        server.should_exit = True
        await asyncio.wait_for(serve_task, timeout=15)


async def test_screenshot_requires_granted_capability_end_to_end(tmp_path) -> None:
    port = _free_port()
    settings = Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "relay.sqlite3",
        secret_key="integration-secret-key-material-0123456789",
        admin_ids="100",
        public_url=f"ws://127.0.0.1:{port}",
    )
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    )
    serve_task = asyncio.create_task(server.serve())
    try:
        await _wait_started(server)
        service = app.state.service
        await service.repo.ensure_operator(100, "admin")
        token, _ = await service.issue_enrollment(100, "integration")
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            enrolled = await client.post(
                "/api/enroll",
                json={"token": token, "name": "shot-pc", "os_name": "Linux"},
            )
        assert enrolled.status_code == 200
        credentials = enrolled.json()
        device_id = credentials["device_id"]
        secret = credentials["device_secret"]

        await service.update_policy(device_id, ["shell", "screenshot"])
        nonce = new_nonce()
        timestamp = int(time.time())
        signature = sign(secret, device_message(device_id, nonce, timestamp))
        async with websockets.connect(f"ws://127.0.0.1:{port}/agent") as socket:
            await socket.send(
                encode(
                    Msg.HELLO,
                    {
                        "device_id": device_id,
                        "nonce": nonce,
                        "timestamp": timestamp,
                        "signature": signature,
                    },
                )
            )
            hello = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert hello.type == Msg.HELLO_OK
            assert hello.payload["device"]["capabilities"] == ["shell", "screenshot"]

            session = await service.request_session(
                100, device_id, "support", ["shell", "screenshot"]
            )
            request = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert request.type == Msg.SESSION_REQUEST
            await socket.send(
                encode(
                    Msg.SESSION_DECISION,
                    {
                        "session_id": session["id"],
                        "approved": True,
                        "capabilities": ["shell", "screenshot"],
                    },
                )
            )
            approved = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert approved.type == Msg.SESSION_APPROVED

            capture_task = asyncio.create_task(service.capture_screenshot(session["id"], 100))
            screenshot_request = decode(await asyncio.wait_for(socket.recv(), timeout=5))
            assert screenshot_request.type == Msg.SCREENSHOT_REQUEST
            await socket.send(
                encode(
                    Msg.SCREENSHOT_RESULT,
                    {
                        "image": base64.b64encode(b"image-bytes").decode("ascii"),
                        "width": 800,
                        "height": 600,
                        "taken_at": "2026-01-01T00:00:00+00:00",
                    },
                    ref=screenshot_request.id,
                )
            )
            image, meta = await asyncio.wait_for(capture_task, timeout=5)
            assert image == b"image-bytes"
            assert meta["width"] == 800
    finally:
        server.should_exit = True
        await asyncio.wait_for(serve_task, timeout=15)
