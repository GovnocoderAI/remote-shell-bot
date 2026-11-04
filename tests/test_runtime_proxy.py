from __future__ import annotations

import asyncio
import contextlib
import socket

import uvicorn

from rsb.agent.config import AgentConfig, hash_password
from rsb.agent.runtime import AgentRuntime
from rsb.config import Settings
from rsb.net.pool import StaticResolver
from rsb.server.app import create_app
from tests.proxy_helpers import proxy_url, start_http_proxy


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _wait_started(server: uvicorn.Server, wait_seconds: float = 10.0) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while not server.started:
        if loop.time() > deadline:
            raise TimeoutError("relay did not start")
        await asyncio.sleep(0.02)


async def _wait_until(predicate, wait_seconds: float = 10.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return False


async def test_agent_connects_through_local_proxy(tmp_path) -> None:
    relay_port = _free_port()
    ui_port = _free_port()
    settings = Settings(
        data_dir=tmp_path / "server",
        database_path=tmp_path / "server" / "relay.sqlite3",
        secret_key="runtime-proxy-secret-key-material-0123456789",
        admin_ids="100",
        public_url=f"ws://127.0.0.1:{relay_port}",
    )
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=relay_port, log_level="warning", access_log=False
        )
    )
    server_task = asyncio.create_task(server.serve())
    proxy_server = await start_http_proxy()
    runtime_task: asyncio.Task[None] | None = None
    try:
        await _wait_started(server)
        service = app.state.service
        await service.repo.ensure_operator(100, "admin")
        token, _ = await service.issue_enrollment(100, "proxy-runtime")
        device, secret = await service.enroll_device(token, "proxy-runtime", "host", "Linux", "6.8")
        config = AgentConfig(
            device_id=device["id"],
            device_secret=secret,
            relay_url=settings.public_url,
            name="proxy-runtime",
            ui_port=ui_port,
            ui_token="ui-token",
            password_hash=hash_password("password123"),
        )
        config_path = tmp_path / "agent.json"
        config.save(config_path)
        runtime = AgentRuntime(
            settings,
            config,
            config_path,
            proxy_resolver=StaticResolver(proxy_url(proxy_server)),
        )
        runtime_task = asyncio.create_task(runtime.run(False))
        assert await _wait_until(lambda: runtime.connected), "agent did not connect"
        assert await _wait_until(lambda: service.hub.is_online(device["id"]))
        assert runtime.state()["proxy"] == proxy_url(proxy_server)
    finally:
        if runtime_task is not None:
            runtime_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await runtime_task
        proxy_server.close()
        await proxy_server.wait_closed()
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=15)
