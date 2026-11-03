from __future__ import annotations

import asyncio
import getpass
import platform
import secrets
import sys
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from rsb.agent.config import AgentConfig, hash_password, new_ui_token
from rsb.config import Settings
from rsb.errors import ConfigError, RsbError
from rsb.logging import configure_logging
from rsb.protocol import MAX_FRAME_BYTES
from rsb.util import http_base, relay_endpoint

app = typer.Typer(
    help="RemoteShellBot server, host agent and enrollment utility.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def server(
    host: str | None = typer.Option(None, help="Override RSB_RELAY_HOST."),
    port: int | None = typer.Option(None, help="Override RSB_RELAY_PORT."),
    log_level: str | None = typer.Option(None, help="Override RSB_LOG_LEVEL."),
) -> None:
    """Run the relay, the Telegram bot and the database."""
    import uvicorn

    from rsb.server.app import create_app

    settings = Settings()
    if host:
        settings.relay_host = host
    if port:
        settings.relay_port = port
    if log_level:
        settings.log_level = log_level.upper()
    try:
        settings.validate_for_server()
    except ConfigError as exc:
        console.print(f"Configuration error: {exc}", style="red")
        raise typer.Exit(code=2) from exc
    configure_logging(settings.log_level)
    settings.ensure_dirs()
    if settings.public_url.startswith("ws://") and settings.relay_host not in {
        "127.0.0.1",
        "localhost",
    }:
        console.print(
            "Warning: public relay URL uses plain ws:// without TLS. "
            "Use wss:// behind a TLS reverse proxy in production.",
            style="yellow",
        )
    console.print(f"Relay listening on {settings.relay_host}:{settings.relay_port}")
    console.print(f"Public URL: {settings.public_url}")
    uvicorn.run(
        create_app(settings),
        host=settings.relay_host,
        port=settings.relay_port,
        log_level=settings.log_level.lower(),
        access_log=False,
        ws_max_size=MAX_FRAME_BYTES,
        ssl_certfile=str(settings.tls_certfile) if settings.tls_certfile else None,
        ssl_keyfile=str(settings.tls_keyfile) if settings.tls_keyfile else None,
    )


@app.command()
def agent(
    config: Path | None = typer.Option(None, help="Path to agent.json."),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
    open_ui: bool = typer.Option(False, "--open-ui", help="Open the panel in a browser."),
) -> None:
    """Run the host agent and its local control panel."""
    from rsb.agent.runtime import AgentRuntime

    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    configure_logging(settings.log_level)
    path = config or (settings.data_dir / "agent.json")
    try:
        configuration = AgentConfig.load(path)
    except ConfigError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=2) from exc
    runtime = AgentRuntime(settings, configuration, path)
    console.print(f"Device: {configuration.name} ({configuration.device_id})")
    console.print(f"Local panel: {runtime.ui_url}")
    try:
        asyncio.run(runtime.run(open_ui=open_ui))
    except KeyboardInterrupt:
        console.print("Agent stopped.")
    except RsbError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=1) from exc


@app.command()
def enroll(
    relay: str = typer.Option(..., prompt="Relay URL"),
    token: str = typer.Option(..., prompt="Enrollment token"),
    name: str | None = typer.Option(None, help="Device display name."),
    password: str | None = typer.Option(
        None,
        "--password",
        envvar="RSB_HOST_PASSWORD",
        help="Host password; prompted when omitted.",
    ),
    ui_port: int = typer.Option(8765, help="Local panel port."),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
    config: Path | None = typer.Option(None, help="Path to agent.json."),
    force: bool = typer.Option(False, help="Overwrite an existing enrollment."),
) -> None:
    """Enroll this machine and write agent.json."""
    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    settings.ensure_dirs()
    path = config or (settings.data_dir / "agent.json")
    if path.exists() and not force:
        console.print(f"{path} already exists. Use --force to re-enroll.", style="red")
        raise typer.Exit(code=2)
    if password is None:
        if sys.stdin.isatty():
            first = getpass.getpass("Host password: ")
            second = getpass.getpass("Repeat host password: ")
            if first != second:
                console.print("Passwords do not match.", style="red")
                raise typer.Exit(code=2)
            password = first
        else:
            password = secrets.token_urlsafe(12)
            console.print(f"Generated host password: {password}", style="yellow")
    if len(password) < 8:
        console.print("Host password must contain at least 8 characters.", style="red")
        raise typer.Exit(code=2)
    device_name = (name or platform.node() or "device").strip()[:64]
    payload = {
        "token": token.strip(),
        "name": device_name,
        "hostname": platform.node()[:128],
        "os_name": platform.system()[:64],
        "os_version": platform.release()[:64],
    }
    endpoint = http_base(relay).rstrip("/") + "/api/enroll"
    try:
        with httpx.Client(timeout=25) as client:
            response = client.post(endpoint, json=payload)
    except httpx.HTTPError as exc:
        console.print(f"Cannot reach relay at {endpoint}: {exc}", style="red")
        raise typer.Exit(code=1) from exc
    if response.status_code != 200:
        detail = response.text
        try:
            detail = response.json().get("detail", detail)
        except ValueError:
            pass
        console.print(f"Enrollment rejected: {detail}", style="red")
        raise typer.Exit(code=1)
    data = response.json()
    configuration = AgentConfig(
        device_id=str(data["device_id"]),
        device_secret=str(data["device_secret"]),
        relay_url=relay_endpoint(relay),
        name=device_name,
        ui_port=ui_port,
        ui_token=new_ui_token(),
        password_hash=hash_password(password),
    )
    configuration.save(path)
    console.print(f"Enrolled as {device_name}", style="green")
    console.print(f"Configuration: {path}")
    console.print(f"Local panel: http://127.0.0.1:{ui_port}/?token={configuration.ui_token}")
    console.print("Run: rsb agent")


@app.command()
def doctor() -> None:
    """Check server and agent configuration."""
    settings = Settings()
    table = Table(title="RemoteShellBot diagnostics")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("Data directory", str(settings.data_dir))
    table.add_row("Database", str(settings.db_path))
    table.add_row("Relay listen", f"{settings.relay_host}:{settings.relay_port}")
    table.add_row("Public URL", settings.public_url)
    table.add_row(
        "Bot token",
        "configured" if settings.bot_token.get_secret_value() else "missing",
    )
    table.add_row("Operators", str(len(settings.admin_ids_set)))
    table.add_row(
        "TLS files",
        "configured" if settings.tls_certfile and settings.tls_keyfile else "not used",
    )
    agent_path = settings.data_dir / "agent.json"
    table.add_row("Agent config", str(agent_path) if agent_path.exists() else "missing")
    try:
        settings.resolve_secret_key()
        table.add_row("Secret key", "available")
    except RsbError as exc:
        table.add_row("Secret key", f"error: {exc}")
    console.print(table)
    endpoint = http_base(settings.public_url).rstrip("/") + "/healthz"
    try:
        with httpx.Client(timeout=8) as client:
            response = client.get(endpoint)
        console.print(f"Relay health: HTTP {response.status_code} ({endpoint})")
    except httpx.HTTPError as exc:
        console.print(f"Relay health: unreachable ({exc})", style="yellow")
