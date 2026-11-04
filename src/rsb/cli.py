from __future__ import annotations

import asyncio
import getpass
import json
import platform
import secrets
import sys
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from rsb.agent.config import AgentConfig, hash_password, new_ui_token
from rsb.config import Settings
from rsb.db.database import Database
from rsb.db.repository import Repository
from rsb.errors import ConfigError, RsbError
from rsb.logging import configure_logging
from rsb.net.diagnostics import (
    detect_vpn_interfaces,
    relay_health_url,
    run_diagnostics,
)
from rsb.net.pool import select_proxy
from rsb.net.proxy import ProxyFormatError, normalize_proxy, redact_proxy
from rsb.net.vpn import (
    ensure_vpn,
    is_admin,
    parse_wireguard_configs,
    read_local_configs,
    read_source_urls,
    wireguard_binary,
)
from rsb.protocol import MAX_FRAME_BYTES
from rsb.util import ensure_private_file, http_base, relay_endpoint

app = typer.Typer(
    help="RemoteShellBot server, host agent and enrollment utility.",
    no_args_is_help=True,
    add_completion=False,
)
THEME = Theme(
    {
        "rsb.title": "bold cyan",
        "rsb.accent": "bold magenta",
        "rsb.ok": "bold green",
        "rsb.warn": "bold yellow",
        "rsb.err": "bold red",
        "rsb.dim": "grey62",
    }
)
console = Console(theme=THEME)


@app.command()
def server(
    host: str | None = typer.Option(None, help="Override RSB_RELAY_HOST."),
    port: int | None = typer.Option(None, help="Override RSB_RELAY_PORT."),
    log_level: str | None = typer.Option(None, help="Override RSB_LOG_LEVEL."),
) -> None:
    """Run the relay, the Telegram bot and the database."""
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

    import uvicorn

    from rsb.server.app import create_app

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
    console.print(
        Panel(
            f"Слушает: [bold]{settings.relay_host}:{settings.relay_port}[/]\n"
            f"Public URL: [bold]{settings.public_url}[/]",
            title="[rsb.title]RemoteShellBot relay",
            border_style="cyan",
        )
    )
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
        settings.validate_for_agent()
    except ConfigError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=2) from exc
    try:
        runtime = AgentRuntime(settings, configuration, path)
    except ConfigError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=2) from exc
    console.print(
        Panel(
            f"Устройство: [bold]{configuration.name}[/]\n"
            f"ID: [rsb.dim]{configuration.device_id}[/]\n"
            f"Панель: [bold]{runtime.ui_url}[/]",
            title="[rsb.title]RemoteShellBot agent",
            border_style="cyan",
        )
    )
    try:
        asyncio.run(runtime.run(open_ui=open_ui))
    except KeyboardInterrupt:
        console.print("Agent stopped.")
    except RsbError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=1) from exc


@app.command()
def connect(
    config: Path | None = typer.Option(None, help="Path to agent.json."),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
    open_ui: bool = typer.Option(False, "--open-ui", help="Open the panel in a browser."),
    proxy: list[str] = typer.Option([], "--proxy", help="Proxy URL; repeatable."),
    proxy_file: Path | None = typer.Option(None, help="File with one proxy per line."),
    no_direct: bool = typer.Option(False, "--no-direct", help="Skip direct connection."),
    no_public: bool = typer.Option(
        False, "--no-public-proxies", help="Do not use public proxy lists."
    ),
    proxy_source: list[str] = typer.Option(
        [], "--proxy-source", help="Additional proxy list URL; repeatable."
    ),
    wait_seconds: float = typer.Option(
        4.0, "--timeout", min=1.0, max=60.0, help="Probe timeout in seconds."
    ),
    vpn: bool = typer.Option(False, "--vpn", help="Try WireGuard before proxies."),
    vpn_public: bool = typer.Option(
        False, "--vpn-public", help="Fetch VPN configs from configured sources."
    ),
    vpn_source: list[str] = typer.Option(
        [], "--vpn-source", help="Additional WireGuard config URL; repeatable."
    ),
    require_vpn: bool = typer.Option(
        False, "--require-vpn", help="Abort if VPN cannot be established."
    ),
) -> None:
    """Connect the agent, falling back to proxies, VPN and public lists."""
    from rsb.agent.runtime import AgentRuntime

    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    configure_logging(settings.log_level)
    path = config or (settings.data_dir / "agent.json")
    try:
        configuration = AgentConfig.load(path)
        settings.validate_for_agent()
    except ConfigError as exc:
        console.print(str(exc), style="red")
        raise typer.Exit(code=2) from exc
    explicit: list[str] = []
    for value in proxy:
        try:
            explicit.append(normalize_proxy(value))
        except ProxyFormatError as exc:
            console.print(f"Invalid --proxy value: {exc}", style="red")
            raise typer.Exit(code=2) from exc
    health_url = relay_health_url(configuration.relay_url)
    candidates_file = proxy_file or settings.resolved_proxy_file

    async def runner() -> None:
        vpn_session = None
        try:
            if vpn:
                vpn_session = await ensure_vpn(
                    settings,
                    health_url,
                    allow_public=vpn_public or bool(vpn_source),
                    wait_seconds=wait_seconds,
                    extra_sources=vpn_source,
                )
                style = "green" if vpn_session.connected else "yellow"
                console.print(f"VPN: {vpn_session.detail}", style=style)
                for warning in vpn_session.warnings:
                    console.print(f"Внимание: {warning}", style="yellow")
                if require_vpn and not vpn_session.connected:
                    raise ConfigError("VPN обязателен, но подключить его не удалось")
            selection = await select_proxy(
                health_url,
                explicit=explicit,
                proxy_file=candidates_file,
                allow_direct=not no_direct,
                allow_public=not no_public or bool(proxy_source),
                relay_url=configuration.relay_url,
                wait_seconds=wait_seconds,
                concurrency=settings.proxy_concurrency,
                max_test=settings.public_proxy_max_test,
                cache_path=settings.proxy_cache_path,
                cache_ttl=settings.proxy_cache_ttl_seconds,
                extra_source_urls=list(settings.public_source_urls) + proxy_source,
            )
            if selection.source == "direct":
                console.print("Канал: прямое подключение", style="green")
            else:
                console.print(
                    "Канал: "
                    f"{redact_proxy(selection.proxy or '')} "
                    f"({selection.source}, проверено: {selection.tested})",
                    style="green",
                )
            for warning in selection.warnings:
                console.print(f"Внимание: {warning}", style="yellow")
            runtime = AgentRuntime(
                settings,
                configuration,
                path,
                proxy_resolver=selection.resolver,
            )
            console.print(f"Device: {configuration.name} ({configuration.device_id})")
            console.print(f"Local panel: {runtime.ui_url}")
            await runtime.run(open_ui=open_ui)
        finally:
            if vpn_session is not None:
                await vpn_session.close()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        console.print("Agent stopped.")
    except RsbError as exc:
        console.print(str(exc), style="red")
        console.print(
            f"Подсказка: добавьте рабочий прокси в {candidates_file} или запустите rsb netcheck.",
            style="yellow",
        )
        raise typer.Exit(code=1) from exc


@app.command()
def netcheck(
    relay: str | None = typer.Option(None, help="Relay URL; defaults to RSB_PUBLIC_URL."),
    proxy: str | None = typer.Option(
        None, "--proxy", envvar="RSB_AGENT_PROXY", help="Check a specific proxy."
    ),
    wait_seconds: float = typer.Option(
        6.0, "--timeout", min=1.0, max=120.0, help="Probe timeout in seconds."
    ),
    telegram: bool = typer.Option(True, "--telegram/--no-telegram"),
    json_output: bool = typer.Option(False, "--json", help="Print machine-readable JSON."),
) -> None:
    """Diagnose connectivity to the relay, Telegram and proxies."""
    settings = Settings()
    target = relay or settings.public_url
    proxy_value = (proxy or settings.agent_proxy or "").strip() or None
    if proxy_value:
        try:
            proxy_value = normalize_proxy(proxy_value)
        except ProxyFormatError as exc:
            console.print(f"Invalid proxy: {exc}", style="red")
            raise typer.Exit(code=2) from exc
    report = asyncio.run(
        run_diagnostics(
            target,
            proxy=proxy_value,
            wait_seconds=wait_seconds,
            include_telegram=telegram,
        )
    )
    if json_output:
        typer.echo(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        raise typer.Exit(code=0 if report.relay_ok else 1)
    table = Table(title="RemoteShellBot connectivity")
    table.add_column("Проверка")
    table.add_column("Статус")
    table.add_column("Детали", overflow="fold")
    table.add_column("мс", justify="right")
    for item in report.results:
        table.add_row(
            item.name,
            "[green]ok[/green]" if item.ok else "[red]fail[/red]",
            item.detail,
            f"{item.latency_ms:.0f}" if item.latency_ms is not None else "",
        )
    console.print(table)
    if report.proxies:
        console.print(
            "Системные прокси: "
            + ", ".join(f"{name}={value}" for name, value in report.proxies.items())
        )
    if report.vpn_interfaces:
        console.print("VPN-интерфейсы: " + ", ".join(report.vpn_interfaces))
    console.print(Panel(report.verdict, title="Вердикт"))
    if not report.relay_ok:
        console.print(
            "Подсказка: rsb connect попробует прокси из окружения, proxies.txt и публичные списки.",
            style="yellow",
        )
    telegram_result = report.result("telegram.api")
    if telegram_result is not None and not telegram_result.ok:
        console.print(
            "Telegram API недоступен. Для сервера задайте RSB_TELEGRAM_PROXY.",
            style="yellow",
        )
    raise typer.Exit(code=0 if report.relay_ok else 1)


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
    console.print(
        Panel(
            f"Устройство: [bold]{device_name}[/]\n"
            f"Конфигурация: {path}\n"
            f"Локальная панель: [bold]http://127.0.0.1:{ui_port}/?token={configuration.ui_token}[/]\n\n"
            "Дальше: [rsb.accent]rsb connect[/]",
            title="[rsb.ok]Enrollment завершён",
            border_style="green",
        )
    )


vpn_app = typer.Typer(
    help="WireGuard status and local configuration helpers.",
    no_args_is_help=True,
)
app.add_typer(vpn_app, name="vpn")


@vpn_app.command("status")
def vpn_status(
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
) -> None:
    """Show VPN interfaces, WireGuard availability and local configs."""
    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    adapters = detect_vpn_interfaces()
    binary = wireguard_binary()
    configs = read_local_configs(settings.resolved_vpn_dir)
    urls = read_source_urls(settings.resolved_vpn_sources_file) + settings.vpn_source_urls
    table = Table(title="RemoteShellBot VPN")
    table.add_column("Параметр")
    table.add_column("Значение", overflow="fold")
    table.add_row("WireGuard", binary or "не найден")
    table.add_row("Права администратора", "да" if is_admin() else "нет")
    table.add_row("Активные VPN", ", ".join(adapters) if adapters else "нет")
    table.add_row("Каталог конфигов", str(settings.resolved_vpn_dir))
    table.add_row("Локальные конфиги", str(len(configs)))
    table.add_row("Публичные источники", str(len(urls)))
    table.add_row("Файл источников", str(settings.resolved_vpn_sources_file))
    console.print(table)


@vpn_app.command("add")
def vpn_add(
    path: Path = typer.Argument(..., exists=True, dir_okay=False),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
) -> None:
    """Import one or more WireGuard configs into the local directory."""
    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        console.print(f"Cannot read {path}: {exc}", style="red")
        raise typer.Exit(code=1) from exc
    configs = parse_wireguard_configs(text, prefix=path.stem)
    if not configs:
        console.print("No valid WireGuard [Interface]/[Peer] blocks found.", style="red")
        raise typer.Exit(code=1)
    directory = settings.resolved_vpn_dir
    directory.mkdir(parents=True, exist_ok=True)
    for config in configs:
        target = directory / f"{config.name}.conf"
        target.write_text(config.text, encoding="utf-8")
        ensure_private_file(target)
        console.print(f"Imported: {target}")
    console.print(f"Imported configs: {len(configs)}", style="green")


operator_app = typer.Typer(
    help="Manage operator access requests.",
    no_args_is_help=True,
)
app.add_typer(operator_app, name="operator")


async def _list_access_requests(data_dir: Path | None, status: str | None) -> list[dict]:
    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    settings.ensure_dirs()
    database = Database(settings.db_path)
    await database.open()
    try:
        return await Repository(database).list_access_requests(status)
    finally:
        await database.close()


@operator_app.command("list")
def operator_list(
    status: str | None = typer.Option(None, help="pending, approved or denied"),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
) -> None:
    """List access requests."""
    rows = asyncio.run(_list_access_requests(data_dir, status))
    if not rows:
        console.print("Заявок нет.")
        return
    table = Table(title="Access requests")
    table.add_column("Telegram ID")
    table.add_column("Username")
    table.add_column("Status")
    table.add_column("Created")
    for row in rows:
        table.add_row(
            str(row["telegram_id"]),
            str(row.get("username") or "-"),
            str(row["status"]),
            str(row["created_at"]),
        )
    console.print(table)


async def _decide_access(data_dir: Path | None, telegram_id: int, status: str) -> dict | None:
    settings = Settings()
    if data_dir:
        settings.data_dir = data_dir
    settings.ensure_dirs()
    database = Database(settings.db_path)
    await database.open()
    try:
        repo = Repository(database)
        request = await repo.get_access_request(telegram_id)
        await repo.set_access_status(telegram_id, status, decided_by=0)
        if status == "approved":
            operator = await repo.ensure_operator(
                telegram_id, request["username"] if request else None
            )
            if not operator["is_active"]:
                await repo.set_operator_active(telegram_id, True)
        await repo.add_audit(
            f"access.{status}",
            actor_type="cli",
            actor_id="operator",
            detail={"telegram_id": telegram_id},
        )
        return request
    finally:
        await database.close()


@operator_app.command("approve")
def operator_approve(
    telegram_id: int = typer.Argument(..., help="Telegram user ID"),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
) -> None:
    """Approve access without using the bot."""
    request = asyncio.run(_decide_access(data_dir, telegram_id, "approved"))
    username = request["username"] if request else None
    console.print(
        f"Доступ выдан: {telegram_id}" + (f" (@{username})" if username else ""),
        style="green",
    )


@operator_app.command("deny")
def operator_deny(
    telegram_id: int = typer.Argument(..., help="Telegram user ID"),
    data_dir: Path | None = typer.Option(None, help="Override RSB_DATA_DIR."),
) -> None:
    """Deny access without using the bot."""
    asyncio.run(_decide_access(data_dir, telegram_id, "denied"))
    console.print(f"Доступ отклонён: {telegram_id}", style="yellow")


@app.command("console")
def console_command(
    url: str | None = typer.Option(
        None, "--url", help="Relay base URL, for example http://127.0.0.1:30000."
    ),
    token: str | None = typer.Option(
        None, "--token", envvar="RSB_CONSOLE_TOKEN", help="Console API token."
    ),
    interval: float = typer.Option(
        1.0, "--interval", min=0.3, max=10.0, help="Live screen frame interval."
    ),
) -> None:
    """Open the interactive operator console."""
    settings = Settings()
    token_value = (token or settings.console_token.get_secret_value()).strip()
    if not token_value:
        console.print(
            Panel(
                "RSB_CONSOLE_TOKEN не задан.\n"
                "Добавьте токен в .env на сервере и перезапустите relay.",
                title="[rsb.err]Консоль недоступна",
                border_style="red",
            )
        )
        raise typer.Exit(code=2)
    base_url = (url or http_base(settings.public_url)).rstrip("/")
    from rsb.console.app import run_console

    run_console(base_url, token_value, interval=interval)


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
