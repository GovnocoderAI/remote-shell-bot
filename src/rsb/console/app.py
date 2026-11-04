from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from rsb.console.client import ConsoleAPIError, ConsoleClient
from rsb.console.render import (
    PreviewError,
    default_screenshot_path,
    open_temporary_screenshot,
    preview_ansi,
    save_screenshot,
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

HELP_ROWS = [
    ("devices, ls", "список машин"),
    ("connect <номер|id>", "запросить доступ у хоста"),
    ("status", "текущая сессия и последние команды"),
    ("screen", "снимок экрана с ANSI-предпросмотром"),
    ("save [путь]", "сохранить снимок в файл"),
    ("open", "открыть снимок во внешнем просмотрщике"),
    ("watch", "live-просмотр экрана до Ctrl+C"),
    ("audit", "последние события"),
    ("close", "завершить сессию"),
    ("clear", "очистить терминал"),
    ("quit", "выход"),
    ("<команда>", "при активной сессии выполняется в shell"),
]


def _short(value: str, length: int = 10) -> str:
    return value if len(value) <= length else value[:length]


def _status_text(device: dict[str, Any]) -> Text:
    status = device.get("status", "offline")
    if status == "online":
        return Text("в сети", style="rsb.ok")
    if status == "revoked":
        return Text("отозвано", style="rsb.err")
    return Text("не в сети", style="rsb.dim")


def _rights(device: dict[str, Any]) -> str:
    from rsb.server.policy import describe

    return describe(device.get("capabilities", []))


class ConsoleApp:
    def __init__(self, base_url: str, token: str, interval: float = 1.0) -> None:
        self.base_url = base_url
        self.token = token
        self.interval = max(0.3, interval)
        self.ui = Console(theme=THEME, highlight=False)
        self.client = ConsoleClient(base_url, token)
        self.session: dict[str, Any] | None = None
        self.operator: dict[str, Any] = {}
        self.devices: list[dict[str, Any]] = []

    def run(self) -> None:
        try:
            overview = self.client.overview()
        except ConsoleAPIError as exc:
            self.ui.print(
                Panel(
                    f"{exc}\n\n"
                    "Проверьте RSB_CONSOLE_TOKEN на сервере и перезапустите relay.\n"
                    "Порт и URL: rsb console --url http://127.0.0.1:<port>",
                    title="[rsb.err]Консольный API недоступен",
                    border_style="red",
                )
            )
            self.client.close()
            return
        self.operator = overview.get("operator") or {}
        self.devices = list(overview.get("devices") or [])
        self.session = overview.get("session")
        self._banner(overview)
        if self.session is not None:
            self._print_session(self.session)
        try:
            while True:
                prompt = self._prompt()
                try:
                    line = self.ui.input(prompt).strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not line:
                    continue
                if not self._handle(line):
                    break
        finally:
            self.client.close()
            self.ui.print("[rsb.dim]Консоль закрыта.[/]")

    def _banner(self, overview: dict[str, Any]) -> None:
        stats = overview.get("stats") or {}
        operator = self.operator
        name = operator.get("username")
        identity = f"@{name}" if name else f"ID {operator.get('id')}"
        text = Text()
        text.append("RemoteShellBot", style="rsb.title")
        text.append("  оператор ", style="rsb.dim")
        text.append(identity, style="rsb.accent")
        text.append("\n")
        text.append("Relay: ", style="rsb.dim")
        text.append(self.base_url, style="white")
        text.append("\n")
        text.append(
            f"Устройств: {stats.get('devices_online', 0)} в сети / "
            f"{stats.get('devices_total', 0)} всего    "
            f"Сессий: {stats.get('active_sessions', 0)}    "
            f"Ожидают: {stats.get('pending_sessions', 0)}",
            style="rsb.dim",
        )
        self.ui.print(
            Panel(
                text,
                title="[rsb.title]RemoteShellBot Console",
                subtitle="введите help",
                border_style="cyan",
                padding=(1, 2),
            )
        )

    def _prompt(self) -> str:
        if self.session is not None and self.session.get("state") == "active":
            device_id = self.session.get("device_id", "")
            device = next((d for d in self.devices if d["id"] == device_id), None)
            name = device["name"] if device else _short(device_id)
            return f"[rsb.accent]{name}[/] [rsb.dim]$[/] "
        return "[rsb.title]rsb[/] [rsb.dim]>[/] "

    def _handle(self, line: str) -> bool:
        command, _, argument = line.partition(" ")
        command = command.lower()
        argument = argument.strip()
        if command in {"quit", "exit", "q"}:
            return False
        if command in {"help", "?"}:
            self._help()
            return True
        if command in {"devices", "ls", "d"}:
            self._load_devices()
            self._print_devices()
            return True
        if command in {"connect", "c"}:
            self._connect(argument)
            return True
        if command in {"status", "s"}:
            self._status()
            return True
        if command in {"screen", "shot"}:
            self._screen()
            return True
        if command in {"save"}:
            self._save(argument)
            return True
        if command in {"open"}:
            self._open()
            return True
        if command in {"watch", "stream"}:
            self._watch()
            return True
        if command in {"audit", "a"}:
            self._audit()
            return True
        if command in {"close", "disconnect"}:
            self._close()
            return True
        if command == "clear":
            self.ui.clear()
            return True
        if self.session is not None and self.session.get("state") == "active":
            self._run_command(line)
            return True
        self.ui.print("[rsb.warn]Неизвестная команда.[/] Введите [rsb.accent]help[/].")
        return True

    def _help(self) -> None:
        table = Table(
            title="Команды консоли",
            box=box.ROUNDED,
            header_style="rsb.title",
            border_style="grey37",
        )
        table.add_column("Команда", style="rsb.accent")
        table.add_column("Назначение")
        for name, description in HELP_ROWS:
            table.add_row(name, description)
        self.ui.print(table)

    def _load_devices(self) -> None:
        try:
            self.devices = self.client.devices()
        except ConsoleAPIError as exc:
            self._error(exc)

    def _print_devices(self) -> None:
        if not self.devices:
            self.ui.print(
                Panel(
                    "Нет зарегистрированных устройств.\n"
                    "Выполните /enroll в боте и установите агент.",
                    border_style="yellow",
                )
            )
            return
        table = Table(
            title="Устройства",
            box=box.ROUNDED,
            header_style="rsb.title",
            border_style="grey37",
        )
        table.add_column("#", justify="right", style="rsb.dim")
        table.add_column("Имя", style="bold")
        table.add_column("Система")
        table.add_column("Статус")
        table.add_column("Права")
        table.add_column("ID", style="rsb.dim")
        for index, device in enumerate(self.devices, start=1):
            table.add_row(
                str(index),
                device.get("name") or "-",
                device.get("os_name") or "-",
                _status_text(device),
                _rights(device),
                _short(device.get("id", "")),
            )
        self.ui.print(table)

    def _resolve_device(self, argument: str) -> dict[str, Any] | None:
        self._load_devices()
        if not self.devices:
            self._print_devices()
            return None
        if not argument:
            if len(self.devices) == 1:
                return self.devices[0]
            self._print_devices()
            argument = self.ui.input("Номер или ID устройства: ").strip()
            if not argument:
                return None
        if argument.isdigit():
            index = int(argument)
            if 1 <= index <= len(self.devices):
                return self.devices[index - 1]
        lowered = argument.lower()
        matches = [
            device
            for device in self.devices
            if device["id"] == argument
            or device["id"].startswith(argument)
            or str(device.get("name", "")).lower() == lowered
        ]
        if len(matches) == 1:
            return matches[0]
        self.ui.print("[rsb.err]Устройство не найдено или неоднозначно.[/]")
        return None

    def _connect(self, argument: str) -> None:
        if self.session is not None:
            self.ui.print("[rsb.warn]Уже есть открытая сессия. Сначала выполните close.[/]")
            return
        device = self._resolve_device(argument)
        if device is None:
            return
        if device.get("status") != "online":
            self.ui.print("[rsb.err]Устройство не в сети.[/]")
            return
        capabilities = ["shell"]
        if "screenshot" in device.get("capabilities", []) and Confirm.ask(
            "Запросить снимок экрана для live-просмотра?",
            default=True,
            console=self.ui,
        ):
            capabilities.append("screenshot")
        try:
            self.client.request_session(device["id"], capabilities)
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        self.ui.print(
            Panel(
                f"Запрос отправлен на [bold]{device['name']}[/].\n"
                f"Запрошено: [rsb.accent]{', '.join(capabilities)}[/].\n"
                "Подтвердите запрос в локальной панели хоста.",
                title="[rsb.warn]Ожидание подтверждения",
                border_style="yellow",
            )
        )
        deadline = time.monotonic() + 200
        try:
            with self.ui.status("[rsb.warn]Ожидание решения владельца машины...[/]"):
                while time.monotonic() < deadline:
                    data = self.client.current_session()
                    current = data.get("session")
                    if current is None:
                        time.sleep(2)
                        continue
                    state = current.get("state")
                    if state == "active":
                        self.session = current
                        self._print_session(current)
                        return
                    if state in {"denied", "closed", "expired"}:
                        self.ui.print(
                            Panel(
                                f"Сессия не открыта: [rsb.err]{state}[/]",
                                border_style="red",
                            )
                        )
                        return
                    time.sleep(2)
                self.ui.print("[rsb.err]Истекло время ожидания подтверждения.[/]")
        except KeyboardInterrupt:
            self.ui.print("[rsb.warn]Ожидание прервано.[/]")

    def _print_session(self, session: dict[str, Any]) -> None:
        device = next((d for d in self.devices if d["id"] == session.get("device_id")), None)
        name = device["name"] if device else _short(session.get("device_id", ""))
        self.ui.print(
            Panel(
                f"Устройство: [bold]{name}[/]\n"
                f"Состояние: [rsb.ok]{session.get('state')}[/]\n"
                f"Права: [rsb.accent]{_rights({'capabilities': session.get('capabilities', [])})}[/]\n"
                f"Действует до: {session.get('expires_at')}\n\n"
                "Команды выполняются обычным вводом. "
                "Хост видит каждую команду и каждый снимок.",
                title="[rsb.title]Сессия",
                border_style="green",
            )
        )

    def _session_id(self) -> str | None:
        if self.session is None:
            self.ui.print("[rsb.warn]Нет активной сессии.[/]")
            return None
        if self.session.get("state") != "active":
            self.ui.print("[rsb.warn]Сессия ещё не активна.[/]")
            return None
        return str(self.session["id"])

    def _run_command(self, command: str) -> None:
        session_id = self._session_id()
        if session_id is None:
            return
        try:
            with self.ui.status("[rsb.accent]Выполняется...[/]"):
                result = self.client.command(session_id, command)
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        output = str(result.get("output") or "")
        exit_code = result.get("exit_code")
        timed_out = bool(result.get("timed_out"))
        style = "green" if exit_code == 0 and not timed_out else "red"
        body = Text(output) if output else Text("(нет вывода)", style="rsb.dim")
        self.ui.print(
            Panel(
                body,
                title=f"exit {exit_code}  ·  {result.get('cwd') or ''}",
                border_style=style,
                padding=(0, 1),
            )
        )

    def _screen(self) -> None:
        session_id = self._session_id()
        if session_id is None:
            return
        try:
            image, meta = self.client.screenshot(session_id)
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        self._render(image, meta)

    def _render(self, image: bytes, meta: dict[str, Any]) -> None:
        width = max(20, min(80, self.ui.width - 6))
        try:
            preview = preview_ansi(image, width=width, max_height=40)
        except PreviewError as exc:
            self._error(exc)
            return
        taken = meta.get("taken_at") or ""
        self.ui.print(
            Panel(
                f"{meta.get('width') or '?'}x{meta.get('height') or '?'}  ·  {taken}",
                title="[rsb.title]Снимок экрана",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        self.ui.print(Text.from_ansi(preview))

    def _save(self, argument: str) -> None:
        session_id = self._session_id()
        if session_id is None:
            return
        path = Path(argument).expanduser() if argument else default_screenshot_path()
        try:
            image, _ = self.client.screenshot(session_id)
            saved = save_screenshot(image, path)
        except (ConsoleAPIError, OSError) as exc:
            self._error(exc)
            return
        self.ui.print(f"[rsb.ok]Сохранено:[/] {saved}")

    def _open(self) -> None:
        session_id = self._session_id()
        if session_id is None:
            return
        try:
            image, _ = self.client.screenshot(session_id)
            path = open_temporary_screenshot(image)
        except (ConsoleAPIError, OSError) as exc:
            self._error(exc)
            return
        self.ui.print(f"[rsb.ok]Открыто:[/] {path}")

    def _watch(self) -> None:
        session_id = self._session_id()
        if session_id is None:
            return
        if "screenshot" not in self.session.get("capabilities", []):
            self.ui.print("[rsb.err]Хост не выдал право на снимок экрана.[/]")
            return
        self.ui.print(
            Panel(
                "Live-просмотр. Хост видит каждый снимок. Остановка: Ctrl+C.",
                border_style="yellow",
            )
        )
        width = max(20, min(80, self.ui.width - 6))
        try:
            while True:
                image, meta = self.client.screenshot(session_id)
                self.ui.clear()
                self.ui.print(
                    Panel(
                        f"{meta.get('taken_at') or ''}  ·  "
                        f"{meta.get('width') or '?'}x{meta.get('height') or '?'}  ·  "
                        "Ctrl+C для остановки",
                        title="[rsb.title]Live screen",
                        border_style="cyan",
                    )
                )
                self.ui.print(Text.from_ansi(preview_ansi(image, width=width, max_height=40)))
                time.sleep(self.interval)
        except KeyboardInterrupt:
            self.ui.print("[rsb.warn]Трансляция остановлена.[/]")
        except (ConsoleAPIError, PreviewError) as exc:
            self._error(exc)

    def _status(self) -> None:
        try:
            data = self.client.current_session()
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        session = data.get("session")
        if session is None:
            self.session = None
            self.ui.print("[rsb.dim]Активной сессии нет.[/]")
            return
        self.session = session
        self._print_session(session)
        commands = data.get("commands") or []
        if commands:
            table = Table(
                title="Последние команды",
                box=box.SIMPLE_HEAVY,
                header_style="rsb.title",
            )
            table.add_column("Команда", style="rsb.accent")
            table.add_column("Код")
            table.add_column("Когда", style="rsb.dim")
            for item in commands[:10]:
                table.add_row(
                    item.get("command", ""),
                    str(item.get("exit_code")),
                    str(item.get("started_at")),
                )
            self.ui.print(table)

    def _audit(self) -> None:
        try:
            entries = self.client.audit(20)
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        table = Table(
            title="Журнал аудита",
            box=box.SIMPLE_HEAVY,
            header_style="rsb.title",
        )
        table.add_column("Время", style="rsb.dim")
        table.add_column("Событие", style="rsb.accent")
        table.add_column("Детали")
        for item in entries:
            table.add_row(
                str(item.get("ts")),
                str(item.get("action")),
                str(item.get("detail") or ""),
            )
        self.ui.print(table)

    def _close(self) -> None:
        if self.session is None:
            self.ui.print("[rsb.dim]Активной сессии нет.[/]")
            return
        try:
            self.client.close_session(str(self.session["id"]))
        except ConsoleAPIError as exc:
            self._error(exc)
            return
        self.session = None
        self.ui.print("[rsb.ok]Сессия закрыта.[/]")

    def _error(self, exc: Exception) -> None:
        self.ui.print(Panel(str(exc), title="[rsb.err]Ошибка", border_style="red"))


def run_console(base_url: str, token: str, interval: float = 1.0) -> None:
    ConsoleApp(base_url, token, interval=interval).run()
