#!/usr/bin/env python3
"""Installer for the RemoteShellBot host agent.

Creates an isolated environment, installs the package, enrolls the machine,
writes agent.json and optionally registers autostart as a user service.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import secrets
import stat
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
MIN_PYTHON = (3, 11)
TASK_NAME = "RemoteShellBotAgent"
SYSTEMD_UNIT = "remote-shell-bot.service"
LAUNCHD_LABEL = "com.remoteshellbot.agent"


def default_install_dir() -> Path:
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA") or str(home)
        return Path(base) / "RemoteShellBot"
    if system == "Darwin":
        return home / "Library" / "Application Support" / "RemoteShellBot"
    base = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return base / "remote-shell-bot"


def venv_python(install_dir: Path) -> Path:
    if platform.system() == "Windows":
        return install_dir / "venv" / "Scripts" / "python.exe"
    return install_dir / "venv" / "bin" / "python"


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    printable = " ".join(str(part) for part in command)
    print(f"> {printable}")
    subprocess.run(command, check=True, env=env)


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass


def create_environment(install_dir: Path, base_python: str) -> Path:
    target = install_dir / "venv"
    python = venv_python(install_dir)
    if not python.exists():
        print(f"Creating virtual environment at {target}")
        run([base_python, "-m", "venv", str(target)])
    run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    run([str(python), "-m", "pip", "install", "--upgrade", str(PROJECT_ROOT)])
    return python


def enroll_device(
    python: Path,
    relay: str,
    token: str,
    name: str,
    password: str,
    ui_port: int,
    data_dir: Path,
    force: bool,
) -> dict:
    config_path = data_dir / "agent.json"
    command = [
        str(python),
        "-m",
        "rsb",
        "enroll",
        "--relay",
        relay,
        "--token",
        token,
        "--name",
        name,
        "--ui-port",
        str(ui_port),
        "--data-dir",
        str(data_dir),
    ]
    if force:
        command.append("--force")
    environment = dict(os.environ)
    environment["RSB_HOST_PASSWORD"] = password
    run(command, env=environment)
    return json.loads(config_path.read_text(encoding="utf-8"))


def write_launcher(install_dir: Path, python: Path, data_dir: Path) -> Path:
    if platform.system() == "Windows":
        launcher = install_dir / "rsb-agent.cmd"
        content = f'@echo off\r\n"{python}" -m rsb connect --data-dir "{data_dir}"\r\n'
        launcher.write_text(content, encoding="utf-8")
        return launcher
    launcher = install_dir / "rsb-agent.sh"
    content = f'#!/bin/sh\nexec "{python}" -m rsb connect --data-dir "{data_dir}"\n'
    launcher.write_text(content, encoding="utf-8")
    os.chmod(launcher, 0o700)
    return launcher


def install_service(launcher: Path, install_dir: Path, data_dir: Path) -> bool:
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(
                [
                    "schtasks",
                    "/Create",
                    "/TN",
                    TASK_NAME,
                    "/SC",
                    "ONLOGON",
                    "/RL",
                    "LIMITED",
                    "/TR",
                    f'"{launcher}"',
                    "/F",
                ],
                check=True,
                capture_output=True,
            )
            print(f"Scheduled task created: {TASK_NAME}")
            return True
        if system == "Darwin":
            agents = Path.home() / "Library" / "LaunchAgents"
            agents.mkdir(parents=True, exist_ok=True)
            logs = install_dir / "logs"
            logs.mkdir(parents=True, exist_ok=True)
            plist = agents / f"{LAUNCHD_LABEL}.plist"
            plist.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>\n'
                f"  <key>Label</key><string>{LAUNCHD_LABEL}</string>\n"
                "  <key>ProgramArguments</key><array>"
                f"<string>{launcher}</string></array>\n"
                "  <key>RunAtLoad</key><true/>\n"
                "  <key>KeepAlive</key><true/>\n"
                f"  <key>StandardOutPath</key><string>{logs / 'agent.log'}</string>\n"
                f"  <key>StandardErrorPath</key><string>{logs / 'agent.err'}</string>\n"
                "</dict></plist>\n",
                encoding="utf-8",
            )
            subprocess.run(
                ["launchctl", "unload", str(plist)],
                check=False,
                capture_output=True,
            )
            subprocess.run(["launchctl", "load", str(plist)], check=True)
            print(f"Launch agent loaded: {plist}")
            return True
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit = unit_dir / SYSTEMD_UNIT
        unit.write_text(
            "[Unit]\n"
            "Description=RemoteShellBot host agent\n"
            "After=network-online.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f'ExecStart="{venv_python(install_dir)}" -m rsb connect '
            f'--data-dir "{data_dir}"\n'
            "Restart=always\n"
            "RestartSec=5\n"
            "Environment=PYTHONUNBUFFERED=1\n\n"
            "[Install]\n"
            "WantedBy=default.target\n",
            encoding="utf-8",
        )
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(
            ["systemctl", "--user", "enable", "--now", SYSTEMD_UNIT],
            check=True,
            capture_output=True,
        )
        print(f"Systemd user unit enabled: {unit}")
        print(
            "Note: run 'loginctl enable-linger $USER' to keep the agent "
            "running without an active login session."
        )
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Autostart was not configured: {exc}")
        return False


def check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        required = ".".join(str(part) for part in MIN_PYTHON)
        raise SystemExit(f"Python {required} or newer is required")


def prompt_password(provided: str | None) -> str:
    if provided:
        if len(provided) < 8:
            raise SystemExit("Host password must contain at least 8 characters")
        return provided
    if sys.stdin.isatty():
        first = getpass.getpass("Host password: ")
        second = getpass.getpass("Repeat host password: ")
        if first != second:
            raise SystemExit("Passwords do not match")
        if len(first) < 8:
            raise SystemExit("Host password must contain at least 8 characters")
        return first
    generated = secrets.token_urlsafe(12)
    print(f"Generated host password: {generated}")
    return generated


def main() -> int:
    check_python()
    parser = argparse.ArgumentParser(
        description="Install and enroll the RemoteShellBot host agent."
    )
    parser.add_argument("--relay", help="Relay URL, for example wss://support.example.com")
    parser.add_argument("--token", help="One-time enrollment token from the bot")
    parser.add_argument("--name", default=platform.node() or "device", help="Device name")
    parser.add_argument(
        "--password",
        help="Host password; prompted when omitted and generated in non-interactive mode",
    )
    parser.add_argument("--ui-port", type=int, default=8765, help="Local panel port")
    parser.add_argument(
        "--install-dir",
        type=Path,
        default=default_install_dir(),
        help="Installation directory",
    )
    parser.add_argument(
        "--data-dir", type=Path, help="Data directory; defaults to <install-dir>/data"
    )
    parser.add_argument(
        "--python", default=sys.executable, help="Base interpreter for the virtual environment"
    )
    parser.add_argument("--no-service", action="store_true", help="Do not register autostart")
    parser.add_argument("--no-enroll", action="store_true", help="Install only, skip enrollment")
    parser.add_argument("--force", action="store_true", help="Re-enroll an existing installation")
    options = parser.parse_args()

    if not options.no_enroll and (not options.relay or not options.token):
        parser.error("--relay and --token are required unless --no-enroll is used")

    install_dir: Path = options.install_dir.expanduser().resolve()
    data_dir: Path = (
        options.data_dir.expanduser().resolve() if options.data_dir else install_dir / "data"
    )
    ensure_private_dir(install_dir)
    ensure_private_dir(data_dir)
    python = create_environment(install_dir, options.python)
    print(f"Package installed: {PROJECT_ROOT}")

    configuration: dict | None = None
    if not options.no_enroll:
        password = prompt_password(options.password)
        configuration = enroll_device(
            python=python,
            relay=options.relay,
            token=options.token,
            name=options.name[:64],
            password=password,
            ui_port=options.ui_port,
            data_dir=data_dir,
            force=options.force,
        )
        print(f"Device enrolled: {configuration['device_id']}")

    launcher = write_launcher(install_dir, python, data_dir)
    print(f"Launcher: {launcher}")

    if options.no_service:
        print("Autostart disabled. Start manually: " + str(launcher))
    elif configuration is None:
        print("Autostart is skipped until enrollment is completed.")
    else:
        installed = install_service(launcher, install_dir, data_dir)
        if installed and platform.system() == "Windows":
            print(f"Start now: schtasks /Run /TN {TASK_NAME}")

    if configuration is not None:
        print("")
        print("RemoteShellBot agent is ready.")
        print(f"Local panel: http://127.0.0.1:{options.ui_port}/?token={configuration['ui_token']}")
        print("The host password unlocks the panel and approvals.")
    else:
        print("")
        print("Enrollment is pending. Run:")
        print(f'  "{python}" -m rsb enroll --relay <url> --token <token> --data-dir "{data_dir}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
