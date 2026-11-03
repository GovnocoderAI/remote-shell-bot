from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from rsb.errors import ConfigError
from rsb.util import ensure_private_file


def default_data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "RemoteShellBot"
    return Path.home() / ".remote-shell-bot"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RSB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    data_dir: Path = Field(default_factory=default_data_dir)
    database_path: Path | None = None

    bot_token: SecretStr = SecretStr("")
    admin_ids: str = ""
    secret_key: SecretStr = SecretStr("")

    relay_host: str = "0.0.0.0"
    relay_port: int = Field(default=8080, ge=1, le=65535)
    public_url: str = "ws://127.0.0.1:8080"

    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None

    agent_ui_host: str = "127.0.0.1"
    agent_ui_port: int = Field(default=8765, ge=1, le=65535)
    agent_lock_timeout_seconds: int = Field(default=900, ge=60)

    session_ttl_seconds: int = Field(default=1800, ge=60)
    session_request_ttl_seconds: int = Field(default=180, ge=30)
    operator_auth_ttl_seconds: int = Field(default=28800, ge=300)
    enrollment_ttl_seconds: int = Field(default=900, ge=60)
    command_timeout_seconds: int = Field(default=120, ge=1)
    command_max_output_bytes: int = Field(default=65536, ge=1024)
    screenshot_max_bytes: int = Field(default=4000000, ge=65536)
    audit_retention_days: int = Field(default=30, ge=1)

    log_level: str = "INFO"

    @field_validator("database_path", "tls_certfile", "tls_keyfile", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def admin_ids_set(self) -> frozenset[int]:
        found: set[int] = set()
        for part in self.admin_ids.replace(";", ",").split(","):
            part = part.strip()
            if part.lstrip("-").isdigit():
                found.add(int(part))
        return frozenset(found)

    @property
    def db_path(self) -> Path:
        return self.database_path or (self.data_dir / "rsb.sqlite3")

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def resolve_secret_key(self) -> bytes:
        configured = self.secret_key.get_secret_value().strip()
        if configured:
            key = configured.encode("utf-8")
            if len(key) < 16:
                raise ConfigError("RSB_SECRET_KEY must contain at least 16 bytes")
            return key
        key_file = self.data_dir / "secret.key"
        if key_file.exists():
            stored = key_file.read_bytes().strip()
            if len(stored) < 16:
                raise ConfigError(f"secret key file {key_file} is corrupted")
            return stored
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = base64.urlsafe_b64encode(secrets.token_bytes(32))
        key_file.write_bytes(key)
        ensure_private_file(key_file)
        return key

    def validate_for_server(self) -> None:
        if not self.bot_token.get_secret_value().strip():
            raise ConfigError("RSB_BOT_TOKEN is not set")
        if not self.admin_ids_set:
            raise ConfigError("RSB_ADMIN_IDS is empty")
        if not self.public_url.strip():
            raise ConfigError("RSB_PUBLIC_URL is not set")
        if bool(self.tls_certfile) != bool(self.tls_keyfile):
            raise ConfigError("RSB_TLS_CERTFILE and RSB_TLS_KEYFILE must be set together")

    def validate_for_agent(self) -> None:
        if not self.public_url.strip():
            raise ConfigError("RSB_PUBLIC_URL is not set")
