from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from rsb.errors import ConfigError
from rsb.util import ensure_private_file

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 64 * 1024 * 1024


@dataclass(slots=True)
class AgentConfig:
    device_id: str
    device_secret: str
    relay_url: str
    name: str
    ui_port: int
    ui_token: str
    password_hash: str

    @classmethod
    def load(cls, path: Path) -> AgentConfig:
        if not path.exists():
            raise ConfigError(
                f"agent configuration not found at {path}. "
                "Run enroll first: rsb enroll --relay <url> --token <token>"
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            config = cls(
                device_id=str(data["device_id"]),
                device_secret=str(data["device_secret"]),
                relay_url=str(data["relay_url"]),
                name=str(data["name"]),
                ui_port=int(data["ui_port"]),
                ui_token=str(data["ui_token"]),
                password_hash=str(data["password_hash"]),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ConfigError(f"agent configuration at {path} is invalid") from exc
        if not all(
            [
                config.device_id,
                config.device_secret,
                config.relay_url,
                config.ui_token,
                config.password_hash,
            ]
        ):
            raise ConfigError(f"agent configuration at {path} is incomplete")
        return config

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        ensure_private_file(temporary)
        temporary.replace(path)
        ensure_private_file(path)


def hash_password(password: str) -> str:
    if len(password) < 8:
        raise ConfigError("host password must contain at least 8 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
            maxmem=SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(digest, bytes.fromhex(digest_hex))
    except (ValueError, TypeError):
        return False


def new_ui_token() -> str:
    return secrets.token_urlsafe(32)
