from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rsb.errors import AuthenticationError

TOTP_ISSUER = "RemoteShellBot"
TOTP_INTERVAL = 30


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), expected_hash)


def sign(secret: str, message: str) -> str:
    return hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(secret: str, message: str, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, message), signature)


def device_message(device_id: str, nonce: str, timestamp: int) -> str:
    return f"{device_id}|{nonce}|{timestamp}"


class SecretBox:
    def __init__(self, secret: bytes) -> None:
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"remote-shell-bot/totp",
            info=b"secret-box",
        ).derive(secret)
        self._fernet = Fernet(base64.urlsafe_b64encode(derived))

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise AuthenticationError("stored secret cannot be decrypted") from exc


def totp_new_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL, issuer=TOTP_ISSUER).provisioning_uri(
        name=account, issuer_name=TOTP_ISSUER
    )


def totp_now(secret: str, at: int | None = None) -> str:
    return (
        pyotp.TOTP(secret, interval=TOTP_INTERVAL).at(at)
        if at is not None
        else pyotp.TOTP(secret, interval=TOTP_INTERVAL).now()
    )


def totp_verify(secret: str, code: str, valid_window: int = 1) -> bool:
    normalized = "".join(ch for ch in code if ch.isdigit())
    if len(normalized) != 6:
        return False
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL).verify(normalized, valid_window=valid_window)
