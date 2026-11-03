from __future__ import annotations

import pytest

from rsb.agent.config import hash_password, verify_password
from rsb.errors import AuthenticationError, ConfigError
from rsb.security import (
    SecretBox,
    device_message,
    generate_token,
    hash_token,
    sign,
    totp_new_secret,
    totp_uri,
    totp_verify,
    verify_signature,
    verify_token,
)


def test_token_hash_roundtrip() -> None:
    token = generate_token()
    digest = hash_token(token)
    assert verify_token(token, digest)
    assert not verify_token(token + "x", digest)


def test_hmac_signature_roundtrip() -> None:
    secret = generate_token()
    message = device_message("device", "nonce", 1730000000)
    assert verify_signature(secret, message, sign(secret, message))
    assert not verify_signature(secret, message + "x", sign(secret, message))


def test_secret_box_roundtrip_and_wrong_key() -> None:
    box = SecretBox(b"a" * 32)
    stored = box.encrypt("totp-secret")
    assert stored != "totp-secret"
    assert box.decrypt(stored) == "totp-secret"
    with pytest.raises(AuthenticationError):
        SecretBox(b"b" * 32).decrypt(stored)


def test_totp_verification() -> None:
    secret = totp_new_secret()
    assert "otpauth://totp/" in totp_uri(secret, "operator-1")
    from pyotp import TOTP

    code = TOTP(secret).now()
    assert totp_verify(secret, code)
    assert not totp_verify(secret, "000000")


def test_host_password_hash() -> None:
    encoded = hash_password("correct horse battery")
    assert encoded.startswith("scrypt$")
    assert verify_password("correct horse battery", encoded)
    assert not verify_password("wrong password", encoded)
    assert not verify_password("correct horse battery", "broken")


def test_short_password_is_rejected() -> None:
    with pytest.raises(ConfigError):
        hash_password("short")
