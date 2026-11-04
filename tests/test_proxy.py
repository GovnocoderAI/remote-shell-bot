from __future__ import annotations

import pytest

from rsb.errors import ConfigError
from rsb.net.proxy import (
    ProxyFormatError,
    from_env,
    from_text,
    normalize_proxy,
    redact_proxy,
    scrub_proxy_secrets,
    validate_relay_transport,
)


def test_normalize_host_port_defaults_to_http() -> None:
    assert normalize_proxy("127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_normalize_keeps_socks_scheme() -> None:
    assert normalize_proxy("socks5://user:pass@example.com:1080") == (
        "socks5://user:pass@example.com:1080"
    )


def test_normalize_requires_port() -> None:
    with pytest.raises(ProxyFormatError):
        normalize_proxy("socks5://example.com")
    with pytest.raises(ProxyFormatError):
        normalize_proxy("http://example.com")


def test_normalize_rejects_invalid_values() -> None:
    for value in ("", "ftp://example.com:21", "http://example.com:0", "http://"):
        with pytest.raises(ProxyFormatError):
            normalize_proxy(value)


def test_redact_proxy_hides_password() -> None:
    assert redact_proxy("http://user:secret@example.com:8080") == (
        "http://user:***@example.com:8080"
    )
    assert redact_proxy("http://example.com:8080") == "http://example.com:8080"


def test_scrub_proxy_secrets() -> None:
    proxy = "socks5://user:secret@example.com:1080"
    text = f"failed to connect to {proxy} with secret"
    scrubbed = scrub_proxy_secrets(text, proxy)
    assert "secret" not in scrubbed
    assert "user:***@example.com" in scrubbed


def test_from_text_parses_comments_and_duplicates() -> None:
    text = """
    # comment
    127.0.0.1:8080
    socks5://127.0.0.1:1080
    127.0.0.1:8080
    invalid
    """
    candidates = from_text(text, "test")
    assert [candidate.url for candidate in candidates] == [
        "http://127.0.0.1:8080",
        "socks5://127.0.0.1:1080",
    ]
    assert all(candidate.source == "test" for candidate in candidates)


def test_from_env_reads_proxy_variables(monkeypatch) -> None:
    monkeypatch.delenv("ALL_PROXY", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://user:pass@127.0.0.1:8888")
    candidates = from_env()
    assert candidates[0].url == "http://user:pass@127.0.0.1:8888"
    assert candidates[0].source == "env:HTTPS_PROXY"


def test_proxy_transport_requires_tls_off_loopback() -> None:
    with pytest.raises(ConfigError):
        validate_relay_transport("ws://support.example.com", "http://127.0.0.1:8080")
    validate_relay_transport("ws://127.0.0.1:8080", "http://127.0.0.1:8080")
    validate_relay_transport("wss://support.example.com", "http://127.0.0.1:8080")
