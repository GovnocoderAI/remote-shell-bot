from __future__ import annotations

import pytest

from rsb.errors import ProtocolError
from rsb.protocol import MAX_FRAME_BYTES, Envelope, decode, encode


def test_roundtrip_preserves_fields() -> None:
    raw = encode("command.exec", {"command": "ls", "nested": {"a": 1}}, ref="abc")
    envelope = decode(raw)
    assert envelope.type == "command.exec"
    assert envelope.payload["command"] == "ls"
    assert envelope.ref == "abc"
    assert len(envelope.id) == 32


def test_generated_id_is_unique() -> None:
    first = Envelope(type="heartbeat")
    second = Envelope(type="heartbeat")
    assert first.id != second.id


def test_invalid_json_is_rejected() -> None:
    with pytest.raises(ProtocolError):
        decode("{not json")


def test_missing_type_is_rejected() -> None:
    with pytest.raises(ProtocolError):
        decode('{"payload": {}}')


def test_non_object_payload_is_rejected() -> None:
    with pytest.raises(ProtocolError):
        decode('{"type": "heartbeat", "payload": []}')


def test_oversized_frame_is_rejected() -> None:
    with pytest.raises(ProtocolError):
        decode("x" * (MAX_FRAME_BYTES + 1))


def test_require_reports_missing_field() -> None:
    envelope = decode('{"type": "hello", "payload": {}}')
    with pytest.raises(ProtocolError):
        envelope.require("device_id")
