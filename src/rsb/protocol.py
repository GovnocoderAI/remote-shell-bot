from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rsb.errors import ProtocolError
from rsb.util import new_id

MAX_CONTROL_BYTES = 64 * 1024
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_TYPE_LENGTH = 64


class Msg:
    HELLO = "hello"
    HELLO_OK = "hello.ok"
    HELLO_ERROR = "hello.error"
    HEARTBEAT = "heartbeat"
    SESSION_REQUEST = "session.request"
    SESSION_APPROVED = "session.approved"
    SESSION_DENIED = "session.denied"
    SESSION_DECISION = "session.decision"
    SESSION_CLOSE = "session.close"
    SESSION_CLOSE_REQUEST = "session.close_request"
    SESSION_UPDATE = "session.update"
    SESSION_CAPABILITIES = "session.capabilities"
    COMMAND_EXEC = "command.exec"
    COMMAND_RESULT = "command.result"
    SCREENSHOT_REQUEST = "screenshot.request"
    SCREENSHOT_RESULT = "screenshot.result"
    POLICY_UPDATE = "policy.update"
    POLICY_UPDATED = "policy.updated"
    GRANT_REVOKE = "grant.revoke"
    GRANT_REVOKED = "grant.revoked"
    AUDIT_EVENT = "audit.event"
    ERROR = "error"


@dataclass(slots=True)
class Envelope:
    type: str
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    ref: str | None = None

    def to_json(self) -> str:
        return json.dumps(
            {"type": self.type, "id": self.id, "ref": self.ref, "payload": self.payload},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> Envelope:
        if isinstance(raw, bytes):
            if len(raw) > MAX_FRAME_BYTES:
                raise ProtocolError("frame exceeds maximum size")
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolError("frame is not valid utf-8") from exc
        if len(raw.encode("utf-8")) > MAX_FRAME_BYTES:
            raise ProtocolError("frame exceeds maximum size")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProtocolError("frame is not valid json") from exc
        if not isinstance(data, dict):
            raise ProtocolError("frame must be a json object")
        message_type = data.get("type")
        if not isinstance(message_type, str) or not message_type:
            raise ProtocolError("message type is required")
        if len(message_type) > MAX_TYPE_LENGTH:
            raise ProtocolError("message type is too long")
        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be an object")
        message_id = data.get("id")
        if message_id is None:
            message_id = new_id()
        if not isinstance(message_id, str) or len(message_id) > 64:
            raise ProtocolError("message id is invalid")
        ref = data.get("ref")
        if ref is not None and (not isinstance(ref, str) or len(ref) > 64):
            raise ProtocolError("reference is invalid")
        return cls(type=message_type, payload=payload, id=message_id, ref=ref)

    def require(self, key: str) -> Any:
        if key not in self.payload:
            raise ProtocolError(f"payload field '{key}' is required")
        return self.payload[key]


def encode(message_type: str, payload: dict[str, Any] | None = None, ref: str | None = None) -> str:
    return Envelope(type=message_type, payload=payload or {}, ref=ref).to_json()


def decode(raw: str | bytes) -> Envelope:
    return Envelope.from_json(raw)
