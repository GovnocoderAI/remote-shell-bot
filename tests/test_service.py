from __future__ import annotations

import base64
import time

import pytest

from rsb.errors import (
    AuthenticationError,
    AuthorizationError,
    CommandFailedError,
    SessionStateError,
)
from rsb.protocol import Envelope, Msg
from rsb.security import device_message, sign
from rsb.server.policy import CapabilityError
from rsb.server.service import Service
from rsb.util import new_nonce, now_iso


class FakeHub:
    def __init__(self) -> None:
        self.online: set[str] = set()
        self.sent: list[tuple[str, dict]] = []
        self.responses: dict[str, dict] = {}

    def is_online(self, device_id: str) -> bool:
        return device_id in self.online

    def get(self, device_id: str):
        return None

    async def send(
        self, device_id: str, message_type: str, payload: dict, ref: str | None = None
    ) -> bool:
        self.sent.append((message_type, payload))
        return True

    async def request(
        self, device_id: str, message_type: str, payload: dict, wait_seconds: float
    ) -> Envelope:
        return Envelope(type=message_type, payload=self.responses[message_type])

    async def shutdown(self) -> None:
        self.online.clear()


class FakeNotifier:
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    async def session_active(self, operator_id: int, session: dict, device: dict) -> None:
        self.events.append(("active", session["id"]))

    async def session_denied(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        self.events.append(("denied", session["id"]))

    async def session_closed(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        self.events.append(("closed", session["id"]))

    async def session_expired(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        self.events.append(("expired", session["id"]))

    async def session_updated(self, operator_id: int, session: dict, device: dict) -> None:
        self.events.append(("updated", session["id"]))

    async def screenshot(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        image: bytes,
        meta: dict,
    ) -> None:
        self.events.append(("screenshot", session["id"]))


async def scenario(service: Service) -> tuple[dict, str, FakeHub, FakeNotifier]:
    hub = FakeHub()
    notifier = FakeNotifier()
    service.hub = hub  # type: ignore[assignment]
    service.notifier = notifier
    await service.repo.ensure_operator(100, "admin")
    token, _ = await service.issue_enrollment(100, "workstation")
    device, secret = await service.enroll_device(
        token, "workstation", "workstation.local", "Linux", "6.8"
    )
    hub.online.add(device["id"])
    return device, secret, hub, notifier


async def test_enrollment_token_is_single_use(service: Service) -> None:
    await scenario(service)
    token, _ = await service.issue_enrollment(100, "second")
    await service.enroll_device(token, "second", None, "Linux", "6")
    with pytest.raises(AuthenticationError):
        await service.enroll_device(token, "second", None, "Linux", "6")


async def test_device_authentication_rejects_replay(service: Service) -> None:
    device, secret, _, _ = await scenario(service)
    timestamp = int(time.time())
    nonce = new_nonce()
    signature = sign(secret, device_message(device["id"], nonce, timestamp))
    authenticated = await service.authenticate_device(device["id"], nonce, timestamp, signature)
    assert authenticated["id"] == device["id"]
    with pytest.raises(AuthenticationError):
        await service.authenticate_device(device["id"], nonce, timestamp, signature)
    with pytest.raises(AuthenticationError):
        await service.authenticate_device(device["id"], new_nonce(), timestamp, "bad")
    with pytest.raises(AuthenticationError):
        await service.authenticate_device(device["id"], new_nonce(), timestamp - 1000, signature)


async def test_session_approval_and_command(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    assert session["state"] == "pending"
    assert hub.sent[-1][0] == Msg.SESSION_REQUEST

    await service.decide_session(device["id"], session["id"], True, ["shell"])
    active = await service.repo.get_session(session["id"])
    assert active is not None
    assert active["state"] == "active"
    assert active["capabilities"] == ["shell"]
    assert ("active", session["id"]) in notifier.events
    assert hub.sent[-1][0] == Msg.SESSION_APPROVED
    assert "token" in hub.sent[-1][1]["account"]

    hub.responses[Msg.COMMAND_EXEC] = {
        "output": "ok\n",
        "exit_code": 0,
        "cwd": "/tmp",
        "truncated": False,
        "timed_out": False,
    }
    result = await service.execute_command(session["id"], 100, "echo ok")
    assert result["output"] == "ok\n"
    assert result["exit_code"] == 0
    commands = await service.repo.list_commands(session["id"])
    assert commands[0]["command"] == "echo ok"

    with pytest.raises(AuthorizationError):
        await service.execute_command(session["id"], 200, "id")

    await service.close_session(session["id"], actor_type="operator", actor_id=100, operator_id=100)
    closed = await service.repo.get_session(session["id"])
    assert closed is not None
    assert closed["state"] == "closed"
    assert hub.sent[-1][0] == Msg.SESSION_CLOSE
    with pytest.raises(SessionStateError):
        await service.execute_command(session["id"], 100, "id")


async def test_denied_session_is_not_activated(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.decide_session(device["id"], session["id"], False, [])
    denied = await service.repo.get_session(session["id"])
    assert denied is not None
    assert denied["state"] == "denied"
    assert ("denied", session["id"]) in notifier.events
    assert hub.sent[-1][0] == Msg.SESSION_DENIED


async def test_screenshot_requires_granted_capability(service: Service) -> None:
    device, _, hub, _ = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.decide_session(device["id"], session["id"], True, ["shell"])
    with pytest.raises(AuthorizationError):
        await service.capture_screenshot(session["id"], 100)
    assert not hub.responses


async def test_screenshot_with_capability(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell", "screenshot"])
    await service.decide_session(device["id"], session["id"], True, ["shell", "screenshot"])
    hub.responses[Msg.SCREENSHOT_REQUEST] = {
        "image": base64.b64encode(b"jpeg-bytes").decode("ascii"),
        "width": 800,
        "height": 600,
        "taken_at": now_iso(),
    }
    image, meta = await service.capture_screenshot(session["id"], 100)
    assert image == b"jpeg-bytes"
    assert meta["width"] == 800
    assert ("screenshot", session["id"]) in notifier.events


async def test_approval_cannot_exceed_requested_capabilities(service: Service) -> None:
    device, _, _, notifier = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.decide_session(device["id"], session["id"], True, ["screenshot"])
    result = await service.repo.get_session(session["id"])
    assert result is not None
    assert result["state"] == "denied"
    assert ("denied", session["id"]) in notifier.events


async def test_policy_controls_requested_capabilities(service: Service) -> None:
    device, _, _, _ = await scenario(service)
    await service.update_policy(device["id"], ["screenshot"])
    with pytest.raises(CapabilityError):
        await service.request_session(100, device["id"], "support", ["shell"])
    session = await service.request_session(100, device["id"], "support", ["screenshot"])
    assert session["requested_capabilities"] == ["screenshot"]
    await service.close_session(session["id"])


async def test_expired_sessions_are_closed(service: Service) -> None:
    device, _, _, notifier = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.db.execute(
        "UPDATE sessions SET expires_at = ? WHERE id = ?",
        ("2000-01-01T00:00:00+00:00", session["id"]),
    )
    count = await service.expire_due_sessions()
    assert count == 1
    expired = await service.repo.get_session(session["id"])
    assert expired is not None
    assert expired["state"] == "expired"
    assert ("expired", session["id"]) in notifier.events


async def test_host_can_reduce_session_capabilities(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell", "screenshot"])
    await service.decide_session(device["id"], session["id"], True, ["shell", "screenshot"])
    reduced = await service.update_session_capabilities(device["id"], session["id"], ["shell"])
    assert reduced == ["shell"]
    updated = await service.repo.get_session(session["id"])
    assert updated is not None
    assert updated["capabilities"] == ["shell"]
    account = await service.repo.get_active_account(session["id"])
    assert account is not None
    assert account["capabilities"] == ["shell"]
    assert any(message == Msg.SESSION_UPDATE for message, _ in hub.sent)
    assert ("updated", session["id"]) in notifier.events
    with pytest.raises(AuthorizationError):
        await service.update_session_capabilities(
            device["id"], session["id"], ["shell", "screenshot"]
        )


async def test_policy_change_trims_active_session(service: Service) -> None:
    device, _, hub, _ = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell", "screenshot"])
    await service.decide_session(device["id"], session["id"], True, ["shell", "screenshot"])
    await service.update_policy(device["id"], ["shell"])
    updated = await service.repo.get_session(session["id"])
    assert updated is not None
    assert updated["state"] == "active"
    assert updated["capabilities"] == ["shell"]
    assert any(message == Msg.SESSION_UPDATE for message, _ in hub.sent)
    with pytest.raises(AuthorizationError):
        await service.capture_screenshot(session["id"], 100)


async def test_policy_change_denies_stale_pending_request(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell", "screenshot"])
    await service.update_policy(device["id"], ["shell"])
    denied = await service.repo.get_session(session["id"])
    assert denied is not None
    assert denied["state"] == "denied"
    assert ("denied", session["id"]) in notifier.events
    assert any(message == Msg.SESSION_DENIED for message, _ in hub.sent)


async def test_empty_policy_closes_active_session(service: Service) -> None:
    device, _, _, notifier = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.decide_session(device["id"], session["id"], True, ["shell"])
    await service.update_policy(device["id"], [])
    closed = await service.repo.get_session(session["id"])
    assert closed is not None
    assert closed["state"] == "closed"
    assert ("closed", session["id"]) in notifier.events


async def test_command_error_is_reported(service: Service) -> None:
    device, _, hub, _ = await scenario(service)
    session = await service.request_session(100, device["id"], "support", ["shell"])
    await service.decide_session(device["id"], session["id"], True, ["shell"])
    hub.responses[Msg.COMMAND_EXEC] = {"error": "shell refused"}
    with pytest.raises(CommandFailedError):
        await service.execute_command(session["id"], 100, "id")
    commands = await service.repo.list_commands(session["id"])
    assert commands[0]["output"] == "error: shell refused"


async def test_screenshot_without_notification(service: Service) -> None:
    device, _, hub, notifier = await scenario(service)
    await service.update_policy(device["id"], ["shell", "screenshot"])
    session = await service.request_session(100, device["id"], "support", ["shell", "screenshot"])
    await service.decide_session(device["id"], session["id"], True, ["shell", "screenshot"])
    hub.responses[Msg.SCREENSHOT_REQUEST] = {
        "image": base64.b64encode(b"frame").decode("ascii"),
        "width": 640,
        "height": 480,
        "taken_at": now_iso(),
    }
    before = len(notifier.events)
    image, _ = await service.capture_screenshot(session["id"], 100, notify=False)
    assert image == b"frame"
    assert len(notifier.events) == before
