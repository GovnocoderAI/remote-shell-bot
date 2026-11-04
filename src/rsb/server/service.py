from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import time
from datetime import datetime
from typing import Any, Protocol

from rsb.config import Settings
from rsb.db.database import Database
from rsb.db.repository import Repository
from rsb.errors import (
    AuthenticationError,
    AuthorizationError,
    CommandFailedError,
    ConflictError,
    DeviceOfflineError,
    NotFoundError,
    RsbError,
    ScreenshotError,
    SessionStateError,
)
from rsb.protocol import Envelope, Msg
from rsb.security import (
    SecretBox,
    device_message,
    generate_token,
    hash_token,
    verify_signature,
)
from rsb.server import policy
from rsb.server.hub import AgentConnection, Hub
from rsb.server.policy import CapabilityError
from rsb.util import iso_in, new_id, parse_iso, short_id, utcnow

log = logging.getLogger("rsb.service")

MAX_COMMAND_LENGTH = 4000
TIMESTAMP_WINDOW_SECONDS = 120


class Notifier(Protocol):
    async def session_active(self, operator_id: int, session: dict, device: dict) -> None: ...

    async def session_denied(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None: ...

    async def session_closed(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None: ...

    async def session_expired(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None: ...

    async def session_updated(self, operator_id: int, session: dict, device: dict) -> None: ...

    async def screenshot(
        self, operator_id: int, session: dict, device: dict, image: bytes, meta: dict
    ) -> None: ...


class NullNotifier:
    async def session_active(self, operator_id: int, session: dict, device: dict) -> None:
        return None

    async def session_denied(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        return None

    async def session_closed(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        return None

    async def session_expired(
        self, operator_id: int, session: dict, device: dict, reason: str | None = None
    ) -> None:
        return None

    async def session_updated(self, operator_id: int, session: dict, device: dict) -> None:
        return None

    async def screenshot(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        image: bytes,
        meta: dict,
    ) -> None:
        return None


class Service:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.repo = Repository(db)
        self.box = SecretBox(settings.resolve_secret_key())
        self.hub = Hub()
        self.notifier: Notifier = NullNotifier()
        self._nonces: dict[str, float] = {}
        self._account_tokens: dict[str, str] = {}

    async def startup_cleanup(self) -> None:
        await self.repo.reset_device_statuses()
        open_sessions = await self.repo.list_open_sessions()
        for session in open_sessions:
            await self._finish_session(
                session, policy.STATE_CLOSED, "server_restart", "system", notify=False
            )

    async def issue_enrollment(self, operator_id: int, label: str) -> tuple[str, str]:
        token = generate_token()
        expires_at = iso_in(self.settings.enrollment_ttl_seconds)
        await self.repo.issue_enrollment(
            hash_token(token), operator_id, label.strip()[:64], expires_at
        )
        await self.repo.add_audit(
            "enrollment.issued",
            actor_type="operator",
            actor_id=operator_id,
            detail={"label": label},
        )
        return token, expires_at

    async def enroll_device(
        self,
        token: str,
        name: str,
        hostname: str | None,
        os_name: str | None,
        os_version: str | None,
    ) -> tuple[dict[str, Any], str]:
        enrollment = await self.repo.consume_enrollment(hash_token(token))
        if enrollment is None:
            raise AuthenticationError("enrollment token is invalid or expired")
        device_secret = generate_token()
        device_id = new_id()
        display_name = (name or hostname or "device").strip()[:64]
        device = await self.repo.create_device(
            device_id=device_id,
            name=display_name,
            hostname=(hostname or "")[:128] or None,
            os_name=(os_name or "")[:64] or None,
            os_version=(os_version or "")[:64] or None,
            owner_telegram_id=enrollment["created_by"],
            secret_encrypted=self.box.encrypt(device_secret),
            capabilities=[policy.CAP_SHELL],
        )
        await self.repo.link_enrollment_device(hash_token(token), device_id)
        await self.repo.add_audit(
            "device.enrolled",
            actor_type="operator",
            actor_id=enrollment["created_by"],
            device_id=device_id,
            detail={"name": display_name, "hostname": hostname, "os": os_name},
        )
        return device, device_secret

    async def authenticate_device(
        self, device_id: str, nonce: str, timestamp: int, signature: str
    ) -> dict[str, Any]:
        if abs(time.time() - timestamp) > TIMESTAMP_WINDOW_SECONDS:
            raise AuthenticationError("handshake timestamp is outside the allowed window")
        nonce_key = f"{device_id}:{nonce}"
        current = time.monotonic()
        if nonce_key in self._nonces and current - self._nonces[nonce_key] < 300:
            raise AuthenticationError("handshake nonce was already used")
        if len(self._nonces) > 8192:
            cutoff = current - 300
            self._nonces = {key: value for key, value in self._nonces.items() if value >= cutoff}
        self._nonces[nonce_key] = current
        device = await self.repo.get_device(device_id)
        if device is None or device["revoked_at"] is not None:
            raise AuthenticationError("device is not registered")
        secret = self.box.decrypt(device["secret_encrypted"])
        expected = device_message(device_id, nonce, timestamp)
        if not verify_signature(secret, expected, signature):
            raise AuthenticationError("device signature is invalid")
        return device

    async def attach_device(
        self, device: dict[str, Any], connection: AgentConnection
    ) -> dict[str, Any]:
        previous = self.hub.register(connection)
        if previous is not None and previous is not connection:
            previous.fail(DeviceOfflineError("replaced by a new connection"))
            try:
                await previous.websocket.close(code=4002)
            except Exception:
                pass
        await self.repo.set_device_status(device["id"], "online")
        await self.repo.add_audit(
            "device.connected", actor_type="device", actor_id=device["id"], device_id=device["id"]
        )
        grants = await self.repo.list_grants(device["id"])
        return {
            "server_time": int(time.time()),
            "session_ttl": self.settings.session_ttl_seconds,
            "request_ttl": self.settings.session_request_ttl_seconds,
            "device": {
                "id": device["id"],
                "name": device["name"],
                "hostname": device["hostname"],
                "os_name": device["os_name"],
                "capabilities": device["capabilities"],
            },
            "grants": [
                {
                    "operator_id": grant["operator_id"],
                    "capabilities": grant["capabilities"],
                    "updated_at": grant["updated_at"],
                }
                for grant in grants
            ],
        }

    async def detach_device(self, device_id: str) -> None:
        device = await self.repo.get_device(device_id)
        status = "revoked" if device is not None and device["revoked_at"] else "offline"
        await self.repo.set_device_status(device_id, status)
        open_session = await self.repo.get_open_session_for_device(device_id)
        if open_session is not None:
            await self._finish_session(
                open_session, policy.STATE_CLOSED, "device_offline", "system"
            )
        await self.repo.add_audit(
            "device.disconnected",
            actor_type="device",
            actor_id=device_id,
            device_id=device_id,
        )

    async def request_session(
        self,
        operator_id: int,
        device_id: str,
        purpose: str,
        requested_capabilities: list[str],
    ) -> dict[str, Any]:
        requested = policy.require_valid(requested_capabilities)
        device = await self.repo.get_device(device_id)
        if device is None or device["revoked_at"] is not None:
            raise NotFoundError("device is not available")
        if not policy.is_subset(requested, device["capabilities"]):
            raise CapabilityError("device does not allow the requested capabilities")
        if not self.hub.is_online(device_id):
            raise DeviceOfflineError("device is offline")
        operator = await self.repo.get_operator(operator_id)
        if operator is None:
            raise AuthorizationError("operator is not registered")
        if await self.repo.get_open_session_for_operator(operator_id) is not None:
            raise ConflictError("operator already has an open session")
        if await self.repo.get_open_session_for_device(device_id) is not None:
            raise ConflictError("device already has an open session")
        grant = await self.repo.get_grant(device_id, operator_id)
        session = await self.repo.create_session(
            session_id=new_id(),
            device_id=device_id,
            operator_id=operator_id,
            purpose=purpose.strip()[:120] or "support",
            requested_capabilities=requested,
            expires_at=iso_in(self.settings.session_request_ttl_seconds),
        )
        sent = await self.hub.send(
            device_id,
            Msg.SESSION_REQUEST,
            {
                "session_id": session["id"],
                "operator": {"id": operator_id, "username": operator["username"]},
                "purpose": session["purpose"],
                "requested_capabilities": requested,
                "previous_capabilities": grant["capabilities"] if grant else None,
                "requested_at": session["created_at"],
                "expires_at": session["expires_at"],
            },
        )
        if not sent:
            await self.repo.close_session(session["id"], policy.STATE_CLOSED)
            raise DeviceOfflineError("device is offline")
        await self.repo.add_audit(
            "session.requested",
            actor_type="operator",
            actor_id=operator_id,
            device_id=device_id,
            session_id=session["id"],
            detail={"purpose": session["purpose"], "capabilities": requested},
        )
        return session

    async def decide_session(
        self,
        device_id: str,
        session_id: str,
        approved: bool,
        capabilities: list[str],
        reason: str | None = None,
    ) -> None:
        session = await self.repo.get_session(session_id)
        if session is None:
            raise NotFoundError("session not found")
        if session["device_id"] != device_id:
            raise AuthorizationError("session belongs to another device")
        if session["state"] != policy.STATE_PENDING:
            raise SessionStateError("session is not pending")
        if parse_iso(session["expires_at"]) <= utcnow():
            await self._finish_session(session, policy.STATE_EXPIRED, "request_expired", "system")
            raise SessionStateError("session request has expired")
        device = await self.repo.get_device(device_id)
        if device is None:
            raise NotFoundError("device not found")
        if not approved:
            await self._deny(session, device, reason or "host_denied")
            return
        allowed = set(device["capabilities"]) & set(session["requested_capabilities"])
        granted = policy.normalize([cap for cap in capabilities if cap in allowed])
        if not granted:
            await self._deny(session, device, "no_capabilities")
            return
        expires_at = iso_in(self.settings.session_ttl_seconds)
        account_id = new_id()
        account_token = generate_token()
        username = f"rsb-{short_id(6)}"
        activated = await self.repo.activate_session(
            session_id=session_id,
            capabilities=granted,
            expires_at=expires_at,
            account_id=account_id,
            username=username,
            token_hash=hash_token(account_token),
        )
        if not activated:
            raise SessionStateError("session can no longer be activated")
        self._account_tokens[session_id] = account_token
        await self.repo.upsert_grant(device_id, session["operator_id"], granted)
        await self.repo.add_audit(
            "session.approved",
            actor_type="device",
            actor_id=device_id,
            device_id=device_id,
            session_id=session_id,
            detail={"operator_id": session["operator_id"], "capabilities": granted},
        )
        session = await self.repo.get_session(session_id)
        assert session is not None
        operator = await self.repo.get_operator(session["operator_id"])
        sent = await self.hub.send(
            device_id,
            Msg.SESSION_APPROVED,
            {
                "session_id": session_id,
                "capabilities": granted,
                "account": {
                    "id": account_id,
                    "username": username,
                    "token": account_token,
                    "expires_at": expires_at,
                },
                "operator": {
                    "id": session["operator_id"],
                    "username": operator["username"] if operator else None,
                },
                "purpose": session["purpose"],
                "expires_at": expires_at,
            },
        )
        if not sent:
            await self._finish_session(session, policy.STATE_CLOSED, "device_offline", "system")
            raise DeviceOfflineError("device disconnected during approval")
        await self.notifier.session_active(session["operator_id"], session, device)

    async def _deny(self, session: dict[str, Any], device: dict[str, Any], reason: str) -> None:
        await self.repo.set_session_denied(session["id"])
        await self.repo.add_audit(
            "session.denied",
            actor_type="device",
            actor_id=session["device_id"],
            device_id=session["device_id"],
            session_id=session["id"],
            detail={"reason": reason},
        )
        if self.hub.is_online(session["device_id"]):
            await self.hub.send(
                session["device_id"],
                Msg.SESSION_DENIED,
                {"session_id": session["id"], "reason": reason},
            )
        await self.notifier.session_denied(session["operator_id"], session, device, reason)

    async def close_session(
        self,
        session_id: str,
        *,
        actor_type: str = "system",
        actor_id: str | int | None = None,
        reason: str = "closed",
        operator_id: int | None = None,
        notify: bool = True,
    ) -> None:
        session = await self.repo.get_session(session_id)
        if session is None:
            raise NotFoundError("session not found")
        if operator_id is not None and session["operator_id"] != operator_id:
            raise AuthorizationError("session belongs to another operator")
        if session["state"] not in policy.OPEN_STATES:
            return
        await self._finish_session(
            session, policy.STATE_CLOSED, reason, actor_type, actor_id, notify
        )

    async def _finish_session(
        self,
        session: dict[str, Any],
        state: str,
        reason: str,
        actor_type: str,
        actor_id: str | int | None = None,
        notify: bool = True,
    ) -> None:
        await self.repo.close_session(session["id"], state)
        await self.repo.revoke_accounts(session["id"])
        self._account_tokens.pop(session["id"], None)
        if self.hub.is_online(session["device_id"]):
            await self.hub.send(
                session["device_id"],
                Msg.SESSION_CLOSE,
                {"session_id": session["id"], "reason": reason},
            )
        await self.repo.add_audit(
            f"session.{state}",
            actor_type=actor_type,
            actor_id=actor_id,
            device_id=session["device_id"],
            session_id=session["id"],
            detail={"reason": reason},
        )
        if not notify:
            return
        device = await self.repo.get_device(session["device_id"])
        if device is None:
            return
        if state == policy.STATE_EXPIRED:
            await self.notifier.session_expired(session["operator_id"], session, device, reason)
        else:
            await self.notifier.session_closed(session["operator_id"], session, device, reason)

    async def expire_due_sessions(self) -> int:
        due = await self.repo.due_sessions()
        for session in due:
            await self._finish_session(session, policy.STATE_EXPIRED, "expired", "system")
        return len(due)

    async def execute_command(
        self, session_id: str, operator_id: int, command: str
    ) -> dict[str, Any]:
        session = await self.repo.get_session(session_id)
        if session is None:
            raise NotFoundError("session not found")
        if session["operator_id"] != operator_id:
            raise AuthorizationError("session belongs to another operator")
        if session["state"] != policy.STATE_ACTIVE:
            raise SessionStateError("session is not active")
        if policy.CAP_SHELL not in session["capabilities"]:
            raise AuthorizationError("shell capability is not granted")
        if parse_iso(session["expires_at"]) <= utcnow():
            await self._finish_session(session, policy.STATE_EXPIRED, "expired", "system")
            raise SessionStateError("session has expired")
        command = command.strip()
        if not command:
            raise CommandFailedError("command is empty")
        if len(command) > MAX_COMMAND_LENGTH:
            raise CommandFailedError("command is too long")
        account_token = self._account_tokens.get(session_id)
        account = await self.repo.get_active_account(session_id)
        if account is None:
            raise SessionStateError("session account is not available")
        if account_token is None:
            await self._finish_session(session, policy.STATE_CLOSED, "account_lost", "system")
            raise SessionStateError("session account is not available")
        if parse_iso(account["expires_at"]) <= utcnow():
            await self._finish_session(session, policy.STATE_EXPIRED, "expired", "system")
            raise SessionStateError("session has expired")
        command_id = await self.repo.add_command(session_id, operator_id, command)
        try:
            response = await self.hub.request(
                session["device_id"],
                Msg.COMMAND_EXEC,
                {
                    "session_id": session_id,
                    "account_token": account_token,
                    "command": command,
                },
                wait_seconds=self.settings.command_timeout_seconds + 15,
            )
        except RsbError as exc:
            await self.repo.finish_command(command_id, None, f"error: {exc}", True)
            raise CommandFailedError(str(exc)) from exc
        except Exception as exc:
            await self.repo.finish_command(command_id, None, f"error: {exc}", True)
            raise CommandFailedError("command execution failed") from exc
        payload = response.payload
        error = payload.get("error")
        if isinstance(error, str) and error:
            await self.repo.finish_command(command_id, None, f"error: {error}", True)
            raise CommandFailedError(error)
        output = str(payload.get("output", ""))[: self.settings.command_max_output_bytes]
        exit_code = payload.get("exit_code")
        truncated = bool(payload.get("truncated"))
        await self.repo.finish_command(command_id, exit_code, output, truncated)
        await self.repo.add_audit(
            "command.executed",
            actor_type="operator",
            actor_id=operator_id,
            device_id=session["device_id"],
            session_id=session_id,
            detail={
                "command": command,
                "exit_code": exit_code,
                "truncated": truncated,
            },
        )
        return {
            "command_id": command_id,
            "output": output,
            "exit_code": exit_code,
            "truncated": truncated,
            "cwd": payload.get("cwd"),
            "timed_out": bool(payload.get("timed_out")),
        }

    async def capture_screenshot(
        self, session_id: str, operator_id: int, notify: bool = True
    ) -> tuple[bytes, dict[str, Any]]:
        session = await self.repo.get_session(session_id)
        if session is None:
            raise NotFoundError("session not found")
        if session["operator_id"] != operator_id:
            raise AuthorizationError("session belongs to another operator")
        if session["state"] != policy.STATE_ACTIVE:
            raise SessionStateError("session is not active")
        if parse_iso(session["expires_at"]) <= utcnow():
            await self._finish_session(session, policy.STATE_EXPIRED, "expired", "system")
            raise SessionStateError("session has expired")
        if policy.CAP_SCREENSHOT not in session["capabilities"]:
            raise AuthorizationError("screenshot capability is not granted")
        account = await self.repo.get_active_account(session_id)
        if account is None or parse_iso(account["expires_at"]) <= utcnow():
            await self._finish_session(session, policy.STATE_EXPIRED, "expired", "system")
            raise SessionStateError("session account is not available")
        account_token = self._account_tokens.get(session_id)
        if account_token is None:
            raise SessionStateError("session account is not available")
        try:
            response = await self.hub.request(
                session["device_id"],
                Msg.SCREENSHOT_REQUEST,
                {"session_id": session_id, "account_token": account_token},
                wait_seconds=45,
            )
        except RsbError as exc:
            raise ScreenshotError(str(exc)) from exc
        agent_error = response.payload.get("error")
        if isinstance(agent_error, str) and agent_error:
            raise ScreenshotError(agent_error)
        image_b64 = response.payload.get("image")
        if not isinstance(image_b64, str) or not image_b64:
            raise ScreenshotError("agent returned an empty screenshot")
        try:
            image = base64.b64decode(image_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ScreenshotError("agent returned invalid screenshot data") from exc
        if len(image) > self.settings.screenshot_max_bytes:
            raise ScreenshotError("screenshot exceeds the size limit")
        meta = {
            "width": response.payload.get("width"),
            "height": response.payload.get("height"),
            "taken_at": response.payload.get("taken_at"),
        }
        await self.repo.add_audit(
            "screenshot.captured",
            actor_type="operator",
            actor_id=operator_id,
            device_id=session["device_id"],
            session_id=session_id,
            detail={"bytes": len(image)},
        )
        if notify:
            device = await self.repo.get_device(session["device_id"])
            if device is not None:
                await self.notifier.screenshot(operator_id, session, device, image, meta)
        return image, meta

    async def update_policy(self, device_id: str, capabilities: list[str]) -> list[str]:
        normalized = policy.sanitize(capabilities, allow_empty=True)
        device = await self.repo.get_device(device_id)
        if device is None:
            raise NotFoundError("device not found")
        await self.repo.set_device_capabilities(device_id, normalized)
        await self.repo.add_audit(
            "policy.updated",
            actor_type="device",
            actor_id=device_id,
            device_id=device_id,
            detail={"capabilities": normalized},
        )
        if self.hub.is_online(device_id):
            await self.hub.send(device_id, Msg.POLICY_UPDATED, {"capabilities": normalized})
        for session in await self.repo.list_open_sessions_for_device(device_id):
            if session["state"] == policy.STATE_PENDING:
                if not policy.is_subset(session["requested_capabilities"], normalized):
                    await self._deny(session, device, "policy_changed")
                continue
            await self._apply_capabilities(
                session,
                normalized,
                actor_type="device",
                actor_id=device_id,
                reason="policy_changed",
            )
        return normalized

    async def update_session_capabilities(
        self, device_id: str, session_id: str, capabilities: list[str]
    ) -> list[str]:
        session = await self.repo.get_session(session_id)
        if session is None:
            raise NotFoundError("session not found")
        if session["device_id"] != device_id:
            raise AuthorizationError("session belongs to another device")
        if session["state"] != policy.STATE_ACTIVE:
            raise SessionStateError("session is not active")
        requested = set(str(item) for item in capabilities)
        if not requested <= set(session["capabilities"]):
            raise AuthorizationError("session capabilities can only be reduced")
        return await self._apply_capabilities(
            session,
            list(requested),
            actor_type="device",
            actor_id=device_id,
            reason="host_restricted",
        )

    async def _apply_capabilities(
        self,
        session: dict[str, Any],
        capabilities: list[str],
        *,
        actor_type: str,
        actor_id: str | int | None,
        reason: str,
    ) -> list[str]:
        device = await self.repo.get_device(session["device_id"])
        if device is None:
            return []
        allowed = set(session["capabilities"]) & set(device["capabilities"]) & set(capabilities)
        updated = policy.normalize(allowed)
        if not updated:
            await self._finish_session(session, policy.STATE_CLOSED, reason, actor_type, actor_id)
            return []
        if updated == session["capabilities"]:
            return updated
        await self.repo.update_session_capabilities(session["id"], updated)
        await self.repo.update_account_capabilities(session["id"], updated)
        if self.hub.is_online(session["device_id"]):
            await self.hub.send(
                session["device_id"],
                Msg.SESSION_UPDATE,
                {"session_id": session["id"], "capabilities": updated},
            )
        await self.repo.add_audit(
            "session.capabilities_updated",
            actor_type=actor_type,
            actor_id=actor_id,
            device_id=session["device_id"],
            session_id=session["id"],
            detail={"capabilities": updated, "reason": reason},
        )
        refreshed = await self.repo.get_session(session["id"])
        if refreshed is not None:
            await self.notifier.session_updated(refreshed["operator_id"], refreshed, device)
        return updated

    async def revoke_grant(self, device_id: str, operator_id: int) -> None:
        await self.repo.delete_grant(device_id, operator_id)
        await self.repo.add_audit(
            "grant.revoked",
            actor_type="device",
            actor_id=device_id,
            device_id=device_id,
            detail={"operator_id": operator_id},
        )
        if self.hub.is_online(device_id):
            await self.hub.send(device_id, Msg.GRANT_REVOKED, {"operator_id": operator_id})

    async def revoke_device(
        self, device_id: str, actor_type: str = "operator", actor_id: str | int | None = None
    ) -> None:
        device = await self.repo.get_device(device_id)
        if device is None:
            raise NotFoundError("device not found")
        await self.repo.revoke_device(device_id)
        for session in await self.repo.list_open_sessions_for_device(device_id):
            await self._finish_session(
                session, policy.STATE_CLOSED, "device_revoked", actor_type, actor_id
            )
        await self.repo.delete_grants_for_device(device_id)
        await self.repo.add_audit(
            "device.revoked",
            actor_type=actor_type,
            actor_id=actor_id,
            device_id=device_id,
        )
        connection = self.hub.get(device_id)
        if connection is not None:
            try:
                await connection.websocket.close(code=4001)
            except Exception:
                pass

    def operator_authorized(self, operator: dict[str, Any] | None) -> bool:
        if operator is None or not operator["is_active"]:
            return False
        if not operator["totp_secret"] or not operator["totp_confirmed_at"]:
            return False
        expires_at = operator["auth_expires_at"]
        if not expires_at:
            return False
        return parse_iso(expires_at) > utcnow()

    async def handle_agent_message(self, connection: AgentConnection, envelope: Envelope) -> None:
        try:
            if envelope.type == Msg.SESSION_DECISION:
                payload = envelope.payload
                await self.decide_session(
                    device_id=connection.device_id,
                    session_id=str(payload.get("session_id", "")),
                    approved=bool(payload.get("approved")),
                    capabilities=[str(item) for item in payload.get("capabilities", [])],
                    reason=payload.get("reason"),
                )
            elif envelope.type == Msg.SESSION_CLOSE_REQUEST:
                payload = envelope.payload
                await self.close_session(
                    str(payload.get("session_id", "")),
                    actor_type="device",
                    actor_id=connection.device_id,
                    reason=str(payload.get("reason") or "host_closed"),
                )
            elif envelope.type == Msg.SESSION_CAPABILITIES:
                payload = envelope.payload
                await self.update_session_capabilities(
                    connection.device_id,
                    str(payload.get("session_id", "")),
                    [str(item) for item in payload.get("capabilities", [])],
                )
            elif envelope.type == Msg.AUDIT_EVENT:
                payload = envelope.payload
                session = await self.repo.get_session(str(payload.get("session_id", "")))
                await self.repo.add_audit(
                    f"agent.{payload.get('action', 'event')}",
                    actor_type="device",
                    actor_id=connection.device_id,
                    device_id=connection.device_id,
                    session_id=session["id"] if session else None,
                    detail=payload.get("detail") if isinstance(payload.get("detail"), dict) else {},
                )
            elif envelope.type == Msg.HEARTBEAT:
                await self.repo.touch_device(connection.device_id)
            elif envelope.type == Msg.POLICY_UPDATE:
                capabilities = [str(item) for item in envelope.payload.get("capabilities", [])]
                await self.update_policy(connection.device_id, capabilities)
            elif envelope.type == Msg.GRANT_REVOKE:
                await self.revoke_grant(
                    connection.device_id, int(envelope.payload.get("operator_id", 0))
                )
            else:
                log.debug("unhandled agent message %s", envelope.type)
        except RsbError as exc:
            log.warning("agent message %s failed: %s", envelope.type, exc)
            details: dict[str, Any] = {"message": str(exc)}
            session_id = envelope.payload.get("session_id")
            if isinstance(session_id, str):
                details["session_id"] = session_id
            await connection.send(Msg.ERROR, details, ref=envelope.id)
        except Exception:
            log.exception("agent message %s crashed", envelope.type)
            await connection.send(Msg.ERROR, {"message": "internal error"}, ref=envelope.id)

    async def maintenance_loop(self, stop: asyncio.Event) -> None:
        last_purge = 0.0
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=15)
                break
            except TimeoutError:
                pass
            try:
                await self.expire_due_sessions()
                now = time.monotonic()
                if now - last_purge > 21600:
                    await self.purge_history()
                    last_purge = now
            except Exception:
                log.exception("maintenance iteration failed")

    async def purge_history(self) -> None:
        retention = self.settings.audit_retention_days
        cutoff = datetime.fromtimestamp(time.time() - retention * 86400, tz=utcnow().tzinfo)
        stamp = cutoff.isoformat(timespec="seconds")
        await self.repo.purge_audit(stamp)
        await self.repo.purge_commands(stamp)

    async def shutdown(self) -> None:
        await self.hub.shutdown()
