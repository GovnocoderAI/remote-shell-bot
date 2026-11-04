from __future__ import annotations

import json
from typing import Any

import aiosqlite

from rsb.db.database import Database
from rsb.util import now_iso


def _record(row: aiosqlite.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    data = dict(row)
    for key in ("capabilities", "requested_capabilities"):
        if key in data and isinstance(data[key], str):
            try:
                data[key] = json.loads(data[key])
            except json.JSONDecodeError:
                data[key] = []
    if "detail" in data and isinstance(data["detail"], str):
        try:
            data["detail"] = json.loads(data["detail"])
        except json.JSONDecodeError:
            data["detail"] = {"raw": data["detail"]}
    return data


def _records(rows: list[aiosqlite.Row]) -> list[dict[str, Any]]:
    return [record for row in rows if (record := _record(row)) is not None]


class Repository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def ensure_operator(
        self, telegram_id: int, username: str | None, now: str | None = None
    ) -> dict[str, Any]:
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO operators(telegram_id, username, created_at, last_seen_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username = excluded.username,
                last_seen_at = excluded.last_seen_at
            """,
            (telegram_id, username, stamp, stamp),
        )
        operator = await self.get_operator(telegram_id)
        assert operator is not None
        return operator

    async def get_operator(self, telegram_id: int) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone("SELECT * FROM operators WHERE telegram_id = ?", (telegram_id,))
        )

    async def list_operators(self) -> list[dict[str, Any]]:
        return _records(await self.db.fetchall("SELECT * FROM operators ORDER BY created_at"))

    async def set_operator_totp(
        self, telegram_id: int, secret: str, now: str | None = None
    ) -> None:
        await self.db.execute(
            """
            UPDATE operators
            SET totp_secret = ?, totp_confirmed_at = NULL, auth_expires_at = NULL
            WHERE telegram_id = ?
            """,
            (secret, telegram_id),
        )

    async def confirm_operator_totp(self, telegram_id: int, now: str | None = None) -> None:
        await self.db.execute(
            "UPDATE operators SET totp_confirmed_at = ? WHERE telegram_id = ?",
            (now or now_iso(), telegram_id),
        )

    async def set_operator_auth(
        self, telegram_id: int, expires_at: str, now: str | None = None
    ) -> None:
        await self.db.execute(
            "UPDATE operators SET auth_expires_at = ?, last_seen_at = ? WHERE telegram_id = ?",
            (expires_at, now or now_iso(), telegram_id),
        )

    async def clear_operator_auth(self, telegram_id: int) -> None:
        await self.db.execute(
            "UPDATE operators SET auth_expires_at = NULL WHERE telegram_id = ?",
            (telegram_id,),
        )

    async def set_operator_active(self, telegram_id: int, active: bool) -> None:
        await self.db.execute(
            "UPDATE operators SET is_active = ? WHERE telegram_id = ?",
            (1 if active else 0, telegram_id),
        )

    async def get_access_request(self, telegram_id: int) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone(
                "SELECT * FROM access_requests WHERE telegram_id = ?", (telegram_id,)
            )
        )

    async def upsert_access_request(
        self,
        telegram_id: int,
        username: str | None,
        now: str | None = None,
    ) -> dict[str, Any]:
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO access_requests(telegram_id, username, status, created_at)
            VALUES(?, ?, 'pending', ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                username = excluded.username,
                status = CASE
                    WHEN access_requests.status = 'approved' THEN 'approved'
                    ELSE 'pending'
                END,
                created_at = CASE
                    WHEN access_requests.status = 'approved' THEN access_requests.created_at
                    ELSE excluded.created_at
                END,
                decided_at = CASE
                    WHEN access_requests.status = 'approved' THEN access_requests.decided_at
                    ELSE NULL
                END,
                decided_by = CASE
                    WHEN access_requests.status = 'approved' THEN access_requests.decided_by
                    ELSE NULL
                END
            """,
            (telegram_id, username, stamp),
        )
        request = await self.get_access_request(telegram_id)
        assert request is not None
        return request

    async def set_access_status(
        self,
        telegram_id: int,
        status: str,
        decided_by: int | None = None,
        now: str | None = None,
    ) -> None:
        if status not in {"pending", "approved", "denied"}:
            raise ValueError("invalid access status")
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO access_requests(
                telegram_id, username, status, created_at, decided_at, decided_by
            )
            VALUES(?, NULL, ?, ?, ?, ?)
            ON CONFLICT(telegram_id) DO UPDATE SET
                status = excluded.status,
                decided_at = excluded.decided_at,
                decided_by = excluded.decided_by
            """,
            (telegram_id, status, stamp, stamp, decided_by),
        )

    async def has_access(self, telegram_id: int) -> bool:
        row = await self.db.fetchone(
            "SELECT 1 FROM access_requests WHERE telegram_id = ? AND status = 'approved'",
            (telegram_id,),
        )
        return row is not None

    async def list_access_requests(
        self, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        if status is None:
            rows = await self.db.fetchall(
                "SELECT * FROM access_requests ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        else:
            rows = await self.db.fetchall(
                "SELECT * FROM access_requests WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status, limit),
            )
        return _records(rows)

    async def issue_enrollment(
        self,
        token_hash: str,
        created_by: int,
        label: str,
        expires_at: str,
        now: str | None = None,
    ) -> None:
        await self.db.execute(
            """
            INSERT INTO enrollment_tokens(token_hash, label, created_by, created_at, expires_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (token_hash, label, created_by, now or now_iso(), expires_at),
        )

    async def consume_enrollment(
        self, token_hash: str, now: str | None = None
    ) -> dict[str, Any] | None:
        stamp = now or now_iso()
        async with self.db.transaction() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM enrollment_tokens
                WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
                """,
                (token_hash, stamp),
            )
            row = await cursor.fetchone()
            if row is None:
                return None
            update = await conn.execute(
                "UPDATE enrollment_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL",
                (stamp, token_hash),
            )
            if update.rowcount != 1:
                return None
            return _record(row)

    async def link_enrollment_device(self, token_hash: str, device_id: str) -> None:
        await self.db.execute(
            "UPDATE enrollment_tokens SET used_device_id = ? WHERE token_hash = ?",
            (device_id, token_hash),
        )

    async def create_device(
        self,
        device_id: str,
        name: str,
        hostname: str | None,
        os_name: str | None,
        os_version: str | None,
        owner_telegram_id: int | None,
        secret_encrypted: str,
        capabilities: list[str],
        now: str | None = None,
    ) -> dict[str, Any]:
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO devices(
                id, name, hostname, os_name, os_version, owner_telegram_id,
                secret_encrypted, capabilities, status, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'offline', ?)
            """,
            (
                device_id,
                name,
                hostname,
                os_name,
                os_version,
                owner_telegram_id,
                secret_encrypted,
                json.dumps(capabilities),
                stamp,
            ),
        )
        device = await self.get_device(device_id)
        assert device is not None
        return device

    async def get_device(self, device_id: str) -> dict[str, Any] | None:
        return _record(await self.db.fetchone("SELECT * FROM devices WHERE id = ?", (device_id,)))

    async def list_devices(self, include_revoked: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM devices"
        params: tuple[Any, ...] = ()
        if not include_revoked:
            query += " WHERE revoked_at IS NULL"
        query += " ORDER BY created_at"
        return _records(await self.db.fetchall(query, params))

    async def set_device_status(self, device_id: str, status: str, now: str | None = None) -> None:
        await self.db.execute(
            "UPDATE devices SET status = ?, last_seen_at = ? WHERE id = ?",
            (status, now or now_iso(), device_id),
        )

    async def touch_device(self, device_id: str, now: str | None = None) -> None:
        await self.db.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?",
            (now or now_iso(), device_id),
        )

    async def set_device_capabilities(self, device_id: str, capabilities: list[str]) -> None:
        await self.db.execute(
            "UPDATE devices SET capabilities = ? WHERE id = ?",
            (json.dumps(capabilities), device_id),
        )

    async def revoke_device(self, device_id: str, now: str | None = None) -> None:
        stamp = now or now_iso()
        await self.db.execute(
            "UPDATE devices SET revoked_at = ?, status = 'revoked' WHERE id = ?",
            (stamp, device_id),
        )

    async def create_session(
        self,
        session_id: str,
        device_id: str,
        operator_id: int,
        purpose: str,
        requested_capabilities: list[str],
        expires_at: str,
        now: str | None = None,
    ) -> dict[str, Any]:
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO sessions(
                id, device_id, operator_id, state, purpose,
                requested_capabilities, capabilities, created_at, expires_at
            )
            VALUES(?, ?, ?, 'pending', ?, ?, '[]', ?, ?)
            """,
            (
                session_id,
                device_id,
                operator_id,
                purpose,
                json.dumps(requested_capabilities),
                stamp,
                expires_at,
            ),
        )
        session = await self.get_session(session_id)
        assert session is not None
        return session

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        return _record(await self.db.fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,)))

    async def get_open_session_for_operator(self, operator_id: int) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone(
                "SELECT * FROM sessions WHERE operator_id = ? AND state IN ('pending','active') "
                "ORDER BY created_at DESC LIMIT 1",
                (operator_id,),
            )
        )

    async def get_open_session_for_device(self, device_id: str) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone(
                "SELECT * FROM sessions WHERE device_id = ? AND state IN ('pending','active') "
                "ORDER BY created_at DESC LIMIT 1",
                (device_id,),
            )
        )

    async def list_active_sessions(self) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM sessions WHERE state = 'active' ORDER BY created_at"
            )
        )

    async def list_open_sessions(self) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM sessions WHERE state IN ('pending','active') ORDER BY created_at"
            )
        )

    async def list_open_sessions_for_device(self, device_id: str) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM sessions WHERE device_id = ? AND state IN ('pending','active') "
                "ORDER BY created_at",
                (device_id,),
            )
        )

    async def update_session_capabilities(self, session_id: str, capabilities: list[str]) -> None:
        await self.db.execute(
            "UPDATE sessions SET capabilities = ? WHERE id = ? AND state = 'active'",
            (json.dumps(capabilities), session_id),
        )

    async def update_account_capabilities(self, session_id: str, capabilities: list[str]) -> None:
        await self.db.execute(
            "UPDATE session_accounts SET capabilities = ? "
            "WHERE session_id = ? AND revoked_at IS NULL",
            (json.dumps(capabilities), session_id),
        )

    async def reset_device_statuses(self) -> None:
        await self.db.execute("UPDATE devices SET status = 'offline' WHERE status = 'online'")

    async def list_recent_sessions(self, limit: int = 20) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        )

    async def activate_session(
        self,
        session_id: str,
        capabilities: list[str],
        expires_at: str,
        account_id: str,
        username: str,
        token_hash: str,
        now: str | None = None,
    ) -> bool:
        stamp = now or now_iso()
        async with self.db.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE sessions
                SET state = 'active', capabilities = ?, approved_at = ?, expires_at = ?
                WHERE id = ? AND state = 'pending'
                """,
                (json.dumps(capabilities), stamp, expires_at, session_id),
            )
            if cursor.rowcount != 1:
                return False
            await conn.execute(
                """
                INSERT INTO session_accounts(
                    id, session_id, username, token_hash, capabilities, created_at, expires_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    account_id,
                    session_id,
                    username,
                    token_hash,
                    json.dumps(capabilities),
                    stamp,
                    expires_at,
                ),
            )
            return True

    async def set_session_denied(self, session_id: str, now: str | None = None) -> None:
        await self.db.execute(
            "UPDATE sessions SET state = 'denied', denied_at = ?, closed_at = ? "
            "WHERE id = ? AND state = 'pending'",
            (now or now_iso(), now or now_iso(), session_id),
        )

    async def close_session(
        self, session_id: str, state: str = "closed", now: str | None = None
    ) -> None:
        if state not in {"closed", "expired"}:
            raise ValueError("invalid closing state")
        await self.db.execute(
            "UPDATE sessions SET state = ?, closed_at = ? WHERE id = ? AND state IN ('pending','active')",
            (state, now or now_iso(), session_id),
        )

    async def due_sessions(self, now: str | None = None) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM sessions WHERE state IN ('pending','active') AND expires_at <= ?",
                (now or now_iso(),),
            )
        )

    async def create_account(
        self,
        account_id: str,
        session_id: str,
        username: str,
        token_hash: str,
        capabilities: list[str],
        expires_at: str,
        now: str | None = None,
    ) -> None:
        await self.db.execute(
            """
            INSERT INTO session_accounts(
                id, session_id, username, token_hash, capabilities, created_at, expires_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_id,
                session_id,
                username,
                token_hash,
                json.dumps(capabilities),
                now or now_iso(),
                expires_at,
            ),
        )

    async def get_active_account(self, session_id: str) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone(
                "SELECT * FROM session_accounts WHERE session_id = ? AND revoked_at IS NULL "
                "ORDER BY created_at DESC LIMIT 1",
                (session_id,),
            )
        )

    async def revoke_accounts(self, session_id: str, now: str | None = None) -> None:
        await self.db.execute(
            "UPDATE session_accounts SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL",
            (now or now_iso(), session_id),
        )

    async def upsert_grant(
        self,
        device_id: str,
        operator_id: int,
        capabilities: list[str],
        now: str | None = None,
    ) -> None:
        stamp = now or now_iso()
        await self.db.execute(
            """
            INSERT INTO access_grants(device_id, operator_id, capabilities, granted_at, updated_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(device_id, operator_id) DO UPDATE SET
                capabilities = excluded.capabilities,
                updated_at = excluded.updated_at
            """,
            (device_id, operator_id, json.dumps(capabilities), stamp, stamp),
        )

    async def get_grant(self, device_id: str, operator_id: int) -> dict[str, Any] | None:
        return _record(
            await self.db.fetchone(
                "SELECT * FROM access_grants WHERE device_id = ? AND operator_id = ?",
                (device_id, operator_id),
            )
        )

    async def list_grants(self, device_id: str) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM access_grants WHERE device_id = ? ORDER BY updated_at DESC",
                (device_id,),
            )
        )

    async def delete_grant(self, device_id: str, operator_id: int) -> None:
        await self.db.execute(
            "DELETE FROM access_grants WHERE device_id = ? AND operator_id = ?",
            (device_id, operator_id),
        )

    async def delete_grants_for_device(self, device_id: str) -> None:
        await self.db.execute("DELETE FROM access_grants WHERE device_id = ?", (device_id,))

    async def add_command(
        self,
        session_id: str,
        operator_id: int,
        command: str,
        now: str | None = None,
    ) -> int:
        return await self.db.execute(
            """
            INSERT INTO commands(session_id, operator_id, command, started_at)
            VALUES(?, ?, ?, ?)
            """,
            (session_id, operator_id, command, now or now_iso()),
        )

    async def finish_command(
        self,
        command_id: int,
        exit_code: int | None,
        output: str,
        truncated: bool,
        now: str | None = None,
    ) -> None:
        await self.db.execute(
            "UPDATE commands SET exit_code = ?, output = ?, truncated = ?, finished_at = ? "
            "WHERE id = ?",
            (exit_code, output, 1 if truncated else 0, now or now_iso(), command_id),
        )

    async def list_commands(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall(
                "SELECT * FROM commands WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            )
        )

    async def purge_commands(self, before: str) -> None:
        await self.db.execute("DELETE FROM commands WHERE started_at < ?", (before,))

    async def add_audit(
        self,
        action: str,
        actor_type: str = "system",
        actor_id: str | int | None = None,
        device_id: str | None = None,
        session_id: str | None = None,
        detail: dict[str, Any] | None = None,
        now: str | None = None,
    ) -> int:
        return await self.db.execute(
            """
            INSERT INTO audit(ts, actor_type, actor_id, action, device_id, session_id, detail)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now or now_iso(),
                actor_type,
                None if actor_id is None else str(actor_id),
                action,
                device_id,
                session_id,
                json.dumps(detail or {}, ensure_ascii=False),
            ),
        )

    async def list_audit(self, limit: int = 20) -> list[dict[str, Any]]:
        return _records(
            await self.db.fetchall("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        )

    async def purge_audit(self, before: str) -> None:
        await self.db.execute("DELETE FROM audit WHERE ts < ?", (before,))

    async def stats(self) -> dict[str, int]:
        devices_online = await self.db.scalar(
            "SELECT COUNT(*) FROM devices WHERE status = 'online' AND revoked_at IS NULL"
        )
        devices_total = await self.db.scalar(
            "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL"
        )
        active_sessions = await self.db.scalar(
            "SELECT COUNT(*) FROM sessions WHERE state = 'active'"
        )
        pending_sessions = await self.db.scalar(
            "SELECT COUNT(*) FROM sessions WHERE state = 'pending'"
        )
        return {
            "devices_online": int(devices_online or 0),
            "devices_total": int(devices_total or 0),
            "active_sessions": int(active_sessions or 0),
            "pending_sessions": int(pending_sessions or 0),
        }
