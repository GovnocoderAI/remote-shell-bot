from __future__ import annotations

from rsb.db.repository import Repository
from rsb.util import iso_in, new_id

PAST = "2000-01-01T00:00:00+00:00"


async def _create_device(repo: Repository) -> dict:
    return await repo.create_device(
        device_id=new_id(),
        name="workstation",
        hostname="workstation.local",
        os_name="Linux",
        os_version="6.8",
        owner_telegram_id=100,
        secret_encrypted="encrypted-secret",
        capabilities=["shell"],
    )


async def test_operator_lifecycle(repo: Repository) -> None:
    operator = await repo.ensure_operator(100, "admin")
    assert operator["telegram_id"] == 100
    assert operator["username"] == "admin"
    assert operator["is_active"] == 1

    renamed = await repo.ensure_operator(100, "renamed")
    assert renamed["username"] == "renamed"

    await repo.set_operator_totp(100, "encrypted")
    await repo.confirm_operator_totp(100)
    await repo.set_operator_auth(100, iso_in(600))
    current = await repo.get_operator(100)
    assert current is not None
    assert current["totp_secret"] == "encrypted"
    assert current["totp_confirmed_at"]
    assert current["auth_expires_at"]

    await repo.clear_operator_auth(100)
    cleared = await repo.get_operator(100)
    assert cleared is not None
    assert cleared["auth_expires_at"] is None

    await repo.set_operator_active(100, False)
    disabled = await repo.get_operator(100)
    assert disabled is not None
    assert disabled["is_active"] == 0


async def test_enrollment_is_single_use(repo: Repository) -> None:
    await repo.issue_enrollment("hash", 100, "office", iso_in(300))
    first = await repo.consume_enrollment("hash")
    assert first is not None
    assert first["created_by"] == 100
    assert await repo.consume_enrollment("hash") is None


async def test_expired_enrollment_is_rejected(repo: Repository) -> None:
    await repo.issue_enrollment("hash", 100, "office", PAST)
    assert await repo.consume_enrollment("hash") is None


async def test_device_and_session_lifecycle(repo: Repository) -> None:
    device = await _create_device(repo)
    assert device["status"] == "offline"
    assert device["capabilities"] == ["shell"]

    await repo.set_device_capabilities(device["id"], ["shell", "screenshot"])
    updated = await repo.get_device(device["id"])
    assert updated is not None
    assert updated["capabilities"] == ["shell", "screenshot"]

    session = await repo.create_session(
        session_id=new_id(),
        device_id=device["id"],
        operator_id=100,
        purpose="support",
        requested_capabilities=["shell"],
        expires_at=iso_in(300),
    )
    assert session["state"] == "pending"
    assert await repo.get_open_session_for_device(device["id"]) is not None

    account_id = new_id()
    activated = await repo.activate_session(
        session_id=session["id"],
        capabilities=["shell"],
        expires_at=iso_in(1800),
        account_id=account_id,
        username="rsb-test",
        token_hash="token-hash",
    )
    assert activated
    active = await repo.get_session(session["id"])
    assert active is not None
    assert active["state"] == "active"
    assert active["capabilities"] == ["shell"]

    account = await repo.get_active_account(session["id"])
    assert account is not None
    assert account["username"] == "rsb-test"

    duplicate = await repo.activate_session(
        session_id=session["id"],
        capabilities=["shell"],
        expires_at=iso_in(1800),
        account_id=new_id(),
        username="rsb-other",
        token_hash="other-hash",
    )
    assert not duplicate

    await repo.close_session(session["id"])
    await repo.revoke_accounts(session["id"])
    closed = await repo.get_session(session["id"])
    assert closed is not None
    assert closed["state"] == "closed"
    assert await repo.get_active_account(session["id"]) is None


async def test_grants_and_audit(repo: Repository) -> None:
    device = await _create_device(repo)
    await repo.upsert_grant(device["id"], 100, ["shell"])
    await repo.upsert_grant(device["id"], 100, ["shell", "screenshot"])
    grant = await repo.get_grant(device["id"], 100)
    assert grant is not None
    assert grant["capabilities"] == ["shell", "screenshot"]
    assert len(await repo.list_grants(device["id"])) == 1

    await repo.delete_grant(device["id"], 100)
    assert await repo.get_grant(device["id"], 100) is None

    await repo.add_audit("test.event", actor_type="operator", actor_id=100, detail={"a": 1})
    entries = await repo.list_audit(5)
    assert entries[0]["action"] == "test.event"
    assert entries[0]["detail"] == {"a": 1}

    await repo.revoke_device(device["id"])
    revoked = await repo.get_device(device["id"])
    assert revoked is not None
    assert revoked["revoked_at"] is not None
    assert await repo.list_devices() == []


async def test_stats(repo: Repository) -> None:
    device = await _create_device(repo)
    await repo.set_device_status(device["id"], "online")
    stats = await repo.stats()
    assert stats["devices_total"] == 1
    assert stats["devices_online"] == 1
    assert stats["active_sessions"] == 0
