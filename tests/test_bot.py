from __future__ import annotations

from rsb.server.bot import keyboards, views
from rsb.server.bot.handlers import build_router


def _device() -> dict:
    return {
        "id": "a" * 32,
        "name": "workstation",
        "hostname": "workstation.local",
        "os_name": "Linux",
        "os_version": "6.8",
        "status": "online",
        "capabilities": ["shell", "screenshot"],
        "last_seen_at": "2026-01-01T12:00:00+00:00",
        "auto_approve": 0,
    }


def _session() -> dict:
    return {
        "id": "b" * 32,
        "device_id": "a" * 32,
        "operator_id": 100,
        "state": "active",
        "purpose": "support",
        "capabilities": ["shell", "screenshot"],
        "requested_capabilities": ["shell", "screenshot"],
        "created_at": "2026-01-01T12:00:00+00:00",
        "expires_at": "2026-01-01T12:30:00+00:00",
    }


def _callbacks(markup) -> list[str]:
    values = []
    for row in markup.inline_keyboard:
        for button in row:
            if button.callback_data:
                values.append(button.callback_data)
    return values


def test_callback_data_fits_telegram_limit() -> None:
    device = _device()
    session = _session()
    markups = [
        keyboards.main_menu(),
        keyboards.device_list([device]),
        keyboards.device_menu(device, False),
        keyboards.device_menu(device, True),
        keyboards.capability_menu(device["id"], ["shell", "screenshot"]),
        keyboards.session_controls(session),
        keyboards.revoke_confirm(device["id"]),
        keyboards.pending_controls(session),
    ]
    for markup in markups:
        for data in _callbacks(markup):
            assert len(data.encode("utf-8")) <= 64


def test_views_escape_user_controlled_values() -> None:
    device = _device()
    device["name"] = "<script>alert(1)</script>"
    rendered = views.device_card(device, [], None)
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_reason_labels() -> None:
    assert views.reason_text("policy_changed") == "изменена политика доступа"
    assert views.reason_text("unknown_code") == "unknown_code"
    assert views.reason_text(None) == "закрыто"


async def test_router_builds(service, settings) -> None:
    router = build_router(service, settings)
    assert len(router.message.handlers) >= 10
    assert len(router.callback_query.handlers) >= 5
