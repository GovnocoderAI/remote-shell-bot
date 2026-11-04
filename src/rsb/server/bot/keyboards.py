from __future__ import annotations

from typing import Any

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from rsb.server import policy


def main_menu(include_requests: bool = False) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if include_requests:
        rows.append([InlineKeyboardButton(text="Заявки на доступ", callback_data="requests")])
    rows.extend(
        [
            [
                InlineKeyboardButton(text="Устройства", callback_data="devices"),
                InlineKeyboardButton(text="Моя сессия", callback_data="session"),
            ],
            [InlineKeyboardButton(text="Журнал аудита", callback_data="audit")],
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def new_user() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Запросить доступ", callback_data="access:request")]
        ]
    )


def access_decision(telegram_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Разрешить", callback_data=f"access:approve:{telegram_id}"
                ),
                InlineKeyboardButton(text="Отклонить", callback_data=f"access:deny:{telegram_id}"),
            ]
        ]
    )


def device_list(devices: list[dict[str, Any]]) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text=device["name"][:48], callback_data=f"dev:{device['id']}")]
        for device in devices
    ]
    rows.append([InlineKeyboardButton(text="Назад", callback_data="menu")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def device_menu(device: dict[str, Any], has_open_session: bool) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if device["status"] == "online" and not has_open_session:
        rows.append(
            [InlineKeyboardButton(text="Запросить доступ", callback_data=f"reqmenu:{device['id']}")]
        )
    if has_open_session:
        rows.append([InlineKeyboardButton(text="Открыть сессию", callback_data="session")])
    rows.append(
        [InlineKeyboardButton(text="Отозвать устройство", callback_data=f"rev:{device['id']}")]
    )
    rows.append([InlineKeyboardButton(text="К списку", callback_data="devices")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def capability_menu(device_id: str, capabilities: list[str]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if policy.CAP_SHELL in capabilities:
        rows.append(
            [InlineKeyboardButton(text="Только shell", callback_data=f"req:{device_id}:shell")]
        )
    if policy.CAP_SCREENSHOT in capabilities:
        rows.append(
            [
                InlineKeyboardButton(
                    text="shell и снимок экрана",
                    callback_data=f"req:{device_id}:shell+screenshot",
                )
            ]
        )
    rows.append([InlineKeyboardButton(text="Назад", callback_data=f"dev:{device_id}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def session_controls(session: dict[str, Any]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if policy.CAP_SCREENSHOT in session.get("capabilities", []):
        rows.append(
            [InlineKeyboardButton(text="Снимок экрана", callback_data=f"sess:{session['id']}:shot")]
        )
    rows.append(
        [InlineKeyboardButton(text="Завершить сессию", callback_data=f"sess:{session['id']}:close")]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def revoke_confirm(device_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Подтвердить отзыв", callback_data=f"revok:{device_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"dev:{device_id}")],
        ]
    )


def pending_controls(session: dict[str, Any]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="Отменить запрос", callback_data=f"sess:{session['id']}:close"
                )
            ]
        ]
    )
