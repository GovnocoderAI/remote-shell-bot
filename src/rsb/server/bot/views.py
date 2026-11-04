from __future__ import annotations

import html
from typing import Any

from rsb.server import policy
from rsb.util import parse_iso

STATUS_LABELS = {
    "online": "в сети",
    "offline": "не в сети",
    "revoked": "отозвано",
}

REASON_LABELS = {
    "host_denied": "отклонено владельцем",
    "host_cancelled": "отменено владельцем",
    "host_closed": "закрыто владельцем",
    "policy_changed": "изменена политика доступа",
    "operator_closed": "закрыто оператором",
    "device_offline": "устройство отключилось",
    "device_revoked": "устройство отозвано",
    "server_restart": "перезапуск сервера",
    "request_expired": "истёк срок запроса",
    "expired": "истёк срок сессии",
    "account_lost": "учётная запись сессии потеряна",
    "no_capabilities": "не разрешено ни одно право",
    "closed": "закрыто",
}


def reason_text(value: str | None) -> str:
    if not value:
        return REASON_LABELS["closed"]
    return REASON_LABELS.get(value, value)


def h(value: object) -> str:
    return html.escape(str(value if value is not None else "-"))


def when(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return parse_iso(value).astimezone().strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return h(value)


def status(device: dict[str, Any]) -> str:
    return STATUS_LABELS.get(device.get("status", ""), h(device.get("status")))


def main_menu(stats: dict[str, int]) -> str:
    return (
        "<b>RemoteShellBot</b>\n"
        "Удалённая поддержка с подтверждением на стороне хоста.\n\n"
        f"Устройств в сети: {stats['devices_online']} из {stats['devices_total']}\n"
        f"Активных сессий: {stats['active_sessions']}\n"
        f"Ожидают подтверждения: {stats['pending_sessions']}\n\n"
        "Подключение возможно только после подтверждения владельцем машины. "
        "Хост видит все команды и все снимки экрана."
    )


def access_denied() -> str:
    return (
        "Доступ запрещён. Ваш Telegram ID отсутствует в списке операторов.\n"
        "Передайте администратору сервера свой ID."
    )


def new_user_welcome(user_id: int, username: str | None, support_contact: str = "") -> str:
    contact = f"\nСвязь с администратором: {h(support_contact)}" if support_contact else ""
    return (
        "<b>RemoteShellBot</b>\n"
        "Удалённая поддержка компьютеров с подтверждением на стороне хоста.\n\n"
        "<b>Что умеет</b>\n"
        "- удалённый shell с прозрачным журналом команд;\n"
        "- снимок экрана только с разрешения владельца;\n"
        "- локальная панель, где владелец видит подключения и права.\n\n"
        f"Ваш Telegram ID: <code>{user_id}</code>.\n"
        "Доступ выдаётся администратором. Нажмите «Запросить доступ» "
        "или отправьте /request."
        f"{contact}"
    )


def no_access(user_id: int, support_contact: str = "") -> str:
    contact = f"\nСвязь с администратором: {h(support_contact)}" if support_contact else ""
    return (
        "Доступ к боту не выдан.\n"
        f"Ваш Telegram ID: <code>{user_id}</code>.\n"
        "Отправьте /request, чтобы создать заявку на доступ."
        f"{contact}"
    )


def access_request_sent(support_contact: str = "") -> str:
    contact = (
        f"\nЕсли долго нет ответа, свяжитесь с администратором: {h(support_contact)}"
        if support_contact
        else ""
    )
    return (
        "Заявка на доступ отправлена.\n"
        "После одобрения выполните /start и настройте 2FA через /setup."
        f"{contact}"
    )


def admin_access_request(user_id: int, username: str | None) -> str:
    name = f"@{username}" if username else "без username"
    return (
        "<b>Новая заявка на доступ</b>\n"
        f"Пользователь: {h(name)}\n"
        f"Telegram ID: <code>{user_id}</code>"
    )


def access_approved() -> str:
    return (
        "Доступ выдан.\n\n"
        "Шаг 1. Выполните /start.\n"
        "Шаг 2. Настройте 2FA через /setup и подтвердите кодом /verify.\n"
        "Шаг 3. Выполните /enroll и установите агент на нужную машину."
    )


def access_denied_message() -> str:
    return "Заявка на доступ отклонена администратором."


def need_setup() -> str:
    return "Двухфакторная аутентификация не настроена. Выполните /setup."


def need_verify() -> str:
    return "Требуется подтверждение. Отправьте /verify <шестизначный код>."


def device_line(device: dict[str, Any]) -> str:
    os_name = device.get("os_name") or "unknown"
    return (
        f"<b>{h(device['name'])}</b>\n"
        f"{h(os_name)} · {status(device)} · последняя связь {when(device.get('last_seen_at'))}"
    )


def device_list(devices: list[dict[str, Any]]) -> str:
    if not devices:
        return "Нет зарегистрированных устройств. Выполните /enroll."
    lines = [f"<b>Устройства</b> ({len(devices)})\n"]
    for index, device in enumerate(devices, start=1):
        lines.append(
            f"{index}. {h(device['name'])} · {h(device.get('os_name') or 'unknown')} · "
            f"{status(device)}"
        )
    lines.append("\nВыберите устройство для управления.")
    return "\n".join(lines)


def device_card(
    device: dict[str, Any],
    grants: list[tuple[int, str | None, list[str]]],
    open_session: dict[str, Any] | None,
) -> str:
    lines = [
        f"<b>{h(device['name'])}</b>",
        f"ID: <code>{h(device['id'])}</code>",
        f"Хост: {h(device.get('hostname'))}",
        f"Система: {h(device.get('os_name'))} {h(device.get('os_version'))}",
        f"Статус: {status(device)}",
        f"Последняя связь: {when(device.get('last_seen_at'))}",
        f"Разрешённые права: {h(policy.describe(device.get('capabilities', [])))}",
    ]
    if open_session is not None:
        lines.append(
            f"Открытая сессия: {h(open_session['state'])} с {when(open_session.get('created_at'))}"
        )
    if grants:
        lines.append("\n<b>История доступа операторов</b>")
        for operator_id, username, capabilities in grants:
            name = f"@{username}" if username else str(operator_id)
            lines.append(f"{h(name)} · {h(policy.describe(capabilities))}")
    else:
        lines.append("\nИстория доступа пуста.")
    return "\n".join(lines)


def capability_choice(device: dict[str, Any]) -> str:
    lines = [
        f"<b>{h(device['name'])}</b>",
        "Выберите права для запроса. Хост может сократить их при подтверждении.",
        "",
        f"Доступно устройством: {h(policy.describe(device.get('capabilities', [])))}",
    ]
    return "\n".join(lines)


def request_sent(device: dict[str, Any], capabilities: list[str], expires_at: str) -> str:
    return (
        f"Запрос отправлен на <b>{h(device['name'])}</b>.\n"
        f"Запрошенные права: {h(policy.describe(capabilities))}\n"
        f"Ожидание подтверждения до {when(expires_at)}.\n\n"
        "Владелец машины должен подтвердить запрос в локальной панели. "
        "Без подтверждения сессия закроется автоматически."
    )


def session_updated(device: dict[str, Any], session: dict[str, Any]) -> str:
    return (
        "<b>Хост изменил права сессии</b>\n"
        f"Устройство: {h(device['name'])}\n"
        f"Текущие права: {h(policy.describe(session.get('capabilities', [])))}\n\n"
        "Если право на снимок экрана отозвано, кнопка снимка больше не работает."
    )


def session_card(session: dict[str, Any], device: dict[str, Any]) -> str:
    state = session.get("state")
    return (
        f"<b>{h(device['name'])}</b>\n"
        f"Состояние: {h(state)}\n"
        f"Права: {h(policy.describe(session.get('capabilities', [])))}\n"
        f"Начало: {when(session.get('created_at'))}\n"
        f"Действует до: {when(session.get('expires_at'))}\n\n"
        "Отправляйте команды обычными сообщениями. Каждая команда видна владельцу машины."
    )


def session_activated(
    session: dict[str, Any], device: dict[str, Any], operator_username: str | None
) -> str:
    username = f"@{operator_username}" if operator_username else str(session.get("operator_id"))
    return (
        "<b>Подключение подтверждено</b>\n"
        f"Устройство: {h(device['name'])}\n"
        f"Оператор: {h(username)}\n"
        f"Права: {h(policy.describe(session.get('capabilities', [])))}\n"
        f"Действует до: {when(session.get('expires_at'))}\n\n"
        "Отправляйте команды текстом."
    )


def session_pending(session: dict[str, Any], device: dict[str, Any]) -> str:
    return (
        f"Ожидается подтверждение от <b>{h(device['name'])}</b>.\n"
        f"Права: {h(policy.describe(session.get('requested_capabilities', [])))}\n"
        f"Истекает: {when(session.get('expires_at'))}"
    )


def session_denied(device: dict[str, Any], reason: str | None) -> str:
    return (
        f"Хост <b>{h(device['name'])}</b> отклонил подключение.\nПричина: {h(reason_text(reason))}"
    )


def session_closed(device: dict[str, Any], reason: str | None) -> str:
    return f"Сессия с <b>{h(device['name'])}</b> закрыта.\nПричина: {h(reason_text(reason))}"


def session_expired(device: dict[str, Any]) -> str:
    return f"Сессия с <b>{h(device['name'])}</b> истекла."


def escape_clipped(value: str, limit: int = 2500) -> tuple[str, bool]:
    parts: list[str] = []
    total = 0
    for character in value:
        escaped = html.escape(character)
        if total + len(escaped) > limit:
            return "".join(parts), True
        parts.append(escaped)
        total += len(escaped)
    return "".join(parts), False


def command_result(result: dict[str, Any]) -> str:
    parts = [f"<b>Код возврата:</b> {h(result.get('exit_code'))}"]
    if result.get("timed_out"):
        parts.append("<b>Команда прервана по таймауту.</b>")
    if result.get("truncated"):
        parts.append("<b>Вывод усечён на агенте.</b>")
    if result.get("cwd"):
        parts.append(f"<b>Каталог:</b> {h(result['cwd'])}")
    output = str(result.get("output") or "").strip()
    escaped, clipped = escape_clipped(output)
    if clipped:
        parts.append("<b>Вывод усечён при отправке.</b>")
    if escaped:
        suffix = "\n[вывод сокращён]" if clipped else ""
        body = f"<pre>{escaped}{suffix}</pre>"
    else:
        body = "<i>Нет вывода.</i>"
    return "\n".join(parts) + "\n" + body


def command_failed(reason: str) -> str:
    return f"<b>Команда не выполнена.</b>\n{h(reason)}"


def audit_log(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "Журнал аудита пуст."
    lines = ["<b>Журнал аудита</b>"]
    for entry in entries:
        parts = [when(entry.get("ts")), h(entry.get("action"))]
        if entry.get("actor_id"):
            parts.append(f"actor {h(entry['actor_id'])}")
        if entry.get("device_id"):
            parts.append(f"device {h(entry['device_id'])[:8]}")
        lines.append(" · ".join(parts))
    return "\n".join(lines)


def screenshot_caption(device: dict[str, Any], meta: dict[str, Any]) -> str:
    size = ""
    if meta.get("width") and meta.get("height"):
        size = f" · {meta['width']}x{meta['height']}"
    return f"Снимок экрана: {h(device['name'])}{size} · {when(meta.get('taken_at'))}"


def enroll_ready(
    commands: dict[str, str],
    expires_at: str,
    relay_url: str,
    install_url: str = "",
) -> str:
    blocks = "\n\n".join(
        f"<b>{h(platform)}</b>\n<pre>{h(command)}</pre>" for platform, command in commands.items()
    )
    source_note = f"\n\nУстановщик: <code>{h(install_url)}</code>" if install_url else ""
    return (
        "<b>Одноразовый токен установки</b>\n"
        f"Действует до {when(expires_at)}. Используется один раз, "
        "не пересылайте его.\n\n"
        f"{blocks}\n\n"
        f"Relay: <code>{h(relay_url)}</code>"
        f"{source_note}\n\n"
        "После установки владелец машины задаёт пароль хоста и подтверждает "
        "первое подключение в локальной панели."
    )
