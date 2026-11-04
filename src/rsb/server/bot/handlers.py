from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from io import BytesIO
from typing import Any

import qrcode
from aiogram import F, Router
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import BufferedInputFile, CallbackQuery, Message, User

from rsb.config import Settings
from rsb.errors import AuthenticationError, RsbError
from rsb.security import totp_new_secret, totp_uri, totp_verify
from rsb.server import policy
from rsb.server.bot import keyboards, views
from rsb.server.service import Service
from rsb.util import iso_in, parse_iso, sanitize_filename, utcnow

log = logging.getLogger("rsb.bot")


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[int, deque[float]] = defaultdict(deque)

    def allow(self, key: int) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    def reset(self, key: int) -> None:
        self._hits.pop(key, None)


def _auth_problem(operator: dict[str, Any]) -> str | None:
    if not operator["totp_secret"]:
        return views.need_setup()
    if not operator["totp_confirmed_at"]:
        return "Подтвердите настройку: отправьте /verify <код>."
    expires_at = operator["auth_expires_at"]
    if not expires_at or parse_iso(expires_at) <= utcnow():
        return views.need_verify()
    return None


async def _resolve_operator(
    service: Service, settings: Settings, user: User | None
) -> tuple[dict[str, Any] | None, str | None]:
    if user is None:
        return None, views.access_denied()
    is_admin = user.id in settings.admin_ids_set
    if not is_admin and not await service.repo.has_access(user.id):
        return None, views.no_access(user.id, settings.support_contact)
    operator = await service.repo.ensure_operator(user.id, user.username)
    if not operator["is_active"]:
        return None, "Учётная запись оператора отключена."
    return operator, None


def _is_env_admin(settings: Settings, user: User | None) -> bool:
    return user is not None and user.id in settings.admin_ids_set


def _qr_png(payload: str) -> bytes:
    code = qrcode.QRCode(box_size=8, border=2)
    code.add_data(payload)
    code.make(fit=True)
    image = code.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def build_router(service: Service, settings: Settings) -> Router:
    router = Router(name="operator")
    attempts = SlidingWindow(5, 300)
    command_limiter = SlidingWindow(20, 60)
    request_limiter = SlidingWindow(5, 60)
    access_limiter = SlidingWindow(3, 300)

    async def _edit(callback: CallbackQuery, text: str, markup=None) -> None:
        message = callback.message
        if isinstance(message, Message):
            try:
                await message.edit_text(text, reply_markup=markup, disable_web_page_preview=True)
                return
            except Exception:
                pass
        if callback.from_user is not None:
            try:
                await callback.bot.send_message(
                    callback.from_user.id,
                    text,
                    reply_markup=markup,
                    disable_web_page_preview=True,
                )
            except Exception:
                log.warning("failed to deliver message", exc_info=True)

    async def _authorize_callback(callback: CallbackQuery) -> dict[str, Any] | None:
        operator, problem = await _resolve_operator(service, settings, callback.from_user)
        if operator is None:
            await callback.answer(problem or "Доступ запрещён", show_alert=True)
            return None
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await callback.answer(auth_problem[:190], show_alert=True)
            return None
        return operator

    async def _notify_admins(bot, request: dict) -> None:
        if not settings.admin_ids_set:
            log.warning("access request received but RSB_ADMIN_IDS is empty")
            return
        text = views.admin_access_request(request["telegram_id"], request.get("username"))
        markup = keyboards.access_decision(request["telegram_id"])
        for admin_id in settings.admin_ids_set:
            try:
                await bot.send_message(admin_id, text, reply_markup=markup)
            except Exception:
                log.warning("failed to notify admin %s", admin_id, exc_info=True)

    async def _render_device(device_id: str) -> tuple[str, Any] | None:
        device = await service.repo.get_device(device_id)
        if device is None:
            return None
        grants = await service.repo.list_grants(device_id)
        grant_rows: list[tuple[int, str | None, list[str]]] = []
        for grant in grants:
            operator = await service.repo.get_operator(grant["operator_id"])
            grant_rows.append(
                (
                    grant["operator_id"],
                    operator["username"] if operator else None,
                    grant["capabilities"],
                )
            )
        open_session = await service.repo.get_open_session_for_device(device_id)
        text = views.device_card(device, grant_rows, open_session)
        markup = keyboards.device_menu(device, open_session is not None)
        return text, markup

    async def _render_session(operator_id: int) -> tuple[str, Any]:
        session = await service.repo.get_open_session_for_operator(operator_id)
        if session is None:
            return "Активной сессии нет. Откройте устройство через /devices.", None
        device = await service.repo.get_device(session["device_id"])
        if device is None:
            return "Устройство сессии не найдено.", None
        if session["state"] == policy.STATE_PENDING:
            return views.session_pending(session, device), keyboards.pending_controls(session)
        return views.session_card(session, device), keyboards.session_controls(session)

    @router.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        user = message.from_user
        if user is None:
            return
        is_admin = user.id in settings.admin_ids_set
        approved = is_admin or await service.repo.has_access(user.id)
        if not approved:
            request = await service.repo.get_access_request(user.id)
            if request is not None and request["status"] == "pending":
                await message.answer(
                    views.access_pending(user.id, settings.support_contact),
                    reply_markup=keyboards.access_pending(),
                )
            else:
                await message.answer(
                    views.new_user_welcome(user.id, user.username, settings.support_contact),
                    reply_markup=keyboards.new_user(),
                )
            return
        operator = await service.repo.ensure_operator(user.id, user.username)
        if not operator["is_active"]:
            await message.answer("Учётная запись оператора отключена.")
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(
                "Доступ есть.\n\n"
                "Шаг 1. /setup — подключите 2FA.\n"
                "Шаг 2. /verify &lt;код&gt; — подтвердите вход.\n"
                "Шаг 3. /enroll — установите агент на машину.\n\n"
                f"{auth_problem}"
            )
            return
        stats = await service.repo.stats()
        await message.answer(
            views.main_menu(stats),
            reply_markup=keyboards.main_menu(include_requests=is_admin),
        )

    @router.message(Command("help"))
    async def cmd_help(message: Message) -> None:
        await message.answer(
            "<b>RemoteShellBot</b>\n"
            "Удалённая поддержка с подтверждением на хосте.\n\n"
            "<b>Команды</b>\n"
            "/start — состояние и меню\n"
            "/request — запросить доступ\n"
            "/setup — настройка 2FA\n"
            "/verify &lt;код&gt; — подтверждение входа\n"
            "/devices — список устройств\n"
            "/sessions — текущая сессия\n"
            "/screen — снимок экрана\n"
            "/enroll — установка агента на машину\n"
            "/audit — последние события\n"
            "/revoke &lt;id&gt; — отзыв устройства\n"
            "/logout — сброс авторизации\n"
            "/requests — заявки на доступ (администратор)\n\n"
            "Любое текстовое сообщение при активной сессии выполняется как команда."
        )

    @router.message(Command("request"))
    async def cmd_request(message: Message) -> None:
        user = message.from_user
        if user is None:
            return
        if user.id in settings.admin_ids_set or await service.repo.has_access(user.id):
            await message.answer("Доступ уже есть. Выполните /start.")
            return
        existing = await service.repo.get_access_request(user.id)
        if existing is not None and existing["status"] == "pending":
            await message.answer(views.access_pending(user.id, settings.support_contact))
            return
        if not access_limiter.allow(user.id):
            await message.answer("Заявка уже отправлена недавно. Подождите несколько минут.")
            return
        request = await service.repo.upsert_access_request(user.id, user.username)
        await service.repo.add_audit(
            "access.requested",
            actor_type="user",
            actor_id=user.id,
            detail={"username": user.username},
        )
        await _notify_admins(message.bot, request)
        await message.answer(views.access_request_sent(settings.support_contact))

    @router.message(Command("requests"))
    async def cmd_requests(message: Message) -> None:
        if not _is_env_admin(settings, message.from_user):
            await message.answer("Список заявок доступен только администратору.")
            return
        pending = await service.repo.list_access_requests("pending")
        if not pending:
            await message.answer("Новых заявок нет.")
            return
        await message.answer(f"Заявок на доступ: {len(pending)}")
        for request in pending[:20]:
            await message.answer(
                views.admin_access_request(request["telegram_id"], request.get("username")),
                reply_markup=keyboards.access_decision(request["telegram_id"]),
            )

    @router.message(Command("setup"))
    async def cmd_setup(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        if operator["totp_confirmed_at"]:
            await message.answer(
                "Двухфакторная аутентификация уже настроена. "
                "Перевыпуск выполняет администратор сервера."
            )
            return
        secret = totp_new_secret()
        await service.repo.set_operator_totp(operator["telegram_id"], service.box.encrypt(secret))
        uri = totp_uri(secret, f"operator-{operator['telegram_id']}")
        await message.answer_photo(
            BufferedInputFile(_qr_png(uri), filename="totp.png"),
            caption=(
                "Отсканируйте QR-код в приложении-аутентификаторе.\n"
                "После добавления отправьте /verify с текущим шестизначным кодом."
            ),
        )
        await message.answer(f"Секрет: <code>{secret}</code>\n\nURI: <code>{uri}</code>")

    @router.message(Command("verify"))
    async def cmd_verify(message: Message, command: CommandObject) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        if not operator["totp_secret"]:
            await message.answer(views.need_setup())
            return
        if not attempts.allow(operator["telegram_id"]):
            await message.answer("Слишком много попыток. Повторите через несколько минут.")
            return
        code = (command.args or "").strip()
        try:
            secret = service.box.decrypt(operator["totp_secret"])
        except AuthenticationError:
            await message.answer("Секрет 2FA повреждён. Обратитесь к администратору сервера.")
            return
        if not totp_verify(secret, code):
            await message.answer("Неверный код.")
            return
        attempts.reset(operator["telegram_id"])
        await service.repo.confirm_operator_totp(operator["telegram_id"])
        await service.repo.set_operator_auth(
            operator["telegram_id"],
            iso_in(settings.operator_auth_ttl_seconds),
        )
        stats = await service.repo.stats()
        await message.answer(
            "Подтверждено.\n\n" + views.main_menu(stats),
            reply_markup=keyboards.main_menu(
                include_requests=_is_env_admin(settings, message.from_user)
            ),
            disable_web_page_preview=True,
        )

    @router.message(Command("logout"))
    async def cmd_logout(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        await service.repo.clear_operator_auth(operator["telegram_id"])
        await message.answer("Авторизация сброшена. Для входа отправьте /verify <код>.")

    @router.message(Command("devices"))
    async def cmd_devices(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        devices = await service.repo.list_devices()
        markup = keyboards.device_list(devices) if devices else None
        await message.answer(views.device_list(devices), reply_markup=markup)

    @router.message(Command("sessions"))
    async def cmd_sessions(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        text, markup = await _render_session(operator["telegram_id"])
        await message.answer(text, reply_markup=markup)

    @router.message(Command("enroll"))
    async def cmd_enroll(message: Message, command: CommandObject) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        label = sanitize_filename((command.args or "").strip() or "device")
        token, expires_at = await service.issue_enrollment(operator["telegram_id"], label)
        source_arg = (
            f"--source {settings.install_source_url} "
            if settings.install_source_url.strip()
            else ""
        )
        arguments = f"{source_arg}--relay {settings.public_url} --token {token} --name {label}"
        if settings.install_url.strip():
            windows_command = (
                "powershell -NoProfile -Command "
                f'"iwr {settings.install_url} -OutFile install.py; '
                f'python install.py {arguments}"'
            )
            unix_command = (
                f"curl -fsSL {settings.install_url} -o install.py && python3 install.py {arguments}"
            )
        else:
            windows_command = f"python install.py {arguments}"
            unix_command = f"python3 install.py {arguments}"
        await message.answer(
            views.enroll_ready(
                {
                    "Windows (PowerShell)": windows_command,
                    "Linux/macOS": unix_command,
                },
                expires_at,
                settings.public_url,
                settings.install_url,
            )
        )

    @router.message(Command("screen"))
    async def cmd_screen(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        session = await service.repo.get_open_session_for_operator(operator["telegram_id"])
        if session is None or session["state"] != policy.STATE_ACTIVE:
            await message.answer("Нет активной сессии.")
            return
        if policy.CAP_SCREENSHOT not in session["capabilities"]:
            await message.answer("Хост не выдал право на снимок экрана.")
            return
        status = await message.answer("<i>Снимаю экран...</i>")
        try:
            await service.capture_screenshot(session["id"], operator["telegram_id"])
        except RsbError as exc:
            await status.edit_text(views.command_failed(str(exc)))
            return
        await status.edit_text("Снимок отправлен.")

    @router.message(Command("audit"))
    async def cmd_audit(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        entries = await service.repo.list_audit(15)
        await message.answer(views.audit_log(entries))

    @router.message(Command("revoke"))
    async def cmd_revoke(message: Message, command: CommandObject) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        device_id = (command.args or "").strip()
        if not device_id:
            await message.answer("Укажите идентификатор: /revoke <id>")
            return
        try:
            await service.revoke_device(
                device_id, actor_type="operator", actor_id=operator["telegram_id"]
            )
        except RsbError as exc:
            await message.answer(f"Не удалось отозвать устройство: {views.h(exc)}")
            return
        await message.answer("Устройство отозвано.")

    @router.message(Command("menu"))
    async def cmd_menu(message: Message) -> None:
        await cmd_start(message)

    @router.callback_query(F.data == "access:request")
    async def cb_access_request(callback: CallbackQuery) -> None:
        user = callback.from_user
        if user is None:
            return
        if user.id in settings.admin_ids_set or await service.repo.has_access(user.id):
            await callback.answer("Доступ уже есть. Выполните /start.", show_alert=True)
            return
        existing = await service.repo.get_access_request(user.id)
        if existing is not None and existing["status"] == "pending":
            await callback.answer("Заявка уже ожидает решения.", show_alert=True)
            return
        if not access_limiter.allow(user.id):
            await callback.answer("Заявка уже отправлена недавно.", show_alert=True)
            return
        request = await service.repo.upsert_access_request(user.id, user.username)
        await service.repo.add_audit(
            "access.requested",
            actor_type="user",
            actor_id=user.id,
            detail={"username": user.username},
        )
        await _notify_admins(callback.bot, request)
        await callback.answer("Заявка отправлена")
        await _edit(callback, views.access_request_sent(settings.support_contact))

    @router.callback_query(F.data == "access:status")
    async def cb_access_status(callback: CallbackQuery) -> None:
        user = callback.from_user
        if user is None:
            return
        if user.id in settings.admin_ids_set or await service.repo.has_access(user.id):
            await callback.answer("Доступ уже есть. Выполните /start.", show_alert=True)
            return
        request = await service.repo.get_access_request(user.id)
        if request is None:
            await callback.answer("Заявки нет. Отправьте /request.", show_alert=True)
        elif request["status"] == "pending":
            await callback.answer("Заявка ожидает решения администратора.", show_alert=True)
        elif request["status"] == "denied":
            await callback.answer(
                "Заявка отклонена. Можно отправить новую через /request.",
                show_alert=True,
            )
        else:
            await callback.answer("Доступ выдан. Выполните /start.", show_alert=True)

    @router.callback_query(F.data == "requests")
    async def cb_requests(callback: CallbackQuery) -> None:
        if not _is_env_admin(settings, callback.from_user):
            await callback.answer("Только администратор.", show_alert=True)
            return
        pending = await service.repo.list_access_requests("pending")
        if not pending:
            await _edit(callback, "Новых заявок нет.", keyboards.main_menu(True))
            await callback.answer()
            return
        await _edit(
            callback,
            f"Заявок на доступ: {len(pending)}. Карточки отправлены отдельно.",
            keyboards.main_menu(True),
        )
        if callback.from_user is not None:
            for request in pending[:20]:
                await callback.bot.send_message(
                    callback.from_user.id,
                    views.admin_access_request(request["telegram_id"], request.get("username")),
                    reply_markup=keyboards.access_decision(request["telegram_id"]),
                )
        await callback.answer()

    @router.callback_query(F.data.startswith("access:approve:"))
    async def cb_access_approve(callback: CallbackQuery) -> None:
        if not _is_env_admin(settings, callback.from_user):
            await callback.answer("Только администратор.", show_alert=True)
            return
        try:
            target = int(callback.data.split(":")[2])
        except (IndexError, ValueError):
            await callback.answer("Некорректная заявка.", show_alert=True)
            return
        request = await service.repo.get_access_request(target)
        username = request["username"] if request else None
        admin_id = callback.from_user.id if callback.from_user else None
        await service.repo.set_access_status(target, "approved", decided_by=admin_id)
        operator = await service.repo.ensure_operator(target, username)
        if not operator["is_active"]:
            await service.repo.set_operator_active(target, True)
        await service.repo.add_audit(
            "access.approved",
            actor_type="operator",
            actor_id=admin_id,
            detail={"telegram_id": target, "username": username},
        )
        try:
            await callback.bot.send_message(target, views.access_approved())
        except Exception:
            log.warning("failed to notify approved user %s", target, exc_info=True)
        await _edit(callback, f"Доступ выдан: <code>{target}</code>.")
        await callback.answer("Доступ выдан")

    @router.callback_query(F.data.startswith("access:deny:"))
    async def cb_access_deny(callback: CallbackQuery) -> None:
        if not _is_env_admin(settings, callback.from_user):
            await callback.answer("Только администратор.", show_alert=True)
            return
        try:
            target = int(callback.data.split(":")[2])
        except (IndexError, ValueError):
            await callback.answer("Некорректная заявка.", show_alert=True)
            return
        admin_id = callback.from_user.id if callback.from_user else None
        await service.repo.set_access_status(target, "denied", decided_by=admin_id)
        await service.repo.add_audit(
            "access.denied",
            actor_type="operator",
            actor_id=admin_id,
            detail={"telegram_id": target},
        )
        try:
            await callback.bot.send_message(target, views.access_denied_message())
        except Exception:
            log.warning("failed to notify denied user %s", target, exc_info=True)
        await _edit(callback, f"Заявка отклонена: <code>{target}</code>.")
        await callback.answer("Заявка отклонена")

    @router.callback_query(F.data == "menu")
    async def cb_menu(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        stats = await service.repo.stats()
        await _edit(
            callback,
            views.main_menu(stats),
            keyboards.main_menu(include_requests=_is_env_admin(settings, callback.from_user)),
        )
        await callback.answer()

    @router.callback_query(F.data == "devices")
    async def cb_devices(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        devices = await service.repo.list_devices()
        markup = keyboards.device_list(devices) if devices else keyboards.main_menu()
        await _edit(callback, views.device_list(devices), markup)
        await callback.answer()

    @router.callback_query(F.data == "session")
    async def cb_session(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        text, markup = await _render_session(operator["telegram_id"])
        await _edit(callback, text, markup)
        await callback.answer()

    @router.callback_query(F.data == "audit")
    async def cb_audit(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        entries = await service.repo.list_audit(15)
        await _edit(callback, views.audit_log(entries))
        await callback.answer()

    @router.callback_query(F.data.startswith("dev:"))
    async def cb_device(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        device_id = callback.data.split(":", 1)[1]
        rendered = await _render_device(device_id)
        if rendered is None:
            await callback.answer("Устройство не найдено.", show_alert=True)
            return
        text, markup = rendered
        await _edit(callback, text, markup)
        await callback.answer()

    @router.callback_query(F.data.startswith("reqmenu:"))
    async def cb_request_menu(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        device_id = callback.data.split(":", 1)[1]
        device = await service.repo.get_device(device_id)
        if device is None:
            await callback.answer("Устройство не найдено.", show_alert=True)
            return
        if device["status"] != "online":
            await callback.answer("Устройство не в сети.", show_alert=True)
            return
        capabilities = device["capabilities"]
        if not capabilities:
            await callback.answer("Хост запретил удалённый доступ.", show_alert=True)
            return
        await _edit(
            callback,
            views.capability_choice(device),
            keyboards.capability_menu(device_id, capabilities),
        )
        await callback.answer()

    @router.callback_query(F.data.startswith("req:"))
    async def cb_request(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        parts = callback.data.split(":", 2)
        if len(parts) != 3:
            await callback.answer("Некорректный запрос.", show_alert=True)
            return
        device_id, capabilities_raw = parts[1], parts[2]
        if not request_limiter.allow(operator["telegram_id"]):
            await callback.answer("Слишком много запросов. Подождите минуту.", show_alert=True)
            return
        try:
            capabilities = policy.require_valid(capabilities_raw.split("+"))
            session = await service.request_session(
                operator["telegram_id"], device_id, "support", capabilities
            )
            device = await service.repo.get_device(device_id)
        except RsbError as exc:
            await callback.answer(str(exc)[:190], show_alert=True)
            return
        if device is None:
            await callback.answer("Устройство не найдено.", show_alert=True)
            return
        await _edit(
            callback,
            views.request_sent(device, capabilities, session["expires_at"]),
            keyboards.pending_controls(session),
        )
        await callback.answer("Запрос отправлен")

    @router.callback_query(F.data.startswith("rev:"))
    async def cb_revoke_confirm(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        device_id = callback.data.split(":", 1)[1]
        device = await service.repo.get_device(device_id)
        if device is None:
            await callback.answer("Устройство не найдено.", show_alert=True)
            return
        await _edit(
            callback,
            f"Отозвать <b>{views.h(device['name'])}</b>?\n"
            "Соединение будет закрыто, повторный вход потребует нового enrollment.",
            keyboards.revoke_confirm(device_id),
        )
        await callback.answer()

    @router.callback_query(F.data.startswith("revok:"))
    async def cb_revoke(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        device_id = callback.data.split(":", 1)[1]
        try:
            await service.revoke_device(
                device_id, actor_type="operator", actor_id=operator["telegram_id"]
            )
        except RsbError as exc:
            await callback.answer(str(exc)[:190], show_alert=True)
            return
        await _edit(callback, "Устройство отозвано.")
        await callback.answer()

    @router.callback_query(F.data.startswith("sess:"))
    async def cb_session_action(callback: CallbackQuery) -> None:
        operator = await _authorize_callback(callback)
        if operator is None:
            return
        parts = callback.data.split(":", 2)
        if len(parts) != 3:
            await callback.answer("Некорректное действие.", show_alert=True)
            return
        session_id, action = parts[1], parts[2]
        if action == "close":
            try:
                await service.close_session(
                    session_id,
                    actor_type="operator",
                    actor_id=operator["telegram_id"],
                    reason="operator_closed",
                    operator_id=operator["telegram_id"],
                )
            except RsbError as exc:
                await callback.answer(str(exc)[:190], show_alert=True)
                return
            await _edit(callback, "Сессия закрыта.")
            await callback.answer("Сессия закрыта")
            return
        if action == "shot":
            try:
                await service.capture_screenshot(session_id, operator["telegram_id"])
            except RsbError as exc:
                await callback.answer(str(exc)[:190], show_alert=True)
                return
            await callback.answer("Снимок отправлен")
            return
        await callback.answer("Неизвестное действие.", show_alert=True)

    @router.message(F.text.startswith("/"))
    async def unknown_command(message: Message) -> None:
        await message.answer("Неизвестная команда. Список команд: /help")

    @router.message(F.text & ~F.text.startswith("/"))
    async def on_text(message: Message) -> None:
        operator, problem = await _resolve_operator(service, settings, message.from_user)
        if operator is None:
            await message.answer(problem or views.access_denied())
            return
        auth_problem = _auth_problem(operator)
        if auth_problem:
            await message.answer(auth_problem)
            return
        session = await service.repo.get_open_session_for_operator(operator["telegram_id"])
        if session is None:
            await message.answer("Активной сессии нет. Откройте устройство через /devices.")
            return
        if session["state"] != policy.STATE_ACTIVE:
            await message.answer("Сессия ожидает подтверждения владельца машины.")
            return
        command = (message.text or "").strip()
        if not command:
            return
        if len(command) > 4000:
            await message.answer("Команда слишком длинная. Сократите до 4000 символов.")
            return
        if not command_limiter.allow(operator["telegram_id"]):
            await message.answer("Слишком много команд. Подождите минуту.")
            return
        status = await message.answer("<i>Выполняется...</i>")
        try:
            result = await service.execute_command(session["id"], operator["telegram_id"], command)
        except RsbError as exc:
            await status.edit_text(views.command_failed(str(exc)))
            return
        except Exception:
            log.exception("command execution failed")
            await status.edit_text(views.command_failed("Внутренняя ошибка сервера."))
            return
        try:
            await status.edit_text(views.command_result(result), disable_web_page_preview=True)
        except Exception:
            log.warning("failed to render command result", exc_info=True)
            await status.edit_text("Команда выполнена, вывод не удалось отобразить.")

    return router
