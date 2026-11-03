from __future__ import annotations

import logging

from aiogram import Bot
from aiogram.types import BufferedInputFile

from rsb.server.bot import keyboards, views

log = logging.getLogger("rsb.notifier")


class TelegramNotifier:
    def __init__(self, bot: Bot) -> None:
        self.bot = bot

    async def _send(self, operator_id: int, text: str, markup=None) -> None:
        try:
            await self.bot.send_message(
                operator_id, text, reply_markup=markup, disable_web_page_preview=True
            )
        except Exception:
            log.warning("failed to notify operator %s", operator_id, exc_info=True)

    async def session_active(self, operator_id: int, session: dict, device: dict) -> None:
        text = views.session_activated(session, device, None)
        await self._send(operator_id, text, keyboards.session_controls(session))

    async def session_denied(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        reason: str | None = None,
    ) -> None:
        await self._send(operator_id, views.session_denied(device, reason))

    async def session_closed(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        reason: str | None = None,
    ) -> None:
        await self._send(operator_id, views.session_closed(device, reason))

    async def session_expired(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        reason: str | None = None,
    ) -> None:
        await self._send(operator_id, views.session_expired(device))

    async def session_updated(self, operator_id: int, session: dict, device: dict) -> None:
        await self._send(
            operator_id,
            views.session_updated(device, session),
            keyboards.session_controls(session),
        )

    async def screenshot(
        self,
        operator_id: int,
        session: dict,
        device: dict,
        image: bytes,
        meta: dict,
    ) -> None:
        try:
            await self.bot.send_photo(
                operator_id,
                BufferedInputFile(image, filename="screenshot.jpg"),
                caption=views.screenshot_caption(device, meta),
                reply_markup=keyboards.session_controls(session),
            )
        except Exception:
            log.warning("failed to send screenshot to %s", operator_id, exc_info=True)
