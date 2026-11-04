from __future__ import annotations

from types import SimpleNamespace

from rsb.server.bot.handlers import build_router


class FakeBot:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str, object]] = []

    async def send_message(self, chat_id: int, text: str, **kwargs) -> None:
        self.sent.append((chat_id, text, kwargs.get("reply_markup")))


class FakeMessage:
    def __init__(self, bot: FakeBot, user: SimpleNamespace, text: str = "") -> None:
        self.bot = bot
        self.from_user = user
        self.text = text
        self.answers: list[tuple[str, object]] = []

    async def answer(self, text: str, **kwargs) -> None:
        self.answers.append((text, kwargs.get("reply_markup")))


class FakeCallback:
    def __init__(self, bot: FakeBot, user: SimpleNamespace, data: str) -> None:
        self.bot = bot
        self.from_user = user
        self.data = data
        self.message = None
        self.answers: list[tuple[str | None, bool]] = []

    async def answer(self, text: str | None = None, show_alert: bool = False) -> None:
        self.answers.append((text, show_alert))


def _handler(router, kind: str, name: str):
    for handler in getattr(router, kind).handlers:
        if handler.callback.__name__ == name:
            return handler.callback
    raise AssertionError(f"handler {name} not found")


async def test_new_user_can_request_access_and_admin_approves(service, settings) -> None:
    router = build_router(service, settings)
    candidate = SimpleNamespace(id=300, username="newbie")
    admin = SimpleNamespace(id=100, username="admin")
    bot = FakeBot()

    start = _handler(router, "message", "cmd_start")
    start_message = FakeMessage(bot, candidate)
    await start(message=start_message)

    welcome = start_message.answers[-1]
    assert "RemoteShellBot" in welcome[0]
    assert "Запросить доступ" in str(welcome[1])
    assert "300" in welcome[0]

    request = _handler(router, "message", "cmd_request")
    message = FakeMessage(bot, candidate)
    await request(message=message)
    assert "Заявка на доступ отправлена" in message.answers[-1][0]
    pending = await service.repo.list_access_requests("pending")
    assert [item["telegram_id"] for item in pending] == [300]
    assert any(chat_id == 100 for chat_id, _, _ in bot.sent)

    pending_start = FakeMessage(bot, candidate)
    await start(message=pending_start)
    assert "ожидает решения" in pending_start.answers[-1][0]

    approve = _handler(router, "callback_query", "cb_access_approve")
    callback = FakeCallback(bot, admin, "access:approve:300")
    await approve(callback=callback)
    assert await service.repo.has_access(300)
    assert any(chat_id == 300 and "Доступ выдан" in text for chat_id, text, _ in bot.sent)
    assert callback.answers

    start_again = FakeMessage(bot, candidate)
    await start(message=start_again)
    assert "Шаг 1" in start_again.answers[-1][0]
    assert "/setup" in start_again.answers[-1][0]


async def test_unapproved_user_gets_request_hint_on_command(service, settings) -> None:
    router = build_router(service, settings)
    candidate = SimpleNamespace(id=301, username="other")
    bot = FakeBot()
    devices = _handler(router, "message", "cmd_devices")
    message = FakeMessage(bot, candidate)
    await devices(message=message)
    assert "Доступ к боту не выдан" in message.answers[-1][0]
    assert "/request" in message.answers[-1][0]


async def test_non_admin_cannot_list_or_approve_requests(service, settings) -> None:
    router = build_router(service, settings)
    candidate = SimpleNamespace(id=302, username="intruder")
    bot = FakeBot()
    requests_cmd = _handler(router, "message", "cmd_requests")
    message = FakeMessage(bot, candidate)
    await requests_cmd(message=message)
    assert "только администратору" in message.answers[-1][0]

    approve = _handler(router, "callback_query", "cb_access_approve")
    callback = FakeCallback(bot, candidate, "access:approve:302")
    await approve(callback=callback)
    assert callback.answers[-1][1] is True
    assert not await service.repo.has_access(302)
