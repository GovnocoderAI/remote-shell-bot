from __future__ import annotations

import asyncio

from rsb.server.app import _run_bot


class FlakyDispatcher:
    def __init__(self, failures: int = 1) -> None:
        self.failures = failures
        self.calls = 0

    async def start_polling(self, bot, **kwargs) -> None:
        self.calls += 1
        if self.calls <= self.failures:
            raise RuntimeError("temporary telegram outage")
        return


async def test_polling_supervisor_retries_after_failure() -> None:
    dispatcher = FlakyDispatcher(failures=2)
    await asyncio.wait_for(
        _run_bot(dispatcher, None, asyncio.Event(), retry_delay=0.01),  # type: ignore[arg-type]
        timeout=2,
    )
    assert dispatcher.calls == 3


async def test_polling_supervisor_stops_with_event() -> None:
    dispatcher = FlakyDispatcher(failures=100)
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(
        _run_bot(dispatcher, None, stop, retry_delay=0.01),  # type: ignore[arg-type]
        timeout=2,
    )
    assert dispatcher.calls == 0
