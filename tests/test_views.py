from __future__ import annotations

from rsb.server.bot.views import command_result, escape_clipped


def test_escape_clipped_respects_limit() -> None:
    escaped, clipped = escape_clipped("<" * 5000, 100)
    assert clipped is True
    assert len(escaped) <= 100
    assert escaped.count("&lt;") * 4 == len(escaped)


def test_escape_clipped_keeps_short_text() -> None:
    escaped, clipped = escape_clipped("ok", 100)
    assert escaped == "ok"
    assert clipped is False


def test_command_result_stays_within_telegram_limit() -> None:
    result = command_result(
        {
            "output": "<script>" * 2000,
            "exit_code": 1,
            "cwd": "/home/user",
            "truncated": False,
            "timed_out": False,
        }
    )
    assert len(result) < 4096
    assert "вывод сокращён" in result
    assert "<script>" not in result
    assert "&lt;script&gt;" in result


def test_command_result_handles_empty_output() -> None:
    result = command_result(
        {
            "output": "",
            "exit_code": 0,
            "cwd": "/",
            "truncated": False,
            "timed_out": False,
        }
    )
    assert "Нет вывода" in result
