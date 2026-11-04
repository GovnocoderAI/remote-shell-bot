from __future__ import annotations

from io import BytesIO

from PIL import Image

from rsb.console.render import default_screenshot_path, preview_ansi, save_screenshot


def test_preview_ansi_returns_truecolor_blocks() -> None:
    image = Image.new("RGB", (8, 8), (10, 120, 220))
    buffer = BytesIO()
    image.save(buffer, format="JPEG")
    preview = preview_ansi(buffer.getvalue(), width=20, max_height=10)
    assert "\x1b[38;2;" in preview
    assert "\x1b[48;2;" in preview
    assert "▀" in preview
    assert preview.count("\n") >= 1


def test_save_screenshot(tmp_path) -> None:
    image = Image.new("RGB", (4, 4), (1, 2, 3))
    buffer = BytesIO()
    image.save(buffer, format="JPEG")
    path = save_screenshot(buffer.getvalue(), tmp_path / "shot.jpg")
    assert path.read_bytes() == buffer.getvalue()
    assert default_screenshot_path().suffix == ".jpg"
