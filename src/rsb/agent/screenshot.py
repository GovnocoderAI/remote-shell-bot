from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

import mss
from PIL import Image

from rsb.errors import ScreenshotError
from rsb.util import now_iso

MAX_DIMENSION = 1600
JPEG_QUALITIES = (80, 70, 60, 50, 40)


@dataclass(slots=True)
class Screenshot:
    image: bytes
    width: int
    height: int
    taken_at: str


def capture_screenshot(max_bytes: int) -> Screenshot:
    try:
        with mss.mss() as capture:
            monitors = capture.monitors
            monitor = monitors[1] if len(monitors) > 1 else monitors[0]
            raw = capture.grab(monitor)
            frame = Image.frombytes("RGB", raw.size, raw.rgb)
    except Exception as exc:
        raise ScreenshotError(f"screen capture failed: {exc}") from exc
    frame.thumbnail((MAX_DIMENSION, MAX_DIMENSION), Image.Resampling.LANCZOS)
    buffer = BytesIO()
    for quality in JPEG_QUALITIES:
        buffer.seek(0)
        buffer.truncate()
        frame.save(buffer, format="JPEG", quality=quality, optimize=True)
        if buffer.tell() <= max_bytes:
            return Screenshot(
                image=buffer.getvalue(),
                width=frame.width,
                height=frame.height,
                taken_at=now_iso(),
            )
    raise ScreenshotError("screenshot exceeds the configured size limit")
