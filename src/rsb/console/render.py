from __future__ import annotations

import os
import subprocess
import tempfile
from io import BytesIO
from pathlib import Path

from PIL import Image, UnidentifiedImageError

from rsb.errors import RsbError


class PreviewError(RsbError):
    pass


def preview_ansi(image_bytes: bytes, width: int = 80, max_height: int = 40) -> str:
    try:
        with Image.open(BytesIO(image_bytes)) as source:
            image = source.convert("RGB")
    except (UnidentifiedImageError, OSError) as exc:
        raise PreviewError(f"cannot decode screenshot: {exc}") from exc
    target_width = max(20, min(int(width), 120))
    if image.width > target_width:
        ratio = target_width / image.width
        image = image.resize(
            (target_width, max(2, int(image.height * ratio))),
            Image.Resampling.LANCZOS,
        )
    if image.height > max_height * 2:
        ratio = (max_height * 2) / image.height
        image = image.resize(
            (max(1, int(image.width * ratio)), max_height * 2),
            Image.Resampling.LANCZOS,
        )
    if image.height % 2:
        image = image.resize((image.width, image.height + 1), Image.Resampling.BILINEAR)
    pixels = image.load()
    lines: list[str] = []
    for y in range(0, image.height, 2):
        cells: list[str] = []
        for x in range(image.width):
            top = pixels[x, y]
            bottom = pixels[x, y + 1]
            cells.append(
                f"\x1b[38;2;{top[0]};{top[1]};{top[2]}m"
                f"\x1b[48;2;{bottom[0]};{bottom[1]};{bottom[2]}m▀"
            )
        cells.append("\x1b[0m")
        lines.append("".join(cells))
    return "\n".join(lines)


def save_screenshot(image_bytes: bytes, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(image_bytes)
    return path


def default_screenshot_path() -> Path:
    downloads = Path.home() / "Downloads"
    base = downloads if downloads.exists() else Path.cwd()
    import time

    return base / f"rsb-screen-{time.strftime('%Y%m%d-%H%M%S')}.jpg"


def open_image(path: Path) -> None:
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]
        return
    command = ["open", str(path)] if os.uname().sysname == "Darwin" else ["xdg-open", str(path)]
    subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def open_temporary_screenshot(image_bytes: bytes) -> Path:
    handle, name = tempfile.mkstemp(prefix="rsb-screen-", suffix=".jpg")
    os.close(handle)
    path = Path(name)
    path.write_bytes(image_bytes)
    open_image(path)
    return path
