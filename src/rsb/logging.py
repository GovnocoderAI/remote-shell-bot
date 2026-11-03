from __future__ import annotations

import logging
import sys

FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

NOISY_LOGGERS = {
    "aiogram.event": logging.WARNING,
    "httpx": logging.WARNING,
    "httpcore": logging.WARNING,
    "uvicorn.access": logging.WARNING,
}


def configure_logging(level: str = "INFO", stream=None) -> None:
    numeric = getattr(logging, level.upper(), logging.INFO)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(logging.Formatter(FORMAT, DATE_FORMAT))
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(numeric)
    root.addHandler(handler)
    for name, logger_level in NOISY_LOGGERS.items():
        logging.getLogger(name).setLevel(logger_level)
