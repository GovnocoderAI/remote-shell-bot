from __future__ import annotations

import sys
from pathlib import Path

from install import write_launcher


def test_launcher_uses_resilient_connect(tmp_path: Path) -> None:
    launcher = write_launcher(tmp_path, Path(sys.executable), tmp_path / "data")
    text = launcher.read_text(encoding="utf-8")
    assert "rsb connect" in text
    assert str(tmp_path / "data") in text
    assert "rsb agent" not in text
