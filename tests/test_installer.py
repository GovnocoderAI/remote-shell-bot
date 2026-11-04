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


def test_ensure_project_source_extracts_archive(tmp_path: Path) -> None:
    import tarfile

    from install import ensure_project_source

    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    archive = tmp_path / "source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(project, arcname="remote-shell-bot")

    extracted = ensure_project_source(tmp_path / "missing", str(archive), tmp_path / "work")
    assert (extracted / "pyproject.toml").exists()


def test_ensure_project_source_reuses_local_tree(tmp_path: Path) -> None:
    from install import ensure_project_source

    project = tmp_path / "project"
    project.mkdir()
    (project / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    assert ensure_project_source(project, "ignored", tmp_path / "work") == project


def test_wsl_relay_rewrite(monkeypatch) -> None:
    import install

    monkeypatch.setattr(install, "_is_wsl", lambda: True)
    monkeypatch.setattr(install, "_default_gateway", lambda: "172.20.160.1")
    monkeypatch.setattr(
        install, "_can_connect", lambda host, port, wait_seconds=2.0: host == "172.20.160.1"
    )
    assert install.normalize_relay_for_wsl("ws://127.0.0.1:30000") == ("ws://172.20.160.1:30000")


def test_non_loopback_relay_is_not_rewritten(monkeypatch) -> None:
    import install

    monkeypatch.setattr(install, "_is_wsl", lambda: True)
    assert install.normalize_relay_for_wsl("wss://support.example.com") == (
        "wss://support.example.com"
    )
