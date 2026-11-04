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
