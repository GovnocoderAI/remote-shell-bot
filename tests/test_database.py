from __future__ import annotations

import pytest

from rsb.db.database import SCHEMA_VERSION, Database
from rsb.errors import ConfigError


async def test_fresh_database_has_current_version(tmp_path) -> None:
    database = Database(tmp_path / "test.sqlite3")
    await database.open()
    try:
        row = await database.fetchone("SELECT version FROM schema_meta")
        assert row is not None
        assert row[0] == SCHEMA_VERSION
    finally:
        await database.close()


async def test_schema_version_mismatch_is_rejected(tmp_path) -> None:
    path = tmp_path / "test.sqlite3"
    database = Database(path)
    await database.open()
    await database.execute("UPDATE schema_meta SET version = ?", (SCHEMA_VERSION + 1,))
    await database.close()

    reopened = Database(path)
    with pytest.raises(ConfigError):
        await reopened.open()
    assert reopened._conn is None
