from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from rsb.config import Settings
from rsb.db.database import Database
from rsb.db.repository import Repository
from rsb.server.service import Service


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "test.sqlite3",
        secret_key="test-secret-key-material-0123456789",
        admin_ids="100,200",
        public_url="ws://127.0.0.1:8080",
        bot_token="123456:test-token",
    )


@pytest_asyncio.fixture
async def database(settings: Settings) -> AsyncIterator[Database]:
    settings.ensure_dirs()
    db = Database(settings.db_path)
    await db.open()
    yield db
    await db.close()


@pytest_asyncio.fixture
async def repo(database: Database) -> Repository:
    return Repository(database)


@pytest_asyncio.fixture
async def service(database: Database, settings: Settings) -> Service:
    return Service(database, settings)
