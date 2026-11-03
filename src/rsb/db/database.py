from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from rsb.util import ensure_private_file

SCHEMA_VERSION = 1


class Database:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def connection(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database is not open")
        return self._conn

    async def open(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA synchronous=NORMAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        await conn.execute("PRAGMA busy_timeout=5000")
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        await conn.executescript(schema)
        await conn.execute(
            "INSERT INTO schema_meta(version) SELECT ? "
            "WHERE NOT EXISTS (SELECT 1 FROM schema_meta)",
            (SCHEMA_VERSION,),
        )
        await conn.commit()
        self._conn = conn
        ensure_private_file(self.path)

    async def close(self) -> None:
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            await self.connection.commit()
            return int(cursor.lastrowid or 0)

    async def executemany(self, sql: str, params: Sequence[Sequence[Any]]) -> None:
        async with self._lock:
            await self.connection.executemany(sql, params)
            await self.connection.commit()

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> aiosqlite.Row | None:
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            row = await cursor.fetchone()
            await cursor.close()
            return row

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[aiosqlite.Row]:
        async with self._lock:
            cursor = await self.connection.execute(sql, params)
            rows = await cursor.fetchall()
            await cursor.close()
            return list(rows)

    async def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = await self.fetchone(sql, params)
        return None if row is None else row[0]

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._lock:
            conn = self.connection
            try:
                yield conn
                await conn.commit()
            except BaseException:
                await conn.rollback()
                raise
