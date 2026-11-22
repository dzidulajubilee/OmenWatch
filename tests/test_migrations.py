"""Numbered schema migrations (database/migrations)."""
import sqlite3

import aiosqlite

from omenwatch.database import sqlite as db_module
from omenwatch.database.migrations import migrate, schema_version
from omenwatch.database.migrations.main import STEPS


async def _open(path):
    db = await aiosqlite.connect(path)
    db.row_factory = aiosqlite.Row
    return db


async def test_a_new_database_ends_at_the_latest_version(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "new.db"))
    await db_module.init_db()
    with sqlite3.connect(tmp_path / "new.db") as raw:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == len(STEPS)
        assert raw.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 0


async def test_an_old_database_is_brought_up_to_date_and_keeps_its_data(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as raw:   # a Pantomath 0.4-era database: no version, few columns
        raw.executescript("""
            CREATE TABLE sources (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
                                  category TEXT DEFAULT 'general', color TEXT DEFAULT '#5eead4',
                                  enabled INTEGER DEFAULT 1, interval_seconds INTEGER DEFAULT 300,
                                  last_polled REAL DEFAULT 0, last_error TEXT, created_at REAL);
            CREATE TABLE items (id TEXT PRIMARY KEY, source_id TEXT NOT NULL, title TEXT NOT NULL, link TEXT,
                                summary TEXT, published REAL, fetched_at REAL NOT NULL, guid TEXT NOT NULL,
                                UNIQUE(source_id, guid));
            INSERT INTO sources (id, name, url) VALUES ('s1', 'Old feed', 'http://feeds.example/rss');
            INSERT INTO items (id, source_id, title, fetched_at, guid) VALUES ('i1', 's1', 'Kept', 1, 'g1');
        """)
    monkeypatch.setattr(db_module, "DB_PATH", str(path))
    await db_module.init_db()
    with sqlite3.connect(path) as raw:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == len(STEPS)
        assert raw.execute("SELECT title, content_severity FROM items").fetchone() == ("Kept", "low")
        columns = {r[1] for r in raw.execute("PRAGMA table_info(items)")}
        assert {"severity", "vendors", "watch_hits", "kev_cves", "content_keyword"} <= columns


async def test_steps_run_once(tmp_path):
    calls = []

    async def step_one(db):
        """first"""
        calls.append(1)

    async def step_two(db):
        """second"""
        calls.append(2)

    db = await _open(tmp_path / "x.db")
    try:
        assert await migrate(db, [step_one], "x.db") == 1
        assert await migrate(db, [step_one, step_two], "x.db") == 2
        assert await migrate(db, [step_one, step_two], "x.db") == 2
        assert calls == [1, 2]
        assert await schema_version(db) == 2
    finally:
        await db.close()


async def test_a_backup_from_a_newer_version_is_left_as_it_is(tmp_path):
    ran = []

    async def step(db):
        """only"""
        ran.append(1)

    db = await _open(tmp_path / "newer.db")
    try:
        await db.execute("PRAGMA user_version = 7")
        assert await migrate(db, [step], "newer.db") == 7
        assert ran == []
    finally:
        await db.close()
