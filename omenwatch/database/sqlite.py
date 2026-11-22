import json
import os
import uuid

import aiosqlite

from omenwatch.core import config

# From omenwatch.core.config; module names so tests and the CLI can point them elsewhere.
DB_PATH = config.DB_PATH
CONFIG_PATH = config.FEEDS_CONFIG_PATH


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    try:
        await _configure(db)
    except BaseException:
        # aiosqlite runs each connection on its own non-daemon thread. If we
        # raise here without closing, that thread keeps the whole process
        # alive after the traceback, so a CLI command hangs the terminal and
        # the service never exits for systemd to restart it.
        await db.close()
        raise
    return db


async def _configure(db) -> None:
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys = ON")
    # WAL lets readers (API requests) proceed while the scheduler's
    # background poll is mid-write, instead of blocking behind SQLite's
    # default rollback-journal exclusive lock — this app has exactly that
    # pattern (one continuous background writer + many concurrent API
    # reads) so it matters here, not just as a generic best practice.
    # busy_timeout is the backstop for the remaining moments two writers
    # do overlap (e.g. "poll all now" plus the scheduler tick): retry
    # for up to 5s instead of immediately raising "database is locked".
    await db.execute("PRAGMA journal_mode = WAL")
    await db.execute("PRAGMA busy_timeout = 5000")


async def _run_migrations(db) -> None:
    """Brings omenwatch.db up to the current schema (database/migrations)."""
    from omenwatch.database.migrations import migrate
    from omenwatch.database.migrations.main import STEPS

    await migrate(db, STEPS, "omenwatch.db")


async def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = await get_db()
    try:
        await _run_migrations(db)

        # Only seed from config/feeds.json on a genuinely empty database, and only
        # if the file actually has entries. An empty/missing file means: start
        # with zero sources, exactly as the user configures them from the UI.
        cur = await db.execute("SELECT COUNT(*) as c FROM sources")
        row = await cur.fetchone()
        if row["c"] == 0 and os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH) as f:
                    seed = json.load(f).get("sources", [])
            except Exception:
                seed = []
            for s in seed:
                await db.execute(
                    """INSERT OR IGNORE INTO sources
                       (id, name, url, category, color, icon_url, connector_type, interval_seconds)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        s["name"],
                        s["url"],
                        s.get("category", "general"),
                        s.get("color", "#5eead4"),
                        s.get("icon_url"),
                        s.get("connector_type", "rss"),
                        s.get("interval_seconds", 300),
                    ),
                )
            await db.commit()
    finally:
        await db.close()
