"""
Opening ioc.db.

The IOC database is its own SQLite file, next to omenwatch.db
(/var/lib/omenwatch/ioc.db) rather than more tables inside it:

  - SQLite allows one writer per file. A 200,000-line feed import holds
    only ioc.db's lock, so RSS polling, sign-ins and settings saves on
    omenwatch.db never wait for it.
  - The existing backup stays the size it is. Most of ioc.db is feed data
    that can be downloaded again.
  - If ioc.db is damaged or can't be opened, the IOC tab and /api/v1 say
    so (IocUnavailable) and every other tab keeps working.

Same engine, driver and pragmas as omenwatch.db, so no new dependency.
"""
import os

import aiosqlite

from omenwatch.core import config
from omenwatch.database.sqlite import _configure

IOC_DB_PATH = config.IOC_DB_PATH


class IocUnavailable(Exception):
    """ioc.db couldn't be opened. str() is shown on the IOC tab and returned by /api/v1."""


async def get_ioc_db():
    try:
        db = await aiosqlite.connect(IOC_DB_PATH)
    except Exception as e:
        raise IocUnavailable(f"The IOC database ({IOC_DB_PATH}) can't be opened: {e}") from e
    try:
        await _configure(db)
        # ioc.db's indexes outgrow SQLite's 2 MB default cache quickly, and
        # every value an import adds lands at a random place in them: 32 MB
        # made 1M-indicator imports about 40% faster. NORMAL is safe in WAL
        # mode (a power cut can lose the last commits, never corrupt the
        # file) and saves a disk sync per commit.
        await db.execute("PRAGMA cache_size = -32768")
        await db.execute("PRAGMA synchronous = NORMAL")
    except BaseException as e:
        # Same reason as get_db(): never leave aiosqlite's thread running.
        await db.close()
        if isinstance(e, Exception):
            raise IocUnavailable(f"The IOC database ({IOC_DB_PATH}) can't be opened: {e}") from e
        raise
    return db


async def init_ioc_db() -> None:
    """Creates ioc.db empty on first start and brings an existing one up to date."""
    os.makedirs(os.path.dirname(IOC_DB_PATH), exist_ok=True)
    db = await get_ioc_db()
    try:
        from omenwatch.database.migrations import migrate
        from omenwatch.database.migrations.ioc import STEPS

        await migrate(db, STEPS, "ioc.db")
    finally:
        await db.close()
