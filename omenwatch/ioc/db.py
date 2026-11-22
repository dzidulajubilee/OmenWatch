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


async def get_ioc_db(daemon: bool = False):
    """
    A new connection to ioc.db; close it when done. `daemon` is for pooled
    connections: aiosqlite runs each connection on its own thread, and an
    idle pooled one must never keep the process alive at exit.
    """
    try:
        pending = aiosqlite.connect(IOC_DB_PATH)
        if daemon and hasattr(pending, "_thread"):
            pending._thread.daemon = True   # aiosqlite starts the thread on await
        db = await pending
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


class ReadPool:
    """
    A few ioc.db connections kept open for API requests, instead of a new
    connection (and thread) for every lookup. A connection goes back to the
    pool only when the request ended cleanly with nothing uncommitted;
    otherwise it is closed. If ioc.db has been replaced on disk, older
    connections are dropped rather than served.
    """

    def __init__(self, size: int = 4):
        self.size = size
        self._idle: list[tuple] = []   # (connection, file identity when opened)

    @staticmethod
    def _identity():
        try:
            st = os.stat(IOC_DB_PATH)
            return st.st_dev, st.st_ino
        except OSError:
            return None

    async def acquire(self):
        current = self._identity()
        while self._idle:
            db, identity = self._idle.pop()
            if identity == current:
                return db
            await db.close()
        db = await get_ioc_db(daemon=True)
        db._pool_identity = self._identity()
        return db

    async def release(self, db, clean: bool) -> None:
        identity = getattr(db, "_pool_identity", None)
        if clean and not db.in_transaction and len(self._idle) < self.size and identity == self._identity():
            self._idle.append((db, identity))
        else:
            await db.close()

    async def close(self) -> None:
        while self._idle:
            db, _ = self._idle.pop()
            await db.close()


read_pool = ReadPool()

