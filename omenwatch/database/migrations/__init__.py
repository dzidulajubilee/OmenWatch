"""
Numbered schema migrations. Each database records how far it has come in
SQLite's own PRAGMA user_version; a database at version N gets every step
after N, in order, once.

Step 1 of each database is the baseline: everything up to OmenWatch 2.0.
It also runs on any older database (Pantomath 0.4 onwards, or a restored
old backup), so it stays idempotent: tables and indexes IF NOT EXISTS, and
columns added only when missing.

To change a schema, append a step to its list. Never edit or reorder a step
that has shipped: databases out there have already run it.
"""
from collections.abc import Awaitable, Callable

from omenwatch.core.logging import get_logger

Step = Callable[..., Awaitable[None]]
log = get_logger("migrations")


async def schema_version(db) -> int:
    cur = await db.execute("PRAGMA user_version")
    return (await cur.fetchone())[0]


async def migrate(db, steps: list[Step], name: str) -> int:
    """Runs the steps `db` hasn't had yet. Returns the version it ends at."""
    version = await schema_version(db)
    if version > len(steps):
        # A backup restored from a newer OmenWatch: don't guess at undoing its changes.
        log.warning("%s has schema version %d, newer than this OmenWatch knows (%d); left as it is",
                    name, version, len(steps))
        return version
    for number, step in enumerate(steps[version:], start=version + 1):
        await step(db)
        await db.execute(f"PRAGMA user_version = {number}")
        await db.commit()
        if version:
            log.info("%s: schema migrated to version %d (%s)", name, number, step.__doc__.strip().splitlines()[0])
    return len(steps)


async def add_missing_columns(db, columns: list[tuple[str, str, str]]) -> None:
    """ALTER TABLE ... ADD COLUMN for each (table, column, definition) a table doesn't have yet."""
    checked: dict[str, set[str]] = {}
    for table, column, definition in columns:
        if table not in checked:
            cur = await db.execute(f"PRAGMA table_info({table})")
            checked[table] = {r[1] for r in await cur.fetchall()}
        if column not in checked[table]:
            await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
            checked[table].add(column)
    await db.commit()
