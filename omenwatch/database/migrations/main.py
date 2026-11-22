"""Schema steps for the main database, omenwatch.db. Append; never edit a shipped step."""
from omenwatch.database.migrations import add_missing_columns
from omenwatch.database.models import COLUMNS_ADDED_BEFORE_2_0, INDEX_SCHEMA, TABLE_SCHEMA


async def baseline(db) -> None:
    """everything up to OmenWatch 2.0"""
    await db.executescript(TABLE_SCHEMA)
    await db.commit()
    await add_missing_columns(db, COLUMNS_ADDED_BEFORE_2_0)
    await _backfill_priority(db)
    # Indexes last: one can name a column an old database only has once
    # add_missing_columns has run (see INDEX_SCHEMA in models.py).
    await db.executescript(INDEX_SCHEMA)


async def _backfill_priority(db) -> None:
    """
    0.8.0 moved the keyword rating from items.severity to
    items.content_severity and made severity the priority. Items stored
    earlier get their old rating copied across once, then their priority
    worked out (a restored old backup goes through the same step).
    """
    from omenwatch.news.priority import recompute_priorities

    cur = await db.execute("SELECT COUNT(*) FROM items WHERE content_severity = '' OR content_severity IS NULL")
    if (await cur.fetchone())[0]:
        await db.execute(
            """UPDATE items SET content_severity = CASE WHEN severity IN ('low', 'medium', 'high') THEN severity ELSE 'high' END
               WHERE content_severity = '' OR content_severity IS NULL"""
        )
        await recompute_priorities(db)
        await db.commit()


async def item_entities(db) -> None:
    """correlation: one row per CVE, indicator, actor and vendor an article mentions"""
    from omenwatch.intelligence.correlation import BACKFILL, SCHEMA

    await db.executescript(SCHEMA)
    await db.executescript(BACKFILL)


STEPS = [baseline, item_entities]
