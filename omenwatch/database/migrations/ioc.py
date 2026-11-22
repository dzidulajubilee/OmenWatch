"""Schema steps for the IOC database, ioc.db. Append; never edit a shipped step."""
from omenwatch.database.migrations import add_missing_columns
from omenwatch.ioc.models import IOC_COLUMNS_ADDED_BEFORE_2_0, IOC_INDEX_SCHEMA, IOC_TABLE_SCHEMA


async def baseline(db) -> None:
    """everything up to OmenWatch 2.0"""
    await db.executescript(IOC_TABLE_SCHEMA)
    await db.commit()
    await add_missing_columns(db, IOC_COLUMNS_ADDED_BEFORE_2_0)
    await db.executescript(IOC_INDEX_SCHEMA)


async def drop_value_index(db) -> None:
    """drop the index on value alone"""
    # Lookups and imports find indicators through UNIQUE (type, value) since
    # 2.0, so this second index only made every import slower.
    await db.execute("DROP INDEX IF EXISTS idx_indicators_value")


STEPS = [baseline, drop_value_index]
