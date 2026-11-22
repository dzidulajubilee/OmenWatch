"""ioc.db's read pool and the sign-in cache shortcut (2.0 performance work)."""
import os
import sqlite3

import pytest
from fastapi.testclient import TestClient

from omenwatch.app import app
from omenwatch.auth import sign_in
from omenwatch.ioc.db import IOC_DB_PATH, ReadPool, init_ioc_db


@pytest.fixture(autouse=True)
async def _ioc(fresh_db):
    await init_ioc_db()


async def test_a_clean_connection_is_reused():
    pool = ReadPool(size=2)
    db = await pool.acquire()
    await db.execute("SELECT 1")
    await pool.release(db, clean=True)
    assert await pool.acquire() is db
    await pool.release(db, clean=True)
    await pool.close()


async def test_a_connection_from_a_failed_request_is_closed():
    pool = ReadPool()
    db = await pool.acquire()
    await pool.release(db, clean=False)
    assert db._connection is None
    again = await pool.acquire()
    assert again is not db
    await pool.release(again, clean=True)
    await pool.close()


async def test_a_connection_with_uncommitted_writes_is_not_reused():
    pool = ReadPool()
    db = await pool.acquire()
    await db.execute("INSERT INTO ioc_settings (key, value) VALUES ('pool-test', '1')")
    assert db.in_transaction
    await pool.release(db, clean=True)
    assert db._connection is None
    await pool.close()
    with sqlite3.connect(IOC_DB_PATH) as raw:   # and nothing half-done leaked into the file
        assert raw.execute("SELECT COUNT(*) FROM ioc_settings WHERE key = 'pool-test'").fetchone()[0] == 0


async def test_a_replaced_database_file_is_never_served_from_the_pool():
    pool = ReadPool()
    db = await pool.acquire()
    await pool.release(db, clean=True)
    os.replace(IOC_DB_PATH, IOC_DB_PATH + ".old")      # someone swaps ioc.db
    await init_ioc_db()
    fresh = await pool.acquire()
    assert fresh is not db and db._connection is None
    await pool.release(fresh, clean=True)
    await pool.close()
    os.remove(IOC_DB_PATH + ".old")


async def test_pooled_connections_never_keep_the_process_alive():
    pool = ReadPool()
    db = await pool.acquire()
    assert db._thread.daemon
    await pool.release(db, clean=True)
    await pool.close()


async def test_a_cached_siem_key_skips_the_database(monkeypatch):
    os.environ.pop("OMENWATCH_OPEN_DASHBOARD", None)
    try:
        from omenwatch.database.sqlite import get_db

        db = await get_db()
        key, _ = await sign_in.create_session(db, sign_in.SIEM_ROLE, False, "127.0.0.1", "", kind="api", label="t")
        await db.close()
        client = TestClient(app, headers={"Authorization": f"Bearer {key}"})
        assert client.get("/api/v1/health").status_code == 200          # first use: from the database

        from omenwatch.api import dependencies

        async def no_database():
            raise AssertionError("the cached key should not need the database")

        monkeypatch.setattr(dependencies, "get_db", no_database)
        assert client.get("/api/v1/health").status_code == 200          # then: from the cache
        assert sign_in.cached(key, siem=False) is None                  # never valid as a viewer key
    finally:
        os.environ["OMENWATCH_OPEN_DASHBOARD"] = "1"
