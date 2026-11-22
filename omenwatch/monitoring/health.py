"""
/api/health: is this OmenWatch working? For load balancers, uptime checks and
systemd watchdogs. Public, so it says which check failed and nothing else.
"""
import os
import shutil

from omenwatch.database import sqlite as news_sqlite
from omenwatch.ioc.db import read_pool

MIN_FREE_BYTES = 200 * 1024 * 1024   # below this, SQLite writes and restores start failing


async def _database() -> bool:
    try:
        db = await news_sqlite.get_db()
    except Exception:
        return False
    try:
        await (await db.execute("SELECT 1")).fetchone()
        return True
    except Exception:
        return False
    finally:
        await db.close()


async def _ioc_database() -> bool:
    try:
        db = await read_pool.acquire()
    except Exception:
        return False
    clean = False
    try:
        await (await db.execute("SELECT 1")).fetchone()
        clean = True
    except Exception:
        pass
    finally:
        await read_pool.release(db, clean)
    return clean


def _running(worker) -> bool:
    task = getattr(worker, "_task", None)
    return task is not None and not task.done()


def _disk() -> bool:
    try:
        return shutil.disk_usage(os.path.dirname(os.path.abspath(news_sqlite.DB_PATH))).free >= MIN_FREE_BYTES
    except OSError:
        return False


async def check(news_worker, ioc_worker) -> dict:
    checks = {
        "database": await _database(),
        "ioc_database": await _ioc_database(),
        "news_polling": _running(news_worker),
        "ioc_feeds": _running(ioc_worker),
        "disk_space": _disk(),
    }
    return {"status": "ok" if all(checks.values()) else "fail",
            "checks": {name: "ok" if ok else "fail" for name, ok in checks.items()}}
