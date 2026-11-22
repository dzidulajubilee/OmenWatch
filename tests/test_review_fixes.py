"""Regression tests for the pre-release review: each fails without its fix."""
import asyncio
import os
import time

import pytest
from fastapi.testclient import TestClient

from omenwatch.alerts.dispatcher import send_webhook_sync
from omenwatch.api.routes import ioc as ioc_routes
from omenwatch.api.routes import news as api_routes
from omenwatch.app import app
from omenwatch.auth import sign_in
from omenwatch.database.sqlite import get_db
from omenwatch.intelligence import enrichment
from omenwatch.ioc.db import IOC_DB_PATH, init_ioc_db

client = TestClient(app)


@pytest.fixture(autouse=True)
async def _clean(fresh_db):
    await init_ioc_db()
    resp = client.post("/api/settings/auth/setup", json={"password": "test-password-123"})
    client.headers["X-Settings-Token"] = resp.json()["token"]
    yield


async def _add_source(source_id="s1", icon_url=None):
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category, icon_url) VALUES (?, 'S', 'http://x.com/feed', 'news', ?)",
                     (source_id, icon_url))
    await db.commit()
    await db.close()
    for path in enrichment._paths(source_id):
        if os.path.exists(path):
            os.remove(path)


# ------------------------------------------------------------- source icons

async def test_an_icon_url_never_serves_local_files(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("local-file-content")
    await _add_source(icon_url=f"file://{secret}")
    resp = client.get("/api/sources/s1/icon")
    assert resp.status_code == 404
    assert b"local-file-content" not in resp.content


async def test_an_icon_that_is_not_an_image_is_not_served(monkeypatch):
    await _add_source(icon_url="https://icons.example/favicon.ico")

    class Response:
        headers = {"Content-Type": "text/html; charset=utf-8"}
        def read(self, n=-1): return b"<script>alert(1)</script>"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(enrichment.urllib.request, "urlopen", lambda *a, **k: Response())
    assert client.get("/api/sources/s1/icon").status_code == 404


async def test_an_icon_cached_with_a_bad_type_is_not_served():
    await _add_source()
    os.makedirs(enrichment.ICON_CACHE_DIR, exist_ok=True)
    bin_path, ctype_path, _ = enrichment._paths("s1")
    with open(bin_path, "wb") as f:
        f.write(b"<script>alert(1)</script>")
    with open(ctype_path, "w") as f:
        f.write("text/html")
    assert client.get("/api/sources/s1/icon").status_code == 404


# ----------------------------------------------------------------- webhooks

def test_webhook_urls_must_be_http():
    assert client.post("/api/webhooks", json={"name": "W", "url": "file:///etc/passwd"}).status_code == 400
    ok = client.post("/api/webhooks", json={"name": "W", "url": "https://hooks.example/x"})
    assert ok.status_code == 200
    assert client.patch(f"/api/webhooks/{ok.json()['id']}", json={"url": "file:///etc/passwd"}).status_code == 400
    sent, message = send_webhook_sync("file:///etc/passwd", {"text": "x"})
    assert not sent and "http" in message


# ------------------------------------------------------------------ headers

def test_responses_carry_security_headers():
    for path in ("/", "/api/items"):
        headers = client.get(path).headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "SAMEORIGIN"
        assert "frame-ancestors 'self'" in headers["content-security-policy"]


# ------------------------------------------------------------------ paging

async def test_a_negative_limit_does_not_return_everything():
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'S', 'http://x.com/feed', 'news')")
    await db.executemany(
        "INSERT INTO items (id, source_id, title, guid, fetched_at) VALUES (?, 's1', 't', ?, ?)",
        [(str(i), f"g{i}", i) for i in range(api_routes.MAX_ITEMS_PAGE + 5)],
    )
    await db.commit()
    await db.close()
    assert len(client.get("/api/items?limit=-1").json()) == 1          # SQLite: -1 = no limit
    assert len(client.get("/api/items?limit=50000").json()) == api_routes.MAX_ITEMS_PAGE
    assert len(client.get("/api/items?limit=5&offset=-3").json()) == 5


# ------------------------------------------------- database connection leaks

async def test_a_failing_request_still_closes_its_database_connection(monkeypatch):
    opened = []

    async def tracking_get_db():
        db = await get_db()
        opened.append(db)
        return db

    def broken(row):
        raise RuntimeError("boom")

    monkeypatch.setattr(api_routes, "get_db", tracking_get_db)
    monkeypatch.setattr(api_routes, "_row_to_item", broken)
    db = await get_db()
    await db.execute("INSERT INTO sources (id, name, url, category) VALUES ('s1', 'S', 'http://x.com/feed', 'news')")
    await db.execute("INSERT INTO items (id, source_id, title, guid, fetched_at) VALUES ('1', 's1', 't', 'g', 1)")
    await db.commit()
    await db.close()
    resp = TestClient(app, raise_server_exceptions=False).get("/api/items")
    assert resp.status_code == 500
    assert opened and all(conn._connection is None for conn in opened)


# ------------------------------------------------------------ sign-in state

def test_old_sign_in_failures_age_out():
    ip = "198.51.100.7"
    for _ in range(sign_in.MAX_FAILURES - 1):
        sign_in.record_failure(ip)
    sign_in._failures[ip][2] -= sign_in.FAILURE_WINDOW + 1      # those were long ago
    sign_in.record_failure(ip)
    assert sign_in.check_rate(ip) == (True, 0)


def test_the_failure_table_stays_bounded():
    for i in range(sign_in.MAX_TRACKED + 50):
        sign_in.record_failure(f"2001:db8::{i:x}")
    assert len(sign_in._failures) <= sign_in.MAX_TRACKED


async def test_expired_sessions_are_deleted_by_the_hourly_pass():
    from omenwatch.workers.news_worker import Scheduler

    db = await get_db()
    old, _ = await sign_in.create_session(db, "team", False, "127.0.0.1", "")
    key, _ = await sign_in.create_session(db, "team", False, "127.0.0.1", "", kind="api", label="k")
    await db.execute("UPDATE sessions SET expires_at = ? WHERE kind = 'browser'", (time.time() - 10,))
    await db.commit()
    await db.close()

    await Scheduler(lambda m: None)._maybe_run_retention()

    db = await get_db()
    cur = await db.execute("SELECT kind FROM sessions")
    kinds = [r["kind"] for r in await cur.fetchall()]
    await db.close()
    assert kinds == ["api"]                                        # API keys never expire


async def test_the_news_scheduler_keeps_its_loop_task():
    from omenwatch.workers.news_worker import Scheduler

    scheduler = Scheduler(lambda m: None, check_interval=3600)
    scheduler.poll_all = lambda: asyncio.sleep(0)
    await scheduler.start()
    try:
        assert isinstance(scheduler._task, asyncio.Task)
    finally:
        scheduler.stop()
        scheduler._task.cancel()


# --------------------------------------------------------------- IOC backup

def _leftovers():
    folder = os.path.dirname(os.path.abspath(IOC_DB_PATH))
    return [f for f in os.listdir(folder) if f.startswith(".ioc-backup-")]


def test_an_ioc_backup_leaves_no_copy_behind_when_it_fails(monkeypatch):
    class HalfWritten:
        def execute(self, sql, params):
            with open(params[0], "w") as f:      # the copy is on disk, then something other than SQLite fails
                f.write("feed keys")
            raise OSError("disk unplugged")

        def close(self):
            pass

    monkeypatch.setattr(ioc_routes.sqlite3, "connect", lambda *a, **k: HalfWritten())
    resp = TestClient(app, raise_server_exceptions=False).get("/api/ioc/backup", headers=client.headers)
    assert resp.status_code == 500
    assert _leftovers() == []


def test_an_old_ioc_backup_copy_is_cleared():
    folder = os.path.dirname(os.path.abspath(IOC_DB_PATH))
    stale = os.path.join(folder, ".ioc-backup-stale.db")
    with open(stale, "w") as f:
        f.write("feed keys")
    os.utime(stale, (time.time() - 7200, time.time() - 7200))
    assert client.get("/api/ioc/backup").status_code == 200
    assert not os.path.exists(stale)


# ---------------------------------------------------------------- refresh now

def test_the_refresh_now_routes_answer():
    # FastAPI includes routers by reference, so these work although app.py
    # adds them after including protected_router.
    resp = client.post("/api/sources/poll-all")
    assert resp.status_code == 200 and resp.json() == {"ok": True, "sources_polled": 0}
    assert client.post("/api/sources/missing/poll").status_code == 404
