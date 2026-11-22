"""
Polls every enabled source on its own interval, through whatever
connector its `connector_type` maps to. This file has no RSS-specific
code in it — it only knows about BaseConnector's `update()` contract, so
it doesn't change when new connector types are added later.

Also runs the retention cleanup pass (see `_maybe_run_retention`) — off
by default (retention_days = 0 means "keep forever"), throttled to at
most once an hour so it's not re-scanning the whole items table on every
20-second tick.
"""
import asyncio
import time

from omenwatch.alerts.dispatcher import dispatch_webhooks_for_items
from omenwatch.core.logging import get_logger
from omenwatch.database.sqlite import get_db
from omenwatch.ingestion.connectors.registry import get_connector
from omenwatch.news.kev import kev_due, refresh_kev

log = get_logger("scheduler")

RETENTION_CHECK_INTERVAL = 3600  # seconds


class Scheduler:
    def __init__(self, broadcast_fn, check_interval: int = 20):
        self.broadcast = broadcast_fn
        self.check_interval = check_interval
        self._running = False
        self._last_retention_check = 0
        self._last_kev_check = 0.0
        self._kev_task = None
        self._task = None

    async def start(self):
        self._running = True
        # Kept: the event loop holds tasks only weakly, so an unreferenced
        # loop task can be garbage-collected and polling silently stops.
        self._task = asyncio.create_task(self._loop())

    def stop(self):
        self._running = False

    async def _loop(self):
        while self._running:
            try:
                await self.poll_all()
                await self._maybe_run_retention()
                await self._maybe_refresh_kev()
            except Exception as e:
                log.error("poll loop error: %s", e)
            await asyncio.sleep(self.check_interval)

    async def poll_all(self):
        db = await get_db()
        try:
            cur = await db.execute("SELECT * FROM sources WHERE enabled = 1")
            sources = await cur.fetchall()
            now = time.time()
            for src in sources:
                if now - (src["last_fetched"] or 0) < src["interval_seconds"]:
                    continue
                await self.poll_source(db, dict(src))
        finally:
            await db.close()

    async def poll_source(self, db, src: dict):
        started = time.monotonic()
        try:
            connector = get_connector(src)
            new_items = await connector.update(db)  # fetch -> normalize -> validate -> store

            # last_success / failing_since / last_duration_ms feed the
            # Sources page: last_fetched alone can't say when a failing
            # feed last worked, because it updates on failures too.
            now = time.time()
            await db.execute(
                """UPDATE sources SET last_fetched = ?, last_status = 'ok', last_success = ?,
                                      failing_since = 0, last_duration_ms = ? WHERE id = ?""",
                (now, now, int((time.monotonic() - started) * 1000), src["id"]),
            )
            await db.commit()

            if new_items:
                await self.broadcast({"type": "new_items", "items": new_items})
                await dispatch_webhooks_for_items(db, new_items)

        except Exception as e:
            now = time.time()
            await db.execute(
                """UPDATE sources SET last_fetched = ?, last_status = ?, last_duration_ms = ?,
                                      failing_since = CASE WHEN failing_since > 0 THEN failing_since ELSE ? END
                   WHERE id = ?""",
                (now, f"error: {str(e)[:100]}", int((time.monotonic() - started) * 1000), now, src["id"]),
            )
            await db.commit()

    async def _maybe_refresh_kev(self):
        """
        Keeps the CISA KEV catalog current: once a day after a successful
        download, hourly after a failure, never when turned off in Settings.
        The download runs as a background task so a slow server can't hold
        up feed polling.
        """
        now = time.time()
        if now - self._last_kev_check < 300 or (self._kev_task and not self._kev_task.done()):
            return
        self._last_kev_check = now
        db = await get_db()
        try:
            due = await kev_due(db, now)
        finally:
            await db.close()
        if due:
            self._kev_task = asyncio.create_task(self._refresh_kev())

    async def _refresh_kev(self):
        db = await get_db()
        try:
            status = await refresh_kev(db)
            if status["error"]:
                log.warning("KEV catalog update failed: %s", status["error"])
        except Exception as e:
            log.error("KEV catalog update error: %s", e)
        finally:
            await db.close()

    async def _maybe_run_retention(self):
        now = time.time()
        if now - self._last_retention_check < RETENTION_CHECK_INTERVAL:
            return
        self._last_retention_check = now

        db = await get_db()
        try:
            # Signed-in browsers whose time ran out: otherwise a row stays for
            # every sign-in ever made. API keys (expires_at 0) never expire.
            await db.execute("DELETE FROM sessions WHERE expires_at != 0 AND expires_at < ?", (now,))
            await db.commit()
            cur = await db.execute("SELECT value FROM settings WHERE key = 'retention_days'")
            row = await cur.fetchone()
            retention_days = int(row["value"]) if row and row["value"] else 0
            if retention_days <= 0:
                return  # 0 = keep forever, the default — nothing to prune

            cutoff = now - (retention_days * 86400)
            cursor = await db.execute("DELETE FROM items WHERE fetched_at < ?", (cutoff,))
            await db.commit()
            if cursor.rowcount:
                log.info("retention cleanup: removed %d item(s) older than %dd", cursor.rowcount, retention_days)
        finally:
            await db.close()
