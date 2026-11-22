"""
Feed sources: list, add, edit, test, icons, Refresh now and reprocessing.
"""
import asyncio
import calendar
import time
import uuid

from fastapi import HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from omenwatch.api.dependencies import protected_router, router
from omenwatch.api.routes.live import broadcast
from omenwatch.connectors.registry import CONNECTOR_REGISTRY, available_connector_types
from omenwatch.database.sqlite import get_db
from omenwatch.feeds.rss import FETCH_HARD_LIMIT, FeedFetchError, fetch_raw
from omenwatch.intelligence.enrichment import (
    derive_icon_url,
    fetch_and_cache_icon_sync,
    invalidate_icon_cache,
)
from omenwatch.intelligence.ioc_extraction import CVE_PATTERN
from omenwatch.intelligence.reprocessor import reprocess_items


class SourceIn(BaseModel):
    name: str
    url: str
    category: str = "general"
    color: str = "#5eead4"
    icon_url: str | None = None
    connector_type: str = "rss"
    interval_seconds: int = 300


# ---------------------------------------------------------------- connectors

@router.get("/api/connectors")
async def list_connectors():
    """
    Available source types. v1.0 only ever returns RSS/Atom — this exists
    so the UI (and any future automation) can discover supported types
    instead of hardcoding them, ahead of more connectors landing later.
    """
    return available_connector_types()


# ------------------------------------------------------------------ sources

@router.get("/api/sources/{source_id}/icon")
async def get_source_icon(source_id: str):
    """
    Serves the source's favicon from disk. On the very first request for a
    given source, this fetches the icon once and caches it under
    OMENWATCH_ICON_CACHE (default: alongside the database) — every
    request after that is a disk read, no repeated network calls. If the
    fetch has never succeeded, returns 404, and the frontend's onerror
    handler swaps in the category's colored dot instead.
    """
    db = await get_db()
    try:
        cur = await db.execute("SELECT url, icon_url FROM sources WHERE id = ?", (source_id,))
        src = await cur.fetchone()
        await db.close()
        if not src:
            raise HTTPException(404, "source not found")

        fetch_url = src["icon_url"] or derive_icon_url(src["url"])
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, fetch_and_cache_icon_sync, source_id, fetch_url)
        if result is None:
            raise HTTPException(404, "icon not available")
        path, content_type = result
        # These bytes are cached to disk and only change if the source's URL
        # is edited (which calls invalidate_icon_cache server-side). The
        # frontend re-requests this same URL on every feed re-render (30s
        # poll, every WS new_items broadcast) — without any Cache-Control the
        # browser sends a fresh conditional GET every time. 5 minutes cuts
        # nearly all of that repetition within a session while still picking
        # up an edited icon reasonably quickly — a full day (the more
        # "obvious" cache duration) would mean the browser keeps showing a
        # stale icon for up to 24h after an edit, since this URL never
        # changes to bust it on its own.
        return FileResponse(path, media_type=content_type, headers={"Cache-Control": "public, max-age=300"})
    finally:
        await db.close()


@protected_router.get("/api/sources")
async def list_sources():
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM sources ORDER BY name")
        rows = [dict(r) for r in await cur.fetchall()]
        # items_today / items_total for the Sources page (by when OmenWatch
        # stored them: "did this feed deliver anything today?").
        local = time.localtime()
        today_start = time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))
        cur = await db.execute(
            """SELECT source_id, COUNT(*) AS total, SUM(CASE WHEN fetched_at >= ? THEN 1 ELSE 0 END) AS today
               FROM items GROUP BY source_id""",
            (today_start,),
        )
        counts = {r["source_id"]: (r["total"], r["today"] or 0) for r in await cur.fetchall()}
        await db.close()
        for row in rows:
            row["items_total"], row["items_today"] = counts.get(row["id"], (0, 0))
        return rows
    finally:
        await db.close()


class FeedTestIn(BaseModel):
    url: str


_FEED_FORMATS = {"rss20": "RSS 2.0", "rss10": "RSS 1.0", "rss092": "RSS 0.92", "rss091u": "RSS 0.91",
                 "rss091n": "RSS 0.91", "rss090": "RSS 0.90", "atom10": "Atom 1.0", "atom03": "Atom 0.3"}


@protected_router.post("/api/sources/test")
async def test_source(body: FeedTestIn):
    """
    Try a feed URL without saving anything, so the Add/Edit source form
    can say "valid RSS 2.0 feed, 16 items" or show exactly why it isn't
    (HTTP 404, a web page, no response...) before a broken source is
    saved. Same fetcher, limits and error messages as the scheduler.
    Protected like adding a source: it makes the server fetch a URL.
    """
    loop = asyncio.get_running_loop()
    try:
        feed = await asyncio.wait_for(
            loop.run_in_executor(None, fetch_raw, body.url.strip()), timeout=FETCH_HARD_LIMIT
        )
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"no response within {FETCH_HARD_LIMIT}s"}
    except FeedFetchError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:  # anything unexpected is still a failed test, not a 500
        return {"ok": False, "error": str(e)[:200] or e.__class__.__name__}

    newest = 0.0
    with_cve = 0
    for entry in feed.entries:
        parsed = entry.get("published_parsed") or entry.get("updated_parsed")
        if parsed:
            newest = max(newest, calendar.timegm(parsed))
        if CVE_PATTERN.search(f"{entry.get('title', '')} {entry.get('summary', '')}"):
            with_cve += 1
    version = feed.get("version") or ""
    return {
        "ok": True,
        "format": _FEED_FORMATS.get(version, version or "feed"),
        "title": feed.feed.get("title", ""),
        "items": len(feed.entries),
        "newest_published": newest or None,
        "items_with_cve": with_cve,
    }


@protected_router.post("/api/sources")
async def add_source(source: SourceIn):
    if source.connector_type not in CONNECTOR_REGISTRY:
        raise HTTPException(
            400,
            f"Unsupported source type '{source.connector_type}'. "
            f"v1.0 only supports: {', '.join(CONNECTOR_REGISTRY)}.",
        )

    db = await get_db()
    try:
        sid = str(uuid.uuid4())
        icon_url = source.icon_url or derive_icon_url(source.url)
        try:
            await db.execute(
                """INSERT INTO sources (id, name, url, category, color, icon_url, connector_type, interval_seconds)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sid, source.name, source.url, source.category, source.color, icon_url,
                 source.connector_type, source.interval_seconds),
            )
            await db.commit()
        except Exception as e:
            raise HTTPException(400, f"Could not add source (maybe duplicate URL): {e}") from e
        await db.close()
        await broadcast({"type": "sources_changed"})
        return {"id": sid, "icon_url": icon_url}
    finally:
        await db.close()


@protected_router.delete("/api/sources/{source_id}")
async def delete_source(source_id: str):
    db = await get_db()
    try:
        await db.execute("DELETE FROM sources WHERE id = ?", (source_id,))
        await db.commit()
        await db.close()
        invalidate_icon_cache(source_id)
        await broadcast({"type": "sources_changed"})
        return {"ok": True}
    finally:
        await db.close()


class SourceEditIn(BaseModel):
    name: str | None = None
    url: str | None = None
    category: str | None = None
    color: str | None = None
    icon_url: str | None = None
    connector_type: str | None = None
    interval_seconds: int | None = None
    enabled: bool | None = None


@protected_router.patch("/api/sources/{source_id}")
async def update_source(source_id: str, payload: SourceEditIn):
    """
    Partial update — only fields actually present in the request body are
    changed; everything else is left as-is. This is what backs both the
    quick pause/resume toggle (sends only `enabled`) and the full Edit
    Source modal (sends whatever fields the user changed). Previously
    this endpoint only supported toggling `enabled`, so editing a
    source's name/URL/category/interval meant deleting and re-adding it
    — this is the actual fix for that gap.
    """
    if payload.connector_type is not None and payload.connector_type not in CONNECTOR_REGISTRY:
        raise HTTPException(
            400,
            f"Unsupported source type '{payload.connector_type}'. "
            f"v1.0 only supports: {', '.join(CONNECTOR_REGISTRY)}.",
        )

    db = await get_db()
    try:
        cur = await db.execute("SELECT id FROM sources WHERE id = ?", (source_id,))
        if not await cur.fetchone():
            raise HTTPException(404, "source not found")

        updates: dict = {}
        for field in ("name", "url", "category", "color", "icon_url", "connector_type", "interval_seconds"):
            value = getattr(payload, field)
            if value is not None:
                updates[field] = value
        if payload.enabled is not None:
            updates["enabled"] = int(payload.enabled)

        if not updates:
            return {"ok": True}

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        try:
            await db.execute(f"UPDATE sources SET {set_clause} WHERE id = ?", [*updates.values(), source_id])
            await db.commit()
        except Exception as e:
            raise HTTPException(400, f"Could not update source (maybe duplicate URL): {e}") from e

        if "icon_url" in updates or "url" in updates:
            invalidate_icon_cache(source_id)  # force a re-fetch on next request rather than serving a stale icon

        await db.close()
        await broadcast({"type": "sources_changed"})
        return {"ok": True}
    finally:
        await db.close()


@protected_router.get("/api/sources/export")
async def export_sources():
    db = await get_db()
    try:
        cur = await db.execute("SELECT name, url, category, color, icon_url, connector_type, interval_seconds FROM sources")
        rows = [dict(r) for r in await cur.fetchall()]
        return {"sources": rows}
    finally:
        await db.close()


@protected_router.post("/api/sources/import")
async def import_sources(payload: dict):
    """Bulk-add sources, e.g. from a previously exported feeds.json. Skips duplicates."""
    db = await get_db()
    try:
        added, skipped = 0, 0
        for s in payload.get("sources", []):
            icon_url = s.get("icon_url") or derive_icon_url(s["url"])
            try:
                await db.execute(
                    """INSERT INTO sources (id, name, url, category, color, icon_url, connector_type, interval_seconds)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (str(uuid.uuid4()), s["name"], s["url"], s.get("category", "general"),
                     s.get("color", "#5eead4"), icon_url, s.get("connector_type", "rss"),
                     s.get("interval_seconds", 300)),
                )
                added += 1
            except Exception:
                skipped += 1
        await db.commit()
        await db.close()
        await broadcast({"type": "sources_changed"})
        return {"added": added, "skipped": skipped}
    finally:
        await db.close()

_SOURCE_STATE_ORDER = {"failing": 0, "pending": 1, "healthy": 2, "paused": 3}


def _source_health(row: dict) -> dict:
    """
    Public, read-only view of one source for the dashboard and the header
    status indicator. Deliberately excludes the URL: feed URLs sometimes
    carry an API key or token, and this is served without a login.
    """
    status = row.get("last_status") or ""
    if not row.get("enabled"):
        state, error = "paused", ""
    elif status == "ok":
        state, error = "healthy", ""
    elif status.startswith("error"):
        state, error = "failing", status.split(":", 1)[1].strip() if ":" in status else status
    else:
        state, error = "pending", ""
    return {
        "id": row["id"], "name": row["name"], "category": row["category"], "state": state,
        "error": error, "last_fetched": row.get("last_fetched"),
        "last_success": row.get("last_success") or None, "failing_since": row.get("failing_since") or None,
    }


# ----------------------------------------------------------------- polling

def make_poll_now_route(scheduler):
    @protected_router.post("/api/sources/{source_id}/poll")
    async def poll_now(source_id: str):
        db = await get_db()
        try:
            cur = await db.execute("SELECT * FROM sources WHERE id = ?", (source_id,))
            src = await cur.fetchone()
            if not src:
                raise HTTPException(404, "source not found")
            await scheduler.poll_source(db, dict(src))
        finally:
            await db.close()
        return {"ok": True}

    @protected_router.post("/api/sources/poll-all")
    async def poll_all_now():
        """
        Refreshes every enabled source immediately, bypassing each
        source's normal interval throttle — an on-demand "refresh now"
        rather than waiting for the next scheduled tick. Same
        fetch -> normalize -> validate -> store pipeline as a normal
        poll; the UNIQUE(source_id, guid) constraint means this is safe
        to run as often as you like — it only ever adds genuinely new
        items, never duplicates.
        """
        db = await get_db()
        try:
            cur = await db.execute("SELECT * FROM sources WHERE enabled = 1")
            sources = [dict(r) for r in await cur.fetchall()]
            for src in sources:
                await scheduler.poll_source(db, src)
        finally:
            await db.close()
        return {"ok": True, "sources_polled": len(sources)}

    return poll_now


# ------------------------------------------------------------- reprocessing

class ReprocessIn(BaseModel):
    source_id: str | None = None
    deep_extraction: bool | None = None  # None = respect the current Settings toggle


@protected_router.post("/api/reprocess")
async def reprocess(payload: ReprocessIn | None = None):
    """
    Re-runs severity/tagging/IOC extraction against items already on
    disk — no RSS re-fetch, no network call to the source at all (only
    to each item's own article page, if deep extraction is used). This
    is what actually backfills vendors/actors/CVEs/etc. for items stored
    before those extraction features existed; adding a database column
    with a migration never retroactively computes values for old rows.
    Can take a while on a large history with deep extraction on — it's a
    foreground request deliberately (so the caller gets a real
    processed/sources count back), not fired into the background.
    """
    payload = payload or ReprocessIn()
    db = await get_db()
    try:
        return await reprocess_items(db, payload.source_id, payload.deep_extraction)
    finally:
        await db.close()
