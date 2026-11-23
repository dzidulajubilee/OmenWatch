"""
Our stack (the watchlist) and CISA's Known Exploited Vulnerabilities.
"""
import time
import uuid
from datetime import date

from fastapi import HTTPException
from pydantic import BaseModel

from omenwatch.api.dependencies import protected_router, router
from omenwatch.database.sqlite import get_db
from omenwatch.news.kev import kev_status, refresh_kev
from omenwatch.news.watchlist import entry_terms, rematch_all

# ---------------------------------------------------------------- our stack

class WatchIn(BaseModel):
    name: str
    aliases: str = ""
    versions: str = ""      # what we run, e.g. "7.4.3, 7.2.8"; shown to people, never used to lower a priority
    updated_on: str = ""    # YYYY-MM-DD, when these systems were last updated


class WatchEditIn(BaseModel):
    name: str | None = None
    aliases: str | None = None
    versions: str | None = None
    updated_on: str | None = None


def _clean_versions(versions: str) -> str:
    parts = [" ".join(v.split()) for v in (versions or "").split(",")]
    parts = list(dict.fromkeys(v for v in parts if v))
    if len(parts) > 10:
        raise HTTPException(400, "Up to 10 versions per entry")
    if any(len(v) > 40 for v in parts):
        raise HTTPException(400, "A version can have up to 40 characters")
    return ",".join(parts)


def _clean_updated_on(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        day = date.fromisoformat(value)
    except ValueError:
        raise HTTPException(400, "Give the last update as a date, YYYY-MM-DD") from None
    if day.isoformat() > time.strftime("%Y-%m-%d", time.localtime(time.time() + 86400)):
        raise HTTPException(400, "The last update can't be in the future")
    return day.isoformat()


def _clean_watch_entry(name: str, aliases: str) -> tuple[str, str]:
    name = " ".join((name or "").split())
    if not name:
        raise HTTPException(400, "Give the entry a name")
    if "," in name:
        raise HTTPException(400, "A name can't contain a comma. Put other spellings under 'Also match'.")
    terms = entry_terms(name, aliases)
    for term in terms:
        if len(term) < 2:
            raise HTTPException(400, f"'{term}' is too short: terms need at least 2 characters")
        if len(term) > 60:
            raise HTTPException(400, f"'{term[:30]}…' is too long: terms can have up to 60 characters")
    if len(terms) > 21:
        raise HTTPException(400, "Up to 20 extra terms per entry")
    return name, ",".join(terms[1:])


async def _watch_name_taken(db, name: str, except_id: str | None = None) -> bool:
    cur = await db.execute(
        "SELECT 1 FROM watchlist WHERE lower(name) = lower(?) AND id != ?", (name, except_id or "")
    )
    return await cur.fetchone() is not None


@protected_router.get("/api/watchlist")
async def list_watchlist():
    """
    Our stack, with how many stored items each entry marks. Settings-only
    (it is an inventory of what the organisation runs); the dashboard only
    ever gets counts.
    """
    db = await get_db()
    try:
        cur = await db.execute("SELECT id, name, aliases, versions, updated_on, created_at FROM watchlist ORDER BY name COLLATE NOCASE")
        rows = [dict(r) for r in await cur.fetchall()]
        for row in rows:
            cur = await db.execute(
                "SELECT COUNT(*) FROM items WHERE instr(',' || watch_hits || ',', ',' || ? || ',') > 0", (row["name"],)
            )
            row["items"] = (await cur.fetchone())[0]
    finally:
        await db.close()
    return rows


@protected_router.post("/api/watchlist")
async def add_watch_entry(entry: WatchIn):
    """Adds an entry and re-checks every stored item, so it applies to history too."""
    name, aliases = _clean_watch_entry(entry.name, entry.aliases)
    versions, updated_on = _clean_versions(entry.versions), _clean_updated_on(entry.updated_on)
    db = await get_db()
    try:
        if await _watch_name_taken(db, name):
            raise HTTPException(409, f"'{name}' is already on the list")
        wid = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO watchlist (id, name, aliases, versions, updated_on) VALUES (?,?,?,?,?)",
            (wid, name, aliases, versions, updated_on),
        )
        await db.commit()
        marked = await rematch_all(db)
    finally:
        await db.close()
    return {"id": wid, "items_marked": marked}


@protected_router.patch("/api/watchlist/{entry_id}")
async def edit_watch_entry(entry_id: str, payload: WatchEditIn):
    db = await get_db()
    try:
        cur = await db.execute("SELECT name, aliases, versions, updated_on FROM watchlist WHERE id = ?", (entry_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "No such entry")
        name, aliases = _clean_watch_entry(
            payload.name if payload.name is not None else row["name"],
            payload.aliases if payload.aliases is not None else row["aliases"],
        )
        versions = _clean_versions(payload.versions if payload.versions is not None else row["versions"])
        updated_on = _clean_updated_on(payload.updated_on if payload.updated_on is not None else row["updated_on"])
        if await _watch_name_taken(db, name, except_id=entry_id):
            raise HTTPException(409, f"'{name}' is already on the list")
        await db.execute(
            "UPDATE watchlist SET name = ?, aliases = ?, versions = ?, updated_on = ? WHERE id = ?",
            (name, aliases, versions, updated_on, entry_id),
        )
        await db.commit()
        marked = await rematch_all(db)
    finally:
        await db.close()
    return {"id": entry_id, "items_marked": marked}


@router.get("/api/watchlist/context")
async def watchlist_context(item: str = ""):
    """
    Versions and last update of the Our stack entries one item is marked
    with (the item detail panel). Keyed by item, not by name, so it can't be
    used to probe the list: the full list stays in Settings. Needs sign-in.
    """
    db = await get_db()
    try:
        cur = await db.execute("SELECT watch_hits FROM items WHERE id = ?", (item,))
        row = await cur.fetchone()
        names = [n for n in ((row["watch_hits"] if row else "") or "").split(",") if n][:20]
        if not names:
            return []
        cur = await db.execute(
            f"SELECT name, versions, updated_on FROM watchlist WHERE name IN ({','.join('?' * len(names))})", names
        )
        return [
            {"name": r["name"], "versions": [v for v in (r["versions"] or "").split(",") if v], "updated_on": r["updated_on"] or ""}
            for r in await cur.fetchall()
        ]
    finally:
        await db.close()


@protected_router.delete("/api/watchlist/{entry_id}")
async def delete_watch_entry(entry_id: str):
    db = await get_db()
    try:
        cur = await db.execute("DELETE FROM watchlist WHERE id = ?", (entry_id,))
        if cur.rowcount == 0:
            raise HTTPException(404, "No such entry")
        await db.commit()
        marked = await rematch_all(db)
    finally:
        await db.close()
    return {"ok": True, "items_marked": marked}


# ------------------------------------------------------ exploited (CISA KEV)

class KevSettingsIn(BaseModel):
    enabled: bool | None = None
    url: str | None = None   # empty string = CISA's official feed


@protected_router.get("/api/kev/status")
async def get_kev_status():
    db = await get_db()
    try:
        return await kev_status(db)
    finally:
        await db.close()


@protected_router.patch("/api/kev/settings")
async def update_kev_settings(payload: KevSettingsIn):
    db = await get_db()
    try:
        if payload.url is not None:
            url = payload.url.strip()
            if url and not url.lower().startswith(("http://", "https://")):
                raise HTTPException(400, "The catalog URL must start with http:// or https://")
            await db.execute(
                "INSERT INTO settings (key, value) VALUES ('kev_url', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (url,),
            )
        if payload.enabled is not None:
            await db.execute(
                "INSERT INTO settings (key, value) VALUES ('kev_enabled', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("1" if payload.enabled else "0",),
            )
        await db.commit()
        return await kev_status(db)
    finally:
        await db.close()


@protected_router.post("/api/kev/refresh")
async def refresh_kev_now():
    """Downloads the catalog now (Settings -> Update now). Protected: it makes the server fetch a URL."""
    db = await get_db()
    try:
        return await refresh_kev(db)
    finally:
        await db.close()


@router.get("/api/kev")
async def lookup_kev(cves: str = ""):
    """Catalog entries for up to 50 comma-separated CVE IDs (the item detail panel). Needs sign-in, like all data."""
    ids = list(dict.fromkeys(c.strip().upper() for c in cves.split(",") if c.strip()))[:50]
    if not ids:
        return []
    db = await get_db()
    try:
        cur = await db.execute(f"SELECT * FROM kev WHERE cve IN ({','.join('?' * len(ids))})", ids)
        return [dict(r) for r in await cur.fetchall()]
    finally:
        await db.close()
