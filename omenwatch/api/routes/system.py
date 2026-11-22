"""
Settings, backup and restore.
"""
import asyncio

from fastapi import File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from omenwatch.api.dependencies import protected_router
from omenwatch.database.restore import (
    RestoreValidationError,
    restore_database,
    save_upload_to_temp,
    validate_sqlite_backup,
)
from omenwatch.database.sqlite import DB_PATH, get_db, init_db


@protected_router.get("/api/backup")
async def backup_database():
    return FileResponse(DB_PATH, filename="omenwatch-backup.db", media_type="application/octet-stream")


@protected_router.post("/api/restore")
async def restore_database_endpoint(file: UploadFile = File(...)):  # noqa: B008 (FastAPI's way to declare an upload)
    """
    Restores the database from a previously-downloaded /api/backup file.
    This REPLACES every item, source, setting, and webhook currently
    stored — it is the one genuinely destructive endpoint in this app.

    Safety sequence (see omenwatch/database/restore.py for the full
    reasoning): the upload is streamed to a temp file and fully
    validated (SQLite header, integrity check, expected tables) before
    the live database is touched at all; a bad or unrelated file never
    gets this far. Only then is the live database checkpointed and
    copied to a timestamped omenwatch-pre-restore-*.db safety backup,
    before the validated upload is atomically swapped into place.

    Returns the safety-backup path so the caller always has a way back
    if the restore turns out to be the wrong file.
    """
    tmp_path = None
    try:
        tmp_path = await save_upload_to_temp(file)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, validate_sqlite_backup, tmp_path)
        # on success, restore_database consumes/moves tmp_path via os.replace
        result = await loop.run_in_executor(None, restore_database, tmp_path)
        # validate_sqlite_backup() only confirms the CORE tables exist —
        # it deliberately doesn't check every column, since that would
        # make every backup taken on an older version "incompatible" the
        # moment a new migration ships, even though the whole point of the
        # migration system is that older databases are safe to bring
        # forward. A backup taken before a later column was added (e.g.
        # webhooks.allow_insecure_tls) is exactly this case: swapping it in
        # verbatim leaves the *running* process — which never restarts as
        # part of a restore — serving a database missing columns its own
        # queries expect, failing with "no such column" until someone
        # thinks to restart the service by hand. Re-running the same
        # schema+migrations step the app already runs on every normal
        # startup (init_db()) brings the just-restored file up to the
        # current schema immediately, so an older backup restores cleanly
        # without a manual restart.
        await init_db()
        return result
    except RestoreValidationError as e:
        raise HTTPException(400, str(e)) from None
    finally:
        # If we're still holding tmp_path here, either validation failed
        # (raised before restore_database ran) or something else went
        # wrong before the os.replace() — in both cases it was never
        # moved, so clean it up. If restore_database() succeeded,
        # tmp_path no longer exists (os.replace already consumed it) and
        # this is a harmless no-op.
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


# ----------------------------------------------------------------- settings

@protected_router.get("/api/settings")
async def get_settings():
    db = await get_db()
    try:
        cur = await db.execute("SELECT key, value FROM settings")
        rows = {r["key"]: r["value"] for r in await cur.fetchall()}
        return {
            # 0 = keep forever (default). Otherwise, a number of days.
            "retention_days": int(rows.get("retention_days", 0)),
            # Whether new items get their full article page fetched for
            # richer severity/tag/IOC extraction. Default on — see
            # omenwatch/connectors/rss.py:_deep_extraction_enabled.
            "deep_extraction": rows.get("deep_extraction", "1") != "0",
        }
    finally:
        await db.close()


@protected_router.post("/api/settings")
async def update_settings(payload: dict):
    db = await get_db()
    try:
        for key, value in payload.items():
            await db.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(value)),
            )
        await db.commit()
        return {"ok": True}
    finally:
        await db.close()
