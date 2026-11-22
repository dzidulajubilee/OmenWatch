"""
/api/v1: the lookup API for SIEMs, firewalls and scripts. Read-only, SIEM
keys only, and a contract that stays put while the dashboard's own /api
routes change with the interface.
"""
import csv
import io
import json
import time

from fastapi import HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

from omenwatch import __version__
from omenwatch.api.dependencies import siem_router
from omenwatch.api.routes.ioc import LookupIn, indicator_conditions, ioc_db, lookup_list
from omenwatch.ioc.db import get_ioc_db
from omenwatch.ioc.hits import hit_counter
from omenwatch.ioc.lookup import iso, lookup_values, parse_since


@siem_router.get("/lookup")
async def v1_lookup_one(value: str, include_expired: bool = False):
    matched: list[int] = []
    async with ioc_db() as db:
        result = await lookup_values(db, [value.strip()], include_expired, hits=matched)
    hit_counter.record(matched, 1)
    return result["results"][0]


@siem_router.post("/lookup")
async def v1_lookup(body: LookupIn):
    values = lookup_list(body)
    matched: list[int] = []
    async with ioc_db() as db:
        result = await lookup_values(db, values, body.include_expired, hits=matched)
    hit_counter.record(matched, len(values))
    # Only plain JSON types: skip FastAPI's encoder, slow on a 1,000-value answer.
    return JSONResponse(result)


EXPORT_COLUMNS = ("type", "value", "status", "confidence", "threat_type", "malware", "campaign", "first_seen", "last_seen", "expires_at")


@siem_router.get("/export")
async def v1_export(type: str | None = None, min_confidence: int = 0, malware: str | None = None, feed: str | None = None,
                    format: str = "txt", since: str | None = None, include_expired: bool = False):
    """
    Whole lists for a SIEM lookup table, a firewall's external block list
    or (cdb) a Wazuh CDB list. Without `since`: what matches now (active, or
    also expired with include_expired). With `since`: every indicator that
    changed after that time, whatever its status, so a sync can remove what
    expired; txt can't say that, so it lists only the active ones. The
    X-OmenWatch-Exported-At header is the `since` to send next time.

    `cdb` is a Wazuh CDB list: `key:confidence` per line, keys with a colon
    (URLs, IPv6) in double quotes. Wazuh reloads a list only when the
    manager restarts, so it is always the whole list, never `since`.
    """
    if format not in ("txt", "csv", "json", "cdb"):
        raise HTTPException(400, "format is txt, csv, json or cdb")
    if format == "cdb" and since:
        raise HTTPException(400, "A CDB list is always the whole list: leave out since")
    since_ts = parse_since(since)
    if since_ts is not None and format != "txt":
        status = "all"
    else:
        status = "active,expired" if include_expired else "active"
    conditions, params = indicator_conditions(type, None, status, min_confidence, malware, feed)
    if since_ts is not None:
        conditions.append("updated_at > ?")
        params.append(since_ts)
    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    # Check the database opens before starting a 200 response.
    async with ioc_db():
        pass
    exported_at = time.time()

    async def rows():
        db = await get_ioc_db()
        try:
            last_id = 0
            while True:
                cur = await db.execute(
                    f"SELECT * FROM indicators{where}{' AND' if where else ' WHERE'} id > ? ORDER BY id LIMIT 5000",
                    [*params, last_id],
                )
                batch = await cur.fetchall()
                if not batch:
                    return
                for r in batch:
                    yield r
                last_id = batch[-1]["id"]
        finally:
            await db.close()

    def record(r) -> dict:
        out = {k: r[k] for k in EXPORT_COLUMNS}
        for k in ("first_seen", "last_seen", "expires_at"):
            out[k] = iso(out[k])
        for k in ("threat_type", "malware", "campaign"):
            out[k] = out[k] or None
        return out

    async def body():
        if format == "txt":
            async for r in rows():
                yield r["value"] + "\n"
        elif format == "cdb":
            async for r in rows():
                value = r["value"]
                if '"' in value or "\n" in value:
                    continue                          # can't be written as a CDB key
                yield (f'"{value}"' if ":" in value else value) + f":{r['confidence']}\n"
        elif format == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(EXPORT_COLUMNS)
            async for r in rows():
                rec = record(r)
                writer.writerow(["" if rec[k] is None else rec[k] for k in EXPORT_COLUMNS])
                if buffer.tell() > 64 * 1024:
                    yield buffer.getvalue()
                    buffer.seek(0)
                    buffer.truncate()
            yield buffer.getvalue()
        else:
            yield '{"exported_at": ' + json.dumps(iso(exported_at)) + ', "indicators": ['
            first = True
            async for r in rows():
                yield ("" if first else ",") + json.dumps(record(r), separators=(",", ":"))
                first = False
            yield "]}\n"

    media = {"txt": "text/plain", "cdb": "text/plain", "csv": "text/csv", "json": "application/json"}[format]
    return StreamingResponse(body(), media_type=f"{media}; charset=utf-8",
                             headers={"X-OmenWatch-Exported-At": iso(exported_at),
                                      # Before 2.0 OmenWatch was Pantomath; older scripts read this name.
                                      "X-Pantomath-Exported-At": iso(exported_at)})


@siem_router.get("/health")
async def v1_health():
    """Counts and the last successful feed update, for the SIEM connector's own checks."""
    async with ioc_db() as db:
        cur = await db.execute("SELECT type, COUNT(*) AS n FROM indicators WHERE status = 'active' GROUP BY type")
        by_type = {r["type"]: r["n"] for r in await cur.fetchall()}
        cur = await db.execute("SELECT enabled, last_status, last_success FROM ioc_feeds")
        feeds = [dict(r) for r in await cur.fetchall()]
    enabled = [f for f in feeds if f["enabled"]]
    failing = sum(1 for f in enabled if f["last_status"].startswith("error"))
    return {
        "status": "degraded" if failing else "ok",
        "version": __version__,
        "indicators": {"active": sum(by_type.values()), "by_type": by_type},
        "feeds": {"total": len(feeds), "enabled": len(enabled), "failing": failing},
        "last_feed_update": iso(max((f["last_success"] or 0 for f in feeds), default=0)),
        "generated_at": iso(time.time()),
    }
