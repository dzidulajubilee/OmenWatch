"""
Looking values up in ioc.db: the one lookup both the IOC tab and /api/v1 use,
and the date helpers their answers share.
"""
import datetime
import time

from fastapi import HTTPException

from omenwatch.ioc.normalize import (
    IocValueError,
    candidates,
    detect,
    normalize,
)
from omenwatch.ioc.store import (
    load_allowlist,
    rows_by_type_value,
)


def iso(ts) -> str | None:
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_since(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        parsed = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(400, "since must be a Unix time or an ISO 8601 time such as 2026-10-19T08:00:00Z") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def local_midnight() -> float:
    local = time.localtime()
    return time.mktime((local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))


# ------------------------------------------------------------------ lookups

async def lookup_values(db, values: list[str], include_expired: bool = False, for_people: bool = False,
                        hits: list | None = None) -> dict:
    """
    The one lookup both the tab and /api/v1 use. Every value is matched on
    the UNIQUE (type, value) index, in one query per type for the whole request. A
    miss is a normal result. `for_people` adds what an analyst wants and a
    SIEM doesn't: the row id, and why a stored value doesn't match. The id
    of every match is appended to `hits`, for the SIEM hit counts.
    """
    wanted = []
    for raw in values:
        raw = str(raw)
        options = candidates(raw)
        wanted.append((raw, options))
    found = await rows_by_type_value(db, "*", {option for _, options in wanted for option in options})
    matched_ids = [r["id"] for r in found.values() if r["status"] == "active" or (include_expired and r["status"] == "expired")]
    sources: dict[int, list] = {}
    for start in range(0, len(matched_ids), 900):
        chunk = matched_ids[start:start + 900]
        cur = await db.execute(
            f"""SELECT indicator_id, source_name, confidence, reference FROM sightings
                WHERE active = 1 AND indicator_id IN ({','.join('?' * len(chunk))}) ORDER BY confidence DESC""",
            chunk,
        )
        for r in await cur.fetchall():
            entry = {"name": r["source_name"], "confidence": r["confidence"]}
            if r["reference"]:
                entry["reference"] = r["reference"]
            sources.setdefault(r["indicator_id"], []).append(entry)
    allow = await load_allowlist(db) if for_people else None

    results, matched = [], 0
    for raw, options in wanted:
        if not options:
            result = {"value": raw, "type": detect(raw), "match": False}
            if for_people:
                result["reason"] = _why_not(raw)
            results.append(result)
            continue
        rows = [found[o] for o in options if o in found]
        hit = next((r for r in rows if r["status"] == "active"), None) or next(
            (r for r in rows if include_expired and r["status"] == "expired"), None)
        if not hit:
            result = {"value": raw, "type": options[0][0], "match": False}
            if for_people:
                stored = rows[0] if rows else None
                if stored:
                    result.update(id=stored["id"], status=stored["status"], type=stored["type"])
                elif allow and allow.covers(*options[0]):
                    result["status"] = "allowlisted"
            results.append(result)
            continue
        matched += 1
        if hits is not None:
            hits.append(hit["id"])
        result = {
            "value": raw, "type": hit["type"], "match": True, "status": hit["status"], "confidence": hit["confidence"],
            "threat_type": hit["threat_type"] or None, "malware": hit["malware"] or None, "campaign": hit["campaign"] or None,
            "first_seen": iso(hit["first_seen"]), "last_seen": iso(hit["last_seen"]), "expires_at": iso(hit["expires_at"]),
            "sources": sources.get(hit["id"], []),
        }
        if hit["value"] != raw:
            result["normalized"] = hit["value"]
        if for_people:
            result["id"] = hit["id"]
        results.append(result)
    return {"checked": len(values), "matched": matched, "results": results}


def _why_not(raw: str) -> str:
    detected = detect(raw)
    if not detected:
        return "not a recognised indicator"
    try:
        normalize(detected, raw)
    except IocValueError as e:
        return str(e)
    return "not stored"
