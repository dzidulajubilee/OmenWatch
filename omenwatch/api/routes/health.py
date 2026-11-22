"""Health, metrics and correlation (2.0)."""
from contextlib import asynccontextmanager

from fastapi import HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from omenwatch.api.dependencies import auth_router, router
from omenwatch.core.live import active_ws
from omenwatch.database.sqlite import get_db
from omenwatch.intelligence import correlation
from omenwatch.ioc.db import read_pool
from omenwatch.monitoring import health, metrics


@asynccontextmanager
async def optional_ioc_db():
    """A pooled ioc.db connection, or None when the IOC database can't be opened (the rest still answers)."""
    try:
        db = await read_pool.acquire()
    except Exception:
        yield None
        return
    clean = False
    try:
        yield db
        clean = True
    finally:
        await read_pool.release(db, clean)


@auth_router.get("/api/health")
async def health_check():
    """Public: 200 when every check passes, 503 naming the ones that don't."""
    from omenwatch.workers.main import ioc_worker, news_worker

    result = await health.check(news_worker, ioc_worker)
    return JSONResponse(result, status_code=200 if result["status"] == "ok" else 503,
                        headers={"Cache-Control": "no-store"})


@router.get("/metrics")
async def prometheus_metrics():
    """Prometheus scrape target. Needs an API key (Authorization: Bearer ...) like the rest of the dashboard's data."""
    db = await get_db()
    try:
        async with optional_ioc_db() as ioc:
            text = await metrics.render(db, ioc, len(active_ws))
    finally:
        await db.close()
    return PlainTextResponse(text, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/api/items/{item_id}/related")
async def item_related(item_id: str, limit: int = Query(20, ge=1, le=100)):
    """What an article mentions, what the IOC database and KEV know about it, and related articles."""
    db = await get_db()
    try:
        async with optional_ioc_db() as ioc:
            result = await correlation.related_to_item(db, ioc, item_id, limit)
    finally:
        await db.close()
    if result is None:
        raise HTTPException(404, "No such article.")
    return result


@router.get("/api/correlate")
async def correlate(kind: str = Query(...), value: str = Query(..., min_length=1, max_length=512),
                    limit: int = Query(50, ge=1, le=500)):
    """
    Every article that mentions one CVE, IP, hash, email address, actor or
    vendor, with what they mention alongside it. `kind` may also be an IOC
    database type (ipv4, md5, sha1, sha256, email), so the IOC tab can ask
    about an indicator as it stores it.
    """
    kind = correlation.INDICATOR_KINDS.get(kind.lower(), kind.lower())
    if kind not in correlation.KINDS:
        raise HTTPException(400, f"kind must be one of {', '.join(correlation.KINDS)}")
    db = await get_db()
    try:
        async with optional_ioc_db() as ioc:
            return await correlation.pivot(db, ioc, kind, value, limit)
    finally:
        await db.close()
