import pathlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from omenwatch import __version__
from omenwatch.api.dependencies import ioc_protected_router, ioc_router, siem_router
from omenwatch.api.routes import auth_router, broadcast, make_poll_now_route, protected_router, router
from omenwatch.api.routes.ioc import ioc_scheduler
from omenwatch.database.sqlite import init_db
from omenwatch.feeds.scheduler import Scheduler
from omenwatch.ioc.db import init_ioc_db

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

scheduler = Scheduler(broadcast)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # First run (0.8.1): make sure the setup code exists; never log the code itself.
    from omenwatch.auth import setup_code
    from omenwatch.database.sqlite import get_db

    db = await get_db()
    try:
        if await setup_code.ensure_setup_code(db):
            print("[omenwatch] Not set up yet. Open the dashboard and enter the setup code; "
                  "show it on this server with: sudo omenwatch-admin setup-code")
    finally:
        await db.close()
    await scheduler.start()
    # The IOC database (1.0.0) is its own file: if it can't be set up, its
    # tab and /api/v1 report why and every other part of OmenWatch runs.
    try:
        await init_ioc_db()
    except Exception as e:
        print(f"[omenwatch] The IOC database is unavailable: {e}")
    await ioc_scheduler.start()
    yield
    scheduler.stop()
    await ioc_scheduler.shutdown()


app = FastAPI(title="OmenWatch", lifespan=lifespan)

# On every response. Other sites can't frame the dashboard (clickjacking
# the Settings buttons), browsers never guess a type other than the one
# sent, and links out to articles don't tell publishers this server's
# address.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Content-Security-Policy": "frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
    "Referrer-Policy": "same-origin",
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response

app.include_router(auth_router)
app.include_router(router)
app.include_router(protected_router)
make_poll_now_route(scheduler)  # registers /api/sources/{id}/poll(-all) on protected_router
app.include_router(ioc_router)
app.include_router(ioc_protected_router)
app.include_router(siem_router)


@app.get("/")
async def dashboard():
    """
    Renders the page shell with a cache-busting query param on every
    CSS/JS reference, derived from the installed package version. Without
    this, a browser that cached omenwatch.css or app.js from a previous
    release can keep serving that stale copy indefinitely after an
    upgrade — since the URL never changes, there's nothing to tell it a
    newer version exists. Tying the cache-busting token to the actual
    installed version means every release automatically forces a fresh
    fetch, with no per-release manual step to remember.
    """
    html = (FRONTEND / "pages" / "dashboard.html").read_text()
    html = html.replace("{{CACHEBUST}}", __version__)
    return HTMLResponse(html)


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
