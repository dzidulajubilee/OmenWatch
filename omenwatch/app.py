from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from omenwatch import __version__
from omenwatch.api.dependencies import ioc_protected_router, ioc_router, siem_router
from omenwatch.api.routes import auth_router, make_poll_now_route, protected_router, router
from omenwatch.core import config
from omenwatch.core.logging import get_logger
from omenwatch.core.logging import setup as setup_logging
from omenwatch.core.security import add_security_headers
from omenwatch.database.sqlite import init_db
from omenwatch.ioc.db import init_ioc_db
from omenwatch.workers.main import ioc_worker, news_worker

FRONTEND = config.APP_ROOT / "frontend"

setup_logging()
log = get_logger("app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # First run (0.8.1): make sure the setup code exists; never log the code itself.
    from omenwatch.auth import setup_code
    from omenwatch.database.sqlite import get_db

    db = await get_db()
    try:
        if await setup_code.ensure_setup_code(db):
            log.info("Not set up yet. Open the dashboard and enter the setup code; "
                     "show it on this server with: sudo omenwatch-admin setup-code")
    finally:
        await db.close()
    await news_worker.start()
    # The IOC database (1.0.0) is its own file: if it can't be set up, its
    # tab and /api/v1 report why and every other part of OmenWatch runs.
    try:
        await init_ioc_db()
    except Exception as e:
        log.error("The IOC database is unavailable: %s", e)
    await ioc_worker.start()
    yield
    news_worker.stop()
    await ioc_worker.shutdown()


app = FastAPI(title="OmenWatch", lifespan=lifespan)

add_security_headers(app)



app.include_router(auth_router)
app.include_router(router)
app.include_router(protected_router)
make_poll_now_route(news_worker)  # registers /api/sources/{id}/poll(-all) on protected_router
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
