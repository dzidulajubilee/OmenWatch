"""
Who may call what. Every route sits on one of these routers, so a new route
is gated by construction:

  router, ioc_router          a signed-in viewer (cookie, API key or an
                              unlocked Settings session)
  protected_router,           an unlocked Settings session: changing sources,
  ioc_protected_router        settings, IOC data, feeds and keys
  siem_router (/api/v1)       a SIEM key and nothing else
  auth_router                 nothing: sign-in itself, and the WebSocket,
                              which checks the cookie on its own
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request

from omenwatch.auth import settings_auth, sign_in
from omenwatch.database.sqlite import get_db


async def session_for(token: str | None, siem: bool = False) -> dict | None:
    """sign_in.validate(), opening the database only when the short cache doesn't know the token."""
    session = sign_in.cached(token, siem)
    if session is sign_in.MISS:
        db = await get_db()
        try:
            session = await sign_in.validate(db, token, siem=siem)
        finally:
            await db.close()
    return session


async def require_viewer(request: Request):
    """
    Dependency on every route of `router` (0.8.0): the dashboard's data is
    only for signed-in people. Accepts the sign-in cookie, an API key
    (`Authorization: Bearer ...`), or an unlocked Settings token. The
    X-OmenWatch-Sign-In header tells the frontend to show the sign-in page
    rather than the Settings unlock prompt.
    """
    if sign_in.open_dashboard():
        return
    if settings_auth.validate_session(request.headers.get("x-settings-token")):
        return
    token = sign_in.token_from(request.cookies.get(sign_in.COOKIE_NAME), request.headers.get("authorization"))
    if token:
        session = await session_for(token)
        if session:
            request.state.session = session
            return
    raise HTTPException(401, "Sign in to OmenWatch to see this.", headers={"X-OmenWatch-Sign-In": "required"})


# Everything the dashboard shows. Sign-in is enforced by construction: a
# route added here is protected without anyone having to remember it.
router = APIRouter(dependencies=[Depends(require_viewer)])

# The only routes reachable without signing in: sign-in itself and the
# WebSocket (which checks the cookie on its own, see ws_endpoint).
auth_router = APIRouter()


async def require_settings_auth(x_settings_token: str | None = Header(None)):
    """
    Dependency applied to every route under the Settings and Sources
    surfaces (see `protected_router` below) — never to anything else.
    The rest of the app (Dashboard, Live Feed, IOCs, etc.) is designed to
    be an always-open SOC/NOC display; only configuration actions are
    gated. Enforced here, server-side, rather than only hidden in the
    frontend — a UI-only lock would do nothing against someone calling
    these endpoints directly.
    """
    if not settings_auth.validate_session(x_settings_token):
        raise HTTPException(401, "Settings session expired or invalid — please log in again.")


# Every route on this router requires a valid settings-auth session.
# Kept as a *second* router (rather than adding a dependency to each of
# the ~17 individual route functions) so the gate is enforced by
# construction — a new route added here is automatically protected
# without anyone needing to remember to add the dependency by hand.
protected_router = APIRouter(dependencies=[Depends(require_settings_auth)])


def client_ip(request: Request) -> str:
    ip = request.client.host if request.client else ""
    # Behind `omenwatch-admin setup-https`, nginx on the same host forwards
    # the real address; only trust the header when the request came from it.
    forwarded = request.headers.get("x-forwarded-for", "")
    if ip in ("127.0.0.1", "::1") and forwarded:
        ip = forwarded.split(",")[0].strip()
    return ip


# ------------------------------------------------------------ IOC database

ioc_router = APIRouter(dependencies=[Depends(require_viewer)])
ioc_protected_router = APIRouter(dependencies=[Depends(require_settings_auth)])


# ------------------------------------------------------------------- /api/v1

async def require_siem_key(request: Request):
    """
    Only SIEM keys (Settings, Security) open /api/v1, sent as
    `Authorization: Bearer <key>`. Browser sessions and ordinary API keys
    don't: they keep exactly the access they had before 1.0.0.
    """
    if sign_in.open_dashboard():
        return
    token = sign_in.token_from(None, request.headers.get("authorization"))
    if token and await session_for(token, siem=True):
        return
    raise HTTPException(401, "Send a SIEM key as 'Authorization: Bearer <key>'. Create one in OmenWatch, Settings, Security.",
                        headers={"WWW-Authenticate": "Bearer"})


siem_router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_siem_key)])
