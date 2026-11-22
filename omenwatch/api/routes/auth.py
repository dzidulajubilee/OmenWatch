"""
Signing in, the Settings password, sessions, API keys and the team password.
"""

from fastapi import Header, HTTPException, Request, Response
from pydantic import BaseModel

from omenwatch import __version__
from omenwatch.api.dependencies import auth_router, client_ip, protected_router, router
from omenwatch.auth import settings_auth, setup_code, sign_in
from omenwatch.database.sqlite import get_db


class SettingsPasswordSetup(BaseModel):
    password: str
    setup_code: str = ""


class SettingsPasswordLogin(BaseModel):
    password: str


class SettingsRecoveryReset(BaseModel):
    recovery_code: str
    new_password: str


@router.get("/api/settings/auth/status")
async def settings_auth_status():
    """Whether a Settings/Sources password has been configured yet — the frontend uses this to decide setup-form vs login-form."""
    db = await get_db()
    try:
        configured = await settings_auth.is_password_configured(db)
        return {"configured": configured}
    finally:
        await db.close()


@router.post("/api/settings/auth/setup")
async def settings_auth_setup(body: SettingsPasswordSetup):
    """
    First-time setup only. Returns the one-time recovery code — the
    frontend must display this prominently and make clear it will never
    be shown again, since only its hash is stored.
    """
    db = await get_db()
    try:
        if await settings_auth.is_password_configured(db):
            raise HTTPException(409, "A password is already configured for Settings/Sources.")
        # 0.8.1: with sign-in on, being signed in (say, with the team password)
        # must not be enough to claim the Settings password: the setup code from
        # the server is required here too. With sign-in off (behind an
        # authenticating proxy) the proxy is the gate, as before.
        if not sign_in.open_dashboard() and not await setup_code.verify(db, body.setup_code):
            raise HTTPException(401, "That setup code isn't right. Show it on the server with: sudo omenwatch-admin setup-code")
        try:
            recovery_code = await settings_auth.setup_password(db, body.password)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await setup_code.discard(db)
        return {"token": settings_auth.create_session(), "recovery_code": recovery_code}
    finally:
        await db.close()


@router.post("/api/settings/auth/login")
async def settings_auth_login(body: SettingsPasswordLogin):
    db = await get_db()
    try:
        ok, err = await settings_auth.verify_password(db, body.password)
        await db.close()
        if not ok:
            raise HTTPException(401, err)
        return {"token": settings_auth.create_session()}
    finally:
        await db.close()


@router.post("/api/settings/auth/recover")
async def settings_auth_recover(body: SettingsRecoveryReset):
    """
    The recovery-code path: proves identity via the one-time code shown
    at setup instead of the password, then immediately sets a new
    password AND issues a new recovery code (the old code is single-use).
    """
    db = await get_db()
    try:
        ok, err, new_recovery = await settings_auth.reset_via_recovery_code(db, body.recovery_code, body.new_password)
        await db.close()
        if not ok:
            raise HTTPException(401, err)
        return {"token": settings_auth.create_session(), "recovery_code": new_recovery}
    finally:
        await db.close()


@router.post("/api/settings/auth/logout")
async def settings_auth_logout(x_settings_token: str | None = Header(None)):
    settings_auth.invalidate_session(x_settings_token)
    return {"ok": True}


# ------------------------------------------------------------------ sign-in

class SignInBody(BaseModel):
    password: str
    remember: bool = False


class SetupBody(BaseModel):
    password: str
    setup_code: str = ""
    remember: bool = True


class RecoverBody(BaseModel):
    recovery_code: str
    new_password: str
    remember: bool = False


class TeamPasswordBody(BaseModel):
    password: str


class ApiKeyBody(BaseModel):
    label: str


def _set_session_cookie(request: Request, response: Response, token: str, remember: bool) -> None:
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        sign_in.COOKIE_NAME, token, max_age=sign_in.REMEMBER_SECONDS if remember else None,
        httponly=True, samesite="strict", secure=https, path="/",
    )


@auth_router.get("/api/auth/status")
async def auth_status(request: Request):
    """What the sign-in page needs: set up yet? signed in? Nothing about the data."""
    db = await get_db()
    try:
        configured = await settings_auth.is_password_configured(db)
        if not configured:
            await setup_code.ensure_setup_code(db)  # so there's always one to find on the server
        team = await sign_in.team_password_set(db)
        session = await sign_in.validate(db, request.cookies.get(sign_in.COOKIE_NAME))
    finally:
        await db.close()
    open_ = sign_in.open_dashboard()
    return {
        "signed_in": open_ or bool(session),
        "open": open_,
        "setup_needed": not configured,
        "team_password": team,
        "role": session["role"] if session else None,
        "remembered": bool(session and session["remember"]),
        "version": __version__,
    }


@auth_router.post("/api/auth/login")
async def auth_login(body: SignInBody, request: Request, response: Response):
    ip = client_ip(request)
    allowed, wait = sign_in.check_rate(ip)
    if not allowed:
        raise HTTPException(429, f"Too many attempts. Try again in {wait} seconds.")
    db = await get_db()
    try:
        if not await settings_auth.is_password_configured(db):
            raise HTTPException(409, "OmenWatch hasn't been set up yet.")
        role = await sign_in.match_password(db, body.password)
        if not role:
            sign_in.record_failure(ip)
            raise HTTPException(401, "That password isn't right.")
        sign_in.record_success(ip)
        token, _ = await sign_in.create_session(db, role, body.remember, ip, request.headers.get("user-agent", ""))
    finally:
        await db.close()
    _set_session_cookie(request, response, token, body.remember)
    result = {"ok": True, "role": role}
    if role == "admin":
        # Signing in with the Settings password also unlocks Settings.
        result["settings_token"] = settings_auth.create_session()
    return result


@auth_router.post("/api/auth/setup")
async def auth_setup(body: SetupBody, request: Request, response: Response):
    """
    First run only: creates the Settings password and signs this browser in.
    Needs the one-time setup code from the server (setup_code.py), so the
    first person to reach the page can't take the install over.
    """
    ip = client_ip(request)
    allowed, wait = sign_in.check_rate(ip)
    if not allowed:
        raise HTTPException(429, f"Too many attempts. Try again in {wait} seconds.")
    db = await get_db()
    try:
        if await settings_auth.is_password_configured(db):
            raise HTTPException(409, "OmenWatch is already set up. Sign in instead.")
        if not await setup_code.verify(db, body.setup_code):
            sign_in.record_failure(ip)
            raise HTTPException(401, "That setup code isn't right. Show it on the server with: sudo omenwatch-admin setup-code")
        sign_in.record_success(ip)
        try:
            recovery_code = await settings_auth.setup_password(db, body.password)
        except ValueError as e:
            raise HTTPException(400, str(e)) from None
        await setup_code.discard(db)
        token, _ = await sign_in.create_session(db, "admin", body.remember, ip, request.headers.get("user-agent", ""))
    finally:
        await db.close()
    _set_session_cookie(request, response, token, body.remember)
    return {"ok": True, "role": "admin", "recovery_code": recovery_code, "settings_token": settings_auth.create_session()}


@auth_router.post("/api/auth/recover")
async def auth_recover(body: RecoverBody, request: Request, response: Response):
    """
    "Forgot the Settings password?" on the sign-in page: the one-time
    recovery code sets a new one and signs this browser in. The code is
    replaced (it's single-use) and other devices signed in with the old
    Settings password are signed out.
    """
    ip = client_ip(request)
    allowed, wait = sign_in.check_rate(ip)
    if not allowed:
        raise HTTPException(429, f"Too many attempts. Try again in {wait} seconds.")
    db = await get_db()
    try:
        if not await settings_auth.is_password_configured(db):
            raise HTTPException(409, "OmenWatch hasn't been set up yet.")
        if len(body.new_password or "") < settings_auth.MIN_PASSWORD_LENGTH:
            raise HTTPException(400, f"Use at least {settings_auth.MIN_PASSWORD_LENGTH} characters.")
        if await sign_in._matches_team_password(db, body.new_password):
            raise HTTPException(400, "Use a different password from the team password.")
        ok, error, new_code = await settings_auth.reset_via_recovery_code(db, body.recovery_code, body.new_password)
        if not ok:
            sign_in.record_failure(ip)
            raise HTTPException(401, error or "That recovery code isn't right.")
        sign_in.record_success(ip)
        await db.execute("DELETE FROM sessions WHERE role = 'admin'")
        await db.commit()
        sign_in._cache.clear()
        token, _ = await sign_in.create_session(db, "admin", body.remember, ip, request.headers.get("user-agent", ""))
    finally:
        await db.close()
    _set_session_cookie(request, response, token, body.remember)
    return {"ok": True, "role": "admin", "recovery_code": new_code, "settings_token": settings_auth.create_session()}


@auth_router.post("/api/auth/logout")
async def auth_logout(request: Request, response: Response):
    db = await get_db()
    try:
        session = await sign_in.validate(db, request.cookies.get(sign_in.COOKIE_NAME))
        if session:
            await sign_in.revoke(db, session["id"])
    finally:
        await db.close()
    response.delete_cookie(sign_in.COOKIE_NAME, path="/")
    return {"ok": True}


@protected_router.get("/api/auth/sessions")
async def list_signed_in(request: Request):
    """Signed-in devices, API keys and SIEM keys, for Settings, Security."""
    token = request.cookies.get(sign_in.COOKIE_NAME)
    db = await get_db()
    try:
        rows = await sign_in.list_sessions(db, sign_in.hash_token(token) if token else None)
    finally:
        await db.close()
    keys = [r for r in rows if r["kind"] == "api"]
    return {
        "devices": [r for r in rows if r["kind"] == "browser"],
        "api_keys": [r for r in keys if r["role"] != sign_in.SIEM_ROLE],
        "siem_keys": [r for r in keys if r["role"] == sign_in.SIEM_ROLE],
    }


@protected_router.delete("/api/auth/sessions/{session_id}")
async def revoke_signed_in(session_id: str):
    db = await get_db()
    try:
        if not await sign_in.revoke(db, session_id):
            raise HTTPException(404, "Already signed out")
    finally:
        await db.close()
    return {"ok": True}


@protected_router.post("/api/auth/sessions/sign-out-others")
async def sign_out_others(request: Request):
    db = await get_db()
    try:
        current = await sign_in.validate(db, request.cookies.get(sign_in.COOKIE_NAME))
        removed = await sign_in.revoke_others(db, current["id"] if current else None)
    finally:
        await db.close()
    return {"signed_out": removed}


@protected_router.post("/api/auth/api-keys")
async def create_api_key(body: ApiKeyBody, request: Request):
    """A key for scripts (`Authorization: Bearer <key>`), shown once. Read-only: it can't change settings."""
    label = " ".join((body.label or "").split())[:60]
    if not label:
        raise HTTPException(400, "Give the key a name, so you know what uses it")
    db = await get_db()
    try:
        token, key_id = await sign_in.create_session(db, "api", False, client_ip(request), "", kind="api", label=label)
    finally:
        await db.close()
    return {"id": key_id, "key": token}


@protected_router.put("/api/auth/team-password")
async def set_team_password(body: TeamPasswordBody):
    db = await get_db()
    try:
        await sign_in.set_team_password(db, body.password)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    finally:
        await db.close()
    return {"ok": True}


@protected_router.delete("/api/auth/team-password")
async def remove_team_password():
    db = await get_db()
    try:
        await sign_in.clear_team_password(db)
    finally:
        await db.close()
    return {"ok": True}
