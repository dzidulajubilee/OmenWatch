"""
Webhook alerts.
"""
import asyncio
import time
import uuid

from fastapi import HTTPException
from pydantic import BaseModel

from omenwatch.alerts.dispatcher import build_payload, send_webhook_sync
from omenwatch.alerts.webhook_keys import check_and_consume_attempt, hash_key, mask_url, new_salt
from omenwatch.api.dependencies import protected_router
from omenwatch.database.sqlite import get_db

# ----------------------------------------------------------------- webhooks

class WebhookIn(BaseModel):
    name: str
    url: str
    keyword: str = ""
    source_id: str = ""
    min_severity: str = ""
    enabled: bool = True
    allow_insecure_tls: bool = False  # skip TLS certificate verification (self-signed certs, internal CAs)
    only_affects_us: bool = False     # only items that mention something on Our stack
    only_exploited: bool = False      # only items with a CVE on CISA's KEV catalog
    key: str | None = None  # optional — if set, this webhook is protected from creation


def _serialize_webhook(row: dict) -> dict:
    """Never sends key_hash/key_salt/attempt-tracking to the client, and
    masks the URL for protected webhooks — the whole point of protecting
    one is that loading the Settings page shouldn't hand out the real URL."""
    out = {k: v for k, v in row.items() if k not in ("key_hash", "key_salt", "key_fail_count", "key_locked_until")}
    if row.get("protected"):
        out["url"] = mask_url(row["url"])
    return out


def _check_webhook_url(url: str) -> None:
    if not url.strip().lower().startswith(("http://", "https://")):
        raise HTTPException(400, "The webhook URL must start with http:// or https://")


@protected_router.get("/api/webhooks")
async def list_webhooks():
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM webhooks ORDER BY name")
        return [_serialize_webhook(dict(r)) for r in await cur.fetchall()]
    finally:
        await db.close()


@protected_router.post("/api/webhooks")
async def add_webhook(webhook: WebhookIn):
    if webhook.min_severity and webhook.min_severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(400, "min_severity must be one of: low, medium, high, critical (or empty for any)")
    if webhook.key is not None and not webhook.key.strip():
        raise HTTPException(400, "Webhook key can't be blank")
    _check_webhook_url(webhook.url)

    db = await get_db()
    try:
        wid = str(uuid.uuid4())
        protected, key_salt, key_hash = 0, None, None
        if webhook.key:
            salt = new_salt()
            protected, key_salt, key_hash = 1, salt.hex(), hash_key(webhook.key, salt)

        await db.execute(
            """INSERT INTO webhooks (id, name, url, keyword, source_id, min_severity, enabled, protected, key_salt, key_hash,
                                     allow_insecure_tls, only_affects_us, only_exploited)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (wid, webhook.name, webhook.url, webhook.keyword, webhook.source_id,
             webhook.min_severity, int(webhook.enabled), protected, key_salt, key_hash, int(webhook.allow_insecure_tls),
             int(webhook.only_affects_us), int(webhook.only_exploited)),
        )
        await db.commit()
        return {"id": wid}
    finally:
        await db.close()


class WebhookEditIn(BaseModel):
    name: str | None = None
    url: str | None = None
    keyword: str | None = None
    source_id: str | None = None
    min_severity: str | None = None
    enabled: bool | None = None
    allow_insecure_tls: bool | None = None  # skip TLS certificate verification (self-signed certs, internal CAs)
    only_affects_us: bool | None = None
    only_exploited: bool | None = None
    key: str | None = None            # current key — required to authorize any change to an already-protected webhook
    set_key: str | None = None        # sets a new key: adds protection if there wasn't any, or changes the existing one
    remove_protection: bool = False   # drops protection entirely (still requires the current `key`)


class WebhookKeyIn(BaseModel):
    key: str


@protected_router.patch("/api/webhooks/{webhook_id}")
async def update_webhook(webhook_id: str, payload: WebhookEditIn):
    """Partial update, same pattern as sources — only fields present in the body are changed.
    A protected webhook requires the correct `key` before anything about it
    can change, including removing the protection itself."""
    if payload.min_severity and payload.min_severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(400, "min_severity must be one of: low, medium, high, critical (or empty for any)")
    if payload.url is not None:
        _check_webhook_url(payload.url)

    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "webhook not found")
        row = dict(row)

        if row.get("protected"):
            ok, err = await check_and_consume_attempt(db, row, payload.key or "")
            if not ok:
                raise HTTPException(401, err)

        updates: dict = {}
        for field in ("name", "url", "keyword", "source_id", "min_severity"):
            value = getattr(payload, field)
            if value is not None:
                updates[field] = value
        if payload.enabled is not None:
            updates["enabled"] = int(payload.enabled)
        if payload.allow_insecure_tls is not None:
            updates["allow_insecure_tls"] = int(payload.allow_insecure_tls)
        for flag in ("only_affects_us", "only_exploited"):
            if getattr(payload, flag) is not None:
                updates[flag] = int(getattr(payload, flag))

        if payload.set_key is not None:
            if not payload.set_key.strip():
                raise HTTPException(400, "Webhook key can't be blank")
            salt = new_salt()
            updates.update(
                protected=1, key_salt=salt.hex(), key_hash=hash_key(payload.set_key, salt),
                key_fail_count=0, key_locked_until=0,
            )
        elif payload.remove_protection:
            updates.update(protected=0, key_salt=None, key_hash=None, key_fail_count=0, key_locked_until=0)

        if updates:
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            await db.execute(f"UPDATE webhooks SET {set_clause} WHERE id = ?", [*updates.values(), webhook_id])
            await db.commit()
        return {"ok": True}
    finally:
        await db.close()


@protected_router.post("/api/webhooks/{webhook_id}/reveal")
async def reveal_webhook_url(webhook_id: str, payload: WebhookKeyIn):
    """Returns the real URL for a webhook. Unprotected webhooks return it
    immediately; protected ones require the correct key. This — plus
    deleting and recreating — is the only way to see a protected webhook's
    full URL again."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "webhook not found")
        row = dict(row)

        if not row.get("protected"):
            return {"url": row["url"]}

        ok, err = await check_and_consume_attempt(db, row, payload.key)
        await db.close()
        if not ok:
            raise HTTPException(401, err)
        return {"url": row["url"]}
    finally:
        await db.close()


@protected_router.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str):
    db = await get_db()
    try:
        await db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        await db.commit()
        return {"ok": True}
    finally:
        await db.close()


@protected_router.post("/api/webhooks/{webhook_id}/test")
async def test_webhook(webhook_id: str):
    """Sends a synthetic test payload immediately, so you can verify a webhook works without waiting for a real match."""
    db = await get_db()
    try:
        cur = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        webhook = await cur.fetchone()
        if not webhook:
            raise HTTPException(404, "webhook not found")
        webhook = dict(webhook)

        test_item = {
            "id": "test", "title": "OmenWatch test alert",
            "summary": "This is a test payload sent from the Settings page — if you're seeing this, the webhook is working.",
            "link": "", "severity": "high", "source_id": "", "source_name": "OmenWatch",
            "category": "general", "vendors": [], "actors": [], "cves": [],
        }
        payload = build_payload(test_item, webhook)
        loop = asyncio.get_event_loop()
        ok, status = await loop.run_in_executor(
            None, send_webhook_sync, webhook["url"], payload, bool(webhook.get("allow_insecure_tls"))
        )

        await db.execute(
            "UPDATE webhooks SET last_triggered = ?, last_status = ? WHERE id = ?",
            (time.time(), status, webhook_id),
        )
        await db.commit()
        await db.close()
        if not ok:
            raise HTTPException(502, f"Webhook delivery failed: {status}")
        return {"ok": True, "status": status}
    finally:
        await db.close()
