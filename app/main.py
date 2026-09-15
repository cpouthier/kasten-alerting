"""kasten-alerting: polls Kasten K10 action objects (BackupAction,
RestoreAction, ExportAction, etc.) and sends a digest email whenever new
ones finish in a status you've selected. See poller.py for why this has to
poll rather than watch, and README.md for the full picture.
"""
import asyncio
import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import alerting
import db
import k10
import poller
import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kasten-alerting")

app = FastAPI()


@app.on_event("startup")
async def _startup():
    settings.init()
    db.init_db()
    asyncio.create_task(poller.run_forever())


class AlertingSettingsRequest(BaseModel):
    enabled: bool = False
    action_kinds: list[str] = []
    statuses: list[str] = []
    poll_interval_seconds: int = 300
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    from_address: str = ""
    to_addresses: list[str] = []
    # Write-only, same pattern as malware-scan: blank on a PUT means "keep
    # whatever's already stored" - the current password is never sent back
    # to the browser to begin with.
    password: str | None = None
    clear_password: bool = False


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/api/action-kinds")
def api_action_kinds():
    return k10.ACTION_KINDS


@app.get("/api/statuses")
def api_statuses():
    return k10.TERMINAL_STATES


async def _has_smtp_password() -> bool:
    data = await k10.get_secret_data(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME)
    return data is not None and bool(data.get("password"))


@app.get("/api/settings")
async def api_get_settings():
    return {**settings.get_alerting(), "has_password": await _has_smtp_password()}


@app.put("/api/settings")
async def api_update_settings(body: AlertingSettingsRequest):
    try:
        cfg = settings.update_alerting(
            enabled=body.enabled,
            action_kinds=body.action_kinds,
            statuses=body.statuses,
            poll_interval_seconds=body.poll_interval_seconds,
            smtp_host=body.smtp_host,
            smtp_port=body.smtp_port,
            smtp_security=body.smtp_security,
            smtp_username=body.smtp_username,
            from_address=body.from_address,
            to_addresses=body.to_addresses,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.clear_password:
        await k10.delete_secret(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME)
    elif body.password:
        await k10.create_secret(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME, {"password": body.password})

    return {**cfg, "has_password": await _has_smtp_password()}


@app.post("/api/settings/test-email")
async def api_test_email(body: AlertingSettingsRequest):
    if not body.smtp_host or not body.from_address or not body.to_addresses:
        raise HTTPException(
            status_code=400,
            detail="smtp_host, from_address and at least one recipient are required to send a test email",
        )
    password = body.password
    if not password:
        stored = await k10.get_secret_data(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME)
        password = stored.get("password") if stored else None
    cfg = {
        "smtp_host": body.smtp_host, "smtp_port": body.smtp_port, "smtp_security": body.smtp_security,
        "smtp_username": body.smtp_username, "from_address": body.from_address, "to_addresses": body.to_addresses,
    }
    try:
        await alerting.send_test_email(cfg, password)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"sent": True}


@app.post("/api/poll-now")
async def api_poll_now():
    """Manual trigger for the Settings page's "Check now" button - runs
    exactly the same cycle poller.run_forever fires on a timer, useful to
    confirm a config change works without waiting for the next interval."""
    await poller.run_once()
    return {"triggered": True}


@app.get("/api/digests")
def api_list_digests():
    return db.list_digests()


@app.get("/api/digests/{digest_id}")
def api_get_digest(digest_id: str):
    digest = db.get_digest(digest_id)
    if digest is None:
        raise HTTPException(status_code=404, detail="digest not found")
    return digest


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
