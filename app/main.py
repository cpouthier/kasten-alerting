"""kasten-alerting: polls Veeam Kasten action objects (BackupAction,
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
import maintenance
import poller
import settings
import snmp_trap
import tz

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("kasten-alerting")

app = FastAPI()


@app.on_event("startup")
async def _startup():
    settings.init()
    db.init_db()
    asyncio.create_task(poller.run_forever())
    asyncio.create_task(maintenance.run_forever())


class AlertingSettingsRequest(BaseModel):
    enabled: bool = False
    action_kinds: list[str] = []
    statuses: list[str] = []
    excluded_policies: list[str] = []
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

    snmp_enabled: bool = False
    snmp_host: str = ""
    snmp_port: int = 162
    snmp_version: str = "v2c"
    snmp_v3_username: str = ""
    snmp_v3_auth_protocol: str = "sha"
    snmp_v3_priv_protocol: str = "aes"
    # Write-only, same pattern as the SMTP password - blank means "keep
    # whatever's already stored" for each field independently.
    snmp_community: str | None = None
    snmp_v3_auth_password: str | None = None
    snmp_v3_priv_password: str | None = None
    clear_snmp_credentials: bool = False


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


async def _snmp_credentials_status() -> dict:
    data = await k10.get_secret_data(k10.APP_NAMESPACE, snmp_trap.SNMP_SECRET_NAME) or {}
    return {
        "has_community": bool(data.get("community")),
        "has_v3_auth_password": bool(data.get("v3_auth_password")),
        "has_v3_priv_password": bool(data.get("v3_priv_password")),
    }


async def _settings_view() -> dict:
    return {
        **settings.get_alerting(),
        "has_password": await _has_smtp_password(),
        "snmp_credentials": await _snmp_credentials_status(),
        # SNMPv3 needs this exact value configured on the receiving NMS
        # before it will accept an authenticated trap from this app - see
        # snmp_trap.py's module docstring. Shown here (not write-only,
        # it's not secret) so it can be copied straight from the page.
        "snmp_engine_id": snmp_trap.engine_id_hex(),
    }


@app.get("/api/settings")
async def api_get_settings():
    return await _settings_view()


@app.put("/api/settings")
async def api_update_settings(body: AlertingSettingsRequest):
    try:
        settings.update_alerting(
            enabled=body.enabled,
            action_kinds=body.action_kinds,
            statuses=body.statuses,
            excluded_policies=body.excluded_policies,
            poll_interval_seconds=body.poll_interval_seconds,
            smtp_host=body.smtp_host,
            smtp_port=body.smtp_port,
            smtp_security=body.smtp_security,
            smtp_username=body.smtp_username,
            from_address=body.from_address,
            to_addresses=body.to_addresses,
            snmp_enabled=body.snmp_enabled,
            snmp_host=body.snmp_host,
            snmp_port=body.snmp_port,
            snmp_version=body.snmp_version,
            snmp_v3_username=body.snmp_v3_username,
            snmp_v3_auth_protocol=body.snmp_v3_auth_protocol,
            snmp_v3_priv_protocol=body.snmp_v3_priv_protocol,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.clear_password:
        await k10.delete_secret(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME)
    elif body.password:
        await k10.create_secret(k10.APP_NAMESPACE, alerting.SMTP_SECRET_NAME, {"password": body.password})

    if body.clear_snmp_credentials:
        await k10.delete_secret(k10.APP_NAMESPACE, snmp_trap.SNMP_SECRET_NAME)
    else:
        # Merge onto whatever's already stored - saving a new v3 priv
        # password, say, must not silently wipe an already-saved community
        # string (or vice versa), since a PUT here only ever carries the
        # fields the admin actually just typed.
        existing = await k10.get_secret_data(k10.APP_NAMESPACE, snmp_trap.SNMP_SECRET_NAME) or {}
        updated = dict(existing)
        if body.snmp_community:
            updated["community"] = body.snmp_community
        if body.snmp_v3_auth_password:
            updated["v3_auth_password"] = body.snmp_v3_auth_password
        if body.snmp_v3_priv_password:
            updated["v3_priv_password"] = body.snmp_v3_priv_password
        if updated != existing:
            await k10.create_secret(k10.APP_NAMESPACE, snmp_trap.SNMP_SECRET_NAME, updated)

    return await _settings_view()


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


@app.post("/api/settings/test-trap")
async def api_test_trap(body: AlertingSettingsRequest):
    if not body.snmp_host:
        raise HTTPException(status_code=400, detail="snmp_host is required to send a test trap")
    if body.snmp_version == "v3" and not body.snmp_v3_username:
        raise HTTPException(status_code=400, detail="snmp_v3_username is required for SNMPv3")

    stored = await k10.get_secret_data(k10.APP_NAMESPACE, snmp_trap.SNMP_SECRET_NAME) or {}
    creds = {
        "community": body.snmp_community or stored.get("community"),
        "v3_auth_password": body.snmp_v3_auth_password or stored.get("v3_auth_password"),
        "v3_priv_password": body.snmp_v3_priv_password or stored.get("v3_priv_password"),
    }
    cfg = {
        "snmp_host": body.snmp_host, "snmp_port": body.snmp_port, "snmp_version": body.snmp_version,
        "snmp_v3_username": body.snmp_v3_username, "snmp_v3_auth_protocol": body.snmp_v3_auth_protocol,
        "snmp_v3_priv_protocol": body.snmp_v3_priv_protocol,
    }
    try:
        await snmp_trap.send_test_trap(cfg, creds)
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


class MaintenanceSettingsRequest(BaseModel):
    enabled: bool = True
    interval_days: int = 7


@app.get("/api/maintenance")
def api_get_maintenance():
    return {**settings.get_maintenance(), "last_run": db.last_maintenance_run()}


@app.put("/api/maintenance")
def api_update_maintenance(body: MaintenanceSettingsRequest):
    try:
        cfg = settings.update_maintenance(enabled=body.enabled, interval_days=body.interval_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {**cfg, "last_run": db.last_maintenance_run()}


@app.post("/api/maintenance/run-now")
async def api_maintenance_run_now():
    """Manual trigger, same idea as /api/poll-now - runs regardless of
    whether automatic maintenance is currently enabled, so it's always
    usable to clean up on demand or just to verify the feature works."""
    await maintenance.run_once()
    return {"triggered": True, "last_run": db.last_maintenance_run()}


@app.get("/api/digests")
def api_list_digests():
    # sent_at is stored as UTC (see db.py/poller.py) - converted to
    # DISPLAY_TZ here, at the API boundary, same as alerting.py does for
    # the email itself. Raw UTC stays canonical in the database.
    return [{**d, "sent_at": tz.format_local(d["sent_at"])} for d in db.list_digests()]


@app.get("/api/digests/{digest_id}")
def api_get_digest(digest_id: str):
    digest = db.get_digest(digest_id)
    if digest is None:
        raise HTTPException(status_code=404, detail="digest not found")
    digest["sent_at"] = tz.format_local(digest["sent_at"])
    digest["items"] = [{**item, "timestamp": tz.format_local(item["timestamp"])} for item in digest["items"]]
    return digest


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
