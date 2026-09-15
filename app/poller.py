"""Polling loop: Kasten explicitly disables "watch" on every action kind
(confirmed live against a real cluster - `kubectl get backupactions -A
--watch` and `kubectl get runactions -A --watch` both return "Error from
server (MethodNotAllowed): watch is not supported..."), so there's no
event-driven alternative here - this periodically lists each selected
action kind and diffs against what's already been seen (db.py).

Two things keep a poll cycle from ever flooding a digest with pre-existing
history instead of genuinely new events:

1. Only a NEWLY-terminal action (uid not yet in db.seen_actions) is a
   candidate at all - one already seen on an earlier cycle is skipped
   outright, whether or not it matches the current alert filter.
2. The first time a given action kind is ever polled (this app's first
   boot, or the first poll after that kind gets newly selected in
   Settings), every currently-terminal object of that kind is silently
   marked seen without being included in this cycle's digest - a "kind
   baseline" (db.is_baselined/mark_baselined). Without this, enabling e.g.
   RetireAction on a cluster that already has thousands of them would
   otherwise dump its entire history into one digest email.

Non-terminal actions (Running, Pending, ...) are never marked seen at all -
they're simply left for a later cycle once they reach one of
k10.TERMINAL_STATES.
"""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

import alerting
import db
import k10
import settings

logger = logging.getLogger("kasten-alerting.poller")


def _extract_error(error: dict | None) -> tuple[str, list[str]]:
    """Kasten's status.error is {"message": "...", "cause": "<JSON string>"}
    - the cause, once parsed, is a chain of nested {"cause": {...},
    "message": "..."} dicts (Kanister's error-wrapping convention), each
    level adding context around the one before it. Flattened here into an
    ordered list of messages, outermost ("Job failed to be executed") first
    - the way a human would actually want to read it, rather than the raw
    JSON blob."""
    if not error:
        return "", []
    top_message = error.get("message") or ""
    lines = [top_message] if top_message else []
    cause = error.get("cause")
    if isinstance(cause, str):
        try:
            cause = json.loads(cause)
        except (ValueError, TypeError):
            cause = None
    while isinstance(cause, dict):
        msg = cause.get("message")
        if msg:
            lines.append(msg)
        cause = cause.get("cause")
    return top_message, lines


def _extract(kind_label: str, obj: dict) -> dict:
    meta = obj.get("metadata", {}) or {}
    labels = meta.get("labels", {}) or {}
    status = obj.get("status", {}) or {}
    spec = obj.get("spec", {}) or {}
    subject = spec.get("subject", {}) or {}

    namespace = labels.get("k10.kasten.io/appNamespace") or subject.get("namespace") or meta.get("namespace") or ""
    policy_name = labels.get("k10.kasten.io/policyName") or ""
    timestamp = status.get("endTime") or status.get("startTime") or meta.get("creationTimestamp") or ""
    error_message, error_lines = _extract_error(status.get("error"))

    return {
        "uid": meta.get("uid"),
        "kind": kind_label,
        "name": meta.get("name"),
        "namespace": namespace,
        "policy_name": policy_name,
        "state": status.get("state") or "",
        "timestamp": timestamp,
        "error_message": error_message,
        "error_lines": error_lines,
    }


async def _poll_kind(kind_cfg: dict, alert_statuses: set[str]) -> list[dict]:
    """Returns items newly discovered this cycle that match alert_statuses -
    empty during a kind's baseline pass, or whenever nothing new turned up."""
    kind_id, kind_label = kind_cfg["id"], kind_cfg["kind"]
    try:
        objects = await k10.list_actions(kind_id)
    except k10.KubectlError:
        logger.exception("failed to list %s this cycle (skipping)", kind_id)
        return []

    baselining = not db.is_baselined(kind_id)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    new_items = []

    for obj in objects:
        item = _extract(kind_label, obj)
        if item["state"] not in k10.TERMINAL_STATES or not item["uid"]:
            continue
        if db.is_seen(item["uid"]):
            continue
        db.mark_seen(item["uid"], kind_label, item["name"], item["namespace"], item["state"], now)
        if not baselining and item["state"] in alert_statuses:
            new_items.append(item)

    if baselining:
        db.mark_baselined(kind_id, now)
        logger.info("baselined %s: %d pre-existing terminal object(s) marked seen, none alerted", kind_id, len(objects))

    return new_items


async def run_once() -> None:
    cfg = settings.get_alerting()
    alert_statuses = set(cfg["statuses"])
    selected_kinds = [k10.ACTION_KIND_BY_ID[k] for k in cfg["action_kinds"] if k in k10.ACTION_KIND_BY_ID]

    all_new_items: list[dict] = []
    for kind_cfg in selected_kinds:
        all_new_items.extend(await _poll_kind(kind_cfg, alert_statuses))

    if not all_new_items:
        return

    logger.info("%d new alertable action(s) this cycle", len(all_new_items))
    if not cfg["enabled"]:
        # Bookkeeping (seen_actions/kind_baseline) still ran above so
        # nothing piles up while alerting is off - just no email while
        # it's toggled off, same as malware-scan's own email_alerts.enabled.
        return

    digest_id = uuid.uuid4().hex[:12]
    sent_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    email_error = None
    try:
        await alerting.send_digest(cfg, all_new_items)
    except Exception as exc:
        logger.exception("failed to send digest email")
        email_error = str(exc)
    db.insert_digest(digest_id, sent_at, all_new_items, email_error)


async def run_forever() -> None:
    while True:
        try:
            await run_once()
        except Exception:
            logger.exception("poll cycle failed unexpectedly")
        interval = max(settings.get_alerting()["poll_interval_seconds"], settings.MIN_POLL_INTERVAL_SECONDS)
        await asyncio.sleep(interval)
