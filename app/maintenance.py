"""Periodic reconciliation of db.seen_actions against what's actually
still in the cluster - the dedup bookkeeping poller.py relies on
(db.is_seen/mark_seen) only ever grows on its own, even for an action
Kasten itself has since garbage-collected (RunAction and RetireAction
especially churn through thousands of objects over a cluster's lifetime -
see k10.ACTION_KINDS). Nothing else in this app ever needs a stale row
again once the object it describes is gone, so this deletes it.

Runs weekly by default (settings.DEFAULT_MAINTENANCE), configurable on
the Settings page - same run_forever/run_once split and manual "run now"
trigger as poller.py.
"""
import asyncio
import logging
import uuid
from datetime import datetime, timezone

import db
import k10
import settings

logger = logging.getLogger("kasten-alerting.maintenance")


async def run_once() -> None:
    run_id = uuid.uuid4().hex[:12]
    ran_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    kinds_checked = 0
    rows_removed = 0
    error = None

    try:
        for kind_label in db.seen_kinds():
            kind_cfg = k10.ACTION_KIND_BY_LABEL.get(kind_label)
            if kind_cfg is None:
                # A kind this app polled under an older version and no
                # longer knows about at all - nothing to reconcile against,
                # leave its rows alone rather than guessing.
                continue
            kinds_checked += 1
            try:
                live_objects = await k10.list_actions(kind_cfg["id"])
            except k10.KubectlError:
                logger.exception("failed to list %s during maintenance (skipping this kind)", kind_cfg["id"])
                continue
            live_uids = {obj.get("metadata", {}).get("uid") for obj in live_objects}
            live_uids.discard(None)
            stale_uids = db.seen_uids_for_kind(kind_label) - live_uids
            removed = db.delete_seen(stale_uids)
            rows_removed += removed
            if removed:
                logger.info("maintenance: removed %d stale %s row(s) no longer in the cluster", removed, kind_label)
    except Exception as exc:
        logger.exception("maintenance run failed")
        error = str(exc)

    db.insert_maintenance_run(run_id, ran_at, kinds_checked, rows_removed, error)


async def run_forever() -> None:
    while True:
        cfg = settings.get_maintenance()
        if cfg["enabled"]:
            try:
                await run_once()
            except Exception:
                logger.exception("maintenance cycle failed unexpectedly")
        interval_days = max(cfg["interval_days"], settings.MIN_MAINTENANCE_INTERVAL_DAYS)
        await asyncio.sleep(interval_days * 86400)
