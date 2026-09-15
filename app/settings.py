"""App-wide settings, persisted as JSON on the shared PVC (same pattern as
cpouthier/malware-scan's app/settings.py) - so they survive a pod restart.

The SMTP *password* is deliberately NOT stored here: like malware-scan's
own settings.py, it's real credential material, not just config, so it
lives in a Kubernetes Secret instead (see k10.py/alerting.py). Every other
field, including which action kinds/statuses to alert on and how often to
poll, is fine as plaintext JSON, same trust level as everything else here.
"""
import json
import logging
import os

import k10

logger = logging.getLogger("kasten-alerting.settings")

SETTINGS_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "settings.json")

MIN_POLL_INTERVAL_SECONDS = 60  # a floor, not a suggestion - see _validate

DEFAULT_ALERTING = {
    "enabled": False,
    "action_kinds": [k["id"] for k in k10.ACTION_KINDS if k["default_selected"]],
    # Shared across every selected action kind (see the "one filter for
    # everything" design decision) - only "Failed" by default, the one
    # unambiguous "something is actually wrong" outcome; Cancelled/Skipped/
    # Complete are usually routine (a policy skipping a namespace it
    # already handled, a manual cancel, an ordinary success) and available
    # to enable in Settings for anyone who wants a fuller audit trail.
    "statuses": ["Failed"],
    # Policy names (k10.kasten.io/policyName) to never alert on, even if
    # their actions otherwise match action_kinds/statuses above - e.g. a
    # cluster's own k10-disaster-recovery-policy, whose BackupActions are
    # routine self-backup noise for most people. Bookkeeping (seen_actions)
    # still runs for these, same as a kind/status that isn't selected - see
    # poller._poll_kind.
    "excluded_policies": [],
    "poll_interval_seconds": 300,
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_security": "starttls",  # "none" | "starttls" | "ssl"
    "smtp_username": "",
    "from_address": "",
    "to_addresses": [],
}

_SETTINGS: dict = {}


def init() -> None:
    _load()


def _load() -> None:
    global _SETTINGS
    if not os.path.exists(SETTINGS_FILE):
        _SETTINGS = {"alerting": dict(DEFAULT_ALERTING)}
        return
    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("failed to read %s, starting with defaults: %s", SETTINGS_FILE, exc)
        data = {}
    # Merge onto defaults, not the file's shape outright - a field added
    # after this was first saved (e.g. a new action kind) would otherwise
    # silently be missing instead of falling back sanely.
    alerting = {**DEFAULT_ALERTING, **data.get("alerting", {})}
    _SETTINGS = {"alerting": alerting}


def _save() -> None:
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    tmp = f"{SETTINGS_FILE}.tmp"
    with open(tmp, "w") as f:
        json.dump(_SETTINGS, f, indent=2)
    os.replace(tmp, SETTINGS_FILE)


def get_alerting() -> dict:
    return dict(_SETTINGS.get("alerting", DEFAULT_ALERTING))


def update_alerting(**fields) -> dict:
    current = get_alerting()
    current.update(fields)
    _validate_alerting(current)
    _SETTINGS["alerting"] = current
    _save()
    return current


def _validate_alerting(cfg: dict) -> None:
    unknown_kinds = set(cfg.get("action_kinds") or []) - set(k10.ACTION_KIND_BY_ID)
    if unknown_kinds:
        raise ValueError(f"unknown action kind(s): {', '.join(sorted(unknown_kinds))}")
    unknown_statuses = set(cfg.get("statuses") or []) - set(k10.TERMINAL_STATES)
    if unknown_statuses:
        raise ValueError(f"unknown status(es): {', '.join(sorted(unknown_statuses))}")
    interval = int(cfg.get("poll_interval_seconds") or 0)
    if interval < MIN_POLL_INTERVAL_SECONDS:
        raise ValueError(f"poll_interval_seconds must be at least {MIN_POLL_INTERVAL_SECONDS}")

    if cfg["enabled"]:
        if not cfg.get("action_kinds"):
            raise ValueError("select at least one action kind to monitor")
        if not cfg.get("statuses"):
            raise ValueError("select at least one status to alert on")
        if not cfg.get("smtp_host"):
            raise ValueError("smtp_host is required when alerting is enabled")
        if not (1 <= int(cfg.get("smtp_port") or 0) <= 65535):
            raise ValueError("smtp_port must be between 1 and 65535")
        if cfg.get("smtp_security") not in ("none", "starttls", "ssl"):
            raise ValueError('smtp_security must be "none", "starttls" or "ssl"')
        if not cfg.get("from_address"):
            raise ValueError("from_address is required when alerting is enabled")
        if not cfg.get("to_addresses"):
            raise ValueError("at least one recipient (to_addresses) is required when alerting is enabled")
