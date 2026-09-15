"""App-wide settings, persisted as JSON on the shared PVC (same pattern as
cpouthier/malware-scan's app/settings.py) - so they survive a pod restart.

Real credential material is deliberately NOT stored here, same split as
malware-scan's own settings.py: the SMTP password (see alerting.py) and
the SNMP v2c community string / v3 auth+priv passwords (see snmp_trap.py)
each live in their own Kubernetes Secret instead. Every other field,
including which action kinds/statuses to alert on, how often to poll, and
the non-secret SNMP connection details (host/port/version/username/
protocols), is fine as plaintext JSON, same trust level as everything
else here.
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
    # SNMP traps are an independent delivery channel from email above -
    # its own enabled flag, not gated by `enabled` (which only ever
    # controls the digest email) - see poller.run_once. One trap per
    # alertable action, not batched into a digest; see snmp_trap.py.
    "snmp_enabled": False,
    "snmp_host": "",
    "snmp_port": 162,
    "snmp_version": "v2c",  # "v2c" | "v3"
    "snmp_v3_username": "",
    "snmp_v3_auth_protocol": "sha",  # "sha" | "md5" | "none"
    "snmp_v3_priv_protocol": "aes",  # "aes" | "des" | "none"
    # This app's own SNMPv3 engineID (RFC3411), minus the fixed enterprise
    # prefix - generated once, on first use, and never afterward; see
    # snmp_trap._get_engine_id for why this can never just be regenerated
    # per restart without breaking every NMS already configured for it.
    "snmp_engine_id_suffix": "",
}

# Weekly reconciliation of db.seen_actions against what's actually still
# in the cluster - Kasten itself can eventually garbage-collect old action
# objects (RunAction/RetireAction especially, see k10.ACTION_KINDS), at
# which point this app's own bookkeeping of their UIDs is pure dead
# weight with nothing left to ever reference it again. See maintenance.py.
DEFAULT_MAINTENANCE = {
    "enabled": True,
    "interval_days": 7,
}
MIN_MAINTENANCE_INTERVAL_DAYS = 1

_SETTINGS: dict = {}


def init() -> None:
    _load()


def _load() -> None:
    global _SETTINGS
    if not os.path.exists(SETTINGS_FILE):
        _SETTINGS = {"alerting": dict(DEFAULT_ALERTING), "maintenance": dict(DEFAULT_MAINTENANCE)}
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
    maintenance = {**DEFAULT_MAINTENANCE, **data.get("maintenance", {})}
    _SETTINGS = {"alerting": alerting, "maintenance": maintenance}


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


def get_maintenance() -> dict:
    return dict(_SETTINGS.get("maintenance", DEFAULT_MAINTENANCE))


def update_maintenance(**fields) -> dict:
    current = get_maintenance()
    current.update(fields)
    interval = int(current.get("interval_days") or 0)
    if interval < MIN_MAINTENANCE_INTERVAL_DAYS:
        raise ValueError(f"interval_days must be at least {MIN_MAINTENANCE_INTERVAL_DAYS}")
    _SETTINGS["maintenance"] = current
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

    if cfg.get("snmp_enabled"):
        if not cfg.get("snmp_host"):
            raise ValueError("snmp_host is required when SNMP trapping is enabled")
        if not (1 <= int(cfg.get("snmp_port") or 0) <= 65535):
            raise ValueError("snmp_port must be between 1 and 65535")
        if cfg.get("snmp_version") not in ("v2c", "v3"):
            raise ValueError('snmp_version must be "v2c" or "v3"')
        if cfg["snmp_version"] == "v3":
            if not cfg.get("snmp_v3_username"):
                raise ValueError("snmp_v3_username is required for SNMPv3")
            if cfg.get("snmp_v3_auth_protocol") not in ("sha", "md5", "none"):
                raise ValueError('snmp_v3_auth_protocol must be "sha", "md5" or "none"')
            if cfg.get("snmp_v3_priv_protocol") not in ("aes", "des", "none"):
                raise ValueError('snmp_v3_priv_protocol must be "aes", "des" or "none"')
            if cfg["snmp_v3_priv_protocol"] != "none" and cfg["snmp_v3_auth_protocol"] == "none":
                raise ValueError("SNMPv3 privacy (encryption) requires authentication to also be enabled")
