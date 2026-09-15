"""Display-timezone conversion. Every timestamp this app reads from Kasten
(status.endTime/startTime, metadata.creationTimestamp) is UTC - RFC3339
with a trailing "Z" - regardless of where the cluster physically runs, and
so is sent_at (this app's own "when was this digest sent", set with
datetime.now(timezone.utc) in poller.py). Storage (db.py) and internal
comparisons/ordering stay on those raw UTC strings on purpose - only the
two actual output boundaries (alerting.py's email, main.py's API
responses feeding the Settings/History UI) convert to DISPLAY_TZ, right
before rendering.

DISPLAY_TZ comes from this container's own TZ env var (see
helm/kasten-alerting/values.yaml's `timezone`, plumbed into
deployment.yaml) - defaults to UTC, same as the container would show
unset. Set it to the cluster's actual timezone (e.g. "Europe/Paris") so a
digest reads in the same wall-clock time the cluster's own logs/cron
would, not UTC.
"""
import os
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    DISPLAY_TZ = ZoneInfo(os.environ.get("TZ", "UTC"))
except ZoneInfoNotFoundError:
    DISPLAY_TZ = ZoneInfo("UTC")


def format_local(iso_str: str) -> str:
    """Converts a UTC RFC3339 timestamp to DISPLAY_TZ, formatted for
    humans (email/UI), e.g. "2026-08-03 17:39:38 CEST". Falls back to the
    raw string unparsed (empty, or an unexpected shape) rather than
    raising - a formatting glitch here should never break a digest send."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return iso_str
    return dt.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
