"""SQLite state on the same PVC as settings.json - two independent jobs:

1. Dedup bookkeeping (seen_actions, kind_baseline) so poller.py never
   alerts on the same action twice, and never floods a digest with an
   action kind's entire pre-existing history the first time it's polled
   (either on this app's first-ever boot, or the first poll after a kind
   gets newly selected in Settings) - see poller.run_once for how these two
   tables are actually used together.
2. The alert history the Settings page's History tab shows (digests) -
   one row per digest email actually sent, each holding the full list of
   actions it covered so a past alert can be reopened later, the same way
   malware-scan's own History page reopens a past scan.
"""
import json
import os
import sqlite3
from contextlib import contextmanager

DB_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "alerts.db")


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    with _connect() as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS seen_actions (
                uid TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                namespace TEXT,
                state TEXT NOT NULL,
                seen_at TEXT NOT NULL
            )"""
        )
        conn.execute("CREATE TABLE IF NOT EXISTS kind_baseline (kind_id TEXT PRIMARY KEY, baselined_at TEXT NOT NULL)")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS digests (
                id TEXT PRIMARY KEY,
                sent_at TEXT NOT NULL,
                item_count INTEGER NOT NULL,
                items_json TEXT NOT NULL,
                email_error TEXT
            )"""
        )


def is_seen(uid: str) -> bool:
    with _connect() as conn:
        return conn.execute("SELECT 1 FROM seen_actions WHERE uid = ?", (uid,)).fetchone() is not None


def mark_seen(uid: str, kind: str, name: str, namespace: str, state: str, seen_at: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO seen_actions (uid, kind, name, namespace, state, seen_at) VALUES (?, ?, ?, ?, ?, ?)",
            (uid, kind, name, namespace, state, seen_at),
        )


def is_baselined(kind_id: str) -> bool:
    with _connect() as conn:
        return conn.execute("SELECT 1 FROM kind_baseline WHERE kind_id = ?", (kind_id,)).fetchone() is not None


def mark_baselined(kind_id: str, baselined_at: str) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO kind_baseline (kind_id, baselined_at) VALUES (?, ?)",
            (kind_id, baselined_at),
        )


def insert_digest(digest_id: str, sent_at: str, items: list[dict], email_error: str | None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO digests (id, sent_at, item_count, items_json, email_error) VALUES (?, ?, ?, ?, ?)",
            (digest_id, sent_at, len(items), json.dumps(items), email_error),
        )


def list_digests(limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, sent_at, item_count, email_error FROM digests ORDER BY sent_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_digest(digest_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM digests WHERE id = ?", (digest_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["items"] = json.loads(d.pop("items_json"))
        return d
