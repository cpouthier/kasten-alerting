"""SQLite state on the same PVC as settings.json - three independent jobs:

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
3. A log of maintenance.py's periodic seen_actions reconciliation
   (maintenance_runs) - seen_actions otherwise only ever grows, even for
   actions Kasten itself has since garbage-collected, so this deletes rows
   whose uid is no longer live and keeps a short record of what happened.
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
        conn.execute(
            """CREATE TABLE IF NOT EXISTS maintenance_runs (
                id TEXT PRIMARY KEY,
                ran_at TEXT NOT NULL,
                kinds_checked INTEGER NOT NULL,
                rows_removed INTEGER NOT NULL,
                error TEXT
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


def seen_kinds() -> list[str]:
    """Every distinct Kind currently present in seen_actions - what
    maintenance.py needs to reconcile, independent of which kinds are
    *currently* selected in Settings (a kind someone later unselects still
    has old bookkeeping worth cleaning up)."""
    with _connect() as conn:
        rows = conn.execute("SELECT DISTINCT kind FROM seen_actions").fetchall()
        return [row["kind"] for row in rows]


def seen_uids_for_kind(kind: str) -> set[str]:
    with _connect() as conn:
        rows = conn.execute("SELECT uid FROM seen_actions WHERE kind = ?", (kind,)).fetchall()
        return {row["uid"] for row in rows}


def delete_seen(uids: set[str]) -> int:
    if not uids:
        return 0
    with _connect() as conn:
        placeholders = ",".join("?" * len(uids))
        cur = conn.execute(f"DELETE FROM seen_actions WHERE uid IN ({placeholders})", tuple(uids))
        return cur.rowcount


def insert_maintenance_run(run_id: str, ran_at: str, kinds_checked: int, rows_removed: int, error: str | None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO maintenance_runs (id, ran_at, kinds_checked, rows_removed, error) VALUES (?, ?, ?, ?, ?)",
            (run_id, ran_at, kinds_checked, rows_removed, error),
        )


def last_maintenance_run() -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM maintenance_runs ORDER BY ran_at DESC LIMIT 1").fetchone()
        return dict(row) if row else None
