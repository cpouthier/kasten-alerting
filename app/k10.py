"""Thin async wrapper around kubectl/oc for the two things this app needs:
listing Kasten action objects (poller.py) and reading/writing this app's own
SMTP credentials Secret (settings.py/alerting.py). Same shelling-out pattern
as cpouthier/malware-scan's app/k10.py, including its "oc" on OpenShift /
"kubectl" everywhere else auto-detection - see _kubectl_binary below.
"""
import asyncio
import base64
import json
import logging
import shutil

logger = logging.getLogger("kasten-alerting.k10")

APP_NAMESPACE = "kasten-alerting"

# Every Kasten action kind that supports "get"/"list" (see README's RBAC
# section for how this was verified) - actions.kio.kasten.io/v1alpha1,
# CancelAction excluded on purpose: the API only supports "create" on it
# (it's a command, not an observable object - `kubectl get cancelactions`
# 404s outright), so there's nothing here to ever poll.
ACTION_KINDS = [
    {"id": "backupactions", "kind": "BackupAction", "label": "Backup", "default_selected": True},
    {"id": "restoreactions", "kind": "RestoreAction", "label": "Restore", "default_selected": True},
    {"id": "exportactions", "kind": "ExportAction", "label": "Export", "default_selected": True},
    {"id": "validateactions", "kind": "ValidateAction", "label": "Validate", "default_selected": True},
    {"id": "runactions", "kind": "RunAction", "label": "Run (policy execution)", "default_selected": True},
    {"id": "batchrestoreactions", "kind": "BatchRestoreAction", "label": "Batch Restore", "default_selected": False},
    {"id": "importactions", "kind": "ImportAction", "label": "Import", "default_selected": False},
    {"id": "backupclusteractions", "kind": "BackupClusterAction", "label": "Backup Cluster", "default_selected": False},
    {"id": "restoreclusteractions", "kind": "RestoreClusterAction", "label": "Restore Cluster", "default_selected": False},
    {"id": "stageactions", "kind": "StageAction", "label": "Stage", "default_selected": False},
    {"id": "upgradeactions", "kind": "UpgradeAction", "label": "Upgrade", "default_selected": False},
    {"id": "reportactions", "kind": "ReportAction", "label": "Report", "default_selected": False},
    # Kasten's own retention housekeeping (cleans up expired RestorePoints) -
    # fires constantly and in bulk on any cluster with active policies
    # (thousands of objects even on a small homelab), so left off by default
    # even though it's fully supported like every other kind here.
    {"id": "retireactions", "kind": "RetireAction", "label": "Retire (housekeeping, high volume)", "default_selected": False},
]
ACTION_KIND_BY_ID = {k["id"]: k for k in ACTION_KINDS}
# poller.py stores the Kubernetes Kind (e.g. "BackupAction"), not the
# resource id (e.g. "backupactions"), against each row in db.seen_actions -
# maintenance.py needs this reverse lookup to know which resource to list
# when reconciling a given kind's bookkeeping against the live cluster.
ACTION_KIND_BY_LABEL = {k["kind"]: k for k in ACTION_KINDS}

# The 4 terminal states a Kasten action can end in - see README for how
# this was confirmed against a live cluster. Anything else (Running,
# Pending, ...) is still in progress and never alerted on; poller.py simply
# leaves those for a later poll once they reach one of these.
TERMINAL_STATES = ["Complete", "Failed", "Cancelled", "Skipped"]


class KubectlError(RuntimeError):
    def __init__(self, args, rc, stderr, binary="kubectl"):
        super().__init__(f"{binary} {' '.join(args)} failed ({rc}): {stderr.strip()}")
        self.rc = rc
        self.stderr = stderr


async def _exec(binary: str, args, input_data: bytes | None = None) -> str:
    proc = await asyncio.create_subprocess_exec(
        binary, *args,
        stdin=asyncio.subprocess.PIPE if input_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate(input_data)
    if proc.returncode != 0:
        raise KubectlError(args, proc.returncode, stderr.decode(errors="replace"), binary)
    return stdout.decode(errors="replace")


_is_openshift_cache: bool | None = None
_kubectl_binary_cache: str | None = None


async def _is_openshift() -> bool:
    global _is_openshift_cache
    if _is_openshift_cache is None:
        try:
            out = await _exec("kubectl", ["get", "--raw", "/apis"])
            groups = json.loads(out).get("groups", [])
            _is_openshift_cache = any(g.get("name") == "security.openshift.io" for g in groups)
        except (KubectlError, json.JSONDecodeError, OSError):
            logger.exception("failed to detect OpenShift vs plain Kubernetes - assuming plain Kubernetes")
            _is_openshift_cache = False
    return _is_openshift_cache


async def _kubectl_binary() -> str:
    global _kubectl_binary_cache
    if _kubectl_binary_cache is None:
        _kubectl_binary_cache = "oc" if (await _is_openshift() and shutil.which("oc")) else "kubectl"
    return _kubectl_binary_cache


async def run_kubectl(args, input_data: bytes | None = None) -> str:
    return await _exec(await _kubectl_binary(), args, input_data)


async def list_actions(resource_plural: str) -> list[dict]:
    """All objects of one action kind, cluster-wide. Kasten explicitly
    disables "watch" on every actions.kio.kasten.io kind (confirmed live -
    see README), so this is a plain list call, not an informer - poller.py
    is what turns repeated calls to this into "what's new since last time"."""
    out = await run_kubectl(["get", resource_plural, "-A", "-o", "json"])
    return json.loads(out).get("items", [])


async def create_secret(namespace: str, name: str, string_data: dict[str, str]):
    manifest = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": "Opaque",
        "stringData": string_data,
    }
    await run_kubectl(["apply", "-f", "-", "-o", "json", "--validate=false"], json.dumps(manifest).encode())


async def delete_secret(namespace: str, name: str):
    await run_kubectl(["delete", "secret", name, "-n", namespace, "--ignore-not-found", "--wait=false"])


async def get_secret_data(namespace: str, name: str) -> dict[str, str] | None:
    try:
        out = await run_kubectl(["get", "secret", name, "-n", namespace, "-o", "json"])
    except KubectlError as exc:
        if "NotFound" in exc.stderr:
            return None
        raise
    data = json.loads(out).get("data") or {}
    return {k: base64.b64decode(v).decode() for k, v in data.items()}
