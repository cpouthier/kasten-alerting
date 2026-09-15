# kasten-alerting

Alerts on Kasten K10 action failures (and any other outcome you care
about) by email - BackupAction, RestoreAction, ExportAction, RunAction, and
every other action kind Kasten exposes.

---

## Why this polls instead of watching

Kasten explicitly disables `watch` on every `actions.kio.kasten.io` kind.

So there's no event-driven alternative - this app periodically lists every
selected action kind and diffs against what it's already seen. 
The interval is configurable on the Settings page (minimum 60s).

**First-run safety**: the very first time a given action kind is polled,
either this app's first-ever boot, or the first poll after you newly
select a kind in Settings, every currently-terminal object of that kind
is silently marked "seen" without triggering an alert (a "baseline" pass).
Without this, turning on e.g. Retire (which can already have thousands of
objects on a cluster with a long history) would otherwise dump its entire
backlog into one digest email. From the next poll onward, only genuinely
new terminal-state actions are ever reported.

## What triggers an email

One digest email per poll cycle that found at least one new action whose
kind and status you've selected, not one email per action, so an incident
that fails many actions at once (a storage outage, say) can't flood your
inbox. Each digest lists every action it covers: kind, action name, policy
name (when the action came from a policy - `k10.kasten.io/policyName`),
namespace, timestamp, and, for anything that failed, the full error/cause
chain Kasten recorded on the object itself (`status.error`).

Toggling alerting off in Settings doesn't stop the polling/bookkeeping,
only the emailing - so nothing piles up into a flood the moment you turn
it back on.

## Action kinds monitored

Every kind that supports `get`/`list` (13 of the 14 `actions.kio.kasten.io`
kinds - `CancelAction` only supports `create`, so there's nothing on it to
ever poll): **BackupAction, RestoreAction, ExportAction, ValidateAction,
RunAction**, BatchRestoreAction, ImportAction, BackupClusterAction,
RestoreClusterAction, StageAction, UpgradeAction, ReportAction, and
RetireAction. 
The first five are selected by default; the rest (mostly
rarer or, in Retire's case, very high-volume housekeeping) are available
to enable in Settings but off by default.

Statuses: `Complete`, `Failed`, `Cancelled`, `Skipped` - one shared filter
across every selected kind. `Failed`/`Cancelled`/`Skipped` are on by
default, `Complete` is off (alerting on every single success would be
noisy) but available if you want a full audit trail.

---

## Deploying

```bash
helm upgrade --install kasten-alerting ./helm/kasten-alerting \
  --namespace kasten-alerting --create-namespace \
  --set image.repository=<you>/kasten-alerting \
  --set storageClass=<your-storage-class> \
  --set timezone=Europe/Paris
```

`timezone` (an IANA name, e.g. `Europe/Paris`) is what the digest email and
History tab display timestamps in - Kasten's own timestamps are always UTC
regardless of where the cluster physically runs (containers default to UTC
too), so without this every timestamp reads a few hours off from your
cluster's actual wall-clock time. Defaults to `UTC` if left unset.

On OpenShift, set `service.type=ClusterIP` and `route.enabled=true`
instead of relying on a LoadBalancer - see `values.yaml`.

### RBAC

Cluster-scoped, `get`/`list` only, on the 13 pollable action kinds above,
plus the usual `secrets` verbs in this app's own namespace for the SMTP
password (same write-only pattern as malware-scan's own SMTP alerting -
the password is never round-tripped back to the browser once saved, only
whether one is currently set). See `helm/kasten-alerting/templates/
clusterrole.yaml` for the exact rule set.

---

## Local development

```bash
cd app
pip install -r requirements.txt
DATA_DIR=/tmp/kasten-alerting-data uvicorn main:app --reload
```

Needs `kubectl` on PATH and a working `KUBECONFIG` pointed at a cluster
with Kasten installed - there's no mock mode.
