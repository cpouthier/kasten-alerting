# kasten-alerting

Alerts on Veeam Kasten action failures (and any other outcome you care
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

Statuses: `Complete`, `Failed`, `Cancelled`, `Skipped` (one shared filter
across every selected kind). Only `Failed` is on by default - the one
unambiguous "something is actually wrong" outcome; `Cancelled`/`Skipped`
(usually a manual cancel, a policy skipping a namespace it
already handled) and `Complete` (a full audit trail of successes too) are
available to enable in Settings.

---

## Deploying

The image is published at `docker.io/cpouthier/kasten-alerting` (multi-arch:
`linux/amd64` + `linux/arm64`) - the chart already points at it by default,
no build step needed.

### Standard Kubernetes

```bash
helm upgrade --install kasten-alerting ./helm/kasten-alerting \
  --namespace kasten-alerting --create-namespace \
  --set storageClass=<your-storage-class> \
  --set timezone=Europe/Paris
```

- `storageClass` is required - must already exist in your cluster
  (`kubectl get storageclass`). Backs the 1Gi PVC holding `settings.json`
  and the SQLite dedup/history database (`app/settings.py`, `app/db.py`).
- `timezone` (an IANA name, e.g. `Europe/Paris`) is what the digest email
  and History tab display timestamps in - Kasten's own timestamps are
  always UTC regardless of where the cluster physically runs, so without
  this every timestamp reads a few hours off from your own wall-clock
  time. Defaults to `UTC`. This can't be auto-detected from the cluster
  itself - see `app/tz.py`'s docstring for why.
- `service.type` defaults to `LoadBalancer` (e.g. MetalLB). If your
  cluster has no LoadBalancer implementation, switch to `ClusterIP`
  (`--set service.type=ClusterIP`) and reach it with
  `kubectl -n kasten-alerting port-forward svc/kasten-alerting 8080:80`
  instead.

### OpenShift

Same chart - swap the LoadBalancer Service for a Route:

```bash
helm upgrade --install kasten-alerting ./helm/kasten-alerting \
  --namespace kasten-alerting --create-namespace \
  --set storageClass=<your-storage-class> \
  --set timezone=Europe/Paris \
  --set service.type=ClusterIP \
  --set route.enabled=true
```

- `route.host` pins a specific hostname (`--set
  route.host=kasten-alerting.apps.example.com`); left empty, OpenShift
  generates one from the route name + namespace + cluster's default
  subdomain.
- `route.tls.termination` defaults to `edge` (TLS ends at the router -
  this app itself only ever serves plain HTTP).
- No SecurityContextConstraints changes needed: this app never requests a
  privileged container or any non-default SCC.
- At runtime, the app itself detects OpenShift (checking for the
  `security.openshift.io` API group) and uses `oc` instead of `kubectl`
  for every cluster call from then on, matching what a human operator
  would use - see `app/k10.py`'s `_kubectl_binary`. Nothing to configure
  for this; it's automatic either way.

---

## RBAC

Two separate objects, deliberately scoped as narrowly as each job allows -
see `helm/kasten-alerting/templates/{clusterrole,role}.yaml` for the exact
YAML.

**ClusterRole `kasten-alerting`** (cluster-scoped, bound cluster-wide via
`ClusterRoleBinding`) - `get`/`list` only, on the 13 `actions.kio.kasten.io`
kinds this app can poll:

```
backupactions, backupclusteractions, batchrestoreactions, exportactions,
importactions, reportactions, restoreactions, restoreclusteractions,
retireactions, runactions, stageactions, upgradeactions, validateactions
```

This has to be cluster-scoped: an action lives in whichever namespace its
source application does (or has no namespace at all for the three
cluster-scoped kinds - BackupClusterAction, RestoreClusterAction,
RetireAction), not a fixed namespace this chart controls, and this app
needs to see every one of them regardless of where they land. `get`/`list`
only - this app only ever observes, it never creates, deletes, or modifies
a Kasten action. `CancelAction` (the 14th `actions.kio.kasten.io` kind) is
deliberately absent: its API only supports `create` (it's a command, not a
queryable object), so a `get`/`list` grant on it would be meaningless.

**Role `kasten-alerting`** (namespaced, bound only within the release
namespace via `RoleBinding`) - on `secrets`:

```
get, list, watch, create, patch, delete
```

This app only ever touches one Secret, its own SMTP password
(`kasten-alerting-smtp`), always in its own namespace - so unlike the
action kinds above, this is intentionally *not* in the ClusterRole, which
would otherwise mean a grant on every Secret in every namespace cluster-
wide. `create`+`patch` because saving the password goes through `kubectl
apply` (create on the first save, patch on every one after); `delete` is
for clearing it from the Settings page. The password itself is
write-only end to end: the API never returns it once saved, only whether
one is currently set (`has_password`).

Nothing else is granted - no access to Pods, logs, ConfigMaps, or any
other resource. Unlike malware-scan (which restores data into scratch
namespaces and runs scanner pods), this app only ever reads Kasten action
objects and manages its own Secret.

---