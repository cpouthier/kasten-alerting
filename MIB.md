# KASTEN-ALERTING-MIB

kasten-alerting can send one SNMP trap per detected action (Failed,
Cancelled, Skipped, or Complete - whatever you've selected in Settings),
in addition to or instead of the digest email. This document is the human
reference for `mibs/KASTEN-ALERTING-MIB.mib` - what each object means, how
to import it into an NMS, and the SNMPv3 quirk that trips up most people
the first time.

> ⚠️ **Placeholder enterprise number.** This MIB is registered under
> `enterprises.99999` (`1.3.6.1.4.1.99999`), which is **not** an
> IANA-assigned Private Enterprise Number for this project - it's a
> commonly-used placeholder, picked because this is a personal/internal
> tool with no PEN of its own. On a shared NMS that also loads other
> vendors' MIBs, a placeholder number is never guaranteed to be conflict-
> free. If that matters to you, register a free PEN at
> [pen.iana.org](https://pen.iana.org) and renumber both the MIB (the
> `::= { enterprises 99999 }` line) and the matching OIDs in
> `app/snmp_trap.py` (`_BASE_OID`) before relying on this in a shared
> environment.

---

## Importing the MIB

The file is plain SMIv2, no non-standard dependencies beyond the usual
`SNMPv2-SMI`/`SNMPv2-TC`/`SNMPv2-CONF` every NMS already ships:

- **net-snmp** (`snmptrapd`, `snmptranslate`, ...): copy
  `mibs/KASTEN-ALERTING-MIB.mib` into a directory on your `MIBDIRS`
  (e.g. `/usr/share/snmp/mibs/`, or pass `-M <dir>` to point at it
  directly), then reference it as `-m KASTEN-ALERTING-MIB`.
- **Zabbix / PRTG / SolarWinds / LibreNMS / most commercial NMS tools**:
  each has its own "Import MIB" or "MIB Loader" screen in the UI or CLI -
  point it at `mibs/KASTEN-ALERTING-MIB.mib`. All of them can resolve the
  standard imports (`SNMPv2-SMI`, etc.) on their own.

Validated during development with `snmptranslate` (net-snmp) - both
`snmptranslate -m KASTEN-ALERTING-MIB -Tp` (full tree dump) and numeric
OID → name / name → numeric OID resolution in both directions.

---

## Object reference

All objects live under `kastenAlertingObjects` (`enterprises.99999.1`).
Every one is a scalar (`.0` instance), `accessible-for-notify` - they only
ever appear as varbinds inside a trap, never queried directly via GET.

| Object | OID | Type | Meaning |
|---|---|---|---|
| `kastenActionKind` | `.1.1.0` | DisplayString | Kubernetes Kind of the action, e.g. `BackupAction`, `ExportAction`, `RunAction` - exactly as Kasten names it. |
| `kastenActionName` | `.1.2.0` | DisplayString | The action object's own `metadata.name`. |
| `kastenActionNamespace` | `.1.3.0` | DisplayString | Namespace of the application this action concerns. Empty for a cluster-scoped kind (BackupClusterAction, RestoreClusterAction, RetireAction). |
| `kastenActionPolicy` | `.1.4.0` | DisplayString | The Kasten Policy that triggered this action. Empty for a manual/ad-hoc action. |
| `kastenActionLocationProfile` | `.1.5.0` | DisplayString | The Location Profile this action reads from or writes to - mainly populated for ExportAction/ImportAction/BackupAction. |
| `kastenActionState` | `.1.6.0` | DisplayString | `Complete`, `Failed`, `Cancelled`, or `Skipped` - Kasten's own value, unmodified. |
| `kastenActionSeverity` | `.1.7.0` | INTEGER `{critical(1), warning(2), informational(3)}` | A coarse classification of `kastenActionState`, for NMS tools that colour-code/escalate on a severity field rather than parsing free text: `critical` for Failed, `warning` for Cancelled/Skipped, `informational` for Complete. |
| `kastenActionTimestamp` | `.1.8.0` | DisplayString | When the action reached this state, formatted in kasten-alerting's own configured display timezone (the chart's `timezone` value - see `app/tz.py`), not raw UTC. |
| `kastenActionErrorMessage` | `.1.9.0` | DisplayString | The top-level message from the action's error (typically only set for Failed), truncated to 255 characters. |
| `kastenActionUID` | `.1.10.0` | DisplayString | The action object's Kubernetes `metadata.uid` - a stable key for correlating this trap against kasten-alerting's own History tab or `GET /api/digests`. |

## Notifications

| Notification | OID | Objects carried | Sent when |
|---|---|---|---|
| `kastenActionAlertTrap` | `enterprises.99999.2.0.1` | all 10 objects above | Once per action kasten-alerting detects finishing in a status you've selected - **one trap per action**, not batched like the digest email (see "Why one trap per action" below). |
| `kastenAlertingTestTrap` | `enterprises.99999.2.0.2` | `kastenActionTimestamp` only | The Settings page's "Send test trap" button. |

---

## Why one trap per action, not a digest

The digest email deliberately batches everything a poll cycle finds into
one message, so an incident that fails many actions at once can't flood
an inbox. SNMP traps work the other way: an NMS is *built* to receive,
correlate, count, and deduplicate a burst of individual events from the
same underlying cause - that's the whole point of tools like this. Trying
to cram a whole poll cycle's findings into one trap (a "table" of varbinds)
fights that model and buys nothing, so kasten-alerting sends one
`kastenActionAlertTrap` per action instead, exactly like a normal
NMS-monitored device would.

---

## Prerequisites

### Network

- **UDP egress** from the kasten-alerting pod to your NMS, on the port
  you configure (default `162`, the IANA-assigned SNMP trap port - many
  environments instead point at a non-privileged port like `1162`
  precisely because binding `162` needs root on the receiving side).
  If there's a firewall between the cluster and the NMS (common - the NMS
  is often on a different network segment than the cluster), open that
  port explicitly. There's no way to detect this failure from
  kasten-alerting's side: see "TRAP has no delivery confirmation" below.
- No inbound access is needed in the other direction - kasten-alerting
  never listens for anything SNMP-related, it only ever sends.

### On the NMS

- The MIB imported (see above) if you want traps to render with real
  field names/descriptions instead of raw numeric OIDs - not required for
  the trap to arrive and be *received*, only for it to be *readable*.
- **v2c**: a community string configured to match what you set in
  kasten-alerting's Settings (default community strings like `public` are
  usually read-only/monitoring-only on a real NMS setup and may not accept
  traps - check your tool's docs).
- **v3**: see the dedicated section below - there's a specific,
  easy-to-miss requirement here beyond just username/passwords matching.

### TRAP has no delivery confirmation

SNMP TRAP (as opposed to INFORM) is fire-and-forget by UDP design - the
receiver never acknowledges it, and kasten-alerting has no way to know
whether your NMS actually received or accepted a trap, only whether it
managed to send the UDP packet locally (DNS resolved, socket opened,
credentials well-formed). A "Send test trap" that reports success and
still doesn't show up on your NMS means the packet left the pod but was
dropped somewhere after that - check network reachability first, then
(for v3) the engine ID below, then your NMS's own trap-receiver logs.

---

## SNMPv3: the Engine ID requirement

This is the one part of SNMPv3 that isn't obvious and will silently break
every trap if missed - discovered and confirmed against a real `snmptrapd`
during this feature's development.

**The problem:** for a GET/SET, SNMPv3's authentication is keyed to the
*receiving* agent's engine ID, which a manager typically discovers
automatically. A **TRAP is the other way around**: per RFC 3414, its
security parameters are keyed to the **sending** engine's own ID. Your NMS
has no way to discover kasten-alerting's engine ID on its own from an
unsolicited trap - it has to be told in advance, exactly, or it silently
rejects every authenticated trap as coming from an "Unknown User" (that
exact wording, confirmed against net-snmp's `snmptrapd` in debug mode)
even when the username and passwords are entirely correct.

**The fix:**

1. On the Settings page, with SNMP version set to v3, copy the value shown
   under "This app's SNMPv3 Engine ID" (also available via
   `GET /api/settings` → `snmp_engine_id`).
2. Tell your NMS this exact engine ID when configuring the v3 user for
   kasten-alerting. How varies by tool:
   - **net-snmp** (`snmptrapd`): `createUser -e <engineID> <username> SHA <authpass> AES <privpass>` in `snmptrapd.conf`.
   - Most commercial NMS tools have a "remote engine ID" or "context engine ID" field on the SNMPv3 trap-receiver/user configuration screen - paste it there.
3. This value is generated **once**, the first time SNMP is used, and
   persisted (`snmp_engine_id_suffix` in kasten-alerting's own settings,
   stored on its data PVC) - it does **not** change across pod restarts or
   redeploys. You only need to configure it on the NMS once, not every
   time kasten-alerting restarts.

Confirmed working end to end during development: a v3 `authPriv`
(SHA+AES) trap sent with the wrong/default engine ID was silently dropped
(`snmptrapd -Dusm` logged `usm: no match on engineID` / `usm: Unknown
User`); the identical trap, after telling `snmptrapd` the correct engine
ID via `createUser -e`, was accepted and logged correctly
(`usm: Verification succeeded`).

---

## Credentials

The v2c community string and the v3 auth/priv passwords are write-only,
kept in a Kubernetes Secret (`kasten-alerting-snmp`, in this app's own
namespace) - the API never returns them once saved, only whether each is
currently set. Same pattern as the SMTP password (see the main README's
RBAC section) and scoped by the same namespaced `Role`, not the
cluster-wide `ClusterRole`.
