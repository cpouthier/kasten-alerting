"""SNMP trap notifications - sends one trap per alertable action (not
batched into a digest like the email, see poller.run_once), so a burst
during a real incident lands as a burst of traps, which is what an NMS is
actually built to correlate/deduplicate, unlike an inbox.

OIDs match mibs/KASTEN-ALERTING-MIB.mib exactly - see MIB.md for the full
object reference and NMS import instructions. Both are hand-kept in sync;
this module does NOT compile or load the .mib file at runtime (every OID
below is a plain numeric tuple), so a typo here would silently diverge
from the shipped MIB - double check both when changing either.

v2c community string and v3 auth/priv passwords are write-only, kept in a
Secret (SNMP_SECRET_NAME), same pattern as alerting.py's SMTP password.
"""
import logging
import os
from datetime import datetime, timezone

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    Integer32,
    NotificationType,
    ObjectIdentity,
    ObjectType,
    OctetString,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    send_notification,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

import k10
import settings

logger = logging.getLogger("kasten-alerting.snmp_trap")

SNMP_SECRET_NAME = "kasten-alerting-snmp"

# kastenAlertingMIB ::= { enterprises 99999 } - see the MIB module's own
# DESCRIPTION for why 99999 (a placeholder PEN, not one actually
# registered to this project) and what to do if that ever matters to you.
_BASE_OID = "1.3.6.1.4.1.99999"
TRAP_OID = f"{_BASE_OID}.2.0.1"       # kastenActionAlertTrap
TEST_TRAP_OID = f"{_BASE_OID}.2.0.2"  # kastenAlertingTestTrap

_OID_KIND = f"{_BASE_OID}.1.1.0"
_OID_NAME = f"{_BASE_OID}.1.2.0"
_OID_NAMESPACE = f"{_BASE_OID}.1.3.0"
_OID_POLICY = f"{_BASE_OID}.1.4.0"
_OID_LOCATION_PROFILE = f"{_BASE_OID}.1.5.0"
_OID_STATE = f"{_BASE_OID}.1.6.0"
_OID_SEVERITY = f"{_BASE_OID}.1.7.0"
_OID_TIMESTAMP = f"{_BASE_OID}.1.8.0"
_OID_ERROR_MESSAGE = f"{_BASE_OID}.1.9.0"
_OID_UID = f"{_BASE_OID}.1.10.0"

# kastenActionSeverity's INTEGER enum - see the MIB.
_SEVERITY_BY_STATE = {"Failed": 1, "Cancelled": 2, "Skipped": 2, "Complete": 3}

_AUTH_PROTOCOLS = {"sha": usmHMACSHAAuthProtocol, "md5": usmHMACMD5AuthProtocol, "none": usmNoAuthProtocol}
_PRIV_PROTOCOLS = {"aes": usmAesCfb128Protocol, "des": usmDESPrivProtocol, "none": usmNoPrivProtocol}

# RFC3411 ENGINE-ID prefix for this MIB's placeholder enterprise number
# (99999 = 0x1869F), high bit of the first octet set per the "enterprise-
# specific format" convention - the remaining 8 octets are a random
# suffix, generated once and persisted (settings.snmp_engine_id_suffix),
# never regenerated on its own. This MUST stay stable across restarts:
# an SNMPv3 trap's security parameters are keyed to the SENDING engine's
# own engineID (unlike a GET/SET, which uses the receiver's), so an NMS
# that's been told this engineID (createUser -e <id>, or "trap host"
# style auto-learning) stops recognizing kasten-alerting's traps the
# moment this value changes - see MIB.md's SNMPv3 section for exactly why,
# verified against a real snmptrapd during development.
_ENGINE_ID_PREFIX = bytes([0x80, 0x01, 0x86, 0x9F])


def _get_engine_id() -> OctetString:
    cfg = settings.get_alerting()
    suffix_hex = cfg.get("snmp_engine_id_suffix") or ""
    if not suffix_hex:
        suffix_hex = os.urandom(8).hex()
        settings.update_alerting(snmp_engine_id_suffix=suffix_hex)
    return OctetString(hexValue=(_ENGINE_ID_PREFIX + bytes.fromhex(suffix_hex)).hex())


def engine_id_hex() -> str:
    """Human-readable form for the Settings page - an SNMPv3 NMS needs to
    be told this exact value (see MIB.md) before it will accept
    authenticated traps from this app."""
    return "0x" + _get_engine_id().prettyPrint().replace("0x", "")


def _auth_data(cfg: dict, creds: dict):
    if cfg["snmp_version"] == "v2c":
        return CommunityData(creds.get("community") or "", mpModel=1)
    auth_protocol = _AUTH_PROTOCOLS[cfg["snmp_v3_auth_protocol"]]
    priv_protocol = _PRIV_PROTOCOLS[cfg["snmp_v3_priv_protocol"]]
    auth_key = creds.get("v3_auth_password") or None if auth_protocol != usmNoAuthProtocol else None
    priv_key = creds.get("v3_priv_password") or None if priv_protocol != usmNoPrivProtocol else None
    return UsmUserData(
        cfg["snmp_v3_username"],
        authKey=auth_key,
        privKey=priv_key,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )


def _item_varbinds(item: dict) -> list[ObjectType]:
    error_message = (item.get("error_message") or "")[:255]
    return [
        ObjectType(ObjectIdentity(_OID_KIND), OctetString(item["kind"])),
        ObjectType(ObjectIdentity(_OID_NAME), OctetString(item["name"] or "")),
        ObjectType(ObjectIdentity(_OID_NAMESPACE), OctetString(item["namespace"] or "")),
        ObjectType(ObjectIdentity(_OID_POLICY), OctetString(item["policy_name"] or "")),
        ObjectType(ObjectIdentity(_OID_LOCATION_PROFILE), OctetString(item["location_profile"] or "")),
        ObjectType(ObjectIdentity(_OID_STATE), OctetString(item["state"])),
        ObjectType(ObjectIdentity(_OID_SEVERITY), Integer32(_SEVERITY_BY_STATE.get(item["state"], 2))),
        ObjectType(ObjectIdentity(_OID_TIMESTAMP), OctetString(item["timestamp"] or "")),
        ObjectType(ObjectIdentity(_OID_ERROR_MESSAGE), OctetString(error_message)),
        ObjectType(ObjectIdentity(_OID_UID), OctetString(item.get("uid") or "")),
    ]


async def _send(cfg: dict, creds: dict, trap_oid: str, varbinds: list[ObjectType]) -> None:
    notif = NotificationType(ObjectIdentity(trap_oid)).add_varbinds(*varbinds)
    error_indication, error_status, error_index, _ = await send_notification(
        SnmpEngine(snmpEngineID=_get_engine_id()),
        _auth_data(cfg, creds),
        await UdpTransportTarget.create((cfg["snmp_host"], int(cfg["snmp_port"]))),
        ContextData(),
        "trap",
        notif,
    )
    # TRAP (as opposed to INFORM) is fire-and-forget by design - the
    # receiver never acknowledges it, so error_indication only ever
    # reflects a LOCAL failure (DNS, socket, bad credentials format), not
    # whether the NMS actually received or accepted it. Still worth
    # raising: a local failure means the packet was never even sent.
    if error_indication:
        raise RuntimeError(str(error_indication))


async def _get_credentials() -> dict:
    data = await k10.get_secret_data(k10.APP_NAMESPACE, SNMP_SECRET_NAME)
    return data or {}


async def send_alert_trap(item: dict) -> None:
    cfg = settings.get_alerting()
    if not cfg.get("snmp_enabled"):
        return
    creds = await _get_credentials()
    logger.info("sending SNMP trap (%s) for %s %s/%s to %s:%s",
                cfg["snmp_version"], item["kind"], item["namespace"], item["name"],
                cfg["snmp_host"], cfg["snmp_port"])
    await _send(cfg, creds, TRAP_OID, _item_varbinds(item))


async def send_test_trap(cfg: dict, creds: dict) -> None:
    varbinds = [ObjectType(ObjectIdentity(_OID_TIMESTAMP), OctetString(datetime.now(timezone.utc).isoformat(timespec="seconds")))]
    await _send(cfg, creds, TEST_TRAP_OID, varbinds)
