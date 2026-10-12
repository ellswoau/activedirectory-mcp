"""Shared helpers for AD tool implementations."""
from __future__ import annotations

import datetime as _dt
import uuid as _uuid
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from ms_active_directory import ADUser, ADGroup
    from ms_active_directory.core.ad_objects import ADComputer, ADObject

# LDAP attribute names we routinely request. These are fetched explicitly in
# addition to the library's always-returned name/object-class attributes.
USER_INFO_ATTRS = [
    "displayName", "givenName", "sn", "mail", "manager", "title",
    "department", "telephoneNumber", "description",
    "lastLogon", "lastLogonTimestamp", "whenChanged", "userAccountControl",
    "lockoutTime",
    # Immutable object identity: objectGUID (raw-byte hex) + objectSid. Needed
    # by directory-aware consumers (e.g. PrinterLogic AD-object deployments).
    "objectGUID", "objectSid",
]
GROUP_INFO_ATTRS = ["description", "displayName", "mail"]
COMPUTER_INFO_ATTRS = [
    "dNSHostName", "operatingSystem", "operatingSystemVersion", "description",
    "lastLogon", "lastLogonTimestamp", "whenChanged", "userAccountControl",
    "lockoutTime",
    "canonicalName", "servicePrincipalName",
]

#: The ``manager`` raw value in AD is the DN of the manager's user object.
MANAGER_ATTR = "manager"
#: gecos/employee metadata (RFC 2307 posix) — handy for the manager card.
POSIX_USER_ATTRS = ["gecos", "uidNumber", "gidNumber"]

# Windows AD stores lastLogon as 100ns ticks since 1601-01-01 UTC.
_WINDOWS_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
_NS_PER_HUNDRED = 100  # 100 ns per tick


def windows_time_to_iso(ticks: object) -> Optional[str]:
    """Convert an AD 100ns-since-1601 ``lastLogon`` value to ISO-8601 UTC."""
    try:
        ticks_int = int(ticks)
    except (TypeError, ValueError):
        return None
    if ticks_int <= 0:
        return None
    try:
        dt = _WINDOWS_EPOCH + _dt.timedelta(microseconds=ticks_int / 10)
    except OverflowError:
        return None
    return dt.isoformat()


def generalized_time_to_iso(value: object) -> Optional[str]:
    """Parse an LDAP GeneralizedTime (e.g. ``20240101120000.0Z``) to ISO UTC."""
    if not value:
        return None
    s = str(value).strip()
    try:
        # ldap3 decodes GeneralizedTime into a datetime already in most paths.
        if isinstance(value, _dt.datetime):
            return value.isoformat()
        return _parse_generalized(s).isoformat()
    except (ValueError, TypeError):
        return None


def _parse_generalized(s: str):
    """Best-effort parser for GeneralizedTime strings."""
    s = s.strip()
    tz = _dt.timezone.utc
    # Strip a trailing Z and remember whether we had an explicit offset.
    if s.endswith(("Z", "z")):
        s = s[:-1]
        tz = _dt.timezone.utc
    else:
        # Optional numeric offset +HHMM / +HH:MM / -HHMM.
        for marker in ("+", "-"):
            idx = s.find(marker, 10)
            if idx > 0:
                off = s[idx + 1:]
                s = s[:idx]
                off = off.replace(":", "")
                hrs = int(off[:2] or 0)
                mins = int(off[2:4] or 0)
                td = _dt.timedelta(hours=hrs, minutes=mins)
                if marker == "-":
                    td = -td
                tz = _dt.timezone(td)
                break
    # Forms: YYYYMMDDHHMMSS, optionally with fractional seconds.
    base, _, frac = s.partition(".")
    frac = frac.rstrip("Z")
    if len(base) < 14:
        raise ValueError("too short")
    year = int(base[0:4]); month = int(base[4:6]); day = int(base[6:8])
    hour = int(base[8:10]); minute = int(base[10:12]); second = int(base[12:14])
    micro = 0
    if frac:
        frac = (frac + "000000")[:6]
        micro = int(frac)
    return _dt.datetime(year, month, day, hour, minute, second, micro, tzinfo=tz)


def lockout_time_active(value: object) -> bool:
    """True when the AD ``lockoutTime`` attribute says the account is locked.

    ``lockoutTime`` is Windows FILETIME ticks (100ns since 1601-01-01 UTC).
    ``0`` (or missing) means not locked; any non-zero value means the account
    was locked out. Unlike the ``userAccountControl`` LOCKOUT bit, this
    attribute is replicated between domain controllers, so it is a second,
    independent signal for lockout.
    """
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def is_locked_out(uac_value: object, lockout_time: object = None) -> bool:
    """Evaluate every available lockout signal and return True if ANY says the
    account is locked.

    Signals checked:

    * the ``userAccountControl`` LOCKOUT bit (0x10) -- a per-DC derived flag;
    * a non-zero ``lockoutTime`` -- the replicated lockout attribute.

    OR-ing the two means a lockout reported by either method forces the
    account to be treated as locked, instead of the two disagreeing.
    """
    try:
        uac_flagged = bool(int(uac_value) & 0x10)
    except (TypeError, ValueError):
        uac_flagged = False
    return uac_flagged or lockout_time_active(lockout_time)


def uac_flags(value: object, lockout_time: object = None) -> Dict[str, bool]:
    """Decode the common AD ``userAccountControl`` flags we care about.

    ``locked_out`` is the OR of the LOCKOUT bit and a non-zero ``lockoutTime``
    (see :func:`is_locked_out`) so both detection methods are honoured."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return {}
    return {
        "locked_out": is_locked_out(n, lockout_time),
        "password_expired": bool(n & 0x800000),  # PASSWORD_EXPIRED
        "disabled": bool(n & 0x2),             # ACCOUNTDISABLE
        "dont_expire_password": bool(n & 0x10000),
    }


def format_object_guid(value: object) -> Optional[Dict[str, str]]:
    """Normalise an AD ``objectGUID`` to both wire forms.

    Returns ``{"raw": <32 hex, raw byte order, no dashes>, "canonical":
    <dashed UUID>}`` or ``None``. The **raw** form is what PrinterLogic (and
    similar tools) expect: ``uuid.UUID(...).bytes_le.hex()`` -- AD stores the
    first three GUID fields little-endian on the wire."""
    if value is None:
        return None
    try:
        if isinstance(value, _uuid.UUID):
            u = value
        elif isinstance(value, (bytes, bytearray)):
            b = bytes(value)
            u = _uuid.UUID(bytes_le=b) if len(b) == 16 else _uuid.UUID(bytes=b)
        else:
            u = _uuid.UUID(str(value).strip().strip("{}"))
    except (ValueError, TypeError, AttributeError):
        return None
    return {"raw": u.bytes_le.hex(), "canonical": str(u)}


def format_object_sid(value: object) -> Optional[str]:
    """Normalise an AD ``objectSid`` to ``S-1-5-21-...`` string form.

    Handles the raw binary SID (revision, subauthority count, 6-byte
    big-endian identifier authority, little-endian subauthorities) as well as
    already-formatted strings."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        b = bytes(value)
        if len(b) < 8:
            return None
        rev = b[0]
        nsub = b[1]
        idauth = int.from_bytes(b[2:8], "big")
        subs = [int.from_bytes(b[8 + 4 * i:12 + 4 * i], "little")
                for i in range(nsub)]
        return "-".join(["S", str(rev), str(idauth)] + [str(x) for x in subs])
    return str(value)


def summarize_object(obj: ADObject, *extra: str) -> Dict[str, object]:
    """Build a compact summary from an AD object's name/location/attrs."""
    out: Dict[str, object] = {
        "name": getattr(obj, "name", None) or getattr(obj, "common_name", None),
        "samaccount_name": getattr(obj, "samaccount_name", None),
        "common_name": getattr(obj, "common_name", None),
        "distinguished_name": obj.distinguished_name,
        "location": getattr(obj, "location", None),
        "type": obj.__class__.__name__.removeprefix("AD"),
    }
    for attr in extra:
        val = obj.get(attr)
        if val is not None:
            out[attr] = val
    return out


def summarize_user(user: ADUser, include_uac: bool = True) -> Dict[str, object]:
    """Summarize a user object with the attributes we usually care about."""
    out = summarize_object(user, "displayName", "givenName", "sn", "mail",
                           "manager", "title", "department", "telephoneNumber",
                           "description", "lastLogonTimestamp")
    ll = user.get("lastLogon")
    out["lastLogon"] = windows_time_to_iso(ll) if ll else None
    out["lastLogon_raw"] = ll
    out["lockoutTime"] = user.get("lockoutTime")
    if include_uac:
        out["account_flags"] = uac_flags(user.get("userAccountControl"),
                                         user.get("lockoutTime"))
    guid = format_object_guid(user.get("objectGUID"))
    if guid:
        out["objectGUID"] = guid["raw"]
        out["objectGUID_canonical"] = guid["canonical"]
    sid = format_object_sid(user.get("objectSid"))
    if sid:
        out["objectSid"] = sid
    return out


def summarize_computer(comp: ADComputer) -> Dict[str, object]:
    """Summarize a computer object (used to validate AD-join status)."""
    out = summarize_object(comp, "dNSHostName", "operatingSystem",
                           "operatingSystemVersion", "description",
                           "canonicalName", "lastLogonTimestamp")
    out["service_principal_names"] = comp.get("servicePrincipalName")
    out["account_flags"] = uac_flags(comp.get("userAccountControl"),
                                     comp.get("lockoutTime"))
    out["lockoutTime"] = comp.get("lockoutTime")
    ll = comp.get("lastLogon")
    out["lastLogon"] = windows_time_to_iso(ll) if ll else None
    out["lastLogon_raw"] = ll
    return out


def summarize_group(group: ADGroup) -> Dict[str, object]:
    """Summarize a group object including its description."""
    out = summarize_object(group, "description", "displayName", "mail")
    return out


def rdn_of_dn(dn: str) -> str:
    """Return the RDN (first component) of a distinguished name, e.g.
    ``"CN=Jane Manager,OU=People,DC=ad,DC=example,DC=com"`` -> ``"Jane Manager"``."""
    if not dn:
        return ""
    # First comma out of parentheses splits off the RDN.
    depth = 0
    for i, ch in enumerate(dn):
        if ch in "(":
            depth += 1
        elif ch in ")":
            depth -= 1
        elif ch == "," and depth == 0:
            return dn[:i]
    return dn