"""Shared helpers for AD tool implementations."""
from __future__ import annotations

import datetime as _dt
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
]
GROUP_INFO_ATTRS = ["description", "displayName", "mail"]
COMPUTER_INFO_ATTRS = [
    "dNSHostName", "operatingSystem", "operatingSystemVersion", "description",
    "lastLogon", "lastLogonTimestamp", "whenChanged", "userAccountControl",
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


def uac_flags(value: object) -> Dict[str, bool]:
    """Decode the common AD ``userAccountControl`` flags we care about."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return {}
    return {
        "locked_out": bool(n & 0x10),          # LOCKOUT
        "password_expired": bool(n & 0x800000),  # PASSWORD_EXPIRED
        "disabled": bool(n & 0x2),             # ACCOUNTDISABLE
        "dont_expire_password": bool(n & 0x10000),
    }


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
    if include_uac:
        out["account_flags"] = uac_flags(user.get("userAccountControl"))
    return out


def summarize_computer(comp: ADComputer) -> Dict[str, object]:
    """Summarize a computer object (used to validate AD-join status)."""
    out = summarize_object(comp, "dNSHostName", "operatingSystem",
                           "operatingSystemVersion", "description",
                           "canonicalName", "lastLogonTimestamp")
    out["service_principal_names"] = comp.get("servicePrincipalName")
    out["account_flags"] = uac_flags(comp.get("userAccountControl"))
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