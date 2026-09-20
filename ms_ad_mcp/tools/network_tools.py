"""Network tools: reverse-DNS lookup and computer last-logon info."""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import ADConfig

from ..client import get_client
from ..dnsclient import reverse_dns_lookup as _reverse
from ..exceptions import wrap_ad_error as _wrap
from ._common import (
    COMPUTER_INFO_ATTRS,
    generalized_time_to_iso,
    summarize_computer,
    windows_time_to_iso,
)


def register(mcp: "FastMCP", config: "ADConfig") -> None:
    @mcp.tool()
    def reverse_dns_lookup(ip_address: str, nameservers: Optional[List[str]] = None) -> dict:
        """Reverse-resolve an IP address to hostname(s), like ``nslookup`` on a
        PTR query, using the configured/system DNS resolvers. Returns PTR
        answers, forward-confirmation status and a socket fallback. DNS lookup
        is independent of AD authentication."""
        return _reverse(ip_address, nameservers=nameservers)

    @mcp.tool()
    def last_logon_for_hostname(hostname: str) -> dict:
        """Report when a computer last logged in to AD, looked up by hostname
        (validates the account exists and echoes its lastLogon timestamps).

        NOTE: AD does not natively record *which human user* last logged on to
        a given workstation; that requires endpoint/agent log data. This tool
        returns the computer account's own lastLogon / lastLogonTimestamp,
        which show when the workstation itself last authenticated."""
        session = get_client(config).session()
        comp = None
        for name in dict.fromkeys([hostname, f"{hostname}$"]):
            try:
                comp = session.find_computer_by_sam_name(
                    name, attributes_to_lookup=COMPUTER_INFO_ATTRS)
            except Exception:  # noqa: BLE001 - try next candidate form
                comp = None
            if comp is not None:
                break
        if comp is None:
            return {
                "hostname": hostname,
                "found": False,
                "detail": "No AD computer account found for this hostname.",
            }
        summary = summarize_computer(comp)
        summary["found"] = True
        summary["hostname"] = hostname
        summary["last_logon_iso"] = windows_time_to_iso(comp.get("lastLogon"))
        summary["last_logon_timestamp_iso"] = generalized_time_to_iso(
            comp.get("lastLogonTimestamp"))
        summary["note"] = (
            "This is the computer account's own last logon, not the last human "
            "user. User-level last-login is not available from AD alone."
        )
        return summary