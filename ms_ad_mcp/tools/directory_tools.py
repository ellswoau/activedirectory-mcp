"""Directory tools: user/computer lookup, group memberships, add-to-group and
manager information."""
from __future__ import annotations

from typing import TYPE_CHECKING, List

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import ADConfig

from ..client import get_client
from ..exceptions import ADError, wrap_ad_error as _wrap
from ._common import (
    COMPUTER_INFO_ATTRS,
    GROUP_INFO_ATTRS,
    MANAGER_ATTR,
    POSIX_USER_ATTRS,
    USER_INFO_ATTRS,
    rdn_of_dn,
    summarize_computer,
    summarize_group,
    summarize_user,
)


def register(mcp: "FastMCP", config: "ADConfig") -> None:
    @mcp.tool()
    def find_user(username: str) -> dict:
        """Look up a user by sAMAccountName (e.g. ``jsmith``) and return their
        core attributes: displayName, given name, surname, mail, title,
        department, manager DN, last logon and account flags. Returns {} if not
        found."""
        session = get_client(config).session()
        with _wrap(f"finding user '{username}'"):
            user = session.find_user_by_sam_name(username, attributes_to_lookup=USER_INFO_ATTRS)
        if user is None:
            return {"found": False, "username": username}
        summary = summarize_user(user)
        summary["found"] = True
        summary["username"] = username
        return summary

    @mcp.tool()
    def find_computer(hostname: str) -> dict:
        """Look up a computer account by hostname/sAMAccountName to validate its
        AD-join status. Returns the computer's DNS hostname, OS, lastLogon and
        account flags, or {"joined": False} when no such computer account
        exists."""
        session = get_client(config).session()
        candidates = [hostname, f"{hostname.strip().rstrip('.')}", f"{hostname}$"]
        found = None
        for name in dict.fromkeys(candidates):
            if not name:
                continue
            try:
                obj = session.find_computer_by_sam_name(
                    name, attributes_to_lookup=COMPUTER_INFO_ATTRS)
            except Exception:  # noqa: BLE001 - try next candidate form
                obj = None
            if obj is not None:
                found = (name, obj)
                break
        if found is None:
            return {"joined": False, "hostname": hostname,
                    "detail": "No AD computer account found for this hostname."}
        summary = summarize_computer(found[1])
        summary["joined"] = True
        summary["query_name"] = found[0]
        return summary

    @mcp.tool()
    def user_group_memberships(username: str) -> dict:
        """Return the AD groups a user belongs to, including each group's
        sAMAccountName and description, plus the group count."""
        session = get_client(config).session()
        with _wrap(f"finding groups for '{username}'"):
            groups = session.find_groups_for_user(
                username, attributes_to_lookup=GROUP_INFO_ATTRS)
        items = [summarize_group(g) for g in groups]
        items.sort(key=lambda g: (g.get("name") or "").lower())
        return {
            "username": username,
            "group_count": len(items),
            "groups": items,
        }

    @mcp.tool()
    def add_user_to_group(username: str, group_name: str) -> dict:
        """Add a user to an AD group by sAMAccountName (e.g. ``linux-admins``).
        The service account needs member-write rights on the group. Returns the
        group and confirms membership was applied."""
        session = get_client(config).session()
        with _wrap(f"adding '{username}' to group '{group_name}'"):
            session.add_users_to_groups([username], [group_name])
        return {
            "added": True,
            "username": username,
            "group": group_name,
            "note": "Membership applied; verify with user_group_memberships.",
        }

    @mcp.tool()
    def get_manager(username: str) -> dict:
        """Return the user's manager details from AD, including the manager's
        email address. Resolution: read the user's ``manager`` attribute (the
        manager's DN), then look that object up and read its mail/title/etc.
        Returns the manager DN/name even if the manager record can't be read."""
        session = get_client(config).session()
        with _wrap(f"reading manager info for '{username}'"):
            user = session.find_user_by_sam_name(username, attributes_to_lookup=USER_INFO_ATTRS)
        if user is None:
            raise ADError(f"User '{username}' not found in AD")

        manager_dn = user.get(MANAGER_ATTR, unpack_one_item_lists=True)
        result = {
            "username": username,
            "manager_dn": manager_dn,
            "manager_name": rdn_of_dn(manager_dn) if manager_dn else None,
        }
        if not manager_dn:
            result["manager_found"] = False
            return result

        with _wrap(f"looking up manager '{manager_dn}'"):
            manager = session.find_user_by_distinguished_name(
                manager_dn, attributes_to_lookup=USER_INFO_ATTRS + POSIX_USER_ATTRS)
        if manager is None:
            result["manager_found"] = False
            result["detail"] = "manager attribute set but manager object not readable"
            return result

        summary = summarize_user(manager, include_uac=False)
        result["manager_found"] = True
        result["manager"] = summary
        return result