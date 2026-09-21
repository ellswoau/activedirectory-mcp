"""Account-management tools: unlock, password changes and user creation."""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import ADConfig

from ..client import get_client
from ..exceptions import ADError
from ..exceptions import wrap_ad_error as _wrap
from ._common import USER_INFO_ATTRS, uac_flags


def register(mcp: "FastMCP", config: "ADConfig") -> None:
    @mcp.tool()
    def unlock_account(username: str) -> dict:
        """Unlock a locked-out AD user or computer account by its
        sAMAccountName (or distinguished name / common name). Reports the
        result and whether the account is still flagged as locked."""
        session = get_client(config).session()
        with _wrap(f"unlocking account '{username}'"):
            session.unlock_account(username)
        flags = {}
        try:
            flags = _account_uac_flags(config, username)
        except ADError:
            pass
        return {
            "unlocked": True,
            "account": username,
            "locked_flag_after": flags.get("locked_out"),
            "note": "Account unlocked. Ask the user to sign in with a fresh password.",
        }

    @mcp.tool()
    def reset_password(username: str, new_password: str) -> dict:
        """Reset a user's (or computer's) AD password to ``new_password``
        without supplying the old one. This is the admin/support 'force reset'
        path (requires password-reset privilege on the service account)."""
        session = get_client(config).session()
        with _wrap(f"resetting password for '{username}'"):
            session.reset_password_for_account(username, new_password)
        return {
            "password_reset": True,
            "account": username,
            "note": "Password reset. Expiry/forced-change is governed by domain "
                    "password policy; the new password is not returned.",
        }

    @mcp.tool()
    def change_password(username: str, current_password: str, new_password: str) -> dict:
        """Change a user's password by verifying ``current_password`` first
        (the self-service / 'knows old password' path). Use this when the
        current password is known; use reset_password otherwise."""
        session = get_client(config).session()
        with _wrap(f"changing password for '{username}'"):
            session.change_password_for_account(username, new_password, current_password)
        return {
            "password_changed": True,
            "account": username,
            "note": "Password changed from the known current password.",
        }

    @mcp.tool()
    def create_user(
        username: str,
        password: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        object_location: Optional[str] = None,
        description: Optional[str] = None,
        title: Optional[str] = None,
        department: Optional[str] = None,
        telephone_number: Optional[str] = None,
    ) -> dict:
        """Create a new AD user account. Provide at least ``username`` and, for
        an immediately usable account, ``password``. ``email`` (mail) and the
        other fields map to the standard inetOrgPerson/person attributes.
        Returns a redacted summary of the created account (password never
        returned)."""
        extra: dict = {}
        if email:
            extra["mail"] = email
        if display_name:
            extra["displayName"] = display_name
        if description:
            extra["description"] = description
        if title:
            extra["title"] = title
        if department:
            extra["department"] = department
        if telephone_number:
            extra["telephoneNumber"] = telephone_number

        session = get_client(config).session()
        with _wrap(f"creating user '{username}'"):
            user = session.create_user(
                username,
                first_name=first_name,
                last_name=last_name,
                object_location=object_location,
                user_password=password,
                **extra,
            )
        return {
            "created": True,
            "distinguished_name": user.get_user_distinguished_name(),
            "samaccount_name": user.get_samaccount_name(),
            "user_principal_name": user.get_user_principal_name(),
            "mail": email,
            "note": "User created. Password policy (e.g. force change on first "
                    "login) still applies.",
        }


def _account_uac_flags(config: "ADConfig", username: str) -> dict:
    """Best-effort read of the account lock/USC flags for a username, used to
    double-confirm an unlock rather than guessing.

    Reads both the ``userAccountControl`` LOCKOUT bit and ``lockoutTime`` so
    either signal can report the account as locked (see ``is_locked_out``)."""
    session = get_client(config).session()
    user = session.find_user_by_sam_name(username, attributes_to_lookup=USER_INFO_ATTRS)
    if user is None:
        return {}
    return uac_flags(user.get("userAccountControl"), user.get("lockoutTime"))