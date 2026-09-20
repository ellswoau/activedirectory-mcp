"""Error helpers for the AD MCP server.

All library exceptions are re-raised as :class:`ADError` with a descriptive
message, but the raw exception type is preserved on ``.cause`` so diagnostics
stay debuggable.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from ms_active_directory import MsActiveDirectoryException


class ADError(Exception):
    """Raised for any Active Directory / LDAP operation failure."""

    def __init__(self, message: str, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.message = message
        self.cause = cause

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.cause is not None:
            return f"{self.message}: {self.cause}"
        return self.message


@contextmanager
def wrap_ad_error(what: str) -> Iterator[None]:
    """Translate ms-active-directory exceptions into :class:`ADError`.

    Usage::

        with wrap_ad_error("unlocking the account"):
            session.unlock_account(name)
    """
    try:
        yield
    except ADError:
        raise
    except MsActiveDirectoryException as exc:
        raise ADError(f"Could not {what}", exc) from exc
    except Exception as exc:  # noqa: BLE001 - surface unexpected errors clearly
        raise ADError(f"Could not {what}", exc) from exc