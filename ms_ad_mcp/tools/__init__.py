"""Tool definition functions for the AD MCP server.

Each ``register_*`` function wires fastmcp ``@tool`` decorators bound to a
resolved :class:`ADConfig`. Splitting imports keeps the server lean and allows
tests to build clients on demand.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import ADConfig

from . import account_tools, directory_tools, network_tools


def register_all(mcp: "FastMCP", config: "ADConfig") -> None:
    account_tools.register(mcp, config)
    directory_tools.register(mcp, config)
    network_tools.register(mcp, config)