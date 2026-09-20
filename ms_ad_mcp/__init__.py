"""Active Directory MCP server.

Exposes account / directory administration tools for a Microsoft Active
Directory domain over the Model Context Protocol using FastMCP. Under the
hood it wraps the ``ms-active-directory`` Python library (LDAP over TLS,
SIMPLE/NTLM/GSSAPI auth).
"""

__version__ = "0.1.0"