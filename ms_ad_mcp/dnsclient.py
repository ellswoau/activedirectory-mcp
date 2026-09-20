"""Reverse-DNS lookup helpers (the ``nslookup`` equivalent).

Active Directory does not store a client's PTR records, so reverse hostname
lookup is performed via the system DNS resolvers (as ``nslookup`` would) using
``dnspython``. Forward confirmation is attempted with a matching ``A``/``AAAA``
record so the answer reflects what the zone actually serves.
"""
from __future__ import annotations

import socket
from typing import Dict, List, Optional

import dns.reversename
import dns.resolver
import dns.exception

from .exceptions import ADError


def _resolve_ptr(ip: str, nameservers: Optional[List[str]] = None) -> List[str]:
    """Return the PTR hostnames for ``ip`` (trailing dot removed)."""
    addr = dns.reversename.from_address(ip)
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    try:
        answers = resolver.resolve(addr, "PTR", lifetime=5)
        return sorted({str(a).rstrip(".") for a in answers})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.resolver.LifetimeTimeout):
        return []


def _forward_confirm(hostname: str, nameservers: Optional[List[str]] = None) -> List[str]:
    """Resolve A/AAAA records for ``hostname`` to confirm a PTR answer."""
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = nameservers
    out: List[str] = []
    for rtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, rtype, lifetime=5)
            out.extend(str(a.address) for a in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.LifetimeTimeout):
            continue
    return out


def reverse_dns_lookup(ip_address: str, nameservers: Optional[List[str]] = None) -> Dict[str, object]:
    """Reverse-resolve ``ip_address`` to hostname(s) using the system resolvers.

    Returns a dict with the PTR answer(s), forward-confirmation status, and a
    socket fallback result. Raises :class:`ADError` for an invalid IP.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip_address.strip())
    except ValueError as exc:
        raise ADError(f"'{ip_address}' is not a valid IP address", exc)

    ptr = _resolve_ptr(ip_address.strip(), nameservers)
    confirmed = []
    unconfirmed = []
    for host in ptr:
        fwd = _forward_confirm(host, nameservers)
        (confirmed if ip_address.strip() in fwd else unconfirmed).append({
            "hostname": host,
            "forward_addresses": fwd,
        })

    result: Dict[str, object] = {
        "ip_address": ip_address.strip(),
        "ptrs": [h for h in ptr],
        "answers": confirmed + unconfirmed,
        "forward_confirmed": bool(confirmed),
    }

    # Fallback to the socket gethostbyaddr result (often the canonical name).
    try:
        canonical, _aliases, _addrs = socket.gethostbyaddr(ip_address.strip())
        result["socket_hostname"] = canonical
    except (socket.herror, socket.timeout, OSError):
        result["socket_hostname"] = None

    return result