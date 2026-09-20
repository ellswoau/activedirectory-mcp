"""LDAP session client wrapping ``ms_active_directory``'s ``ADSession``.

The client resolves an ``ADDomain`` (optionally pinning explicit LDAP URIs),
creates an authenticated session with the configured service account, and
exposes a small, safe surface that tool modules call. A registry keyed by
domain lets tools share one live session per config and unbind cleanly on
shutdown.
"""
from __future__ import annotations

import threading
from typing import Dict, Optional

from ms_active_directory import ADDomain, ADSession

from .config import ADConfig
from .exceptions import ADError, wrap_ad_error


class ADClient:
    """Stateful client bound to one Active Directory domain config."""

    def __init__(self, config: ADConfig):
        self.config = config
        self._domain: Optional[ADDomain] = None
        self._session: Optional[ADSession] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ connect
    def _build_domain(self) -> ADDomain:
        kwargs = {}
        if self.config.ldap_uris:
            kwargs["ldap_servers_or_uris"] = list(self.config.ldap_uris)
        if self.config.ca_cert_file:
            kwargs["ca_certificates_file_path"] = self.config.ca_cert_file
        return ADDomain(self.config.domain, **kwargs)

    def session(self) -> ADSession:
        """Return a live ADSession, (re)connecting lazily under a lock."""
        with self._lock:
            if self._session is not None and self._session.is_open():
                return self._session
            self._domain = self._build_domain()
            with wrap_ad_error("creating an AD session"):
                self._session = self._domain.create_session_as_user(
                    self.config.username,
                    self.config.password,
                    authentication_mechanism=self.config.auth_mechanism or None,
                )
            if self.config.search_paging_size and self.config.search_paging_size > 0:
                self._session.set_search_paging_size(self.config.search_paging_size)
            return self._session

    # ------------------------------------------------------------------ helpers
    def test_connection(self) -> Dict[str, object]:
        """Authenticate and return basic connectivity info (no secrets)."""
        sess = self.session()
        who = None
        with wrap_ad_error("reading session identity"):
            who = sess.who_am_i()
        return {
            "connected": True,
            "domain": self.config.domain,
            "user": self.config.username,
            "auth_mechanism": self.config.auth_mechanism,
            "who_am_i": who,
            "encrypted": sess.is_encrypted(),
            "site_file": self.config.ca_cert_file or "",
        }

    def close(self) -> None:
        """Best-effort unbind of the underlying LDAP connection."""
        with self._lock:
            sess, self._session = self._session, None
        if sess is not None:
            try:
                sess.ldap_connection.unbind()
            except Exception:  # noqa: BLE001 - best effort on shutdown
                pass


# Registry so tools share one client per config (keyed by domain client_id).
_client_registry: Dict[str, ADClient] = {}
_registry_lock = threading.Lock()


def get_client(config: ADConfig) -> ADClient:
    key = config.client_id
    with _registry_lock:
        client = _client_registry.get(key)
        if client is None or client.config != config:
            client = ADClient(config)
            _client_registry[key] = client
        return client


def clear_client(key: Optional[str]) -> None:
    """Close and drop the cached client for ``key`` (best effort)."""
    if not key:
        return
    with _registry_lock:
        client = _client_registry.pop(key, None)
    if client:
        client.close()