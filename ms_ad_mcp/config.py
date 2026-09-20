"""Configuration and secure credential handling for the AD MCP server.

Credentials can be supplied from (in order of precedence):
  1. Explicit keyword arguments (e.g. when called programmatically)
  2. Environment variables (``AD_*``)
  3. A JSON config file (``AD_CONFIG_FILE``, or ``--config``)

Passwords are never logged and config files are written with 0600 perms when
created via the ``python -m ms_ad_mcp config init`` wizard.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

# Environment variable names (AD_ = Active Directory)
ENV_DOMAIN = "AD_DOMAIN"
ENV_USERNAME = "AD_USERNAME"
ENV_PASSWORD = "AD_PASSWORD"
ENV_LDAP_URIS = "AD_LDAP_URIS"
ENV_AUTH_MECHANISM = "AD_AUTH_MECHANISM"
ENV_CA_CERT_FILE = "AD_CA_CERT_FILE"
ENV_SEARCH_PAGING_SIZE = "AD_SEARCH_PAGING_SIZE"
ENV_CONFIG_FILE = "AD_CONFIG_FILE"
# Optional bearer token that gates the network MCP endpoints when set.
ENV_MCP_TOKEN = "AD_MCP_AUTH_TOKEN"

# Supported LDAP authentication mechanisms (ldap3 names).
SUPPORTED_AUTH_MECHANISMS = ("SIMPLE", "NTLM", "GSSAPI")

_PASSWORD_TAG = "***REDACTED***"


@dataclass
class ADConfig:
    """Resolved configuration to connect to one Active Directory domain."""

    # DNS name of the AD domain (e.g. ``ad.example.com``).
    domain: str = ""
    # Service account used for the LDAP bind. Use UPN (user@domain) or the
    # bare sAMAccountName when using the default SIMPLE bind.
    username: str = ""
    password: str = ""
    # Optional explicit LDAP server URIs (e.g. ``ldaps://dc01:636``), used to
    # skip DNS SRV discovery. Comma separated in env/file form.
    ldap_uris: list = field(default_factory=list)
    # SIMPLE (default), NTLM or GSSAPI. Must be uppercase.
    auth_mechanism: str = "SIMPLE"
    # Optional path to a CA bundle used to trust LDAPS server certificates.
    ca_cert_file: str = ""
    # Page size for large directory searches.
    search_paging_size: int = 100

    @property
    def client_id(self) -> str:
        """Stable cache key derived from the domain name."""
        return self.domain.lower().strip()

    def redacted(self) -> dict:
        """Return a dict safe for logging (password redacted)."""
        d = asdict(self)
        d["password"] = _PASSWORD_TAG if d.get("password") else ""
        return d

    def is_complete(self) -> bool:
        return bool(self.domain and self.username and self.password)


class ConfigError(Exception):
    """Raised when configuration/credentials are missing or invalid."""


def _bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def _split_uris(value: Optional[str]) -> list:
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def _load_dotenv() -> None:
    """Load a local ``.env`` file into os.environ if python-dotenv is present."""
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
    except ImportError:  # pragma: no cover - python-dotenv is optional
        pass


def load_config(
    config_file: Optional[str] = None,
    *,
    domain: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ldap_uris: Optional[list] = None,
    auth_mechanism: Optional[str] = None,
    ca_cert_file: Optional[str] = None,
    search_paging_size: Optional[int] = None,
) -> ADConfig:
    """Load and merge configuration from kwargs, env and a config file.

    A local ``.env`` file is loaded into the environment first (when
    python-dotenv is installed), then the usual precedence applies.

    Raises :class:`ConfigError` if essential credentials are missing.
    """
    cfg = ADConfig()

    # 0. Optionally hydrate environment from a local .env file.
    _load_dotenv()

    # 1. Config file (env or explicit path).
    config_file = config_file or os.environ.get(ENV_CONFIG_FILE)
    if config_file and Path(config_file).exists():
        data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        for key in ("domain", "username", "password", "auth_mechanism",
                    "ca_cert_file", "search_paging_size"):
            if data.get(key) is not None:
                setattr(cfg, key, data[key])
        if data.get("ldap_uris"):
            uris = data["ldap_uris"]
            cfg.ldap_uris = uris if isinstance(uris, list) else _split_uris(str(uris))

    # 2. Environment overrides the file.
    if os.environ.get(ENV_DOMAIN):
        cfg.domain = os.environ[ENV_DOMAIN].strip()
    if os.environ.get(ENV_USERNAME):
        cfg.username = os.environ[ENV_USERNAME].strip()
    if os.environ.get(ENV_PASSWORD):
        cfg.password = os.environ[ENV_PASSWORD]
    if os.environ.get(ENV_LDAP_URIS):
        cfg.ldap_uris = _split_uris(os.environ[ENV_LDAP_URIS])
    if os.environ.get(ENV_AUTH_MECHANISM):
        cfg.auth_mechanism = os.environ[ENV_AUTH_MECHANISM].strip().upper()
    if os.environ.get(ENV_CA_CERT_FILE):
        cfg.ca_cert_file = os.environ[ENV_CA_CERT_FILE].strip()
    if os.environ.get(ENV_SEARCH_PAGING_SIZE):
        cfg.search_paging_size = _int(os.environ[ENV_SEARCH_PAGING_SIZE],
                                      cfg.search_paging_size)

    # 3. Explicit arguments win.
    if domain is not None:
        cfg.domain = domain.strip()
    if username is not None:
        cfg.username = username.strip()
    if password is not None:
        cfg.password = password
    if ldap_uris is not None:
        cfg.ldap_uris = list(ldap_uris)
    if auth_mechanism is not None:
        cfg.auth_mechanism = auth_mechanism.strip().upper()
    if ca_cert_file is not None:
        cfg.ca_cert_file = ca_cert_file.strip()
    if search_paging_size is not None:
        cfg.search_paging_size = int(search_paging_size)

    cfg.auth_mechanism = cfg.auth_mechanism or "SIMPLE"
    if cfg.auth_mechanism not in SUPPORTED_AUTH_MECHANISMS:
        raise ConfigError(
            f"Unsupported AD_AUTH_MECHANISM '{cfg.auth_mechanism}'. "
            f"Choose from {', '.join(SUPPORTED_AUTH_MECHANISMS)}."
        )

    if not cfg.is_complete():
        missing = [
            name for name, val in (
                ("domain", cfg.domain),
                ("username", cfg.username),
                ("password", cfg.password),
            ) if not val
        ]
        raise ConfigError(
            "Incomplete AD credentials. Missing: " + ", ".join(missing) + ". "
            "Set the AD_* env vars or run `python -m ms_ad_mcp config init "
            "--config <file>`."
        )
    return cfg


def configure_interactive(config_file: str) -> str:
    """Prompt securely for credentials and write a 0600 config file.

    The password is requested with ``getpass`` so it is never echoed, and the
    resulting file is only readable by the owner.
    """
    import getpass

    p = Path(config_file).expanduser()
    data = {}
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

    print("Active Directory domain\n------------------------")
    data["domain"] = input(
        f"AD domain DNS name [{data.get('domain', '')}]: "
    ).strip() or data.get("domain", "")
    data["username"] = input(
        f"Service account username [{data.get('username', '')}]: "
    ).strip() or data.get("username", "")
    data["password"] = getpass.getpass("Service account password: ") or data.get("password", "")
    uri_raw = input(
        "Optional LDAP server URIs, comma separated "
        f"[{', '.join(data.get('ldap_uris', []))}]: "
    ).strip()
    if uri_raw:
        data["ldap_uris"] = [u.strip() for u in uri_raw.split(",") if u.strip()]
    data["auth_mechanism"] = (input(
        f"Auth mechanism SIMPLE/NTLM/GSSAPI [{data.get('auth_mechanism', 'SIMPLE')}]: "
    ).strip() or data.get("auth_mechanism", "SIMPLE")).upper()
    data["ca_cert_file"] = input(
        f"Optional CA cert file for LDAPS [{data.get('ca_cert_file', '')}]: "
    ).strip() or data.get("ca_cert_file", "")

    if not (data.get("domain") and data.get("username") and data.get("password")):
        raise ConfigError("domain, username and password are all required.")

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)
    return str(p)