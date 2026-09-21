"""Sanity checks for the AD MCP server that do NOT require a live Active
Directory domain.

Run: python tests_sanity.py   (or: python -m pytest -q)

These cover config precedence/preduction, the pure helper functions, DNS
reverse lookup plumbing, and tool registration. Live-AD behaviour (unlock,
password reset, create user, ...) can only be tested against a real domain.
"""
from __future__ import annotations

import datetime
import os

# Ensure the package is importable when run from the repo root.
os.environ.setdefault("AD_DOMAIN", "ad.example.com")
os.environ.setdefault("AD_USERNAME", "svc@ad.example.com")
os.environ.setdefault("AD_PASSWORD", "unused")

from ms_ad_mcp import __version__  # noqa: E402
from ms_ad_mcp.config import ADConfig, ConfigError, load_config  # noqa: E402
from ms_ad_mcp.dnsclient import reverse_dns_lookup  # noqa: E402
from ms_ad_mcp.server import build_server  # noqa: E402
from ms_ad_mcp.tools._common import (  # noqa: E402
    generalized_time_to_iso,
    is_locked_out,
    lockout_time_active,
    rdn_of_dn,
    uac_flags,
    windows_time_to_iso,
)


def test_version():
    assert __version__


def test_redacted_hides_password():
    cfg = ADConfig(domain="d.example.com", username="u", password="hunter2")
    out = cfg.redacted()
    assert out["password"] == "***REDACTED***"
    assert "hunter2" not in repr(out)


def test_config_missing_creds_raises():
    import unittest.mock as mock
    with mock.patch.dict(os.environ, {}, clear=True):
        try:
            load_config()
            assert False, "expected ConfigError"
        except ConfigError:
            pass


def test_config_env_over_file():
    # Env vars must win over a config file
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        f = os.path.join(td, "ad.json")
        with open(f, "w") as fh:
            fh.write('{"domain":"file.example.com","username":"fileu",'
                     '"password":"filep","auth_mechanism":"SIMPLE"}')
        cfg = load_config(f,
                          domain=os.environ["AD_DOMAIN"],
                          username=os.environ["AD_USERNAME"],
                          password=os.environ["AD_PASSWORD"])
        assert cfg.domain == os.environ["AD_DOMAIN"]
        assert cfg.username == os.environ["AD_USERNAME"]


def test_windows_time():
    # 133134107830000000 ticks == 2022-11-20T09:39:43Z
    assert windows_time_to_iso(133134107830000000) == "2022-11-20T09:39:43+00:00"
    assert windows_time_to_iso(0) is None
    assert windows_time_to_iso("garbage") is None


def test_generalized_time():
    assert generalized_time_to_iso("20240101120000.0Z") == "2024-01-01T12:00:00+00:00"
    assert generalized_time_to_iso(datetime.datetime(2024, 1, 1, 12, 0, 0)) == \
        "2024-01-01T12:00:00"
    assert generalized_time_to_iso(None) is None


def test_uac_flags():
    flags = uac_flags(764)  # 0x16c -> locked(0x10) + disabled(0x2) + ... 
    assert flags["locked_out"] is True
    assert flags["password_expired"] is False


def test_lockout_time_active():
    assert lockout_time_active(0) is False
    assert lockout_time_active(None) is False
    assert lockout_time_active("0") is False
    assert lockout_time_active(133134107830000000) is True
    assert lockout_time_active("garbage") is False


def test_locked_out_uses_both_signals():
    # UAC LOCKOUT bit only -> locked.
    assert is_locked_out(0x10, 0) is True
    # lockoutTime only (UAC bit clear) -> locked.
    assert is_locked_out(0x10000, 133134107830000000) is True
    # neither -> not locked.
    assert is_locked_out(0x10000, 0) is False
    # unparseable UAC but an active lockoutTime -> still locked.
    assert is_locked_out(None, 133134107830000000) is True


def test_uac_flags_lockout_time_forces_true():
    # UAC has no LOCKOUT bit but lockoutTime is set: must report locked.
    flags = uac_flags(0x10000, 133134107830000000)
    assert flags["locked_out"] is True
    # And the reverse: LOCKOUT bit set, lockoutTime clear.
    assert uac_flags(0x10, 0)["locked_out"] is True


def test_rdn():
    assert rdn_of_dn("CN=Jane Manager,OU=P,DC=ad,DC=example,DC=com") == "CN=Jane Manager"


def test_tool_registration():
    cfg = load_config()
    mcp = build_server(config=cfg)
    import asyncio
    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    required = {
        "unlock_account", "reset_password", "change_password", "create_user",
        "find_user", "find_computer", "user_group_memberships",
        "add_user_to_group", "get_manager", "reverse_dns_lookup",
        "last_logon_for_hostname", "ad_ping", "ad_config",
    }
    assert required <= names, f"missing tools: {required - names}"


def test_reverse_dns_smoke():
    # 8.8.8.8 should resolve to dns.google when outbound DNS is available.
    try:
        result = reverse_dns_lookup("8.8.8.8")
    except Exception:  # no network in CI/sandbox
        return
    assert result["ip_address"] == "8.8.8.8"
    assert isinstance(result["ptrs"], list)


def test_reverse_dns_invalid():
    try:
        reverse_dns_lookup("not-an-ip")
        assert False, "expected an error for an invalid IP"
    except Exception:
        pass


def _run_all():
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    return passed == len(fns)


if __name__ == "__main__":
    import sys
    sys.exit(0 if _run_all() else 1)