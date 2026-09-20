# ms-ad-mcp — Active Directory MCP server

A [Model Context Protocol](https://modelcontextprotocol.io) server exposing
account / directory administration for a Microsoft Active Directory domain,
built with Python FastMCP on top of the
[ms-active-directory](https://pypi.org/project/ms-active-directory/) library
(LDAP over TLS, SIMPLE / NTLM / GSSAPI auth).

Works both as a direct `python -m ms_ad_mcp` process and as a Docker container
(see "Running via Docker" below).

The design mirrors [omnissa-horizon-mcp](https://github.com/ellswoau/omnissa-horizon-mcp):
same config/environment precedence (`explicit args > env > config file`),
same `python -m` + Docker layout, same optional Bearer-token-gated network
transport with a credential-free `/health` endpoint, and a lazy client bound
to one connection per domain.

## Tools

Account management

- `unlock_account` — unlock a locked-out user or computer account
- `reset_password` — admin/shared-force password reset (no old password needed)
- `change_password` — change password after verifying the current one
- `create_user` — create a new user (username, password, name, email, dept, …)

Directory

- `find_user` — user attributes (display name, mail, title, dept, last logon…)
- `find_computer` — look up a computer account to validate its **AD-join status**
- `user_group_memberships` — a user's groups **including each group's description**
- `add_user_to_group` — add a user to a group (e.g. `linux-admins`)
- `get_manager` — a user's manager details **including the manager's email**

Network / host

- `reverse_dns_lookup` — `nslookup`-style PTR reverse lookup of an IP address
- `last_logon_for_hostname` — a computer account's last logon (see the caveat in its docstring: AD does not store *which human user* last logged in to a given workstation)

Connection

- `ad_ping` — verify service-account connectivity/authentication
- `ad_config` — redacted description of the connected domain

## Requirements

- Python 3.9+ (tested on 3.12)
- `pip install -r requirements.txt`

## Configuration

Credentials are never hard-coded. Provide them via a config JSON file or
environment variables (precedence: explicit args > env > file).

### Config wizard

```bash
cd ms-ad-mcp
python -m ms_ad_mcp config init --config ./ad.json
```

This prompts for the AD domain DNS name, service account username and password
(password entered without echoing), plus optional LDAP server URIs, and writes
the file with 0600 owner-only permissions. Example result:

```json
{
  "domain": "ad.example.com",
  "username": "svc-ad-mcp@ad.example.com",
  "password": "…",
  "ldap_uris": ["ldaps://dc01.ad.example.com:636"],
  "auth_mechanism": "SIMPLE",
  "ca_cert_file": "",
  "search_paging_size": 100
}
```

### Environment variables

```bash
export AD_DOMAIN="ad.example.com"
export AD_USERNAME="svc-ad-mcp@ad.example.com"
export AD_PASSWORD="…"
# Optional: pin LDAP servers to skip DNS SRV discovery
export AD_LDAP_URIS="ldaps://dc01.ad.example.com:636,ldap://dc02.ad.example.com:389"
export AD_AUTH_MECHANISM="SIMPLE"      # SIMPLE | NTLM | GSSAPI
export AD_CA_CERT_FILE="/etc/ldap-ca.pem"   # only if LDAPS needs a custom CA
export AD_SEARCH_PAGING_SIZE="100"
# Optional: bearer token gating the network MCP endpoints (empty = auth disabled)
export AD_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
# Optional, to point at a config file:
export AD_CONFIG_FILE="./ad.json"
```

A `.env` file is also honored if `python-dotenv` is installed (see
`.env.example`). See `ms_ad_mcp/config.py` for all `AD_*` vars.

## Running

```bash
# connectivity test
python -m ms_ad_mcp ping --config ./ad.json

# stdio transport (used by Claude Desktop / MCP clients)
python -m ms_ad_mcp --config ./ad.json     # --config passthrough
```

### Claude Desktop config

```json
{
  "mcpServers": {
    "ms-ad-mcp": {
      "command": "python",
      "args": ["-m", "ms_ad_mcp"],
      "env": { "AD_CONFIG_FILE": "/abs/path/to/ad.json" }
    }
  }
}
```

## HTTP / SSE daemon & bearer auth

Launch as a networked daemon:

```bash
python -m ms_ad_mcp --transport http --host 0.0.0.0 --port 8000
# or: --transport sse | streamable-http
```

Or set `AD_CONFIG_FILE` / `AD_*` env vars and drop `--config`.

The network transport is gated behind a bearer token when configured. With a
token set, every endpoint except `/health` and `/healthz` requires
`Authorization: Bearer <token>` and returns 401 otherwise.

```bash
export AD_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"

python -m ms_ad_mcp --transport http --host 0.0.0.0 --port 8000
curl -i http://localhost:8000/health            # public 200 + JSON status
curl -H "Authorization: Bearer $AD_MCP_AUTH_TOKEN" http://host:8000/mcp
```

Notes:

- When `AD_MCP_AUTH_TOKEN` is unset/empty, auth is disabled (open).
- `/health` stays public so load balancers / uptime monitors can probe liveness
  without a secret. It returns `{"status":"ok","service":"ms-ad-mcp",...}` and
  does **not** perform a blocking LDAP bind.

## Running via Docker

```bash
docker build -t ms-ad-mcp .
```

Create your config with `config init`, then run stdio interactively (or pass a
mounted config file):

```bash
docker run -i --rm \
  -e AD_CONFIG_FILE=/config/ad.json \
  -v "$(pwd)/ad.json:/config/ad.json:ro" \
  ms-ad-mcp
```

Point the MCP client at the container (e.g. Claude Desktop):

```json
{
  "mcpServers": {
    "ms-ad-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "AD_CONFIG_FILE=/config/ad.json",
               "-v", "/abs/path/ad.json:/config/ad.json:ro", "ms-ad-mcp"]
    }
  }
}
```

Or pass secrets via `-e` instead of mounting a file:

```bash
docker run -i --rm \
  -e AD_DOMAIN=ad.example.com \
  -e AD_USERNAME=svc-ad-mcp@ad.example.com \
  -e AD_PASSWORD='***' \
  -e AD_LDAP_URIS=ldaps://dc01.ad.example.com:636 \
  ms-ad-mcp
```

File-permission note: the container runs as an unprivileged user, so a mounted
`ad.json` must be world/group-readable for it to open, or you'll hit
`Permission denied`. Prefer env vars, or chown the file to the container UID.

As a network daemon:

```bash
docker run -d --name ad-mcp -p 8000:8000 \
  -e AD_CONFIG_FILE=/config/ad.json \
  -e AD_MCP_AUTH_TOKEN="$(openssl rand -hex 32)" \
  -v "$(pwd)/ad.json:/config/ad.json:ro" \
  ms-ad-mcp --transport http --host 0.0.0.0 --port 8000
```

or with Compose (bundled):

```bash
docker compose up -d --build    # requires AD_MCP_AUTH_TOKEN
```

The Docker `HEALTHCHECK` and the bundled `docker-compose.yml` healthcheck both
hit `/health` automatically.

## Security notes

- Passwords are never logged; `ad_config()` / `redacted()` mask them.
- Mutating operations (unlock, reset/change password, create user, add to
  group) require the corresponding AD permissions on the service account.
- Usernames are sAMAccountNames; always confirm exact spelling with
  `find_user` before mutating an account (the tool docstrings call this out).
- The service account needs LDAP read/write rights for the objects it manages.

## Layout

```
ms-ad-mcp/
├── README.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .env.example
├── tests_sanity.py
└── ms_ad_mcp/
    ├── __init__.py
    ├── __main__.py      # python -m entrypoint
    ├── server.py        # FastMCP app + CLI (config init / ping / run)
    ├── config.py        # secure config & credential resolution
    ├── client.py        # AD LDAP session client (lazy session per domain)
    ├── exceptions.py    # ADError wrapper
    ├── dnsclient.py     # reverse-DNS (nslookup) helpers
    └── tools/
        ├── __init__.py  # registers all tool modules
        ├── _common.py   # shared attribute/summary/date helpers
        ├── account_tools.py
        ├── directory_tools.py
        └── network_tools.py
```

## Testing

```bash
python tests_sanity.py     # no live AD required
```