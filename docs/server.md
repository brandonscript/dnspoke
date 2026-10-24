# Server configuration

The relay uses DNS Lexicon to manage records. Select your provider and keep its credentials on the server. Clients receive permission to update one hostname, not access to the provider account.

## Installing without Docker

Install the server dependencies with Python 3.12 or later:

```sh
python -m pip install 'dnspoke[server] @ git+https://github.com/brandonscript/dnspoke.git@v0.1.1'
```

Run the server with the Gunicorn command in the [Dockerfile](../Dockerfile). Set the environment variables below and make the database directory writable by the service user. Run `dnspoke admin` on that server with the same environment and database. Client-only installations need no server dependencies and also include the local admin commands.

## Environment

Copy `.env.example` to `.env` and restrict it with `chmod 600 .env`.

| Setting | Purpose | Default |
| --- | --- | --- |
| `RELAY_PUBLIC_URL` | Public HTTPS origin clients use for enrollment and updates | Required for invitations |
| `DNS_ZONE` | DNS zone managed by this instance | Required |
| `DNS_PROVIDER` | Lexicon provider identifier | Required |
| `DNS_PROVIDER_COOLDOWN` | Minimum seconds between provider operations, including failed attempts | `0` |
| `DNS_DATABASE` | SQLite database path | `/data/state.sqlite3` |
| `DNS_TRUST_PROXY` | Set to `1` behind the trusted HTTPS proxy | Off |
| `DNS_TRUSTED_PROXY` | Fixed source IP of that proxy | Required when proxy trust is enabled |
| `PROXY_NETWORK` | Existing Docker network shared with the HTTPS proxy | Set in `.env` |

Add the exact `LEXICON_<PROVIDER>_*` credential variables required by your provider. See [Lexicon's configuration reference](https://dns-lexicon.github.io/dns-lexicon/configuration_reference.html). Providers that require extra SDK dependencies may also need their Lexicon extras installed in the server image.

`RELAY_PUBLIC_URL` must be an HTTPS origin, without a path, query string, or embedded credentials. Recreate the container after changing environment settings:

```sh
docker compose -f compose.example.yml up -d --force-recreate
```

## HTTPS proxy

The Compose example joins the existing network named by `PROXY_NETWORK`. Give your proxy a fixed address on that network and use it for `DNS_TRUSTED_PROXY`. The service rejects API requests from other source addresses. Keep port 8090 internal.

For example, a Caddy site can forward to the service:

```caddyfile
dns.example.com {
    reverse_proxy dnspoke:8090
}
```

The proxy must replace untrusted forwarded headers. Configure a public DNS record for the relay and verify its HTTPS certificate before sharing invites. `/health` is an internal liveness endpoint.

## Storage and backups

The image runs as uid 10001. The named `/data` volume stores the SQLite database and provider cache. For a bind mount, make the directory writable by that uid.

Back up the volume privately. It contains hashed credentials, assigned hostnames, IP addresses, and the audit log. Raw invitation and device secrets are not stored in the database. Stop the service before taking a filesystem copy, or use SQLite's backup API.

## Invitations and existing records

An invite is valid for 15 minutes by default. `--ttl` accepts 60–3600 seconds. A replacement invite invalidates the previous unused invite for that hostname.

Without `--adopt-existing`, a device can create its assigned record but cannot take over an existing one. With that option, it may update the exact single A record for its hostname. Conflicting types or multiple exact records require administrator attention. Infrastructure labels such as `mail`, `dns`, and `auth` are reserved.

If enrollment was interrupted after consuming the invite, revoke the resulting device and issue a new invite. Deleting the client's local file does not revoke its server-side credential.

Only public IPv4 is accepted. Private, CGNAT, IPv6, and private router addresses seen through hairpin connections are rejected. An internal client may need to connect without hairpin NAT so the relay can observe its public address.
