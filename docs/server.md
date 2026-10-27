# Server configuration

The relay uses [DNS Lexicon](https://dns-lexicon.github.io/dns-lexicon/) to manage records. Select your provider and keep its credentials on the server. Clients receive permission to update one hostname, not access to the provider account.

## Installing without Docker

Native server hosting supports macOS and Linux. The [shell installer](install.md#hosting-a-server-on-macos-or-linux) accepts `--server`, or you can use a Python virtual environment:

Install the server dependencies with Python 3.12 or later:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install 'dnspoke[server] @ git+https://github.com/brandonscript/dnspoke.git@v0.1.7'
```

Set `DNS_DATABASE` to a writable file, for example `$HOME/.local/share/dnspoke/server/state.sqlite3`, and `TLDEXTRACT_CACHE_PATH` to a writable cache directory. The Docker default `/data/state.sqlite3` is intended for a mounted volume. After configuring the environment, start the native server with:

```sh
.venv/bin/gunicorn --bind 127.0.0.1:8090 --workers 1 --threads 1 --timeout 90 'dnspoke.server:create_app()'
```

Use `~/.local/share/dnspoke/venv/bin/gunicorn` instead for a shell installation. The single worker/thread settings match the [Dockerfile](../Dockerfile). Keep the listener internal and put your HTTPS proxy in front. Native hosting with a local proxy normally sets `DNS_TRUSTED_PROXY=127.0.0.1`. The `--bind` address is not the public relay URL. Set the environment variables below and make the database directory writable by the service user. Run `dnspoke admin` on that server with the same environment and database. Client-only installations need no server dependencies and also include the local admin commands.

## Environment

Copy `.env.example` to `.env` and restrict it with `chmod 600 .env`.

| Setting | Purpose | Default |
| --- | --- | --- |
| `RELAY_PUBLIC_URL` | Public HTTPS origin clients use for enrollment and updates | Generated and saved on first startup |
| `DNS_ZONE` | DNS zone managed by this instance | Required |
| `DNS_PROVIDER` | [Lexicon](https://dns-lexicon.github.io/dns-lexicon/) provider identifier | Required |
| `DNS_PROVIDER_COOLDOWN` | Minimum seconds between provider operations, including failed attempts | `0` |
| `DNS_DATABASE` | SQLite database path | `/data/state.sqlite3` |
| `DNS_TRUST_PROXY` | Set to `1` behind the trusted HTTPS proxy | Off |
| `DNS_TRUSTED_PROXY` | Fixed source IP of that proxy | Required when proxy trust is enabled |
| `PROXY_NETWORK` | Existing Docker network shared with the HTTPS proxy | Set in `.env` |

Add the exact `LEXICON_<PROVIDER>_*` credential variables required by your provider. See [Lexicon's configuration reference](https://dns-lexicon.github.io/dns-lexicon/configuration_reference.html). Providers that require extra SDK dependencies may also need their [Lexicon](https://dns-lexicon.github.io/dns-lexicon/) extras installed in the server image.

`RELAY_PUBLIC_URL` must be an HTTPS origin, without a path, query string, or embedded credentials. Recreate the container after changing environment settings:

```sh
docker compose -f compose.example.yml up -d --force-recreate
```

## Local administration

Admin commands use the relay's local SQLite database and server environment. A Homebrew client installation on the Docker host does not automatically connect to the container's database. For Docker, run the command inside the running relay:

```sh
docker exec dnspoke dnspoke admin devices
docker exec dnspoke dnspoke help admin invite
```

For a native relay, use the same `DNS_DATABASE` environment setting as the server, or specify its database directly:

```sh
dnspoke admin --database /path/to/state.sqlite3 devices
```

`--database` also works after the subcommand. `--config` selects the client credential file and does not configure the server database. Invites and endpoint configuration require `DNS_ZONE` and the same server environment as the running relay. Device listing, revocation, and audit commands report a missing database instead of creating an empty one.

Use `dnspoke help admin` or `dnspoke admin help` to browse administration commands. `dnspoke admin device`, `dnspoke admin devices`, and `dnspoke admin devices list` all list devices.

## Choosing the relay address

On its first startup, the server generates a random eight-character hex hostname under `DNS_ZONE` and saves it in the database. Restarts keep the same hostname. To see it, run:

```sh
dnspoke admin endpoint
# https://a1b2c3d4.example.com
```

Use `dnspoke admin endpoint --enroll-at enroll.example.com` to save a chosen hostname instead; a single label or HTTPS origin also works. `RELAY_PUBLIC_URL` overrides the saved value when set. Create the corresponding DNS record and configure the HTTPS proxy before sharing invites; hostname selection does not provision either. Changing the relay address requires updating the proxy and existing clients. Underscores cannot be used in public HTTPS certificate hostnames. Random labels obscure the address but are not access controls, and certificates may disclose them through [certificate transparency](https://letsencrypt.org/docs/ct-logs/).

## HTTPS proxy

The Compose example joins the existing network named by `PROXY_NETWORK`. Give your proxy a fixed address on that network and use it for `DNS_TRUSTED_PROXY`. The service rejects API requests from other source addresses. Keep port 8090 internal.

For example, a Caddy site can forward to the service:

```caddyfile
dns.example.com {
    reverse_proxy dnspoke:8090
}
```

The proxy must replace untrusted forwarded headers. Configure a public DNS record for the relay and verify its HTTPS certificate before sharing invites. `/health` is an internal liveness endpoint.

### Nginx and Let's Encrypt

Nginx can terminate HTTPS and forward requests to `dnspoke`. Point your relay hostname (for example, `dns.example.com`) at the proxy's public address and allow inbound TCP ports 80 and 443. Any published AAAA record must also reach this proxy.

For Nginx running on the host, publish the relay port only on loopback by adding this to the `dnspoke` service in your Compose file:

```yaml
ports:
  - "127.0.0.1:8090:8090"
```

Keep `DNS_TRUST_PROXY=1` and set `DNS_TRUSTED_PROXY` to the source address the relay actually sees from Nginx. With Docker port forwarding this may be the bridge gateway, rather than `127.0.0.1`. For a containerized proxy, use a fixed address on the shared Docker network instead and forward directly to `dnspoke:8090`, without publishing the port.

Start with an HTTP server block in your Nginx configuration, inside the `http` context (often an included site file):

```nginx
server {
    listen 80;
    server_name dns.example.com;

    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;
    }
}
```

This example assumes Nginx is the public edge proxy. Overwrite `X-Forwarded-For` as shown so clients cannot choose the address used for DNS updates. An additional CDN or load balancer requires configuring Nginx's [real IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html) to trust only that upstream's addresses first.

Validate and reload Nginx, then install Certbot and its Nginx plugin using the [official instructions for your operating system](https://certbot.eff.org/instructions?ws=nginx). On a host installation, the basic flow is:

```sh
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d dns.example.com
sudo certbot renew --dry-run
```

Choose the HTTP-to-HTTPS redirect when prompted. Certbot obtains a Let's Encrypt certificate and updates the site to listen on port 443 with TLS. Verify `https://dns.example.com/health`, set `RELAY_PUBLIC_URL=https://dns.example.com`, and recreate the relay container before issuing invites. Keep port 80 available for HTTP validation and renewal; [DNS validation](https://letsencrypt.org/docs/challenge-types/) is another option if that is not possible.

Confirm that Certbot's renewal timer or scheduled job is enabled and that successful renewals reload Nginx. For container deployments, Certbot needs access to the validation files and certificate storage, and the proxy needs to reload renewed certificates. The host commands above assume Certbot manages that host's Nginx configuration; follow the [Certbot user guide](https://eff-certbot.readthedocs.io/en/stable/using.html) for webroot validation, deployment hooks, and other layouts.

See Nginx's [HTTPS setup](https://nginx.org/en/docs/http/configuring_https_servers.html) and [proxy header documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header) for the underlying configuration.

[OpenResty](https://openresty.org/en/getting-started.html) is also an option if you already use its Nginx and Lua tooling. The same proxy configuration applies; its official packages use `openresty` in place of the `nginx` command. Plain Nginx with Certbot is sufficient here. OpenResty itself does not automate certificate issuance or renewal, and its binary and configuration paths may require additional Certbot configuration.

## Storage and backups

The image runs as uid 10001. The named `/data` volume stores the SQLite database and provider cache. For a bind mount, make the directory writable by that uid.

Back up the volume privately. It contains hashed credentials, assigned hostnames, IP addresses, and the audit log. Raw invitation and device secrets are not stored in the database. Stop the service before taking a filesystem copy, or use SQLite's backup API.

## Invitations and existing records

An invite is valid for 15 minutes by default. `--ttl` accepts 60–86400 seconds (up to 24 hours). Lifetimes over 900 seconds require `--yolo`; for example, `dnspoke admin invite alice --ttl 86400 --yolo`. A replacement invite invalidates the previous unused invite for that hostname.

Without `--adopt-existing`, a device can create its assigned record but cannot take over an existing one. With that option, it may update the exact single A record for its hostname. Conflicting types or multiple exact records require administrator attention. Infrastructure labels such as `mail`, `dns`, and `auth` are reserved.

If enrollment was interrupted after consuming the invite, revoke the resulting device and issue a new invite. Deleting the client's local file does not revoke its server-side credential.

Only public IPv4 is accepted. Private, CGNAT, IPv6, and private router addresses seen through hairpin connections are rejected. An internal client may need to connect without hairpin NAT so the relay can observe its public address.
