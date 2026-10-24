# dnspoke

dnspoke is a self-hosted dynamic DNS relay. Invite someone to manage one hostname, and their client keeps it pointed at their current public IP. DNS-provider credentials stay on your server.

## For DNS owners

### 1. Set up the relay

```sh
git clone https://github.com/brandonscript/dnspoke.git
cd dnspoke
cp .env.example .env
```

Edit `.env` with your relay address, DNS zone, provider, and the credentials required by [DNS Lexicon](https://dns-lexicon.github.io/dns-lexicon/configuration_reference.html):

```dotenv
RELAY_PUBLIC_URL=https://dns.example.com
DNS_ZONE=example.com
DNS_PROVIDER=your_provider
```

`RELAY_PUBLIC_URL` is where the relay is hosted. `DNS_ZONE` is the zone it manages. Configure these once; each invite includes the relay address automatically.

Connect the service to your HTTPS proxy's Docker network, set its trusted proxy address in `.env`, then start it:

```sh
docker compose -f compose.example.yml up -d --build
```

See [server configuration](docs/server.md) for the network, credentials, storage, and proxy setup.

The same CLI includes client and local admin commands. Homebrew installs it without server dependencies; the Docker image includes the full relay server. Administration requires access to the server database and environment.

### 2. Invite a client

```sh
docker compose -f compose.example.yml exec dnspoke dnspoke admin invite alice
```

This grants access to `alice.example.com` only. Example output:

```text
Hostname: alice.example.com
Server: https://dns.example.com
Expires in: 900s
One-time invite (share privately): Mi8BI0VniavN7wEjRWdkbnMuZXhhbXBsZS5jb20
```

The example code is not valid. A real invite contains a random secret and the relay address, both encoded together. Send the complete code privately along with the client instructions below.

Invites expire after 15 minutes and can be used once. Use `invite alice --ttl 600` for a ten-minute invite. To let a client update an existing A record, inspect it first and add `--adopt-existing`.

### 3. Manage access

```sh
docker compose -f compose.example.yml exec dnspoke dnspoke admin devices
docker compose -f compose.example.yml exec dnspoke dnspoke admin revoke DEVICE_ID
docker compose -f compose.example.yml exec dnspoke dnspoke admin audit
```

Device listings include the device ID, its reported local hostname (`device_hostname`), assigned DNS hostname, and registration date (`registered_at`, in UTC). The local hostname is captured at enrollment; older clients show `null`.

One active device is allowed per hostname. Revoke a device before replacing it. Revocation disables its credential and outstanding update tokens; the DNS record stays in place.

## For invited clients

### Install and enroll

```sh
brew install brandonscript/tap/dnspoke
dnspoke enroll
```

Paste the invite when prompted, or pass it directly:

```sh
dnspoke enroll 'Mi8BI0VniavN7wEjRWdkbnMuZXhhbXBsZS5jb20'
```

Use the real code your administrator sent, not the example above. The client saves the relay address and a device credential automatically. Enrollment lasts until the administrator revokes it.

Send an update and check your enrollment:

```sh
dnspoke update
dnspoke status
```

### Run in the background

```sh
brew services start dnspoke
```

The default check period is five minutes. To check every 15 minutes instead:

```sh
dnspoke configure --ttl 15
brew services restart dnspoke
```

Run Homebrew services as your user, without `sudo`. Stop with `brew services stop dnspoke`. For foreground use, run `dnspoke watch --ttl 15`.

For client commands, `--ttl` is the polling interval in minutes, with a minimum of five. For `dnspoke admin invite`, it is the invite lifetime in seconds.

## Details

- Only public IPv4 A records are supported. The address is the one the relay sees, so VPNs and outbound proxies affect it.
- Updates are restricted to the assigned hostname. Wildcards, other records, and the zone apex are left alone.
- Device credentials are stored in `~/.config/dnspoke/device.json`, or under `$XDG_CONFIG_HOME`. The file must be mode 600 and its directory mode 700.
- The client skips unchanged addresses and reconciles DNS on the first check after 24 hours. Failed updates retry with backoff.
- DNS updates do not configure router forwarding, firewall rules, or TLS for the hostname.

[Server configuration](docs/server.md) · [Protocol and limits](docs/technical.md) · [Development](docs/development.md)

## License

[MIT](LICENSE).
