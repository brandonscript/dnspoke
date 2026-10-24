# Protocol and limits

## HTTP API

| Endpoint | Authentication | Result |
| --- | --- | --- |
| `GET /v1/ip` | None | Observed public IPv4 address |
| `POST /v1/enroll` | One-time invite in JSON `{"invite":"..."}` | Device credential, returned once |
| `POST /v1/device` | Device credential; JSON `{"local_ip":"*.*.*.42"}` (or full IP / `null`) | Replaces or clears only this device's local IP metadata |
| `POST /v1/token` | Device credential in `Authorization: Bearer ...` | Five-minute update token |
| `POST /v1/update` | Update token in `Authorization: Bearer ...`; JSON `{}` | Reconciles the assigned record with the observed IPv4 |

Enrollment optionally accepts `device_hostname` and `local_ip`. Updated clients send a masked local IP by default; full addresses require opting in. This metadata does not control DNS and is not added to the DNS audit log.

Clients cannot select a different hostname or IP in an update request. Responses disable caching. The client requires HTTPS and refuses redirects.

## Credentials

Invites are unpadded URL-safe Base64. The decoded payload contains `2/`, a 12-byte random secret, and the UTF-8 server authority. HTTPS is implicit. The encoding obscures the address but is not encryption. Unsupported versions are rejected.

The invite secret has 96 bits of entropy and can be exchanged once, before expiry. Enrollment returns a separate random 256-bit device credential that lasts until revoked. That credential obtains random 256-bit update tokens, each valid for five minutes and one update attempt. Minting a new token invalidates older tokens for the device.

Only SHA-256 hashes of secrets are stored server-side. Credentials are sent in HTTPS headers or JSON bodies, never query strings. An invite passed as a command-line argument may remain in shell history.

## Limits

- Enrollment: 10 attempts per source address per 15 minutes.
- API requests: 120 per source address per minute.
- Successful DNS updates: one per device per five minutes.
- Provider operations: spaced by `DNS_PROVIDER_COOLDOWN`, including failed attempts.

The background client checks for IP changes on its configured interval and reconciles DNS on the first check after 24 hours. Failures back off up to 30 minutes, or the configured interval if longer.

## Provider operations

A single Gunicorn worker and thread serialize provider operations. SQLite write transactions serialize updates with enrollment and revocation. Requests-based provider calls use ten-second timeouts; the worker has a 90-second overall timeout. Providers using other SDKs may need their own timeout configuration.

Record matching is exact. No records are deleted. Other names, wildcards, and conflicting record types are not modified. The administrator must explicitly authorize adoption of an existing A record.

A provider write cannot participate in the local database transaction. If a remote write succeeds but acknowledgement or verification is lost, inspect the exact record before retrying; a newly created record may need explicit adoption. Other applications sharing the provider account may also compete for provider-side limits.

Provider-selection tests use mocked [Lexicon](https://dns-lexicon.github.io/dns-lexicon/) clients. Verify your chosen provider with a controlled record before using it for existing hostnames.
