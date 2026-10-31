# Local DNS administration

These commands use the server's DNS credentials locally; they do not add HTTP
endpoints or expand enrolled clients' A-record permissions. Set
`DNS_ADMIN_ZONES=example.com` explicitly in the administrator process.

```sh
printf '%s' target.example.net | dnspoke admin dns add CNAME alias.example.com
dnspoke admin dns list CNAME alias.example.com
printf '%s' verification-value | dnspoke admin dns add TXT _verification.example.com
```

Adds preserve unrelated records and refuse conflicting CNAMEs. Removal requires
an exact provider record ID, owner, type and content:

```sh
printf '%s' verification-value | dnspoke admin dns remove TXT _verification.example.com --identifier RECORD_ID
```

For DNS-01 hooks, also set `DNS_ACME_DOMAINS=host.example.com` (exact certificate
names, comma-separated). Pipe a JSON object with `domain` and `validation` to
`dnspoke admin acme present`, then the same object to `dnspoke admin acme cleanup`.
The validation must be a 43-character base64url SHA256 digest. Only the exact
`_acme-challenge` TXT name is managed. A private SQLite journal beside the relay
database records ownership using a digest rather than the validation value;
`DNS_ACME_DATABASE` overrides its path. Cleanup preserves preexisting matching
records and refuses speculative removal without an ownership receipt. A crash
between provider creation and journaling can leave a TXT record for manual review;
provider failures do not authorize bulk cleanup.

Use `dnspoke help admin dns` and `dnspoke help admin acme` for the full interface.
Keep provider credentials and the journal private. A zone allowlist constrains
these commands; it does not reduce the privileges of the provider account itself.
