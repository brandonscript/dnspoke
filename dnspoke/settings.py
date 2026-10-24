"""Persistent relay address selection, shared by server startup and administration."""
import re
import secrets
from urllib.parse import urlsplit

from .core import Store, Rejected, hostname
from .invitations import validate_server


def relay_url(store: Store, zone: str, override: str | None = None, enroll_at: str | None = None) -> str:
    chosen = None
    if enroll_at:
        target = enroll_at if '.' in enroll_at or '://' in enroll_at else hostname(enroll_at, zone)
        chosen = validate_server(target if '://' in target else 'https://' + target)
        domain = urlsplit(chosen).hostname or ''
        if len(domain) > 253 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in domain.split('.')):
            raise Rejected('Use a DNS hostname with letters, digits, or hyphens; underscores are not supported')
    explicit = validate_server(override) if override else None
    if explicit and chosen and explicit != chosen:
        raise Rejected('RELAY_PUBLIC_URL overrides the saved address; change or unset it before using --enroll-at')
    with store.transaction() as db:
        previous = db.execute("SELECT value FROM meta WHERE key='relay_public_url'").fetchone()
        url = explicit or chosen or (str(previous['value']) if previous else 'https://' + hostname(secrets.token_hex(4), zone))
        db.execute("INSERT INTO meta(key,value) VALUES('relay_public_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (url,))
    return url
