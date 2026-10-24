"""Portable invites carrying an HTTPS origin and a one-use secret."""
from urllib.parse import urlsplit
import base64
import binascii
import re

from .core import Rejected, invite_digest

def validate_server(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ('', '/')
                or any(c.isspace() or ord(c) < 32 for c in value)):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise Rejected('Server must be an HTTPS origin without credentials, path, query, or fragment') from None
    return value.rstrip('/')


def pack_invite(server: str, secret: str) -> str:
    server = validate_server(server)
    invite_digest(secret)
    authority = urlsplit(server).netloc.encode('utf-8')
    # The version and slash are inside the encoding, followed by a 12-byte
    # secret and the authority. HTTPS is implicit; the fixed secret size
    # avoids JSON field names or an additional length field.
    payload = b'2/' + bytes.fromhex(secret) + authority
    return base64.urlsafe_b64encode(payload).decode().rstrip('=')


def unpack_invite(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise Rejected('Invalid invite; paste the complete invite supplied by your administrator')
    try:
        if not re.fullmatch(r'[A-Za-z0-9_-]+', value):
            raise ValueError
        payload = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
        version, body = payload.split(b'/', 1)
        if version != b'2':
            raise Rejected('Unsupported invite version; update your CLI or ask your administrator')
        if len(body) < 13:
            raise ValueError
        secret = body[:12].hex()
        server = validate_server('https://' + body[12:].decode('utf-8'))
        invite_digest(secret)
        return server, secret
    except Rejected:
        raise
    except (ValueError, TypeError, binascii.Error):
        raise Rejected('Invalid invite; paste the complete invite supplied by your administrator') from None
