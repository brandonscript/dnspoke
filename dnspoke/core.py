"""Shared validation and persistent credentials. No DNS-provider credentials here."""
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
import hashlib
import ipaddress
import re
import secrets
import sqlite3
import time

from .types import Enrollment, UpdateToken

class Rejected(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def digest(secret: object) -> str:
    if not isinstance(secret, str) or not 32 <= len(secret) <= 200:
        raise Rejected('Invalid credential', 401)
    return hashlib.sha256(secret.encode()).hexdigest()


def invite_digest(secret: object) -> str:
    if isinstance(secret, str) and re.fullmatch(r'[0-9a-f]{24}', secret):
        return hashlib.sha256(secret.encode()).hexdigest()
    raise Rejected('Invalid invitation', 401)


def new_secret() -> str:
    return secrets.token_urlsafe(32)


def hostname(label: str, zone: str) -> str:
    zone = zone.lower().rstrip('.')
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
        raise Rejected('Use a single lowercase DNS label (no dots or wildcards)')
    if label in {'www', 'mail', 'dns', 'api', 'auth', 'console', 'ns1', 'ns2', 'smtp'}:
        raise Rejected('This label is reserved for infrastructure')
    return f'{label}.{zone}'


def public_ipv4(value: str | None) -> str:
    try:
        if value is None:
            raise ValueError
        address = ipaddress.ip_address(value)
    except ValueError:
        raise Rejected('A public IPv4 address is required') from None
    if address.version != 4 or not address.is_global:
        raise Rejected('A public IPv4 address is required')
    return str(address)


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.transaction() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS invites (
                    hash TEXT PRIMARY KEY, hostname TEXT NOT NULL,
                    expires REAL NOT NULL, adopt INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL,
                    hostname TEXT NOT NULL, adopt INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0, last_update REAL,
                    last_ip TEXT, created REAL NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS active_hostname
                    ON devices(hostname) WHERE revoked = 0;
                CREATE TABLE IF NOT EXISTS tokens (
                    hash TEXT PRIMARY KEY, device TEXT NOT NULL,
                    expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS limits (
                    bucket TEXT PRIMARY KEY, count INTEGER NOT NULL,
                    expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value REAL);
                CREATE TABLE IF NOT EXISTS audit (
                    at REAL NOT NULL, device TEXT NOT NULL, hostname TEXT NOT NULL,
                    old_ip TEXT, new_ip TEXT NOT NULL, changed INTEGER NOT NULL);
            ''')
        Path(path).chmod(0o600)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def throttle(self, category: str, identity: str | None, maximum: int, period: int) -> None:
        # Separate transaction: invalid auth attempts must still count.
        now = time.time()
        key = hashlib.sha256(f'{category}:{identity}:{int(now // period)}'.encode()).hexdigest()
        with self.transaction() as db:
            db.execute('DELETE FROM limits WHERE expires < ?', (now,))
            row = db.execute('SELECT count FROM limits WHERE bucket=?', (key,)).fetchone()
            if row and row['count'] >= maximum:
                raise Rejected('Too many requests; try again later', 429)
            db.execute('INSERT INTO limits VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1', (key, now + period))

    def invite(self, name: str, ttl: int = 900, adopt: bool = False) -> str:
        if not 60 <= ttl <= 3600:
            raise Rejected('Invite lifetime must be between 60 and 3600 seconds')
        secret = secrets.token_hex(12)  # 96-bit, single-use invitation only.
        with self.transaction() as db:
            if db.execute('SELECT 1 FROM devices WHERE hostname=? AND revoked=0', (name,)).fetchone():
                raise Rejected('Revoke the active device for this hostname first', 409)
            db.execute('DELETE FROM invites WHERE hostname=? OR expires < ?', (name, time.time()))
            db.execute('INSERT INTO invites VALUES (?,?,?,?)', (invite_digest(secret), name, time.time() + ttl, adopt))
        return secret

    def enroll(self, invite: object) -> Enrollment:
        secret, device = new_secret(), secrets.token_hex(12)
        now = time.time()
        with self.transaction() as db:
            row = db.execute('SELECT * FROM invites WHERE hash=? AND expires>?', (invite_digest(invite), now)).fetchone()
            if not row:
                raise Rejected('Invalid or expired invite', 401)
            if db.execute('SELECT 1 FROM devices WHERE hostname=? AND revoked=0', (row['hostname'],)).fetchone():
                raise Rejected('Hostname already assigned', 409)
            db.execute('INSERT INTO devices(id,hash,hostname,adopt,created) VALUES(?,?,?,?,?)', (device, digest(secret), row['hostname'], row['adopt'], now))
            db.execute('DELETE FROM invites WHERE hash=?', (invite_digest(invite),))
        return {'device_id': device, 'device_secret': secret, 'hostname': row['hostname']}

    def token(self, secret: object) -> UpdateToken:
        token, now = new_secret(), time.time()
        with self.transaction() as db:
            row = db.execute('SELECT * FROM devices WHERE hash=? AND revoked=0', (digest(secret),)).fetchone()
            if not row:
                raise Rejected('Invalid or revoked device', 401)
            db.execute('DELETE FROM tokens WHERE expires <= ? OR device=?', (now, row['id']))
            db.execute('INSERT INTO tokens VALUES (?,?,?)', (digest(token), row['id'], now + 300))
        return {'token': token, 'expires_in': 300, 'hostname': row['hostname']}

    def revoke(self, device: str) -> bool:
        with self.transaction() as db:
            found = db.execute('UPDATE devices SET revoked=1 WHERE id=?', (device,)).rowcount
            db.execute('DELETE FROM tokens WHERE device=?', (device,))
            return bool(found)
