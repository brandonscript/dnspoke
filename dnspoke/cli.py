"""Dynamic DNS enrollment, updates, and local server administration."""
from __future__ import annotations

from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import IO, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import argparse
import ipaddress
import json
import os
import random
import signal
import stat
import sys
import tempfile
import threading
import time

from . import __version__, admin
from .core import Rejected
from .invitations import unpack_invite
from .types import DeviceConfig

class ClientError(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: IO[bytes], code: int, msg: str, headers: Message, newurl: str) -> None:
        return None


def server_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ClientError('Invalid server URL') from None
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
        raise ClientError('Server must be an HTTPS origin without credentials, path, query, or fragment')
    return value.rstrip('/')


def response_string(response: Mapping[str, object], key: str) -> str:
    value = response[key]
    if not isinstance(value, str):
        raise ClientError('Invalid server response')
    return value


def api(server: str, path: str, data: Mapping[str, object] | None = None, credential: str | None = None) -> dict[str, object]:
    headers = {'Accept': 'application/json', 'User-Agent': f'dnspoke/{__version__}'}
    if credential:
        headers['Authorization'] = 'Bearer ' + credential
    payload = None
    if data is not None:
        payload = json.dumps(data).encode()
        headers['Content-Type'] = 'application/json'
    req = Request(server_url(server) + path, data=payload, headers=headers)
    try:
        with build_opener(NoRedirect).open(req, timeout=90) as response:
            raw = response.read(16385)
            if len(raw) > 16384:
                raise ClientError('Oversized server response')
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            return cast(dict[str, object], value)
    except HTTPError as error:
        messages = {401: 'Credential expired, used, or revoked; ask the administrator if enrollment is needed',
                    409: 'Conflicting DNS assignment; ask the administrator',
                    429: 'Rate limited; retry after five minutes',
                    502: 'DNS provider temporarily unavailable', 503: 'Service busy; retry later'}
        raise ClientError(messages.get(error.code, f'Server rejected request (HTTP {error.code}); redirects are never followed')) from None
    except (URLError, TimeoutError, OSError):
        raise ClientError('Cannot reach the HTTPS service; no local credentials changed') from None
    except (ValueError, KeyError):
        raise ClientError('Invalid server response') from None


def read_config(path: Path) -> DeviceConfig:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ClientError('Credential file must be owned by you, regular, and mode 600')
    try:
        value = json.loads(path.read_text())
        server_url(value['server'])
        if not isinstance(value['device_secret'], str) or not isinstance(value['hostname'], str):
            raise ValueError
        return cast(DeviceConfig, value)
    except (ValueError, KeyError, TypeError):
        raise ClientError('Invalid credential file') from None


def write_config(path: Path, config: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o077:
        raise ClientError('Credential directory must be owned by you and mode 700')
    fd, temporary = tempfile.mkstemp(prefix='.device-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(config, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update(path: Path, force: bool = False) -> None:
    config = read_config(path)
    ip = response_string(api(config['server'], '/v1/ip'), 'ip')
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4 or not address.is_global:
            raise ValueError
    except ValueError:
        raise ClientError('Server did not observe a public IPv4 address') from None
    if not force and config.get('last_ip') == ip and time.time() - config.get('last_sync', 0) < 86400:
        print(f"{config['hostname']}: unchanged ({ip})", flush=True)
        return
    token = api(config['server'], '/v1/token', {}, config['device_secret'])
    if token.get('hostname') != config['hostname']:
        raise ClientError('Token hostname does not match this device')
    result = api(config['server'], '/v1/update', {}, response_string(token, 'token'))
    if result.get('hostname') != config['hostname'] or result.get('ip') != ip:
        raise ClientError('Update response did not match; network address may have changed, retry later')
    config['last_ip'] = response_string(result, 'ip')
    config['last_sync'] = time.time()
    write_config(path, config)
    print(f"{config['hostname']}: {'updated' if result['changed'] else 'verified'} {result['ip']}", flush=True)


def check_period(minutes: object) -> int:
    if type(minutes) is not int or minutes < 5:
        raise ClientError('Check period must be a whole number of minutes, at least 5')
    return minutes * 60


def polling_interval(config: Mapping[str, object], minutes: int | None = None, seconds: int | None = None) -> int:
    if minutes is not None:
        return check_period(minutes)
    if seconds is not None:
        if seconds < 300:
            raise ClientError('Polling interval must be at least 300 seconds')
        return seconds
    return check_period(config.get('check_period_minutes', 5))


def main() -> int:
    default = Path(os.environ.get('XDG_CONFIG_HOME', Path.home() / '.config')) / 'dnspoke/device.json'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--config', type=Path, default=default)
    commands = parser.add_subparsers(dest='command', required=True)
    admin.configure_parser(commands.add_parser('admin', help='Manage this server using its local database and environment'))
    enroll = commands.add_parser('enroll', help='Exchange a one-time invite for this device')
    enroll.add_argument('invite', nargs='?', help='Complete invite code; prompts visibly when omitted')
    send = commands.add_parser('update', help='Report a changed public IPv4 address')
    send.add_argument('--force', action='store_true', help='Verify DNS even if your address is unchanged')
    configure = commands.add_parser('configure', help='Save background service settings')
    configure.add_argument('--ttl', type=int, required=True, metavar='MINUTES', help='Minutes between checks (minimum 5)')
    commands.add_parser('status', help='Show local enrollment status without revealing credentials')
    commands.add_parser('token', help='Print a five-minute, single-use update token')
    watch = commands.add_parser('watch', help='Poll for address changes; suitable for brew services')
    period = watch.add_mutually_exclusive_group()
    period.add_argument('--ttl', type=int, metavar='MINUTES', help='Override saved check period in minutes (minimum 5)')
    period.add_argument('--interval', type=int, metavar='SECONDS', help='Legacy override in seconds (minimum 300)')
    args = parser.parse_args()
    if args.command == 'admin':
        return admin.run(args)
    try:
        if args.command == 'enroll':
            if args.config.exists():
                raise ClientError('Already enrolled; use a separate --config or ask the administrator to revoke the old device')
            # Check local storage before consuming the one-use invite.
            args.config.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if args.config.parent.stat().st_mode & 0o077:
                raise ClientError('Credential directory must be mode 700')
            invite = (args.invite if args.invite is not None else input('One-time invite: ')).strip()
            try:
                server, invite = unpack_invite(invite)
            except Rejected as error:
                raise ClientError(str(error)) from None
            print(f'Enrolling with {server}…')
            result = api(server, '/v1/enroll', {'invite': invite})
            if not all(isinstance(result.get(k), str) for k in ('device_id', 'device_secret', 'hostname')):
                raise ClientError('Invalid enrollment response; ask the administrator for a new invite')
            enrollment: DeviceConfig = {
                'server': server,
                'device_id': response_string(result, 'device_id'),
                'device_secret': response_string(result, 'device_secret'),
                'hostname': response_string(result, 'hostname'),
            }
            write_config(args.config, enrollment)
            print(f"Enrolled {result['hostname']}. Run dnspoke update, then enable the background service if desired.")
        elif args.command == 'update':
            update(args.config, args.force)
        elif args.command == 'configure':
            check_period(args.ttl)
            config = read_config(args.config)
            config['check_period_minutes'] = args.ttl
            write_config(args.config, config)
            print(f'Polling TTL saved: {args.ttl} minutes. Restart any running service to apply.')
        elif args.command == 'status':
            config = read_config(args.config)
            status = {k: config.get(k) for k in ('server', 'hostname', 'device_id', 'last_ip', 'last_sync')}
            status['check_period_minutes'] = config.get('check_period_minutes', 5)
            print(json.dumps(status, indent=2))
        elif args.command == 'token':
            config = read_config(args.config)
            print(api(config['server'], '/v1/token', {}, config['device_secret'])['token'])
        else:
            interval = polling_interval(read_config(args.config), args.ttl, args.interval)
            stop = threading.Event()
            def handle_stop(signum: int, frame: object) -> None:
                stop.set()
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, handle_stop)
            failures = 0
            while not stop.is_set():
                try:
                    update(args.config)
                    failures = 0
                except (ClientError, OSError, KeyError, TypeError) as error:
                    failures += 1
                    print(str(error) if isinstance(error, ClientError) else 'Local credentials unavailable or invalid', file=sys.stderr, flush=True)
                stop.wait(max(interval, min(1800, interval * (2 ** min(failures, 3)))) + random.uniform(0, 15))
    except (ClientError, OSError, KeyError, TypeError) as error:
        print(str(error) if isinstance(error, ClientError) else 'Local credentials unavailable or invalid', file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
