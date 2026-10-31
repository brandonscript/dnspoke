"""Local relay administration using the server's database and environment."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import os
import sqlite3
import sys

from .core import Store, Rejected, hostname
from . import admin_dns
from .help import add_command, add_help_command, format_help, parse_arguments
from .invitations import pack_invite
from .settings import relay_url

DEFAULT_DATABASE = Path('/data/state.sqlite3')
DATABASE_GUIDANCE = (
    'For a Docker relay, run: docker exec dnspoke dnspoke admin devices\n'
    'For a native relay, set DNS_DATABASE or pass --database with the server database path.\n'
    'Invites and endpoint configuration also require DNS_ZONE in the server environment.'
)


def configure_parser(parser: argparse.ArgumentParser) -> None:
    format_help(parser, __doc__ or '',
                '  docker exec dnspoke dnspoke admin devices\n'
                '  dnspoke admin --database /path/to/state.sqlite3 devices\n'
                '  dnspoke admin invite alice\n'
                '  dnspoke admin invite alice --ttl 86400 --yolo\n'
                '  dnspoke help admin invite')
    parser.epilog = (parser.epilog or '') + '\n\n' + DATABASE_GUIDANCE
    parser.add_argument('--database', type=Path, metavar='PATH', help='Server SQLite database; otherwise DNS_DATABASE or /data/state.sqlite3')
    commands = parser.add_subparsers(dest='admin_command', title='Commands', metavar='COMMAND')
    endpoint = add_command(commands, 'endpoint', 'Show or configure the relay address',
                           'Show the saved relay URL. On a new instance, generate and save a random hostname.\n'
                           'RELAY_PUBLIC_URL overrides the saved address. Requires DNS_ZONE.',
                           '  dnspoke admin endpoint\n  dnspoke admin endpoint --enroll-at relay.example.com')
    endpoint.add_argument('--enroll-at', metavar='HOSTNAME', help='Save a custom label, hostname, or HTTPS origin')
    invite = add_command(commands, 'invite', 'Invite a client to manage one hostname',
                         'Create a single-use invite for LABEL under DNS_ZONE. The default lifetime is 15 minutes.\n'
                         'Requires the server database and environment; send the resulting code privately.',
                         '  dnspoke admin invite alice\n'
                         '  dnspoke admin invite alice --ttl 86400 --yolo\n'
                         '  dnspoke admin invite alice --adopt-existing')
    invite.add_argument('label', metavar='LABEL', help='Single DNS label: alice grants access to alice under DNS_ZONE')
    invite.add_argument('--ttl', type=int, default=900, metavar='SECONDS', help='Invite lifetime, 60–86400 seconds (default: 900); over 900 requires --yolo')
    invite.add_argument('--yolo', action='store_true', help='Allow a lifetime longer than 15 minutes, up to 24 hours')
    invite.add_argument('--adopt-existing', action='store_true', help='Allow updating an existing single A record for this hostname')
    devices = add_command(commands, 'devices', 'List enrolled devices and their status',
                          'List device IDs, assigned hostnames, local device details, registration dates,\n'
                          'revocation status, and the last successful DNS update. Credentials are never shown.',
                          '  dnspoke admin devices\n  dnspoke admin devices list', aliases=('device',))
    devices.set_defaults(admin_command='devices')
    devices.add_argument('action', nargs='?', choices=['list'], default='list', help='Optional explicit list action')
    revoke = add_command(commands, 'revoke', 'Revoke a device and its outstanding update tokens',
                         'Disable an enrolled device immediately. Its DNS record stays in place.\n'
                         'Find DEVICE_ID with dnspoke admin devices.',
                         '  dnspoke admin devices\n  dnspoke admin revoke DEVICE_ID')
    revoke.add_argument('device_id', metavar='DEVICE_ID', help='Device ID from the device list')
    audit = add_command(commands, 'audit', 'Show the last 100 successful DNS updates',
                        'Show the newest DNS update audit entries first, including the hostname,\n'
                        'old and new public IPs, and whether the provider changed the record.',
                        '  dnspoke admin audit')
    for child in (endpoint, invite, devices, revoke, audit):
        child.add_argument('--database', type=Path, metavar='PATH', default=argparse.SUPPRESS,
                           help='Server SQLite database (overrides DNS_DATABASE)')
    admin_dns.configure_parser(commands)
    add_help_command(commands)


def database_path(args: argparse.Namespace) -> Path:
    explicit = args.database or os.environ.get('DNS_DATABASE')
    path = Path(explicit) if explicit else DEFAULT_DATABASE
    if not path.is_file() and (not explicit or args.admin_command not in ('invite', 'endpoint')):
        raise Rejected(f'No relay database found at {path}.\n' + DATABASE_GUIDANCE)
    return path


def run(args: argparse.Namespace) -> int:
    if args.admin_command in ("dns", "acme"):
        return admin_dns.run(args)
    path: Path | None = None
    try:
        if args.admin_command in ('invite', 'endpoint') and not os.environ.get('DNS_ZONE'):
            raise Rejected('Missing server setting: DNS_ZONE.\n' + DATABASE_GUIDANCE)
        path = database_path(args)
        store = Store(path)
        if args.admin_command == 'endpoint':
            print(relay_url(store, os.environ['DNS_ZONE'], os.environ.get('RELAY_PUBLIC_URL'), args.enroll_at))
            return 0
        if args.admin_command == 'invite':
            server = relay_url(store, os.environ['DNS_ZONE'], os.environ.get('RELAY_PUBLIC_URL'))
            name = hostname(args.label, os.environ['DNS_ZONE'])
            secret = store.invite(name, args.ttl, args.adopt_existing, yolo=args.yolo)
            invitation = pack_invite(server, secret)
            print(f'Hostname: {name}\nServer: {server}\nExpires in: {args.ttl}s\nOne-time invite (share privately): {invitation}')
        elif args.admin_command == 'revoke':
            if not store.revoke(args.device_id):
                raise Rejected('Device not found')
            print('Device revoked, including outstanding update tokens')
        else:
            with store.transaction() as db:
                query = ('SELECT id,hostname,device_hostname,local_ip,revoked,last_ip,last_update,created FROM devices ORDER BY created'
                         if args.admin_command == 'devices' else 'SELECT * FROM audit ORDER BY at DESC LIMIT 100')
                rows = [dict(row) for row in db.execute(query)]
                if args.admin_command == 'devices':
                    for row in rows:
                        row['registered_at'] = datetime.fromtimestamp(row['created'], timezone.utc).isoformat()
                print(json.dumps(rows, indent=2))
    except Rejected as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    except KeyError as error:
        print(f'Error: Missing server setting: {error.args[0]}.\n' + DATABASE_GUIDANCE, file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error):
        print(f'Error: Cannot access the relay database at {path or DEFAULT_DATABASE}.\n'
              'Check the path, permissions, and database health; retry if the server is busy.\n'
              + DATABASE_GUIDANCE, file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog='dnspoke admin')
    configure_parser(parser)
    args = parse_arguments(parser)
    return run(args) if args is not None else 0


if __name__ == '__main__':
    sys.exit(main())
