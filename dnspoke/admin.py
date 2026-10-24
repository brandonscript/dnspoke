"""Local-only operator commands; run inside the service container."""
from datetime import datetime, timezone
import argparse
import json
import os
import secrets
import sys

from .core import Store, Rejected, hostname
from .invitations import pack_invite, validate_server

def configure_parser(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest='admin_command', required=True)
    endpoint = commands.add_parser('endpoint', help='Suggest a relay URL to save as RELAY_PUBLIC_URL')
    endpoint.add_argument('--label', help='Choose a DNS label instead of a random eight-character hex label')
    invite = commands.add_parser('invite')
    invite.add_argument('label', help='Single label under the configured zone')
    invite.add_argument('--ttl', type=int, default=900, help='Invite lifetime in seconds (60–86400); over 900 requires --yolo')
    invite.add_argument('--yolo', action='store_true', help='Allow an invite longer than 15 minutes, up to 24 hours')
    invite.add_argument('--adopt-existing', action='store_true', help='Permit replacing the exact existing single A record for this hostname')
    commands.add_parser('devices')
    revoke = commands.add_parser('revoke')
    revoke.add_argument('device_id')
    commands.add_parser('audit')


def run(args: argparse.Namespace) -> int:
    try:
        if args.admin_command == 'endpoint':
            label = args.label if args.label is not None else secrets.token_hex(4)
            print('https://' + hostname(label, os.environ['DNS_ZONE']))
            return 0
        store = Store(os.environ.get('DNS_DATABASE', '/data/state.sqlite3'))
        if args.admin_command == 'invite':
            if not os.environ.get('RELAY_PUBLIC_URL'):
                raise Rejected('Set RELAY_PUBLIC_URL once in the server configuration before issuing invites')
            server = validate_server(os.environ['RELAY_PUBLIC_URL'])
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
    except (Rejected, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args())


if __name__ == '__main__':
    sys.exit(main())
