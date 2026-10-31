"""Dynamic DNS enrollment, updates, and local server administration."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import random
import signal
import socket
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import IO, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__, admin
from .core import Rejected
from .help import add_command, add_help_command, format_help, parse_arguments
from .invitations import unpack_invite
from .storage import ClientError as ClientError
from .storage import check_path, config_path, prepare_directory, secure_file
from .types import DeviceConfig


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: IO[bytes], code: int, msg: str, headers: Message, newurl: str
    ) -> None:
        return None


def server_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ClientError("Invalid server URL") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ClientError(
            "Server must be an HTTPS origin without credentials, path, query, or fragment"
        )
    return value.rstrip("/")


def response_string(response: Mapping[str, object], key: str) -> str:
    value = response[key]
    if not isinstance(value, str):
        raise ClientError("Invalid server response")
    return value


def api(
    server: str, path: str, data: Mapping[str, object] | None = None, credential: str | None = None
) -> dict[str, object]:
    headers = {"Accept": "application/json", "User-Agent": f"dnspoke/{__version__}"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    payload = None
    if data is not None:
        payload = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = Request(server_url(server) + path, data=payload, headers=headers)
    try:
        with build_opener(NoRedirect).open(req, timeout=90) as response:
            raw = response.read(16385)
            if len(raw) > 16384:
                raise ClientError("Oversized server response")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            return cast(dict[str, object], value)
    except HTTPError as error:
        messages = {
            401: (
                "Credential expired, used, or revoked; "
                "ask the administrator if enrollment is needed"
            ),
            409: "Conflicting DNS assignment; ask the administrator",
            429: "Rate limited; retry after five minutes",
            502: "DNS provider temporarily unavailable",
            503: "Service busy; retry later",
        }
        raise ClientError(
            messages.get(
                error.code,
                f"Server rejected request (HTTP {error.code}); redirects are never followed",
            )
        ) from None
    except (URLError, TimeoutError, OSError):
        raise ClientError("Cannot reach the HTTPS service; no local credentials changed") from None
    except (ValueError, KeyError):
        raise ClientError("Invalid server response") from None


def read_config(path: Path) -> DeviceConfig:
    check_path(path.parent, directory=True)
    check_path(path)
    try:
        value = json.loads(path.read_text())
        server_url(value["server"])
        if not isinstance(value["device_secret"], str) or not isinstance(value["hostname"], str):
            raise ValueError
        return cast(DeviceConfig, value)
    except (ValueError, KeyError, TypeError):
        raise ClientError("Invalid credential file") from None


def write_config(path: Path, config: Mapping[str, object]) -> None:
    prepare_directory(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".device-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(config, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        secure_file(Path(temporary))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def local_address(server: str) -> str:
    parsed = urlsplit(server_url(server))
    for family, kind, protocol, _, address in socket.getaddrinfo(
        parsed.hostname, parsed.port or 443, type=socket.SOCK_DGRAM
    ):
        try:
            with socket.socket(family, kind, protocol) as connection:
                connection.connect(address)
                return str(connection.getsockname()[0]).split("%", 1)[0]
        except OSError:
            continue
    raise ClientError("Cannot determine the local address used to reach the relay")


def shared_local_ip(server: str, mode: str) -> str | None:
    if mode == "hidden":
        return None
    if mode not in ("masked", "full"):
        raise ClientError("ip_mode must be masked, full, or hidden")
    address = ipaddress.ip_address(local_address(server))
    if mode == "full":
        return str(address)
    if address.version == 4:
        return "*.*.*." + str(address).rsplit(".", 1)[1]
    return "*::" + format(int(address) & 0xFFFF, "x")


def sync_local_ip(config: DeviceConfig) -> None:
    api(
        config["server"],
        "/v1/device",
        {"local_ip": shared_local_ip(config["server"], config.get("ip_mode", "masked"))},
        config["device_secret"],
    )


def ip_options(parser: argparse.ArgumentParser) -> None:
    options = parser.add_mutually_exclusive_group()
    options.add_argument(
        "--ip",
        dest="ip_mode",
        action="store_const",
        const="full",
        help="Share the full local IP for debugging",
    )
    options.add_argument(
        "--mask-ip",
        dest="ip_mode",
        action="store_const",
        const="masked",
        help="Share only the last IPv4 octet or IPv6 segment (default)",
    )
    options.add_argument(
        "--no-ip",
        dest="ip_mode",
        action="store_const",
        const="hidden",
        help="Remove the local IP from the server",
    )


def update(path: Path, force: bool = False) -> None:
    config = read_config(path)
    sync_local_ip(config)
    ip = response_string(api(config["server"], "/v1/ip"), "ip")
    try:
        address = ipaddress.ip_address(ip)
        if address.version != 4 or not address.is_global:
            raise ValueError
    except ValueError:
        raise ClientError("Server did not observe a public IPv4 address") from None
    if (
        not force
        and config.get("last_ip") == ip
        and time.time() - config.get("last_sync", 0) < 86400
    ):
        print(f"{config['hostname']}: unchanged ({ip})", flush=True)
        return
    token = api(config["server"], "/v1/token", {}, config["device_secret"])
    if token.get("hostname") != config["hostname"]:
        raise ClientError("Token hostname does not match this device")
    result = api(config["server"], "/v1/update", {}, response_string(token, "token"))
    if result.get("hostname") != config["hostname"] or result.get("ip") != ip:
        raise ClientError(
            "Update response did not match; network address may have changed, retry later"
        )
    config["last_ip"] = response_string(result, "ip")
    config["last_sync"] = time.time()
    write_config(path, config)
    print(
        f"{config['hostname']}: {'updated' if result['changed'] else 'verified'} {result['ip']}",
        flush=True,
    )


def check_period(minutes: object) -> int:
    if type(minutes) is not int or minutes < 5:
        raise ClientError("Check period must be a whole number of minutes, at least 5")
    return minutes * 60


def polling_interval(
    config: Mapping[str, object], minutes: int | None = None, seconds: int | None = None
) -> int:
    if minutes is not None:
        return check_period(minutes)
    if seconds is not None:
        if seconds < 300:
            raise ClientError("Polling interval must be at least 300 seconds")
        return seconds
    return check_period(config.get("check_period_minutes", 5))


def main() -> int:
    default = config_path()
    parser = argparse.ArgumentParser(prog="dnspoke")
    format_help(
        parser,
        "Keep your assigned DNS hostname pointed at your current public IP.\n"
        "Enroll with an invite from a relay owner, update once, then enable background checks.",
        "  dnspoke enroll INVITE\n"
        "  dnspoke update\n"
        "  dnspoke watch --ttl 15\n"
        "  dnspoke help admin\n"
        "  docker exec dnspoke dnspoke admin devices",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Show the installed version and exit",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=default,
        metavar="FILE",
        help=f"Client credential file (default: {default}); separate from the server database",
    )
    commands = parser.add_subparsers(dest="command", title="Commands", metavar="COMMAND")
    admin.configure_parser(
        add_command(commands, "admin", "Administer a relay using its local database")
    )
    enroll = add_command(
        commands,
        "enroll",
        "Enroll this device with a one-time invite",
        "Exchange an invite for a persistent device credential. "
        "The invite includes the relay URL.\n"
        "Omit INVITE to paste it at a visible prompt. Each invite can be used once.",
        "  dnspoke enroll\n  dnspoke enroll INVITE\n  dnspoke enroll --no-ip INVITE",
    )
    enroll.add_argument(
        "invite",
        nargs="?",
        metavar="INVITE",
        help="Complete invite code supplied by the relay owner",
    )
    ip_options(enroll)
    send = add_command(
        commands,
        "update",
        "Update DNS if your public IPv4 address changed",
        "Contact the relay, check your public IP, and update only your assigned hostname.\n"
        "Unchanged addresses are skipped unless forced or due for daily reconciliation.",
        "  dnspoke update\n  dnspoke update --force",
    )
    send.add_argument(
        "--force",
        action="store_true",
        help="Verify DNS even if your address is unchanged; rate limits still apply",
    )
    configure = add_command(
        commands,
        "configure",
        "Save polling and local IP sharing preferences",
        "Save settings for this enrolled device. Local IP sharing changes sync immediately;\n"
        "restart a running watcher after changing its polling period. TTL is in minutes here.",
        "  dnspoke configure --ttl 15\n"
        "  dnspoke configure --ip\n"
        "  dnspoke configure --mask-ip\n"
        "  dnspoke configure --no-ip",
    )
    configure.add_argument(
        "--ttl", type=int, metavar="MINUTES", help="Minutes between checks (minimum: 5; default: 5)"
    )
    ip_options(configure)
    add_command(
        commands,
        "status",
        "Show enrollment and saved settings without credentials",
        "Show the relay URL, assigned hostname, device ID, last sync, "
        "polling period, and IP sharing mode.\n"
        "This reads local settings; it does not query the relay.",
        "  dnspoke status",
    )
    add_command(
        commands,
        "token",
        "Print a short-lived DNS update token",
        "Mint and print a single-use update token, valid for five minutes. Requires enrollment.\n"
        "This prints a secret; update and watch obtain tokens automatically for normal use.",
        "  dnspoke token",
    )
    watch = add_command(
        commands,
        "watch",
        "Keep DNS current with background polling",
        "Check periodically until stopped with Ctrl+C or a termination signal.\n"
        "Use the saved polling period (default: five minutes), or override it with --ttl.\n"
        "For Homebrew services, configure the period first, then restart the service.",
        "  dnspoke watch\n"
        "  dnspoke watch --ttl 15\n"
        "  dnspoke configure --ttl 15\n"
        "  brew services restart dnspoke",
    )
    period = watch.add_mutually_exclusive_group()
    period.add_argument(
        "--ttl",
        type=int,
        metavar="MINUTES",
        help="Override the saved check period (minimum: 5 minutes)",
    )
    period.add_argument(
        "--interval",
        type=int,
        metavar="SECONDS",
        help="Legacy seconds-based override (minimum: 300)",
    )
    add_help_command(commands)
    args = parse_arguments(parser)
    if args is None:
        return 0
    if args.command == "admin":
        return admin.run(args)
    try:
        if args.command == "enroll":
            if args.config.exists():
                raise ClientError(
                    "Already enrolled; use a separate --config or ask the administrator "
                    "to revoke the old device"
                )
            # Check local storage before consuming the one-use invite.
            prepare_directory(args.config.parent)
            invite = (
                args.invite if args.invite is not None else input("One-time invite: ")
            ).strip()
            try:
                server, invite = unpack_invite(invite)
            except Rejected as error:
                raise ClientError(str(error)) from None
            print(f"Enrolling with {server}…")
            mode = args.ip_mode or "masked"
            result = api(
                server,
                "/v1/enroll",
                {
                    "invite": invite,
                    "device_hostname": socket.gethostname(),
                    "local_ip": shared_local_ip(server, mode),
                },
            )
            if not all(
                isinstance(result.get(k), str) for k in ("device_id", "device_secret", "hostname")
            ):
                raise ClientError(
                    "Invalid enrollment response; ask the administrator for a new invite"
                )
            enrollment: DeviceConfig = {
                "server": server,
                "ip_mode": mode,
                "device_id": response_string(result, "device_id"),
                "device_secret": response_string(result, "device_secret"),
                "hostname": response_string(result, "hostname"),
            }
            write_config(args.config, enrollment)
            print(
                f"Enrolled {result['hostname']}. Run dnspoke update, "
                "then enable the background service if desired."
            )
        elif args.command == "update":
            update(args.config, args.force)
        elif args.command == "configure":
            if args.ttl is None and args.ip_mode is None:
                raise ClientError("Choose --ttl, --ip, --mask-ip, or --no-ip")
            if args.ttl is not None:
                check_period(args.ttl)
            config = read_config(args.config)
            if args.ttl is not None:
                config["check_period_minutes"] = args.ttl
            if args.ip_mode is not None:
                config["ip_mode"] = args.ip_mode
            write_config(args.config, config)
            if args.ip_mode is not None:
                sync_local_ip(config)
                print(f"Local IP sharing: {args.ip_mode}. Server updated.")
            if args.ttl is not None:
                print(
                    f"Polling TTL saved: {args.ttl} minutes. Restart any running service to apply."
                )
        elif args.command == "status":
            config = read_config(args.config)
            status = {
                k: config.get(k)
                for k in ("server", "hostname", "device_id", "last_ip", "last_sync")
            }
            status["ip_mode"] = config.get("ip_mode", "masked")
            status["check_period_minutes"] = config.get("check_period_minutes", 5)
            print(json.dumps(status, indent=2))
        elif args.command == "token":
            config = read_config(args.config)
            print(api(config["server"], "/v1/token", {}, config["device_secret"])["token"])
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
                    print(
                        str(error)
                        if isinstance(error, ClientError)
                        else "Local credentials unavailable or invalid",
                        file=sys.stderr,
                        flush=True,
                    )
                stop.wait(
                    max(interval, min(1800, interval * (2 ** min(failures, 3))))
                    + random.uniform(0, 15)
                )
    except (ClientError, OSError, KeyError, TypeError) as error:
        print(
            str(error)
            if isinstance(error, ClientError)
            else "Local credentials unavailable or invalid",
            file=sys.stderr,
        )
        return 1
    except (KeyboardInterrupt, EOFError):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
