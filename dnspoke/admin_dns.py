"""Local-only TXT/CNAME administration and journaled ACME challenge cleanup."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol, cast

from .core import Rejected
from .help import add_command, add_help_command
from .provider import LexiconProvider
from .types import DNSRecord, RecordClient


class AdminRecordClient(RecordClient, Protocol):
    def delete_record(self, *, identifier: str, rtype: str, name: str, content: str) -> bool: ...


def dns_name(value: str, *, owner: bool = False) -> str:
    name = value.lower().removesuffix(".")
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if owner:
        label = r"_?" + label
    if (
        len(name) > 253
        or "." not in name
        or not all(len(part) <= 63 and re.fullmatch(label, part) for part in name.split("."))
    ):
        raise Rejected("Expected an ASCII fully qualified DNS name; no wildcards or empty labels")
    return name


def configured_names(setting: str) -> list[str]:
    return [dns_name(s.strip()) for s in os.environ.get(setting, "").split(",") if s.strip()]


def zone_for(name: str) -> str:
    zones = configured_names("DNS_ADMIN_ZONES")
    if not zones:
        raise Rejected("Set an explicit DNS_ADMIN_ZONES allowlist before local DNS administration")
    candidates = [z for z in zones if name == z or name.endswith("." + z)]
    if not candidates:
        raise Rejected("DNS name is outside DNS_ADMIN_ZONES")
    return max(candidates, key=len)


def checked_value(rtype: str, name: str, zone: str, value: str) -> str:
    if rtype not in ("TXT", "CNAME"):
        raise Rejected("Only TXT and CNAME records are supported by local DNS administration")
    if rtype == "CNAME":
        value = dns_name(value)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise Rejected("CNAME targets must be DNS names, not IP addresses")
        if name in (zone, value):
            raise Rejected("CNAME cannot replace the zone apex or point to itself")
    elif (
        not value
        or len(value.encode("utf-8")) > 255
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise Rejected("TXT content must be 1–255 bytes with no control characters")
    return value


def exact_records(client: RecordClient, name: str) -> list[DNSRecord]:
    return [r for r in client.list_records() if r["name"].rstrip(".").lower() == name]


def equal_value(record: DNSRecord, rtype: str, value: str) -> bool:
    old = record["content"].rstrip(".").lower() if rtype == "CNAME" else record["content"]
    return record["type"].upper() == rtype and old == value


def add_record(
    client: RecordClient, rtype: str, name: str, zone: str, value: str
) -> dict[str, Any]:
    value = checked_value(rtype, name, zone, value)
    before = exact_records(client, name)
    if any(r["type"].upper() == "CNAME" for r in before) or (rtype == "CNAME" and before):
        if len(before) == 1 and equal_value(before[0], rtype, value):
            return {"created": False, "record_id": before[0]["id"]}
        raise Rejected("Conflicting records exist at this exact name; no records changed")
    matching = [r for r in before if equal_value(r, rtype, value)]
    if matching:
        if len(matching) != 1:
            raise Rejected("Duplicate exact records require administrator review")
        return {"created": False, "record_id": matching[0]["id"]}
    if not client.create_record(rtype, name, value):
        raise Rejected("DNS provider did not acknowledge creation")
    after = [r for r in exact_records(client, name) if equal_value(r, rtype, value)]
    if len(after) != 1:
        raise Rejected(
            "DNS creation could not be verified; inspect exact-name records before retrying"
        )
    return {"created": True, "record_id": after[0]["id"]}


def remove_record(
    client: AdminRecordClient, identifier: str, rtype: str, name: str, zone: str, value: str
) -> bool:
    value = checked_value(rtype, name, zone, value)
    found = [r for r in exact_records(client, name) if str(r["id"]) == identifier]
    if not found:
        return False
    if len(found) != 1 or not equal_value(found[0], rtype, value):
        raise Rejected("Record ID/name/type/content do not all match; no records changed")
    if not client.delete_record(identifier=identifier, rtype=rtype, name=name, content=value):
        raise Rejected("DNS provider did not acknowledge removal")
    if any(str(r["id"]) == identifier for r in exact_records(client, name)):
        raise Rejected("DNS record removal could not be verified")
    return True


@contextmanager
def provider(zone: str) -> Iterator[AdminRecordClient]:
    with LexiconProvider(zone, os.environ.get("DNS_PROVIDER")).connect() as client:
        yield cast(AdminRecordClient, client)


def acme_request(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    domain = dns_name(str(payload.get("domain", "")))
    if domain not in configured_names("DNS_ACME_DOMAINS"):
        raise Rejected("Certificate domain is not explicitly allowed by DNS_ACME_DOMAINS")
    token = str(payload.get("validation", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise Rejected("Expected a DNS-01 SHA256 validation value")
    name = "_acme-challenge." + domain
    return domain, name, zone_for(name), token


def acme_database(args: argparse.Namespace) -> Path:
    base = Path(args.database or os.environ.get("DNS_DATABASE", "/data/state.sqlite3"))
    p = Path(os.environ.get("DNS_ACME_DATABASE", str(base.with_name("acme.sqlite3"))))
    if p.is_symlink():
        raise Rejected("ACME journal must not be a symbolic link")
    return p


def acme_operation(action: str, payload: dict[str, Any], path: Path) -> dict[str, Any]:
    domain, name, zone, token = acme_request(payload)
    digest = hashlib.sha256(token.encode()).hexdigest()
    os.umask(0o077)
    with sqlite3.connect(path, timeout=20) as db:
        path.chmod(0o600)
        db.execute(
            "CREATE TABLE IF NOT EXISTS challenges(domain TEXT, digest TEXT, "
            "record_id TEXT, owned INTEGER, PRIMARY KEY(domain,digest))"
        )
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT record_id,owned FROM challenges WHERE domain=? AND digest=?", (domain, digest)
        ).fetchone()
        if action == "cleanup" and row is None:
            raise Rejected("No ACME ownership receipt; refusing speculative DNS cleanup")
        with provider(zone) as client:
            if action == "present":
                current = exact_records(client, name)
                if row and any(
                    str(r["id"]) == row[0] and equal_value(r, "TXT", token) for r in current
                ):
                    return {"domain": domain, "present": True, "created": False}
                result = add_record(client, "TXT", name, zone, token)
                db.execute(
                    "INSERT OR REPLACE INTO challenges VALUES(?,?,?,?)",
                    (domain, digest, str(result["record_id"]), int(result["created"])),
                )
                return {"domain": domain, "present": True, "created": result["created"]}
            if row is None:
                raise Rejected("No ACME ownership receipt; refusing speculative DNS cleanup")
            removed = False
            if row[1]:
                removed = remove_record(client, row[0], "TXT", name, zone, token)
            db.execute("DELETE FROM challenges WHERE domain=? AND digest=?", (domain, digest))
            return {"domain": domain, "removed": removed, "preexisting_preserved": not bool(row[1])}


def configure_parser(commands: Any) -> None:
    dns = add_command(
        commands,
        "dns",
        "Administer exact-name TXT and CNAME records locally",
        "Local server credentials only. Requires DNS_ADMIN_ZONES. "
        "Client DNS permissions remain A-only.",
        "  printf %s target.example.net | dnspoke admin dns add CNAME alias.example.com\n"
        "  dnspoke admin dns list TXT _acme-challenge.example.com",
    )
    subs = dns.add_subparsers(dest="dns_action", title="Commands", metavar="COMMAND")
    for action in ("list", "add", "remove"):
        p = add_command(
            subs,
            action,
            {
                "list": "List records at an exact name",
                "add": "Add without overwriting conflicting records",
                "remove": "Remove only an exact ID/type/name/content match",
            }[action],
        )
        p.add_argument("record_type", choices=["TXT", "CNAME"])
        p.add_argument("name", help="Fully qualified record owner")
        if action == "remove":
            p.add_argument("--identifier", required=True, help="Exact provider record ID")
        if action != "list":
            p.epilog = (
                p.epilog or ""
            ) + "\nRecord content is read from standard input (no trailing newline)."
    add_help_command(subs)
    acme = add_command(
        commands,
        "acme",
        "Present or clean up journaled DNS-01 challenges locally",
        "Requires DNS_ADMIN_ZONES and an exact DNS_ACME_DOMAINS allowlist.\n"
        'Read JSON {"domain":"host.example.com","validation":"BASE64URL_SHA256"} '
        "from standard input.\n"
        "Cleanup removes only a recorded challenge created by this helper; "
        "existing records are preserved.",
    )
    acme.add_argument("acme_action", choices=["present", "cleanup"])


def run(args: argparse.Namespace) -> int:
    result: Any
    try:
        if args.admin_command == "acme":
            payload = json.loads(sys.stdin.read(4097))
            if not isinstance(payload, dict):
                raise Rejected("Expected a JSON object on standard input")
            result = acme_operation(args.acme_action, payload, acme_database(args))
        else:
            name = dns_name(args.name, owner=True)
            zone = zone_for(name)
            with provider(zone) as client:
                if args.dns_action == "list":
                    result = [
                        r
                        for r in exact_records(client, name)
                        if r["type"].upper() == args.record_type
                    ]
                else:
                    value = sys.stdin.read(4097).removesuffix("\n")
                    if args.dns_action == "add":
                        result = add_record(client, args.record_type, name, zone, value)
                    else:
                        result = {
                            "removed": remove_record(
                                client, args.identifier, args.record_type, name, zone, value
                            )
                        }
        print(json.dumps(result))
        return 0
    except Rejected as error:
        print(f"Error: {error}", file=sys.stderr)
    except (ValueError, TypeError):
        print("Error: Invalid DNS administration input", file=sys.stderr)
    except Exception:
        # Provider exceptions can contain authentication payloads: never print them.
        print(
            "Error: DNS provider/journal operation failed; verify connectivity, "
            "credentials and private journal permissions",
            file=sys.stderr,
        )
    return 1
