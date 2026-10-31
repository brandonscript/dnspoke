from __future__ import annotations

import argparse
import io
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from dnspoke import admin_dns as dns
from dnspoke.core import Rejected
from dnspoke.types import DNSRecord


class Records:
    def __init__(self, records: list[DNSRecord] | None = None) -> None:
        self.records = list(records or [])
        self.calls: list[str] = []

    def list_records(self) -> list[DNSRecord]:
        return list(self.records)

    def create_record(self, rtype: str, name: str, content: str) -> bool:
        self.calls.append("create")
        self.records.append(
            {"id": str(len(self.records) + 100), "name": name, "type": rtype, "content": content}
        )
        return True

    def update_record(self, *, identifier: str, rtype: str, name: str, content: str) -> bool:
        raise AssertionError("No record updates/overwrites allowed")

    def delete_record(self, *, identifier: str, rtype: str, name: str, content: str) -> bool:
        self.calls.append("delete:" + identifier)
        self.records = [r for r in self.records if r["id"] != identifier]
        return True


def record(identifier: str, name: str, kind: str, content: str) -> DNSRecord:
    return {"id": identifier, "name": name, "type": kind, "content": content}


@pytest.fixture
def policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DNS_ADMIN_ZONES", "example.com")
    monkeypatch.setenv("DNS_ACME_DOMAINS", "app.example.com")


@pytest.mark.parametrize(
    "bad", ["example.com.attacker.net", "anotherexample.com", "evil.example.net"]
)
def test_zone_suffix_cannot_escape(policy: None, bad: str) -> None:
    with pytest.raises(Rejected):
        dns.zone_for(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "*.example.com",
        "a..example.com",
        "a.example.com\n",
        "example.com/path",
        "a" * 64 + ".example.com",
        "_" + "a" * 63 + ".example.com",
    ],
)
def test_name_validation(bad: str) -> None:
    with pytest.raises(Rejected):
        dns.dns_name(bad, owner=True)


def test_txt_preserves_other_values_and_names() -> None:
    name = "_acme-challenge.app.example.com"
    existing = [
        record("1", name, "TXT", "other-validation"),
        record("2", name + ".other", "TXT", "value"),
        record("3", "app.example.com", "A", "203.0.113.1"),
    ]
    c = Records(existing)
    out = dns.add_record(c, "TXT", name, "example.com", "new-validation")
    assert out["created"] and c.records[:3] == existing
    assert not dns.add_record(c, "TXT", name, "example.com", "new-validation")["created"]
    assert c.calls == ["create"]


@pytest.mark.parametrize("kind", ["A", "AAAA", "TXT", "CNAME", "MX"])
def test_cname_conflicts_never_overwritten(kind: str) -> None:
    c = Records([record("1", "alias.example.com", kind, "elsewhere.example.net")])
    with pytest.raises(Rejected):
        dns.add_record(c, "CNAME", "alias.example.com", "example.com", "target.example.net")
    assert not c.calls


def test_existing_cname_is_idempotent_and_normalized() -> None:
    c = Records([record("1", "ALIAS.EXAMPLE.COM.", "CNAME", "TARGET.EXAMPLE.NET.")])
    assert not dns.add_record(c, "CNAME", "alias.example.com", "example.com", "target.example.net")[
        "created"
    ]
    assert not c.calls


@pytest.mark.parametrize(
    "name,value",
    [
        ("example.com", "target.example.net"),
        ("alias.example.com", "alias.example.com"),
        ("alias.example.com", "192.0.2.1"),
    ],
)
def test_cname_apex_self_and_ip_rejected(name: str, value: str) -> None:
    c = Records()
    with pytest.raises(Rejected):
        dns.add_record(c, "CNAME", name, "example.com", value)
    assert not c.calls


def test_delete_requires_exact_id_type_name_content() -> None:
    c = Records(
        [
            record("1", "test.example.com", "TXT", "mine"),
            record("2", "test.example.com", "TXT", "other"),
        ]
    )
    with pytest.raises(Rejected):
        dns.remove_record(c, "2", "TXT", "test.example.com", "example.com", "mine")
    assert not c.calls
    assert dns.remove_record(c, "1", "TXT", "test.example.com", "example.com", "mine")
    assert c.records == [record("2", "test.example.com", "TXT", "other")]


@pytest.mark.parametrize("preexisting", [False, True])
def test_acme_journal_cleanup_preserves_borrowed_records(
    policy: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preexisting: bool
) -> None:
    token = "A" * 43
    c = Records(
        [record("old", "_acme-challenge.app.example.com", "TXT", token)] if preexisting else []
    )

    @contextmanager
    def provider(zone: str) -> Iterator[dns.AdminRecordClient]:
        assert zone == "example.com"
        yield c

    monkeypatch.setattr(dns, "provider", provider)
    payload = {"domain": "app.example.com", "validation": token}
    path = tmp_path / "acme.sqlite"
    assert dns.acme_operation("present", payload, path)["created"] is not preexisting
    assert dns.acme_operation("present", payload, path)["present"]
    out = dns.acme_operation("cleanup", payload, path)
    assert out["preexisting_preserved"] == preexisting
    assert bool(c.records) == preexisting
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(Rejected, match="ownership receipt"):
        dns.acme_operation("cleanup", payload, path)


def test_acme_requires_exact_domain_and_digest_value(policy: None) -> None:
    for payload in [
        {"domain": "other.example.com", "validation": "A" * 43},
        {"domain": "app.example.com", "validation": "x"},
    ]:
        with pytest.raises(Rejected):
            dns.acme_request(payload)


def test_provider_exception_does_not_print_secrets(
    policy: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    @contextmanager
    def provider(zone: str) -> Iterator[dns.AdminRecordClient]:
        raise RuntimeError("credential=DO-NOT-PRINT")
        yield Records()

    monkeypatch.setattr(dns, "provider", provider)
    args = argparse.Namespace(
        admin_command="dns", dns_action="list", name="alias.example.com", record_type="TXT"
    )
    assert dns.run(args) == 1
    assert "DO-NOT-PRINT" not in capsys.readouterr().err


def test_acme_cli_reads_stdin_without_public_api(
    policy: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    c = Records()

    @contextmanager
    def provider(zone: str) -> Iterator[dns.AdminRecordClient]:
        yield c

    monkeypatch.setattr(dns, "provider", provider)
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps({"domain": "app.example.com", "validation": "A" * 43}))
    )
    monkeypatch.setenv("DNS_ACME_DATABASE", str(tmp_path / "acme.sqlite"))
    args = argparse.Namespace(admin_command="acme", acme_action="present", database=None)
    assert dns.run(args) == 0
