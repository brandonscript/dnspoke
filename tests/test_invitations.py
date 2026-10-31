from __future__ import annotations

import base64
from pathlib import Path

import pytest

from dnspoke import cli
from dnspoke.core import Rejected, Store
from dnspoke.invitations import pack_invite, unpack_invite


def encoded(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def test_version_and_secret_are_inside_encoding() -> None:
    secret = "ab" * 12
    value = pack_invite("https://dns.example.com/", secret)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    assert raw == b"2/" + bytes.fromhex(secret) + b"dns.example.com"
    assert "/" not in value and "." not in value
    assert "dns.example.com" not in value
    assert len(value) == 39
    assert unpack_invite(value) == ("https://dns.example.com", secret)


@pytest.mark.parametrize(
    "authority",
    [
        "user:pass@dns.example.com",
        "dns.example.com/path",
        "dns.example.com?secret=x",
        "dns.example.com:bad",
        "dns.example.com\n",
        "dns.example.com#fragment",
    ],
)
def test_bad_embedded_server_rejected(authority: str) -> None:
    with pytest.raises(Rejected):
        unpack_invite(encoded(b"2/" + b"x" * 12 + authority.encode()))


@pytest.mark.parametrize(
    "value",
    [
        "not.an.invite",
        "!",
        "a" * 4097,
        "https://dns.example.com/#secret",
        "dr2.abc",
        "dnspoke-v1.abc",
        "",
    ],
)
def test_malformed_invites_rejected(value: str) -> None:
    with pytest.raises(Rejected):
        unpack_invite(value)


def test_admin_uses_configured_instance_and_scopes_invite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DNS_DATABASE", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("DNS_ZONE", "example.com")
    monkeypatch.setenv("RELAY_PUBLIC_URL", "https://dns.example.com")
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "invite", "alice"])
    assert cli.main() == 0
    token = capsys.readouterr().out.split("One-time invite (share privately): ")[1].strip()
    server, secret = unpack_invite(token)
    assert server == "https://dns.example.com"
    assert Store(tmp_path / "state.sqlite3").enroll(secret)["hostname"] == "alice.example.com"


def test_missing_server_config_uses_saved_random_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("DNS_DATABASE", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("DNS_ZONE", "example.com")
    monkeypatch.delenv("RELAY_PUBLIC_URL", raising=False)
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "invite", "alice"])
    assert cli.main() == 0
    output = capsys.readouterr().out
    from dnspoke.settings import relay_url

    assert relay_url(Store(tmp_path / "state.sqlite3"), "example.com") in output


def test_invite_entropy_single_use_and_credential_exchange(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.sqlite3")
    secret = store.invite("alice.example.com")
    assert len(bytes.fromhex(secret)) == 12
    invitation = pack_invite("https://dns.example.com", secret)
    assert unpack_invite(invitation) == ("https://dns.example.com", secret)
    device = store.enroll(secret)
    assert len(device["device_secret"]) == 43
    assert len(store.token(device["device_secret"])["token"]) == 43
    with pytest.raises(Rejected):
        store.enroll(secret)
    with pytest.raises(Rejected):
        store.token(secret)


@pytest.mark.parametrize("server", ["https://relay.example.com:8443", "https://[2001:db8::1]:8443"])
def test_authority_preserves_port_and_ipv6(server: str) -> None:
    assert unpack_invite(pack_invite(server, "ab" * 12)) == (server, "ab" * 12)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"2/",
        b"2/" + b"x" * 12,
        b"2/" + b"x" * 11,
        b"wrong",
        b"2/" + b"x" * 12 + b"user@host.example",
    ],
)
def test_bad_binary_invite_rejected(payload: bytes) -> None:
    with pytest.raises(Rejected):
        unpack_invite(encoded(payload))


def test_unknown_version_rejected_explicitly() -> None:
    with pytest.raises(Rejected, match="Unsupported invite version"):
        unpack_invite(encoded(b"3/" + b"x" * 12 + b"dns.example.com"))


def test_admin_device_management_through_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "state.sqlite3"
    monkeypatch.setenv("DNS_DATABASE", str(database))
    store = Store(database)
    device = store.enroll(store.invite("alice.example.com"), "test-laptop.local")
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "devices"])
    assert cli.main() == 0
    listing = capsys.readouterr().out
    assert device["device_id"] in listing
    assert "test-laptop.local" in listing
    assert "registered_at" in listing and "+00:00" in listing
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "revoke", device["device_id"]])
    assert cli.main() == 0
    assert "Device revoked" in capsys.readouterr().out
    with pytest.raises(Rejected):
        store.token(device["device_secret"])
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "audit"])
    assert cli.main() == 0
    assert capsys.readouterr().out.strip() == "[]"


@pytest.mark.parametrize(
    ("ttl", "yolo", "allowed"),
    [
        (900, False, True),
        (901, False, False),
        (3600, False, False),
        (86400, False, False),
        (86400, True, True),
        (86401, True, False),
        (59, True, False),
    ],
)
def test_cli_extended_invites_require_yolo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ttl: int,
    yolo: bool,
    allowed: bool,
) -> None:
    monkeypatch.setenv("DNS_DATABASE", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("DNS_ZONE", "example.com")
    monkeypatch.setenv("RELAY_PUBLIC_URL", "https://dns.example.com")
    argv = ["dnspoke", "admin", "invite", "alice", "--ttl", str(ttl)]
    if yolo:
        argv.append("--yolo")
    monkeypatch.setattr("sys.argv", argv)
    assert cli.main() == (0 if allowed else 1)
    captured = capsys.readouterr()
    store = Store(tmp_path / "state.sqlite3")
    with store.transaction() as db:
        row = db.execute("SELECT expires FROM invites").fetchone()
    if not allowed:
        assert row is None
        assert "One-time invite" not in captured.out
        if 900 < ttl <= 86400:
            assert "--yolo" in captured.err
    else:
        import time

        assert row is not None
        assert time.time() + ttl - 5 <= row["expires"] <= time.time() + ttl
        code = captured.out.split("One-time invite (share privately): ")[1].strip()
        _, secret = unpack_invite(code)
        store.enroll(secret)
        with pytest.raises(Rejected):
            store.enroll(secret)


@pytest.mark.parametrize("label", [None, "enroll"])
def test_endpoint_suggests_random_or_chosen_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    label: str | None,
) -> None:
    import re

    monkeypatch.setenv("DNS_ZONE", "example.com")
    monkeypatch.setenv("DNS_DATABASE", str(tmp_path / "state.sqlite3"))
    monkeypatch.delenv("RELAY_PUBLIC_URL", raising=False)
    argv = ["dnspoke", "admin", "endpoint"]
    if label:
        argv += ["--enroll-at", label]
    monkeypatch.setattr("sys.argv", argv)
    assert cli.main() == 0
    url = capsys.readouterr().out.strip()
    if label:
        assert url == "https://enroll.example.com"
    else:
        assert re.fullmatch(r"https://[0-9a-f]{8}\.example\.com", url)
