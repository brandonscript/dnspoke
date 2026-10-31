from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from dnspoke import __version__, admin, cli
from dnspoke.core import Store

HELP_PATHS = [
    [],
    ["help"],
    ["admin"],
    ["help", "admin"],
    ["admin", "help"],
    ["help", "admin", "invite"],
    ["admin", "help", "invite"],
    ["admin", "invite", "help"],
    *[
        ["help", command]
        for command in ("enroll", "update", "configure", "status", "token", "watch")
    ],
    *[
        ["admin", "help", command]
        for command in ("endpoint", "devices", "device", "revoke", "audit")
    ],
]


@pytest.mark.parametrize("arguments", HELP_PATHS)
def test_help_is_useful_without_accessing_server_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
) -> None:
    database = tmp_path / "missing/state.sqlite3"
    monkeypatch.setenv("DNS_DATABASE", str(database))

    def forbidden(*args: object, **kwargs: object) -> Store:
        raise AssertionError("Help must not open a database")

    monkeypatch.setattr(admin, "Store", forbidden)
    monkeypatch.setattr("sys.argv", ["python3.14 -m dnspoke.cli", *arguments])
    assert cli.main() == 0
    captured = capsys.readouterr()
    assert not captured.err
    assert captured.out.startswith("usage: dnspoke")
    assert "python3.14 -m" not in captured.out
    assert "Examples:" in captured.out
    assert "Options:" in captured.out
    assert not database.parent.exists()


@pytest.mark.parametrize(
    "arguments",
    [["--help"], ["admin", "--help"], ["admin", "invite", "--help"], ["watch", "--help"]],
)
def test_flag_help_uses_same_format(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["dnspoke", *arguments])
    with pytest.raises(SystemExit) as exit:
        cli.main()
    assert exit.value.code == 0
    assert "Examples:" in capsys.readouterr().out


def test_version_flag_still_prints_only_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["dnspoke", "--version"])
    with pytest.raises(SystemExit) as exit:
        cli.main()
    assert exit.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


@pytest.mark.parametrize(
    "arguments", [["device"], ["devices"], ["device", "list"], ["devices", "list"]]
)
@pytest.mark.parametrize("option_first", [True, False])
def test_device_list_aliases_and_database_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    option_first: bool,
) -> None:
    database = tmp_path / "state.sqlite3"
    store = Store(database)
    device = store.enroll(store.invite("alice.example.com"))
    monkeypatch.setenv("DNS_DATABASE", str(tmp_path / "wrong.sqlite3"))
    option = ["--database", str(database)]
    monkeypatch.setattr(
        "sys.argv",
        ["dnspoke", "admin", *(option + arguments if option_first else arguments + option)],
    )
    assert cli.main() == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["id"] == device["device_id"]
    assert device["device_secret"] not in str(rows)
    assert not (tmp_path / "wrong.sqlite3").exists()


@pytest.mark.parametrize("command", ["devices", "audit", "revoke"])
def test_missing_native_database_gives_docker_guidance_without_creating_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
) -> None:
    missing = tmp_path / "missing/state.sqlite3"
    monkeypatch.delenv("DNS_DATABASE", raising=False)
    monkeypatch.setattr(admin, "DEFAULT_DATABASE", missing)
    monkeypatch.setattr(
        "sys.argv", ["dnspoke", "admin", command, *(["device-id"] if command == "revoke" else [])]
    )
    assert cli.main() == 1
    error = capsys.readouterr().err
    assert "docker exec dnspoke dnspoke admin devices" in error
    assert "DNS_DATABASE" in error and "--database" in error
    assert "Traceback" not in error
    assert not missing.parent.exists()


@pytest.mark.parametrize(
    "failure",
    [
        PermissionError("raw details"),
        sqlite3.OperationalError("raw details"),
        sqlite3.DatabaseError("raw details"),
    ],
)
def test_database_errors_are_actionable_without_tracebacks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    failure: Exception,
) -> None:
    database = tmp_path / "state.sqlite3"
    database.touch()
    monkeypatch.setenv("DNS_DATABASE", str(database))

    def inaccessible(*args: object, **kwargs: object) -> Store:
        raise failure

    monkeypatch.setattr(admin, "Store", inaccessible)
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "devices"])
    assert cli.main() == 1
    error = capsys.readouterr().err
    assert "Cannot access the relay database" in error
    assert "permissions" in error and "docker exec" in error
    assert "raw details" not in error and "Traceback" not in error


def test_missing_zone_fails_before_creating_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "missing/state.sqlite3"
    monkeypatch.setenv("DNS_DATABASE", str(database))
    monkeypatch.delenv("DNS_ZONE", raising=False)
    monkeypatch.setattr("sys.argv", ["dnspoke", "admin", "invite", "alice"])
    assert cli.main() == 1
    assert "Missing server setting: DNS_ZONE" in capsys.readouterr().err
    assert not database.parent.exists()


def test_help_after_config_and_database_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "dnspoke",
            "--config",
            str(tmp_path / "client.json"),
            "admin",
            "--database",
            str(tmp_path / "db"),
            "help",
            "devices",
        ],
    )
    assert cli.main() == 0
    assert "List device IDs" in capsys.readouterr().out
    assert not list(tmp_path.iterdir())
