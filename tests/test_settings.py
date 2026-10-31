import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from dnspoke.core import Rejected, Store
from dnspoke.server import create_app
from dnspoke.settings import relay_url


def test_generated_endpoint_is_stable_across_startups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RELAY_PUBLIC_URL", raising=False)
    monkeypatch.setenv("DNS_PROVIDER", "hover")
    path = tmp_path / "state.sqlite3"
    store = Store(path)
    create_app(store)
    chosen = relay_url(store, "example.com")
    assert re.fullmatch(r"https://[0-9a-f]{8}\.example\.com", chosen)
    with ThreadPoolExecutor(max_workers=4) as workers:
        assert (
            list(workers.map(lambda _: relay_url(Store(path), "example.com"), range(8)))
            == [chosen] * 8
        )
    create_app(Store(path))
    assert relay_url(Store(path), "example.com") == chosen


@pytest.mark.parametrize("choice", ["enroll", "enroll.example.com", "https://enroll.example.com"])
def test_custom_endpoint_is_saved_and_environment_wins(tmp_path: Path, choice: str) -> None:
    store = Store(tmp_path / "state.sqlite3")
    assert relay_url(store, "example.com", enroll_at=choice) == "https://enroll.example.com"
    assert relay_url(store, "example.com") == "https://enroll.example.com"
    assert (
        relay_url(store, "example.com", "https://override.example.com")
        == "https://override.example.com"
    )
    with pytest.raises(Rejected, match="RELAY_PUBLIC_URL"):
        relay_url(store, "example.com", "https://override.example.com", "other")


@pytest.mark.parametrize(
    "choice",
    [
        "_12345678",
        "https://_12345678.example.com",
        "http://example.com",
        "name/path",
        "-name.example.com",
    ],
)
def test_bad_custom_endpoint_rejected(tmp_path: Path, choice: str) -> None:
    with pytest.raises(Rejected):
        relay_url(Store(tmp_path / "state.sqlite3"), "example.com", enroll_at=choice)
