import pytest


@pytest.fixture(autouse=True)
def default_zone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('DNS_ZONE', 'example.com')
