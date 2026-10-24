from __future__ import annotations

from pathlib import Path
from typing import Literal

from lexicon.config import ConfigResolver
import pytest
import requests

from dnspoke.core import Store
from dnspoke.provider import LexiconProvider
from dnspoke.server import create_app

@pytest.mark.parametrize('name', ['providerone', 'providertwo'])
def test_configured_provider_and_its_environment_reach_lexicon(name: str,monkeypatch: pytest.MonkeyPatch) -> None:
    from lexicon import client
    captured=[]
    monkeypatch.setenv(f'LEXICON_{name.upper()}_AUTH_TOKEN','test-only-token')
    class Client:
        def __init__(self,config: ConfigResolver) -> None:
            captured.append((config.resolve('lexicon:provider_name'),
                             config.resolve('lexicon:domain'),
                             config.resolve(f'lexicon:{name}:auth_token')))
        def __enter__(self) -> Client:return self
        def __exit__(self,*args: object) -> Literal[False]:return False
    monkeypatch.setattr(client,'Client',Client)
    original=requests.sessions.Session.request
    with LexiconProvider('example.com',name).connect():
        assert requests.sessions.Session.request is not original
    assert requests.sessions.Session.request is original
    assert captured==[(name,'example.com','test-only-token')]


@pytest.mark.parametrize('value', [None,'','../provider','bad-provider','PROVIDER'])
def test_invalid_or_missing_provider_fails_closed(value: str | None) -> None:
    with pytest.raises(ValueError,match='DNS_PROVIDER'):
        LexiconProvider('example.com',value)


@pytest.mark.parametrize('value', ['-1','3601','invalid'])
def test_invalid_cooldown_rejected(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,value: str) -> None:
    monkeypatch.setenv('DNS_PROVIDER_COOLDOWN',value)
    class Provider:
        def update(self, name: str, ip: str, adopt: bool) -> bool:
            return True
    with pytest.raises(ValueError,match='DNS_PROVIDER_COOLDOWN'):
        create_app(Store(tmp_path/'state.sqlite3'),Provider())


def test_zero_default_allows_independent_devices_without_provider_delay(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('DNS_PROVIDER_COOLDOWN',raising=False)
    class Provider:
        def update(self,*args: object) -> bool:return True
    store=Store(tmp_path/'state.sqlite3')
    client=create_app(store,Provider()).test_client()
    for label in ('alice','bob'):
        device=store.enroll(store.invite(label+'.example.com'))
        token=store.token(device['device_secret'])['token']
        response=client.post('/v1/update',json={},headers={'Authorization':'Bearer '+token},environ_overrides={'REMOTE_ADDR':'8.8.8.8'})
        assert response.status_code==200
