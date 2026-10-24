from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from flask.testing import FlaskClient
from werkzeug.test import TestResponse
import pytest

from dnspoke.core import Rejected, hostname, public_ipv4
from dnspoke.core import Store
from dnspoke.provider import LexiconProvider
from dnspoke.server import create_app
from dnspoke.types import DNSRecord, Enrollment, RecordClient

class FakeProvider:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []
        self.error: Exception | None = None
    def update(self, name: str, ip: str, adopt: bool) -> bool:
        self.calls.append((name, ip, adopt))
        if self.error:
            raise self.error
        return True


@pytest.fixture
def setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Store, FakeProvider, FlaskClient]:
    monkeypatch.setenv("DNS_PROVIDER_COOLDOWN", "35")
    store = Store(tmp_path / 'state.sqlite3')
    provider = FakeProvider()
    app = create_app(store, provider)
    app.config['TESTING'] = True
    return store, provider, app.test_client()


def enroll(store: Store, label: str='alice', adopt: bool=False) -> Enrollment:
    return store.enroll(store.invite(hostname(label, 'example.com'), adopt=adopt))


def send(client: FlaskClient, path: str, token: str | None=None, data: dict[str, object] | None=None, ip: str='8.8.8.8') -> TestResponse:
    return client.post(path, json={} if data is None else data,
        headers={'Authorization': 'Bearer ' + token} if token else {},
        environ_overrides={'REMOTE_ADDR': ip})


def update(store: Store, client: FlaskClient, device: Enrollment, *, data: dict[str, object] | None = None, ip: str = '8.8.8.8') -> TestResponse:
    token = store.token(device['device_secret'])['token']
    return send(client, '/v1/update', token, data=data, ip=ip)


def test_invite_is_single_use_and_hashed(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, _ = setup
    invite = store.invite('alice.example.com')
    with store.transaction() as db:
        assert db.execute('SELECT hash FROM invites').fetchone()['hash'] != invite
    device = store.enroll(invite)
    with pytest.raises(Rejected):
        store.enroll(invite)
    with store.transaction() as db:
        assert db.execute('SELECT hash FROM devices').fetchone()['hash'] != device['device_secret']


def test_expired_invite_rejected(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, _ = setup
    invite = store.invite('alice.example.com')
    with store.transaction() as db:
        db.execute('UPDATE invites SET expires=0')
    with pytest.raises(Rejected):
        store.enroll(invite)


def test_concurrent_redemption_has_one_winner(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, _ = setup
    invite = store.invite('alice.example.com')
    def redeem(_: int) -> bool:
        try:
            return bool(store.enroll(invite))
        except Rejected:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(redeem, range(2))) == 1


def test_scoped_update_uses_observed_ip_and_records_audit(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    response = update(store, client, device)
    assert response.status_code == 200
    assert provider.calls == [('alice.example.com', '8.8.8.8', False)]
    with store.transaction() as db:
        assert db.execute('SELECT hostname FROM audit').fetchone()['hostname'] == 'alice.example.com'
        assert db.execute('SELECT adopt FROM devices').fetchone()['adopt'] == 1


def test_token_cannot_select_name_or_ip(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    assert update(store, client, device, data={'hostname': 'bob.example.com', 'ip': '1.1.1.1'}).status_code == 400
    assert not provider.calls


def test_revoked_device_cannot_mint_or_use_tokens(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    token = store.token(device['device_secret'])['token']
    assert store.revoke(device['device_id'])
    with pytest.raises(Rejected):
        store.token(device['device_secret'])
    assert send(client, '/v1/update', token).status_code == 401
    assert not provider.calls


def test_expired_token_and_replay_rejected(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, client = setup
    device = enroll(store)
    token = store.token(device['device_secret'])['token']
    with store.transaction() as db:
        db.execute('UPDATE tokens SET expires=0')
    assert send(client, '/v1/update', token).status_code == 401
    token = store.token(device['device_secret'])['token']
    assert send(client, '/v1/update', token).status_code == 200
    assert send(client, '/v1/update', token).status_code == 401


def test_device_secret_is_not_update_token(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    assert send(client, '/v1/update', device['device_secret']).status_code == 401
    assert not provider.calls


def test_failures_consume_token_and_preserve_totp_cooldown(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    provider.error = RuntimeError('secret-password-do-not-expose')
    token = store.token(device['device_secret'])['token']
    response = send(client, '/v1/update', token)
    assert response.status_code == 502
    assert b'secret-password' not in response.data
    assert send(client, '/v1/update', token).status_code == 401
    provider.error = None
    assert update(store, client, device).status_code == 429
    assert len(provider.calls) == 1


def test_per_device_cooldown(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, provider, client = setup
    device = enroll(store)
    assert update(store, client, device).status_code == 200
    with store.transaction() as db:
        db.execute("DELETE FROM meta")
    assert update(store, client, device).status_code == 429
    assert len(provider.calls) == 1


def test_invalid_auth_is_rate_limited(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, client = setup
    for _ in range(10):
        assert send(client, '/v1/enroll', data={'invite': 'x'*43}).status_code == 401
    assert send(client, '/v1/enroll', data={'invite': 'x'*43}).status_code == 429


@pytest.mark.parametrize('label', ['@', '*', 'a.b', '-alice', 'Alice', 'mail', 'dns', 'a'*64])
def test_bad_labels(label: str) -> None:
    with pytest.raises(Rejected):
        hostname(label, 'example.com')


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.0.0.1', '::1', '2001:4860:4860::8888', 'bad', '192.0.2.1', '100.64.0.1'])
def test_non_public_ipv4_rejected(ip: str) -> None:
    with pytest.raises(Rejected):
        public_ipv4(ip)


class FakeLexicon:
    def __init__(self, records: list[DNSRecord]) -> None:
        self.records = records
        self.mutations: list[dict[str, str] | tuple[str, str, str]] = []
    def list_records(self) -> list[DNSRecord]:
        return self.records
    def update_record(self, **kw: str) -> bool:
        self.mutations.append(kw)
        for record in self.records:
            if record['id'] == kw['identifier']:
                record['content'] = kw['content']
        return True
    def create_record(self, kind: str, name: str, ip: str) -> bool:
        self.mutations.append((kind, name, ip))
        self.records.append({'id':'new', 'type':kind, 'name':name, 'content':ip})
        return True


def adapter(client: FakeLexicon) -> LexiconProvider:
    from contextlib import contextmanager
    class Adapter(LexiconProvider):
        @contextmanager
        def connect(self) -> Iterator[RecordClient]:
            yield client
    return Adapter('example.com', 'example_provider')


def record(name: str, kind: str='A', content: str='1.1.1.1', id: str='id') -> DNSRecord:
    return {'id': id, 'name':name, 'type':kind, 'content':content}


def test_exact_matching_preserves_wildcards_and_substring_names() -> None:
    client = FakeLexicon([record('*.example.com',id='wildcard'), record('notalice.example.com',id='other'), record('alice.example.com')])
    assert adapter(client).update('alice.example.com', '8.8.8.8', True)
    assert client.records[0]['content'] == client.records[1]['content'] == '1.1.1.1'
    assert client.mutations == [{'identifier':'id','rtype':'A','name':'alice.example.com','content':'8.8.8.8'}]


@pytest.mark.parametrize('records', [[record('alice.example.com', 'CNAME')], [record('alice.example.com'),record('alice.example.com',id='other')], [record('alice.example.com','TXT')]])
def test_provider_refuses_conflicting_records(records: list[DNSRecord]) -> None:
    client = FakeLexicon(records)
    with pytest.raises(Rejected):
        adapter(client).update('alice.example.com','8.8.8.8', True)
    assert not client.mutations


def test_existing_record_requires_adoption_even_with_same_ip() -> None:
    client = FakeLexicon([record('alice.example.com',content='8.8.8.8')])
    with pytest.raises(Rejected):
        adapter(client).update('alice.example.com','8.8.8.8',False)
    assert not client.mutations


def test_new_record_created_without_touching_wildcard() -> None:
    client = FakeLexicon([record('*.example.com')])
    assert adapter(client).update('alice.example.com','8.8.8.8',False)
    assert client.mutations == [('A','alice.example.com','8.8.8.8')]


def test_new_invite_can_replace_revoked_device(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store, _, _ = setup
    device = enroll(store)
    with pytest.raises(Rejected):
        store.invite('alice.example.com')
    store.revoke(device['device_id'])
    assert enroll(store)['device_id'] != device['device_id']


def test_forwarded_headers_only_trusted_from_configured_proxy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('DNS_TRUST_PROXY','1')
    monkeypatch.setenv('DNS_TRUSTED_PROXY','172.20.0.2')
    client = create_app(Store(tmp_path/'proxy.sqlite3'),FakeProvider()).test_client()
    response=client.get('/v1/ip',headers={'X-Forwarded-For':'8.8.8.8'},environ_overrides={'REMOTE_ADDR':'172.20.0.9'})
    assert response.status_code==403
    response=client.get('/v1/ip',headers={'X-Forwarded-For':'8.8.8.8'},environ_overrides={'REMOTE_ADDR':'172.20.0.2'})
    assert response.json is not None
    assert response.json['ip']=='8.8.8.8'


def test_cross_device_tokens_cannot_be_substituted(setup: tuple[Store, FakeProvider, FlaskClient]) -> None:
    store,provider,client=setup
    alice=enroll(store,'alice')
    bob=enroll(store,'bob')
    token=store.token(bob['device_secret'])['token']
    bob_response = send(client,'/v1/update',token)
    assert bob_response.json is not None
    assert bob_response.json['hostname']=='bob.example.com'
    assert provider.calls[0][0]=='bob.example.com'
    with store.transaction() as db:db.execute('DELETE FROM meta')
    alice_response = update(store,client,alice)
    assert alice_response.json is not None
    assert alice_response.json['hostname']=='alice.example.com'


def test_existing_database_migrates_without_losing_credentials(tmp_path: Path) -> None:
    path = tmp_path / 'legacy.sqlite3'
    store = Store(path)
    device = enroll(store)
    with store.transaction() as db:
        db.execute('ALTER TABLE devices DROP COLUMN device_hostname')
    migrated = Store(path)
    Store(path)
    assert migrated.token(device['device_secret'])['hostname'] == 'alice.example.com'
    with migrated.transaction() as db:
        row = db.execute('SELECT * FROM devices').fetchone()
        assert row['device_hostname'] is None
        assert row['created'] > 0


@pytest.mark.parametrize('value', ['', 'x' * 254, 'bad\nname', '\x1b[31mhost', ' host', 123, {'name': 'host'}])
def test_invalid_device_hostname_does_not_consume_invite(setup: tuple[Store, FakeProvider, FlaskClient], value: object) -> None:
    store, _, client = setup
    invite = store.invite('alice.example.com')
    assert send(client, '/v1/enroll', data={'invite': invite, 'device_hostname': value}).status_code == 400
    assert send(client, '/v1/enroll', data={'invite': invite, 'device_hostname': 'laptop.local'}).status_code == 200
