from __future__ import annotations

from pathlib import Path

import pytest

from dnspoke import cli

def config(tmp_path: Path) -> Path:
    directory=tmp_path / 'private'
    directory.mkdir(mode=0o700)
    path=directory / 'device.json'
    cli.write_config(path, {'server':'https://dns.example.com','hostname':'alice.example.com','device_secret':'x'*43})
    return path


def test_credentials_are_private_and_status_does_not_print_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    path=config(tmp_path)
    assert path.stat().st_mode & 0o777 == 0o600
    monkeypatch.setattr('sys.argv',['dnspoke','--config',str(path),'status'])
    assert cli.main()==0
    assert 'x'*43 not in capsys.readouterr().out
    path.chmod(0o644)
    with pytest.raises(cli.ClientError):
        cli.read_config(path)


@pytest.mark.parametrize('value',['https://[','http://dns.example.com','https://user:pass@dns.example.com','https://dns.example.com/x','https://dns.example.com?token=x','https://dns.example.com#x'])
def test_only_https_origin(value: str) -> None:
    with pytest.raises(cli.ClientError):
        cli.server_url(value)


def test_polling_skips_unchanged_ip_but_reconciles_daily(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    path=config(tmp_path)
    calls=[]
    def api(server: str,route: str,data: dict[str, object] | None=None,credential: str | None=None) -> dict[str, object]:
        calls.append(route)
        responses: dict[str, dict[str, object]] = {'/v1/ip':{'ip':'8.8.8.8'},'/v1/token':{'token':'token','hostname':'alice.example.com'},'/v1/update':{'hostname':'alice.example.com','ip':'8.8.8.8','changed':True}}
        return responses[route]
    monkeypatch.setattr(cli,'api',api)
    cli.update(path)
    assert calls==['/v1/ip','/v1/token','/v1/update']
    calls.clear()
    cli.update(path)
    assert calls==['/v1/ip']
    saved=cli.read_config(path);saved['last_sync']=0;cli.write_config(path,saved)
    calls.clear();cli.update(path)
    assert calls==['/v1/ip','/v1/token','/v1/update']


def test_no_config_commit_after_failed_update(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    path=config(tmp_path)
    before=path.read_text()
    def api(server: str,route: str,data: dict[str, object] | None=None,credential: str | None=None) -> dict[str, object]:
        if route=='/v1/ip':return {'ip':'8.8.8.8'}
        if route=='/v1/token':return {'hostname':'alice.example.com','token':'token'}
        raise cli.ClientError('network failure')
    monkeypatch.setattr(cli,'api',api)
    with pytest.raises(cli.ClientError):cli.update(path)
    assert path.read_text()==before


def test_token_cannot_be_sent_to_different_hostname(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    path=config(tmp_path)
    def api(server: str,route: str,data: dict[str, object] | None=None,credential: str | None=None) -> dict[str, object]:
        if route=='/v1/ip':return {'ip':'8.8.8.8'}
        return {'hostname':'bob.example.com','token':'token'}
    monkeypatch.setattr(cli,'api',api)
    with pytest.raises(cli.ClientError):cli.update(path)


def test_saved_service_period_preserves_credentials(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,capsys: pytest.CaptureFixture[str]) -> None:
    path=config(tmp_path)
    secret=cli.read_config(path)['device_secret']
    monkeypatch.setattr('sys.argv',['dnspoke','--config',str(path),'configure','--ttl','15'])
    assert cli.main()==0
    saved=cli.read_config(path)
    assert saved['device_secret']==secret
    assert cli.polling_interval(saved)==900
    assert secret not in capsys.readouterr().out
    assert cli.polling_interval(saved,minutes=10)==600
    assert cli.polling_interval(saved,seconds=360)==360


@pytest.mark.parametrize('minutes', [0, -1, 4, True, '15', 1.5])
def test_invalid_check_period_rejected(minutes: object) -> None:
    with pytest.raises(cli.ClientError):cli.check_period(minutes)


def test_default_and_long_period() -> None:
    assert cli.polling_interval({})==300
    assert cli.polling_interval({'check_period_minutes':60})==3600


def test_bad_period_does_not_change_config(tmp_path: Path,monkeypatch: pytest.MonkeyPatch) -> None:
    path=config(tmp_path)
    before=path.read_bytes()
    monkeypatch.setattr('sys.argv',['dnspoke','--config',str(path),'configure','--ttl','4'])
    assert cli.main()==1
    assert path.read_bytes()==before


@pytest.mark.parametrize('positional', [False, True])
def test_visible_or_positional_invite(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,capsys: pytest.CaptureFixture[str],positional: bool) -> None:
    from dnspoke.invitations import pack_invite
    path=tmp_path/'client/device.json'
    invitation=pack_invite('https://dns.example.com','ab'*12)
    argv=['dnspoke','--config',str(path),'enroll']
    monkeypatch.setattr('socket.gethostname', lambda: 'test-laptop.local')
    prompts=[]
    if positional:argv.append(invitation)
    def visible(prompt: str) -> str:
        prompts.append(prompt)
        return invitation
    monkeypatch.setattr('builtins.input',visible)
    monkeypatch.setattr('sys.argv',argv)
    def api(server: str,route: str,data: dict[str, object] | None=None,credential: str | None=None) -> dict[str, object]:
        assert server=='https://dns.example.com'
        assert data=={'invite':'ab'*12, 'device_hostname': 'test-laptop.local'}
        return {'hostname':'alice.example.com','device_id':'test-device','device_secret':'y'*43}
    monkeypatch.setattr(cli,'api',api)
    assert cli.main()==0
    output=capsys.readouterr().out
    assert 'https://dns.example.com' in output
    assert invitation not in output
    assert bool(prompts)==(not positional)
    assert cli.read_config(path)['hostname']=='alice.example.com'


@pytest.mark.parametrize('minutes,fail,expected', [(15,False,900),(60,True,3600)])
def test_watch_uses_saved_period_even_after_errors(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,minutes: int,fail: bool,expected: int) -> None:
    path=config(tmp_path)
    saved=cli.read_config(path);saved['check_period_minutes']=minutes;cli.write_config(path,saved)
    waits=[]
    class Stop:
        stopped=False
        def is_set(self) -> bool:return self.stopped
        def set(self) -> None:self.stopped=True
        def wait(self,seconds: float) -> None:waits.append(seconds);self.stopped=True
    stop=Stop()
    monkeypatch.setattr('dnspoke.cli.threading.Event',lambda:stop)
    monkeypatch.setattr('dnspoke.cli.signal.signal',lambda *args:None)
    monkeypatch.setattr('dnspoke.cli.random.uniform',lambda *args:0)
    def update(path: Path) -> None:
        if fail:raise cli.ClientError('Temporary outage')
    monkeypatch.setattr(cli,'update',update)
    monkeypatch.setattr('sys.argv',['dnspoke','--config',str(path),'watch'])
    assert cli.main()==0
    assert waits==[expected]
