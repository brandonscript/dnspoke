"""Real HTTPS client/server exchange with an in-memory DNS provider; no live DNS."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING
import subprocess
import threading

from flask import redirect
from werkzeug.serving import make_server
from werkzeug.wrappers import Response
import pytest

from dnspoke import cli
from dnspoke.core import Store
from dnspoke.invitations import pack_invite
from dnspoke.server import create_app

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIEnvironment

class DNS:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]]=[]
    def update(self,name: str,ip: str,adopt: bool) -> bool:
        self.calls.append((name,ip,adopt))
        return True


def test_https_enroll_update_revoke_and_refuse_redirects(tmp_path: Path,monkeypatch: pytest.MonkeyPatch,capsys: pytest.CaptureFixture[str]) -> None:
    key,cert=tmp_path/'key.pem',tmp_path/'cert.pem'
    subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:prime256v1',
                    '-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost',
                    '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    monkeypatch.setenv('SSL_CERT_FILE',str(cert))
    monkeypatch.delenv('DNS_TRUST_PROXY',raising=False)
    store=Store(tmp_path/'state.sqlite3')
    provider=DNS()
    app=create_app(store,provider)
    followed=[]
    @app.get('/redirect')
    def redirect_to_another_path() -> Response:
        return redirect('/unexpected',code=302)
    @app.get('/unexpected')
    def unexpected() -> dict[str, bool]:
        followed.append(True)
        return {'ok':True}
    direct=app.wsgi_app
    def fake_remote(environ: WSGIEnvironment,start_response: StartResponse) -> Iterable[bytes]:
        environ['REMOTE_ADDR']='8.8.8.8'
        return direct(environ,start_response)
    setattr(app, "wsgi_app", fake_remote)
    server=make_server('127.0.0.1',0,app,ssl_context=(str(cert),str(key)))
    worker=threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    endpoint=f'https://localhost:{server.server_port}'
    credential_file=tmp_path/'client-private/device.json'
    invite=store.invite('alice.example.com')
    monkeypatch.setattr('builtins.input',lambda _:pack_invite(endpoint, invite))
    try:
        monkeypatch.setattr('sys.argv',['dnspoke','--config',str(credential_file),'enroll'])
        assert cli.main()==0
        cli.update(credential_file)
        assert provider.calls==[('alice.example.com','8.8.8.8',False)]
        assert cli.read_config(credential_file)['last_ip']=='8.8.8.8'
        store.revoke(cli.read_config(credential_file)['device_id'])
        monkeypatch.setattr('sys.argv',['dnspoke','--config',str(credential_file),'update','--force'])
        assert cli.main()==1
        captured=capsys.readouterr()
        assert 'revoked' in captured.err
        assert invite not in captured.out+captured.err
        assert cli.read_config(credential_file)['device_secret'] not in captured.out+captured.err
        with pytest.raises(cli.ClientError,match='redirects are never followed'):
            cli.api(endpoint,'/redirect')
        assert followed==[]
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
