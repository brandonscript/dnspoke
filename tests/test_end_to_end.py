"""Real HTTPS client/server exchange with an in-memory DNS provider; no live DNS."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING
from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
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
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                                  x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                   .sign(private_key, hashes.SHA256()))
    key.write_bytes(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
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
    monkeypatch.setattr(cli, 'local_address', lambda server: '192.168.1.42')
    monkeypatch.setattr('socket.gethostname', lambda: 'test-laptop.local')
    invite=store.invite('alice.example.com')
    monkeypatch.setattr('builtins.input',lambda _:pack_invite(endpoint, invite))
    try:
        monkeypatch.setattr('sys.argv',['dnspoke','--config',str(credential_file),'enroll'])
        assert cli.main()==0
        with store.transaction() as db:
            assert db.execute('SELECT device_hostname FROM devices').fetchone()['device_hostname'] == 'test-laptop.local'
        cli.update(credential_file)
        assert provider.calls==[('alice.example.com','8.8.8.8',False)]
        assert cli.read_config(credential_file)['last_ip']=='8.8.8.8'
        for flag, expected in [('--ip', '192.168.1.42'), ('--mask-ip', '*.*.*.42'), ('--no-ip', None)]:
            monkeypatch.setattr('sys.argv', ['dnspoke', '--config', str(credential_file), 'configure', flag])
            assert cli.main() == 0
            with store.transaction() as db:
                assert db.execute('SELECT local_ip FROM devices').fetchone()[0] == expected
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
