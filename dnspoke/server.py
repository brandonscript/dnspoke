"""Public API. Administrative operations are available only through the local CLI."""
from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, cast
import os
import sqlite3
import time

from flask import Flask, jsonify, request
from flask.typing import ResponseReturnValue
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.wrappers import Response

from .core import Store, Rejected, digest, public_ipv4
from .provider import LexiconProvider
from .types import DNSProvider
from .settings import relay_url

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIEnvironment

def create_app(store: Store | None = None, provider: DNSProvider | None = None) -> Flask:
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 2048
    store = store or Store(os.environ.get('DNS_DATABASE', '/data/state.sqlite3'))
    endpoint = relay_url(store, os.environ['DNS_ZONE'], os.environ.get('RELAY_PUBLIC_URL'))
    app.logger.info('Relay URL: %s', endpoint)
    provider = provider or LexiconProvider(os.environ['DNS_ZONE'], os.environ.get('DNS_PROVIDER'))
    try:
        provider_cooldown = int(os.environ.get('DNS_PROVIDER_COOLDOWN', '0'))
    except ValueError:
        raise ValueError('DNS_PROVIDER_COOLDOWN must be an integer between 0 and 3600') from None
    if not 0 <= provider_cooldown <= 3600:
        raise ValueError('DNS_PROVIDER_COOLDOWN must be an integer between 0 and 3600')
    # Enable only behind a single trusted proxy with no published upstream port.
    if os.environ.get('DNS_TRUST_PROXY') == '1':
        direct = app.wsgi_app
        forwarded = ProxyFix(direct, x_for=1, x_proto=1, x_host=0)
        trusted_proxy = os.environ['DNS_TRUSTED_PROXY']
        def proxy_only(environ: WSGIEnvironment, start_response: StartResponse) -> Iterable[bytes]:
            if environ.get('PATH_INFO') == '/health':
                return direct(environ, start_response)
            if environ.get('REMOTE_ADDR') != trusted_proxy:
                return Response('Trusted proxy required', status=403)(environ, start_response)
            return forwarded(environ, start_response)
        setattr(app, "wsgi_app", proxy_only)

    @app.errorhandler(Rejected)
    def rejected(error: Rejected) -> Response:
        response = jsonify(error=str(error))
        response.status_code = error.status
        if error.status == 429:
            response.headers['Retry-After'] = '300'
        return response

    @app.errorhandler(sqlite3.OperationalError)
    def busy(error: sqlite3.OperationalError) -> ResponseReturnValue:
        return jsonify(error='Service busy; retry later'), 503

    @app.after_request
    def private(response: Response) -> Response:
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.before_request
    def limit_requests() -> None:
        if request.path.startswith('/v1/'):
            store.throttle('requests', request.remote_addr, 120, 60)

    def body() -> dict[str, object]:
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise Rejected('Expected a JSON object')
        return cast(dict[str, object], value)

    def bearer() -> str:
        header = request.headers.get('Authorization', '')
        if not header.startswith('Bearer '):
            raise Rejected('Bearer credential required', 401)
        return header[7:]

    @app.get('/health')
    def health() -> Response:
        return jsonify(ok=True)

    @app.get('/v1/ip')
    def observed_ip() -> Response:
        return jsonify(ip=public_ipv4(request.remote_addr))

    @app.post('/v1/enroll')
    def enroll() -> Response:
        store.throttle('enroll', request.remote_addr, 10, 900)
        data = body()
        return jsonify(store.enroll(data.get('invite'), data.get('device_hostname'), data.get('local_ip')))

    @app.post('/v1/device')
    def device_details() -> Response:
        data = body()
        if set(data) != {'local_ip'}:
            raise Rejected('Expected local_ip, or null to remove it')
        store.set_local_ip(bearer(), data['local_ip'])
        return jsonify(ok=True)

    @app.post('/v1/token')
    def token() -> Response:
        return jsonify(store.token(bearer()))

    @app.post('/v1/update')
    def update() -> Response:
        # Caller cannot select an arbitrary name, zone, or address.
        if body():
            raise Rejected('Update body must be empty; address is observed by the server')
        ip = public_ipv4(request.remote_addr)
        now, token_hash = time.time(), digest(bearer())
        failure: Rejected | None = None
        changed = False
        with store.transaction() as db:
            row = db.execute('''SELECT d.* FROM tokens t JOIN devices d ON d.id=t.device
                WHERE t.hash=? AND t.expires>? AND d.revoked=0''', (token_hash, now)).fetchone()
            if not row:
                raise Rejected('Invalid, expired, or used update token', 401)
            if row['last_update'] is not None and now - row['last_update'] < 300:
                raise Rejected('Update interval is five minutes', 429)
            last_auth = db.execute("SELECT value FROM meta WHERE key='provider_auth'").fetchone()
            if last_auth and now - last_auth['value'] < provider_cooldown:
                raise Rejected('DNS provider cooldown; try again later', 429)
            # Keep attempts and consumed tokens committed even on provider failure.
            # The write lock serializes updates with enrollment and revocation.
            db.execute('DELETE FROM tokens WHERE hash=?', (token_hash,))
            try:
                changed = provider.update(row['hostname'], ip, bool(row['adopt']))
            except Rejected as error:
                failure = error
            except Exception:
                # Provider exceptions may contain authentication bodies or cookies.
                failure = Rejected('DNS provider update failed; retry later or contact the administrator', 502)
            db.execute("INSERT INTO meta VALUES('provider_auth',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (time.time(),))
            if failure is None:
                db.execute('UPDATE devices SET last_update=?,last_ip=?,adopt=1 WHERE id=?', (now, ip, row['id']))
                db.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)', (now, row['id'], row['hostname'], row['last_ip'], ip, int(changed)))
        if failure:
            raise failure
        return jsonify(hostname=row['hostname'], ip=ip, changed=changed)

    return app
