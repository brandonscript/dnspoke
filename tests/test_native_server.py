"""Start the installed Unix WSGI server without touching DNS."""
from pathlib import Path
import os
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from dnspoke.core import Store
from dnspoke.settings import relay_url


@pytest.mark.skipif(os.name == 'nt', reason='Native server supports macOS and Linux')
def test_gunicorn_serves_health_and_saves_default_endpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database = tmp_path / 'server.sqlite3'
    monkeypatch.setenv('DNS_DATABASE', str(database))
    monkeypatch.setenv('DNS_ZONE', 'example.com')
    monkeypatch.setenv('DNS_PROVIDER', 'hover')
    monkeypatch.delenv('RELAY_PUBLIC_URL', raising=False)
    monkeypatch.delenv('DNS_TRUST_PROXY', raising=False)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen([sys.executable, '-m', 'gunicorn', '--bind', f'127.0.0.1:{port}',
                                '--workers', '1', '--threads', '1', 'dnspoke.server:create_app()'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            try:
                with urlopen(f'http://127.0.0.1:{port}/health', timeout=1) as response:
                    assert response.status == 200
                    assert b'true' in response.read()
                break
            except (URLError, OSError):
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail('Native server did not start')
                time.sleep(0.1)
        assert database.exists()
        with Store(database).transaction() as db:
            assert db.execute("SELECT value FROM meta WHERE key='relay_public_url'").fetchone() is not None
        assert relay_url(Store(database), 'example.com').endswith('.example.com')
    finally:
        process.terminate()
        process.communicate(timeout=10)
