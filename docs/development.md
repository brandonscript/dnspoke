# Development

Python 3.12 or later is required. The client uses only the standard library; the server installs Flask, Gunicorn, and DNS Lexicon.

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[server,test,typecheck]'
.venv/bin/mypy
.venv/bin/pytest -q
```

Mypy runs in strict mode across the package and tests. Typed dictionaries describe stored credentials and provider records; protocols define provider behavior. The package includes `py.typed` for downstream type checkers.

Tests use temporary databases, mocked DNS providers, and a local HTTPS server. They do not modify real DNS. The HTTPS test uses the `openssl` command to create a temporary certificate.

## Client installation from source

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/dnspoke --help
```

Install the `server` extra when running the relay itself. For server configuration and Docker use, see [server configuration](server.md).
