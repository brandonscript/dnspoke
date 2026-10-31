# Development

Python 3.12 or later is required. The client uses only the standard library; the server installs Flask, Gunicorn, and [DNS Lexicon](https://dns-lexicon.github.io/dns-lexicon/).

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[server,test,typecheck,lint]'
.venv/bin/pre-commit install
.venv/bin/pre-commit run --all-files
.venv/bin/mypy
.venv/bin/pytest -q
```

Mypy runs in strict mode across the package and tests. Typed dictionaries describe stored credentials and provider records; protocols define provider behavior. The package includes `py.typed` for downstream type checkers.

Tests use temporary databases, mocked DNS providers, and a local HTTPS server. They do not modify real DNS. The HTTPS test generates a temporary certificate with the test-only cryptography dependency. Native Gunicorn startup is tested on macOS and Linux; Windows runs the client, credential ACL, and HTTPS enrollment/update tests.

## Client installation from source

```sh
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/dnspoke --help
```

Install the `server` extra when running the relay itself. For server configuration and Docker use, see [server configuration](server.md).


For a Windows client development environment:

```powershell
py -3 -m venv .venv
.venv\Scripts\python -m pip install -e '.[test]'
.venv\Scripts\python -m pytest -q tests/test_client.py tests/test_storage.py tests/test_end_to_end.py
```

Both installers accept a local source checkout for testing: `sh install.sh --source . --prefix /tmp/dnspoke-test`, or `.\install.ps1 -Source . -InstallDir "$env:TEMP\dnspoke-test" -NoPath`. CI exercises installation and reinstallation, including paths containing spaces. Neither installer enrolls a client or starts background updates automatically.

Ruff checks basic errors, imports, and a 100-character line limit. The pre-commit hooks
apply safe lint fixes and formatting to staged Python files; restage changes and retry
when a hook edits a file. CI checks formatting without changing files. During the
DNS administration rollout, these checks cover its three Python files only.
