from pathlib import Path
import os
import subprocess

import pytest

from dnspoke import cli, storage


def test_config_path_respects_platform_and_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
    if os.name == 'nt':
        monkeypatch.setenv('LOCALAPPDATA', str(tmp_path))
        assert storage.config_path() == tmp_path / 'dnspoke/device.json'
    else:
        assert storage.config_path() == Path.home() / '.config/dnspoke/device.json'
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'override'))
    assert storage.config_path() == tmp_path / 'override/dnspoke/device.json'


def test_private_directory_and_atomic_replacement(tmp_path: Path) -> None:
    path = tmp_path / 'private/device.json'
    config = {'server': 'https://dns.example.com', 'hostname': 'alice.example.com', 'device_secret': 'x' * 43}
    cli.write_config(path, config)
    storage.check_path(path.parent, directory=True)
    storage.check_path(path)
    cli.write_config(path, dict(config, device_secret='y' * 43))
    assert cli.read_config(path)['device_secret'] == 'y' * 43
    assert not list(path.parent.glob('.device-*'))


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL behavior')
def test_windows_rejects_shared_credentials(tmp_path: Path) -> None:
    path = tmp_path / 'private/device.json'
    cli.write_config(path, {'server': 'https://dns.example.com', 'hostname': 'alice.example.com', 'device_secret': 'x' * 43})
    result = subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:R'], capture_output=True, check=False)
    assert result.returncode == 0
    with pytest.raises(cli.ClientError, match='Windows permissions'):
        cli.read_config(path)
    storage.secure_file(path)
    assert cli.read_config(path)['hostname'] == 'alice.example.com'


@pytest.mark.skipif(os.name != 'nt', reason='Windows ACL behavior')
def test_windows_rejects_shared_directory_before_enrollment(tmp_path: Path) -> None:
    directory = tmp_path / 'shared'
    storage.prepare_directory(directory)
    result = subprocess.run(['icacls', str(directory), '/grant', '*S-1-1-0:(OI)(CI)R'], capture_output=True, check=False)
    assert result.returncode == 0
    with pytest.raises(cli.ClientError, match='Windows permissions'):
        storage.prepare_directory(directory)
