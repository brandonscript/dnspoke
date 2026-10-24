"""Platform-specific locations and access checks for device credentials."""
from pathlib import Path
import base64
import os
import stat
import subprocess


class ClientError(Exception):
    pass


_WINDOWS_ACL = r'''
$ErrorActionPreference = 'Stop'
$path = $env:DNSPOKE_ACL_PATH
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($env:DNSPOKE_ACL_MODE -eq 'secure') {
    if (Test-Path -LiteralPath $path -PathType Container) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'FullControl', 'Allow')
    }
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
}
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $user.Value) {
    throw 'Credential path must be owned by the current user'
}
$allowed = $false
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow') {
        if ($rule.IdentityReference.Value -ne $user.Value) { throw 'Credential path grants access to another identity' }
        $allowed = $true
    }
}
if (-not $allowed) { throw 'Credential path must grant access to the current user' }
'''


def windows_acl(path: Path, *, secure: bool = False) -> None:
    shell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    environment = dict(os.environ, DNSPOKE_ACL_PATH=str(path.resolve()), DNSPOKE_ACL_MODE='secure' if secure else 'check')
    encoded = base64.b64encode(_WINDOWS_ACL.encode('utf-16-le')).decode('ascii')
    result = subprocess.run([str(shell), '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            env=environment, capture_output=True, timeout=30, check=False,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise ClientError('Credential file and directory must have private Windows permissions for your user')


def config_path() -> Path:
    if os.environ.get('XDG_CONFIG_HOME'):
        base = Path(os.environ['XDG_CONFIG_HOME'])
    elif os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local'))
    else:
        base = Path.home() / '.config'
    return base / 'dnspoke/device.json'


def check_path(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    if (path.is_symlink() or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ClientError('Credential paths must be regular files and directories without links')
    if os.name == 'nt':
        windows_acl(path)
    elif info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ClientError('Credential paths must be owned by you and private (file 600, directory 700)')


def prepare_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, mode=0o700)
    except FileExistsError:
        pass
    else:
        if os.name == 'nt':
            windows_acl(path, secure=True)
    check_path(path, directory=True)


def secure_file(path: Path) -> None:
    if os.name == 'nt':
        windows_acl(path, secure=True)
    else:
        path.chmod(0o600)
