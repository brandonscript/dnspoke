[CmdletBinding()]
param(
    [ValidatePattern('^v[0-9]+\.[0-9]+\.[0-9]+$')]
    [string]$Version = 'v0.1.6',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\dnspoke'),
    [string]$Python,
    [string]$Source,
    [switch]$NoPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT') { throw 'Use install.sh on macOS or Linux.' }
$pythonArgs = @()
if (-not $Python) {
    foreach ($candidate in @('py', 'python', 'python3')) {
        $command = Get-Command $candidate -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        $candidateArgs = @()
        if ($candidate -eq 'py') { $candidateArgs = @('-3') }
        try {
            & $command.Source @candidateArgs -c 'import ssl, venv, sys; sys.exit(sys.version_info < (3, 12))' 2>$null
        } catch { continue }
        if ($LASTEXITCODE -eq 0) {
            $Python = $command.Source
            $pythonArgs = $candidateArgs
            break
        }
    }
}
if (-not $Python) { throw 'Install Python 3.12+ first: winget install --exact --id Python.Python.3.14. Open a new PowerShell window and rerun.' }
& $Python @pythonArgs -c 'import ssl, venv, sys; sys.exit(sys.version_info < (3, 12))'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ with SSL and venv support is required.' }
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$venv = Join-Path $InstallDir 'venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
$bin = Join-Path $InstallDir 'bin'
if (-not (Test-Path -LiteralPath $venvPython)) {
    & $Python @pythonArgs -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
}
$package = "dnspoke @ https://github.com/brandonscript/dnspoke/archive/refs/tags/$Version.tar.gz"
if ($Source) { $package = (Resolve-Path -LiteralPath $Source).Path }
& $venvPython -m pip install --upgrade $package
if ($LASTEXITCODE -ne 0) { throw 'Could not install dnspoke.' }
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$wrapper = Join-Path $bin 'dnspoke.cmd'
@"
@echo off
"%~dp0..\venv\Scripts\python.exe" -m dnspoke.cli %*
"@ | Set-Content -LiteralPath $wrapper -Encoding ASCII
if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @($userPath -split ';' | Where-Object { $_ })
    if ($parts -notcontains $bin) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $bin) -join ';'), 'User')
    }
    if (($env:Path -split ';') -notcontains $bin) { $env:Path = "$bin;$env:Path" }
}
& $venvPython -m dnspoke.cli --version
if ($LASTEXITCODE -ne 0) { throw 'Installed command failed its version check.' }
Write-Host "Installed: $wrapper"
Write-Host 'Open a new terminal if needed, then run: dnspoke enroll'
