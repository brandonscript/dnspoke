# Installing `dnspoke`

The client runs on macOS, Linux, and Windows. The server runs on macOS and Linux, either natively or in Docker. Python 3.12 or later is required by the script installers; Homebrew installs Python for you.

## macOS and Linux: Homebrew

[Install Homebrew](https://brew.sh/) if needed, then:

```sh
brew install brandonscript/tap/dnspoke
dnspoke enroll
dnspoke update
brew services start dnspoke
```

To upgrade, run `brew update && brew upgrade dnspoke`, then restart a running service. Homebrew installs the client and local admin commands. Use the server installation below to host a relay.

## Linux: shell installer

The shell installer is an alternative when you do not use Homebrew. It also works on macOS. Install Python 3.12+ with SSL and `venv` support first. Debian and Ubuntu may require the matching `python3-venv` package.

```sh
curl -fsSLo install.sh https://raw.githubusercontent.com/brandonscript/dnspoke/v0.1.6/install.sh
sh install.sh
export PATH="$HOME/.local/bin:$PATH"
dnspoke enroll
dnspoke update
```

The installer creates an isolated environment under `~/.local/share/dnspoke/venv` and links the command into `~/.local/bin`. Add that bin directory to your shell's PATH permanently if needed. No root access is required. Use `--prefix DIR` for another location or `--python /path/to/python3` to choose Python.

Run the installer again to upgrade. `--version vX.Y.Z` selects a release; without it, a downloaded installer uses the release it shipped with. Enrollment and preferences are stored separately and preserved. Stop background updates before upgrading, then start them again afterward.

### Background updates without Homebrew

`dnspoke watch` runs continuously in the foreground. On Linux systems with systemd, create `~/.config/systemd/user/dnspoke.service`:

```ini
[Unit]
Description=dnspoke dynamic DNS client

[Service]
ExecStart=%h/.local/bin/dnspoke watch
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
```

Adjust `ExecStart` if you chose a different prefix. After enrolling:

```sh
systemctl --user daemon-reload
systemctl --user enable --now dnspoke
journalctl --user -u dnspoke
```

Stop with `systemctl --user stop dnspoke`. The user service normally follows your login session; continuous operation after logout requires enabling lingering for that user through your system administrator. Do not also run a Homebrew service for the same enrollment.

## Windows: PowerShell installer

Install Python 3.12 or later from [python.org](https://www.python.org/downloads/windows/), or with Windows Package Manager:

```powershell
winget install --exact --id Python.Python.3.14
```

Open a new PowerShell window, then download and run the installer:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/brandonscript/dnspoke/v0.1.6/install.ps1 -OutFile install.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
$env:Path = "$env:LOCALAPPDATA\Programs\dnspoke\bin;$env:Path"
dnspoke enroll
dnspoke update
```

This uses a process-level execution policy for the installer and does not change your machine's policy. Run as your normal user. The installer creates an isolated environment and command under `%LOCALAPPDATA%\Programs\dnspoke`, adds its `bin` directory to your user PATH, and leaves enrollment intact when rerun. Open a new terminal if another application has not picked up the PATH change. Use `-Python C:\path\to\python.exe`, `-InstallDir DIR`, or `-Version vX.Y.Z` when needed. `-NoPath` leaves PATH unchanged.

The default credential file is `%LOCALAPPDATA%\dnspoke\device.json`. The client creates a private directory and file ACL for your Windows user and checks those permissions when reading credentials. Store the config on a filesystem that supports Windows ACLs. An explicit `--config` or `XDG_CONFIG_HOME` overrides the default location.

### Background updates on Windows

Run `dnspoke watch` in PowerShell for foreground use. To start it automatically, create a task in Windows Task Scheduler:

- Use your normal Windows user, select **Run only when user is logged on**, and leave **Run with highest privileges** unchecked.
- Trigger it **At log on** for that user.
- Set the program to the full path of `%LOCALAPPDATA%\Programs\dnspoke\venv\Scripts\pythonw.exe` and the arguments to `-m dnspoke.cli watch`. Expand `%LOCALAPPDATA%` to your actual directory when entering the path.
- Disable the task's execution time limit, allow it on battery if appropriate, and choose **Do not start a new instance** if it is already running.

`pythonw.exe` runs without a console window. Use `dnspoke update` in PowerShell to troubleshoot errors interactively. End the task before upgrading and run it again afterward. Background operation while logged out and running as a Windows system service are not configured by this installer.

## Hosting a server on macOS or Linux

Docker is described in [server configuration](server.md). To install natively, use the shell installer with server dependencies:

```sh
sh install.sh --server
```

The WSGI server is installed at `~/.local/share/dnspoke/venv/bin/gunicorn`. Configure the server environment, storage, DNS, and HTTPS proxy before running it. The server configuration guide includes the startup command. Installing server dependencies does not start a relay or modify DNS. Native Windows server hosting is not supported.

## Removing an installation

Stop background updates first. Homebrew installations can be removed with `brew uninstall dnspoke`. For a script installation, remove its command and isolated environment; keep the credential file if you intend to reinstall. On Windows, also remove the installer's `bin` entry from your user PATH and delete any scheduled task you created. Revoke a device on the relay before disposing of its credentials; deleting a local file does not revoke server access.
