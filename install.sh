#!/bin/sh
set -eu

version=v0.1.7
prefix="${HOME}/.local"
source_path=
server=false
usage() {
    echo 'Usage: install.sh [--version vX.Y.Z] [--prefix DIR] [--python PATH] [--server] [--source DIR]'
}
python_command="${DNSPOKE_PYTHON:-}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--prefix|--python|--source)
            [ "$#" -ge 2 ] || { usage >&2; exit 1; }
            case "$1" in
                --version) version=$2 ;;
                --prefix) prefix=$2 ;;
                --python) python_command=$2 ;;
                --source) source_path=$2 ;;
            esac
            shift 2 ;;
        --server) server=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done
case "$(uname -s)" in Linux|Darwin) ;; *) echo 'Use install.ps1 on Windows.' >&2; exit 1 ;; esac
if [ -z "$python_command" ]; then
    for candidate in python3.14 python3.13 python3.12 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 12))' 2>/dev/null; then
            python_command=$candidate
            break
        fi
    done
fi
if [ -z "$python_command" ] || ! "$python_command" -c 'import ssl, venv, sys; sys.exit(sys.version_info < (3, 12))'; then
    echo 'Install Python 3.12+ with SSL and venv support, then rerun. On Debian/Ubuntu install the matching python3-venv package too.' >&2
    exit 1
fi
"$python_command" -c 'import re,sys; sys.exit(not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+",sys.argv[1]))' "$version" || { echo 'Version must look like v0.1.7.' >&2; exit 1; }
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd)
venv_path="$prefix/share/dnspoke/venv"
bin_path="$prefix/bin/dnspoke"
mkdir -p "$prefix/bin"
if [ -e "$bin_path" ] || [ -L "$bin_path" ]; then
    if [ ! -L "$bin_path" ] || [ "$(readlink "$bin_path")" != "$venv_path/bin/dnspoke" ]; then
        echo "Refusing to replace another installation at $bin_path" >&2
        exit 1
    fi
fi
if [ ! -x "$venv_path/bin/python" ]; then
    "$python_command" -m venv "$venv_path"
fi
if [ -n "$source_path" ]; then
    source_path=$(cd "$source_path" && pwd)
    package="$source_path"
else
    package="dnspoke @ https://github.com/brandonscript/dnspoke/archive/refs/tags/$version.tar.gz"
fi
if [ "$server" = true ]; then
    if [ -n "$source_path" ]; then package="$source_path[server]"; else package="dnspoke[server] @ https://github.com/brandonscript/dnspoke/archive/refs/tags/$version.tar.gz"; fi
fi
"$venv_path/bin/python" -m pip install --upgrade "$package"
ln -sf "$venv_path/bin/dnspoke" "$bin_path"
"$bin_path" --version
printf 'Installed: %s\nAdd %s to PATH if needed.\nNext: dnspoke enroll\n' "$bin_path" "$prefix/bin"
if [ "$server" = true ]; then
    printf 'Server installed. Set its environment and run %s/bin/gunicorn; see docs/server.md.\n' "$venv_path"
fi
