#!/bin/sh
# SysAI installer. Downloads source from the public GitHub repository.
set -eu

REPO_ARCHIVE='https://github.com/v3trov/SysAI/archive/refs/heads/main.tar.gz'

say() { printf '\n[%s/5] %s\n' "$1" "$2"; }
ask_tty() {
    if [ ! -r /dev/tty ]; then
        return 1
    fi
    printf '%s' "$1" > /dev/tty
    IFS= read -r answer < /dev/tty || return 1
    printf '%s' "$answer"
}

if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root: curl -fsSL https://raw.githubusercontent.com/v3trov/SysAI/main/install.sh | sudo sh' >&2
    exit 1
fi

say 1 'Checking system'
if [ ! -f /etc/os-release ]; then
    echo 'Unsupported system: missing /etc/os-release' >&2
    exit 1
fi
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
    debian:*|ubuntu:*|armbian:*|*:debian*|*:ubuntu*) ;;
    *) echo "Unsupported distribution: ${ID:-unknown}" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|aarch64|armv7l|armv6l) ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
printf 'OS: %s | arch: %s\n' "${PRETTY_NAME:-$ID}" "$(uname -m)"

say 2 'Installing required system packages'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv curl ca-certificates tar
if ! python3 -c 'import sys; assert sys.version_info >= (3, 10)' >/dev/null 2>&1; then
    echo 'Python 3.10 or newer is required' >&2
    exit 1
fi

if [ -e /usr/local/bin/sysai ] || [ -L /usr/local/bin/sysai ]; then
    if [ ! -L /usr/local/bin/sysai ] || [ "$(readlink /usr/local/bin/sysai)" != /opt/sysai/venv/bin/sysai ]; then
        echo '/usr/local/bin/sysai is not owned by this installation' >&2
        exit 1
    fi
fi

say 3 'Downloading SysAI source from GitHub'
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 -fsSL "$REPO_ARCHIVE" -o "$work_dir/source.tar.gz"
mkdir "$work_dir/source"
tar -xzf "$work_dir/source.tar.gz" -C "$work_dir/source" --strip-components=1
if [ ! -f "$work_dir/source/pyproject.toml" ]; then
    echo 'Downloaded archive does not contain SysAI source' >&2
    exit 1
fi

say 4 'Installing isolated Python environment'
install -d -m 0755 /opt/sysai
install -d -m 0700 /var/lib/sysai /etc/sysai
python3 -m venv /opt/sysai/venv
PIP_NO_INPUT=1 /opt/sysai/venv/bin/python -m pip install --upgrade "$work_dir/source"
ln -sfn /opt/sysai/venv/bin/sysai /usr/local/bin/sysai

say 5 'Private DeepSeek API setup'
if [ -f /etc/sysai/deepseek.key ]; then
    reply=$(ask_tty 'An API key is already configured. Configure a new key now? [y/N] ') || reply=n
else
    reply=$(ask_tty 'Configure the DeepSeek API key now? [Y/n] ') || reply=n
    [ -n "$reply" ] || reply=y
fi
case "$reply" in
    y|Y|yes|YES) /opt/sysai/venv/bin/sysai setup || printf 'API setup did not finish. Run later: sudo sysai setup\n' ;;
    *) printf 'Setup skipped. Run later: sudo sysai setup\n' ;;
esac
printf '\nSysAI installed. Start with: sysai\n'
