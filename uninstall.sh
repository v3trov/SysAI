#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo 'Run as root' >&2
    exit 1
fi
if [ ! -L /usr/local/bin/sysai ] || [ "$(readlink /usr/local/bin/sysai)" != /opt/sysai/venv/bin/sysai ]; then
    echo 'Expected SysAI symlink not found; no files removed' >&2
    exit 1
fi
rm /usr/local/bin/sysai
if [ -d /opt/sysai/venv ]; then
    rm -r /opt/sysai/venv
fi
printf 'Program removed. /var/lib/sysai and /etc/sysai were retained.\n'
