#!/bin/sh
# nfpm preremove for packetyeeter-collector: stop the service before its
# binary/unit files are removed so systemd doesn't hold a deleted binary.
set -e

if [ "$1" = "remove" ] || [ "$1" = "purge" ] || [ -z "$1" ]; then
    systemctl stop packetyeeter-collector >/dev/null 2>&1 || true
    systemctl disable packetyeeter-collector >/dev/null 2>&1 || true
fi

exit 0
