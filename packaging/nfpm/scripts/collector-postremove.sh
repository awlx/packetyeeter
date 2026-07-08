#!/bin/sh
# nfpm postremove for packetyeeter-collector.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

exit 0
