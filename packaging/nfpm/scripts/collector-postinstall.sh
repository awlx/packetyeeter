#!/bin/sh
# nfpm postinstall for packetyeeter-collector.
# Deliberately does NOT enable or start the service: the collector loads
# eBPF/XDP programs and requires operator-provided config (interface,
# analyzer address, allowlist) in /etc/default/packetyeeter-collector
# before it is safe to run. See docs/operations.md for staged rollout
# guidance (analyzer dry-run -> one collector canary -> wider rollout).
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

# This version removed the -haproxy-port flag. The package replaces the unit
# file, but a local drop-in that overrides ExecStart= shadows it and is left
# untouched by the upgrade. Go's flag parser rejects unknown flags, so the
# collector would exit 2 on the next restart and Restart=on-failure would turn
# that into a crash loop -- and because this script does not restart the
# service, the failure surfaces later, detached from the upgrade that caused
# it. Check the resolved configuration and say so now.
if command -v systemctl >/dev/null 2>&1; then
    stale_units=$(systemctl cat packetyeeter-collector 2>/dev/null \
        | awk '/^# \//{f=$2} /haproxy-port/{print f}' \
        | sort -u)
    if [ -n "$stale_units" ]; then
        echo "WARNING: -haproxy-port is no longer a valid collector flag, but it is" >&2
        echo "         still passed by:" >&2
        echo "$stale_units" | sed 's/^/           /' >&2
        echo "         The collector will fail to start until it is removed." >&2
        echo "         Remove it, then: sudo systemctl daemon-reload" >&2
    fi
fi

echo "packetyeeter-collector installed."
echo "Review /etc/default/packetyeeter-collector, then:"
echo "  sudo systemctl enable --now packetyeeter-collector"

exit 0
