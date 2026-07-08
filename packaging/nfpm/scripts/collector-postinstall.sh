#!/bin/sh
# nfpm postinstall for packetyeeter-collector.
# Deliberately does NOT enable or start the service: the collector loads
# eBPF/XDP programs and requires operator-provided config (interface,
# analyzer address, allowlist) in /etc/default/packetyeeter-collector
# before it is safe to run. See docs/operations.md for staged rollout
# guidance (analyzer dry-run -> one collector canary -> wider rollout).
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

echo "packetyeeter-collector installed."
echo "Review /etc/default/packetyeeter-collector, then:"
echo "  sudo systemctl enable --now packetyeeter-collector"

exit 0
