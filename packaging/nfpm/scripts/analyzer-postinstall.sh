#!/bin/sh
# nfpm postinstall for packetyeeter-analyzer.
# Deliberately does NOT enable or start the service: review
# /etc/default/packetyeeter-analyzer (listen address, GeoIP path, dry-run)
# before starting it. See docs/operations.md for staged rollout guidance.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

echo "packetyeeter-analyzer installed."
echo "Review /etc/default/packetyeeter-analyzer, then:"
echo "  sudo systemctl enable --now packetyeeter-analyzer"

exit 0
