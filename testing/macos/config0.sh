#!/usr/bin/env bash
# Config 0 — Baseline (no captive portal). Open network.
# Guide: captive-portal-testing-guide.md §Configuration 0
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 0 "Baseline — open network" \
  "WireGuard direct (UDP). Fallback chain not triggered." \
  "connects immediately"

apply_rules <<EOF
# Config 0 — no restrictions. All traffic passes.
# Present so the harness has a known-clean starting state.
EOF

echo
echo "Baseline is the control run. If this fails, nothing below is meaningful."
footer
