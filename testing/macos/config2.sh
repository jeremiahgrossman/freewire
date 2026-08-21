#!/usr/bin/env bash
# Config 2 — Port 443 open direct, everything else blocked. Forces Path 2.
# Guide: captive-portal-testing-guide.md §Configuration 2
# This is the most common real-world captive portal (~80% of networks).
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 2 "Port 443 open to internet, all else blocked" \
  "Path 2 — TLS/443 direct" \
  "<=5s (2s HTTP CONNECT timeout + 3s TLS/443)"

apply_rules <<EOF
# Config 2 — 443 open directly, no proxy present.
block out on $UPLINK_IF all
pass out on $UPLINK_IF proto tcp to any port 443
pass out on $UPLINK_IF proto udp to any port 53
pass out on $UPLINK_IF inet proto icmp
EOF

echo
echo "HTTP CONNECT should fail (no proxy), then TLS/443 should succeed."
echo "Confirm the 2s CONNECT timeout is actually spent — if this connects"
echo "in well under 2s, the CONNECT probe may be short-circuiting."
footer
