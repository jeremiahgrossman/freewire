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
# Scoped to the server, not the whole interface.
#
# This was "block out on $UPLINK_IF all" while UPLINK_IF was a container bridge,
# where it only affected traffic to the test server. Once the server moved to
# the internet and UPLINK_IF became the physical interface, the same line cut
# the machine off the network entirely -- including DHCP, DNS and the operator's
# own session. The configs only ever needed to control which paths to the server
# are reachable.
block out on $UPLINK_IF to $SERVER_IP
# Bootstrap API. In production this shares 443; see config.env.
pass out on $UPLINK_IF proto tcp to $SERVER_IP port $API_PORT
pass out on $UPLINK_IF proto tcp to any port 443
pass out on $UPLINK_IF proto udp to any port 53
pass out on $UPLINK_IF inet proto icmp
EOF

echo
echo "HTTP CONNECT should fail (no proxy), then TLS/443 should succeed."
echo "Confirm the 2s CONNECT timeout is actually spent — if this connects"
echo "in well under 2s, the CONNECT probe may be short-circuiting."
footer
