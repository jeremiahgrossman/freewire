#!/usr/bin/env bash
# Config 6 — Upgrade test. Run WHILE connected via DNS tunnel (config 3).
# Guide: captive-portal-testing-guide.md §Configuration 6
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 6 "Open 443 mid-session (upgrade test)" \
  "DNS tunnel -> TLS/443, transparently" \
  "within one upgrade probe interval"

cat <<PRE
PREREQUISITE: the client must already be connected via the DNS tunnel.
Run config3.sh, confirm the DNS tunnel is live, and only then run this.

PRE

read -r -p "Is the client connected via DNS tunnel right now? [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "Run config3.sh first."; exit 1; }

apply_rules <<EOF
# Config 6 — config 3 plus 443 now permitted.
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
pass out on $UPLINK_IF proto udp to any port 53
pass out on $UPLINK_IF inet proto icmp
pass out on $UPLINK_IF proto tcp to any port 443
EOF

cat <<NOTE

Watch for:
  - The session does NOT drop. "Connected" stays visible throughout.
  - The reduced-speed indicator clears once TLS/443 takes over.
  - DNS query volume to $TUNNEL_DOMAIN falls off as 443 picks up.

Per path-upgrade-manager-spec.md the manager only upgrades toward
lower-priority numbers, so it must move DNS(4) -> TLS/443(3) and then
stop. If it oscillates, the hysteresis logic is wrong.

NOTE
footer
