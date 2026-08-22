#!/usr/bin/env bash
# Config 4 — Fully local DNS resolver (NXDOMAIN), ICMP allowed. Forces Path 4.
# Guide: captive-portal-testing-guide.md §Configuration 4
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 4 "Local DNS resolver returns NXDOMAIN, ICMP allowed" \
  "Path 4 — ICMP tunnel" \
  "close to 10s (full chain timeout)"

cat <<PRE
This config needs a resolver that NXDOMAINs everything, and the client
pointed at it, so the DNS transport fails and the chain falls to icmp_udp.

    dnsmasq -C testing/dnsmasq-nxdomain.conf -d &

and in the client config:

    "dns_resolver": "127.0.0.1:5353"

The rules below are scoped to the server: they control which paths to it are
reachable and leave the rest of the machine's networking alone.

PRE

apply_rules <<EOF
# Config 4 — the ICMP/UDP tunnel is the only route out. DNS is redirected
# to a local NXDOMAIN resolver so the DNS tunnel path fails cleanly.
#
# Note the transport is icmp_udp: it rides UDP 4500, not the ICMP protocol.
# An earlier version of this config passed "inet proto icmp" and blocked
# UDP 4500, so it blocked the very path it was meant to force.
# No rdr here.
#
# Redirecting every port-53 packet to the NXDOMAIN resolver would take the
# operator's own DNS down with it, and it is not needed: the client is pointed
# at that resolver directly with dns_resolver in its config, which makes the DNS
# transport fail for the same reason without touching anything else on the
# machine.
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
pass out on $UPLINK_IF proto udp to $SERVER_IP port $ICMP_UDP_PORT
EOF

echo
echo "Expect all of: CONNECT fails, TLS/443 fails, DNS tunnel fails"
echo "(NXDOMAIN), ICMP succeeds. Watch for payload-bearing echoes:"
echo "    sudo tcpdump -i $UPLINK_IF 'icmp and host $SERVER_IP'"
echo
echo "ICMP is capped at 20 pps per icmp-tunnel-protocol-spec.md — confirm"
echo "the client does not exceed that under load."
footer
