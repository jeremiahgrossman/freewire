#!/usr/bin/env bash
# Config 4 — Fully local DNS resolver (NXDOMAIN), ICMP allowed. Forces Path 4.
# Guide: captive-portal-testing-guide.md §Configuration 4
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 4 "Local DNS resolver returns NXDOMAIN, ICMP allowed" \
  "Path 4 — ICMP tunnel" \
  "close to 10s (full chain timeout)"

cat <<PRE
This config needs a local resolver that NXDOMAINs everything, so that
*.$TUNNEL_DOMAIN never reaches the server. Start dnsmasq first:

    # /usr/local/etc/dnsmasq.conf  (or /opt/homebrew/etc/dnsmasq.conf)
    no-resolv
    address=/#/
    port=5353

    sudo brew services restart dnsmasq

PRE

apply_rules <<EOF
# Config 4 — ICMP is the only route out. DNS is redirected to the
# local NXDOMAIN resolver so the DNS tunnel path fails cleanly.
block out on $UPLINK_IF all
# Bootstrap API. In production this shares 443; see config.env.
pass out on $UPLINK_IF proto tcp to $SERVER_IP port $API_PORT
pass out on $UPLINK_IF inet proto icmp
rdr pass on $UPLINK_IF proto udp to port 53 -> 127.0.0.1 port 5353
EOF

echo
echo "Expect all of: CONNECT fails, TLS/443 fails, DNS tunnel fails"
echo "(NXDOMAIN), ICMP succeeds. Watch for payload-bearing echoes:"
echo "    sudo tcpdump -i $UPLINK_IF 'icmp and host $SERVER_IP'"
echo
echo "ICMP is capped at 20 pps per icmp-tunnel-protocol-spec.md — confirm"
echo "the client does not exceed that under load."
footer
