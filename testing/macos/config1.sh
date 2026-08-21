#!/usr/bin/env bash
# Config 1 — HTTP CONNECT proxy available. Forces Path 1.
# Guide: captive-portal-testing-guide.md §Configuration 1
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 1 "HTTP CONNECT proxy on 443, all else blocked" \
  "Path 1 — HTTP CONNECT" \
  "<=2s to connected"

if ! nc -z "$GATEWAY_IP" 443 2>/dev/null; then
  echo "WARNING: no listener on $GATEWAY_IP:443."
  echo "Start the proxy first, in another terminal:"
  echo "    sudo python3 $ROOT/proxy.py"
  echo
  read -r -p "Continue anyway? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || exit 1
fi

apply_rules <<EOF
# Config 1 — only the gateway's CONNECT proxy and DNS may egress.
block out on $UPLINK_IF all
# Bootstrap API. In production this shares 443; see config.env.
pass out on $UPLINK_IF proto tcp to $SERVER_IP port $API_PORT
pass out on $UPLINK_IF proto tcp to $GATEWAY_IP port 443
pass out on $UPLINK_IF proto udp to any port 53
EOF

echo
echo "Verify with tcpdump that the client sends a CONNECT method,"
echo "not a TLS ClientHello:"
echo "    sudo tcpdump -i $UPLINK_IF 'tcp port 443 and host $GATEWAY_IP'"
footer
