#!/usr/bin/env bash
# Config 3 — DNS forwarding only, 443 blocked. Forces Path 3 (DNS tunnel).
# Guide: captive-portal-testing-guide.md §Configuration 3
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 3 "DNS forwards upstream, port 443 blocked" \
  "Path 3 — DNS tunnel" \
  "<=8s (2s + 3s + 3s)"

apply_rules <<EOF
# Config 3 — DNS and ICMP only. No 443.
block out on $UPLINK_IF all
pass out on $UPLINK_IF proto udp to any port 53
pass out on $UPLINK_IF inet proto icmp
EOF

cat <<NOTE

This is the highest-risk config — the DNS tunnel is the most complex
component and the least exercised. Three things to check beyond
"did it connect":

  1. EDNS0 negotiated (look for OPT records with a large payload):
       sudo tcpdump -i $UPLINK_IF -v 'udp port 53 and host $SERVER_IP'

  2. Sliding window healthy (expect >10 queries/sec sustained):
       sudo tcpdump -i $UPLINK_IF -v 'udp port 53' | grep -c '$TUNNEL_DOMAIN'

  3. Upgrade probe fires and correctly FAILS here, leaving the client
     on the DNS tunnel rather than flapping. The UI should show the
     reduced-speed indicator per ux-workflows.md 1.3.
NOTE
footer
