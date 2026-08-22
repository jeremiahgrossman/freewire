#!/usr/bin/env bash
# Config 5 — Everything blocked. Verifies CONN-2b (genuine block).
# Guide: captive-portal-testing-guide.md §Configuration 5
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 5 "All external traffic blocked" \
  "None — all four paths fail" \
  "<=11s to CONN-2b (10s chain + 1s portal probe)"

apply_rules <<EOF
# Config 5 — hard block. The captive portal probe must also fail,
# so nothing is allowed out at all.
# Scoped to the server, not the whole interface.
#
# This was "block out on $UPLINK_IF all" while UPLINK_IF was a container bridge,
# where it only affected traffic to the test server. Once the server moved to
# the internet and UPLINK_IF became the physical interface, the same line cut
# the machine off the network entirely -- including DHCP, DNS and the operator's
# own session. The configs only ever needed to control which paths to the server
# are reachable.
block out on $UPLINK_IF to $SERVER_IP
EOF

cat <<NOTE

Expected user-visible result — CONN-2b, verbatim from error-states-spec.md:

    "This network is blocking secure connections."
    "Freewire tried every available method. This network may restrict
     all VPN traffic."

Three things that must ALL hold:

  1. CONN-2b, not CONN-2a. The portal probe to captive.apple.com must
     time out rather than return a redirect. If you see the in-app
     browser open, the probe found a portal and this run is invalid.

  2. Kill switch does NOT activate. No tunnel was ever established, so
     traffic keeps flowing unprotected. This is correct behavior.

  3. Total time <=11s. Longer means a path is not honoring its timeout.

NOTE
echo "To test CONN-2a instead, allow HTTP out and redirect it to a portal page."
footer
