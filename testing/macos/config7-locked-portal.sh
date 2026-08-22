#!/usr/bin/env bash
# Config 7 — Locked captive portal: only DNS escapes.
#
# This is the product's central scenario, and until t.pinghop.net was delegated
# (2026-08-22) it could not be tested at a desk at all. Every path that talks to
# the server directly is blocked; the DNS transport survives because it reaches
# the server THROUGH a recursive resolver, not directly, so blocking our own
# machine's traffic to the server never touches it.
#
# The rules are the same shape as config 5 (block out to the server), but the
# expected outcome is the opposite: config 5 assumed the DNS transport was
# pointed straight at the server IP (the dnsResolverOverride debug shortcut) and
# so predicted a total block (CONN-2b). Remove that override and the same rules
# leave the one path a real locked portal also leaves open.
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

banner 7 "Locked portal — only DNS escapes" \
  "dns (via the resolver + t.pinghop.net delegation)" \
  "<=6s to a chosen transport of 'dns'"

# PREREQUISITE the test depends on: DNS must use the system resolver, not the
# server IP. With the override set, the DNS transport queries the blocked server
# directly and this test degenerates into config 5.
REAL_USER="${SUDO_USER:-}"
if [[ -n "$REAL_USER" ]]; then
  OVERRIDE="$(sudo -u "$REAL_USER" defaults read com.freewire.vpn.Freewire dnsResolverOverride 2>/dev/null || true)"
  if [[ -n "$OVERRIDE" ]]; then
    echo "!! dnsResolverOverride is set to '$OVERRIDE'." >&2
    echo "!! This test needs it UNSET so DNS goes through the resolver, not the server." >&2
    echo "!! Run:  defaults delete com.freewire.vpn.Freewire dnsResolverOverride" >&2
    echo "!! Then re-run this config." >&2
    exit 1
  fi
  echo "dnsResolverOverride is unset — DNS will use the system resolver. Good."
fi

apply_rules <<EOF
# Config 7 — every direct path to the server is blocked. The DNS transport is
# not, because it never addresses the server: it queries the resolver, which
# follows the delegation to the server on our behalf. Scoped to the server so it
# cannot cut the machine off the network (see the config 5 warning).
block out on $UPLINK_IF to $SERVER_IP
EOF

cat <<NOTE

Expected result: the client selects the DNS transport.

Two ways to check, in order of preference:

  1. Safe, no routing (recommended). The tunnel binary can run the real fallback
     chain and report the winner without ever taking over the machine:

         echo '<tunnel-config-json>' | sudo $ROOT/../tunnel/freewire-tunnel --select-only

     It prints one line to stdout: the chosen transport. Expect:  dns
     (The app writes that config JSON when it connects; capture it once, or use
     the app path below.)

  2. The full app. Connect Freewire and watch the ready line / menu: the active
     transport should be DNS. Note that on a locked portal a DNS-routed machine
     is slow by design (~300-500 Kbps for everything). Disconnect, or
     'sudo $ROOT/../tunnel/freewire-tunnel --restore', to recover.

What must hold:

  1. Chosen transport is 'dns', not CONN-2b. If every path fails, the most
     likely cause is dnsResolverOverride still pointing at the server, or the
     delegation not resolving (check: dig +short NS t.pinghop.net @1.1.1.1
     followed to the server).

  2. HTTP CONNECT, TLS/443, ICMP/UDP and direct WireGuard all fail first. The
     stderr from --select-only lists each as unavailable before 'dns' wins.
     That sequence is the proof the chain degraded correctly, not that DNS
     happened to be tried first.

NOTE

footer
