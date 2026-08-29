#!/usr/bin/env bash
# Essentials Mode PHASE 2 validation: the domain allowlist + scoped resolver.
# Brings the tunnel up with a DOMAIN in the allowlist and asserts the four things
# the scoped resolver must get right:
#
#   1. TAKEOVER  — the scoped resolver is listening on 127.0.0.1:53 and the system
#                  resolver points at it.
#   2. ALLOW     — an allowlisted domain (signal.org) RESOLVES through it (forwarded
#                  to the upstream routed into the tunnel).
#   3. REFUSE    — a non-allowlisted domain (example.com) returns NXDOMAIN, so the
#                  app cannot connect and stays blackholed.
#   4. ROUTE     — a resolved allowlisted IP is dynamically routed INTO the tunnel.
#
#   testing/essentials-domain-test.sh
#   ALLOW_DOMAIN=signal.org DENY_DOMAIN=example.com testing/essentials-domain-test.sh
#
# ⚠️ RISKIER THAN THE PHASE 1 TEST. Phase 1 never touched DNS; this one TAKES OVER
# the system resolver, so while it runs, most lookups on THIS MACHINE (including
# this shell and your browser) are scoped — non-allowlisted names get NXDOMAIN —
# until teardown. It is bounded: the 45s watchdog and the EXIT trap always restore
# routes AND resolvers, and cleanupDNS runs first on teardown. Run it when you can
# tolerate ~30s of scoped DNS. Uses the fast wireguard carrier (reliable on a
# hotspot) so the tunnel itself is never the variable.
#
# Needs the passwordless sudo rule for freewire-tunnel and the server reachable.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_BIN="$ROOT/tunnel/freewire-tunnel"
STATE="/tmp/freewire-test"
LOG="/tmp/freewire-essentials-domain-test.log"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"

ALLOW_DOMAIN="${ALLOW_DOMAIN:-signal.org}"
DENY_DOMAIN="${DENY_DOMAIN:-example.com}"
# The allowlist carries one IP prefix (so scope routing is exercised too) and the
# allowlisted domain (so the scoped resolver activates).
export FREEWIRE_ESSENTIALS="${FREEWIRE_ESSENTIALS:-17.0.0.0/8,$ALLOW_DOMAIN}"
CARRIER="${CARRIER:-wireguard}"

cleanup() { { echo "---- teardown $(date '+%H:%M:%S') ----"; "$ROOT/testing/disconnect.sh" 2>&1; } >> "$LOG" 2>&1; }
trap cleanup EXIT
HARD_DEADLINE="${HARD_DEADLINE:-45}"
( sleep "$HARD_DEADLINE"
  echo "---- HARD DEADLINE ${HARD_DEADLINE}s: force-restoring ----" >> "$LOG"
  sudo -n "$TUNNEL_BIN" --stop >/dev/null 2>&1
  pkill -f "/tunnel/freewire-tunnel" >/dev/null 2>&1
  sudo -n "$TUNNEL_BIN" --restore >/dev/null 2>&1 ) &
WATCHDOG=$!
trap 'kill "$WATCHDOG" 2>/dev/null; cleanup' EXIT

{
  echo "════════════════════════════════════════════════════════════════"
  echo "essentials-domain-test @ $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  allowlist=$FREEWIRE_ESSENTIALS  carrier=$CARRIER"
  echo "  allow=$ALLOW_DOMAIN  deny=$DENY_DOMAIN"
  echo "════════════════════════════════════════════════════════════════"
} > "$LOG"

{ echo "---- connect (forced $CARRIER, essentials + domain) ----"; "$ROOT/testing/connect.sh" "$CARRIER" 2>&1; } >> "$LOG" 2>&1

if ! grep -q "ready " "$STATE/tunnel.out" 2>/dev/null; then
  { echo "---- CONNECT FAILED (no ready line); tunnel.err tail ----"; tail -30 "$STATE/tunnel.err" 2>/dev/null; } >> "$LOG"
  echo "FAIL: tunnel did not come up (see $LOG)"; exit 1
fi

# Give the resolver a moment to bind + the takeover to land.
sleep 1

{
  echo "---- 1. TAKEOVER: scoped resolver up + system resolver pointed at it ----"
  grep -q "essentials resolver up" "$STATE/tunnel.err" 2>/dev/null \
    && echo "  OK: resolver reported up ($(grep 'essentials resolver up' "$STATE/tunnel.err" | tail -1 | sed 's/.*resolver up //'))" \
    || echo "  ?: no 'essentials resolver up' line in tunnel.err"
  echo "  listening on 127.0.0.1:53?"; (lsof -nP -iUDP:53 2>/dev/null | grep 127.0.0.1 | sed 's/^/    /' | head -2) || echo "    (lsof saw nothing)"
  echo "  system resolver:"; scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print "    "$0; exit}'

  echo "---- 2. ALLOW: $ALLOW_DOMAIN must RESOLVE through the scoped resolver ----"
  ALLOW_OUT="$(dig @127.0.0.1 +time=6 +tries=1 "$ALLOW_DOMAIN" 2>&1)"
  ALLOW_IPS="$(echo "$ALLOW_OUT" | awk '/^'"$ALLOW_DOMAIN"'\.?[[:space:]]/ && ($4=="A"||$4=="AAAA"){print $5}' | head -4 | tr '\n' ' ')"
  if [ -n "$ALLOW_IPS" ]; then echo "  OK: resolved -> $ALLOW_IPS"
  else echo "  FAIL: $ALLOW_DOMAIN did not resolve. status: $(echo "$ALLOW_OUT" | awk -F', ' '/status:/{print $2}')"; fi

  echo "---- 3. REFUSE: $DENY_DOMAIN must be NXDOMAIN (blackholed) ----"
  DENY_STATUS="$(dig @127.0.0.1 +time=6 +tries=1 "$DENY_DOMAIN" 2>&1 | awk -F'status: ' '/status:/{print $2}' | awk -F',' '{print $1}')"
  if [ "$DENY_STATUS" = "NXDOMAIN" ]; then echo "  OK: $DENY_DOMAIN refused (NXDOMAIN)"
  else echo "  FAIL: $DENY_DOMAIN returned status '$DENY_STATUS' (want NXDOMAIN) — a non-allowlisted name resolved"; fi

  echo "---- 4. ROUTE: a resolved allowlisted IP is routed INTO the tunnel ----"
  FIRST_IP="$(echo "$ALLOW_IPS" | awk '{print $1}')"
  if [ -n "$FIRST_IP" ] && [[ "$FIRST_IP" != *:* ]]; then
    RIFACE="$(route -n get "$FIRST_IP" 2>/dev/null | awk '/interface:/{print $2}')"
    echo "  $FIRST_IP -> ${RIFACE:-?}   (want a utun)"
    grep "routed $FIRST_IP" "$STATE/tunnel.err" 2>/dev/null | tail -1 | sed 's/^/  /'
  else
    echo "  (no IPv4 answer to check; skipping)"
  fi

  echo "---- verdict ----"
  echo "  Read the OK/FAIL lines above. ALLOW+REFUSE together prove the scoped"
  echo "  resolver enforces the allowlist; ROUTE proves the resolved IP is carried."
} >> "$LOG"

echo "essentials-domain-test: done, tearing down" >> "$LOG"
echo "DONE — read $LOG"
