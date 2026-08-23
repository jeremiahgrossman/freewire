#!/usr/bin/env bash
# Autonomous routed transport test. Brings the tunnel up on ONE forced transport
# WITH real routing, measures whether traffic actually egresses through the
# server, captures the send-path counters and the pinned bypass routes, then
# tears everything down and verifies the machine was restored.
#
# Why this exists: a routed DNS/ICMP test sends ALL machine traffic (including
# the shell that launched it) through a ~500 Kbps tunnel, so a human-in-the-loop
# test locks up the operator's machine mid-run. This script is self-contained and
# bounded: it never waits indefinitely, and an EXIT trap always restores routing
# even if a step wedges. Run it in the background and read the log when it exits:
#
#   testing/routed-test.sh dns                 # carrier queries the server direct
#   FREEWIRE_DNS_RESOLVER=1.1.1.1:53 testing/routed-test.sh dns   # via a recursor
#   FREEWIRE_DNS_RESOLVER=192.168.0.1:53 testing/routed-test.sh dns  # via router
#
# Reads the result from /tmp/freewire-routed-test.log afterward. Needs the
# passwordless sudo rule for freewire-tunnel (see testing/README.md) and the
# server API reachable (config7 must NOT be locking it).
set -uo pipefail

TRANSPORT="${1:-dns}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_BIN="$ROOT/tunnel/freewire-tunnel"
STATE="/tmp/freewire-test"
LOG="/tmp/freewire-routed-test.log"
SAMPLES="${SAMPLES:-6}"        # egress probes while routed
CURL_TIMEOUT="${CURL_TIMEOUT:-6}"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"

# Always put the machine back, whatever happens. This is the safety net the
# whole design rests on: even a wedged tunnel process gets SIGTERM'd and routing
# gets restored, so the operator's machine never stays captured.
cleanup() {
  {
    echo "---- teardown $(date '+%H:%M:%S') ----"
    "$ROOT/testing/disconnect.sh" 2>&1
  } >> "$LOG" 2>&1
}
trap cleanup EXIT

{
  echo "════════════════════════════════════════════════════════════════"
  echo "routed-test: transport=$TRANSPORT resolver=${FREEWIRE_DNS_RESOLVER:-<server-direct>} @ $(date '+%Y-%m-%d %H:%M:%S')"
  echo "════════════════════════════════════════════════════════════════"
} > "$LOG"

# --- connect (forces the transport, hard) ---
{
  echo "---- connect ----"
  "$ROOT/testing/connect.sh" "$TRANSPORT" 2>&1
} >> "$LOG" 2>&1

if ! grep -q "^    ready\|ready " "$STATE/tunnel.out" 2>/dev/null; then
  {
    echo "---- CONNECT FAILED (no ready line); tunnel.err tail ----"
    tail -30 "$STATE/tunnel.err" 2>/dev/null
  } >> "$LOG"
  exit 1   # trap restores
fi

# --- snapshot what got pinned outside the tunnel (answers the resolver question) ---
{
  echo "---- pinned bypass routes (server + resolver must be here, else carrier loops) ----"
  netstat -rn -f inet | awk -v s="$SERVER" '$1==s || $1 ~ /^0\/1$/ || $1 ~ /^128\.0\/1$/ {print "  "$0}'
  echo "  (any host route to the carrier resolver should also appear above)"
  netstat -rn -f inet | grep -E "1\.1\.1\.1|192\.168\.0\.1" | sed 's/^/  resolver? /'
} >> "$LOG"

# --- sample egress through the live routes ---
{
  echo "---- egress samples (want: egress == $SERVER == tunnelled) ----"
} >> "$LOG"
tun=0; dir=0; blk=0
for i in $(seq 1 "$SAMPLES"); do
  resp=$(curl -s -m "$CURL_TIMEOUT" -w '|%{time_total}' https://checkip.amazonaws.com 2>/dev/null)
  ip=$(echo "$resp" | sed 's/|.*//' | tr -d '\n ')
  lat=$(echo "$resp" | awk -F'|' '{print $2}')
  if [ "$ip" = "$SERVER" ]; then note="TUNNELLED"; tun=$((tun+1))
  elif [ -n "$ip" ]; then note="DIRECT ($ip)"; dir=$((dir+1))
  else note="BLOCKED"; blk=$((blk+1)); fi
  echo "  sample $i: $note  ${lat:-—}s" >> "$LOG"
done
{
  echo "  → $tun tunnelled / $dir direct / $blk blocked (of $SAMPLES)"
  echo "---- send-path counters (from tunnel.err) ----"
  grep -E "dns send|tail-drop|forced to transport|routing:|carry no traffic" "$STATE/tunnel.err" 2>/dev/null | tail -12 | sed 's/^/  /'
} >> "$LOG"

# trap runs cleanup (disconnect + restore verification)
echo "routed-test: done, tearing down" >> "$LOG"
