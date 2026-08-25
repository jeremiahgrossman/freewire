#!/usr/bin/env bash
# Measure end-to-end throughput of ONE carrier, routed, against a no-tunnel
# baseline. Answers the open question for cdn_wss: does CloudFront's WebSocket
# buffering throttle it, or does it carry near line rate?
#
#   testing/throughput-test.sh cdn_wss        # measure the CDN-fronted carrier
#   testing/throughput-test.sh wss443         # direct WebSocket, for comparison
#   testing/throughput-test.sh udp443         # UDP/443, near line rate expected
#   FREEWIRE_CDN_HOST=... testing/throughput-test.sh cdn_wss   # override CDN host
#
# It downloads a fixed blob from a fast CDN (Cloudflare's speed endpoint) with NO
# tunnel first (baseline), then through the routed tunnel, and reports both MB/s
# plus the ratio. Same detached-watchdog safety as routed-test.sh: the machine is
# never captured past HARD_DEADLINE even if a step wedges.
#
# HANDLE WITH the same care as routed-test.sh -- it routes ALL machine traffic
# through the tunnel for the measurement window. Do not run on a machine you need
# responsive during the run.
set -uo pipefail

TRANSPORT="${1:-cdn_wss}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_BIN="$ROOT/tunnel/freewire-tunnel"
STATE="/tmp/freewire-test"
LOG="/tmp/freewire-throughput-test.log"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
BYTES="${BYTES:-25000000}"                     # 25 MB blob
URL="https://speed.cloudflare.com/__down?bytes=$BYTES"
DL_TIMEOUT="${DL_TIMEOUT:-40}"
HARD_DEADLINE="${HARD_DEADLINE:-70}"           # > DL_TIMEOUT + connect + teardown

cleanup() { { echo "---- teardown $(date '+%H:%M:%S') ----"; "$ROOT/testing/disconnect.sh" 2>&1; } >> "$LOG" 2>&1; }
trap cleanup EXIT

# Detached hard-restore watchdog: force the machine back no matter what.
(
  sleep "$HARD_DEADLINE"
  echo "---- HARD DEADLINE ${HARD_DEADLINE}s hit: force-restoring ----" >> "$LOG"
  sudo -n "$TUNNEL_BIN" --stop >/dev/null 2>&1
  pkill -f "/tunnel/freewire-tunnel" >/dev/null 2>&1
  sudo -n "$TUNNEL_BIN" --restore >/dev/null 2>&1
) &
WATCHDOG=$!
trap 'kill "$WATCHDOG" 2>/dev/null; cleanup' EXIT

# rate_mbps <seconds> <bytes> -> MB/s (decimal), or "-" if seconds is empty/zero.
rate_mbps() { awk -v s="$1" -v b="$2" 'BEGIN{ if (s+0>0) printf "%.2f", (b/1048576)/s; else print "-" }'; }

{
  echo "════════════════════════════════════════════════════════════════"
  echo "throughput-test: transport=$TRANSPORT blob=${BYTES}B @ $(date '+%Y-%m-%d %H:%M:%S')"
  echo "════════════════════════════════════════════════════════════════"
} > "$LOG"

# --- baseline: no tunnel ---
{
  echo "---- baseline (no tunnel) ----"
  base_t=$(curl -s -o /dev/null -m "$DL_TIMEOUT" -w '%{time_total}' "$URL" 2>/dev/null)
  echo "  ${base_t}s -> $(rate_mbps "$base_t" "$BYTES") MB/s"
} >> "$LOG"

# --- connect, routed, forced to the transport ---
{ echo "---- connect ($TRANSPORT) ----"; "$ROOT/testing/connect.sh" "$TRANSPORT" 2>&1; } >> "$LOG" 2>&1
if ! grep -q "ready " "$STATE/tunnel.out" 2>/dev/null; then
  { echo "---- CONNECT FAILED (no ready line) ----"; tail -20 "$STATE/tunnel.err" 2>/dev/null; } >> "$LOG"
  exit 1
fi

# --- confirm we are actually tunnelled before trusting the number ---
egress=$(curl -s -m 8 https://checkip.amazonaws.com 2>/dev/null | tr -d '\n ')
{
  echo "---- routed egress check ----"
  if [ "$egress" = "$SERVER" ]; then echo "  TUNNELLED (egress=$egress)"; else echo "  NOT TUNNELLED (egress=${egress:-blocked}) -- throughput below is meaningless"; fi
} >> "$LOG"

# --- tunnelled download ---
{
  echo "---- through the $TRANSPORT tunnel ----"
  tun_t=$(curl -s -o /dev/null -m "$DL_TIMEOUT" -w '%{time_total}' "$URL" 2>/dev/null)
  echo "  ${tun_t}s -> $(rate_mbps "$tun_t" "$BYTES") MB/s"
} >> "$LOG"

# --- verdict ---
{
  echo "---- verdict ----"
  awk -v bt="$base_t" -v tt="$tun_t" -v b="$BYTES" 'BEGIN{
    if (bt+0>0 && tt+0>0) {
      br=(b/1048576)/bt; tr=(b/1048576)/tt;
      printf "  baseline %.2f MB/s, tunnelled %.2f MB/s -> %.0f%% of baseline\n", br, tr, 100*tr/br;
      printf "  tunnelled ~%.1f Mbps\n", tr*8;
    } else print "  could not measure (a download did not complete in time)";
  }'
  echo "  (DNS carrier floor for reference is ~0.07 MB/s / ~0.57 Mbps)"
} >> "$LOG"

echo "throughput-test: done, see $LOG"
