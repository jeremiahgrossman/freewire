#!/usr/bin/env bash
# Measure the CURRENTLY-CONNECTED tunnel. Read-only: no routing, no sudo, no
# changes -- it just uses whatever connection is up. Run it AFTER the Freewire
# app connects on the café wifi, to turn "feels slow" into a real number.
#
#   1. On café wifi, launch the Freewire app; wait for it to say Protected.
#   2. bash testing/cafe-measure.sh
#   3. Reconnect the hotspot; the result file is read back.
#
# Safe to run anytime; if no tunnel is up it just reports the direct numbers.
set -uo pipefail
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
STAMP="$(date '+%Y%m%d-%H%M%S')"
OUT="/tmp/freewire-cafe-measure-$STAMP.txt"
exec > >(tee "$OUT") 2>&1

echo "════════════════════════════════════════════════════════════════"
echo "café measure @ $(date '+%Y-%m-%d %H:%M:%S')   -> $OUT"
echo "════════════════════════════════════════════════════════════════"

echo "---- are we tunnelled? (egress should be the server $SERVER) ----"
EG="$(curl -s --max-time 15 https://checkip.amazonaws.com 2>/dev/null | tr -d '\n ')"
if [ "$EG" = "$SERVER" ]; then
  echo "  TUNNELLED: egress = $EG  (traffic is going through Freewire)"
elif [ -n "$EG" ]; then
  echo "  NOT tunnelled: egress = $EG  (this is the café/direct path, not the tunnel)"
else
  echo "  no egress at all -- either fully blocked, or the tunnel is up but carrying nothing"
fi

echo "---- interface / routes (is a utun carrying the default?) ----"
route -n get default 2>/dev/null | awk '/interface:/{print "  default via "$2}'
ifconfig 2>/dev/null | grep -E "^utun[0-9]" | sed 's/:.*//' | sed 's/^/  up: /' | tail -3

echo "---- latency (10 pings to the server) ----"
ping -c 10 -t 20 "$SERVER" 2>&1 | tail -2 | sed 's/^/  /'

echo "---- throughput (downloads through whatever path is up) ----"
for bytes in 300000 1000000; do
  t="$(curl -s -o /dev/null --max-time 40 -w '%{time_total}' "https://speed.cloudflare.com/__down?bytes=$bytes" 2>/dev/null)"
  mbps="$(awk -v s="$t" -v b="$bytes" 'BEGIN{ if (s+0>0) printf "%.1f", (b*8/1e6)/s; else print "timeout" }')"
  kbs="$(awk -v s="$t" -v b="$bytes" 'BEGIN{ if (s+0>0) printf "%.0f", (b/1024)/s; else print "-" }')"
  echo "  ${bytes}B in ${t}s -> ${mbps} Mbps (${kbs} KB/s)"
done

echo "---- a real page load (does interactive browsing work at all?) ----"
pt="$(curl -s -o /dev/null --max-time 30 -w '%{time_total}' https://example.com 2>/dev/null)"
echo "  example.com fetched in ${pt}s $([ "${pt%%.*}" -ge 10 ] 2>/dev/null && echo '(painful but working)' || echo '')"

echo "════════════════════════════════════════════════════════════════"
echo "DONE. Reconnect the hotspot, then tell Claude: cat $OUT"
echo "  DNS-floor reference: the original café measured ~0.07 MB/s / ~72 Kbps."
echo "════════════════════════════════════════════════════════════════"
