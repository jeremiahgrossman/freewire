#!/usr/bin/env bash
# Self-contained café capture. Run this in Terminal.app WHILE on the café wifi
# (pre-login, hotspot OFF). It needs no internet to Claude and no live session:
# it probes OUR server over whatever network is active and writes everything to a
# file. Then reconnect the hotspot and the result file is read back.
#
#   bash testing/cafe-run.sh
#
# Non-routed and safe: it changes no routes, no resolver, no utun (the probe
# battery is rootless; the per-carrier WG handshake uses --select-only, which
# also installs no routing). Losing the network mid-run strands nothing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
CDN="${FREEWIRE_CDN_HOST:-d29cubp361kpm8.cloudfront.net}"
TUN="$ROOT/tunnel/freewire-tunnel"
STAMP="$(date '+%Y%m%d-%H%M%S')"
OUT="/tmp/freewire-cafe-$STAMP.txt"

exec > >(tee "$OUT") 2>&1   # everything to screen AND the file

echo "════════════════════════════════════════════════════════════════"
echo "café capture @ $(date '+%Y-%m-%d %H:%M:%S')   -> $OUT"
echo "════════════════════════════════════════════════════════════════"

echo "---- which network is this? (confirm it is the café, NOT the hotspot) ----"
echo "  wifi: $(networksetup -getairportnetwork en0 2>/dev/null | sed 's/^Current Wi-Fi Network: //')"
echo -n "  egress IP (5s timeout; a blocked captive portal shows nothing or a portal IP): "
curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "(no egress -- expected pre-login on a blocking portal)"
echo ""
echo "  NOTE: hotspot egress was 74.254.x.x -- if the egress above is that, you are"
echo "  still on the hotspot and this is NOT a café measurement."
echo ""

echo "---- PROBE BATTERY (rootless; the key survey) ----"
"$TUN" --probe-battery --server "$SERVER" --insecure --cdn "$CDN" 2>&1 || true
echo ""

echo "---- REAL WireGuard handshake per carrier (needs the passwordless sudo rule; "
echo "     skipped cleanly if it is not set) ----"
if sudo -n true 2>/dev/null; then
  bash "$ROOT/testing/probe-transports.sh" --reuse 2>&1 || true
else
  echo "  (no passwordless sudo -- probe-transports skipped; the battery above is the"
  echo "   important result and it ran without root.)"
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "DONE. Reconnect the hotspot, then tell Claude: cat $OUT"
echo "════════════════════════════════════════════════════════════════"
