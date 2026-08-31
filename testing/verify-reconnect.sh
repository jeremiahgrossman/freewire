#!/usr/bin/env bash
# Verify the app recovers from an unexpected carrier/tunnel death. Connects via
# the real app (autoConnect), confirms it's up by EGRESS (the ready line goes to
# stdout, and a clean WireGuard-first connect emits no stderr, so egress == server
# is the reliable signal), kills the tunnel out from under it, and checks the app
# reconnects on its own. Fast path only (no machine slowdown). Self-restoring.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUN="$HERE/tunnel/freewire-tunnel"
# Resolved dynamically rather than hardcoding a DerivedData hash: that hash is
# tied to this exact checkout path and Xcode version, and silently goes stale
# on a clean DerivedData wipe or a fresh checkout with no fallback. Picks the
# most recently built Debug Freewire.app under DerivedData.
APP="$(find ~/Library/Developer/Xcode/DerivedData -maxdepth 6 -type d \
  -path '*/Build/Products/Debug/Freewire.app' -not -path '*/Index.noindex/*' -print 2>/dev/null \
  | xargs -I{} stat -f '%m %N' {} 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)"
if [[ -z "$APP" ]]; then
  echo "no built Freewire.app found under DerivedData -- build first:" >&2
  echo "  xcodebuild build -project macos/Freewire/Freewire.xcodeproj -scheme Freewire -configuration Debug CODE_SIGNING_ALLOWED=NO" >&2
  exit 1
fi
OUT=/tmp/freewire-verify-reconnect.log
SERVER=52.203.246.145
egress() { curl -s -m10 https://checkip.amazonaws.com | tr -d '\n'; }

cleanup() {
  { echo "---- teardown ----"
    osascript -e 'quit app "Freewire"' 2>/dev/null; sleep 2; pkill -x Freewire 2>/dev/null
    sudo -n "$TUN" --stop 2>/dev/null; sudo -n "$TUN" --restore 2>/dev/null
    echo "  egress now: $(egress)"
  } >> "$OUT" 2>&1
}
# No detached watchdog needed: this test uses the fast path (WireGuard/TLS, no
# machine slowdown) and every loop below is bounded with curl timeouts, so it
# cannot wedge. The EXIT trap always restores. (A detached sleep-watchdog could
# orphan and later fire mid-suite, which truncated the regression run.)
trap cleanup EXIT

echo "== verify-reconnect @ $(date '+%H:%M:%S') ==" > "$OUT"
# Start from a genuinely clean slate.
osascript -e 'quit app "Freewire"' 2>/dev/null; sleep 1; pkill -x Freewire 2>/dev/null; sleep 1
sudo -n "$TUN" --stop 2>/dev/null; sudo -n "$TUN" --restore 2>/dev/null

echo "  launching app (autoConnect)" >> "$OUT"
open "$APP"

# Wait for first connect: egress becomes the server.
connected=""
for i in $(seq 1 30); do [ "$(egress)" = "$SERVER" ] && { connected=1; break; }; sleep 1; done
pid1="$(pgrep -f "/tunnel/freewire-tunnel" | head -1)"
{ echo "---- first connect ----"
  echo "  egress: $(egress)  tunnel pid: ${pid1:-none}  connected=${connected:-no}"
} >> "$OUT"
[ -n "$connected" ] || { echo "  FAIL: never connected" >> "$OUT"; exit 1; }

# Kill the tunnel out from under the app (simulated dropped carrier).
echo "---- killing tunnel pid $pid1 (simulated drop) ----" >> "$OUT"
sudo -n "$TUN" --stop 2>/dev/null
# Confirm egress actually left the tunnel (drop took effect).
sleep 2
echo "  egress just after kill: $(egress)" >> "$OUT"

# Watch for the app to bring egress back through the server on a NEW tunnel.
recon=""
for i in $(seq 1 45); do
  pidN="$(pgrep -f "/tunnel/freewire-tunnel" | head -1)"
  if [ -n "$pidN" ] && [ "$pidN" != "$pid1" ] && [ "$(egress)" = "$SERVER" ]; then recon="$pidN"; break; fi
  sleep 1
done
{ echo "---- reconnect check ----"
  if [ -n "$recon" ]; then
    echo "  PASS: reconnected on new tunnel pid $recon, egress back to server"
  else
    echo "  FAIL: no reconnect within ~45s (pid=${pidN:-none}, egress=$(egress))"
  fi
} >> "$OUT"
