#!/usr/bin/env bash
# Self-documenting field diagnostic. Run it on the café wifi AFTER connecting
# Freewire. It records ~60s of egress-over-time to a local file, so you can flip
# back to your hotspot afterward and have Claude read the whole timeline without
# you copying anything.
#
#   ./cafe-diagnostic.sh
#   (connect Freewire first, then run this, let it finish, then switch to hotspot)
#
# What it answers: does traffic actually go THROUGH the tunnel, and does it stay
# working, or does it carry a burst and then stall? The tunnel's stderr shows
# setup; this shows the session.
set -u

SERVER_IP="52.203.246.145"
OUT="/tmp/freewire-cafe-diagnostic.log"
SAMPLES=10
INTERVAL=1
CURL_TIMEOUT=12
# Worst case (every sample times out): SAMPLES*(CURL_TIMEOUT+INTERVAL) seconds.
MAXSECS=$(( SAMPLES * (CURL_TIMEOUT + INTERVAL) ))
echo "café diagnostic: $SAMPLES samples, up to ~${MAXSECS}s if the network is fully blocked."
echo "(prints a line per sample so you can watch progress; Ctrl-C to stop early)"
echo

{
  echo "==== freewire café diagnostic @ $(date '+%Y-%m-%d %H:%M:%S') ===="
  echo "wifi:          $(networksetup -getairportnetwork en0 2>/dev/null | sed 's/.*: //')"
  echo "en0 IPv4:      $(ipconfig getifaddr en0 2>/dev/null || echo none)"
  echo "default iface: $(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
  echo "resolver[0]:   $(scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3; exit}')"
  echo "utun count:    $(ifconfig -l | tr ' ' '\n' | grep -c utun)"
  echo "server IP:     $SERVER_IP  (egress == this means traffic is really tunnelled)"
  echo "----------------------------------------------------------------"
  echo "t(s)  result           egress-IP / note                latency"
} > "$OUT"

start=$(date +%s)
tunneled=0; direct=0; blocked=0
for i in $(seq 1 "$SAMPLES"); do
  now=$(date +%s); t=$((now - start))
  # Egress check through whatever routing is live. Slow == going through a tunnel.
  resp=$(curl -s -m "$CURL_TIMEOUT" -w '|%{http_code}|%{time_total}' https://checkip.amazonaws.com 2>/dev/null)
  ip=$(echo "$resp" | sed 's/|.*//' | tr -d '\n ')
  code=$(echo "$resp" | awk -F'|' '{print $2}')
  lat=$(echo "$resp" | awk -F'|' '{print $3}')
  if [ "$ip" = "$SERVER_IP" ]; then
    note="TUNNELLED (via server)"; tunneled=$((tunneled+1))
  elif [ -n "$ip" ]; then
    note="DIRECT — NOT tunnelled ($ip)"; direct=$((direct+1))
  else
    note="BLOCKED / no response"; blocked=$((blocked+1))
  fi
  printf '%4ds  %-16s %-32s %ss\n' "$t" "$note" "${ip:-—}" "${lat:-—}" >> "$OUT"
  # Live progress to the terminal, with a running tally, so it never looks hung.
  printf '  [%2d/%d] t=%3ds  %-24s  (ok:%d direct:%d blocked:%d)\n' \
    "$i" "$SAMPLES" "$t" "$note" "$tunneled" "$direct" "$blocked"
  sleep "$INTERVAL"
done

{
  echo "----------------------------------------------------------------"
  echo "summary: $tunneled tunnelled / $direct direct / $blocked blocked  (of $SAMPLES)"
  if [ "$tunneled" -eq "$SAMPLES" ]; then
    echo "verdict: SUSTAINED — traffic went through the tunnel the whole time."
  elif [ "$tunneled" -gt 0 ]; then
    echo "verdict: INTERMITTENT — the tunnel carried some samples and dropped others (throttling)."
  else
    echo "verdict: NOT TUNNELLED — traffic never went through the server (false Protected, or tunnel dead)."
  fi
  echo
  echo "==== tail of freewire-tunnel-stderr.log ===="
  tail -25 /tmp/freewire-tunnel-stderr.log 2>/dev/null
} >> "$OUT"

echo "Done. Wrote $OUT ($SAMPLES samples over $((SAMPLES*INTERVAL))s)."
echo "Now switch to your hotspot and tell Claude 'diagnostic done' — it will read the file."
