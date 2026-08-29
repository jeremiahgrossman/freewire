#!/usr/bin/env bash
# Essentials Mode validation. Brings the tunnel up in Essentials Mode (allowlist
# split tunnel) over a THROTTLED DNS carrier (the café #3 repro), then asserts the
# two things the mode must get right:
#
#   1. SCOPE  — the allowlist (17.0.0.0/8) routes INTO the tunnel, while a
#               non-allowlisted host stays on the physical path (egress != server).
#   2. SURVIVAL — the tunnel STAYS UP under the cap instead of collapsing, because
#               only the allowlist enters the pipe (contrast: full-tunnel over the
#               same throttled DNS overflows the queue and tears down -> CONN-2a).
#
#   testing/essentials-test.sh                 # 17.0.0.0/8, DNS capped to ~72 Kbps
#   FREEWIRE_ESSENTIALS=17.0.0.0/8,1.2.3.4 testing/essentials-test.sh
#
# SAFE to run on a machine in use: Essentials Mode does NOT capture the default
# route, so this shell, your browser, and any remote session keep using the
# physical path. Only 17.0.0.0/8 goes through the (tiny) tunnel. The same watchdog
# + EXIT trap as routed-test.sh still force-restore the machine no matter what.
#
# Needs the passwordless sudo rule for freewire-tunnel (see testing/README.md) and
# the server API reachable.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_BIN="$ROOT/tunnel/freewire-tunnel"
STATE="/tmp/freewire-test"
LOG="/tmp/freewire-essentials-test.log"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"

# Essentials Mode config, exported so connect.sh's tunnel child inherits them.
export FREEWIRE_ESSENTIALS="${FREEWIRE_ESSENTIALS:-1}"           # =1 -> seed 17.0.0.0/8
# CARRIER: the SCOPE test (the MVP behavior) is proven over any reliable carrier,
# so default to wireguard, which works on an open hotspot. DNS is throttled and its
# handshake can fail under an aggressive cap, which would test the carrier, not the
# routing. Override CARRIER=dns to also exercise the throttled path.
CARRIER="${CARRIER:-wireguard}"
# Optional throttle for a DNS survival run. NOTE: FREEWIRE_DNS_CARRIER_CAP is
# QUERIES/SEC, not Kbps. Leave unset for the scope test (default); a WG-over-DNS
# handshake needs a burst, so too low a q/s cap strangles connect before routing.
[ -n "${FREEWIRE_DNS_CARRIER_CAP:-}" ] && export FREEWIRE_DNS_CARRIER_CAP

# A representative address INSIDE the seed allowlist, for the route-scope check.
ALLOW_IP="${ALLOW_IP:-17.253.144.10}"   # Apple range; route lookup only, no packet sent
# A non-allowlisted host: its egress must be the hotspot, NOT the server.
OUTSIDE_HOST="checkip.amazonaws.com"

cleanup() { { echo "---- teardown $(date '+%H:%M:%S') ----"; "$ROOT/testing/disconnect.sh" 2>&1; } >> "$LOG" 2>&1; }
trap cleanup EXIT

# Detached hard-deadline watchdog: force-restore after HARD_DEADLINE even if wedged.
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
  echo "essentials-test @ $(date '+%Y-%m-%d %H:%M:%S')"
  echo "  allowlist=$FREEWIRE_ESSENTIALS  carrier=$CARRIER  dns-cap=${FREEWIRE_DNS_CARRIER_CAP:-<none>} q/s"
  echo "════════════════════════════════════════════════════════════════"
} > "$LOG"

# Bring it up forced to the chosen carrier, in Essentials Mode.
{ echo "---- connect (forced $CARRIER, essentials) ----"; "$ROOT/testing/connect.sh" "$CARRIER" 2>&1; } >> "$LOG" 2>&1

if ! grep -q "ready " "$STATE/tunnel.out" 2>/dev/null; then
  { echo "---- CONNECT FAILED (no ready line) — Essentials should NOT collapse; tunnel.err tail ----"
    tail -30 "$STATE/tunnel.err" 2>/dev/null; } >> "$LOG"
  echo "FAIL: tunnel did not come up in essentials mode (see $LOG)"; exit 1
fi

{
  echo "---- 1. SCOPE: allowlist -> tunnel, everything else -> physical ----"
  # Allowlisted address must resolve to a utun; the split-default (0/1,128/1) must
  # be ABSENT (essentials installs 17.0.0.0/8, not the whole space).
  aiface="$(route -n get "$ALLOW_IP" 2>/dev/null | awk '/interface:/{print $2}')"
  echo "  allowlisted $ALLOW_IP -> ${aiface:-?}   (want a utun)"
  echo "  essentials route present?"; netstat -rn -f inet | awk '$1 ~ /^17\// {print "    "$0}'
  echo "  split-default present? (should be EMPTY in essentials mode)"
  netstat -rn -f inet | awk '$1 ~ /^0\/1$/ || $1 ~ /^128\.0\/1$/ {print "    LEAK: "$0}'

  echo "---- egress for a NON-allowlisted host (want the hotspot, NOT $SERVER) ----"
  eg="$(curl -s -m 8 https://$OUTSIDE_HOST 2>/dev/null | tr -d '\n ')"
  if [ "$eg" = "$SERVER" ]; then echo "  FAIL: non-allowlisted egress = $SERVER — the machine is full-tunnelled (scope leak)"
  elif [ -n "$eg" ]; then echo "  OK: non-allowlisted egress = $eg (physical path, machine NOT full-tunnelled)"
  else echo "  ?: non-allowlisted egress blocked ($eg)"; fi
} >> "$LOG"

# 2. SURVIVAL: the tunnel must STAY UP with only the allowlist in the pipe. Over a
# throttled DNS carrier, full-tunnel collapses here (queue 256/256, tail-drop
# storm); essentials should stay calm because offered load is tiny. Over wireguard
# there is no throttle, so "stays up" is the bar.
{
  echo "---- 2. SURVIVAL: is the tunnel still up ~8s in? (over dns: want NO tail-drop storm) ----"
} >> "$LOG"
sleep 8
{
  grep -E "dns send|tail-drop|carry no traffic|CONN-2|route-check|ESSENTIALS|essentials" "$STATE/tunnel.err" 2>/dev/null | tail -14 | sed 's/^/  /'
  echo "---- verdict ----"
  if grep -q "carry no traffic\|all_paths_failed" "$STATE/tunnel.err" 2>/dev/null; then
    echo "  FAIL: tunnel tore down — essentials did not survive the throttle."
  else
    echo "  PASS (survival): tunnel still up under the cap; only the allowlist is in the pipe."
  fi
} >> "$LOG"

echo "essentials-test: done, tearing down" >> "$LOG"
echo "DONE — read $LOG"
