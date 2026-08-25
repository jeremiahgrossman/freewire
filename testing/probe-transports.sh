#!/usr/bin/env bash
# Probe EVERY transport against the server and report which carry a WireGuard
# handshake, and how fast. Non-routed and safe: each probe uses --select-only, so
# the chain opens the transport, completes the real WG handshake over it, prints
# the result, and exits WITHOUT installing routing. Nothing touches the system's
# routes or resolver, so it can't slow the machine.
#
# This is the per-session "check all methods" tool: run it on any network
# (including a captive portal) to see the full menu of what's reachable, so the
# fastest available carrier can be chosen instead of the first in a fixed order.
#
# FIELD USE: run it ONCE on an open network (your hotspot) to register a probe
# peer and cache its config, then run it again on the captive-portal wifi -- the
# API is blocked there, so it falls back to the cached config and still probes
# every transport (that is the only way to learn what a café allows across all seven
# pathways, including ICMP, since a live connect stops at the first that
# works). The probe peer is persistent and NOT deleted, so it survives the switch.
#
#   testing/probe-transports.sh          # register+cache if API reachable, else reuse cache
#   testing/probe-transports.sh --reuse  # force reuse of the cached peer (skip the API)
set -uo pipefail
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
API="https://$SERVER:8080"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUN="$ROOT/tunnel/freewire-tunnel"
TOKENS="$ROOT/tunnel/freewire-tokens"
STATE="/tmp/freewire-test"; mkdir -p "$STATE"
CFG="$STATE/probe-config.json"   # cached across the hotspot->café switch (same boot)
REUSE=0; [[ "${1:-}" == "--reuse" ]] && REUSE=1

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[[ -x "$TUN" ]] || { echo "build first: (cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel)" >&2; exit 1; }

# Reach the API only when not forced to reuse. A captive portal blocks it, which
# is expected -- we then fall back to the cached probe peer from an earlier run.
SC=""; [[ $REUSE == 0 ]] && SC="$(curl -sk --max-time 8 "$API/v1/server/config" 2>/dev/null)"
KEY="$(jq -r .public_key <<<"$SC" 2>/dev/null)"

if [[ -n "$KEY" && "$KEY" != null ]]; then
  echo "==> API reachable: registering a probe peer and caching its config"
  WG="$(jq -r .endpoint_port <<<"$SC")"; TLS="$(jq -r .tls_endpoint_port <<<"$SC")"
  DNS="$(jq -r .dns_tunnel_port <<<"$SC")"; ICMP="$(jq -r .icmp_udp_port <<<"$SC")"; CDN="$(jq -r '.cdn_host // ""' <<<"$SC")"
  PRIV="$(openssl rand 32 | base64)"
  PUB="$(cd "$ROOT/tunnel" && go run ../testing/pubkey.go "$PRIV" 2>/dev/null)"
  TOKEN="$([[ -x "$TOKENS" ]] && "$TOKENS" issue --server "$API" --count 1 --insecure --issuer-pin "$STATE/issuer.pin" 2>/dev/null | head -1 || true)"
  AUTH=(); [[ -n "$TOKEN" ]] && AUTH=(-H "Authorization: PrivateToken token=$TOKEN")
  PEER="$(curl -sk --max-time 10 -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d "{\"public_key\":\"$PUB\"}" "$API/v1/peers")"
  TIP="$(jq -r .tunnel_ip <<<"$PEER")"
  [[ -n "$TIP" && "$TIP" != null ]] || { echo "registration failed: $PEER" >&2; exit 1; }
  cat > "$CFG" <<JSON
{
  "private_key": "$PRIV", "server_public_key": "$KEY",
  "server_endpoint": "$SERVER:$WG", "server_host": "$SERVER",
  "tunnel_ip": "$TIP", "server_tunnel_ip": "10.0.0.1",
  "keepalive": 25, "insecure_tls": true,
  "tls_port": $TLS, "dns_tunnel_port": $DNS, "icmp_udp_port": $ICMP, "cdn_host": "$CDN"
}
JSON
  echo "    cached probe peer $TIP -> $CFG (reused automatically when the API is blocked)"
else
  # API unreachable (captive portal) or --reuse: fall back to the cached peer.
  [[ -f "$CFG" ]] || { echo "no cached probe peer at $CFG -- run this once on an open network first (hotspot) to register one." >&2; exit 1; }
  echo "==> API not reachable (captive portal); reusing the cached probe peer $CFG"
fi

echo "==> probing each transport (non-routed; WG handshake over each)"
WG="$(jq -r .server_endpoint <<<"$(cat "$CFG")" | sed 's/.*://')"
TLS="$(jq -r .tls_port <<<"$(cat "$CFG")")"; DNS="$(jq -r .dns_tunnel_port <<<"$(cat "$CFG")")"; ICMP="$(jq -r .icmp_udp_port <<<"$(cat "$CFG")")"; CDN="$(jq -r '.cdn_host // ""' <<<"$(cat "$CFG")")"
printf '  %-14s %-8s %s\n' "TRANSPORT" "PORT" "RESULT"
declare -A PORT=( [wireguard]="UDP $WG" [udp443]="UDP $TLS" [http_connect]="gateway" [tls443]="TCP $TLS" [wss443]="TCP $TLS" [cdn_wss]="CDN 443" [dns]="UDP $DNS" [icmp_udp]="UDP $ICMP" )
# wss443 sits next to tls443 on the same port: probing both is how a portal that
# passes web-443 (HTTP Upgrade) while refusing raw 443 shows itself here.
for t in wireguard udp443 http_connect tls443 wss443 cdn_wss dns icmp_udp; do
  start=$(python3 -c 'import time;print(int(time.time()*1000))')
  # sudo: --select-only still creates the utun for the WireGuard device, which
  # needs root. The passwordless rule covers the tunnel binary. No routing is
  # installed (that's what --select-only guarantees), so this stays safe.
  out="$(sudo -n "$TUN" --force-transport "$t" --select-only < "$CFG" 2>/dev/null)"
  end=$(python3 -c 'import time;print(int(time.time()*1000))')
  ms=$((end - start))
  if [[ "$out" == "$t" ]]; then res="OK  (${ms}ms)"; else res="-- no"; fi
  printf '  %-14s %-8s %s\n' "$t" "${PORT[$t]}" "$res"
done

# The probe peer is deliberately KEPT (persistent) so the same cached config can
# be reused on the captive-portal wifi where the API is blocked. It is a normal
# peer the server evicts when idle; delete it by hand later if you want:
#   PT=$(jq -r .peer_token "$CFG" 2>/dev/null)  # (peer_token isn't stored in CFG; see below)
# Note: CFG holds the private key + tunnel IP, not the peer_token, so there is
# nothing here to leak a redemption handle. To reclaim the slot, reconnect the
# app (which re-registers) or let idle eviction handle it.
echo "==> done (nothing was routed; machine untouched). Probe peer kept for café reuse."
