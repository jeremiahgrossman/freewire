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
#   testing/probe-transports.sh
set -uo pipefail
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
API="https://$SERVER:8080"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUN="$ROOT/tunnel/freewire-tunnel"
TOKENS="$ROOT/tunnel/freewire-tokens"
STATE="/tmp/freewire-test"; mkdir -p "$STATE"
CFG="$STATE/probe-config.json"

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[[ -x "$TUN" ]] || { echo "build first: (cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel)" >&2; exit 1; }

echo "==> registering a probe peer"
SC="$(curl -sk --max-time 10 "$API/v1/server/config")"
KEY="$(jq -r .public_key <<<"$SC")"; WG="$(jq -r .endpoint_port <<<"$SC")"
TLS="$(jq -r .tls_endpoint_port <<<"$SC")"; DNS="$(jq -r .dns_tunnel_port <<<"$SC")"
ICMP="$(jq -r .icmp_udp_port <<<"$SC")"
[[ -n "$KEY" && "$KEY" != null ]] || { echo "no server config (captive portal blocking the API? probe still works with a cached peer)" >&2; exit 1; }
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
  "tls_port": $TLS, "dns_tunnel_port": $DNS, "icmp_udp_port": $ICMP
}
JSON

echo "==> probing each transport (non-routed; WG handshake over each)"
printf '  %-14s %-8s %s\n' "TRANSPORT" "PORT" "RESULT"
declare -A PORT=( [wireguard]="UDP $WG" [http_connect]="gateway" [tls443]="TCP $TLS" [dns]="UDP $DNS" [icmp_udp]="UDP $ICMP" )
for t in wireguard http_connect tls443 dns icmp_udp; do
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

# Best-effort: release the probe peer slot.
PT="$(jq -r .peer_token <<<"$PEER")"
[[ -n "$PT" && "$PT" != null ]] && curl -sk --max-time 8 -X DELETE "$API/v1/peers/$PT" >/dev/null 2>&1
echo "==> done (nothing was routed; machine untouched)"
