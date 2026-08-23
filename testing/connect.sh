#!/usr/bin/env bash
# Bring the tunnel up without the app, for automated end-to-end checks.
#
# Two of today's most serious defects -- a green "Protected" over unrouted
# traffic, and DNS leaking to the ISP while traffic was tunneled -- passed every
# static check and were visible only when the product actually ran. Each round
# of that cost a human a build, a click and a wait. This script removes the
# human from the loop so an end-to-end run is cheap enough to do routinely.
#
# It generates its own WireGuard keypair rather than reading the app's. The
# app's private key lives in the Keychain and must stay there; a test peer needs
# an identity, not that identity.
#
#   testing/connect.sh          # connect, print status, stay up
#   testing/disconnect.sh       # tear down and verify restoration
set -euo pipefail

#   testing/connect.sh dns     # force a transport instead of running the chain
#
# Forcing a transport is how the DNS and ICMP paths get tested for egress
# without a firewall. The harness configs prove path *selection* under portal
# rules; they were run with routing skipped, so they never showed that those
# transports actually carry traffic. This does, at the cost of not exercising
# the fallback chain -- the two are complementary, not substitutes.
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
TRANSPORT="${1:-}"
API="https://$SERVER:8080"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TUNNEL_BIN="$ROOT/tunnel/freewire-tunnel"
TOKENS_BIN="$ROOT/tunnel/freewire-tokens"
STATE="/tmp/freewire-test"
mkdir -p "$STATE"

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
[[ -x "$TUNNEL_BIN" ]] || { echo "build first: (cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel)" >&2; exit 1; }

if pgrep -f "/tunnel/freewire-tunnel" >/dev/null 2>&1; then
  echo "a tunnel is already running; run testing/disconnect.sh first" >&2
  exit 1
fi

# Repair anything a previous run left behind. A run killed without cleanup
# leaves the system pointed at a resolver that is no longer listening, and this
# script is usually the next thing to run after that happens.
sudo -n "$TUNNEL_BIN" --restore >/dev/null 2>&1 || true

echo "==> fetching server config"
CFG="$(curl -sk --max-time 10 "$API/v1/server/config")"
SERVER_KEY="$(jq -r .public_key <<<"$CFG")"
WG_PORT="$(jq -r .endpoint_port <<<"$CFG")"
TLS_PORT="$(jq -r .tls_endpoint_port <<<"$CFG")"
DNS_PORT="$(jq -r .dns_tunnel_port <<<"$CFG")"
ICMP_PORT="$(jq -r .icmp_udp_port <<<"$CFG")"
[[ -n "$SERVER_KEY" && "$SERVER_KEY" != null ]] || { echo "no server key in config" >&2; exit 1; }

# The key the client pins must be the key the server serves, or this script
# would happily test against something the real app would refuse.
PINNED="$(defaults read com.freewire.vpn.Freewire pinnedServerKey 2>/dev/null || true)"
if [[ -n "$PINNED" && "$PINNED" != "$SERVER_KEY" ]]; then
  echo "server key does not match the app's pin; refusing to connect" >&2
  echo "  server: $SERVER_KEY" >&2
  echo "  pinned: $PINNED" >&2
  exit 1
fi

echo "==> generating a test keypair"
PRIV="$(openssl rand 32 | base64)"
# Run from the tunnel module: testing/ has no go.mod of its own, and the helper
# needs curve25519 from the module's dependencies.
PUB="$(cd "$ROOT/tunnel" && go run ../testing/pubkey.go "$PRIV" 2>/dev/null || true)"
[[ -n "$PUB" ]] || { echo "could not derive a public key" >&2; exit 1; }

echo "==> requesting a Privacy Pass token"
TOKEN=""
if [[ -x "$TOKENS_BIN" ]]; then
  TOKEN="$("$TOKENS_BIN" issue --server "$API" --count 1 --insecure \
      --issuer-pin "$STATE/issuer.pin" 2>/dev/null | head -1 || true)"
fi

echo "==> registering peer"
AUTH=()
[[ -n "$TOKEN" ]] && AUTH=(-H "Authorization: PrivateToken token=$TOKEN")
PEER="$(curl -sk --max-time 10 -X POST "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"public_key\":\"$PUB\"}" "$API/v1/peers")"
TUNNEL_IP="$(jq -r .tunnel_ip <<<"$PEER")"
PEER_TOKEN="$(jq -r .peer_token <<<"$PEER")"
[[ -n "$TUNNEL_IP" && "$TUNNEL_IP" != null ]] || { echo "registration failed: $PEER" >&2; exit 1; }
echo "    tunnel ip $TUNNEL_IP"
printf '%s' "$PEER_TOKEN" > "$STATE/peer-token"

PREFERRED=""
if [[ -n "$TRANSPORT" ]]; then
  case "$TRANSPORT" in
    wireguard|tls443|http_connect|dns|icmp_udp) ;;
    *) echo "unknown transport: $TRANSPORT" >&2; exit 1 ;;
  esac
  PREFERRED=",
  \"preferred_transport\": \"$TRANSPORT\""
  # The DNS transport queries the authoritative server directly. In production
  # the tunnel zone is delegated and the system resolver forwards; nowhere else
  # is, so without this the DNS path cannot be exercised at all.
  if [[ "$TRANSPORT" == "dns" ]]; then
    # Which resolver the carrier queries. Default: the authoritative server
    # directly, which isolates the WG-over-DNS data plane from any recursive
    # resolver. Override with FREEWIRE_DNS_RESOLVER (e.g. "1.1.1.1:53" or the
    # router) to test the real delegated path and any resolver throttling.
    DNSR="${FREEWIRE_DNS_RESOLVER:-$SERVER:$DNS_PORT}"
    PREFERRED="$PREFERRED,
  \"dns_resolver\": \"$DNSR\""
    echo "    dns resolver: $DNSR"
  fi
  echo "==> forcing transport: $TRANSPORT"
fi

cat > "$STATE/config.json" <<JSON
{
  "private_key": "$PRIV",
  "server_public_key": "$SERVER_KEY",
  "server_endpoint": "$SERVER:$WG_PORT",
  "server_host": "$SERVER",
  "tunnel_ip": "$TUNNEL_IP",
  "server_tunnel_ip": "10.0.0.1",
  "keepalive": 25,
  "insecure_tls": true,
  "tls_port": $TLS_PORT,
  "dns_tunnel_port": $DNS_PORT,
  "icmp_udp_port": $ICMP_PORT$PREFERRED
}
JSON

echo "==> starting tunnel"
# --force-transport hard-pins the chain to the one transport (preferred_transport
# only reorders and still falls through, which would silently mask a DNS failure
# by succeeding on TLS). For a DNS diagnostic we want the failure, not a fallback.
FORCE=()
[[ -n "$TRANSPORT" ]] && FORCE=(--force-transport "$TRANSPORT")
# Diagnostic: install routing but skip the egress self-check, so a slow-but-
# working transport stays up long enough to measure real egress. Flags ride as
# args (the passwordless rule matches "binary *"), unlike env, which sudo scrubs.
[[ -n "${FREEWIRE_ROUTE_NO_VERIFY:-}" ]] && FORCE+=(--route-no-verify)
# NOTE: sudo scrubs the environment AND the passwordless rule only matches the
# bare binary, so FREEWIRE_DNS_* env knobs cannot be forwarded here (any `env`/
# `--preserve-env` wrapper trips the password prompt). To sweep concurrency under
# routing, change the default in dns_client.go and rebuild. The env knobs still
# work for the non-sudo standalone --dns-throughput sweeps.
# Feed the config over a FIFO and hold the write end open for the tunnel's whole
# life. The tunnel treats stdin-EOF as "the controlling app disconnected" and
# tears down -- correct for the real app (a pipe it holds and closes), but a
# plain `< config.json` EOFs the instant the JSON is read, tearing the tunnel
# down the moment it becomes ready. The holder writes the config, then blocks
# until the tunnel process is gone, so stdin only EOFs on real teardown.
FIFO="$STATE/stdin.fifo"
rm -f "$FIFO"; mkfifo "$FIFO"
sudo -n "$TUNNEL_BIN" "${FORCE[@]}" < "$FIFO" > "$STATE/tunnel.out" 2> "$STATE/tunnel.err" &
echo $! > "$STATE/launcher.pid"
{ cat "$STATE/config.json"; while pgrep -f "/tunnel/freewire-tunnel" >/dev/null 2>&1; do sleep 1; done; } > "$FIFO" &
echo $! > "$STATE/holder.pid"

for _ in $(seq 1 40); do
  if grep -q "^ready" "$STATE/tunnel.out" 2>/dev/null; then
    echo "    $(cat "$STATE/tunnel.out")"
    exit 0
  fi
  if ! pgrep -f "/tunnel/freewire-tunnel" >/dev/null 2>&1; then
    echo "tunnel exited before becoming ready:" >&2
    tail -20 "$STATE/tunnel.err" >&2
    exit 1
  fi
  sleep 0.5
done

echo "timed out waiting for ready:" >&2
tail -20 "$STATE/tunnel.err" >&2
exit 1
