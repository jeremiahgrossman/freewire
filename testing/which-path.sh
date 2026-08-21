#!/usr/bin/env bash
# Determine which fallback path is actually live, at the network layer.
# Guide: captive-portal-testing-guide.md §Verifying Which Path Is Active
#
#   sudo ./which-path.sh [seconds]     (default 10)
#
# Do not trust the client's own path indicator — that is the thing under
# test. This samples real traffic and reports what it sees.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/config.env"

DUR="${1:-10}"
IF="${UPLINK_IF}"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump not found" >&2; exit 1; }

CAP="$(mktemp /tmp/freewire-path.XXXXXX.pcap)"
trap 'rm -f "$CAP"' EXIT

echo "Sampling $IF for ${DUR}s..."
timeout "$DUR" tcpdump -i "$IF" -w "$CAP" -U \
  "tcp port 443 or udp port 53 or icmp" 2>/dev/null || true

count() { tcpdump -r "$CAP" -nn "$1" 2>/dev/null | wc -l | tr -d ' '; }

CONNECT_N=$(count "tcp port 443 and host $GATEWAY_IP")
TLS_N=$(count "tcp port 443 and host $SERVER_IP")
DNS_N=$(count "udp port 53 and host $SERVER_IP")
ICMP_N=$(count "icmp and host $SERVER_IP")
TOTAL=$(tcpdump -r "$CAP" -nn 2>/dev/null | wc -l | tr -d ' ')

# Base32 tunnel subdomains are the DNS tunnel's signature.
TUNNEL_Q=$(tcpdump -r "$CAP" -nn 'udp port 53' 2>/dev/null \
  | grep -c "$TUNNEL_DOMAIN" || true)

echo
printf '  %-28s %s\n' "packets captured" "$TOTAL"
printf '  %-28s %s\n' "443 -> gateway (CONNECT)"  "$CONNECT_N"
printf '  %-28s %s\n' "443 -> server (TLS)"       "$TLS_N"
printf '  %-28s %s\n' "53  -> server (DNS)"       "$DNS_N"
printf '  %-28s %s\n' "  of which tunnel queries" "$TUNNEL_Q"
printf '  %-28s %s\n' "ICMP <-> server"           "$ICMP_N"
echo

# Report the busiest path, with a floor so idle noise is not called a path.
MAX=0; PATH_NAME="none"
pick() { if (( $1 > MAX )); then MAX=$1; PATH_NAME="$2"; fi; }
pick "$CONNECT_N" "Path 1 — HTTP CONNECT"
pick "$TLS_N"     "Path 2 — TLS/443"
pick "$DNS_N"     "Path 3 — DNS tunnel"
pick "$ICMP_N"    "Path 4 — ICMP tunnel"

if (( MAX < 5 )); then
  echo "ACTIVE PATH: none detected"
  if (( TOTAL == 0 )); then
    echo "  No traffic at all. Consistent with Config 5 (hard block)."
    echo "  If the client reported Connected, that is a defect."
  else
    echo "  Traffic present but not to $SERVER_IP — check SERVER_IP/UPLINK_IF."
  fi
else
  echo "ACTIVE PATH: $PATH_NAME  ($MAX packets)"
fi

if (( TUNNEL_Q > 0 )); then
  RATE=$(( TUNNEL_Q / DUR ))
  echo "  DNS tunnel query rate: ~${RATE}/s (healthy sliding window is >10/s)"
fi

echo
echo "Leak check — any traffic bypassing the tunnel:"
tcpdump -r "$CAP" -nn "not arp and not icmp and not host $SERVER_IP" \
  2>/dev/null | head -5 || true
echo "  (silence above = no leak)"
