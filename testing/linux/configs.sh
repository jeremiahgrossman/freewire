#!/usr/bin/env bash
# Freewire captive portal test configs — Linux gateway (iptables).
# Guide: captive-portal-testing-guide.md §Test Configurations
#
# Usage:  sudo ./configs.sh <0|1|2|3|4|5|6|reset>
#
# Use this when running a dedicated Linux/Raspberry Pi gateway with the
# test device behind it. For the single-machine Docker setup, use ../macos/ instead.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/../config.env"

UP="$LINUX_UPLINK_IF"
LOCAL="$LINUX_LOCAL_IF"

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 $*" >&2; exit 1; }
[[ $# -eq 1 ]] || { echo "Usage: sudo $0 <0|1|2|3|4|5|6|reset>" >&2; exit 1; }

base_flush() {
  iptables -F FORWARD
  iptables -t nat -F PREROUTING 2>/dev/null || true
}

# Re-establish NAT so the test device still has a route out where allowed.
base_nat() {
  iptables -t nat -C POSTROUTING -o "$UP" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$UP" -j MASQUERADE
}

established() {
  iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
}

case "$1" in
  0)
    echo "Config 0 — baseline open network"
    base_flush; base_nat
    iptables -P FORWARD ACCEPT
    echo "Expect: WireGuard direct. Fallback chain not triggered."
    ;;

  1)
    echo "Config 1 — HTTP CONNECT proxy on gateway:443"
    echo "Start the proxy first: sudo python3 $HERE/../proxy.py"
    base_flush; base_nat
    iptables -P FORWARD DROP
    iptables -A FORWARD -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -p tcp --dport 443 -d "$GATEWAY_IP" -j ACCEPT
    iptables -A FORWARD -p tcp --dport 443 -j DROP
    established
    echo "Expect: Path 1 (HTTP CONNECT). <=2s."
    ;;

  2)
    echo "Config 2 — 443 open direct, all else blocked"
    base_flush; base_nat
    iptables -P FORWARD DROP
    iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
    iptables -A FORWARD -p udp --dport 53 -j ACCEPT
    established
    echo "Expect: Path 2 (TLS/443). <=5s."
    ;;

  3)
    echo "Config 3 — DNS forwarding only, 443 blocked"
    base_flush; base_nat
    iptables -P FORWARD DROP
    iptables -A FORWARD -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -p icmp -j ACCEPT
    established
    echo "Expect: Path 3 (DNS tunnel). <=8s. Reduced-speed indicator shown."
    ;;

  4)
    echo "Config 4 — local NXDOMAIN resolver, ICMP only"
    echo "Requires dnsmasq on :5353 with 'no-resolv' and 'address=/#/'"
    base_flush; base_nat
    iptables -P FORWARD DROP
    iptables -A FORWARD -p udp --dport 53 -j DROP
    iptables -A FORWARD -p icmp -j ACCEPT
    established
    iptables -t nat -A PREROUTING -i "$LOCAL" -p udp --dport 53 \
      -j REDIRECT --to-port 5353
    echo "Expect: Path 4 (ICMP tunnel). ~10s. Cap 20 pps."
    ;;

  5)
    echo "Config 5 — hard block, everything dropped"
    base_flush; base_nat
    iptables -P FORWARD DROP
    echo "Expect: CONN-2b within 11s. Kill switch must NOT activate."
    ;;

  6)
    echo "Config 6 — open 443 mid-session (upgrade test)"
    echo "Run only while the client is live on the DNS tunnel."
    iptables -I FORWARD 1 -p tcp --dport 443 -j ACCEPT
    echo "Expect: transparent upgrade DNS -> TLS/443, no disconnect."
    ;;

  reset)
    echo "Resetting to open network"
    base_flush; base_nat
    iptables -P FORWARD ACCEPT
    echo "Network restored."
    ;;

  *)
    echo "Unknown config: $1" >&2
    exit 1
    ;;
esac
