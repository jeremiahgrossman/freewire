#!/usr/bin/env bash
# Apply the tunnel's forwarding + NAT rules. Idempotent: safe to run on every
# service start.
#
# This exists because relying on a saved iptables blob (netfilter-persistent)
# failed silently -- iptables-persistent was not installed, so `save` was a
# no-op, and after an instance stop/start the MASQUERADE rule was gone. The
# server then accepted tunnelled packets and forwarded them with a 10.0.0.0/24
# source that nothing upstream could route a reply to: the tunnel connected and
# carried nothing. Re-deriving and re-applying the rules at each start does not
# depend on anything having been persisted, and re-derives the uplink interface
# in case it changed.
set -euo pipefail

TUNNEL_CIDR="10.0.0.0/24"

# Forwarding. The sysctl drop-in persists this across boots, but set it live too
# so a fresh start never forwards with it off.
sysctl -w net.ipv4.ip_forward=1 >/dev/null

UPLINK="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -z "$UPLINK" ]]; then
  echo "freewire-nat: no default route; cannot determine uplink" >&2
  exit 1
fi

# Masquerade tunnel egress out the uplink, or replies cannot route back.
if ! iptables -t nat -C POSTROUTING -s "$TUNNEL_CIDR" -o "$UPLINK" -j MASQUERADE 2>/dev/null; then
  iptables -t nat -A POSTROUTING -s "$TUNNEL_CIDR" -o "$UPLINK" -j MASQUERADE
fi

# Deny before allow: keep tunnelled traffic off the instance metadata service
# and every private range the host can reach (see provision.sh for the why).
block_forward() {
  iptables -C FORWARD -s "$TUNNEL_CIDR" -d "$1" -j REJECT 2>/dev/null \
    || iptables -I FORWARD 1 -s "$TUNNEL_CIDR" -d "$1" -j REJECT
}
block_forward 169.254.0.0/16
block_forward 10.0.0.0/8
block_forward 172.16.0.0/12
block_forward 192.168.0.0/16
block_forward 127.0.0.0/8

# The tunnel subnet itself is private, so re-allow it after the blocks.
iptables -C FORWARD -s "$TUNNEL_CIDR" -d "$TUNNEL_CIDR" -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$TUNNEL_CIDR" -d "$TUNNEL_CIDR" -j ACCEPT

iptables -C FORWARD -s "$TUNNEL_CIDR" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$TUNNEL_CIDR" -j ACCEPT
iptables -C FORWARD -d "$TUNNEL_CIDR" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$TUNNEL_CIDR" -j ACCEPT

echo "freewire-nat: NAT + forwarding applied (uplink $UPLINK)"
