#!/bin/sh
# Source-NAT traffic arriving from the tunnel subnet before forwarding it.
#
# Without this the server forwards packets with their original 10.0.0.0/24
# source address. Nothing upstream has a route back to that subnet, so replies
# are never delivered: the client installs its routes, sends everything into a
# tunnel that looks healthy, and silently loses all connectivity.
set -e

TUNNEL_CIDR="${TUNNEL_CIDR:-10.0.0.0/24}"

# The interface holding the default route is the one traffic leaves by.
UPLINK="$(ip route show default | awk '/default/ {print $5; exit}')"

if [ -n "$UPLINK" ]; then
    if ! iptables -t nat -C POSTROUTING -s "$TUNNEL_CIDR" -o "$UPLINK" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$TUNNEL_CIDR" -o "$UPLINK" -j MASQUERADE
    fi
    iptables -C FORWARD -s "$TUNNEL_CIDR" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -s "$TUNNEL_CIDR" -j ACCEPT
    iptables -C FORWARD -d "$TUNNEL_CIDR" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -d "$TUNNEL_CIDR" -j ACCEPT
    echo "nat: masquerading $TUNNEL_CIDR out of $UPLINK"
else
    echo "nat: no default route found; forwarded traffic will not be translated" >&2
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

exec ./freewire-server /data/freewire-server.json
