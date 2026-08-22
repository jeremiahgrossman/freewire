#!/usr/bin/env bash
# Provision a Freewire server on a fresh Ubuntu/Debian host.
#
#   sudo ./provision.sh
#
# Assumes the freewire-server binary sits beside this script. Idempotent: safe
# to re-run after pushing a new binary.
set -euo pipefail

BIN_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/freewire-server"
BIN_DST="/usr/local/bin/freewire-server"
DATA_DIR="/var/lib/freewire"
CONF="$DATA_DIR/freewire-server.json"
UNIT="/etc/systemd/system/freewire.service"
TUNNEL_CIDR="10.0.0.0/24"

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -f "$BIN_SRC" ]] || { echo "freewire-server not found beside this script" >&2; exit 1; }

echo "==> installing binary"
install -m 0755 "$BIN_SRC" "$BIN_DST"
mkdir -p "$DATA_DIR"
chmod 0700 "$DATA_DIR"

echo "==> enabling forwarding"
# The server forwards tunnel traffic to the internet; without this the kernel
# drops it silently.
cat > /etc/sysctl.d/99-freewire.conf <<EOF
net.ipv4.ip_forward=1
EOF
sysctl -p /etc/sysctl.d/99-freewire.conf >/dev/null

echo "==> configuring NAT + forwarding"
# The NAT/forward rules live in freewire-nat.sh, installed here and re-applied on
# every service start via ExecStartPre (below). This survives reboots and
# instance stop/starts without depending on a saved iptables blob -- which
# silently did NOT persist: iptables-persistent was never installed, so
# `netfilter-persistent save` was a no-op, and after a stop/start the MASQUERADE
# rule was gone, leaving a tunnel that connected but carried nothing (the source
# stayed 10.0.0.0/24 and no reply could route back). Re-applying at each start
# re-derives the uplink too, in case it changed.
NAT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/freewire-nat.sh"
[[ -f "$NAT_SRC" ]] || { echo "freewire-nat.sh not found beside this script" >&2; exit 1; }
install -m 0755 "$NAT_SRC" /usr/local/bin/freewire-nat.sh
/usr/local/bin/freewire-nat.sh

echo "==> freeing port 53"
# systemd-resolved binds 0.0.0.0:53 on Ubuntu, so the DNS tunnel cannot start.
# The failure is easy to miss: every other transport comes up and only the DNS
# fallback is silently absent.
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/freewire.conf <<EOF
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved
  # resolv.conf pointed at the stub that was just switched off.
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  echo "    stub listener disabled"
fi

echo "==> installing service"
cat > "$UNIT" <<EOF
[Unit]
Description=Freewire VPN server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# Re-apply NAT/forwarding before the server starts, so a reboot or instance
# stop/start never leaves the tunnel forwarding with no MASQUERADE.
ExecStartPre=/usr/local/bin/freewire-nat.sh
ExecStart=$BIN_DST $CONF
WorkingDirectory=$DATA_DIR
Restart=always
RestartSec=3
# Needs root: creates a tun device and binds ports below 1024.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable freewire >/dev/null 2>&1
systemctl restart freewire

echo "==> waiting for startup"
for _ in $(seq 1 20); do
  [[ -f "$CONF" ]] && break
  sleep 0.5
done

if [[ ! -f "$CONF" ]]; then
  echo "server did not write its config; check: journalctl -u freewire -n 50" >&2
  exit 1
fi

PUBKEY="$(python3 -c "import json;print(json.load(open('$CONF'))['public_key'])" 2>/dev/null || true)"
PUBIP="$(curl -s -m 5 https://api.ipify.org || echo '<your public IP>')"

cat <<EOF

  Freewire server is running.

  Public IP:  $PUBIP
  Public key: $PUBKEY

  On the Mac, point the client at it and pin that key:

    defaults write com.freewire.vpn.Freewire pinnedServerKey '$PUBKEY'

  The key is what establishes trust, so a self-signed certificate on a bare
  IP is fine -- but the pin has to match exactly or the client refuses to
  connect, by design.

  Open these ports in the instance's security group:
    443/tcp    TLS transport and the API
    51820/udp  WireGuard
    53/udp     DNS tunnel
    4500/udp   ICMP/UDP tunnel

  Logs:  journalctl -u freewire -f
EOF
