# Freewire VPN — Captive Portal Testing Guide

**Audience:** Engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

## Purpose

Freewire's core differentiator is that it establishes a VPN tunnel on captive portal networks. This guide explains how to simulate those networks on your own hardware so every fallback path — HTTP CONNECT, TLS/443, DNS tunnel, ICMP — can be tested, debugged, and benchmarked without going to an airport.

Do not rely on real captive portal networks for development testing. They are inconsistent, unreproducible, and not available on demand.

---

## How Captive Portal Simulation Works

A simulated captive portal is a local network where a gateway machine applies firewall rules that mimic what real captive portals do: block most outbound traffic and let a narrow set of ports or protocols through. The test device (your phone or Mac running Freewire) connects to this network and attempts to tunnel out.

You control exactly which ports and protocols are allowed, which lets you force the Freewire client onto a specific fallback path and verify it behaves correctly.

---

## Required Hardware and Software

**Minimum setup (one Mac as gateway):**
- A Mac with two network interfaces — one connected to the internet (the uplink), one creating a local network for the test device
  - MacBook with wifi (uplink) + USB-C Ethernet adapter (local network) works well
  - Alternatively: two USB-C Ethernet adapters
- The Freewire test device (iPhone, iPad, or second Mac) connected to the local network interface
- Wireshark installed on the gateway machine for traffic inspection

**Recommended setup (dedicated gateway):**
- A Raspberry Pi 4 (or any Linux machine) as the gateway — more reliable for long test runs and easier to reset
- The gateway machine has: one network interface to the internet, one to a local switch or wifi AP
- Test devices connect to the local network
- Advantage: gateway rules can be scripted and reset cleanly between test runs

**Required tools on the gateway:**
- macOS: `pf` (built in), `pfctl`, Python 3 (for the captive portal HTTP server)
- Linux: `iptables` or `nftables`, `dnsmasq` (for local DNS), Python 3
- Both: `iperf3` (throughput benchmarking), `tcpdump` or Wireshark (path verification)

---

## Gateway Setup

### macOS Gateway

Enable IP forwarding and configure the gateway interface:

```bash
# Enable IP forwarding
sudo sysctl -w net.inet.ip.forwarding=1

# Share internet connection via macOS Internet Sharing is the simplest starting point,
# then layer pf rules on top. Enable in: System Settings → General → Sharing → Internet Sharing
# Share from: Wi-Fi (or your uplink interface)
# To computers using: your local interface (e.g., en5 USB Ethernet)
```

Once Internet Sharing is enabled, pf rules are applied via `/etc/pf.conf` or a custom anchor. The test device connects to the shared network and receives a 192.168.x.x address.

### Linux/Raspberry Pi Gateway

```bash
# Install dnsmasq for DNS and DHCP
sudo apt install dnsmasq iptables-persistent

# Enable IP forwarding permanently
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Basic NAT (replace eth0 with your uplink interface, eth1 with local interface)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

---

## Test Configurations

Each configuration simulates a different captive portal network type and forces the Freewire client onto a specific fallback path.

Apply rules on the **gateway** machine. Clear all rules between test runs.

---

### Configuration 0 — Baseline (No Captive Portal)

Open network. All traffic passes. Used to verify Freewire works normally before adding restrictions.

**macOS pf rules:**
```
# No restrictions — default Internet Sharing rules
```

**Linux iptables:**
```bash
# Flush all rules — open network
sudo iptables -F FORWARD
sudo iptables -P FORWARD ACCEPT
```

**Expected behavior:** Freewire connects immediately via WireGuard on its standard UDP port. No fallback chain triggered.

---

### Configuration 1 — HTTP CONNECT Proxy Available (Path 1)

Simulates a captive portal that exposes an HTTP CONNECT proxy on port 443 but blocks everything else.

**Run a simple HTTP CONNECT proxy on the gateway:**
```python
# save as proxy.py — run on the gateway machine
import socket, threading

def handle(client):
    data = client.recv(4096).decode()
    if data.startswith("CONNECT"):
        host, port = data.split()[1].split(":")
        try:
            remote = socket.create_connection((host, int(port)))
            client.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            for s in [client, remote]:
                threading.Thread(target=lambda a,b: (b.send(a.recv(4096)) for _ in iter(int, 1)), args=(s, remote if s==client else client)).start()
        except:
            client.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443))
s.listen(50)
while True:
    threading.Thread(target=handle, args=(s.accept()[0],)).start()
```

**Block everything except port 443 to the gateway (macOS pf):**
```
block out on en0 all
pass out on en0 proto tcp to any port 443
pass out on en0 proto udp to any port 53
```

**Linux iptables:**
```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
# Allow DNS upstream
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
# Allow port 443 to gateway proxy only (block direct 443 to internet)
sudo iptables -A FORWARD -p tcp --dport 443 -d <gateway-ip> -j ACCEPT
sudo iptables -A FORWARD -p tcp --dport 443 -j DROP
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**Expected behavior:** Freewire attempts HTTP CONNECT to `vpn.freewire.com:443` via gateway proxy → succeeds → connects. Client should report path 1 active. Time to connected: ≤2s.

---

### Configuration 2 — Port 443 Open, Everything Else Blocked (Path 2)

Simulates the most common captive portal (~80% of networks): port 443 is open to the internet directly, everything else is blocked.

**macOS pf:**
```
block out on en0 all
pass out on en0 proto tcp to any port 443
pass out on en0 proto udp to any port 53
pass out on en0 inet proto icmp
```

**Linux iptables:**
```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -p tcp --dport 443 -j ACCEPT
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**Expected behavior:** HTTP CONNECT probe fails (no proxy). TLS/443 direct connects to `vpn.freewire.com:443` → succeeds → connects. Client should report path 2 active. Time to connected: ≤5s (2s HTTP CONNECT timeout + 3s TLS/443).

---

### Configuration 3 — DNS Forwarding Only, Port 443 Blocked (Path 3)

Simulates a network where port 443 is blocked but DNS queries are forwarded to the public internet. Forces the DNS tunnel path.

**macOS pf:**
```
block out on en0 all
pass out on en0 proto udp to any port 53
pass out on en0 inet proto icmp
```

**Linux iptables:**
```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -p icmp -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**Expected behavior:** HTTP CONNECT fails, TLS/443 fails, DNS tunnel to `tunnel.freewire.com` succeeds → connects. Client should report DNS tunnel path active, with a note that speed may be reduced. Time to connected: ≤8s (2s + 3s + 3s).

**Important:** With this config you can also test:
- EDNS0 behavior (see §Verifying Path Details below)
- DNS tunnel throughput (see §Benchmarking)
- Upgrade probe: after DNS tunnel establishes, does the client probe TLS/443? With this config it should fail and stay on DNS tunnel.

---

### Configuration 4 — Local DNS Resolver, ICMP Allowed (Path 4)

Simulates the hardest case: a fully local DNS resolver that returns NXDOMAIN for anything it doesn't control. DNS tunnel fails. Only ICMP reaches the internet.

**Set up local DNS resolver on gateway (dnsmasq):**
```bash
# /etc/dnsmasq.conf on gateway
no-resolv
address=/#/  # return NXDOMAIN for all domains
# This makes *.tunnel.freewire.com unreachable via DNS
```

**macOS pf:**
```
block out on en0 all
pass out on en0 inet proto icmp
# Intercept DNS and redirect to local dnsmasq
rdr pass on en1 proto udp to port 53 -> 127.0.0.1 port 5353
```

**Linux iptables + dnsmasq:**
```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
# Block DNS to internet, allow ICMP
sudo iptables -A FORWARD -p udp --dport 53 -j DROP
sudo iptables -A FORWARD -p icmp -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# Redirect DNS queries to local dnsmasq
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

**Expected behavior:** HTTP CONNECT fails, TLS/443 fails, DNS tunnel fails (NXDOMAIN), ICMP tunnel → succeeds → connects. Client should report ICMP path active. Time to connected: close to 10s (full chain timeout).

---

### Configuration 5 — All External Traffic Blocked (CONN-2b failure case)

Simulates a network where no path works and the captive portal probe also times out (genuine block, not just unauthenticated). Verifies CONN-2b error state and that the kill switch does not activate (no tunnel was established).

**macOS pf:**
```
block out on en0 all
pass out on en0 proto udp to any port 53
# DNS resolves but nothing can reach Freewire's servers
```

**Linux iptables:**
```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
# Allow DNS to internet but block everything else (including queries to tunnel.freewire.com)
sudo iptables -A FORWARD -p udp --dport 53 -j ACCEPT
sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
# Block responses from tunnel.freewire.com specifically
sudo iptables -A FORWARD -p udp --sport 53 -m string --string "tunnel.freewire.com" --algo bm -j DROP
```

A simpler approach: block DNS entirely and all other ports.

```bash
sudo iptables -F FORWARD
sudo iptables -P FORWARD DROP
```

**Expected behavior:** All four paths fail. Captive portal probe (`GET http://captive.apple.com/hotspot-detect.html`) times out (1s timeout, no redirect returned — no captive portal is present, just a hard block). Client shows CONN-2b: "This network is blocking secure connections." with sub-text "Freewire tried every available method. This network may restrict all VPN traffic." Kill switch does not activate (no tunnel was established). Traffic continues to flow — unprotected — through the network.

**Note:** To test CONN-2a instead (captive portal detected), run Configuration 5 but configure the gateway to intercept and redirect the HTTP probe request to a portal page. The client should open an in-app browser automatically instead of showing the CONN-2b hard error.

---

### Configuration 6 — Path 2 Active, Then Path 2 Opens (Upgrade Test)

Tests the upgrade logic: client connects via DNS tunnel, then TLS/443 becomes available mid-session, client upgrades transparently.

1. Start with Configuration 3 (DNS only)
2. Confirm client connects via DNS tunnel
3. While connected, modify gateway rules to also allow port 443:

**macOS pf:**
```bash
# Add to existing rules while DNS tunnel is active
sudo pfctl -f /etc/pf.conf.allow443
```

**Linux iptables:**
```bash
sudo iptables -I FORWARD 1 -p tcp --dport 443 -j ACCEPT
```

**Expected behavior:** Within the upgrade probe interval, the client detects TLS/443 is now reachable, upgrades transparently. User sees "Connected" throughout — no disconnect. Active path indicator changes from DNS tunnel to TLS/443.

---

## Verifying Which Path Is Active

Don't rely on the client's path indicator alone. Verify at the network layer using `tcpdump` on the gateway.

### Verify HTTP CONNECT (Path 1)
```bash
sudo tcpdump -i en0 'tcp port 443 and host <gateway-ip>'
# You should see CONNECT method traffic, not a TLS ClientHello
```

### Verify TLS/443 (Path 2)
```bash
sudo tcpdump -i en0 'tcp port 443 and host vpn.freewire.com'
# You should see a TLS ClientHello directed at vpn.freewire.com
```

### Verify DNS Tunnel (Path 3)
```bash
sudo tcpdump -i en0 'udp port 53 and host <freewire-dns-server-ip>'
# You should see a high volume of DNS queries for *.tunnel.freewire.com subdomains
# Queries will have Base32-encoded subdomains — not human-readable
```

### Verify ICMP Tunnel (Path 4)
```bash
sudo tcpdump -i en0 'icmp and host <freewire-server-ip>'
# You should see ICMP echo requests and replies with non-trivial data payloads
```

### Verify No Traffic Leak (All paths failed — Config 5)
```bash
sudo tcpdump -i en0 'not arp and not icmp'
# After CONN-2 error, you should see NO outbound traffic from the test device
# Kill switch confirmed working if this is silent
```

---

## DNS Tunnel Deep Inspection

When testing the DNS tunnel path, additional verification is useful.

### Check EDNS0 is being used
```bash
sudo tcpdump -i en0 -v 'udp port 53 and host <freewire-dns-server-ip>'
# Look for "OPT" records in the additional section of DNS responses
# "OPT" with a large payload indicates EDNS0 is active
```

### Count query rate (sliding window verification)
```bash
sudo tcpdump -i en0 -v 'udp port 53' | grep -c "tunnel.freewire.com"
# Run for 10 seconds, divide by 10 = queries/second
# With a healthy sliding window you should see >10 queries/second sustained
```

### Verify TTL=0 on tunnel subdomains
```bash
dig @<freewire-dns-server-ip> <any-subdomain>.tunnel.freewire.com
# TTL in the response should be 0
```

---

## Throughput Benchmarking

Run after confirming each path works. Use `iperf3` with a server running on a machine reachable through the Freewire tunnel.

```bash
# On a server reachable through the tunnel
iperf3 -s

# On the test device (inside the tunnel)
iperf3 -c <server-ip> -t 60 -i 5
```

### Targets per path

| Path | Minimum | Target |
|---|---|---|
| HTTP CONNECT | 50 Mbps | Limited by internet uplink |
| TLS/443 | 50 Mbps | Limited by internet uplink |
| DNS tunnel | 500 Kbps | 1–2 Mbps with full optimizations |
| ICMP tunnel | 100 Kbps | 500 Kbps |

### DNS tunnel degraded throughput (EDNS0 stripped)

To simulate a resolver that strips EDNS0, cap DNS response size on the gateway:

```bash
# iptables rule to truncate DNS responses (forces 512-byte limit)
sudo iptables -A FORWARD -p udp --sport 53 -m length --length 513:65535 -j DROP
```

Re-run `iperf3` and compare. Throughput should drop but the tunnel should remain functional. If it breaks entirely, that's a bug.

---

## Test Matrix

Run the full matrix before any engineering milestone that touches the fallback chain, upgrade logic, or error states.

| Test | Config | Pass condition |
|---|---|---|
| Path 1 — HTTP CONNECT connects | Config 1 | Connected in ≤2s; tcpdump shows CONNECT method |
| Path 2 — TLS/443 connects | Config 2 | Connected in ≤5s; tcpdump shows TLS to vpn.freewire.com |
| Path 3 — DNS tunnel connects | Config 3 | Connected in ≤8s; tcpdump shows DNS queries to tunnel.freewire.com |
| Path 4 — ICMP tunnel connects | Config 4 | Connected in ≤10s; tcpdump shows ICMP to Freewire server |
| CONN-2b — All paths fail, genuine block | Config 5 | CONN-2b error shown in ≤11s (10s chain + 1s probe); correct message shown; kill switch NOT active |
| Upgrade — DNS → TLS/443 | Config 6 | Upgrade occurs silently; no user-visible disconnect; active path changes |
| Kill switch — tunnel drops mid-session | Config 2, then block 443 | Traffic immediately blocked; reconnecting state shown |
| Reconnect — network change | Config 2, switch wifi networks | Reconnects within 3s; kill switch active during reconnect |
| DNS tunnel throughput | Config 3 | iperf3 shows ≥500 Kbps for 60s |
| EDNS0 stripped — tunnel degrades gracefully | Config 3 + EDNS0 strip | Tunnel remains active; throughput drops but does not break |
| No traffic leak — kill switch after connection failure | Config 5 | tcpdump shows no outbound traffic after CONN-2b error |

---

## Resetting Between Test Runs

Always flush all rules between test configurations to avoid rule bleed.

**macOS:**
```bash
sudo pfctl -F all
sudo pfctl -d
# Re-enable Internet Sharing if needed
```

**Linux:**
```bash
sudo iptables -F
sudo iptables -F -t nat
sudo iptables -P FORWARD ACCEPT
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
# Restart dnsmasq if used
sudo systemctl restart dnsmasq
```

---

## Common Issues

**"DNS tunnel connects but immediately drops"**  
Check that TTL=0 is set on tunnel subdomains. A resolver caching responses with TTL > 0 will return stale data for subsequent queries, breaking the sliding window. See `technical-architecture.md` §4.2.

**"ICMP path doesn't work even in Config 4"**  
Some macOS and Linux hosts rate-limit outbound ICMP by default. Check: `sysctl net.inet.icmp.icmplim` (macOS) or `cat /proc/sys/net/ipv4/icmp_ratelimit` (Linux). Set to 0 for testing.

**"HTTP CONNECT proxy returns 200 but tunnel doesn't work"**  
Verify the proxy is correctly forwarding to `vpn.freewire.com:443` and not just returning 200 and dropping the connection. Use `tcpdump` on the gateway to confirm bidirectional traffic.

**"TLS/443 path triggers DPI fingerprinting detection on test network"**  
This is a production concern, not a local test concern — your local gateway doesn't do DPI. If you want to test DPI resistance, configure `mitmproxy` or `squid` on the gateway with SSL inspection enabled and verify the TLS/443 path falls back gracefully.

**"Can't tell which path is active from the client"**  
Use `tcpdump` as described in §Verifying Which Path Is Active. The client UI path indicator is the product truth; `tcpdump` is the engineering truth. Both should agree.
