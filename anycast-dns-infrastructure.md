# Freewire VPN — Anycast DNS Infrastructure

**Audience:** Server engineers and DevOps  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Depends on:** `technical-architecture.md` §4, `dns-tunnel-protocol-spec.md`

> **Status: Post-launch.** At launch, `tunnel.freewire.com` runs on a single authoritative DNS server in US-East (standard unicast, no BGP). Route 53 latency-based routing will be added post-launch to add EU-West and APAC servers without requiring an ASN. Full anycast (BGP, BIRD2) is a later optimization once traffic data justifies it. This document describes the anycast target architecture — implement the launch approach first.

---

## Launch Architecture (Pre-Anycast)

At launch, run a single EC2 instance in `us-east-1` hosting the Freewire DNS tunnel server. Register `tunnel.freewire.com` NS records pointing to this server's IP. No BGP, no ASN, no BIRD2 required.

**Launch DNS setup:**
```
tunnel.freewire.com.  NS  ns1.tunnel.freewire.com.
tunnel.freewire.com.  NS  ns2.tunnel.freewire.com.
ns1.tunnel.freewire.com.  A  <us-east-server-ip>
ns2.tunnel.freewire.com.  A  <us-east-server-ip>
```

Both NS records point to the same IP — this satisfies the two-nameserver requirement with no additional infrastructure.

**Post-launch expansion:** Add EU-West and APAC servers, use Route 53 latency-based routing at the NS layer to direct resolvers to the nearest server. No ASN needed for this step.

---

## Overview (Anycast Target Architecture)

Freewire's DNS tunnel requires an authoritative DNS server for `tunnel.freewire.com` that is globally reachable from any captive portal network. The authoritative servers deploy on anycast IP addresses so that a captive portal's upstream resolver is automatically routed to the nearest Freewire node, minimizing round-trip latency (the dominant factor in DNS tunnel throughput).

---

## What Anycast Means Here

In standard unicast routing, one IP address maps to one machine. In anycast, the same IP address is announced from multiple locations simultaneously. BGP routing directs each incoming packet to the geographically nearest node advertising that IP. The client (or, in this case, the captive portal's upstream DNS resolver) does not need to know about the multiple locations — it just queries the anycast IP and gets routed to the nearest one automatically.

For the DNS tunnel, this means:
- A captive portal resolver in Frankfurt is routed to Freewire's EU West PoP
- A captive portal resolver in Singapore is routed to Freewire's APAC PoP
- Latency from resolver to authoritative server is minimized in each region

---

## Provider

**Recommended provider at launch: Vultr**

Rationale:
- Vultr offers BGP anycast as a built-in feature (Vultr BGP sessions + IP announcements)
- Simpler to operate than self-managed BGP on AWS or GCP
- Lower per-PoP cost than Cloudflare Spectrum or similar managed anycast products
- Supports the 4 launch regions: US East (New Jersey), US West (Los Angeles), EU West (Amsterdam), APAC (Singapore)

Alternative if Vultr is unsuitable: **Fly.io** (managed anycast, simpler ops but less control over BGP routing) or **Cloudflare Workers** (managed platform, limited UDP support — not suitable for raw DNS server hosting).

---

## Launch PoPs

| PoP | Location | Vultr Region | Anycast IP |
|---|---|---|---|
| US East | New Jersey | `ewr` | (assigned at setup) |
| US West | Los Angeles | `lax` | (same anycast IP announced from all PoPs) |
| EU West | Amsterdam | `ams` | (same anycast IP) |
| APAC | Singapore | `sgp` | (same anycast IP) |

All four PoPs announce the **same anycast IPv4 address** for `tunnel.freewire.com`. BGP routing handles the rest.

---

## Infrastructure per PoP

Each PoP runs a single server (Vultr compute instance, 1 vCPU / 1 GB RAM sufficient at launch):

```
freewire-dns-<region>
├── freewire-server binary (same binary as the VPN gateway)
│   └── DNS tunnel authoritative server component
├── BGP daemon (BIRD2)
│   └── Announces anycast prefix to Vultr BGP peer
└── Certificate (Let's Encrypt, for HTTPS management interface)
```

The Freewire server binary handles DNS at the application layer. It listens on UDP 53 (and TCP 53 for fallback). The BGP daemon is responsible only for announcing the anycast prefix — it has no role in DNS handling.

---

## BGP Configuration

Each PoP establishes a BGP session with Vultr's route server using Vultr's BGP peering service.

### BIRD2 configuration (`/etc/bird/bird.conf`)

```
log syslog all;
router id <instance-private-ip>;

protocol device {}

protocol static {
    route <anycast-prefix>/32 blackhole;  # The anycast IP we're announcing
}

protocol bgp vultr {
    local as 271028;         # Freewire's ASN (apply for one at ARIN/RIPE/APNIC)
    neighbor <vultr-bgp-peer-ip> as 64515;  # Vultr's ASN for BGP peers
    password "<vultr-bgp-password>";

    ipv4 {
        import none;
        export filter {
            if net = <anycast-prefix>/32 then accept;
            reject;
        };
    };
}
```

**ASN requirement:** Freewire needs a public ASN to announce BGP routes. Apply for an ASN at the relevant RIR (ARIN for US: https://www.arin.net/resources/guide/asn/). This is a multi-week process — start early.

**IP block requirement:** Freewire needs a publicly routable IPv4 prefix (minimum /24) to announce as the anycast address. Either obtain an IP block from ARIN/RIPE or use Vultr's bring-your-own-IP (BYOIP) program.

---

## DNS Zone Configuration

`tunnel.freewire.com` is a delegated subdomain of `freewire.com`. The delegation is configured in Freewire's primary DNS zone (wherever `freewire.com` is hosted, e.g., Cloudflare):

```dns
; In freewire.com zone:
tunnel.freewire.com.  NS  ns1.tunnel.freewire.com.
tunnel.freewire.com.  NS  ns2.tunnel.freewire.com.

; Glue records (required because ns1/ns2 are under tunnel.freewire.com itself)
ns1.tunnel.freewire.com.  A  <anycast-ip>
ns2.tunnel.freewire.com.  A  <anycast-ip>
```

Both `ns1` and `ns2` point to the same anycast IP. This is intentional — anycast provides redundancy; the NS1/NS2 distinction is for compatibility with resolvers that require at least two nameservers.

The authoritative server for `tunnel.freewire.com` does not serve any static DNS records. All responses are generated dynamically by the Freewire server binary based on the session token and data in the query subdomain.

---

## PoP Health and Failover

### Health check

Each PoP's BGP daemon monitors the `freewire-server` process. If the process dies or becomes unresponsive:

```
# In BIRD2 config — withdraw anycast announcement if server is down
protocol bfd {
    interface "*" {
        min rx interval 100ms;
        min tx interval 100ms;
    };
}

# Track the server's health via a local check script
protocol static {
    route <anycast-prefix>/32 blackhole {
        check command "/usr/local/bin/freewire-health-check";
    };
}
```

`/usr/local/bin/freewire-health-check` sends a test DNS query to `localhost:53` and exits 0 if healthy, 1 if not. If the check fails, BIRD2 withdraws the BGP announcement for that PoP. Traffic is re-routed to the next-nearest PoP by BGP.

### Automatic recovery

When `freewire-server` recovers (systemd restarts it after failure), the health check passes, BIRD2 re-announces the prefix, and traffic resumes to that PoP. This is automatic — no manual intervention required.

### PoP outage

If a full PoP goes offline (hardware failure, network partition), its BGP session drops. Vultr withdraws its routes. Clients connecting through resolvers previously routed to that PoP are re-routed to the next-nearest PoP. For the DNS tunnel, this appears as a brief delay (one or two queries time out, sliding window detects and retransmits) but the tunnel recovers without reconnect.

---

## Monitoring

| Metric | Tool | Alert threshold |
|---|---|---|
| BGP session state per PoP | BIRD2 logs → Datadog | Alert if session down for >2 minutes |
| DNS query rate per PoP | `freewire-server` metrics endpoint | Alert if drops to 0 (server stopped) |
| DNS tunnel establishment success rate | Application metrics | Alert if <90% |
| Anycast IP reachability | Ping monitor from each region | Alert if >3 consecutive pings fail |
| PoP latency (resolver → authoritative) | Synthetic DNS queries from each region | Alert if p95 >200ms |

---

## Deployment

Each PoP is deployed identically. Use a configuration management tool (Ansible or Terraform) to ensure all PoPs are in sync.

### Initial PoP setup

```bash
# 1. Provision Vultr instance in target region
# 2. Configure BGP session in Vultr portal
# 3. Run setup script:

ansible-playbook -i inventory/ewr freewire-dns-pop.yml

# playbook steps:
#   - Install BIRD2
#   - Configure /etc/bird/bird.conf with region-specific BGP settings
#   - Install freewire-server binary from S3
#   - Configure /etc/freewire/config (DNS tunnel mode, no WireGuard gateway)
#   - Install and configure acme.sh for tunnel.freewire.com certificate
#   - Enable and start services: bird, freewire-server
#   - Verify: send test DNS query, verify BGP session established
```

### Software updates

PoP servers use the same auto-update mechanism as self-hosted servers: on boot, check `s3://freewire-server-releases/latest` and update if a newer binary is available. For DNS PoPs, the server binary runs in DNS-tunnel-only mode (no WireGuard gateway, no Privacy Pass issuer — those run only on managed VPN servers).

---

## Separation from Managed VPN Servers

DNS tunnel PoPs and managed VPN gateway servers are separate infrastructure:

| | DNS Tunnel PoPs | Managed VPN Servers |
|---|---|---|
| Purpose | Authoritative DNS for tunnel.freewire.com | WireGuard gateway + Privacy Pass issuer |
| Network | Anycast (BGP) | Unicast (standard cloud hosting) |
| Provider | Vultr | AWS |
| Regions at launch | 1 (US-East, unicast EC2 — anycast is post-launch) | 1 (US East) |
| Port | UDP 53 | UDP 51820, TCP 443 |

A client using the DNS tunnel path connects to a DNS PoP to establish the tunnel, then the tunnel's traffic exits through the managed VPN server. The DNS PoP is a relay for the tunnel packets — it does not terminate the WireGuard session.
