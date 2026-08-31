> **Audience:** Reference only. Not required for engineering. The PRD (§6.1, §7, §8) is the authoritative source for requirements. This document captures the reasoning and design detail behind the protocol decisions.

# Freewire VPN — Technical Architecture

**Status:** Draft v0.1  
**Last updated:** 2026-06-17  

---

## 1. The Core Problem

Captive portals work by intercepting all outbound traffic at the network layer and dropping anything not destined for the portal itself. A standard VPN client fails because it cannot establish a tunnel to a remote server when the network blocks all routable traffic.

The design goal: establish an encrypted tunnel to a Freewire server on **any** network, before paying or authenticating with any captive portal, without user intervention.

---

## 2. Why DNS Is the Universal Fallback

A captive portal cannot block DNS to the public internet entirely. It needs DNS for its own operation: to resolve the payment processor domain (Stripe, PayPal), to serve its own redirect page, and to handle the TLS certificate validation required by the browser making the payment. If a captive portal locked down DNS to a fully local resolver, it would break its own payment flow.

In practice, captive portals run a local DNS resolver that intercepts queries and redirects them — but for any domain the portal does not control, it must forward the query upstream to a public recursive resolver. That forwarding is the escape hatch.

Freewire operates an authoritative DNS server for `tunnel.freewire.com`. Client devices send DNS queries for subdomains of that domain. The captive portal's resolver forwards those queries to Freewire's server. The server encodes response data in the DNS answer. Traffic flows in both directions — encoded in DNS queries outbound, encoded in DNS responses inbound — without requiring any open port beyond 53.

### The one failure case

Some captive portals run a **fully local DNS resolver** that returns NXDOMAIN for any domain it does not control. In this case, queries for `*.tunnel.freewire.com` never reach Freewire's server. DNS tunneling fails. This is uncommon in consumer environments but exists. ICMP tunneling is the fallback for this case.

---

## 3. Protocol Fallback Chain

The client attempts carriers in **speed order**, fastest first, and commits to the
first one that actually **carries traffic** (not merely handshakes — see the
traffic-verified fall-through below). Total time budget for the full chain: under
10 seconds. The canonical order is `defaultCandidates()` in
`tunnel/cmd/freewire-tunnel/transport.go`; keep this diagram in sync with it.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  1. wireguard      WireGuard UDP direct to server:51820.                 │
│                    Fastest; what an open network lands on immediately.   │
├─────────────────────────────────────────────────────────────────────────┤
│  2. udp443         WireGuard straight over UDP/443 (server relays to WG). │
│                    SAME speed as direct (no TCP-over-TCP); a port portals │
│                    pass far more often (blocking UDP/443 breaks HTTP/3).  │
├─────────────────────────────────────────────────────────────────────────┤
│  3. http_connect   CONNECT through the LOCAL gateway proxy (3128/8080/443)│
│                    then TLS. Independent of our server; ~5% of portals.   │
├─────────────────────────────────────────────────────────────────────────┤
│  4. tls443         Raw TLS to server:443. Works where 443 is left open.   │
├─────────────────────────────────────────────────────────────────────────┤
│  5. wss443         WireGuard inside a WebSocket on TLS/443 — looks like a  │
│                    website; passes "web-443-only" portals that reset raw  │
│                    TLS. Same port/cert as tls443, one extra round trip.   │
├─────────────────────────────────────────────────────────────────────────┤
│  6. cdn_wss        Same WebSocket, but to a CDN edge (CloudFront) that     │
│                    fronts the server. The ONLY carrier that beats          │
│                    DESTINATION gating (portal allow-lists the CDN, not us).│
│                    Skipped unless the server advertised `cdn_host`.        │
├─────────────────────────────────────────────────────────────────────────┤
│  7. dns_tcp        WireGuard over a TCP connection to server:53 (RFC 7766  │
│                    DNS-over-TCP framing). ~56x the UDP dns carrier below,  │
│                    and TCP gives real backpressure instead of tail-drop.   │
│                    Field-validated 2026-08-30: held a full tunnel at a     │
│                    destination-gated café where the UDP dns carrier below  │
│                    used to collapse under load. Added 2026-08-28.          │
├─────────────────────────────────────────────────────────────────────────┤
│  8. dns            WireGuard inside DNS queries/responses to our           │
│                    authoritative server. Survives hard portals that pass   │
│                    only DNS pre-auth; throttled (~72 Kbps floor) but real. │
├─────────────────────────────────────────────────────────────────────────┤
│  9. icmp_udp       WireGuard in ICMP echo payloads. Last resort, for       │
│                    networks with a fully-local DNS resolver.               │
└─────────────────────────────────────────────────────────────────────────┘
```

**Superseded (2026-08-30):** this diagram was 8 carriers as of its last update; `dns_tcp` (row 7 above) was added 2026-08-28 and is now field-validated. Nine carriers ship today.

Per-path handshake budgets (HTTP CONNECT 2s, TLS/443 3s, DNS 3s, ICMP 2s, plus
the captive-portal probe) are in `CLAUDE.md` §"Fallback Chain Timeouts".

### Traffic-verified fall-through

Selection does not stop at the first carrier that *handshakes* — it verifies the
carrier actually carries routed traffic (a real egress self-check). If a carrier
handshakes but carries nothing once routed (the "connected but dead" failure this
project lost weeks to), the client restores the machine, excludes that carrier,
and falls through to the next-fastest. On an open network this fires never and the
chain lands on `wireguard` immediately.

### Upgrade after establishment

Once any path establishes a tunnel, the client tests whether faster paths are now
reachable through the tunnel and upgrades transparently. The upgrade order is the
same speed order (`TunnelTransport.priority` in `PathUpgradeManager.swift`, kept in
lockstep with the Go chain). The user is never aware of which path is active — they
see "Connected."

### Captive portal probe (when all paths fail)

If all nine carriers fail, the client immediately probes whether the cause is an unauthenticated captive portal or a genuine network block. This determines the CONN-2a vs. CONN-2b error state (see `error-states-spec.md`).

**Probe mechanism:**

```
GET http://captive.apple.com/hotspot-detect.html
```

- HTTP only (not HTTPS) — captive portals intercept plain HTTP but cannot intercept HTTPS
- Timeout: 1 second
- Expected response for open network: `200 OK` with body `<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>`
- Captive portal present: any redirect (3xx), or a 200 response with different body content
- Genuine block: request times out or connection refused

**Why `captive.apple.com`:** This is the same endpoint iOS uses internally for captive portal detection. It is well-known, always available, returns a predictable response, and captive portal implementations are already designed to intercept and redirect it.

**Timing:** The probe runs only after all nine carriers have been exhausted. It adds at most 1 second to the total failure time. It does not run on successful connections.

### NEHotspotHelper — fully automatic portal authentication

For networks where portal authentication is a simple HTTP interaction (no user input required), `NEHotspotHelper` can complete authentication silently before the fallback chain even runs.

**How it works:**
- `NEHotspotHelper` registers as a network handler. When the device joins any wifi network, iOS calls the handler to evaluate it.
- The handler makes an HTTP probe. If it detects a captive portal, it programmatically makes the acceptance request (a GET or POST to the portal's confirm endpoint).
- On success, iOS marks the network as authenticated. By the time the user taps Connect in Freewire, the portal is already satisfied and all paths are available.
- On failure (portal requires user input), the handler returns `NEHotspotHelperResult.unsupported` and the normal in-app browser flow takes over.

**Coverage:** Handles most hotel and venue "accept terms" portals. Does not handle portals requiring email, room number, phone verification, or payment.

**Requirement:** `com.apple.developer.networking.HotspotHelper` entitlement — a separate Apple approval from `NEPacketTunnelProvider`. See `apple-entitlement-application.md` §NEHotspotHelper.

---

## 4. Custom Authoritative DNS Server Design

Standard DNS tunneling tools (iodine, dns2tcp) achieve 1–10 Kbps. Freewire's custom authoritative Domain Name System (DNS) server is designed to target 500 Kbps–2 Mbps on the DNS path by exploiting every degree of freedom the DNS protocol allows.

### 4.1 Payload maximization per query

**Outbound (client → server, encoded in query):**
- DNS labels can be up to 63 characters each; total domain up to 253 characters before the apex
- Subdomains encode data as Base32 (required for DNS label compliance): `[seq].[chunk].tunnel.freewire.com`
- Practical payload per query: ~150 bytes of raw data

**Inbound (server → client, encoded in response):**
- Without EDNS0 Extended DNS (EDNS0): 512-byte response limit
- With EDNS0: responses up to 4096 bytes
- All Freewire clients and servers negotiate EDNS0 on first contact; 512-byte fallback only for resolvers that strip EDNS0
- Multi-record responses: a single DNS response can carry A records, AAAA records, TXT records, and MX records simultaneously. Freewire encodes data across all available record types in every response, multiplying the inbound payload per round trip.
- Target inbound payload per response: ~3.5KB with EDNS0 + multi-record

### 4.2 Pipelining with a sliding window

Standard DNS is one query → wait → one response → repeat. This serialization limits throughput to `payload_size / round_trip_time`.

Freewire's DNS tunnel protocol uses a sliding window:

```
Client sends:  [seq=1][seq=2][seq=3][seq=4][seq=5] ───►
Server sends:  ◄─── [ack=1+data][ack=2+data][ack=3+data]
Client sends:  [seq=6][seq=7] ───►  (before seq=4,5 acked)
```

- Window size is negotiated during handshake based on observed round-trip latency
- Out-of-order responses are buffered and reassembled by sequence number
- Lost queries are detected by timeout and retransmitted
- Congestion control (additive increase / multiplicative decrease, similar to TCP) prevents flooding the resolver

### 4.3 Geographic deployment

**At launch:** Single authoritative DNS server in US-East (standard unicast EC2). No BGP or ASN required. The DNS tunnel works globally — latency is higher for non-US users but DNS tunnel is a last-resort fallback, so this is acceptable.

**Post-launch:** Add EU-West and APAC servers with Route 53 latency-based routing on NS records. Then full anycast (BGP) once traffic volume justifies it. See `anycast-dns-infrastructure.md`.

### 4.4 Control plane

Special subdomain prefixes are reserved for the control plane:

| Prefix | Purpose |
|---|---|
| `h.[token].tunnel.freewire.com` | Handshake — negotiate session key, window size, EDNS0 capability |
| `u.[token].tunnel.freewire.com` | Upgrade probe — test whether TLS/443 is reachable |
| `k.[token].tunnel.freewire.com` | Keepalive — maintain resolver cache entry, detect tunnel liveness |
| `t.[seq].[data].tunnel.freewire.com` | Data — tunnel payload |

### 4.5 Encryption

DNS queries and responses are plaintext at the protocol layer. Freewire encrypts the tunnel payload before encoding it into DNS labels. The encryption layer is established during the handshake using a Diffie-Hellman (DH) key exchange encoded in the handshake control messages. The DNS protocol sees random-looking Base32 strings; it does not see plaintext data.

---

## 5. TLS/443 Path

When port 443 is open, Freewire connects using a standard TLS handshake to a Freewire server presenting a valid certificate for `vpn.freewire.com`. The tunnel traffic runs inside the TLS session.

To avoid deep packet inspection (DPI) fingerprinting:
- The TLS handshake uses cipher suites and extensions that match current browser behavior (via the uTLS library or equivalent)
- The ALPN extension advertises `h2` (HTTP/2), consistent with normal browser HTTPS
- The server responds with HTTP/2 framing; tunnel data is encoded as HTTP/2 DATA frames

From the captive portal's perspective, this is indistinguishable from a browser loading an HTTPS page.

---

## 6. HTTP CONNECT Path

Some captive portals expose an HTTP proxy that supports the CONNECT method. The client sends:

```
CONNECT vpn.freewire.com:443 HTTP/1.1
Host: vpn.freewire.com:443
```

If the portal responds with `200 Connection established`, the client has an unrestricted TCP tunnel through port 443 to Freewire's server. Full VPN speed. The client then establishes TLS inside this tunnel.

This path is probed first because it is both fast and produces a full-speed tunnel when available.

---

## 7. ICMP Path

Internet Control Message Protocol (ICMP) echo request and reply packets carry a variable-length data payload. On networks where ICMP to external IPs is permitted, Freewire encodes tunnel data in this payload.

- Each ICMP echo request carries up to ~1400 bytes of encoded payload
- Freewire's server responds with ICMP echo replies carrying encoded response data
- Pipelining applies: multiple ICMP requests in flight simultaneously (AIMD window, 20 pps hard cap — see `icmp-tunnel-protocol-spec.md`)
- Speed: ~100–500 Kbps; sufficient for messaging and light browsing

ICMP is the fallback for networks where DNS resolvers are fully local and do not forward to the public internet.

---

## 8. Network Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  User Device                                                        │
│  ┌──────────────┐     ┌────────────────────────────────────────┐   │
│  │  Freewire    │────►│  Path Selection & Upgrade Manager      │   │
│  │  Client App  │     │  (wg → udp443 → http_connect → tls443   │   │
│  │              │     │   → wss443 → cdn_wss → dns_tcp → dns    │   │
│  │              │     │   → icmp_udp)                           │   │
│  └──────────────┘     └──────────────────┬─────────────────────┘   │
└─────────────────────────────────────────┬┼────────────────────────-┘
                                          ││
                    ┌─────────────────────┘│
                    │  Captive Portal      │ DNS queries (port 53)
                    │  Network             │ ICMP / port 443
                    └──────────┬───────────┘
                               │ Forwards DNS upstream
                               ▼
              ┌────────────────────────────────┐
              │  Public Internet               │
              │                                │
              │  ┌──────────────────────────┐  │
              │  │  Freewire Infrastructure │  │
              │  │                          │  │
              │  │  DNS tunnel server       │  │
              │  │  (t.pinghop.net)         │  │
              │  │  unicast at launch;      │  │
              │  │  anycast post-launch     │  │
              │  │                          │  │
              │  │  VPN gateway server      │  │
              │  │  (origin.pinghop.net:443)│  │
              │  └──────────────────────────┘  │
              └────────────────────────────────┘
```

---

## 9. Resolved Engineering Questions

All questions below are resolved. Full rationale is in `engineering-handoff.md` §Open Engineering Questions.

1. **DNS resolver EDNS0 stripping** — Resolved. Server signals EDNS0 availability via handshake Flags Bit 0. Client enters degraded mode (4× query frequency, ~250 bytes per response) if EDNS0 is stripped. Throughput ~500 Kbps in degraded mode. See `dns-tunnel-protocol-spec.md` §EDNS0-degraded mode.

2. **DNS TTL and caching** — Resolved. Stale responses are detected via sequence number mismatch. On stale detection, client rotates the subdomain prefix (new entropy prefix from monotonic counter) — guaranteed cache miss. See `dns-tunnel-protocol-spec.md` §Stale cache detection.

3. **ICMP rate limiting** — Resolved. Hard cap: 20 packets/second with AIMD below that. Typical throughput: 100–500 Kbps. See `icmp-tunnel-protocol-spec.md` §Rate limits.

4. **uTLS maintenance** — Resolved. Quarterly updates; out-of-cycle update within 30 days of a major Chrome/Safari release; rotate among 3 current fingerprints (Chrome, Safari/iOS, Firefox). See `build-and-release-pipeline.md` §uTLS Fingerprint Maintenance.

5. **Key exchange in DNS tunnel** — Resolved. Minimum 3 round trips: ClientHello query → ServerHello response (1), MAC confirmation query → "OK" response (2), data flow begins on round trip 3. X25519 public keys (32 bytes → 58 Base32 chars) fit in a single label. See `dns-tunnel-protocol-spec.md` §Handshake.

---

## 10. Future work: warm standby, and why not path bonding

Raised 2026-08-22: once the chain has established which transports a network
permits, could the permitted ones run in parallel to raise throughput?

**Bonding for throughput: no.** The paths are not comparable. TLS/443 measured
166 Mbps against this server; the DNS tunnel is 0.5–2 Mbps and the ICMP tunnel
is capped at 500 Kbps by design. Aggregating 166 Mbps with 0.5 Mbps buys 0.3%.
The only case where the arithmetic is interesting is DNS plus ICMP when
everything faster is blocked, and that doubles 0.5 Mbps to 1 Mbps.

It would also cost more than it pays, for two reasons that are structural
rather than implementation detail:

- **WireGuard's anti-replay window is 8128 packets** (`replay.windowSize`,
  RFC 6479). With one path near 70 ms and another beyond 500 ms, packets sent
  early on the slow path arrive after thousands sent later on the fast one and
  are rejected as too old. The tunnel would drop traffic it had successfully
  carried.
- **TCP inside the tunnel sees one path.** Heterogeneous latency across a
  single congestion-control loop causes retransmit-timer thrash and spurious
  retransmits; naive bonding across unequal paths reliably performs worse than
  the fast path alone. MPTCP needs per-subflow congestion control and an
  explicit scheduler precisely to avoid this, and none of that structure exists
  here.

There is also a detection cost: running DNS tunnelling, ICMP and TLS at once is
far more anomalous to a portal that is watching than any one of them.

**Warm standby: mostly not worth doing, and the cheap part is done.**

Designing it changed the conclusion. The point was to avoid re-walking the chain
after a drop. But the chain picks the *best* available path, so a standby is by
construction a *worse* one — on a portal where only the DNS tunnel works, the
standby is ICMP. Holding it open costs continuous polling or keepalives on the
transports least able to afford either, and doubles the anomalous traffic a
portal could notice, to save one handshake.

Almost all of the benefit came from something far cheaper. Reconnect was passing
no preferred transport, so it restarted from WireGuard and re-tested every path
the network had already refused. Naming the last working transport gets recovery
down to one handshake on a path known to work, with the rest of the chain still
following if it has stopped working. That is now implemented; `orderCandidates`
already supported it and only the reconnect path was not using it.

What a true warm standby would still add is avoiding that one handshake, and
WireGuard's roaming would make the switch itself nearly free: re-pointing the
device at a second local proxy is one IPC call, and the session survives because
the peer updates its endpoint on the first authenticated packet. If it is ever
picked up, the open questions are what holds the standby alive without the
keepalives becoming a signal, and whether the server counts a standby peer
against capacity.
