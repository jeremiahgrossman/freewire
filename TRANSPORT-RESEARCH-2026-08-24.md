# Transport research — captive-portal traffic techniques (2026-08-24)

Four parallel research agents surveyed the public literature on moving traffic
through captive portals and censored networks, to find methods Freewire does
not already use and could adopt. Sources are inline in each agent's output
(archived in the session task files); the load-bearing ones are linked below.

**One-line verdict:** the single high-value, buildable add is
**WebSocket-over-TLS-443 carrying WireGuard**. It directly targets the café
failure mode the field logs show, and it reuses infrastructure that already
exists. Everything else is either a dead end (domain fronting, ECH, MAC
cloning), needs infrastructure we can't run (refraction networking, Snowflake),
or is a strategic-but-heavy future direction (MASQUE/HTTP-3).

---

## The reframe: "café blocks 443" was probably wrong

Field test (2026-08-23) logged `tls443: dial 52.203.246.145:443: connection
refused` — an active reset — and I concluded the café blocks 443. The research
says that conclusion is likely incomplete. Portal gateways and transparent
proxies commonly **pass 443 that completes a valid HTTP Upgrade / WebSocket
handshake** (it looks like a normal HTTPS website) while **resetting a raw,
non-HTTP TLS session to an arbitrary IP** on the same port. Our TLS/443 carrier
is the latter: a bare uTLS handshake straight to the server IP, no HTTP. So the
café may not block 443 at all — it may block *non-web* 443. A WebSocket carrier
would present as a real web request and could clear exactly the gateway that
reset us. This is a testable hypothesis, not a certainty; the next field/probe
run should check it.

---

## BUILD — WebSocket-over-TLS-443 (WireGuard inside WSS frames)

- **What:** a `wss://server:443` endpoint on the server; the client opens a
  normal TLS + HTTP/1.1 `Upgrade: websocket` handshake, then streams WireGuard
  UDP datagrams inside WebSocket frames. To the café it is an HTTPS website
  connection, because it is one.
- **Why it's the pick:** it's the common portal-friendly denominator across
  every mature tunneling tool (chisel, gost, wstunnel, xray all converge on
  WS-over-443). Independent guidance is explicit that hotel/airport portals
  "drop everything except 80/443 TCP … WebSocket on 443 bypasses these because
  it IS HTTPS." wstunnel ships a documented WireGuard-over-WSS recipe.
- **Throughput:** the WS+TLS double-wrap costs ~35–45% vs bare WireGuard and
  ~10–18 ms added latency; ~100–120 Mbps usable on a small VPS. On our
  `t4g.small` we're userspace-WireGuard-CPU bound well before the WS layer. This
  is orders of magnitude above the throttled DNS carrier (~15–72 Kbps).
- **Caveat (design around it):** WebSocket rides TCP; WireGuard expects an
  unreliable datagram carrier. TCP-over-TCP reintroduces head-of-line blocking
  and "TCP meltdown" under loss (WireGuard already retransmits, so a lossy link
  double-retransmits). Fine on a decent café link, worse on a lossy one. Map WS
  frames 1:1 to WireGuard datagrams and tolerate the TCP semantics; the clean
  fix for this is the UDP-native MASQUE path (below), later.
- **Cost:** moderate and well-scoped. Server: a WSS listener on 443 that
  upgrades and pipes frames to the local WireGuard UDP socket (TLS + cert infra
  already exist). Client: a new carrier in the existing fastest-first chain,
  structurally like the current TLS/443 carrier plus an HTTP Upgrade + WS
  framing wrapper around the uTLS ClientHello we already rotate. Reuse
  `probeCarriesData` for the egress self-check. wstunnel/chisel are readable
  references. **The fall-through selection just built is what would let the
  chain discover WS-443 works when raw TLS/443 is refused.**
- Refs: [erebe/wstunnel](https://github.com/erebe/wstunnel) (native UDP tunnel,
  WireGuard tutorial), [VPNSmith wstunnel guide](https://www.vpnsmith.com/en/blog/wstunnel-tcp-over-websocket-2026),
  [computerscot WG-over-wstunnel](https://computerscot.github.io/wireguard-through-wstunnel.html),
  [jpillora/chisel](https://github.com/jpillora/chisel).

## SPIKE — IPv6 as a preferred carrier when the portal leaks it

- **What:** many captive portals are IPv4-only; the redirect/firewall never
  touches IPv6. Where the venue still routes IPv6 (RA/SLAAC hands the Mac a
  global v6 address + default route), v6 traffic egresses **unauthenticated**.
- **Why worth a spike:** cleanest and most defensible of the "route around the
  filter" methods — you use a legitimately provisioned address, spoof nothing,
  attack no one. Vendors have had to add explicit work to *restrict* SLAAC
  clients to the portal, which implies the default leaks. Fits the fallback
  chain: probe for a working v6 default route + egress at connect, and if
  present run WireGuard to the server over IPv6 (needs a v6 server endpoint /
  AAAA and a v6-capable carrier in the chain).
- **Ceiling:** only works where the venue provisions v6 and forgets to filter
  it — a shrinking but real population; some venues null-route v6 pre-auth, so a
  v6 address alone isn't proof, must confirm egress. Low-to-moderate cost.
- **Next step:** add an IPv6 egress probe to `probe-transports.sh` and measure
  at real portals before building the carrier.
- Refs: [OPNsense #8761](https://github.com/opnsense/core/issues/8761),
  [HPE Aruba: restricting IPv6 SLAAC to portal](https://airheads.hpe.com/discussion/restricting-ipv6-slaac-clients-traffic-to-captive-portal),
  [Wikipedia: Captive portal](https://en.wikipedia.org/wiki/Captive_portal).

## ROADMAP — MASQUE (CONNECT-UDP / HTTP-3 on 443), later

- The modern, censorship-resistant, **UDP-native** answer to "café allows only
  web-443/QUIC." Self-hostable on the existing EC2 box (a MASQUE proxy is just
  an HTTP/3 server), proven at scale (Apple iCloud Private Relay, Cloudflare
  WARP), with a standards-mandated **HTTP/2-over-TCP/443 fallback** when the
  portal blocks QUIC/UDP. Carries WireGuard UDP with no TCP-over-TCP mismatch —
  which is exactly the WS-443 caveat above, solved.
- **Does not help the DNS-only throttled café** (needs 443 or QUIC reachable),
  but it's the right long-term replacement for the bespoke TLS/443 framing.
- Cost: moderate-to-high (a CONNECT-UDP-over-HTTP-3 client + server;
  `quic-go`/`quiche` have the pieces). File as the successor to WS-443, not a
  now-build.
- Refs: [RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298),
  [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html),
  [Cloudflare MASQUE/WARP](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/).

## OPTIONAL — obfs4-style obfuscation on the TLS/HTTP-CONNECT carriers

- Elligator2 + randomized packet lengths/timing make a handshake
  indistinguishable from random bytes, defeating DPI that fingerprints
  WireGuard-in-TLS. Extends what uTLS rotation already starts. Matters against a
  DPI-equipped network, not a café that merely allowlists web-443 — so lower
  priority than WS-443 for our actual failure mode. Mature Go library
  (`obfs4proxy`). Ref: [PTPerf, IMC 2023](https://arxiv.org/html/2309.14856)
  (obfs4 was the top performer, ~6 Mbps class).

## ICMP carrier — throughput levers (if we ever revisit it)

- The ICMP-tunnel literature (ptunnel-ng, hans) solved "one round-trip per unit"
  the same way our deferred DNS work proposes: **pipeline multiple in-flight
  echoes, full-MTU payloads (~1472 B), windowed loss-aware retransmit.** One
  design pass could serve both the ICMP and DNS carriers. Keep ICMP as the
  minimal fallback it is; high detectability to any IDS.

---

## REJECTED — do not build (with the reason)

- **Domain fronting / meek:** dead on the CDNs that matter. AWS+Google banned it
  2018; Azure Front Door Jan 2024; Fastly Feb 2024. Also requires our data plane
  to sit behind a shared CDN (ToS-hostile to VPN tunneling), which a single-IP
  EC2 deployment doesn't. Surviving CDNs are small ones a portal won't allowlist.
- **ECH (Encrypted Client Hello):** no benefit on our IP-addressed server — the
  ClientHello already carries no SNI (confirmed by our own capture), so there's
  nothing to encrypt. Only helps behind an ECH-capable CDN (reintroduces the
  fronting problem). Confirms the existing WHAT-THE-SERVER-CAN-SEE decision.
- **SNI-spoofing (cosmetic allowlisted SNI to our own IP):** closed by default
  on modern gear that pins SNI to the server cert (FortiGate's server-cert SNI
  check). Viable only against naive SNI-only, IP-blind allowlists — a shrinking,
  unverified population. At most a cheap variant knob on the TLS/443 carrier, not
  a headline. Low priority.
- **MAC cloning an authorized device:** ethically it steals another guest's paid
  session (impersonation, ToS/CFAA exposure for a shipping product) and macOS
  has broken MAC spoofing since Monterey and locked it further in Sonoma/Sequoia.
  Reject.
- **IP takeover / ARP hijack:** active on-path attack on other guests, defeated
  by client isolation (standard on hotel/airport/café gear), trivially detected.
  Reject.
- **DHCP tricks:** not a real standalone bypass; folklore. Skip.
- **Refraction networking (TapDance/Conjure), Snowflake:** need ISP core stations
  or a volunteer-proxy network + centralized broker. Not runnable by a single
  operator. Instructive, not adoptable.

## What the DNS-only throttle research confirms

No published technique raises a single recursor's unique-name forwarding rate;
our ~14 q/s recursor ceiling is a documented protection mechanism, not a bug.
dnstt (the DNS-tunnel SOTA) sits in PTPerf's >80%-download-failure tier. DoH is
an anti-detection tool, not a throughput tool (iodine-over-DoH *regressed* 4–15×
vs plain UDP). Server-direct UDP-53 remains the real DNS carrier; the recursor
path stays the tiny/interactive fallback. **This independently validates the
DECISIONS.md call to defer Stage-2 DNS backpressure as low-yield** — you fill
the throttled pipe efficiently, you do not widen it. The way out of a
throttled-DNS-only café is a *different carrier* (WS-443), not a better DNS
carrier.
