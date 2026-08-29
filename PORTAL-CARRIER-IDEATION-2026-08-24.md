# Novel captive-portal carrier ideation (2026-08-24)

Follow-on to `TRANSPORT-RESEARCH-2026-08-24.md`. Six research/ideation agents
(one lead + four protocol-cluster streams + one link-local kill) explored new
ways to carry WireGuard through a captive portal. This is the synthesis: what to
probe, what to build, and what is folklore, with the causal reasons and sources.

## The reframe that reorders everything

Mainstream captive portals **do not filter by port**. Every major vendor's
pre-auth enforcement is a **destination allow-list** (IP / FQDN walled garden),
default-deny, with only DHCP and DNS punched through globally (the portal cannot
function without them). Confirmed across Meraki, Cisco 9800, Aruba, Purple,
openNDS, MikroTik.

So "which port is open?" is the wrong question. The right one is: **does this
portal pass an arbitrary payload to OUR server's IP on port N?** That is
venue-specific and destination-scoped — "NTP to time.apple.com is allowed" does
not mean "UDP/123 to our server is allowed." The only way to know is to send
non-protocol bytes to our own server on that port and see if they arrive.

Two consequences:
1. **The cheap probe battery is worth more than any single carrier build.**
   Measuring what each real portal leaks turns "build and hope" into "measure,
   then build the one the field says is open." Every agent converged on this.
2. **The traffic-verified fall-through selection (already shipped, `3bae110`) is
   the right architecture** — it discovers, per network, which carrier actually
   carries traffic, which is exactly how you exploit a destination/mode-specific
   leak without knowing it in advance.

The café field data fits the reframe exactly: TCP/443 to our IP was actively
refused, DNS to our server was allowed, because DNS is globally punched through
and our IP was not in any walled garden.

## BUILD ORDER

### 0. Done: WebSocket-over-TLS-443 (`5db4bec`)
The TCP-side answer to "portal passes web-443 (HTTP Upgrade) but resets raw 443
to an IP." Shipped this session. It is the fallback for when UDP/443 is refused
but a completed HTTP handshake on TCP/443 is not.

### 1. Probe battery FIRST (cheap, non-routed, settles the rest empirically)
Add these lines to `testing/probe-transports.sh`, each a non-routed send to OUR
server's IP, before building any of their carriers:
- **UDP/443** (does the portal pass non-web UDP/443 to us?)
- **NTP/123** raw (non-NTP bytes to us on 123)
- **UDP/4500** (already a carrier; confirm it's in the venue's pre-auth ACL)
- **IPv6 egress** (global v6 address + default route present, then UDP to our v6)
- **multi-IP TLS/443** (same probe to 3–4 server IPs in different ranges, to
  detect destination-reputation gating)
Run the whole battery at the next several real portals. Minutes of work; it
replaces speculation with our own field data.

### 2. UDP/443 (QUIC-shaped) — highest-value new carrier
- **Mechanism:** WireGuard in UDP datagrams to `server:443`, optionally shaped
  like a QUIC Initial (long header, version field) so DPI that gates UDP/443 on
  "looks like QUIC" passes it. Terminate on our Go server on UDP/443.
- **Why open:** portals were built to intercept **TCP** web. Blocking UDP/443
  breaks HTTP/3 to Google/Cloudflare/YouTube, so "block QUIC" is an
  **off-by-default** feature every firewall vendor documents how to *enable* —
  proof the default is pass. The café's TCP/443 reset says nothing about UDP/443
  (separate codepath most portals never wrote).
- **Throughput:** near line-rate, tens–100+ Mbps, **no TCP-over-TCP penalty** —
  strictly better than the WSS carrier when it works. WSS/443 is the TCP
  fallback for when UDP/443 is refused.
- **Precedent:** Mullvad shipped WireGuard-over-QUIC (MASQUE, RFC 9298) in
  Sept 2025 for exactly this. This is also the on-ramp to the MASQUE roadmap
  item — build bare UDP/443 first, add HTTP/3/MASQUE shaping if a portal needs it.
- **Cost:** low — we already have a UDP DNS carrier and WG framing; this is "send
  WG to UDP/443." No new root beyond existing routing.
- Sources: Fortinet/WatchGuard/Forcepoint "block QUIC" guides; Cisco captive
  portal "does not support HTTP/3 QUIC"; Mullvad QUIC obfuscation launch.

### 3. IPv6 egress — the whole-address-family bypass
- **Mechanism:** if the venue hands out an RA/SLAAC v6 prefix and doesn't gate v6
  pre-auth, run WireGuard to a v6 literal at full speed. No encapsulation — a
  real carrier, not a covert channel.
- **Why open:** portal intercept/redirect logic is IPv4-only (the redirect is an
  HTTP 302 on a v4 DNS hijack); the v6 ACL equivalent frequently never got
  built. A documented misconfiguration class.
- **Throughput:** full line rate — the best possible outcome.
- **Cost:** trivial (wireguard-go already does v6; AWS gives the server a
  routable v6 address). Probe is one command (check for a global v6 default
  route, then UDP to our v6). **Prevalence on US café/hotel/airport wifi is
  unmeasured — the probe is the experiment.** Keep it as a cheap opportunistic
  rung regardless: it costs nothing to try and pays full speed when it hits.

### 4. Roadmap: MASQUE / HTTP-3 (CONNECT-UDP on 443)
The standards-based, UDP-native successor that #2 grows into. Self-hostable,
proven at scale (Apple Private Relay, Cloudflare WARP, Mullvad), with a mandated
HTTP/2-over-TCP fallback. Build after UDP/443 proves the UDP-443 path is real at
the venues we care about.

### Structural lead: multi-IP destination diversity
Because the café gated by **destination**, not port, giving the server multiple
egress IPs across reputationally-clean ranges multiplies the success odds of
*every* TCP/UDP carrier we already have — no new protocol. Moderate ops work
(multiple EIPs, or a second host in a cleaner ASN), trivial client change (an
endpoint list). Probe first: same TLS/443 probe to several server IPs; if some
pass and some are reset, gating is by IP and this is high leverage.

## FOLKLORE — do not build. Two confidence classes.

A "should work per spec" argument is not a safe kill: a network that misbehaves
can leave a port open the spec says to block, or block one the spec says to
allow. So the kills below are split by *what enforces them*. Only the first
class is safe regardless of how a given portal chooses to behave; the second is
a claim about portal *policy*, which varies by venue and must be **measured, not
assumed** — which is exactly what the probe battery is for.

### Class A — physics/addressing kills (safe regardless of portal behavior)

Enforced *below* the portal's policy layer, by router hardware and the OS
network stack. A misconfigured portal cannot override these.

- **mDNS/5353, SSDP/1900, LLMNR/5355, NetBIOS-NS/137, DHCP broadcast:** their
  destination is a link-local / admin-scoped multicast group or a limited
  broadcast (RFC 5771/2365 scope; TTL-255 check in the mDNS responder, TTL-1 in
  LLMNR; 255.255.255.255 never forwarded). Forwarding one off-link would need
  multicast routing toward the internet that no café AP runs, and the receiving
  stack drops it on the TTL check. Cannot reach our server *by virtue of being
  that protocol*, at any portal, correct or broken.
  - **Residue (honest):** the *unicast* modes — mDNS §5.5 direct-to-:5353, NBNS
    P-node — DO produce a routable packet. But then they are not a special
    carrier at all, just "UDP to port N," and their viability is entirely the
    empirical port question below. The probe battery tests arbitrary UDP to our
    server, so this residue is covered by measurement, not assumption.
- **APNs 17.0.0.0/8, RADIUS/1812, syslog/514:** category errors, not policy. APNs
  is destination-locked to Apple-owned IPs we cannot occupy; RADIUS/syslog flow
  gateway→server and the client is never the speaker. No portal setting changes
  this.
- **IP/TCP header covert fields, pure timing channels:** capacity is
  bits-per-packet / bits-per-second by information theory — below the DNS floor
  regardless of network.
- **Domain fronting, ECH:** dead on the CDNs that matter / no SNI to encrypt on
  our IP-addressed server (prior doc). Structural, not policy.

### Class B — policy/empirical kills (venue-dependent: PROBE, don't assume)

"Usually blocked" or "usually destination-scoped," from vendor docs and field
reports — but a specific café could differ. Do not build a bespoke carrier on
the assumption; DO add a probe line so the field decides.

- **IPsec/IKE 500, NAT-T 4500, L2TP 1701 pre-auth:** field reports and vendor
  guides say *usually blocked* pre-auth, and hotel-gateway "VPN passthrough"
  (Nomadix) is NAT-correctness (so a tunnel survives translation once you've
  paid), NOT pre-auth authorization. But this is portal policy, not physics — a
  vendor default ACL sometimes lists `svc-natt`/4500. **We already listen on
  4500 (the ICMP/UDP carrier) and the probe battery tests it, so the field tells
  us per-café.** Just don't build an IPsec-*shaped* carrier on the assumption.
- **NTP/123 to our server:** RFC 8952/8908 say portals SHOULD allow NTP (clock
  sync before the portal's own HTTPS validates), and Apple mandates it — but a
  well-run walled garden allow-lists *specific* NTP servers, not arbitrary ones.
  Raw UDP/123 to *our* server may or may not pass. The covert-fields version (if
  an NTP ALG is present) tops out ~240 bits/min, below the DNS floor. **Probe raw
  UDP/123 to our server; only build if it passes as a raw UDP carrier.**
- **STUN/3478, TURN/TURNS/5349:** STUN can't relay payload (kill). TURN is a real
  relay we could terminate, but venue-dependent (conferencing-friendly venues)
  and destination-scoped. Probe public-STUN reachability before considering.
- **SIP/5060:** usually ALG-mediated (collapses to a toy) or blocked. Probe
  before dismissing entirely, but low priority.
- **SMTP 25/587, SSH 22:** among the *most* documented deliberately-blocked
  ports on guest networks. Very unlikely, but a probe line costs nothing.
- **MAC-clone/ARP, refraction, Snowflake:** hostile+macOS-broken / need ISP-core
  or broker+proxy infra we can't run (prior doc). These stay killed on
  feasibility, not portal policy.

The rule of thumb: if the kill is enforced by addressing/hardware/information
theory, trust it. If it's enforced by *portal configuration*, turn it into a
probe line and let the café answer.

## Gap sweep round 2 (2026-08-24): is the published field exhausted?

A second wave of ~10 agents swept the academic venues systematically (FOCI/PETS
2023–2025, USENIX Sec 23–25, NDSS 23–26, IMC/CCS, anonbib, net4people) and tore
down the operational tooling (sing-box, Xray/REALITY, ShadowTLS, Hysteria2, TUIC,
Cloak, Shadowsocks-2022, zapret, GoodbyeDPI, Geneva, Outline, AmneziaWG, wstunnel,
chisel). **Honest conclusion: for a single operator on one server against
destination-based allow-listing, the published field is now substantively
exhausted.** The entire modern circumvention corpus is written against a
*different* adversary — nation-state DPI that classifies protocol/content on a
route it otherwise permits. A café doesn't classify your protocol; it won't route
you to an IP you haven't paid for. So almost every famous technique (REALITY,
ShadowTLS, Hysteria, TUIC, obfs4, Shadowsocks-2022, Phantun) is *content/SNI/
active-probe evasion that still terminates on our server's IP* — it dies at the
same destination drop as raw WireGuard. Against destination allow-listing there
are exactly **two** structural answers, and the sweep confirms it from many
angles:

### NEW HIGH-VALUE CLASS — reach a permitted destination (CDN-front our own server)

The one thing that structurally beats destination allow-listing and is
self-hostable by one operator: make our server reachable *as* an allow-listed
cloud destination, so the portal sees a CDN edge IP + CDN hostname instead of our
bare EC2 IP. Not domain fronting (that's dead) — we genuinely terminate behind the
CDN's own first-party endpoint.

- **Headline: CloudFront WebSocket in front of our own EC2.** AWS shipped
  WebSocket support for CloudFront VPC/custom origins (May 2026). Run the WSS-443
  carrier we just built behind a CloudFront distribution; the portal sees
  `*.cloudfront.net` on a CloudFront edge IP. No relay code, uses our existing
  AWS, and CloudFront→origin can preserve WS framing (no forced TCP-over-TCP on
  that leg). Self-hostable, one operator.
- **Alternatives / edge-IP diversity:** a Cloudflare Worker WSS relay (proven at
  scale for vless-over-Workers, but `connect()` is TCP-only → TCP-over-TCP, and
  ToS-gray), a Lambda function-URL relay (CensorLess, PoPETs 2026 — first-party
  function hostname, *not* dead fronting), Deno Deploy. Each is a different CDN =
  different edge IPs = another portal class beaten.
- **The catch, and the probe that settles it:** this beats **FQDN→frozen-IP**
  portals (the portal snoops allowed DNS names, freezes the resolved IPs into an
  ipset, then filters by IP — openNDS/pfSense/UniFi/basic gear, the common café
  class). It does **not** beat **live-SNI** enterprise portals that re-check the
  SNI continuously. Which mode a portal is in is a one-line pre-auth probe:
  `openssl s_client -connect <cloudfront-edge-ip>:443 -servername d123.cloudfront.net`
  from behind the portal. If the TLS completes to the edge IP pre-auth, the whole
  CDN-front class is live there. The café that gated our IP and passed DNS is a
  strong candidate for the winnable mode.
- **Cost caveat:** CloudFront egress ~$0.085/GB — fine for one user, in the
  `deploy/COSTS.md` "ruinous at scale" bucket. Fits single-user scope.

**This is arguably higher-value than raw WSS-443 for the café**, because WSS-443
to our *own* IP still gets IP-gated; CDN-fronted WSS is what reaches a
destination-gated portal. Roadmap: WSS-443 direct (done, beats "blocks non-web
443") → CDN-fronted WSS (beats "blocks our IP"). The fall-through selection
already discovers whichever works.

### The other structural answer — desync a stateful portal (conditional)

**Geneva-class client-side DPI desync** (Geneva, zapret, GoodbyeDPI): craft
your own outbound packets (segment splitting, low-TTL/bad-checksum decoy packets,
RST injection) to desync a *stateful inline* portal's tracking so a flow to a
blocked destination survives. This is the only *client-only* way to create
reachability to a blocked destination — but ONLY if the portal enforces with a
stateful inline redirect box, NOT a hard L3 walled-garden ACL (a low-TTL decoy to
a blocked IP is still a packet to a blocked IP). The café's `443 connection
refused` was an *active reset* from an inline box, which is encouraging for
desyncability. macOS needs a pf/divert packet-mangler (root). Cheap probe: send a
real ClientHello to a blocked destination preceded by a low-TTL fake segment; if
the handshake completes, the portal is desyncable. Gated on that one probe.

### Cheaper self-hostable add-ons the sweep surfaced

- **AmneziaWG** junk-packet + magic-header obfuscation on wireguard-direct: a
  drop-in WG fork on both ends, for networks that *DPI-fingerprint and drop plain
  WireGuard* (distinct from destination/port blocking). Content-only; doesn't beat
  allow-listing. Cheap flag, self-hostable.
- **Outline SDK `disorder` / TCP-reorder**: a named fragmentation-family
  obfuscation we didn't have; client-side, cheap, for the TLS/WSS carriers.
- **Build constraint for WSS-443 (USENIX '24 encapsulated-TLS fingerprinting):**
  do NOT nest an inner TLS handshake inside WSS — run WireGuard's Noise directly
  inside the WSS binary frames. **We already do this** (WG packets ride WSS frames,
  no inner TLS), so the carrier is built the fingerprint-resistant way. Keep it so.
- **Congestion control (FOCI '25 Xue/Ensafi):** BBR ≈ aggressive custom CC below
  ~20% loss, and a bespoke sender adds a fingerprint. Independently validates the
  Stage-2 backpressure deferral and the Stage-1 AIMD — if Stage 2 is ever picked
  up, mirror standard TCP/BBR dynamics, don't hand-roll an aggressive window.

### KILLED as a carrier — data inside the PKI/TLS handshake itself (certificates, keys, handshake fields)

Idea: carry tunnel bytes in the *fields* of a TLS handshake — certificate
contents, key material, handshake randoms — rather than in application data.

**The mechanism is real.** A TLS 1.3 handshake has genuinely free bytes that both
ends control and that no middlebox validates:
- `ClientHello.random` — 32 bytes, arbitrary.
- `legacy_session_id` — 32 bytes, arbitrary in practice.
- `ServerHello.random` — 32 bytes, arbitrary (server → client).
- Server certificate contents and extensions; session tickets; padding,
  extension ordering, GREASE values.

So roughly **~64 bytes per handshake in each direction**, inside a handshake that
looks entirely normal. This is not hypothetical: it is essentially the mechanism
REALITY uses to smuggle an authentication marker into a ClientHello — proven to
work in the wild, but used for *signaling*, not bulk data.

**One correction worth recording**, because it was stated too loosely when this
idea was first raised: the **`key_share` is NOT freely usable** if a real
handshake must complete. X25519 accepts any 32-byte string as a public key, but
if the client puts arbitrary data there it cannot compute the matching shared
secret (that would require the discrete log), so the handshake fails unless the
server special-cases it and abandons standard key agreement. The freely usable
fields are the randoms/session-id/extensions above, not the key exchange.

**Why it is killed anyway — it is a content channel, not a destination one.**
The handshake packets still travel to an IP. If the portal drops packets to our
server's address, the ClientHello never arrives and there is nothing to be
covert *inside*. Concretely: the café reset us at **TCP connect**, before TLS
began, so a handshake-field channel would not have helped there at all. It fails
the one bar that matters here, exactly like the rest of the content-evasion
corpus (REALITY, ShadowTLS, obfs4).

**And the throughput is below the floor.** One full TCP+TLS round trip per ~64
bytes is worse than the DNS carrier we already treat as the slow last resort, and
far worse under a portal that throttles.

**The one niche where it would be uniquely useful** — and the cheap way to test
it: a portal that lets a TLS handshake *complete* to our server but drops the
application data afterwards. That is unusual (portals gate at L3/L4, not
"handshake yes, data no"), but it costs almost nothing to check: run N handshakes
to our server and see whether they complete while raw data is refused. Worth one
probe line if the question ever needs closing; not worth a carrier.

**Verdict:** real, elegant, and in the same category as the covert header/timing
channels — a low-bandwidth *signaling* channel that does not beat destination
gating. Do not build. Recorded so it is not re-proposed.

### KILLED — IP-source-spoofing / reflection ("echo") carriers (physics)

Sending packets pre-auth with a **spoofed source = our server** so replies land
on our server does not work as a carrier, for a stack of independent reasons, any
one of which is fatal:

1. **The café gateway NATs.** Every outbound packet has its source rewritten to
   the gateway's public IP:port. A spoofed source is *overwritten* before it
   leaves the building, so the reflector replies to the gateway (which NATs it
   back to us), never to our server. Spoofing upstream of a NAT is pointless.
2. **Anti-spoofing (BCP 38 / uRPF)** where there is no NAT: access networks widely
   drop packets whose source isn't in the local subnet (CAIDA's Spoofer project
   measures this as broadly deployed and growing). The spoofed packet dies at the
   first hop.
3. **It's blind and unidirectional.** Even if a reply reached our server, the
   client receives *nothing* back on that path — and a VPN needs a bidirectional
   handshake (WireGuard is a round trip). There is no downlink to the client:
   inbound to an unauthenticated client is exactly what the portal blocks.

Reflection/triangular-routing is a real technique class for covert *signaling*
(ultra-low-bandwidth, e.g. idle-scan style), not for carrying a tunnel. Killed on
physics (NAT + anti-spoofing) and on the unidirectional-blind property, not on
portal policy.

## Addendum (2026-08-28): three ports the sweep never asked about

The two research waves above were thorough on *technique* and exhausted the
published field for content evasion. They were not exhaustive on *measurement*:
three TCP ports were never probed, and the highest-value one was never even
noticed as a gap.

- **TCP/53 (DNS-over-TCP, RFC 7766).** The DNS carrier is UDP-only on both ends
  and always has been. This is the gap that matters, because everything that
  throttles the DNS carrier meters **queries, not bytes**: the client's AIMD
  limiter paces in-flight queries, and a recursor's documented cap is on unique
  names forwarded per second. Café #3 confirmed the shape — `queue 256/256`,
  tail-drop, while the carrier itself showed ~27 KB/s and `err 0/s`. DNS-over-TCP
  carries 64KB messages behind a 2-byte length prefix against ~1232 usable bytes
  per EDNS0 UDP exchange, and drops most of the base32 QNAME inflation. Same
  round trips, far more payload. Whether portals that allow-list UDP/53 also pass
  TCP/53 is a **policy question, Class B above: probe, do not assume.**
- **TCP/853 (DoT-class).** Sometimes passed so Android Private DNS keeps working.
- **TCP/80.** A portal MUST do something with :80 to serve its own redirect. One
  that transparently PROXIES rather than drops it will forward a Host-carrying
  request to our origin, which is a WebSocket upgrade away from a carrier. The
  battery probed `http_connect` (an explicit proxy on the gateway) but never
  plain :80 to us.

All three now have probe lines and a server-side responder, deployed and
verified passing on an open network. The `--walled-garden` survey remains
TCP/443-only and could usefully be extended to 80 and 53.

**A correction to how this doc talks about rate limits.** "No published
technique raises a recursor's forwarding rate" is true and stays true, but it
should not be read as "the cap cannot be got around." A limiter is never
widenable and is often *escapable*, because it is always keyed on something:

| keyed on | escapable? |
|---|---|
| client (MAC/IP) | no — MAC cloning is macOS-broken and steals a paid session |
| destination / flow | yes — the multi-IP diversity lead above |
| protocol (a DNS ALG counting queries) | yes — TCP/53 may not be counted at all |
| packets/sec rather than bits/sec | yes — fewer, larger packets |

Café #3's signature (0% loss to a queue-full cliff at ~27 KB/s) fits every row,
so which key is in use is unmeasured. Three of the four escape routes run
through the new probe lines.

**Also recorded, not built: TC-bit-forced recursor TCP fallback.** On the
recursor path the ceiling caps *query rate*, not response size. An authoritative
answer with TC=1 makes the recursor re-ask over TCP/53 to us, which can return up
to 64KB in that one exchange. Downstream capacity per permitted query rises by
roughly 50x with the query rate untouched. Upstream stays capped, but an
asymmetric carrier is fine for browsing. Testable at the desk against a public
recursor, no field trip needed.

## The honest meta-point

Prevalence on the specific venues we visit is **unmeasured for every idea**, and
that is not a gap to close by more reading — it is what the cheap field probes
are for. The two cafés that left only throttled DNS are one data point. Build the
probe battery, run it at the next several portals, and let the field pick which
of UDP/443, IPv6, and multi-IP to invest in. The fall-through selection already
in the tree is what turns any leak the probe finds into a working tunnel.

## Sources
RFC 8952 / RFC 8908 (captive portal architecture; SHOULD-allow OCSP/CRL/NTP),
RFC 5771 / RFC 2365 / RFC 6762 / RFC 4795 / RFC 1001 (multicast scope, mDNS,
LLMNR, NetBIOS), RFC 2131 / RFC 3046 (DHCP relay), RFC 9298 (MASQUE CONNECT-UDP);
Meraki / Cisco 9800 / Aruba / Purple / openNDS / MikroTik walled-garden docs;
Fortinet / WatchGuard / Forcepoint "block QUIC" guides; Cisco "no HTTP/3 QUIC";
Mullvad WireGuard-over-QUIC (Sept 2025); Apple enterprise-network NTP guidance;
Nomadix Access Gateway manual; ACM NTP covert-channel study; Arch BBS hotel-wifi
WireGuard-handshake-blocking thread. Full URLs are in the six agent task outputs
for this session.
