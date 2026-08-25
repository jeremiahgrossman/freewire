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

## FOLKLORE — do not build (with the reason)

The generalizable killer: a protocol is worthless as a carrier if either (a) its
destination is a link-local / admin-scoped multicast or limited broadcast (it
physically cannot leave the segment), or (b) its only "remote" mode degenerates
to "UDP/TCP to port N," whose viability is *entirely* the port-allowlist
question above — in which case the protocol confers nothing and only the probe
matters.

- **mDNS/5353, SSDP/1900, LLMNR/5355, NetBIOS/137, DHCP options:** link-local by
  construction (RFC 5771/2365 scope, TTL-255/TTL-1 checks, limited broadcast,
  relay forwards only to its configured server). Cannot reach our server *by
  virtue of being that protocol*. Unconditional kill. Their unicast modes are
  just "UDP to port N" with no pre-auth allow-list rationale (unlike 53).
- **IPsec/IKE 500, NAT-T 4500, L2TP 1701 pre-auth:** evidence says *blocked*.
  "VPN passthrough" on hotel gateways (Nomadix) is a **NAT-correctness** feature
  (NAT-T/GRE rewriting so a tunnel survives translation once you've paid), NOT
  pre-auth authorization. Conflating the two is the biggest error here. (Note: a
  vendor default ACL sometimes lists `svc-natt`/4500, which is why we keep our
  existing 4500 carrier and *probe* it — but do not build *for* IPsec-shaping.)
- **APNs 5223 / 17.0.0.0/8:** partly real but destination-locked to Apple's
  netblock, which we cannot occupy. And portals deliberately do NOT allow-list
  Apple's captive-detection set (that would suppress the login popup they want).
  Unexploitable.
- **STUN/3478 alone:** discovers your address, cannot relay payload. Only **TURN/
  TURNS (5349/TLS)** is a real relay we could terminate — but it's venue-
  dependent (conferencing-friendly venues) and destination-scoped, so lower
  priority than UDP/443. Probe (public STUN reachability) before considering.
- **SIP/5060, RADIUS/1812, syslog/514:** SIP is ALG-mediated (collapses to a
  toy) or blocked; RADIUS/syslog are gateway→server, the client is never the
  speaker — category error.
- **SMTP 25/587, SSH 22:** the *most* documented deliberately-blocked ports on
  hotel/guest networks. Actively hostile.
- **NTP as a covert-fields channel:** if a portal runs an NTP ALG, the ceiling
  is ~240 bits/min — below the DNS floor. Only worth it if the portal passes
  *raw* UDP/123 to our server (the good case), which the probe decides. Do not
  build the covert-fields version.
- **IP/TCP header covert fields (IP-ID, TTL, DSCP, TCP options, TFO), pure
  timing channels:** bits-per-packet / bits-per-second. Below the DNS floor.
  Toys, not carriers.
- **Domain fronting, ECH, MAC-clone/ARP, refraction, Snowflake:** killed in the
  prior research doc (dead CDNs / no benefit on our IP / hostile+macOS-broken /
  need infra we can't run).

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
