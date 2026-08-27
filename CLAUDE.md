# Freewire VPN: Claude Code Build Guide

You are building **Freewire**, a free consumer VPN that works on captive portal networks (hotel, airport, and café wifi that blocks internet until you pay or log in). No other consumer VPN markets this capability.

**Company:** Freewire  
**Spec corpus:** All `.md` files in this directory are authoritative. `start-here.md` is the orientation index. `engineering-handoff.md` is your primary build guide.

---

## Current State

> **Update this section at the start of each session.**

> **Scope: single user (2026-08-22).** Build only what one person running their
> own server needs. Anything whose purpose is serving *other* people is
> deferred, not cancelled — see "Deferred until there are other users" below.
> Do not add multi-user machinery without checking that decision has changed.

- **Active phase:** Phase 4 — Privacy + reliability (Phase 2 substantially complete)
- **In progress:** nothing
- **CARRIER RE-VALIDATION DONE (2026-08-26, `testing/validate-all-carriers.sh`).**
  Ran every carrier routed against the live server on an open network: **7/7 carry
  real traffic** (wireguard/udp443/tls443/wss443/cdn_wss ~20–30 Mbps here —
  network-path-capped, not carrier-capped; the peak-baseline run measured udp443
  ~125 / cdn_wss ~54). dns + icmp are the ~72 Kbps interactive floor and
  **overflow under whole-machine routed load** (tail-drop, queue full) — which
  RE-VALIDATES the café finding and the documented DNS marginality, not a
  regression. The harness retries a cold-start CONNECT-FAILED flake (a wireguard
  false-fail in the first run reproduced then passed on retest). Assumptions hold.
  A new `--walled-garden` probe (in `cafe-run.sh`) surveys which destinations a
  portal permits, to learn what fronting could work where ours did not.
- **FIELD TEST DONE (2026-08-25, café #2). Result: hard destination-gated captive
  portal — Freewire is SUPPORTED there via DNS.** The probe battery (run from
  `testing/cafe-run.sh`, which is self-contained because a captive portal cuts
  the Claude session's own internet) found: TCP/443 raw + WSS + **the CloudFront
  edge** all `[SYN-RST]` (connection refused on the SYN — destination-gated at L4,
  the café's walled garden does not include our edge); UDP/443 + UDP/123 dropped;
  no IPv6; and **DNS/53 server-direct OK** (188ms handshake). So this café blocks
  every fast carrier by destination but leaves DNS open, exactly the case the DNS
  tunnel exists for. `cdn_wss` did NOT rescue it (edge not allow-listed here) —
  the CDN hypothesis holds for FQDN→frozen-IP portals but not this one.
- **Desync is scoped and NOT the answer here** (`DESYNC-CARRIER-SPEC.md`): a
  `[SYN-RST]` gives desync no handshake to manipulate; it needs a `[reset]`
  (post-handshake SNI reset), which no café has shown. The probe now splits
  `[SYN-RST]` (destination, desync futile) from `[reset]` (content, desync
  viable) from `[timeout]` (hard drop) so this is decided by measurement.
- **PENDING FIELD DATA (the one open thread): is DNS *usable* here, or does it
  just handshake?** Launch the Freewire app on the café wifi (it falls through to
  DNS), then run `testing/cafe-measure.sh` (read-only: egress, latency,
  throughput, a real page load) and read the file back. Expect ~72 Kbps (the DNS
  floor); the question is usable-slow vs unusable-slow. No client change raises a
  throttled-DNS ceiling (research-confirmed), so this grades the experience, it
  does not gate a build.
- **Every field test runs the full carrier battery.** `testing/cafe-run.sh`
  surveys ALL 8 shipped carriers so a portal's support map is complete: the
  rootless probe battery covers 7/8 (wireguard, http_connect, tls443, wss443,
  cdn_wss, udp443, dns — plus the udp123 candidate and IPv6), and the rooted
  `probe-transports.sh` half (real WG handshake per carrier, if you give it sudo)
  covers all 8 including `icmp_udp`, which needs raw sockets and so cannot be in
  the rootless battery. `http_connect` was added to the battery 2026-08-26 (it
  uniquely probes the LOCAL gateway for a CONNECT proxy, not our server, so it had
  been absent). The `--walled-garden` line then maps which third-party
  destinations the portal permits, to learn what fronting could work.
- To re-survey any café: `testing/cafe-run.sh` (self-contained, writes a /tmp
  file). The raw one-liner is
  `tunnel/freewire-tunnel --probe-battery --server 52.203.246.145 --insecure --cdn d29cubp361kpm8.cloudfront.net`
  — rootless, needs no registered peer, works cold.
- **The CloudFront distribution EXISTS and the fronted path is VERIFIED WORKING**
  (2026-08-24): id `EFJL255K0RTR`, hostname **`d29cubp361kpm8.cloudfront.net`**,
  logging off. `--cdn` probe reaches the origin through CloudFront and completes a
  WebSocket end to end (`CDN WebSocket/443 OK via edge …`). Three bugs were found
  and fixed getting there, all desk-caught before the café: (a) the tls443
  listener advertised `h2` via autocert's ALPN → CloudFront spoke HTTP/2 and the
  preface was misread as a raw frame (fixed: `NewTLS443Server` forces http/1.1
  ALPN); (b) CloudFront sends its DISTRIBUTION hostname as the origin SNI, so the
  cert handler served the self-signed cert → CloudFront rejected the origin
  (fixed: unrecognized SNI now serves the real ACME cert for our domain, since a
  CDN validates against the origin domain it is configured with, not the SNI it
  sent); (c) our uTLS client offered `h2` to CloudFront's viewer side (fixed at
  the distribution: HttpVersion=http1.1, since this distribution exists only to
  carry our WebSocket). So the café probe tests address-gating directly:
  ```
  tunnel/freewire-tunnel --probe-battery --server 52.203.246.145 --insecure --cdn d29cubp361kpm8.cloudfront.net
  ```
  Teardown when done (idle is ~free, so no rush): disable then
  `aws cloudfront delete-distribution --id EFJL255K0RTR --if-match <ETag>`.
- **Carriers pre-built for the field (2026-08-25):** `udp443` (WireGuard straight
  over UDP/443 — the fastest carrier, ~125 Mbps measured, no TCP-over-TCP; server
  dispatches the port between the WG relay and the magic probe) and throughput
  measured across the 443 family: **cdn_wss ~54 Mbps** (CloudFront buffering is
  NOT fatal — kill criterion not met), wss443 ~22–50, udp443 ~125. See
  `testing/throughput-test.sh` and `FIELD-TEST-CONTINGENCIES.md`. The probe
  battery now also classifies a block as RST (stateful/desyncable) vs timeout
  (hard ACL). **Server is IPv6-ready** (provisioned + advertises endpoint_host_v6,
  codified in launch-aws.sh); the client `wireguard6` carrier's leak-safe routing
  is the one piece left, deferred to a v6 network — `IPV6-CARRIER-REMAINING.md`.
  Eight carriers ship: wireguard, udp443, http_connect, tls443, wss443, cdn_wss,
  dns, icmp_udp.
- **The `cdn_wss` CARRIER IS BUILT and verified end to end** (routed run 6/6
  TUNNELLED through CloudFront, edge IP 3.163.157.x pinned outside the tunnel by
  the carrier-peer-pinning `01d9780`). It sits after `wss443` in speed order and
  is skipped unless the server advertises `cdn_host`. **One operator step remains
  for the APP to use it automatically:** set `cdn_host` in the server config
  (`/var/lib/freewire/freewire-server.json` → `"cdn_host":
  "d29cubp361kpm8.cloudfront.net"`, then `systemctl restart freewire`). Until
  then the probe tests it via `--cdn` and the routed test via
  `FREEWIRE_CDN_HOST`; the app carrier reads it from the config API.
- **Field prep before the café (user actions, not desk work):** (1) reboot the
  Mac to clear stale `utun` interfaces (the app cache in UserDefaults and the
  server peer on AWS both survive a reboot). (2) To also run `probe-transports.sh`
  at the café, run it once on the hotspot first (its /tmp peer cache is cleared by
  a reboot; the battery is not).
- **CDN-fronted-carrier groundwork is DONE and verified; only the distribution
  is uncreated.** ACME is live on the server: `origin.pinghop.net` (A →
  52.203.246.145, Cloudflare DNS-only) serves a real Let's Encrypt cert, and the
  IP path still serves the self-signed cert to no-SNI clients (the certs.Build
  fix, `a2f4140`, with tests — enabling ACME without it would have locked out
  every IP client). TCP/80 is open for the challenge. The `freewire-deploy` IAM
  user has the CloudFront policy (`deploy/cloudfront-iam-policy.json`, attached
  inline). `deploy/setup-cloudfront.sh` passes preflight; running it is the one
  remaining create step (idle CloudFront is ~free — per-request/GB, no hourly
  charge — so create it whenever, no rush). Then carrier build items #2–#7 in
  `CDN-FRONTED-CARRIER-SPEC.md` (item #2, carrier peer pinning, is already done
  in `01d9780`).

### Session 2026-08-24 (carriers + measurement)

The through-line: the café blocked us by **destination**, so the work was (a) a
selection loop that keeps trying until something actually carries traffic, (b) a
carrier that looks like the web, and (c) instrumentation to measure a portal
instead of guessing.

1. **Traffic-verified fall-through selection** (`3bae110`) — selection judged each
   rung by whether WireGuard *handshaked*, committed to the first that did, and
   gave up if routing then found the tunnel carried nothing. That is why the café
   stopped at DNS and never tried ICMP. Now establish→route is a fall-through
   loop: establish over the fastest carrier that handshakes, route, verify egress;
   if it carries no traffic, restore the machine, exclude that carrier, fall
   through to the next-fastest. "First to handshake" → "fastest that actually
   carries traffic." Fires ONLY when egress verify fails, so a normal network
   behaves exactly as before. `establishTunnel` takes an `excluded` set. Observed
   working live during routed testing (it handled a transient egress failure
   gracefully instead of stranding the machine).
2. **WebSocket-over-TLS-443 carrier** (`5db4bec`) — new `wss443` rung: WireGuard
   inside WSS binary frames on the **existing** 443 port, one cert, one listener.
   The server discriminates raw-vs-WebSocket by peeking ONE byte inside TLS (a raw
   frame starts with a small uint16 length byte; an upgrade starts `G`). wsConn is
   a transparent `net.Conn`, so `runLocalProxy`/`bridgeToWireGuard` are unchanged.
   Hand-rolled RFC 6455 subset, no new dependency; both codecs tested against the
   **RFC's own published vectors** (not against each other). Client verifies
   `Sec-WebSocket-Accept`, so a portal answering with its login page fails at the
   handshake and the chain falls through. **Verified live against the deployed
   server: real WireGuard handshake over wss443 (495ms).**
3. **Probe battery** (`3a032f6`, `--cdn` line `08627d5`) — `--probe-battery`
   surveys every carrier plus the UDP/443, UDP/123 and IPv6 candidates, each
   against OUR server, rootless and non-routed. Backed by a server-side
   **ProbeResponder** (`internal/transport/probe.go`): magic-gated, rate-limited,
   and **non-amplifying** (reply is smaller than the accepted request floor), so
   the open ports are not an NTP or QUIC service. `--cdn` adds the direct-vs-CDN
   comparison that isolates *address* gating from *port* gating.
4. **Carrier peer pinning** (`01d9780`) — `setupRouting` pinned only the
   *configured* server address; with anything in front (a CDN edge IP) the
   carrier's real peer went unpinned, so the split-default route would swallow the
   carrier's own connection and loop it into the tunnel — the "connected but
   carries nothing" failure this project already lost weeks to. Now pins
   `transportConn.RemoteAddr()` too: correct for every carrier, a no-op for direct
   ones. Verified with four routed runs (3× 6/6 TUNNELLED) plus an A/B against the
   pre-change binary rather than assuming it was a no-op.
5. **Server redeployed** (`bad6930`) — the live server now runs the WSS carrier and
   the probe responder. **Pinned key unchanged** (`4MZT9TPG…S2DA=`), so existing
   client pins hold. Fixed a latent deploy bug: security-group port rules lived
   inside the "group does not exist yet" branch, so a group that already existed
   never gained rules added later — a new listener would deploy, bind, and be
   silently unreachable, which the client reports as "blocked" and is
   indistinguishable from a portal blocking it. Rules are now idempotent per run;
   added udp/443 + udp/123.

**Research (two rounds, ~16 agents): the published field is substantively
exhausted for a single operator vs destination allow-listing.** See
`TRANSPORT-RESEARCH-2026-08-24.md` and `PORTAL-CARRIER-IDEATION-2026-08-24.md`.
The modern circumvention corpus targets *content/DPI* evasion on an
already-routable path, so REALITY/ShadowTLS/Hysteria/obfs4/Shadowsocks all still
terminate on our IP and die at the same drop. Against destination gating there
are two structural answers: **reach a permitted destination** (CDN-front our own
server — specced in `CDN-FRONTED-CARRIER-SPEC.md`, items #1 and #2 built) or
**desync a stateful portal** (Geneva-class, only if the portal is inline-stateful
rather than a hard L3 ACL). Killed with reasons: link-local protocols (cannot
egress — physics), IPsec pre-auth ("passthrough" is NAT-correctness, not
authorization), APNs (Apple's netblock), covert header/timing channels (below the
DNS floor), and **IP-source-spoofing/reflection** (the gateway NATs over the
spoofed source, BCP38 drops it otherwise, and it is blind/unidirectional).
Ranked next builds if the field supports them: **UDP/443 QUIC-shaped** (near
line-rate, no TCP-over-TCP, block-QUIC is off by default, Mullvad ships it), then
**IPv6 egress**, then **CDN-fronted WSS**.

- **Earlier work (2026-08-23 field test onward):**
  1. **Fastest-transport selection** — the chain now tries carriers in speed order
     (wireguard-direct first) and picks the fastest a network allows, instead of
     stopping at the first in a fixed order. `testing/probe-transports.sh` lists
     what any network allows (non-routed, --select-only per transport).
  2. **Adaptive carrier-rate pacing (Stage 1 of backpressure)** — per-direction
     AIMD limiters (`dns_ratelimit.go`) discover the path's sustainable rate at
     ~0 loss and pace to it, no hardcoded cap. Desk repro of a throttled portal
     exists (`FREEWIRE_DNS_CARRIER_CAP`); the limiter converges to the cap at 0%
     loss.
  3. **Reconnect + path-upgrade reuse the cached peer** — both used to deregister
     and re-register via the API on every attempt, so they failed behind a portal
     (API blocked) and burned a Privacy Pass token each time. Now they try
     `connectFromCache` first (persistent peer, no control-plane call, fastest-
     first chain reaches wireguard-direct). Verified: killing the live tunnel
     auto-reconnects (`testing/verify-reconnect.sh`).
  4. **Error states CONN-5 + TRUST-4 wired** (from a background task, reviewed and
     cherry-picked to main; the same task's unrequested Stage-2 attempt was NOT
     merged — see below). CONN-5 = open-network timeout (retry once → verbatim
     copy); TRUST-4 = issuer-key-changed, fail-closed. TRUST-4 detection verified
     live (changed pin → freewire-tokens exit 3 → TokenStore hard-block).
  5. **Test + release tooling:** `testing/regression.sh` (one-command core gate:
     build, -race tests, app build, live transport probe), `testing/verify-
     reconnect.sh`, and `scripts/release-macos.sh` (cert-ready: Release archive →
     **embed the Go helpers into the .app** → sign+notarize when a Developer ID
     exists, else unsigned dry run). The dry run caught that the Release bundle
     was missing freewire-tunnel/freewire-tokens (the app has no repo-path
     fallback when distributed); now fixed and DMG verified (12M, mounts).
- **Stage 2 candidate exists but is NOT merged, and FIELD-TESTED as ineffective:**
  branch `claude/vibrant-bassi-823b06` has a delegating-`conn.Bind` backpressure
  implementation (well-engineered, fast paths untouched). Run at a real café
  (2026-08-24): backpressure engaged for real (block, no tail-drop) but HTTPS
  still BLOCKED 0/10 on server-direct — same outcome as main. Its "2/2 TUNNELLED"
  claim did not reproduce (desk 0/3, field 0/10). **Do not merge.** Two of two
  cafés block every faster carrier and leave only DNS, but the café's DNS-to-
  server rate is the real ceiling and no client-side change raises it. See
  `DECISIONS.md` DNS-CARRIER-BACKPRESSURE for the full field result.
- **Why the café's 443 failure was misread** (`TRANSPORT-RESEARCH-2026-08-24.md`):
  the logged `443 connection refused` reads as "blocks 443" but portal gateways
  routinely pass 443 that completes an HTTP Upgrade (looks like a website) while
  resetting a raw uTLS session to an arbitrary IP — exactly our TLS/443 carrier.
  That reading is what produced the WSS-443 carrier above. The DNS-throttle
  literature also independently confirms the Stage-2 deferral: no technique
  widens a recursor's forwarding cap, so the way out of a throttled-DNS-only café
  is a different carrier, not a better DNS carrier.
- **Deferred (deliberate, see `DECISIONS.md` DNS-CARRIER-BACKPRESSURE):** Stage 2,
  true backpressure. Stage 1 keeps the carrier clean but a throttled pipe's queue
  still overflows and starves the active flow. The fix is a custom wireguard-go
  `Bind` that blocks WG's send — a core refactor. Deferred because fastest-
  transport selection already routes around throttling wherever a faster carrier
  exists, so the unfixed case (throttles DNS AND blocks every faster carrier) is
  rare and field-unconfirmed. When picked up: DNS-only device + custom bind,
  leave the fast paths untouched. Verifiable at the desk via the repro.
- **Blocked on:** a Developer ID certificate, for `FreewireHelper` and for signed/notarized distribution.

### DNS routed: characterized (2026-08-23) — two carriers, one fast, one minimal

| portal allows | carrier | result |
|---|---|---|
| outbound port 53 | server-direct (`dns_resolver` = server:53) | **HTTPS works, ~71 KB/s, ~372 q/s, 2/3 curl tunnelled** |
| only its resolver | recursor / multi-recursor spread | packets flow (ICMP 0% loss spread) but **HTTPS won't establish** |

The public-recursor ceiling is fundamental, not a bug: a recursor rate-limits
forwarding UNIQUE (uncacheable) names to our auth server to ~14/s, so upstream
caps near ~50 pkt/s even spread across four recursors (`Config.DNSResolvers`
round-robins the carrier; every resolver is pinned outside the tunnel). Under
whole-machine load the send queue then overflows and a TCP handshake can't
survive. **Admission-control via queue depth was tested and does NOT help** — a
shallow queue (AQM) drops sooner but the cap is the carrier rate, not bufferbloat;
`FREEWIRE_DNS_QUEUE` left at 256 (proven for server-direct). Reaching HTTPS-viable
throughput would need ~25+ recursors, impractical. So: **server-direct is the real
DNS path; the recursor path is a minimal fallback** (tiny/interactive packets).

### FIELD TEST (2026-08-23, café captive portal) — premise holds, next work is backpressure

First real-portal run. What the café did, from the tunnel's own logs:

- **Blocks HTTPS to our server:** `tls443: dial 52.203.246.145:443: connection
  refused` (active reset, not a timeout) → chain fell to DNS. HTTP CONNECT n/a.
- **Allows outbound 53 to our server:** the DNS transport selected **server-direct**
  on its own (the new default strategy), route-check clean.
- **But rate-limits DNS to our server to ~72 Kbps**, cleanly: a non-routed
  `--dns-throughput` to `52.203.246.145:53` held 72 Kbps avg (48–88), **0% loss**
  over 15s at concurrency 8. At the client's normal concurrency 32 it burst to
  71 KB/s then the café throttled it → degrade → the egress self-check tore it
  down.
- **Lowering client concurrency to 8 did NOT rescue it:** carrier went 0% loss
  (`err 0/s`) but the send queue still overflowed (`tail-drop 100+/s, queue
  256/256`) — the whole machine (background + WG retransmits) offers far more than
  a ~72 Kbps pipe, and with no backpressure across the UDP bridge the excess is
  tail-dropped indiscriminately, including the egress probe's packets, so it tears
  down. Concurrency is not the lever.

**Verdict:** the architecture's premise holds — a real captive portal blocks 443
and lets server-direct DNS through, and the fast carrier is reachable. The gap is
that a portal-throttled carrier (~72 Kbps here) can't be made usable by the
current send path, which has no way to pace WireGuard's offered load down to the
measured carrier rate. **The next real work is carrier-rate congestion control /
admission control on the DNS send path** (pace/rate-limit WG ingress to the
carrier's proven sustainable rate so the queue stops overflowing), NOT more
concurrency or queue tuning — both were tried in the field and neither is the
lever. This is a substantial change, deferred to a focused session. Where a
portal does NOT throttle (desk server-direct: 71 KB/s), it already works.

### DNS routed: SOLVED server-direct (2026-08-23)

The months-long "routed DNS carries no traffic" failure is root-caused and fixed
for the server-direct path. The break was never the WireGuard layer: it was a
chain of send-path + carrier issues, fixed in order —
1. send-path congestion collapse (drop-on-full) → bounded queue + worker pool;
2. carrier resolver not pinned → `setupRouting` pins the carrier's actual
   resolver, confirmed by `route-check` (0/1+128.0/1→utun, server+resolver→en0);
3. downstream throttled to ~1 packet/response → server packs multiple packets per
   DNS response (length-prefix framed, EDNS0-budgeted), client splits them;
4. serial polling → concurrent poll pool with a per-poll nonce (defeats recursor
   caching), AEAD decrypt moved off `rxMu`;
5. pollers starving senders → separate send/poll concurrency budgets (24/8).

**The last wall was the public recursor**, not our code: 1.1.1.1 rate-limits
forwarding UNIQUE names to our auth server to ~14/s, so routed traffic saw ~75%
loss (a single ICMP echo occasionally squeaked through — the tell). Server CPU
sat at 0.5% during a routed run, proving the queries never arrived. Bypassing the
recursor (carrier → auth server directly): ICMP loss 75%→25%, curl 2/3 tunnelled,
downstream 13–71 KB/s (~568 Kbps), ~372 q/s. All tuning is env-overridable
(`FREEWIRE_DNS_SEND_CONCURRENCY`/`_POLL_CONCURRENCY`/`_POLL`/`_WORKERS`/`_POOL`).

**Autonomous routed testing now exists** (`testing/routed-test.sh`): forces one
transport with routing, an ICMP round-trip probe + curl egress samples, snapshots
pinned routes and send/downstream counters, and a **detached 45s hard-deadline
watchdog** force-restores routing so a run can never strand the machine (it did
once). Uses the passwordless-sudo rule + `--force-transport` + `--route-no-verify`
(installs routing but skips the egress self-check and suspends the health
watchdog, so a slow-but-working tunnel can be measured). `FREEWIRE_DNS_RESOLVER`
picks the carrier resolver (unset = server-direct). Server redeploys with
`deploy/launch-aws.sh` (idempotent; preserves the pinned key).

### Field findings (2026-08-22, Starbucks + desk)

- **Captive-portal connect is now wired end to end.** The client caches the
  control-plane state (server key, ports, tunnel IP, peer token, DNS zone) after a
  successful connect, and when a portal blocks the API it falls back to the cache
  and comes up over the DNS tunnel. Peer registration is now **persistent for
  single-user** (disconnect/quit no longer deregister), or the cache goes stale.
- **The DNS tunnel carrier is fine.** Sustained throughput is steady ~409 Kbps
  through Starbucks' own resolver and ~496 Kbps through 1.1.1.1, both 0% loss —
  the resolver does not throttle it. Upstream multi-fragment reassembly works too
  (`--dns-datatest`: 1400B/12-frag accepted), though sequentially — a large packet
  takes ~1.66s upstream because `sendPacket` sends fragments one round trip at a
  time (pipelining them is the obvious perf win, deferred as a risky core change).

### DNS routed failure — localized (2026-08-22 desk)

A routed test (config7, real routing) still carried no traffic. What is now ruled
OUT: the resolver (doesn't throttle), the server forwarding (TLS/443 gives real
egress right now), upstream carrier multi-fragment (`--dns-datatest` passes), and
the client's downstream-delivery logic (reads correct on inspection). Two things
also fixed along the way: the egress probe was too weak (a bare TCP dial passed a
tunnel that carried no real data — now a real TLS handshake, `probeCarriesData`),
and the café diagnostic's 3s curl timeout mis-read a slow tunnel as dead (now
12s). What's LEFT: the WireGuard layer over the DNS carrier under real traffic —
the probes send garbage WG drops, so a real WG handshake over DNS is still
unexercised at the desk. Needs live server `tcpdump`.

**Live `tcpdump` result (2026-08-22, home wifi):** during a routed config7 DNS
connect, the server's WG tun (`utun`) saw ZERO outbound client packets (only 7
stray inbound RSTs from prior NAT state); ens5 egress to 1.1.1.1 was 0 packets.
The client log: `egress did not sustain: best streak 0/2 to 1.1.1.1:53: context
deadline exceeded` — the TLS-handshake probe completed none. So **WireGuard-over-
DNS carries no routed traffic**: the carrier works (`--dns-datatest`), the server
forwards (TLS/443 gives real egress), but nothing the app sends through WireGuard
reaches the server's WG tun. The break is the WG↔DNS integration (client bridge
`lp.ReadFrom → sendPacket`, or the WG handshake not completing over the carrier).
Note transport *selection* only checks the carrier opened, not that WG works over
it — so DNS is selected and then fails the real-traffic probe.

**ROOT CAUSE FOUND (2026-08-22): send-window congestion collapse.** A client-side
run-loop trace (routed, forced DNS, machine quiet) shows: WG handshake completes,
then wireguard-go hands data packets to the DNS sender (`wg->dns: read 96/112
bytes`), but the send window (`dnsWindowInit=8`, grows only on success) fills
instantly and drops the vast majority (`WINDOW FULL, dropped`); only a trickle
gets through (`sent, downstream=80`), and WireGuard retransmits the dropped ones,
flooding the window further. The handshake survives only because it is the first
packet, before the window fills. The carrier itself has capacity (400–500 q/s in
`--dns-throughput`) and fragment sends are now pipelined, so the bottleneck is the
packet-rate window + its AIMD (drops don't grow it, so under a burst it can't
recover). **FIX (next, careful): redesign the DNS send path's congestion control**
— size the in-flight window to the carrier's proven capacity and/or add a real
rate limiter, and damp WireGuard's retransmit storm; naively raising the window
may worsen the collapse, so this needs RTT/throughput-based sizing and testing,
not a constant bump. Note the UDP socket pool also caps reusable sockets at 8
(`udpPoolPerServer`), matched to the window of 8 — raising the window alone would
churn sockets (dial+discard) and likely worsen it, so window, pool, and the AIMD
must move together. Everything else in the chain is proven working. Older notes
below.

**WG verbose over forced DNS (2026-08-22, config7 locked): the handshake
COMPLETES.** `Sending handshake initiation` → `Received handshake response` in
~1s over the DNS carrier (verified with `--skip-egress-check` now routing WG's
log to stderr; config7 confirmed blocking direct-to-server so DNS was forced). So
the handshake is not the bug. Full picture: the DNS carrier works packet-by-packet
in isolation (handshake both directions; single packets up to 1400B via
`--dns-datatest`) but **collapses under real concurrent routed load** — the routed
test moved 0 packets to the server tun. This is a **congestion/throughput
problem, not a correctness bug**. Prime suspect: `sendPacket` ships a packet's
fragments SEQUENTIALLY (one DNS round trip each; a 1400B packet = ~1.66s), so the
machine's traffic rate swamps the carrier and packets drown. NEXT: (a) pipeline
fragment sends within a packet (concurrent, bounded by the window; handle the
piggyback coming on whichever fragment completes the packet, and loss) — the
clear perf fix, but a careful core change; and (b) a routed test with background
apps quit, to confirm a single request works when the carrier isn't swamped
(isolating congestion from any residual data-plane bug).

Diagnostic tools built: `--probe-battery` (the one to reach for at a portal:
surveys every carrier against our server, rootless, non-routed), `--wss-probe`
(raw-443 vs WebSocket-443 side by side), `--dns-probe`, `--dns-throughput
[--duration]`, `--dns-datatest`, `--icmp-probe`, `--select-only`,
`testing/probe-transports.sh` (real WG handshake per carrier; café-capable via a
cached peer), `testing/cafe-diagnostic.sh`.
- **Two reliability bugs fixed and verified:** (1) the server's NAT MASQUERADE
  vanished on instance stop/start (netfilter-persistent was a no-op, iptables-
  persistent never installed) — every "connected but no traffic" failure traced
  here; now re-applied on each service start via `ExecStartPre` (`deploy/freewire-nat.sh`),
  verified surviving a reboot. (2) false Protected — the tunnel now requires
  sustained egress (2 spaced probes) on the DNS/ICMP transports before claiming
  protection.
- **Known residue:** the dev Mac accumulated ~9 stale `utun` interfaces during the
  session; a reboot clears them. Do this before the next real-portal test.

> **Do not test the DNS or ICMP transports with routing on a machine in use.**
> Every lookup on the host then goes through a 500 Kbps tunnel at 5-10s each,
> and the machine becomes unusable — including any agent session running the
> test. This was misread as a crash twice. See `testing/README.md`.
> Repair with `sudo tunnel/freewire-tunnel --restore`.

**Scripted end-to-end runs:** `testing/connect.sh` brings the tunnel up against
the live server and `testing/disconnect.sh` tears it down and asserts the
machine was restored (routes, resolvers, IPv6, state files, egress). Use these
before trusting a change. Every serious defect found on 2026-08-21/22 — a false
"Protected" over unrouted traffic, a DNS leak to the ISP, a certificate pin that
would have locked the client out on the next deploy — passed every static check
and appeared only when the product actually ran.

**Both Privacy Pass decisions are made** (2026-08-22), recorded in
`DECISIONS.md`:

1. **Token expiry** — tokens now carry a coarse expiry in whole UTC days inside
   the signed message: `type(2) || expiry(4) || nonce(32) || signature(256)`,
   294 bytes. Validity is 30 days, inside the spent store's retention. The
   issuer signs blindly and cannot set the value, so the client does and the
   server refuses anything over-dated at redemption. CRYPTO-09 (tokens bind to
   no key or origin) stays open — the key-epoch option that would have closed it
   was judged more machinery than the problem needs.
2. **Unauthenticated DH on the DNS and ICMP handshakes** — deferred until
   Freewire serves people other than its operator. An active on-path attacker
   gains transport framing, not traffic: WireGuard inside is authenticated by
   the pinned server key. See `DECISIONS.md` for the fix when it is picked up.

### Dev environment (as of 2026-08-22)

The server runs on **AWS**, not locally. Local container and VM runtimes all
fail the same way: they NAT their own guests but will not forward a third
subnet, so tunnel egress cannot be tested against them. See
`testing/README.md`.

| | |
|---|---|
| Server | `52.203.246.145` (Elastic IP, `t4g.small`, us-east-1). Deploy with `deploy/launch-aws.sh`, remove with `deploy/destroy-aws.sh` |
| Ports | API `8080` (HTTPS), TLS+WebSocket `443/tcp`, DNS `53`, ICMP/UDP `4500`, WireGuard `51820`, probe responder `443/udp` + `123/udp`. `deploy/launch-aws.sh` opens all of them idempotently on every run |
| Trust | The client pins the server's WireGuard public key. Set it with `defaults write com.freewire.vpn.Freewire pinnedServerKey '<key>'`; `provision.sh` prints it |
| Build + run the app | `xcodebuild build -project macos/Freewire/Freewire.xcodeproj -scheme Freewire -configuration Debug CODE_SIGNING_ALLOWED=NO`, then run the product directly to see its stderr |
| Helpers | `cd tunnel && go build -o freewire-tunnel ./cmd/freewire-tunnel && go build -o freewire-tokens ./cmd/freewire-tokens`. Debug builds fall back to these paths |
| Tests | `go test -race ./...` in `server/` and `tunnel/`; `macos/Tests/run.sh` for Swift |

**Verified end to end against AWS (2026-08-21, from the real app):** real egress
(public IP moves from the ISP to the server and back), 166 Mbps on TLS/443
against a 50 Mbps target, 108 ms RTT, all four transports reaching ready, the
full Privacy Pass exchange — a signature the server never saw unblinded, proof
of work solved, first redemption 201, replay 402, and replay still 402 after a
server restart — the issuer key pinned on first use with a changed key refused,
the server's certificate identity stable across restarts, and DNS resolving
through Cloudflare via `utun6` rather than leaking to the local resolver.

Two defects were found only by running the app, having passed every other
check: a leftover `skipRouting` preference produced a green "Protected" while
every packet left in the clear, and DNS leaked to the ISP's resolver while
traffic was tunneled. Prefer an end-to-end run over another test pass when
deciding what to trust.

**Phase 2 configs:** 0, 1, 2, 3 pass. 4, 5 and 6 are ready to run and need a
password-prompting `sudo`; see `testing/README.md` for what each needs and the
safe-combination table.

Config 5 was recorded as "will report CONN-3 rather than CONN-2b, a documented
bootstrap gap, not a regression". That was wrong, and preparing to run it is
what surfaced the reason: the portal probe only ran after the transport chain
had exhausted every path, which requires getting past registration. On a real
captive portal the API is blocked too, so registration fails first and the probe
never ran — the user was told "Freewire's servers are unreachable" while sitting
in front of a login page. Fixed; the probe now runs when the API is unreachable.
Config 5 should now show CONN-2b, and a real portal should show CONN-2a.

**Audits:** three runs. The third audit's verification budget ran out after
confirming eight findings; its remaining 209 unique candidates were adjudicated
by hand afterwards. See `AUDIT-3-ADJUDICATION.md` for the disposition of every
one. Summary: most were already closed by the first two audits' fixes, and the
security-relevant remainder is fixed. The reliability and UX remainder is
recorded there as open with a reason, not silently dropped.

The third audit's confirmed set, and what closed each:
- Privacy Pass issuer key was fetched with no pinning, so an issuer handing each
  client its own key could identify that client at redemption with every
  signature still verifying. Now pinned trust-on-first-use (`--issuer-pin`), and
  the advertised key id is checked against the key served.
- Token issuance was unmetered, which made Privacy Pass ceremonial. Now capped
  by a global bucket (see above).
- The ICMP handshake had no half-open ceiling; the DNS server's bound was never
  carried across. Now 256 pending with a 10-second TTL.
- DNS fragment reassembly was first-writer-wins, so one fragment forged from the
  cleartext query name destroyed any multi-fragment packet. Conflicting
  fragments are now retained and the AEAD tag picks the real one.
- Tokens were stored in plaintext under a file-protection option that does
  nothing on macOS. Now encrypted under a Keychain-held file key.
- Token-rejection copy was invented; `error-states-spec.md` now specifies it as
  TRUST-3 and TRUST-4.

**Network intelligence is deliberately not built.** The spec stands
(`PRD.md` §6.9) and the implementation is declined: reconnect now remembers the
last working transport, so the crowdsourced hint only helps on a first
connection to an unseen network, while a BSSID hash is a location identifier
that public wardriving databases can reverse by lookup. See
NETWORK-INTELLIGENCE in `DECISIONS.md`. Do not add the preferences toggle while
this stands — a toggle for a feature that does nothing is its own false claim.

### Deferred until there are other users

None of these matter for one person on their own server. They become blocking
the moment anyone else connects.

- **Abuse posture.** A free VPN with no accounts attracts spam and infringing
  traffic; complaints reach the host, and hosts terminate VPN operators.
- **Capacity.** 253 peers per server, one /24. Fine for one device.
- **Hosting economics.** EC2 meters egress at $0.09/GB, which is a rounding
  error for personal use and ruinous for a free service. See `deploy/COSTS.md`.
- **Server dashboard, QR config generation** (`server-dashboard-api-spec.md`) —
  these exist to enrol *other* devices.

### Known gaps that matter at any scale

- **PRIVACY-1 (DoH-unreachable warning) is detected but not surfaced.** An
  error-copy verbatim audit (2026-08-26, every `error-states-spec.md` string vs
  the app) found ONE active, undeferred gap: when the DoH resolver is unreachable
  the client falls back to the network's resolver, and the tunnel helper logs it
  loudly (`dohNotice`, `tunnel/.../doh.go`) — but the macOS panel never shows the
  spec's soft warning "Reduced privacy: DNS not encrypted" / "Freewire couldn't
  reach its secure DNS resolver…". Building it is a feature (parse the helper
  signal → panel warning → the spec's 60s auto-retry/auto-dismiss), not a copy
  fix, so it is flagged not built. Every OTHER unbuilt spec string is legitimately
  deferred: iOS states, Phase-3 self-hosted/QR/AWS-deploy copy, Sparkle UPDATE-1/2,
  the post-helper kill-switch "traffic is blocked" variants, and the System
  Extension PERM-3/4 copy (the macOS client uses utun + SMAppService, not a System
  Extension, so that copy does not match the shipped architecture). **All
  implemented active states are verbatim** — no paraphrased or invented copy —
  so architecture rule 4 holds; many render as a label + caption split, which a
  flat string search misses but concatenates to the exact spec sentence.
- **`FreewireHelper` is written but cannot install.** `SMAppService` requires a
  Developer ID and this machine has no signing identity. The rule generation is
  done and tested (16 assertions); the packaging is not. The UI does not claim
  the kill switch — see `error-states-spec.md` §"Interim". **Resolved:**
  `SMAppService`, and **fail closed**.
- `PathUpgradeManager` returns false for the DNS and ICMP paths; probing either
  needs a full handshake.
- The kill-switch cluster is real and untouched: the helper replaces the whole
  pf ruleset instead of loading its anchor, `release()` runs `pfctl -F all`,
  `isEngaged()` infers state from a file, and `sanitize()` strips hostile
  characters rather than rejecting them. All of it is blocked behind the
  Developer ID, because none of it can be tested without installing the helper —
  and fixing untestable pf code is how the wifi broke earlier in this project.
- ECH is not implemented, and is worth less than it appears. It could only ever
  cover Freewire's *own* TLS connection to the server, to stop a portal blocking
  by hostname — and on the current IP-addressed deployment that ClientHello
  carries no SNI at all, confirmed by capture. It cannot touch the SNI the
  server sees from user traffic: that handshake is end to end between the
  browser and the site. See WHAT-THE-SERVER-CAN-SEE in `DECISIONS.md`.
- DoH resolvers are now configurable (`Config.DoHEndpoints`, https-only,
  failover in order), so the hardcoding is gone. The *default* is still a
  Cloudflare failover pair — one operator, a deliberate non-choice on cross-
  operator diversity, since spreading queries across operators is a privacy call
  for the operator to make, not a baked-in default.
- `captive-portal-testing-guide.md`'s `proxy.py` listing is broken — its relay
  threads never iterate. `testing/proxy.py` is a working replacement.

---

## When in Doubt

When uncertain about any design decision, prefer the **more restrictive interpretation** and ask before proceeding. Do not guess at behavior that touches **privacy guarantees, cryptographic key handling, logging decisions, or error state behavior**. The cost of getting these wrong is an architectural re-work, not a bug fix.

---

## Non-Negotiable Architecture Constraints

These rules cannot be overridden by application code. Violating any of them is a critical defect regardless of the phase.

**1. Never log client IP addresses — anywhere**  
Client IPs are never written to disk, database, logs, or error tracking — not on connection, not in error handlers, not in diagnostics. This is a structural privacy guarantee (modeled on Signal's architecture), not a policy preference. If an IP appears in any log, Freewire can be compelled to produce it. The data must not exist.

```go
// Correct — strip IP before any logging
func handleConnection(conn net.Conn) {
    // Do NOT log conn.RemoteAddr() anywhere
    sessionID := generateSessionID() // opaque, not IP-derived
    log.Info("peer connected", "session", sessionID)
}

// Wrong — never do this
func handleConnection(conn net.Conn) {
    log.Info("peer connected", "ip", conn.RemoteAddr()) // NEVER
}
```

**2. Private keys never leave the device**  
The WireGuard private key is generated locally and stored in the device Keychain (`kSecAttrAccessible.afterFirstUnlock`). It is never transmitted to Freewire servers, never written to app storage, and never included in logs or error reports. Only the public key is ever sent to the server.

```swift
// Correct — store private key in Keychain only
let privateKey = WireGuardPrivateKey()
KeychainHelper.store(privateKey.rawRepresentation, key: "wg_private_key")
let publicKey = privateKey.publicKey // only this is sent to server

// Wrong — never do this
UserDefaults.standard.set(privateKey.rawRepresentation, forKey: "wg_private_key") // NEVER
```

**3. Privacy Pass tokens must remain anonymous — never link token to device**  
Tokens are issued blind: the server signs without seeing the unblinded value. After unblinding, spent tokens are submitted with no accompanying device key, IP, or session identifier. The spent token hash record on the server cannot be linked to any device. Do not add any identifier to the redemption request.

```swift
// Correct — token redemption carries only the token
POST /v1/peers
Authorization: PrivacyPass token="<unblinded-token>"
{ "public_key": "...", "device_name": "..." }

// Wrong — never attach device identifiers to redemption
POST /v1/peers
Authorization: PrivacyPass token="<unblinded-token>"
X-Device-ID: "abc123"  // NEVER — breaks anonymity guarantee
```

**4. Error state user-facing copy is specified — do not invent it**  
All 34 error states in `error-states-spec.md` include exact user-visible message strings. Implement them verbatim. Do not paraphrase, consolidate, or add new error messages without updating the spec. Engineers reading crash reports need to match logs to spec entries by exact message text.

**5. Session keys are ephemeral — never persist them**  
DNS tunnel and ICMP tunnel session keys are established via DH exchange per session. They are never written to disk, Keychain, or any persistent store. If the app restarts, a new handshake runs. There is no session resumption.

---

## Do Not Load in Engineering Sessions

These files are post-launch infrastructure or review tooling — not needed during active coding phases:

```
anycast-dns-infrastructure.md     (post-launch — launch uses single unicast server)
product-review-checklist.md       (QA/launch review process — not a coding spec)
```

---

## Tech Stack (Locked: Do Not Change)

| Component | Technology |
|---|---|
| macOS client | Swift, wireguard-go (userspace via utun — no NetworkExtension), pf kill switch via an `SMAppService` privileged helper (**not built yet**; supersedes SMJobBless, deprecated in macOS 13), uTLS for TLS fingerprint rotation, NWPathMonitor for network change detection, Sparkle (auto-update) |
| iOS client | **Deferred.** Will require Swift, WireGuardKit, NetworkExtension (NEPacketTunnelProvider), and Apple entitlement approval when resumed. |
| Server | Go, wireguard-go (reference userspace implementation). Runs in Docker for development — see Current State |
| DNS resolver | Cloudflare 1.1.1.1 (DoH, hardcoded — not user-configurable at launch) |
| Hosting | AWS (EC2, CloudFormation, S3, Route 53) |
| CI/CD | GitHub Actions |
| macOS distribution | Signed + notarized DMG only. Mac App Store permanently incompatible with direct utun access. |
| iOS distribution | Deferred. |

---

## Repository Structure

```
freewire/
├── macos/                  # macOS app (Swift)
│   ├── Freewire/           # App target (menu bar UI, settings, onboarding)
│   ├── FreewireHelper/     # Privileged helper (SMAppService) — pf kill switch. NOT YET BUILT
│   └── FreewireTests/
├── server/                 # Go server binary
│   ├── cmd/freewire-server/
│   ├── internal/
│   └── Makefile
└── .github/
    └── workflows/          # macOS, server build pipelines
```

No `ios/` directory and no `FreewireNE/` target — iOS and NetworkExtension are deferred. The privileged helper handles operations requiring elevated privileges (pf rules, route configuration).

---

## Key Data Model Facts

- **Identity model:** No accounts. A device is identified solely by its WireGuard public key, generated locally at first launch. No email, Apple ID, or phone number — ever.
- **Multi-device:** Each device is a separate identity. No account links them.
- **Key storage:** WireGuard keypair in device Keychain (`kSecAttrAccessible.afterFirstUnlock`). Backed up to iCloud Keychain — device restore inherits same peer identity.
- **Rate limiting:** Privacy Pass blind tokens (RFC 9576). Tokens are anonymous — server cannot link a spent token to the device that received it.
- **Spent token retention:** Hashes retained 30 days, then deleted. Not linked to device, IP, or session.
- **Aggregate metrics only:** Hourly rollups (peak connections, p50/p95 latency) per server. No per-device, per-connection, or per-IP data ever written.
- **Network intelligence:** Opt-in only (off by default). Client hashes BSSID with SHA-256 on-device before transmission. K-anonymity threshold of 5 — hints only served after ≥5 independent reports.

---

## API Conventions

- **Base URL:** `https://vpn.freewire.com/v1/` (managed server API)
- **Authentication:** Privacy Pass blind token in `Authorization: PrivateToken token="..."` header. `PrivateToken` is RFC 9577's scheme name; earlier drafts of this file said `PrivacyPass`, which names the working group rather than the header
- **Token issuance:** `GET /v1/tokens/challenge` then `POST /v1/tokens/issue` carrying `challenge` and `nonce`. Issuance is priced in proof of work because every per-caller rate-limit key is unavailable here — see `server/internal/api/proofofwork.go`
- **Issuance refused:** `429` with `PROOF_OF_WORK_REQUIRED` (no or stale proof) or `RATE_LIMITED` (global budget exhausted)
- **Redemption body:** `public_key` only. `device_name` and `client_version` were removed: any caller attribute alongside a token is a handle the issuance half can be correlated against
- **Privacy Pass error:** `402 Payment Required` for `TOKEN_INVALID` or `TOKEN_SPENT` — not 401, not 429
- **Rate limit abuse:** `429 Too Many Requests` only for non-token-based abuse signals
- **At capacity:** `503` with `PEER_LIMIT_REACHED` on `POST /v1/peers` — surfaces CONN-4 to user
- **Error format:** `{"error": {"code": "SCREAMING_SNAKE_CASE", "message": "..."}}`
- **Server dashboard port:** `8443` (open to `0.0.0.0/0` by default in CloudFormation — admin should restrict to their IP)

---

## Fallback Chain Timeouts

The protocol fallback chain has a hard 10-second budget:

| Path | Timeout | Notes |
|---|---|---|
| HTTP CONNECT | 2s | TCP connect + CONNECT method response |
| TLS/443 | 3s | TCP + TLS handshake + first keepalive |
| DNS tunnel | 3s | 3 DH handshake round trips at ~1s each |
| ICMP | 2s | 3 echo request/reply cycles |
| Captive portal probe | 1s | Fires after all paths fail — determines CONN-2a vs CONN-2b |

Total: ≤11s to CONN-2a (captive portal) or CONN-2b (genuine block).

---

## Performance Targets

| Metric | Target |
|---|---|
| Time to connected (normal network) | ≤ 10s from tap |
| Latency overhead (TLS/443 + open WireGuard) | ≤ 20ms average |
| Throughput (managed server, TLS/443 path) | ≥ 50 Mbps sustained |
| Throughput (DNS tunnel) | 500 Kbps–2 Mbps (EDNS0); ~500 Kbps (EDNS0-degraded) |
| Throughput (ICMP tunnel) | 100–500 Kbps |

---

## Build Sequence

| Phase | What | Specs to read | Milestone gate |
|---|---|---|---|
| **1 — Foundation** | Device key lifecycle, WireGuard on open network, TLS/443 managed connection, basic macOS UX (menu bar app) | `engineering-handoff.md`, `ux-workflows.md` §3, `client-server-api-spec.md`, `data-model.md`, `error-states-spec.md` | User can install, onboard, and connect to a managed server on a normal network |
| **2 — Captive portal** | HTTP CONNECT path, TLS/443 + uTLS, DNS tunnel, ICMP tunnel, path upgrade manager | `technical-architecture.md`, `dns-tunnel-protocol-spec.md`, `icmp-tunnel-protocol-spec.md`, `path-upgrade-manager-spec.md`, `captive-portal-testing-guide.md` | User connects on a captive portal network; all 4 paths tested against all 5 test configs |
| **3 — Self-hosted** | Server dashboard, QR/config generation, CloudFormation template | `server-dashboard-api-spec.md`, `cloudformation-spec.md`, `ux-workflows.md` §4, `sparkle-update-feed-spec.md`, `certificate-management.md`, `build-and-release-pipeline.md` | User can deploy a self-hosted server on AWS and connect from macOS |
| **4 — Privacy + reliability** | Privacy Pass, DoH, ECH, aggregate metrics, network intelligence | `privacy-pass-spec.md`, `testing-plan.md` | All 8 test stages pass; launch gate checklist complete |

### Phase-Gated Spec Reading

Load only the specs for the active phase. The full list is 24 files — loading all at once wastes context.

**Phase 1:** `engineering-handoff.md`, `ux-workflows.md`, `client-server-api-spec.md`, `data-model.md`, `error-states-spec.md`

**Phase 2:** `technical-architecture.md`, `dns-tunnel-protocol-spec.md`, `icmp-tunnel-protocol-spec.md`, `path-upgrade-manager-spec.md`, `captive-portal-testing-guide.md`

**Phase 3:** `server-dashboard-api-spec.md`, `cloudformation-spec.md`, `sparkle-update-feed-spec.md`, `certificate-management.md`, `build-and-release-pipeline.md`

**Phase 4:** `privacy-pass-spec.md`, `testing-plan.md`, `privacy-policy.md`

**Reference (any phase):** `learn-here.md` (definitions)

**iOS post-launch only:** `apple-entitlement-application.md` (NE entitlement — needed when iOS work resumes)

**Post-launch only:** `anycast-dns-infrastructure.md`

---

## Coding Standards

**Swift (macOS — iOS is deferred):**
- All network operations have explicit timeouts — no indefinite waits
- WireGuard is handled by `wireguard-go` (userspace) via direct `utun` — do NOT use WireGuardKit or NetworkExtension on macOS
- Privileged operations (pf kill switch) go in the `FreewireHelper` `SMAppService` target — not the main app target. The target does not exist yet; see Current State
- Keychain access via a dedicated `KeychainHelper` — no direct SecItem calls scattered through the codebase
- Error states: implement exact user-visible strings from `error-states-spec.md` — no paraphrasing
- uTLS on the TLS/443 and HTTP CONNECT paths: rotate among Chrome, Safari, and Firefox fingerprints (implemented in `tunnel/cmd/freewire-tunnel/utls.go`)

**Go (server):**
- Static binary: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build`
- Structured logging: `go.uber.org/zap`
- All network operations have explicit context deadlines
- No client IP addresses in any log line — ever
- Privacy Pass issuance: blind signature only — server never sees unblinded token values

**All targets:**
- Version string format: `MAJOR.MINOR.PATCH` (semantic versioning), shared across iOS, macOS, and server
- Build number: monotonically increasing integer — never reset, never reused

---

## Common Mistakes to Avoid

**1. Logging a client IP address**  
Why: Any IP in a log becomes a record Freewire could be compelled to produce. One log line breaks the structural privacy guarantee the entire data model is built on.  
Do this instead: Log only opaque session identifiers (UUIDs generated per connection). Strip `RemoteAddr()` from every log call before it reaches production. Add a CI lint rule that fails on `RemoteAddr` in server log statements.

**2. Using the wrong HTTP status code for Privacy Pass token rejection**  
Why: The client maps specific HTTP codes to specific error states and retry logic. Using 401 or 429 instead of 402 will trigger the wrong retry path — the user either sees no error or gets stuck in an incorrect retry loop.  
Do this instead: `TOKEN_INVALID` and `TOKEN_SPENT` both return `402 Payment Required`. Reserve `429` for non-token-based rate limit abuse signals only. See `client-server-api-spec.md` §Error codes table.

**3. Using a plain opaque token instead of a blind Privacy Pass token**  
Why: A plain token lets the server correlate "device X was issued token Y and later spent token Y" — linking connection events to the same device over time. This breaks the anonymity guarantee.  
Do this instead: Implement RFC 9576 blind token issuance. The server signs the blinded value without seeing the unblinded token. See `privacy-pass-spec.md` for the full issuance and redemption flow.

**4. Inventing user-facing error copy**  
Why: Engineers reading crash reports and support tickets match user-reported messages to spec entries. Custom copy creates ambiguity — is this a new bug or a known state?  
Do this instead: Every error message is in `error-states-spec.md`. Copy the string verbatim. If a new error condition arises that isn't in the spec, update the spec first, then implement.

**5. Starting the DNS tunnel before the server is working**  
Why: The DNS tunnel (authoritative server + sliding window protocol + DH key exchange) is the most complex component. If you build client and server in parallel without a working server to test against, you'll debug both sides simultaneously.  
Do this instead: Build and test the authoritative DNS server first. Confirm it handles the handshake, EDNS0 negotiation, and stale cache detection. Then build the client-side tunnel against a known-working server.

---

## Open Engineering Questions

Only one question is intentionally left open for engineering to resolve:

| # | Question | Guidance |
|---|---|---|
| OQ-2 | Exact WireGuard idle eviction timeout for peer slots on managed servers | Use WireGuard's native ~3-minute session expiry as the baseline; tune based on capacity testing. See `data-model.md` §Open Questions. |

All other questions are resolved in `engineering-handoff.md` §Resolved engineering questions.
