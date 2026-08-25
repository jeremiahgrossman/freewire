# CDN-fronted WebSocket carrier — engineering spec

**Status:** spec, not built. **Date:** 2026-08-24.
**Prereqs shipped:** WSS-443 carrier (`5db4bec`), traffic-verified fall-through
selection (`3bae110`), probe battery (`3a032f6`).
**Background:** `PORTAL-CARRIER-IDEATION-2026-08-24.md` §"NEW HIGH-VALUE CLASS".

## 1. What this is and why it is the next build

The café gated our **server's IP**. Every carrier we ship terminates on that IP,
so all of them die at the same drop — including the WSS-443 carrier, which beats
"blocks non-web 443" but not "blocks *our address*."

This carrier makes the tunnel arrive at a destination the portal already permits:
the client opens a WebSocket to a **CloudFront distribution** (`d123.cloudfront.net`)
on a **CloudFront edge IP**, and CloudFront proxies it to our EC2 origin. We are
not lying about anything — we genuinely own the distribution and terminate behind
it. That is what separates this from domain fronting (dead, and killed already).

**The bar it clears, and the one it does not:**
- **Beats FQDN→frozen-IP portals** — the common café/hotel class. The portal
  snoops allow-listed DNS names, freezes the resolved IPs into a set, and filters
  by IP. CDN edge IPs are routinely inside that set because the portal's own login
  page, payment SDK, or an allow-listed provider is CDN-hosted.
- **Does not beat live-SNI enterprise portals** that re-check SNI against an
  allow-list continuously. Our SNI is `*.cloudfront.net`, which such a portal has
  not allow-listed. Accepted limitation; no self-hosted technique clears it.

## 2. The one hard problem: routing must pin the *edge* IP, not the server IP

**This is the part that will silently break everything if missed.**

`setupRouting(tunName, bypassHost, ...)` (main.go:766) resolves `bypassHost` (our
server) and pins that single IP outside the tunnel, so the carrier's own packets
are not captured by the split-default route. With a CDN in front, **the carrier's
actual peer is a CloudFront edge IP, not our server.** Pin only the server and the
`0/1 + 128.0/1` split-default swallows the carrier's own TCP connection and loops
it into the tunnel — which presents exactly as "connected but carries nothing,"
the failure mode this project has already burned weeks on.

**Fix (general, and an improvement for every carrier):** pin the *established
connection's actual remote address*, taken from `transportConn.RemoteAddr()`,
in addition to `bypassHost`.

- `establishTunnel` already returns `transportConn` to main, so the address is in
  hand before `setupRouting` is called. Plumb it through as a new argument
  (`carrierPeer string`), pin it with the existing `pinOutsideTunnel`, and skip
  when empty or equal to `bypassIP`.
- `transportConn` is nil for the DNS and ICMP carriers (they run their own
  bridge); those keep pinning resolvers as today. No behavior change for them.
- Do this even for the non-CDN carriers: pinning the real peer is strictly more
  correct than pinning a config value, and it costs one route.
- **Reconnect:** a new connection may land on a *different* edge IP. Pin per
  connection and unpin on teardown; `cleanupRouting` must remove whatever was
  pinned, so track the pinned set rather than recomputing it from config.

Second-order: DNS resolution of `d123.cloudfront.net` must happen outside the
tunnel. It already does on first connect (routing is installed after), and on
reconnect the resolver is pinned by the existing `pinResolver` logic. Verify in
the routed test rather than assuming.

## 3. Architecture

```
client ──TLS+WSS──► CloudFront edge IP ──TLS+WSS──► our EC2 origin ──► wireguard-go
        (SNI: d123.cloudfront.net)      (origin: vpn.example.com)
        [WireGuard packets inside WSS binary frames, end to end]
```

WireGuard is authenticated to the **pinned server public key**, end to end. The
CDN sees TLS-terminated WebSocket frames carrying WireGuard ciphertext — it
cannot read traffic. See §6 for what it *can* see, which is not nothing.

**No new protocol.** The wire format is the existing one: `[uint16 len][packet]`
inside WSS binary frames, `wsConn` unchanged on both ends. This carrier is the
existing WSS carrier pointed at a different hostname with real cert validation.

## 4. Server-side requirements

CloudFront must reach our origin over HTTPS with a **publicly trusted
certificate** — it will not accept our self-signed cert. Two options:

**(a) Public origin + ACME (recommended, least new machinery).** The server
already supports ACME (`config.ACMEDomain`/`ACMEEmail`/`ACMECacheDir`, wired
through `certs.Build`). Requirements:
- a DNS A record for the origin (e.g. `origin.example.com` → the Elastic IP),
- port 80 reachable for the HTTP-01 challenge,
- set `acme_domain` in the server config; the existing cert path does the rest.
Then a CloudFront distribution with that origin, **Origin Protocol Policy =
HTTPS Only**.

**(b) CloudFront VPC origin (hardened variant).** Keeps the origin off the public
internet entirely, so the EC2 IP cannot be probed or gated directly. More AWS
plumbing (VPC origin + security group). Worth it later; not for the first cut.

**Distribution settings that matter:**
- **WebSocket support** — CloudFront supports WS on custom/VPC origins; no
  special toggle, but the `Sec-WebSocket-*` and `Upgrade`/`Connection` headers
  must be forwarded (use an origin request policy that forwards all headers, or
  explicitly allow-list those).
- **Cache: disabled** (`CachingDisabled` managed policy). A cached WebSocket
  upgrade would be nonsense and could poison other clients.
- **Origin timeouts:** raise the origin read/keep-alive timeout to the maximum;
  WireGuard's 25s keepalive must not be mistaken for idleness.
- **Logging: OFF.** Standard access logs and real-time logs both record client
  IPs. See §6 — this is a privacy requirement, not a preference.

**Server code changes: none required.** The 443 listener already discriminates
raw-vs-WebSocket by peeking one byte inside TLS, and CloudFront arrives as an
ordinary WSS client. The WS handshake does not inspect `Host`, so the CDN's
rewritten Host is tolerated. Confirm with the interop harness (§8).

## 5. Client-side changes

**Config** (`Config`, main.go:27). Add one field, plumbed from the server's
`/v1/server/config` (`ServerConfigResponse`, add `cdn_host`), and included in the
captive-portal config cache so it survives a blocked API:

```go
// CDNHost is a CDN hostname that fronts this server (e.g. d123.cloudfront.net).
// Empty disables the CDN carrier. The client validates this certificate
// normally: unlike the direct carriers, there is a real trusted name here.
CDNHost string `json:"cdn_host,omitempty"`
```

**Carrier** (`transport.go`). New rung `cdn_wss`, immediately after `wss443`:

```go
{
    name: "cdn_wss",
    open: func(cfg Config) (net.PacketConn, net.Conn, error) {
        tc, err := tryCDNWSS(cfg)   // no CDNHost -> error, rung skipped
        ...
    },
},
```

`tryCDNWSS` is `tryWSS443` with three deliberate differences:
1. dials `cfg.CDNHost:443` (hostname, so DNS picks a nearby edge),
2. **`InsecureTLS` is ignored — always verify.** A real CDN hostname has a real
   chain; accepting an invalid cert here would accept a portal's MITM. This is
   strictly stronger than the direct carriers, which face a self-signed origin.
3. `wsClientHandshake(tc, cfg.CDNHost)` so `Host:` and `Origin:` name the CDN.

Speed order rationale: extra network hop and CDN latency make it slower than
direct WSS on an open network, but it is the only rung that survives IP gating —
so it sits after `wss443` and before `dns`. Budget: `cdnWSSBudget = 5s` (dial +
TLS + upgrade through an extra hop; one second above `wss443Budget`).

**Selection** needs no change: the traffic-verified fall-through loop will reach
`cdn_wss` when the direct carriers fail or carry nothing, which is exactly the
café case.

## 6. Privacy analysis (must be settled before building)

CLAUDE.md's first non-negotiable is that client IPs are never recorded. Fronting
introduces a third party that sits between the client and us.

- **What CloudFront sees:** the client's source IP, the SNI/Host, connection
  timing and byte counts. It cannot read traffic (WireGuard ciphertext inside).
- **What it must not do:** log. Standard access logging and real-time logs both
  capture client IPs into an S3 bucket or Kinesis stream *we own*, which would
  manufacture exactly the record the architecture promises does not exist.
  **Both must be disabled, and that must be asserted, not assumed** — add a
  deploy-time check to `deploy/` that fails if logging is enabled on the
  distribution.
- **Residual, and it is real:** AWS operates the edge and may retain data under
  its own policies regardless of our settings. We cannot make that go away. The
  honest framing: this carrier trades *a third party seeing connection metadata*
  for *reaching a network that otherwise blocks us entirely*. That is a real
  tradeoff, not a free win.
- **Therefore: not the default carrier.** It sits below the direct carriers in
  speed order, so it is used only when the direct paths fail — the network where
  the alternative is no connection at all. Worth stating in the user-facing
  privacy copy when this ships.
- The client's WireGuard key never leaves the device and the CDN never sees it;
  no identifier is added to the WSS request beyond a browser-plausible UA.

## 7. Costs

CloudFront egress is ~$0.085/GB against EC2's $0.09/GB — no worse per byte, and
it is a rounding error for one user. It is in the same "ruinous for a free
service at scale" bucket as `deploy/COSTS.md` already records; single-user scope
makes it a non-issue today. Note it in COSTS.md when built.

## 8. Testing plan (desk-first, per this project's history)

1. **Fake-CDN harness (desk, no AWS).** A small Go reverse proxy that terminates
   TLS with a locally trusted cert and proxies WSS to the real server listener —
   i.e. what CloudFront does. Extends the existing `wss_interop_test.go` pattern:
   run the real server listener + fake CDN + the real client binary. Proves the
   carrier, the Host/SNI handling, and full cert validation without AWS. **This
   catches most of the risk.**
2. **Routing test (the dangerous part).** `testing/routed-test.sh cdn_wss` with
   the detached watchdog. Assert via `route-check` that the pinned set contains
   **the edge IP the connection actually used**, not just the server IP, and that
   egress is verified. This is where §2 is proven or disproven.
3. **Reconnect on a different edge IP.** Kill the tunnel, confirm reconnect pins
   the new peer and unpins the old (no route leak across reconnects).
4. **Throughput measurement — the real unknown.** CDNs are known to buffer
   WebSocket frames, which can quietly make this unusable. Measure against direct
   WSS on the same network before trusting it. **Kill criterion below.**
5. **Field probe** at a real portal (§9).

## 9. Field probe (build this first — it is cheap and it decides everything)

Before building the carrier, add one line to the probe battery that classifies
the portal:

```
freewire-tunnel --probe-battery --server <ip> --cdn d123.cloudfront.net
```

The new line dials the CDN hostname on 443 and completes the WS upgrade. Result
matrix at a café:

| direct WSS/443 | CDN WSS/443 | meaning |
|---|---|---|
| OK | OK | network is open; direct is cheaper, no need for CDN |
| **-- no** | **OK** | **portal gates our IP, not the port — CDN-fronting is the fix** |
| -- no | -- no | live-SNI portal or a full block; this class cannot help |

The second row is the hypothesis. One café visit confirms or kills the whole
build before we write the carrier.

## 10. Kill criteria (state them now, honor them later)

Abandon or park this carrier if any hold:
- The probe shows CDN WSS fails wherever direct WSS fails (portal is live-SNI or
  blocks broadly) across two or more real portals → the class does not fit our
  venues.
- Measured throughput through CloudFront is worse than the **DNS carrier's
  server-direct ~71 KB/s** → CDN buffering has eaten the benefit; the carrier is
  not worth its complexity or its privacy cost.
- Logging cannot be verifiably disabled → violates the first non-negotiable.

## 11. Work breakdown

| # | Item | Where | Risk |
|---|---|---|---|
| 1 | `--cdn` line in the probe battery | `probebattery.go` | low — **do first** |
| 2 | Pin the carrier's real peer (`transportConn.RemoteAddr()`) | `main.go` setup/cleanupRouting | **highest** — §2 |
| 3 | `CDNHost` config + `cdn_host` in the server config API + cache | `main.go`, `config_handler.go` | low |
| 4 | `tryCDNWSS` + `cdn_wss` rung | `transport.go` | low (reuses WSS) |
| 5 | Fake-CDN interop test | `server/internal/transport` | medium |
| 6 | CloudFront + ACME deployment, logging-off assertion | `deploy/` | medium |
| 7 | Routed + reconnect + throughput tests | `testing/` | medium |

Order: 1 → (probe at a café; stop here unless row 2 of the matrix appears) →
2 → 3 → 4 → 5 → 6 → 7. **Item 1 gates the rest**; item 2 is the one that
silently breaks things and deserves the routed test's full attention.
