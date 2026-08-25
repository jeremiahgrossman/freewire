# Field test: readiness + what each result means to build

**Date:** 2026-08-24. Everything below is desk-verified; run the probe at a real
portal and match the result to a row.

## The one command

```
tunnel/freewire-tunnel --probe-battery --server 52.203.246.145 --insecure --cdn d29cubp361kpm8.cloudfront.net
```

Rootless, non-routed, safe on a machine in use. It probes every carrier plus the
UDP/443, UDP/123, IPv6 and CDN candidates against OUR server and names the
verdict. For the full real-WireGuard-handshake survey (incl. cdn_wss), also:
`testing/probe-transports.sh` (run once on the hotspot first to cache a peer).

## Pre-trip (2 minutes, only you can do)

- **Reboot the Mac** — clears 8 stale utun interfaces from desk testing. The
  app's cached peer (UserDefaults) and the server peer (AWS) both survive it.
- Nothing else. The distribution is up, ACME is live, cdn_host is advertised, the
  app connects (verified), all 7 carriers reach the server.

## Result → what it means → what to build

Rows are ordered best-case to worst-case. "Built" = ships today, nothing to do.

| # | Probe result | Meaning | Action |
|---|---|---|---|
| 1 | wireguard-direct OK | Open/permissive café | **Nothing.** Product just works. |
| 2 | raw 443 fails, **direct WSS OK** | Blocks non-web 443 | **Nothing to build** — `wss443` handles it. Confirm it's selected on a real connect and note throughput. |
| 3 | direct WSS fails, **CDN WSS OK** | Gates our ADDRESS, not the port | **Nothing new to build** — `cdn_wss` handles it. BUT measure throughput (see "CDN throughput" below); the carrier is proven to carry, not yet measured. |
| 4 | **UDP/443 passes to our server** | Portal passes QUIC-class UDP | **BUILD the UDP/443 carrier** — the highest-value next build (near line-rate, no TCP-over-TCP). Not built yet. See below. |
| 5 | UDP/123 passes, UDP/443 doesn't | Portal passes NTP-class UDP | **BUILD the UDP/123 carrier** (same shape as #4, lower priority). |
| 6 | IPv6 egress present | v4-only portal leaks v6 | **Provision v6 on the server FIRST** (it has none today), then build the v6 carrier. Two-part. See below. |
| 7 | Only throttled DNS (the original café) | Hard destination gate, DNS is the floor | If UDP/443 also fails: **nothing client-side raises the ceiling** (research-confirmed). This is the characterized case. |
| 8 | Everything incl. CDN fails | Live-SNI portal or hard block | The hard case. Geneva-class desync IS an option **only if the portal is stateful-inline** (an active RST hints yes); big conditional build. Or accept the café as unsupported. |

## The builds, pre-scoped

### UDP/443 QUIC-shaped carrier (row 4) — the one worth pre-building
- **Why:** research ranks it #1, block-QUIC is off by default on most portals, and
  it is near-line-rate with no TCP-over-TCP penalty. The probe already shows
  UDP/443 reaches our server on open networks.
- **Server:** a real UDP/443 WireGuard-forwarding listener. NOTE the probe
  responder currently owns UDP/443 (magic-gated echo) — the carrier must either
  coexist (dispatch by first byte: magic → probe, else → WG) or the responder
  moves. Straightforward.
- **Client:** a `udp443` carrier that sends WireGuard datagrams to `server:443`,
  optionally shaped like a QUIC Initial. Structurally simpler than the WSS
  carriers (no framing — WireGuard is already UDP). The carrier-peer-pinning and
  fall-through selection already handle it.
- **Effort:** a focused build + one redeploy. **Pre-buildable at the desk now.**

### IPv6 carrier (row 6) — two-part, server first
- **Server has no v6 today** (checked: 0 global inet6, no v6 default route). So
  first: assign an IPv6 address to the EC2 instance, add a v6 SG rule, confirm the
  WireGuard/TLS listeners bind v6 (they bind all interfaces, so likely free), and
  publish the v6 endpoint in the config API.
- **Client:** dial the server's v6 endpoint; `--server6` already exists in the
  probe for reachability. Full speed when it works.
- **Effort:** infra change + small client change. Not pre-buildable without the
  infra step.

### CDN throughput (row 3) — measure, then maybe tune
- `cdn_wss` carries traffic (6/6 routed) but its **throughput is unmeasured**.
  CloudFront WebSocket buffering is the open risk. Measure a real routed run's
  bandwidth vs direct WSS. If it is below the DNS carrier's ~71 KB/s, tune the
  origin keepalive/read timeouts or accept the carrier as a last-resort reach
  (still better than no connection). Kill criterion is in
  `CDN-FRONTED-CARRIER-SPEC.md` §10.

### Geneva-class desync (row 8) — conditional, big
- Only if the portal is a stateful inline redirect box (the café's active RST is
  encouraging), NOT a hard L3 ACL. Client-side pf/divert packet-mangler (root).
  Probe: send a ClientHello to a blocked dest preceded by a low-TTL fake segment;
  if the handshake completes, the portal is desyncable. Defer unless rows 1–6 all
  fail and row 8's probe says yes.

## The honest shape of the field test

Two questions only the field answers: **does a real café gate by address**
(making `cdn_wss` the winner), and **what is CDN throughput**. Everything to
answer them is deployed. The most likely valuable NEW build is the UDP/443
carrier (row 4) — worth pre-building at the desk so the field can validate it
immediately. Everything else is either already built, ops-gated (v6), or a large
conditional (desync).
