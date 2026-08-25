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
| 4 | **UDP/443 passes to our server** | Portal passes QUIC-class UDP | **BUILT** (`udp443`, pre-built 2026-08-25) — validates on the spot, no field build. Near line-rate, no TCP-over-TCP; 307ms handshake, routed 6/6 TUNNELLED. |
| 5 | UDP/123 passes, UDP/443 doesn't | Portal passes NTP-class UDP | **BUILD the UDP/123 carrier** (same shape as #4, lower priority). |
| 6 | IPv6 egress present | v4-only portal leaks v6 | **Server is now v6-ready** (provisioned + advertises endpoint_host_v6). The client `wireguard6` carrier + its leak-safe routing is the one remaining build, and it must be verified ON a v6 network -- see IPV6-CARRIER-REMAINING.md. |
| 7 | Only throttled DNS (the original café) | Hard destination gate, DNS is the floor | If UDP/443 also fails: **nothing client-side raises the ceiling** (research-confirmed). This is the characterized case. |
| 8 | Everything incl. CDN fails | Live-SNI portal or hard block | The hard case. Geneva-class desync IS an option **only if the portal is stateful-inline** (an active RST hints yes); big conditional build. Or accept the café as unsupported. |

## The builds, pre-scoped

### UDP/443 carrier (row 4) — DONE (pre-built 2026-08-25)
- Built and verified end to end: real WG handshake over UDP/443 (307ms, same as
  direct WireGuard — no overhead), routed 6/6 TUNNELLED, only the server IP pinned
  (it talks straight to the server, no CDN edge). The server dispatches UDP/443 by
  first byte — magic → probe reply, WireGuard type 1..4 → per-source relay to the
  local WireGuard, else drop — so `--probe-battery` still works on the port.
- v1 is **bare WireGuard over UDP/443**, no QUIC shaping. If a café gates UDP/443
  on "looks like QUIC" (rare — block-QUIC is off by default), the follow-up is to
  prepend a QUIC Initial-shaped header; the dispatch already leaves room (a QUIC
  long header is 0xC0+, distinct from WireGuard's 1..4 and the probe magic).

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
