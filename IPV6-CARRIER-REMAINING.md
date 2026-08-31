# IPv6 carrier — what's done, and the one piece left (client routing)

**Date:** 2026-08-25.

## Done and verified (server side)

The hard part — the infrastructure — is finished and codified in
`deploy/launch-aws.sh` (idempotent):

- VPC has an Amazon-provided IPv6 /56; the subnet a /64; a `::/0` route to the
  IGW; the instance a global v6 address.
- Ubuntu brought the address up on its own (RA), v6 egress works (~1.2ms to
  Cloudflare), and **wireguard-go binds dual-stack (`[::]:51820`)** — so
  WireGuard is already reachable over IPv6 with no server code change.
- Security-group v6 ingress rules mirror the v4 ports.
- The server auto-detects its global v6 and advertises it as
  **`endpoint_host_v6`** in `/v1/server/config` (verified live:
  `2600:1f18:29ea:800:2cd9:6ba0:29a:42b1`).
- The client `Config` already decodes `server_host_v6` (stored, unused for now).

So a client that reaches the server over IPv6 gets a full-speed WireGuard tunnel
today. The only thing missing is the client *using* it.

## The one piece left: the client `wireguard6` carrier + its routing

Deliberately NOT built yet, for one honest reason: it cannot be tested from a
v4-only network (this dev machine, and most), and the routing half is
**leak-sensitive** — exactly the class of untested routing code that broke the
wifi earlier in this project. It should be built AND verified at a v6-capable
network, which is where you would need to test it anyway (a v6-leaking café is
the whole point).

### Carrier (small, low-risk)
A `wireguard6` rung, tried early (as fast as direct v4 WireGuard when it works):
- `open` returns `(nil,nil,nil)` when `cfg.ServerHostV6 != ""`, else an error so
  the rung is skipped.
- `endpoint(cfg)` returns `[cfg.ServerHostV6]:51820` (the `endpoint` override
  field on `transportCandidate` already exists, used by `udp443`).
- `handshakeBudgetFor("wireguard6")` = 2s (one round trip; falls through fast on
  a v4-only network where the v6 dial has no route).
- Swift `TunnelTransport.wireguard6` (priority ~2, "WireGuard IPv6"), or a
  connecting tunnel mislabels as `.wireguard` — the same false-claim bug fixed
  for the other carriers. Plumb `server_host_v6` through ServerConfig →
  CachedConnection → TunnelConfig like `cdn_host`.

### Routing (the risky, must-verify-on-v6 part)
`setupRouting` currently calls `setIPv6(false)` for every carrier — it disables
IPv6 entirely so v6 user traffic cannot leak around the v4-only tunnel. That
would **kill the wireguard6 carrier's own v6 connection.** So when
`activeTransport == "wireguard6"`:
1. **Do NOT** `setIPv6(false)`.
2. Pin `[serverV6]/128` to the physical interface (a v6 analogue of
   `pinOutsideTunnel`), so the carrier's path to the server stays outside the
   tunnel.
3. **Blackhole the rest of v6** (`route add -inet6 ::/0 ::1 -blackhole` or a
   discard route) so non-server v6 traffic goes nowhere instead of leaking —
   apps fall back to v4, which is carried in the tunnel. This is the leak-safety
   step, and the one that MUST be verified on a real v6 network before trusting.
4. `cleanupRouting` reverses exactly this (remove the v6 pin + blackhole); it
   must not `setIPv6(true)` in this case since v6 was never disabled.

`carrierPeerAddr` is empty for `wireguard6` (a direct carrier, no
`transportConn`), so the server v6 address must be passed to `setupRouting`
explicitly (as `cfg.ServerHostV6`) for the pin.

### Safety net that makes this shippable once written
The traffic-verified fall-through selection + egress self-check mean a *broken*
v6 routing does not strand the machine: the tunnel carries no traffic, the
egress check fails, and the chain falls through to a v4 carrier. The routed-test
watchdog restores routing regardless. The remaining risk is a v6 *leak* during
the pre-fall-through window if the blackhole is wrong — which is precisely why
step 3 must be verified on a v6 network, not shipped blind.

## Bottom line
The server is v6-ready and reproducible. The client carrier is ~an afternoon of
work, but its routing must be built and verified at a v6-capable network. Until
then a v6-leaking café is detected by the probe (`--server6` reachability) but
not yet exploited by the app.

**Update (2026-08-30): the carrier half is now written, tested, and
deliberately staged, not active.** `wireguard6Candidate()` in
`tunnel/cmd/freewire-tunnel/transport.go` implements exactly the "Carrier
(small, low-risk)" section above -- skips when `cfg.ServerHostV6` is empty,
dials `[serverV6]:51820` otherwise, 2s handshake budget -- and
`wireguard6_test.go` covers its open/endpoint logic in isolation. It is
**not** in `defaultCandidates()`'s returned list, and there is still no
`TunnelTransport.wireguard6` case on the Swift side. This was a deliberate
choice, confirmed with the user rather than assumed: the carrier alone is
low-risk, but the "Routing (the risky, must-verify-on-v6 part)" section below
is unchanged and still needs to be built and verified together with wiring
this carrier into the active chain, on a real v6-capable network, in one pass
-- not as two separately-shipped changes where the carrier goes live before
the leak-safe routing exists. `TestWireguard6NotYetInDefaultCandidates` is a
tripwire test that fails (with a pointer back here) if someone wires the
carrier in without doing the Swift side and the routing change in the same
change.
