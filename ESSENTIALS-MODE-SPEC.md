# Essentials Mode — Plan B for hard-throttled captive portals

**Status:** Built, unit-tested, and desk-pre-flight re-confirmed current
(2026-08-30) — see `CLAUDE.md`'s Current State. The one remaining step is real
café field validation (runbook Step 3, `testing/FIELD-TEST-RUNBOOK.md`). Design
recorded 2026-08-28.
**Prereq to build:** a field-confirmed throttled-DNS-only café (café #1 and #2 both
qualify), and the throttle repro `FREEWIRE_DNS_CARRIER_CAP` for desk testing.

---

## The problem this solves

At a hard destination-gated portal (café #1, café #2) the only carrier that escapes
is **server-direct DNS**, and the portal throttles it to ~72 Kbps. That carrier is
real (0% loss in isolation, `--dns-throughput`), but the current **full tunnel**
(route `0.0.0.0/0` into it) collapses: the whole machine offers 50+ Mbps into a
~72 Kbps straw, the send queue overflows, packets tail-drop indiscriminately, and
the egress self-check's own packets die with them → the tunnel tears itself down.

The failure is a **load mismatch, not a carrier failure.** The fix is to offer the
carrier less traffic — specifically, only the traffic that *fits*.

### Field evidence (2026-08-28, café #3 — the collapse, on camera)

The app's normal connect at a hard destination-gated café selected DNS, brought it
up, then collapsed under whole-machine load — captured live in the helper stats:

```
dns send 35/s, tail-drop  0/s (queue 192/256); downstream 27607 B/s   ← ~27 KB/s, err 0/s
dns send 46/s, tail-drop 21/s (queue 256/256); downstream 29256 B/s   ← QUEUE FULL
dns send 28/s, tail-drop 69/s (queue 256/256); downstream 16705 B/s   ← loss collapse
dns send 35/s, tail-drop 68/s (queue 255/256); downstream 13696 B/s   ← falling
→ egress did not sustain: 0/2 to 1.1.1.1:53: dial tcp 1.1.1.1:443: i/o timeout
→ DNS excluded → CONN-2a (portal login prompt)
```

This proves both halves of the thesis at once: **full-tunnel over this café's DNS
is not viable** (the queue overflows and the egress self-check's own packets are
tail-dropped, tearing the tunnel down), **and the carrier has real headroom** —
~27 KB/s downstream (~220 Kbps, faster than café #2's ~72 Kbps floor), with zero
errors before the queue filled. The carrier is fine; the offered load is the
problem. Scoping the offered load to an allowlist is what turns this café usable.

## The decision: admission control by SCOPE, not by pacing

Two ways to reduce offered load:

1. **Pace everything down** (the deferred "Stage 2 backpressure", `DECISIONS.md`
   DNS-CARRIER-BACKPRESSURE): make all 50 Mbps of demand wait for the 72 Kbps pipe.
   Everything crawls equally — web included, which is unusable at 72 Kbps no matter
   how politely it waits. Large core refactor (custom wireguard-go `Bind`).
2. **Reduce what enters the pipe** (this spec): carry only a small allowlist of
   low-bandwidth destinations; let everything else fail on the physical path.

**Essentials Mode chooses #2.** You cannot make web browsing usable at 72 Kbps, so
do not pretend to — carry what fits (messaging, email, push), be honest about the
rest. This is a better fit than backpressure for the hard-throttled case, and it is
a routing change rather than a data-plane refactor.

## What fits in ~9 KB/s

| Carry (allowlist)                         | Cut (blackhole via physical path)     |
|-------------------------------------------|---------------------------------------|
| Text messaging (iMessage/Signal/WhatsApp) | Web browsing (pages are MBs)          |
| Push notifications (APNs, 17.0.0.0/8)     | Video / audio streaming               |
| Email control-plane (IMAP headers+text,   | Cloud sync (iCloud/Drive/Dropbox)     |
| SMTP send). **Attachments excluded.**     | App/OS updates, telemetry             |

A text message is sub-1 KB; an email header is sub-1 KB. The control-plane of
messaging and mail is entirely feasible. Media and web are what blow the budget, so
they are excluded, not merely deprioritized.

## Mechanism (macOS, utun + the Go helper)

**Scope is enforced client-side, by which routes point at the utun.** The server's
WG AllowedIPs and egress are unchanged — the server forwards whatever the client
sends; the client simply sends less.

- **Full tunnel (today):** `setupRouting` installs `0/1` + `128/1` → utun (a
  split-default that beats the physical default), and pins server + carrier-peer +
  resolver outside the tunnel.
- **Essentials mode:** install **only the allowlist prefixes** → utun. Do NOT
  install `0/1`+`128/1`. The physical default route stays, so every non-allowlisted
  destination uses the physical interface — where the portal blackholes it. Only
  allowlisted prefixes enter the tunnel, so the offered load drops from
  whole-machine to a trickle and the queue never overflows.
- Keep the existing outside-tunnel pins (server, carrier-peer, resolver) exactly as
  full tunnel does — they are still required for the carrier itself.

### Keep WireGuard encryption — attack the real overhead instead

Dropping WG crypto was considered and rejected: its AEAD is ~60 bytes/packet and
near-zero CPU, so it saves almost nothing at a packet-rate-limited 72 Kbps, and it
would forfeit the entire privacy guarantee (and violate the pinned-key
non-negotiable). The overhead worth cutting on this path is:

- **DNS-tunnel encoding inflation** — base32/base64 in DNS labels inflates payload
  ~33–100%. Tightening the encoding buys real bytes on the wire.
- **Round-trips** — coalesce more per DNS response (already partly done:
  length-prefixed multi-packet responses).
- **DoH takeover stays OFF** on this carrier (already the DNS-1 behavior): a
  per-lookup HTTPS round trip is unaffordable here.

## The DNS-resolution subtlety (why the MVP is IP-only)

Allowlisted apps must *resolve* their endpoints. If their DNS goes to the portal
resolver, it is blackholed for external names; if it goes nowhere, they cannot
connect even to an allowlisted IP range.

- **MVP: IP-prefix allowlist only.** `17.0.0.0/8` (Apple push + iMessage) needs no
  DNS — it is already an IP range, and the device maintains persistent APNs
  connections. The operator's mail server can be pinned by IP. This sidesteps
  resolution entirely and is enough to prove the model.
- **Phase 2: domain allowlist + scoped in-tunnel resolver — BUILT (2026-08-28),
  integration not yet field-validated.** The allowlist accepts domains alongside
  CIDRs. A scoped resolver (`essentials_resolver.go`) binds `127.0.0.1:53` (free on
  the DNS carrier, where DoH is off), answers ONLY allowlisted names — forwarding
  them to an upstream (`1.1.1.1`) routed *into* the tunnel, then dynamically routing
  each resolved A/AAAA IP into the tunnel — and REFUSES everything else (NXDOMAIN),
  so non-allowlisted apps cannot resolve and stay blackholed. `setupRouting` takes
  the resolver over even on the slow carrier (safe: non-allowlisted names are
  refused instantly, no round trip). Pure logic is unit-tested (matching,
  normalization, DNS wire-format parse/extract). The routed takeover + dynamic
  routing is built but wants a routed desk run and ideally Phase-1 field validation
  before it is trusted — a system-resolver takeover is the class of change that
  broke DNS earlier in this project.

## Default allowlist (seed, user-editable — single-user scope)

| Entry              | Form   | Notes                                                       |
|--------------------|--------|-------------------------------------------------------------|
| Apple push/iMessage| `17.0.0.0/8` | Stable Apple netblock; no DNS needed. MVP-ready.      |
| Operator mail      | IP(s)  | User supplies their IMAP/SMTP server IP. MVP-ready.         |
| Signal             | domains| Phase 2 (needs the scoped resolver; Signal IPs are fluid).  |

The operator curates this. A hand-edited short list is acceptable and correct for
one user; a universal, always-current allowlist is explicitly a non-goal.

## Activation policy — opt-in, never silent

Essentials mode reduces what is protected, so entering it silently is its own
false-connectivity risk (the user believes they are fully tunneled while only
messaging works). Therefore:

- Trigger: the fall-through selection lands on a carrier whose measured rate is
  below a threshold (say < 200 Kbps) AND full-tunnel egress verification fails.
- Then **offer** Essentials mode rather than tearing down: the user explicitly
  accepts "messaging & email only" before the reduced-scope routes are installed.
- The full-tunnel path is unchanged on every network that is not hard-throttled;
  this fires only in the exact café case that otherwise gives nothing.

## UI / status (copy is spec — implement verbatim, per architecture rule 4)

A new state, stronger than DNS-1 (which only warns about DNS visibility). Proposed
entry for `error-states-spec.md` (assign a real ID there before building):

- Headline: **"Limited connectivity — messaging and email only."**
- Sub-text: **"This network is too restrictive for full browsing. Freewire is
  carrying only the apps you allow-listed; everything else is blocked."**

Do NOT show a plain "Protected" — this is partial protection with most traffic
blackholed, and the panel must say so.

## Testing (desk, before any field trip)

Against the throttle repro `FREEWIRE_DNS_CARRIER_CAP`:

1. Install Essentials routes for a test IP prefix; confirm a small HTTPS GET to an
   allowlisted IP succeeds through the tunnel.
2. Confirm a non-allowlisted destination is blackholed (uses physical path, portal
   drops it) — and crucially that its traffic never enters the tunnel queue.
3. Confirm the tunnel stays up under whole-machine background load, because the
   offered load into the carrier is now the allowlist only (no queue overflow, no
   egress-check teardown — the exact failure this mode removes).
4. `--restore` returns the machine to the physical default cleanly.

## Open questions

- **Threshold** for "throttled" (200 Kbps is a guess; measure at a real café).
- **Prioritization within the allowlist** — an email-sync burst could still starve
  a live message. QoS inside the tunnel is Phase 3; the allowlist alone is the 80%.
- **Phase-2 scoped resolver** — the cleanest answer to domain-based entries, but it
  is real work; the IP-only MVP proves the model first.

## Phase 2 scoped-resolver known limitations (from the 2026-08-28 review)

Minor, deliberately not fixed in the MVP; recorded so they are not rediscovered:

- **No response caching.** Every allowlisted lookup does a fresh upstream round trip
  through the tunnel. Fine at essentials' low volume; could reuse `doh.go`'s cache.
- **AAAA answers are returned but not routed.** IPv6 is switched off for the tunnel's
  lifetime, so the resolver hands back AAAA records but does not route them; an app
  may try v6 first and fall back to v4 (happy-eyeballs). Minor added latency.
- **UDP-only forward, no TCP retry.** A truncated (TC-bit) upstream reply is not
  retried over TCP. A/AAAA answers for messaging/mail are small, so this is rare;
  the 4096-byte buffer covers common EDNS sizes.
- **Plain DNS to the upstream, not DoH.** Queries are cleartext from our server to
  the upstream (1.1.1.1/8.8.8.8/9.9.9.9), but tunnelled from the client to the
  server — the local network cannot see them. This is the DNS-1 tradeoff, accepted
  for a slow carrier where DoH's per-lookup HTTPS cost is unaffordable.
- **Benign teardown race.** A resolver goroutine in flight when cleanup runs may add
  one more `-interface` route after the tracked set is cleared; the OS drops routes
  to a vanished utun, so it self-heals.

## Relationship to existing decisions

- Supersedes, for the hard-throttled case, the need to finish Stage-2 backpressure
  (`DECISIONS.md` DNS-CARRIER-BACKPRESSURE): scope-limiting removes the overflow
  that backpressure was meant to pace away, and it does so with routing, not a
  wireguard-go `Bind` refactor.
- Consistent with the traffic-verified fall-through (`technical-architecture.md`
  §3): Essentials mode is what the chain offers when even the last carrier
  handshakes but full-tunnel routing carries nothing.
