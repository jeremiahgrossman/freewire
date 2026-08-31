# Field-test runbook — real captive portal (current plan)

> **Result update (2026-08-30):** the PRIMARY question below —
> does `dns_tcp` survive full-tunnel where UDP-DNS collapsed — is now
> **answered, at a real destination-gated café**: yes. `dns_tcp` held under
> load (3.6–7.6 Mbps sustained, ~13–56× the old UDP-DNS floor) at exactly the
> café shape this runbook describes. See `CLAUDE.md`'s Current State,
> 2026-08-30 entry, for the full result. **The next field-test priority is now
> the FALLBACK section below — Essentials Mode's in-flow offer — at a café
> that blocks TCP/53 specifically** (so `dns_tcp` can't rescue it) while still
> passing UDP/53. Steps 1 and 2 below remain useful for completing the
> carrier support map at a new café; Step 3 is now the headline step.

**Updated 2026-08-29** (added the `dns_tcp` / TCP/53 primary thread; nine carriers
now ship). This is THE plan for the next café visit. Pair it with
`FIELD-TEST-CONTINGENCIES.md` (result → what to build) and, for the throttled-DNS
outcome, `ESSENTIALS-MODE-SPEC.md` (Plan B).

Everything else is proven at the desk (all nine carriers carry traffic on an open
network — `testing/validate-all-carriers.sh` proved 7/7 pre-`dns_tcp`, and
`dns_tcp` is separately routed-verified at 32 Mbps; delegation live; cache
fallback works; false-Protected fixed; disconnect tears down on stdin EOF). The
field answers only what simulation cannot: **which carriers a real portal allows**,
and **whether the DNS floor is actually usable**.

## What this next test decides (in priority order)

**What changed since this test was last planned.** Café #3 (2026-08-28) already
settled the old primary question — at a hard destination-gated café, full-tunnel
UDP-DNS *collapses* under whole-machine load (`queue 256/256` → tail-drop →
egress-check teardown → CONN-2a) even though the carrier itself had **~27 KB/s of
headroom** (`err 0/s` before the queue filled). The carrier was fine; the offered
load overwhelmed a pipe with no backpressure. Two things landed to attack exactly
that, and **both are field-unconfirmed** — this test exists to confirm them.

1. **PRIMARY — does `dns_tcp` survive full-tunnel where UDP-DNS collapsed?**
   `dns_tcp` (shipped 2026-08-28) is WireGuard over a TCP connection to the
   server's port 53. TCP has flow control by construction, so a throttled path
   *paces the sender* instead of tail-dropping into a teardown — the precise
   failure that killed café #3. It sits in the chain **before** the UDP `dns`
   carrier, so if this café passes TCP/53 the app should select `dns_tcp` on its
   own and **hold** where UDP-DNS fell over. The gating field fact: **does a portal
   that passes UDP/53 also pass TCP/53?** The battery's `TCP/53 (dns_tcp carrier)`
   line answers reachability; a routed connect answers whether it carries and
   survives. If it works, a "supported but unusably slow" café becomes genuinely
   usable (~56× the UDP DNS tunnel, measured 32 Mbps at the desk).
2. **FALLBACK — Essentials Mode (the in-flow offer).** If TCP/53 is blocked (so
   `dns_tcp` is unavailable) or `dns_tcp` still can't carry a full tunnel here,
   validate Plan B: carry only a low-bandwidth allowlist so the pipe is never
   overwhelmed. This is the pending Phase-1 validation of the whole
   find→build→ship arc (`ESSENTIALS-MODE-SPEC.md`).
3. **Complete the portal's 9-carrier support map.** Which of wireguard, udp443,
   http_connect, tls443, wss443, cdn_wss, dns_tcp, dns, icmp_udp the portal allows.
   Tool: `cafe-run.sh` (the full battery). Match the result to a
   `FIELD-TEST-CONTINGENCIES.md` row.
4. **Walled-garden survey.** Which third-party destinations the portal permits on
   443 (Apple/Google/Cloudflare/Fastly/a *different* CloudFront edge). If a
   frontable provider is open while our edge is not, a carrier fronted through it
   could beat this café — where our own `cdn_wss` failed. Tool: `cafe-run.sh`
   (`--walled-garden` line).
5. **Classify each block: `[SYN-RST]` vs `[reset]` vs `[timeout]`.** A `[reset]`
   (post-handshake SNI reset) is the only thing that makes desync viable; no café
   has shown one yet. The battery tags each automatically.

## Before you leave (at home / on the hotspot)

1. **Reboot the Mac.** Clears stale `utun` interfaces from desk testing. The app's
   cached peer (UserDefaults) and the server peer (AWS) both survive a reboot.
2. **Build + run the current app**, then populate the cache:
   ```
   xcodebuild build -project macos/Freewire/Freewire.xcodeproj -scheme Freewire -configuration Debug CODE_SIGNING_ALLOWED=NO
   ```
   Launch the built `Freewire.app`, **Connect once on the open network**, confirm
   **Protected** + real egress (public IP becomes the server), then **Disconnect**.
   The peer stays registered (persistent), and the control-plane cache the portal
   fallback needs is now saved.
3. **Prime the rooted probe.** Run `testing/probe-transports.sh` **once on the
   hotspot** so its `/tmp` peer cache exists — a reboot clears it, and at the café
   there is no internet to re-register. (The rootless battery needs no priming.)
4. **Confirm no stale overrides** (all should be empty/error):
   ```
   defaults read com.freewire.vpn.Freewire dnsResolverOverride
   defaults read com.freewire.vpn.Freewire skipRouting
   defaults read com.freewire.vpn.Freewire forceTransport
   ```
5. *(Optional)* If you want the app to auto-select `cdn_wss`, confirm `cdn_host` is
   set in the server config. The probe tests the CDN via `--cdn` regardless, so
   this is not required for the survey.

## At the café — self-contained, no internet needed

A captive portal cuts this Claude session's own internet, so the café tools write
to `/tmp` and are read back afterward. Nothing here needs a live session.

**Step 1 — the full survey (rootless + rooted, ~1–2 min).**
Join the café wifi. If the OS login sheet appears, **Cancel it — do not log in.**
```
bash testing/cafe-run.sh
```
This runs, in one shot: the 9-carrier probe battery (reachability of all carriers
+ UDP/123 and IPv6 candidates, RST/timeout classification), the walled-garden
survey, and — if you give it your password once — the rooted per-carrier real-WG
handshake (`probe-transports.sh`, covering `icmp_udp` too). Writes `/tmp/freewire-cafe-*.txt`.

**Step 2 — connect, and watch WHICH carrier the chain settles on (the primary question).**
Launch `Freewire.app`, Cancel the login sheet, click **Connect**. On a DNS-only
café the chain now falls past the fast carriers to `dns_tcp` **before** the UDP
`dns` carrier, so the carrier it lands on is the headline result:
- **If it settles on `dns_tcp`** (TCP/53 is open here): this is the win we built —
  it should stay connected and **Protected** where café #3 collapsed. Measure it:
  ```
  bash testing/cafe-measure.sh
  ```
  Read-only: real egress, latency, sustained throughput, a real page load. Writes
  `/tmp/freewire-cafe-measure-*.txt`. Expect it to hold under load (TCP
  backpressure) rather than tear down. **Disconnect** when done.
- **If it settles on the UDP `dns` carrier** (TCP/53 blocked but UDP/53 open): this
  is the café #3 repro. Full-tunnel will likely collapse to **CONN-2a** under
  whole-machine load. Still run `cafe-measure.sh` if it stays up long enough to
  grade usable-slow vs unusable-slow, then go to **Step 3** (Essentials Mode is the
  answer for this café).
- **If it shows CONN-2a immediately**: the fast carriers and both DNS carriers all
  failed — go straight to **Step 3**.

You do not have to guess which carrier settled: **`cafe-measure.sh` now prints the
active carrier by name** (read from `/var/run/freewire-tunnel.status`, which the
tunnel writes on connect). Its `which carrier` line says `dns_tcp` or `dns`
outright, so the throughput number is attributable. The `cafe-run.sh` battery from
Step 1 already recorded whether TCP/53 is reachable; the selected carrier and that
battery line should agree, and a disagreement is itself worth capturing.

**Step 2b (optional) — a clean, pinned `dns_tcp` number.** If auto-select is
ambiguous, or you want a `dns_tcp` measurement regardless of what the chain would
pick, pin it, reconnect, measure, then un-pin:
```
defaults write com.freewire.vpn.Freewire forceTransport dns_tcp
```
Reconnect in the app, then `bash testing/cafe-measure.sh`. The pin is a *reorder*
(it puts `dns_tcp` first but the chain still falls through if TCP/53 is blocked),
which is exactly why the `which carrier` line matters: if it reads `dns_tcp` the
number is `dns_tcp`; if it fell through to `dns`, you will see that and know TCP/53
is blocked here. **Always clear the pin afterward**, or the app stays pinned on the
next network:
```
defaults delete com.freewire.vpn.Freewire forceTransport
```

**Step 3 — validate Essentials Mode (the in-flow offer).**
This is the pending Phase-1 validation of the whole find→build→ship arc. On a
hard-throttled café, the normal connect (Step 2) collapses full-tunnel DNS and
shows **CONN-2a "Network login required"** with two buttons. Instead of "Open
Network Login", click **"Try messaging & email only"**. It should reconnect in
Essentials Mode over DNS (carrying only the allowlist, so no queue overflow) and
the panel should switch to **"Limited connectivity — messaging and email only"**
(orange, no shield). Then confirm a real message flows: send an **iMessage** (it
rides Apple's 17.0.0.0/8, in the default allowlist, no DNS needed). A page load in
a browser should FAIL (blackholed) — that is the mode working, not a bug.
Disconnect when done.

**Recover if the machine goes sluggish** (routing everything over a ~72 Kbps DNS
tunnel is slow by design):
```
sudo tunnel/freewire-tunnel --restore
```

**Then** switch back to the hotspot and tell Claude to read the two `/tmp` files.

## Reading the result → what it gates

- **TCP/53 (the primary result)** (from `cafe-run.sh`'s `TCP/53 (dns_tcp carrier)`
  line, confirmed by the carrier the app selects in Step 2): open → `dns_tcp` is the
  fast, backpressured path and likely makes this café usable; blocked → fall back to
  the UDP `dns` carrier (probably collapses) and Essentials Mode.
- **Carrier support map** (from `cafe-run.sh`): match to a `FIELD-TEST-CONTINGENCIES.md`
  row (1 = permissive, … 8 = destination-gated DNS-only). Café #2 was row 8.
- **Walled-garden**: if Cloudflare/Fastly/a generic CloudFront edge is permitted
  while our server + edge are `[SYN-RST]`, a fronted-through-them carrier is the
  candidate next build (our own CDN front is not allow-listed there).
- **DNS usability number** (from `cafe-measure.sh`): the decision on Essentials
  Mode. Roughly: can it carry a text message and a small email in a few seconds?
  → usable-slow → build the IP-only Essentials MVP against the
  `FREEWIRE_DNS_CARRIER_CAP` desk repro. If a page load never completes and even a
  message stalls → unusable-slow → Essentials Mode has nothing to carry; record it
  and stop.
- **Block classes**: any `[reset]` (not seen yet) → desync becomes worth
  considering (`DESYNC-CARRIER-SPEC.md`). All `[SYN-RST]`/`[timeout]` → desync
  stays futile.

## Known limits this test cannot get past

- **Recursor throughput.** Where a portal allows only its own resolver, the DNS
  tunnel is minimal (recursors rate-limit forwards of unique names to ~14/s).
  Server-direct DNS is the path with real speed; café #2 allowed it.
- **DNS hijacking.** A portal that answers every query with its own IP and rewrites
  destination :53 kills the DNS tunnel outright. Fundamental, no client fix.
- **A throttled-DNS *throughput* ceiling is not raisable client-side**
  (research-confirmed) — no client change makes a recursor forward unique names
  faster. But café #3 did not die on the throughput ceiling; it died on **no
  backpressure** (queue overflow → teardown) with headroom to spare. `dns_tcp`
  attacks that failure directly (TCP flow control) and, being server-direct, has no
  recursor in the path at all. So the two answers are complementary: `dns_tcp` for
  "the pipe collapses under load," Essentials Mode for "the pipe is genuinely too
  small to carry a full tunnel." Try `dns_tcp` first; fall back to carrying less.
- **macOS Captive Network Assistant** may gate app traffic while its login sheet is
  up; cancelling the sheet releases it.

## The old procedural note

`cafe-diagnostic.sh` (single-transport egress timeline) still exists and works, but
`cafe-run.sh` supersedes it for the survey — it covers all 9 carriers, the
walled-garden, and the rooted handshakes in one self-contained run.
