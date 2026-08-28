# Field-test runbook — real captive portal (current plan)

**Updated 2026-08-28.** This is THE plan for the next café visit. Pair it with
`FIELD-TEST-CONTINGENCIES.md` (result → what to build) and, for the throttled-DNS
outcome, `ESSENTIALS-MODE-SPEC.md` (Plan B).

Everything else is proven at the desk (all 8 carriers carry traffic on an open
network — `testing/validate-all-carriers.sh`, 7/7 routed; delegation live; cache
fallback works; false-Protected fixed; disconnect tears down on stdin EOF). The
field answers only what simulation cannot: **which carriers a real portal allows**,
and **whether the DNS floor is actually usable**.

## What this next test decides (in priority order)

1. **PRIMARY — is throttled DNS at café #2 *usable*, or does it only handshake?**
   This is the one open thread. Café #2 is a hard destination-gated portal where
   only server-direct DNS/53 escapes (~72 Kbps floor). We know it *handshakes*; we
   do not know if it carries a real message/page at a tolerable speed. The answer
   gates whether **Essentials Mode** (`ESSENTIALS-MODE-SPEC.md`) is worth building:
   usable-slow → build it; unusable-slow → DNS is only a liveness floor and that
   café is effectively unsupported for real use. Tool: `cafe-measure.sh`.
2. **Complete the portal's 8-carrier support map.** Which of wireguard, udp443,
   http_connect, tls443, wss443, cdn_wss, dns, icmp_udp the portal allows. Tool:
   `cafe-run.sh` (the full battery). Match the result to a `FIELD-TEST-CONTINGENCIES.md`
   row.
3. **Walled-garden survey.** Which third-party destinations the portal permits on
   443 (Apple/Google/Cloudflare/Fastly/a *different* CloudFront edge). If a
   frontable provider is open while our edge is not, a carrier fronted through it
   could beat this café — where our own `cdn_wss` failed. Tool: `cafe-run.sh`
   (`--walled-garden` line).
4. **Classify each block: `[SYN-RST]` vs `[reset]` vs `[timeout]`.** A `[reset]`
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
This runs, in one shot: the 8-carrier probe battery (reachability of all carriers
+ UDP/123 and IPv6 candidates, RST/timeout classification), the walled-garden
survey, and — if you give it your password once — the rooted per-carrier real-WG
handshake (`probe-transports.sh`, covering `icmp_udp` too). Writes `/tmp/freewire-cafe-*.txt`.

**Step 2 — grade the DNS floor (the primary question).**
Launch `Freewire.app`, Cancel the login sheet, click **Connect**. It falls through
the chain to DNS (the only carrier this café allows). Once it shows connected:
```
bash testing/cafe-measure.sh
```
Read-only: measures real egress, latency, sustained throughput, and a real page
load over the DNS tunnel. Writes `/tmp/freewire-cafe-measure-*.txt`. This answers
usable-slow vs unusable-slow. Then **Disconnect**.

**Recover if the machine goes sluggish** (routing everything over a ~72 Kbps DNS
tunnel is slow by design):
```
sudo tunnel/freewire-tunnel --restore
```

**Then** switch back to the hotspot and tell Claude to read the two `/tmp` files.

## Reading the result → what it gates

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
- **A throttled-DNS ceiling is not raisable client-side** (research-confirmed).
  That is *why* Plan B is Essentials Mode (carry less), not a faster DNS carrier.
- **macOS Captive Network Assistant** may gate app traffic while its login sheet is
  up; cancelling the sheet releases it.

## The old procedural note

`cafe-diagnostic.sh` (single-transport egress timeline) still exists and works, but
`cafe-run.sh` supersedes it for the survey — it covers all 8 carriers, the
walled-garden, and the rooted handshakes in one self-contained run.
