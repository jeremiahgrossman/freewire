# Freewire VPN — Engineering Handoff

**Version:** 1.0  
**Status:** Ready for engineering  
**Last updated:** 2026-06-17

---

## ⚠️ Before you start

**macOS-first build — NetworkExtension is deferred.** The macOS client uses `wireguard-go` + direct `utun` access instead of `NEPacketTunnelProvider`. No Apple entitlement is required for this path. The tradeoffs: distribution is signed DMG only (no Mac App Store), kill switch is implemented via `pf` firewall through an `SMAppService` privileged helper, and network change handling uses `NWPathMonitor` instead of NE callbacks.

**iOS is deferred.** When iOS work resumes, apply for the `NEPacketTunnelProvider` entitlement at that time — approval takes days to weeks. See `apple-entitlement-application.md`.

---

## What you're building

Freewire is a free consumer VPN with one technical differentiator: it works on captive portal networks (hotel/airport/café wifi that blocks internet until you pay or log in). No consumer VPN markets this capability.

The product has two moving parts:

1. **Client apps** — iOS (deferred) and macOS native apps (Swift). **Superseded:** only iOS uses WireGuardKit + NetworkExtension; the shipped macOS client uses `wireguard-go` over a direct `utun` device instead, specifically to avoid the entitlements NetworkExtension requires — see line 66 below, which already states this correctly. Handle key generation, protocol fallback, tunnel management, and UX.
2. **Server software** — A Go binary that runs on AWS (AMI + CloudFormation). Handles the WireGuard gateway, DNS tunnel authoritative server, and Privacy Pass token issuance. Deployed by Freewire (managed servers) and by users (self-hosted).

The full product spec is in `PRD.md`. This document tells you what to build first, what decisions are already made, and where the open questions are.

---

## Document index

Read these before writing code:

| Document | What it covers | Priority |
|---|---|---|
| `PRD.md` | Full product requirements — the authoritative spec | Required |
| `ux-workflows.md` | Every user flow, screen by screen | Required |
| `error-states-spec.md` | 34 error states with exact user messages and retry logic | Required |
| `data-model.md` | Identity model, what is/isn't stored, Privacy Pass design | Required |
| `technical-architecture.md` | DNS tunnel protocol internals, fallback chain design | Required for server/tunnel work |
| `learn-here.md` | Definitions and concepts for unfamiliar terms | Reference |
| `product-review-checklist.md` | QA and launch checklist | Pre-launch |
| `client-server-api-spec.md` | HTTP API between client and managed server — device registration, Privacy Pass, health | Required for client + server |
| `dns-tunnel-protocol-spec.md` | DNS tunnel wire protocol — subdomain encoding, handshake, sliding window, encryption | Required for DNS tunnel |
| `privacy-pass-spec.md` | Privacy Pass implementation — token type, issuance, redemption, storage | Required for rate limiting |
| `cloudformation-spec.md` | AWS CloudFormation template and AMI spec | Required for self-hosted deploy |
| `build-and-release-pipeline.md` | CI/CD: build, sign, notarize, release | Required before first release |
| `sparkle-update-feed-spec.md` | Sparkle appcast format, signing, CDN hosting | Required for macOS auto-update |
| `certificate-management.md` | TLS certificates and Developer ID lifecycle | Required for macOS + managed servers |
| `anycast-dns-infrastructure.md` | Anycast DNS PoP deployment and BGP for tunnel.freewire.com | Post-launch — launch uses single unicast server in US-East |
| `captive-portal-testing-guide.md` | Simulated captive portal test environments for all eight carriers | Required for testing |
| `apple-entitlement-application.md` | NE entitlement application guidance and recommended framing | Required before TestFlight distribution |
| `icmp-tunnel-protocol-spec.md` | ICMP tunnel wire protocol — packet format, handshake, encryption, pipelining, rate limiting | Required for ICMP tunnel |
| `server-dashboard-api-spec.md` | HTTP API for self-hosted server web dashboard — auth, device management, QR/config generation | Required for self-hosted dashboard |
| `path-upgrade-manager-spec.md` | Path upgrade manager — probe schedule, migration procedure, state machine | Required for client tunnel upgrade |
| `testing-plan.md` | Full waterfall testing process across 8 stages with environments, criteria, and launch gate | Required before any release |
| `privacy-policy.md` | Full public-facing privacy policy draft — requires legal review and effective date before publication | Required before launch (TestFlight / DMG publication) |

---

## Architecture at a glance

### Client (macOS — iOS deferred)

- **Language:** Swift
- **WireGuard layer:** `wireguard-go` (userspace) via direct `utun` interface — no WireGuardKit, no NetworkExtension
- **VPN framework:** None. Tunnel opened via utun socket directly.
- **Kill switch:** `pf` firewall rules managed by an `SMAppService` privileged helper (installed once at first launch)
- **Network change detection:** `NWPathMonitor`
- **DNS:** DNS over HTTPS (DoH), hardcoded to Cloudflare 1.1.1.1. DNS queries bypass Freewire servers entirely.
- **TLS fingerprinting:** uTLS or equivalent — browser-mimicking TLS handshake on the TLS/443 path
- **Auto-update:** Sparkle framework
- **Distribution:** Signed + notarized DMG only. Mac App Store permanently incompatible with direct utun access.

### Server

- **Language:** Go
- **WireGuard implementation:** wireguard-go (reference userspace implementation, MIT license)
- **Components in one binary:** WireGuard gateway + DNS tunnel authoritative server + Privacy Pass token issuer
- **Deployment:** AWS Marketplace AMI + CloudFormation template. Single static binary embedded in AMI.
- **Self-update:** automatic, no user action required

### Identity

No accounts. No email. No Apple ID. A WireGuard keypair is generated locally at first app launch. The device's public key is its sole identity. Private key never leaves the device keychain. See `data-model.md` for the full model and what Freewire structurally cannot log even under compulsion.

---

## Protocol fallback chain

The entire reason this product exists. The client walks this chain on captive portal networks; first success establishes the tunnel. Total time budget: under 10 seconds.

| Path | Mechanism | Coverage | Time budget |
|---|---|---|---|
| 1. HTTP CONNECT | Tunnel TCP through the portal's HTTP proxy on port 443 | ~5% of networks | 2s |
| 2. TLS/443 | Connect to Freewire server on port 443 with browser-mimicking TLS | ~80% of networks | 3s |
| 3. DNS tunnel | Encode all traffic as DNS queries to `tunnel.freewire.com` | ~14% of remaining | 3s |
| 4. ICMP tunnel | Encode traffic in ICMP echo payloads | ~1% of remaining | 2s |

Once any path establishes a tunnel, the client probes faster paths through the tunnel and upgrades transparently. The user sees "Connected" and nothing else.

The DNS tunnel is the most complex component. Read `technical-architecture.md` §2–4 before starting implementation. Key design requirements: EDNS0, multi-record responses, sliding window pipelining, DH key exchange in DNS labels. At launch, the authoritative server runs on a single unicast EC2 instance in US-East — no BGP or anycast required. See `anycast-dns-infrastructure.md` §Launch Architecture.

---

## Recommended build order

> **Superseded (2026-08-30):** this whole section describes an iOS-first build order using WireGuardKit + NetworkExtension. The project actually shipped macOS-first, using `wireguard-go` over a direct `utun` device with no NetworkExtension at all — iOS was deferred entirely. Item 2's "NE permission flow" and item 13's "shares NE/tunnel codebase with iOS... System Extension approval flow" describe a design path macOS never took. **`CLAUDE.md`'s "Build Sequence" table is the current, accurate build order** (Phase 1 Foundation → Phase 2 Captive portal → Phase 3 Self-hosted → Phase 4 Privacy + reliability, matching this doc's phase names but macOS-only content). This section is kept for historical planning context, not as a build guide.

### Phase 1 — Foundation (start here)

1. **Device key lifecycle** — keypair generation at first launch, Keychain storage, fingerprint display. This underpins everything. Define restore/reinstall behavior (new keypair on reinstall is the expected behavior; see `data-model.md`).
2. **WireGuard tunnel on an open network** — get a basic WireGuardKit tunnel working against a dev server before touching captive portals. Validate Keychain integration, NE permission flow, and kill switch.
3. **Managed server connection (TLS/443 path only)** — single region, no captive portal. Get a user from onboarding to connected on a normal network first.
4. **Basic iOS UX** — onboarding, connect/disconnect, settings. See `ux-workflows.md` §2.

### Phase 2 — Captive portal

5. **Captive portal detection** — iOS: `NEHotspotHelper` / CNA; macOS: connectivity check intercept detection.
6. **HTTP CONNECT path** — simplest fallback; implement and test first.
7. **TLS/443 path with uTLS** — browser TLS fingerprint spoofing. Most captive portals are defeated here.
8. **DNS tunnel** — the most complex component. Authoritative server + client tunnel protocol. Start with the server. Budget significant time here.
9. **ICMP tunnel** — last resort; implement after DNS tunnel is stable.
10. **Path upgrade manager** — renegotiate to faster path after initial establishment.

### Phase 3 — Self-hosted + macOS

11. **Server web dashboard** — device management, QR/config generation. See `ux-workflows.md` §4.4.
12. **QR code + config file generation** — server produces; client imports. 24-hour expiry on QR codes.
13. **macOS app** — shares NE/tunnel codebase with iOS. System Extension approval flow, Sparkle auto-update, DMG packaging.
14. **Self-hosted CloudFormation template** — one-click AWS deploy. Binary embedded in AMI.

### Phase 4 — Privacy + reliability

15. **Privacy Pass token issuance** — blind token issuance on first connection, silent background refresh when < 3 tokens remain. See `data-model.md` §rate_limit_token.
16. **DoH implementation** — enforce on all DNS queries through the tunnel.
17. **ECH** — request on TLS connections where supported; silent fallback otherwise.
18. **Aggregate metrics** — hourly rollups only (peak connections, p50/p95 latency). No per-device data. See `data-model.md` §aggregate_metrics.
19. **Network intelligence** — opt-in BSSID-hashed captive portal path reporting. Client: on-device SHA-256 hash of BSSID, `POST /v1/network/report` after outcome, `GET /v1/network/hint` before connect (when opted in). Server: `network_path_hint` table with k-anonymity gate (≥5 reports before serving hint). Opt-in prompt fires at first captive portal success. See `data-model.md` §network_path_hint, `client-server-api-spec.md` §Network Intelligence API.

---

## Key decisions (already made — do not re-litigate)

These are settled. The rationale lives in `PRD.md` §10.

| # | Decision |
|---|---|
| Identity | No accounts. Device WireGuard keypair only. Never linked to any real-world identity. |
| Languages | Swift (macOS client), Go (server). iOS deferred. |
| DoH resolver | **Superseded:** now configurable (`Config.DoHEndpoints`, https-only, failover in order); Cloudflare 1.1.1.1 remains the *default* failover pair, not a hardcoded value. |
| Kill switch | **Superseded:** not shipped at all yet. `FreewireHelper` (the `SMAppService` privileged helper that would enforce it) is written and its rule generation is tested, but cannot be installed — blocked on a Developer ID Application certificate. The UI does not claim kill-switch protection until this ships (fail-closed by omission, not by a toggle default). See `error-states-spec.md` §"Interim". |
| macOS distribution | Direct download (signed, notarized DMG) + Sparkle. Mac App Store is post-launch. |
| Self-hosted deploy | AWS Marketplace only. Binary embedded in AMI. No separate download. |
| Privacy Pass timing | Request initial batch on first connection. Silent background refresh at < 3 tokens. Silent failure on re-issuance error. |
| Token exhaustion | Silent re-issuance. Never blocks the user. |
| Server updates | Automatic. No user action, no in-app notification. |
| iOS notifications | Request after first successful connection. Used only for kill-switch activation and reconnection failure. |
| macOS quit | Tunnel disconnects on quit. Kill switch releases on quit. No confirmation dialog. |
| Captive portal banner (iOS) | Handle silently. No Freewire UI shown when iOS "Sign in to network" banner appears. |
| Self-host config expiry | QR codes expire after 24 hours (confirm in engineering). Already-connected devices unaffected. |
| License | Freewire is proprietary. WireGuardKit and wireguard-go are MIT — no copyleft obligation. |

---

## Resolved engineering questions

All 11 questions are resolved below. Resolutions are also propagated to the relevant spec files.

### From error-states-spec.md

1. **Per-path timeout values** — **Resolved.** The 10-second fallback chain budget is allocated as follows:
   - HTTP CONNECT probe: **2s** (TCP connect + CONNECT response)
   - TLS/443: **3s** (TCP + TLS handshake + first keepalive response)
   - DNS tunnel: **3s** (3 DH handshake round trips at ~1s each)
   - ICMP: **2s** (enough for 3 echo request/reply cycles)
   - Total: 10s exactly. After all eight carriers fail, the captive portal probe fires (1s timeout), totaling ≤11s to CONN-2a or CONN-2b.
   - These values are added to `error-states-spec.md` §CONN-2 and `technical-architecture.md` §fallback chain.

2. **"At capacity" signal** — **Resolved.** Already specified in `client-server-api-spec.md`:
   - At capacity: server returns `capacity_available: false` in `GET /v1/server/config`, or 503 with `PEER_LIMIT_REACHED` on `POST /v1/peers` → surface CONN-4.
   - Unreachable: connection timeout or DNS resolution failure → surface CONN-3.
   - No additional signal mechanism needed.

3. **NE process detection** — **Resolved.** Detect SESSION-4 (OS-killed NE extension) via `NEVPNStatus` notifications:
   - Subscribe to `NEVPNConnection.status` changes via `NotificationCenter` with `.NEVPNStatusDidChange`.
   - On app foreground (`sceneDidBecomeActive` / `applicationDidBecomeActive`): if status is `.disconnected` and no user-initiated disconnect action was recorded in the session → classify as SESSION-4 and display the error.
   - Key: track a boolean `userInitiatedDisconnect` that is only set `true` when the user explicitly taps Disconnect. Any `.disconnected` transition without this flag = unexpected disconnect.

4. **Handshake failure threshold** — **Resolved.** For SELFHOST-4 (WireGuard key mismatch detection):
   - If `NEVPNStatus` does not reach `.connected` within **15 seconds** of `.connecting` start, on a network confirmed reachable (any HTTP request to a public host succeeds), increment a failure counter.
   - After **3 consecutive failures** in a single connection session: surface SELFHOST-4 ("Server configuration may have changed — re-scan the QR code").
   - Reset the counter on any successful connection.
   - Rationale: key mismatch produces persistent WireGuard handshake rejection; 3 failures at 15s each = 45s before surfacing the error, which is acceptable for a self-host-only edge case.

5. **Kill switch during sleep** — **Resolved.** Behavior when device locks/sleeps while connected:
   - The NE extension continues running during normal lock. WireGuard keepalives maintain the tunnel. No change from the user's perspective.
   - If iOS suspends the extension during deep sleep and the tunnel drops on wake: kill switch holds (all traffic blocked). Client begins automatic reconnection using the full fallback chain.
   - If reconnection succeeds: traffic flows normally. No user notification.
   - If reconnection fails after 3 attempts: kill switch remains engaged. User receives a notification: "VPN reconnection failed. Your traffic is blocked until you reconnect or disconnect."
   - Kill switch never releases automatically without user action (Reconnect or Disconnect) unless the user has explicitly disabled the kill switch in Settings.

6. **iCloud backup behavior** — **Resolved.** The WireGuard keypair **is** backed up to iCloud Keychain.
   - Keychain item uses `kSecAttrAccessible.afterFirstUnlock` (backed up, encrypted, available after first unlock on new device).
   - Rationale: seamless device migration is the correct default. A new device restoring from backup inherits the same WireGuard peer identity — the user can connect without re-onboarding.
   - Users who want to reset their identity (e.g., when selling a device) use Settings → "Reset Device Key", which generates a new keypair and de-registers the old peer.
   - This decision is added to `data-model.md`.

### From technical-architecture.md

7. **EDNS0 stripping** — **Resolved.** Mitigation:
   - During the handshake (Step 2 server response), the server reports whether it received an EDNS0-capable query. If the server did not see EDNS0, it sets `Flags` Bit 0 = 0 in the handshake response.
   - The client detects this and enters **EDNS0-degraded mode**: reduce OPT record size to 512, use higher query frequency (4× normal rate) to compensate for smaller payloads per response (~250 bytes vs. ~3500 bytes).
   - Degraded throughput: ~500 Kbps (vs. ~1–2 Mbps with EDNS0). Acceptable for a last-resort fallback path.
   - This behavior is added to `dns-tunnel-protocol-spec.md`.

8. **DNS TTL caching** — **Resolved.** Stale cache detection via sequence numbers:
   - All DNS queries carry a 4-byte sequence number in the encoded payload. The server echoes this sequence number in the encrypted response.
   - If the client receives a response with an unexpected sequence number (older than the current window base), it treats the response as cached and **rotates the subdomain prefix**: subsequent queries use a new entropy prefix derived from a monotonic counter.
   - The new prefix is statistically guaranteed to be a cache miss (resolver has no prior response for it).
   - This behavior is added to `dns-tunnel-protocol-spec.md`.

9. **ICMP rate limiting** — **Already resolved in `icmp-tunnel-protocol-spec.md`.** Hard cap is **20 packets/second** with AIMD below that — sends as fast as AIMD allows, never exceeding 20 pps. At maximum payload (1416 bytes), 20 pps ≈ 227 Kbps theoretical ceiling. Typical real-world throughput: 100–500 Kbps. This meets the ICMP tunnel target (≥500 Kbps is best-effort; 100–500 Kbps is the realistic range).

10. **uTLS maintenance cadence** — **Resolved.** TLS fingerprint update process:
    - Update the uTLS fingerprint library **quarterly** (aligned with major Chrome/Safari release cycles).
    - Trigger an **out-of-cycle update within 30 days** if a new major browser version's fingerprint becomes dominant in the wild (Chrome updates every ~6 weeks).
    - Fingerprint selection: rotate among 3 current fingerprints (latest Chrome, latest Safari/iOS, latest Firefox) to reduce fingerprinting correlation between Freewire users.
    - This cadence is added to `build-and-release-pipeline.md`.

11. **DH exchange in DNS labels** — **Already resolved in `dns-tunnel-protocol-spec.md`.** The minimum is **3 round trips**: Step 1 (ClientHello query → Step 2 server response with ServerHello), Step 2 client query (MAC confirmation) → server "OK" response, then data flow begins on the next query. X25519 public keys (32 bytes → 58 Base32 chars) fit in a single DNS label.

---

## Error handling

All 34 error states are specified in `error-states-spec.md`. Each entry has: trigger condition, immediate behavior, retry logic, exact user-visible message, error type (silent / soft warning / hard block), and recovery path.

Implement these exactly. Do not invent user-facing copy — use the strings in the spec. Do not make architectural assumptions about retry counts or timeout values that differ from the spec without updating it.

---

## Privacy constraints — non-negotiable

These are not product preferences. They are architectural requirements.

- **No client IP addresses are ever logged** — not on connection, not in error logs, not anywhere.
- **No session start/end times per device** — aggregate hourly rollups only.
- **No destination IPs or traffic metadata** — Freewire sees the tunnel, not what's in it.
- **No device identifiers** — not UDID, not IDFA, nothing beyond the WireGuard public key.
- **DNS queries are not logged** — not even on the DNS tunnel path. The DNS labels carry encrypted payload; session keys are ephemeral.
- **Spent Privacy Pass token hashes are retained for 30 days then deleted.** They cannot be linked to any device. This is the only persistent record associated with a connection.

If a logging decision arises during implementation that is not covered by `data-model.md`, default to not logging and raise it explicitly before adding any new persistent data.

---

## Performance targets

| Metric | Target |
|---|---|
| Time to connected (normal network) | ≤ 10s from tap |
| Time to connected (managed path, 80th percentile) | ≤ 2 min from app launch including onboarding |
| Latency overhead (TLS/443 and open network paths) | ≤ 20ms average added latency |
| Throughput (TLS/443 and open network paths) | ≥ 50 Mbps sustained |
| Throughput (DNS tunnel path) | ≥ 500 Kbps; target 1–2 Mbps |
| Managed server uptime | ≥ 99.5% per region per calendar month |
| Client crash rate | < 0.5% of sessions |
| Captive portal success rate | ≥ 90% without user intervention |

---

## Pre-launch checklist

The full checklist is in `product-review-checklist.md`. Items to not miss:

- Apple NetworkExtension entitlement (`NEPacketTunnelProvider`) approved — required before TestFlight distribution. **This applies to the deferred iOS client only.** The macOS launch blocker is different: a **Developer ID Application certificate**, needed to install `FreewireHelper` (the `SMAppService` kill-switch helper) and to sign/notarize the distributed DMG. See `CLAUDE.md`.
- TestFlight build uploaded, invite links working (iOS, deferred)
- Privacy policy (`privacy-policy.md`) reviewed by legal, effective date set, and published at stable URL
- TestFlight beta channel operational with crash rate < 0.5%
- macOS DMG signed and notarized (Gatekeeper blocks unsigned builds)
- Sparkle update feed live and tested
- AWS Marketplace AMI published and one-click deploy tested end-to-end
- Server web dashboard tested (device revocation, QR generation, config download)
- Kill switch tested: traffic blocked on tunnel drop, released on explicit disconnect
- iCloud backup / restore behavior defined and tested (see `data-model.md` DM-5)
- Privacy Pass token refresh tested (batch < 3, silent re-issuance)
- DoH enforcement verified — no DNS leaks through the tunnel
- QR code 24-hour expiry tested
- All 34 error states implemented and tested against the strings in `error-states-spec.md`
