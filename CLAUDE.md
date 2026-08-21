# Freewire VPN: Claude Code Build Guide

You are building **Freewire**, a free consumer VPN that works on captive portal networks (hotel, airport, and café wifi that blocks internet until you pay or log in). No other consumer VPN markets this capability.

**Company:** Freewire  
**Spec corpus:** All `.md` files in this directory are authoritative. `start-here.md` is the orientation index. `engineering-handoff.md` is your primary build guide.

---

## Current State

> **Update this section at the start of each session.**

- **Active phase:** Phase 2 — Captive portal
- **In progress:** nothing
- **Last completed:** Repo restructured to a single root git repo (macos/ + server/ + tunnel/ + specs, 4 commits). Captive portal test harness added at `testing/` — runnable scripts for configs 0–6, a working HTTP CONNECT proxy, and `which-path.sh` for network-layer path verification. `tunnel/go.mod` aligned with `server/go.mod` (was 2.5 years of version skew).
- **Blocked on:** nothing — run configs 1–6 via `testing/README.md`. Config 0 already passes ("Protected · TLS/443", UTM VM Ubuntu 26.04 arm64 at 192.168.64.2).

**Known Phase 2 gaps** (do not block configs 1–6):

- `FreewireHelper` SMJobBless target does not exist — the pf kill switch is unimplemented. `TunnelManager.reconnecting` claims "kill switch active" but nothing enforces it.
- uTLS not integrated — TLS/443 uses a plain Go handshake and is DPI-fingerprintable.
- No tests, no `.github/workflows`. Bugs found in configs 1–6 should become the first regression tests.
- `server/internal/api/config_handler.go:28` reads `r.RemoteAddr`. Not a privacy violation (never logged or persisted, only echoed to the requesting client), but it is functionally wrong when `PublicHost` is unset and puts `RemoteAddr` in a live path. The CI lint rule for `RemoteAddr` would flag it.
- `captive-portal-testing-guide.md`'s `proxy.py` listing is broken — its relay threads never iterate. `testing/proxy.py` is a working replacement; fold it back into the guide.

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
All 24 error states in `error-states-spec.md` include exact user-visible message strings. Implement them verbatim. Do not paraphrase, consolidate, or add new error messages without updating the spec. Engineers reading crash reports need to match logs to spec entries by exact message text.

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
| macOS client | Swift, wireguard-go (userspace via utun — no NetworkExtension), pf kill switch via SMJobBless privileged helper, NWPathMonitor for network change detection, Sparkle (auto-update) |
| iOS client | **Deferred.** Will require Swift, WireGuardKit, NetworkExtension (NEPacketTunnelProvider), and Apple entitlement approval when resumed. |
| Server | Go, wireguard-go (reference userspace implementation) |
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
│   ├── FreewireHelper/     # Privileged helper (SMJobBless) — pf kill switch, utun setup
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
- **Authentication:** Privacy Pass blind token in `Authorization: PrivacyPass token="..."` header
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
- Privileged operations (pf kill switch, utun setup) go in the `FreewireHelper` SMJobBless target — not the main app target
- Keychain access via a dedicated `KeychainHelper` — no direct SecItem calls scattered through the codebase
- Error states: implement exact user-visible strings from `error-states-spec.md` — no paraphrasing
- uTLS on the TLS/443 path: rotate among Chrome, Safari/iOS, and Firefox fingerprints

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
