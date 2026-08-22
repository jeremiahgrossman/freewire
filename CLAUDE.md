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
- **Next action:** Configs 4 and 6 (see `testing/README.md`); the two Privacy Pass
  design decisions below; or the kill-switch cluster once a Developer ID exists.
- **Blocked on:** a Developer ID certificate, for `FreewireHelper` and for signed/notarized distribution.

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
| Ports | API `8080` (HTTPS), TLS `443`, DNS `53`, ICMP/UDP `4500`, WireGuard `51820` |
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
