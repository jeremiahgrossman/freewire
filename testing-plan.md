# Freewire VPN — Testing Plan

**Audience:** Engineering and QA  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

## Overview

This document defines the complete testing process for Freewire VPN across all phases of development. Testing is organized as a waterfall: each stage produces a gate before the next stage begins. No stage is skipped for a production release.

```
Stage 1 → Unit Testing
Stage 2 → Integration Testing
Stage 3 → End-to-End (Happy Path)
Stage 4 → Captive Portal Simulation
Stage 5 → Performance Testing
Stage 6 → Security Review
Stage 7 → Beta (TestFlight / Sideload)
Stage 8 → Launch Gate
```

---

## Environments

### Development (`dev`)

Used by individual engineers during active development.

| Component | Setup |
|---|---|
| iOS client | Xcode Simulator + physical device (provisioned via Xcode) |
| macOS client | Local build, signed with development certificate |
| Server | Local Go binary on developer machine or AWS t3.small in `us-east-1-dev` |
| DNS tunnel | Local authoritative server on `localhost:5300`; override `tunnel.freewire.com` in `/etc/hosts` |
| Network simulation | Developer's own wifi; captive portal via virtual router (see `captive-portal-testing-guide.md`) |
| Privacy Pass | Test key pair (not production); token rate limits disabled |

**No production data. No production keys. No production AWS account.**

Engineers must not test against production servers. A separate AWS account (`freewire-dev`) hosts all development server infrastructure.

---

### Staging (`staging`)

Production-equivalent environment used for integration and end-to-end testing.

| Component | Setup |
|---|---|
| iOS client | TestFlight internal track (`freewire-staging` app identifier) |
| macOS client | Signed + notarized DMG; distributed via direct link (not Sparkle) |
| Server | AWS `freewire-staging` account; 1 managed server in `us-east-1`, CloudFormation identical to production |
| DNS tunnel | `staging.tunnel.freewire.com`; single authoritative server, US-East (AWS) |
| Certificates | Let's Encrypt staging certificates (not trusted by default — install staging root CA on test devices) |
| Privacy Pass | Production-equivalent key pair (separate from production); rate limits enabled |

---

### Production (`prod`)

Live environment. Only release builds are tested here (Stage 7 and Stage 8).

| Component | Setup |
|---|---|
| iOS client | TestFlight public beta → App Store |
| macOS client | Signed + notarized DMG; Sparkle appcast live |
| Server | AWS `freewire-prod`; managed servers in US-East |
| DNS tunnel | `tunnel.freewire.com`; single authoritative server in US-East |

---

## Stage 1 — Unit Testing

**Environment:** Developer local  
**Who runs it:** Each engineer, on every commit  
**Automated:** Yes (GitHub Actions CI, runs on every PR)  
**Gate to next stage:** 100% pass required; no skipped tests

### iOS/macOS client unit tests

Coverage targets: **80% line coverage minimum** for all modules except UI.

| Module | Tests |
|---|---|
| `WireGuardKeyManager` | Keypair generation, Keychain store/retrieve, fingerprint format |
| `FallbackChainManager` | Path ordering, timeout enforcement per path, chain abort on success |
| `DNSTunnelProtocol` | Handshake packet construction, Base32 encoding/decoding, sliding window logic, ChaCha20-Poly1305 encrypt/decrypt |
| `ICMPTunnelProtocol` | Packet construction, handshake steps, HMAC verification, payload encoding |
| `PrivacyPassClient` | Token blinding, unblinding, verification, storage, batch management, refresh trigger at <3 tokens |
| `PathUpgradeManager` | State transitions, probe timeout, migration logic, re-probe schedule |
| `ErrorStateHandler` | Each of the 34 error states: correct message string, correct retry behavior, correct error type (silent/soft/hard) |

Run with:
```bash
xcodebuild test \
  -scheme FreewireVPN \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

### Server unit tests

Coverage target: **80% line coverage** for all packages.

| Package | Tests |
|---|---|
| `internal/wireguard` | Peer add/remove, keypair handling |
| `internal/dnstunnel` | Subdomain parsing, session key derivation, sliding window, Base32 |
| `internal/icmptunnel` | Packet parsing, session management, ICMP-over-UDP framing |
| `internal/privacypass` | Blind signature issuance, verification, spent token deduplication |
| `internal/api` | Each HTTP endpoint: request parsing, response format, error codes |
| `internal/dashboard` | Auth, device CRUD, config generation, QR encoding, expiry logic |

Run with:
```bash
go test ./... -race -count=1
```

The `-race` flag is required. Any data race is a failing test.

---

## Stage 2 — Integration Testing

**Environment:** Dev or Staging  
**Who runs it:** Engineer completing a feature, before opening a PR  
**Automated:** Partial (contract tests automated; scenario tests manual)  
**Gate to next stage:** All automated contract tests pass; manual scenarios signed off

### Client–server API contract tests

Verify that the live server's API responses match `client-server-api-spec.md`. Run against the staging server.

| Test | Endpoint | Checks |
|---|---|---|
| GET /v1/server/config | Correct fields, public key format, version present |
| POST /v1/peers | Device registers, receives tunnel_ip and peer_token; Privacy Pass token accepted |
| POST /v1/peers (no token) | Returns 402 |
| POST /v1/peers (spent token) | Returns 402 with error code `TOKEN_SPENT` |
| DELETE /v1/peers/{token} | 204 on valid token; 404 on invalid |
| POST /v1/tokens/issue | Receives signed token batch; batch size 1–20 accepted |
| POST /v1/tokens/issue (>20) | Returns 400 |
| GET /v1/health | Returns status, peer count |

### Dashboard API contract tests

Verify dashboard API against `server-dashboard-api-spec.md`. Run against a dev server.

| Test | Checks |
|---|---|
| Login with correct password | Returns session token |
| Login with wrong password | Returns 401 |
| 5 wrong passwords | 6th attempt returns 429 |
| GET /devices | Returns list, correct field names and types |
| DELETE /devices/{token} (valid) | Returns 204; device absent from GET /devices |
| DELETE /devices/{token} (invalid) | Returns 404 |
| POST /config/generate | Returns config_token, expiry, urls |
| GET /config/{token}/qr | Returns PNG image |
| GET /config/{token}/download | Returns .conf file with correct fields |
| GET /config/{expired-token} | Returns 410 |

### Network intelligence API contract tests

Verify network intelligence endpoints against `client-server-api-spec.md` §Network Intelligence API. Run against staging server.

| Test | Endpoint | Checks |
|---|---|---|
| POST /v1/network/report (valid) | Returns 204; no error |
| POST /v1/network/report (missing bssid_hash) | Returns 400 |
| POST /v1/network/report (rate limit) | 11th report from same IP within 1 hour returns 429 |
| GET /v1/network/hint (below k-anonymity threshold) | Returns `{"hint_available": false}` |
| GET /v1/network/hint (≥5 reports for hash) | Returns `hint_available: true`, `recommended_path`, `skip_paths`, `confidence` |
| Server MUST NOT log IP of /v1/network/report | Verify in server access logs — no IP present for this endpoint |

---

### DNS tunnel integration

Verify the DNS tunnel end-to-end in the dev environment:

1. Client connects to dev server via DNS tunnel only (block all other paths in test environment)
2. Handshake completes in <4 seconds
3. WireGuard session established through the DNS tunnel
4. HTTP request through the tunnel returns 200
5. Throughput via iperf3: ≥500 Kbps sustained for 30 seconds
6. Keepalive maintains session for 5 minutes without data transfer

### ICMP tunnel integration

Same as DNS tunnel but via ICMP path (block DNS and TLS in test environment):

1. Client connects via ICMP tunnel only
2. Handshake completes in <2.5 seconds
3. WireGuard session established
4. HTTP request through tunnel returns 200
5. Throughput: ≥100 Kbps sustained for 30 seconds

### Privacy Pass integration

1. Client gets first token batch on first connection
2. Batch contains 10 tokens
3. Server verifies token on peer registration
4. Client background-refreshes when batch drops to 2 (test by artificially depleting batch)
5. Spent token rejected on second use (server returns 402 with error code `TOKEN_SPENT`)
6. Token re-issuance failure: connection continues, client retries silently on next connection

---

## Stage 3 — End-to-End (Happy Path)

**Environment:** Staging  
**Who runs it:** QA / engineer  
**Automated:** No (requires physical devices)  
**Gate to next stage:** All scenarios pass on both iOS and macOS

Test the full product flow on a normal network (no captive portal) against the staging server.

### Managed server path (iOS)

| Scenario | Steps | Expected |
|---|---|---|
| First install | Fresh install, no prior data | Onboarding appears |
| Onboarding completion | Complete managed server flow | Connected state |
| Connect | Tap connect | "Connected" within 10s |
| Disconnect | Tap disconnect | "Disconnected"; kill switch released |
| Kill switch | Drop tunnel artificially; check traffic | Traffic blocked until reconnect |
| Kill switch reconnect | Reconnect after kill switch | Traffic resumes; no leak window |
| Background | App backgrounded while connected | Tunnel stays connected |
| Reconnect after sleep | Lock device 5 min; unlock | Tunnel resumes or reconnects within 10s |
| Notification permission | After first connect | System prompt appears once |
| Settings — kill switch off | Disable kill switch | Warning shown; tunnel drops do not block traffic |
| Settings — kill switch on | Re-enable | Reverts to default behavior |
| DoH verification | DNS queries through tunnel | tcpdump on server: all DNS is DoH to 1.1.1.1 |

### Self-hosted server path (iOS)

| Scenario | Steps | Expected |
|---|---|---|
| Self-host onboarding | Enter server IP | Server config fetched |
| QR import | Scan QR from dashboard | Connected to self-hosted server |
| Config download import | Download .conf; import manually | Connected to self-hosted server |
| Second device | Add second device via dashboard | Both devices connect independently |
| Device revoke | Revoke device in dashboard | Revoked device cannot reconnect (SELFHOST-3) |

### macOS specific

| Scenario | Steps | Expected |
|---|---|---|
| DMG install + first launch | Mount DMG; drag to Applications; launch | System Extension approval prompt |
| System Extension approval | Approve in Settings | Extension active |
| Menu bar icon states | Connect / disconnect | Icon changes per state |
| Quit behavior | Cmd-Q while connected | Tunnel disconnects; kill switch released; no confirmation dialog |
| Sparkle update (staging) | Pin appcast to a lower version; relaunch | Update prompt appears |

---

## Stage 4 — Captive Portal Simulation

**Environment:** Dev (local network simulation per `captive-portal-testing-guide.md`)  
**Who runs it:** Engineer for each path implementation; QA before each release  
**Automated:** No  
**Gate to next stage:** All 6 test configurations pass; full test matrix completed

Follow the complete test matrix from `captive-portal-testing-guide.md`:

- Config 0: Baseline (open network) — all paths work
- Config 1: HTTP CONNECT proxy — path 1 (HTTP CONNECT) succeeds; client connects via HTTP CONNECT
- Config 2: Port 443 open only — path 2 (TLS/443) succeeds
- Config 3: DNS forwarding only — path 3 (DNS tunnel) succeeds
- Config 4: DNS local + ICMP allowed — path 4 (ICMP tunnel) succeeds
- Config 5: All traffic blocked, captive portal probe times out — CONN-2b error state; user sees "This network is blocking secure connections."
- Config 6: Upgrade test — client starts on DNS tunnel; upgrades to TLS/443 transparently

For each config:
1. Record which path was selected (tcpdump verification)
2. Confirm connection time is within the time budget for that path
3. Confirm throughput meets the target for that path
4. Confirm the user sees no error messages on success configs
5. Confirm the correct error message appears on Config 5

---

## Stage 5 — Performance Testing

**Environment:** Staging  
**Who runs it:** Engineer (before each major release)  
**Automated:** Partially (iperf3 scripted; latency checks scripted)  
**Gate to next stage:** All targets met

### Targets (from `engineering-handoff.md`)

| Metric | Target | Test method |
|---|---|---|
| Time to connected (normal network) | ≤10s from tap | Stopwatch + screen recording; 20 runs |
| Latency overhead (TLS/443) | ≤20ms avg added | ping through tunnel vs. direct; 100 samples |
| Throughput (TLS/443) | ≥50 Mbps | iperf3 -t 60 through tunnel |
| Throughput (DNS tunnel) | ≥500 Kbps; target 1–2 Mbps | iperf3 in DNS tunnel config; 60s |
| Throughput (ICMP tunnel) | ≥100 Kbps | iperf3 in ICMP tunnel config; 60s |
| Client crash rate | <0.5% of sessions | TestFlight crash report (Stage 7) |
| Captive portal success rate | ≥90% | Test matrix pass rate across configs 1–4 |

### Load test (server)

Simulate concurrent connections against the staging server:

- 10, 25, 50 simultaneous WireGuard peers
- Run for 5 minutes at each concurrency level
- Monitor: CPU, memory, WireGuard peer table, Privacy Pass issuer throughput
- Expected: server stays below 70% CPU at peer limit; no OOM; all peers connected

---

## Stage 6 — Security Review

**Environment:** Staging  
**Who runs it:** Security-focused engineer or external reviewer  
**Automated:** Tools assist; findings are manual  
**Gate to next stage:** All P0 and P1 findings resolved; P2 findings triaged

### Scope

| Area | Tests |
|---|---|
| Privacy Pass token issuance | Verify tokens cannot be linked to device identity; verify spent tokens are rejected; verify rate limits enforced per IP |
| TLS/443 path | Verify no certificate pinning bypass; verify uTLS fingerprint is current (within last 2 browser releases); verify no plaintext fallback |
| DNS tunnel encryption | Verify session key is ephemeral; verify no session key reuse across sessions; verify replay window rejects out-of-order duplicates |
| ICMP tunnel encryption | Same as DNS tunnel; verify Poly1305 tag rejection on tampered packets |
| WireGuard key storage | Verify private key never leaves Keychain; verify no key material in logs |
| Dashboard auth | Verify brute-force lockout; verify session tokens are not guessable; verify sessions invalidate on password change |
| Privacy non-negotiables | Verify no IP addresses in server logs; verify no DNS query logging; verify spent token table has no device linkability |
| CloudFormation AMI | Verify no default SSH credentials; verify SSM-only access; verify security group rules |

### Tools

- `wireshark` / `tcpdump`: verify no plaintext traffic on expected-encrypted paths
- `nmap`: verify port exposure matches `cloudformation-spec.md`
- Frida (iOS): verify Keychain access controls on private key
- Manual code review: Privacy Pass issuance path, token storage

### Finding severity

| Severity | Definition | Required action |
|---|---|---|
| P0 | Breaks privacy guarantees (IP logging, traffic metadata, key exposure) | Block release; fix before Stage 7 |
| P1 | Authentication bypass, token forgery, session hijack | Block release; fix before Stage 7 |
| P2 | Information disclosure, denial of service, missing rate limit | Fix before App Store submission; document if deferred |
| P3 | Defense-in-depth improvement | Add to backlog |

---

## Stage 7 — Beta

**Environment:** Production  
**Who runs it:** Beta testers (TestFlight internal → external)  
**Duration:** Minimum 2 weeks  
**Gate to next stage:** Crash rate <0.5% for 7 consecutive days; no P0/P1 bugs; captive portal success rate ≥90% from crash-free sessions

### TestFlight tracks

| Track | Audience | Build type |
|---|---|---|
| Internal | Engineering team | Every staging-passing build |
| External | Invited beta testers (up to 10,000) | Tagged beta builds only |

### Beta feedback collection

Collect via TestFlight feedback + in-app opt-in crash reporting (use a privacy-preserving crash reporter that does not collect device identifiers — e.g., Firebase Crashlytics with custom ID disabled, or a self-hosted Sentry instance).

Crash reports must not contain IP addresses, WireGuard keys, or any user-identifying data. Confirm this before enabling crash reporting in beta.

### Beta success criteria

- **Crash rate:** <0.5% of sessions for 7 consecutive days
- **Captive portal reports:** <5% of beta users report "VPN didn't work on captive portal network" in TestFlight feedback
- **No P0/P1 bugs** filed during beta
- **Kill switch:** no reports of traffic leaking on tunnel drop
- **DoH:** no DNS leak reports

If any criterion is not met at the end of 2 weeks, extend beta until it is.

---

## Stage 8 — Launch Gate

**Environment:** Production  
**Who runs it:** Engineering lead + product  
**Gate to release:** All items checked

This is the final checklist before TestFlight launch (iOS) and macOS DMG publication. App Store submission follows as a subsequent milestone. Derived from `product-review-checklist.md`.

### Pre-submission checklist

**Infrastructure:**
- [ ] Apple NetworkExtension entitlement (`NEPacketTunnelProvider`) approved — required before TestFlight distribution
- [ ] AWS Marketplace AMI published and one-click deploy tested end-to-end
- [ ] Managed server in US East running and reachable
- [ ] DNS tunnel authoritative server operational at `tunnel.freewire.com` (US-East)
- [ ] `vpn.freewire.com` TLS certificate valid; `tunnel.freewire.com` TLS certificate valid
- [ ] Sparkle appcast live at `https://freewire.com/appcast.xml`; EdDSA signature verified

**Client:**
- [ ] iOS app signed with Distribution certificate; provisioning profile valid
- [ ] macOS DMG signed (Developer ID Application) and notarized (notarytool passes)
- [ ] macOS DMG stapled (stapler run post-notarization)
- [ ] Gatekeeper passes on clean macOS install (no Gatekeeper warning on DMG mount)

**Privacy:**
- [ ] Privacy policy published at a stable URL
- [ ] App Store privacy nutrition label prepared — required before App Store submission (post-launch for iOS)
- [ ] Server audit: confirm no IP address logging in any code path
- [ ] Token table: confirm spent tokens delete after 30 days (verify cleanup job exists and has run)

**Functional (final smoke test on production build):**
- [ ] Connect on open network: <10 seconds
- [ ] Connect on each captive portal config (1–4): connection succeeds
- [ ] Kill switch: traffic blocked on tunnel drop; released on disconnect
- [ ] Privacy Pass: token issued on first connection; silent refresh at <3
- [ ] All error states: spot-check the most common (CONN-1, CONN-2a, CONN-2b, CONN-3, SESSION-1, PERM-1)
- [ ] iCloud backup/restore: keypair backed up to iCloud Keychain (`kSecAttrAccessible.afterFirstUnlock`); test restore on new device inherits identity (see `data-model.md` DM-5)
- [ ] QR code 24-hour expiry: confirm expired token returns 410 on scan
- [ ] macOS Sparkle: update prompt appears on version mismatch; critical update shows urgent UI

**Crash rate (from Stage 7 beta):**
- [ ] <0.5% of sessions for 7 consecutive days confirmed

All items must be checked before TestFlight launch and macOS DMG publication. App Store submission is a subsequent milestone; the nutrition label item above is a prerequisite for that step, not for TestFlight.

---

## Regression Testing

After the initial launch, run the following regression tests before every release:

| Release type | Stages required |
|---|---|
| Patch (bug fix, no new features) | Stage 1, Stage 3 (spot check), Stage 8 |
| Minor (new feature) | Stages 1–5, Stage 7 (1 week), Stage 8 |
| Major (protocol change, new tunnel path) | All stages; Stage 7 (2 weeks minimum) |
| Security fix | Stage 1, Stage 6, Stage 8; expedited; mark as critical update in Sparkle |

---

## Test Data and Fixtures

### WireGuard keypairs

Test keypairs are committed to the repository under `tests/fixtures/`. Do not use production keypairs in tests.

### Privacy Pass test keys

A test RSA key pair (2048-bit) is committed under `tests/fixtures/privacypass/`. The server in dev mode uses this key pair when `FREEWIRE_ENV=test`. Rate limits are set to 10,000 tokens/IP/24h in test mode.

### Captive portal VMs

Virtual router disk images for each captive portal configuration (Configs 1–6) are stored in the engineering team's shared storage. See `captive-portal-testing-guide.md` for setup instructions.

### Test certificates

The dev and staging environments use Let's Encrypt staging certificates. Install the Let's Encrypt staging root CA on test devices:
```
https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem
```
