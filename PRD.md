# Freewire VPN — Product Requirements Document

**Status:** Draft v0.5  
**Last updated:** 2026-06-17  
**Author:** Jeremiah Grossman

---

## 1. Overview

Freewire is a free consumer VPN that routes all device traffic through an encrypted tunnel regardless of the underlying network — including captive portal networks that block internet access until a user has paid or authenticated. Users connect to either Freewire-operated servers or their own self-hosted server deployed on a cloud provider of their choice. Setup is designed to take minutes with no technical knowledge required.

---

## 2. Background

### The problem

Public wifi networks are ubiquitous — airports, hotels, cafés, transit systems, conference centers. Many of these networks use captive portals that intercept traffic and block internet access until the user pays or authenticates. Standard VPN clients fail in these environments because the VPN tunnel cannot be established before the captive portal is satisfied.

Beyond captive portals, public wifi exposes users to traffic inspection, session hijacking, and network-level surveillance. Existing consumer VPN solutions address the surveillance problem but universally fail on captive portals, are expensive (typically $5–15/month), or require technical skill to self-host.

### The premise

A VPN that is free, easy to set up, and works on captive portal networks addresses a gap no current product fills. Freewire's captive portal bypass capability is the primary technical differentiator. Its free pricing and consumer-grade UX are the market differentiators.

---

## 3. Goals and Non-Goals

### Goals

- Route all user traffic through an encrypted VPN tunnel on any network, including captive portal networks
- Support self-hosting (user deploys their own server) and managed service (Freewire-operated servers)
- Complete onboarding — from download to connected — in under five minutes with no technical knowledge required
- Support macOS at launch; iOS in a subsequent release; Android and Windows in a later release
- Remain free for users

### Non-Goals

- Enterprise or team features (multi-user management, MDM, policy enforcement)
- Advanced privacy features beyond a standard VPN (e.g., multi-hop, Tor integration, tracker blocking)
- Browser extension — full device-level traffic routing only
- Hosting the user's traffic with zero-knowledge guarantees (not a promise made at launch)
- Pricing of any kind is out of scope for this document
- Active censorship circumvention (bypassing national firewalls such as China's Great Firewall or Iran's filtering infrastructure) is out of scope at launch. The underlying protocol stack may provide partial capability in some restricted environments, but Freewire does not engineer or test for this use case at launch.

---

## 4. Competitive Positioning

### Layer 1 — Direct competitors (consumer VPNs)

**NordVPN / ExpressVPN / Surfshark**
- Focus: Privacy and unblocking geo-restricted content
- Strengths: Large server networks, polished apps, brand recognition, streaming support
- Weaknesses: Paid ($5–15/month), fail on captive portals, not self-hostable
- Freewire advantage: Free, captive portal bypass, self-host option

**Outline VPN (Jigsaw/Google)**
- Focus: Censorship circumvention via self-hosted Shadowsocks
- Strengths: Free, open source, self-hosted, designed for hostile networks
- Weaknesses: Technical setup required, no managed server option, no captive portal bypass, limited consumer UX
- Freewire advantage: Managed server option, consumer-grade UX, captive portal bypass

**WireGuard (self-hosted)**
- Focus: Protocol layer — users build their own VPN using WireGuard
- Strengths: Fast, modern, open source
- Weaknesses: Requires significant technical skill, no managed option, no captive portal support on standard ports
- Freewire advantage: Abstraction layer, managed option, captive portal bypass, consumer UX

**Mullvad**
- Focus: Privacy-first, anonymous accounts
- Strengths: Strong privacy posture, no email required, accepts cash
- Weaknesses: Paid, no self-hosting, fail on captive portals
- Freewire advantage: Free, captive portal bypass, self-host option

### Layer 2 — Platform competitors (different category, overlapping users)

**iCloud Private Relay (Apple)**
- Focus: Safari and DNS traffic obfuscation for Apple users
- Strengths: Built in, zero setup, trusted brand
- Weaknesses: Not a full VPN, Apple ecosystem only, fails on captive portals
- Approach: Compete — Private Relay is not a VPN; Freewire covers all traffic on all platforms

**Google One VPN**
- Focus: Basic VPN for Google One subscribers
- Strengths: Bundled with existing subscription, trusted brand
- Weaknesses: Paid (via subscription), US-only servers, fails on captive portals, deprecated in 2024
- Approach: Compete

---

## 5. Users

### Primary user

A general consumer who regularly uses public wifi — airports, hotels, cafés, transit — and has encountered situations where they cannot get online without paying a captive portal fee, or wants basic protection on public networks. They are not technical. They want to install an app and have it work.

### Secondary user

A technically capable user who wants to run their own VPN server for privacy or control reasons, and wants a tool that makes that easy and that works on captive portals.

---

## 6. Features and Requirements

### 6.1 Captive Portal Bypass

**Description:** Freewire establishes an encrypted VPN tunnel on networks that use captive portals to block general internet traffic before payment or authentication.

**Requirements:**
- The client detects when it is behind a captive portal automatically, without user input, using platform-native signals (iOS: CNA/NEHotspotHelper; Android: captive portal detection API; macOS/Windows: connectivity check intercept detection)
- The client attempts tunnel establishment using a prioritized fallback chain (see §6.1 Protocol Fallback Chain below); the entire chain completes in under 10 seconds
- The tunnel is established before the captive portal is satisfied — Freewire does not require the user to authenticate with the captive portal first
- If all fallback paths fail, the client displays a plain-language explanation and offers a manual retry
- Captive portal detection and bypass require no manual network configuration by the user
- The active tunnel path (DNS, HTTP CONNECT, or TLS/443) is displayed in the client for transparency

**Protocol Fallback Chain:**

The client attempts each path in order, moving to the next on failure:

1. **HTTP CONNECT probe** — Attempt TCP tunnel through the captive portal's HTTP proxy on port 443. Fast; works on portals that expose HTTP CONNECT. ~5% of networks.
2. **TLS/443 direct** — Connect to Freewire server on port 443 with traffic that presents a valid TLS handshake. Works on portals that leave 443 open without deep packet inspection. ~80% of networks.
3. **DNS tunnel** — Encode all traffic as DNS queries to Freewire's authoritative Domain Name System (DNS) server for `tunnel.freewire.com`. Works on any network where DNS queries reach the public internet, which captive portals must allow to display their own portal page. ~14% of remaining networks.
4. **ICMP tunnel** — Encode traffic in Internet Control Message Protocol (ICMP) echo packets. Last resort; works on networks that allow external ping but block everything else. ~1% of remaining networks.

Once any path establishes a tunnel, the client renegotiates: if a faster path is now reachable through the tunnel, it upgrades transparently. The user is never asked to choose a path.

**DNS tunnel performance requirements:**
- The DNS tunnel implementation must sustain a minimum of 500 Kbps throughput using Freewire's custom authoritative DNS server
- The DNS tunnel uses EDNS0 extended responses, parallel pipelined queries, and multi-record responses to maximize payload per round trip
- See `technical-architecture.md` for the DNS tunnel protocol specification

---

### 6.2 Managed Server Connection

**Description:** Users can connect to Freewire-operated VPN servers without deploying anything themselves.

**Requirements:**
- One server region is available at launch; additional regions may be added post-launch
- No account or login is required. A device's WireGuard public key — generated locally at first launch — is its sole identity on managed servers.
- The client presents available server regions and allows the user to select one
- Connection to a managed server must succeed within 10 seconds under normal network conditions
- Server availability is displayed in the client (connected, degraded, unavailable)
- Freewire's managed servers are free to use with no in-app payment or donation mechanism
- Freewire's managed servers support the captive portal bypass protocol (6.1)

---

### 6.3 Self-Hosted Server Setup

**Description:** Users can deploy and connect to their own VPN server on a cloud provider, with Freewire providing the server software and a guided setup flow.

**Requirements:**
- Amazon Web Services (AWS) is the supported cloud provider at launch
- The setup flow guides a non-technical user through deploying a Freewire server on AWS; setup must complete in under 15 minutes for a user who has never deployed a server before
- Freewire provides a one-click deploy mechanism via AWS Marketplace (AMI and CloudFormation template); this is the sole distribution path for the server binary
- The server software is proprietary and not open source; the binary is embedded in the AMI — no separate download is required or provided
- The client connects to a self-hosted server using the same app and UX as the managed server
- Self-hosted servers support the captive portal bypass protocol (6.1)
- The user receives a shareable configuration (QR code and config file) to connect additional devices to their self-hosted server

---

### 6.4 Client Applications

**Description:** Native macOS VPN client app at launch. iOS deferred to a subsequent release. Android and Windows in a later release.

**Requirements:**
- macOS is supported at launch. iOS, Android, and Windows are post-launch.
- The macOS app uses `wireguard-go` (userspace) via direct `utun` interface — no Apple NetworkExtension framework required.
- Kill switch is implemented via `pf` firewall rules managed by an `SMJobBless` privileged helper installed at first launch.
- Network change detection uses `NWPathMonitor`.
- Distribution is signed + notarized DMG only. Mac App Store distribution is permanently incompatible with direct utun access.
- The client routes all device traffic through the tunnel when connected (full-tunnel mode)
- The client shows current connection status: disconnected, connecting, connected, error
- The client shows which server (managed or self-hosted) is active and in which region
- The client reconnects automatically when the network changes (NWPathMonitor detects path changes)
- Kill switch is enabled by default; all traffic is blocked via pf rules if the VPN tunnel drops unexpectedly until the tunnel is restored or the user explicitly disconnects
- The kill switch can be disabled by the user in settings, with a plain-language explanation of the tradeoff shown before the setting is changed
- Split-tunnel is out of scope at launch (full-tunnel mode only)
- The onboarding flow — from first launch to first successful connection — requires no more than two user decisions on the managed path (privileged helper installation, notification permission); self-hosting adds steps but is a secondary link, not the default

---

### 6.5 Onboarding

**Description:** The first-run experience that takes a user from install to connected.

**Requirements:**
- Onboarding defaults to the managed server path; self-hosting is available via a secondary link ("Running your own server? Set up self-hosting →") and does not require the user to make a path choice on the first screen
- The managed path must complete in under 2 minutes with no account creation — the app generates device keys in the background at first launch
- The self-hosted path must complete in under 15 minutes
- Each step in onboarding has a single clear action — no step requires the user to interpret technical output
- Permission prompts (VPN configuration, notifications) are explained in plain language immediately before they appear
- On completion, the user is connected and the app shows confirmation

---

### 6.6 Connection Reliability and Reconnection

**Description:** The VPN maintains a stable tunnel across network changes and recovers automatically from drops.

**Requirements:**
- The client detects network changes (wifi → cellular, network switch) and re-establishes the tunnel automatically without user action
- Reconnection attempt begins within 3 seconds of detecting a dropped tunnel
- If reconnection fails after 3 attempts, the user is notified and shown a manual retry option
- On reconnection, the kill switch remains active (no traffic leaks during reconnect)
- The client handles IP address changes on the underlying network without dropping the session where the protocol supports it

---

### 6.7 Transparency and Trust

**Description:** Freewire provides users with enough information to understand what the product does and does not protect them from.

**Requirements:**
- The app includes a plain-language explanation of what a VPN does and does not do (accessible from the main UI)
- A privacy policy must be published before launch. It must state clearly: what is logged, for how long, and under what circumstances it is disclosed. A draft exists at `privacy-policy.md` and requires legal review and an effective date before publication.
- The server software used for self-hosting is proprietary; it is distributed as a deployable binary and is not open source
- The client does not collect usage analytics without explicit, informed user consent

---

### 6.8 Distribution and Installation

**Description:** How users obtain and install the Freewire client on their device.

**iOS — Deferred (post-launch)**

iOS is not in scope at launch. When iOS work resumes, the requirements below apply.

**Requirements (post-launch):**
- iOS distribution via TestFlight first; App Store follows after entitlement approval (see Decision #9)
- The app targets the current iOS major version and the one prior
- On first launch, the app requests VPN configuration permission via Apple's NetworkExtension (NE) framework; this prompt is preceded by a plain-language explanation

**Apple entitlement dependency (apply when iOS work begins):**
- `NEPacketTunnelProvider` entitlement required before any TestFlight distribution (must be in provisioning profile)
- `NEHotspotHelper` entitlement enables automatic captive portal auth for simple portals; degrades gracefully without it; apply simultaneously with `NEPacketTunnelProvider`
- Both require manual Apple approval; typical range is days to weeks
- See `apple-entitlement-application.md`

**macOS**

**Requirements:**
- The macOS app is distributed via direct download (DMG containing a signed and notarized application bundle) at launch; Mac App Store submission follows in a subsequent release
- See Decision #8 for rationale
- The direct download app is signed with a valid Apple Developer ID certificate and notarized by Apple's notarization service — Gatekeeper will block unsigned or un-notarized builds on default macOS settings
- The direct download path hosts the DMG on Freewire's own infrastructure; the download URL is stable and versioned
- On first launch, the app requests VPN configuration permission; the same plain-language explanation required on iOS applies here
- The app supports macOS versions: current major version and the two prior at launch
- The Mac App Store version operates under App Sandbox restrictions; the NetworkExtension system extension must be declared in the entitlements file and approved by the user at first launch via a system prompt

**macOS System Extension:**
- On macOS, NEPacketTunnelProvider runs as a System Extension (replacing the legacy Kernel Extension model deprecated in macOS 10.15)
- System Extensions require user approval via a macOS system prompt on first install; this is a mandatory step that cannot be bypassed
- The System Extension approval prompt is preceded by an in-app explanation
- System Extensions installed via the Mac App Store path require the same `com.apple.developer.networking.networkextension` entitlement as iOS

**Shared distribution requirements (iOS and macOS):**
- App version numbers follow semantic versioning (major.minor.patch)
- The App Store listings for iOS and macOS are maintained under a single Apple Developer account using Universal Purchase where applicable
- Crash reporting is integrated and reports are reviewed before each release; no release ships with a known crash rate above 0.5% in the beta channel

- The direct download (signed and notarized DMG) is the primary distribution channel at launch; Mac App Store submission follows in a subsequent release
- The direct download app uses the Sparkle framework for automatic updates; the app checks for updates on launch and notifies the user when one is available, with a one-click install flow

---

### 6.9 Network Path Intelligence

**Description:** An opt-in crowdsourced signal that helps Freewire recommend faster connection paths based on anonymized reports from other users on the same network.

**Requirements:**

- **Opt-in only:** The feature is off by default. The user is offered opt-in at the moment of their first successful captive portal connection (the point of highest perceived value). If the user declines or never encounters a captive portal, the feature stays off permanently.
- **Anonymized at source:** The client hashes the network BSSID with SHA-256 on-device before any data leaves the device. The raw BSSID is never transmitted. Freewire receives only the hash.
- **No user linkage:** Reports contain no device key, no IP address, no user identifier, and no timestamp beyond week granularity. A report carries: BSSID hash, which path succeeded, which paths failed, client version.
- **K-anonymity gate:** The server only returns a hint for a given BSSID hash once at least 5 independent reports have been received. Single-device reports are stored but never surfaced.
- **Non-breaking hints:** A network intelligence hint reorders the fallback chain (try the recommended path first) but never removes paths from it. If the hint is stale or wrong, the client falls back normally.
- **Settings toggle:** The user can change their opt-in decision at any time in Settings → Privacy → Improve detection.
- Data retention: 6 months. See `data-model.md` §network_path_hint and `client-server-api-spec.md` §Network Intelligence API.

---

### 6.10 Cryptographic Privacy

**Description:** Features that move privacy guarantees from operational policy ("we don't log this") to cryptographic architecture ("we technically cannot see this").

**Launch requirements:**

- **DNS over HTTPS (DoH):** The client encrypts all DNS queries using DoH and forwards them to Cloudflare 1.1.1.1, bypassing Freewire's servers entirely. The resolver is hardcoded; not user-configurable at launch. Freewire's managed servers never see which domains a user resolves. This is a cryptographic guarantee, not a logging policy.
- **Encrypted Client Hello (ECH):** The client requests ECH when connecting to TLS destinations that support it. ECH encrypts the SNI (server name) in the TLS ClientHello using the destination server's public key, so Freewire's servers see the destination IP but not the specific hostname. ECH support is negotiated automatically; the client falls back gracefully on destinations that do not support it.

**Explicit limitation to document for users:**

- Freewire's managed servers are trusted intermediaries that decrypt VPN traffic to forward it. They can technically observe destination IP addresses, traffic timing, and volume during active sessions. The protections above reduce what can be observed; they do not eliminate it. Users with the highest privacy requirements should use the self-hosted path, where they control the server.

**Post-launch design goal:**

- **Two-relay architecture:** Route traffic through two independently operated relays in separate jurisdictions. Relay A knows the user's IP but not the destination. Relay B knows the destination but not the user's IP. No single party ever knows both. This is the architecture used by Apple's iCloud Private Relay. This is a post-launch objective that requires server infrastructure redesign.

---

## 7. Integrations

- **Cloud provider APIs** (for self-hosted setup flow): DigitalOcean, AWS, or equivalent — to be determined
- **Apple NetworkExtension framework**: NEPacketTunnelProvider (iOS and macOS) — required before TestFlight distribution; required before App Store submission; NEHotspotHelper (iOS) — separate entitlement, enables automatic captive portal authentication, degrades gracefully without it. Both require explicit Apple approval. See `apple-entitlement-application.md`.
- **Apple Developer ID + Notarization**: Required for the macOS direct download path
- **TestFlight**: Beta distribution for iOS pre-release builds
- **Sparkle**: Auto-update for macOS direct download path (decided; see §6.8)
- **Protocol libraries**: WireGuard (fast path on open networks), custom DNS tunnel implementation (captive portal bypass), platform TLS stack (TLS/443 path)
- **Authoritative DNS infrastructure**: Single authoritative DNS server for `tunnel.freewire.com` at launch (US-East, unicast). Anycast (BGP, multi-region) is a post-launch optimization — see `anycast-dns-infrastructure.md`

---

## 8. Non-Functional Requirements

- **Latency overhead:** VPN tunnel must add no more than 20ms average latency on TLS/443 and open-network paths; DNS tunnel path is exempt (inherent protocol latency)
- **Throughput (TLS/443 and open-network paths):** Must support at least 50 Mbps sustained throughput on managed servers
- **Throughput (DNS tunnel path):** Must sustain at least 500 Kbps; target 1–2 Mbps with optimized implementation
- **Uptime:** Managed server availability must be ≥99.5% per region per calendar month
- **Client startup time:** App must reach the connected state within 10 seconds on a normal network after a user taps Connect
- **Cross-platform parity:** Feature set must be equivalent across all four platforms at launch; no platform may ship a materially reduced feature set labeled as MVP
- **Data isolation:** For managed servers, no user's traffic is accessible to another user
- **No logging of user traffic content:** Traffic content must not be logged on managed servers under any circumstances

---

## 9. Out of Scope

- Enterprise features (centralized management, fleet deployment, policy enforcement)
- Multi-hop or chained VPN routing
- Browser extensions
- Tor integration
- Streaming/geo-unblocking as a marketed feature
- Android and Windows client apps (post-launch)
- IPv6-only network support (nice-to-have, not required at launch)
- Pricing, subscriptions, or any paid tier (out of scope for this document)
- Mobile device management (MDM) or corporate deployment

---

## 10. Open Questions → Decisions Log

### Open Questions

- **OQ-2 (closed):** ~~Server software open-source repository location~~ — resolved: Freewire software is proprietary. No public repository. Server software is distributed as a deployable binary only. Decision #18.
- **OQ-3 (closed):** ~~Privacy Pass token issuance timing~~ — resolved: Decision #19.

### Decisions Log

1. **Protocol selection** — resolved: DNS tunnel (custom authoritative server) as universal fallback, with a prioritized upgrade chain: HTTP CONNECT probe → TLS/443 → DNS tunnel → ICMP tunnel. Once any path is established, the client renegotiates to the fastest available path. DNS tunnel uses Freewire's custom authoritative DNS server with EDNS0, parallel pipelining, and multi-record responses to target 500 Kbps–2 Mbps throughput. See `technical-architecture.md`.

2. **Launch platforms** — resolved: macOS at launch. iOS post-launch (deferred — requires Apple NetworkExtension entitlement and a separate NE-based architecture). Android and Windows post-launch.

3. **Managed server sustainability** — resolved: free with no in-app payment or donation mechanism. No paywall, no subscription, no ads.

4. **Identity model** — resolved: No accounts. No login. A device's WireGuard public key, generated locally at first launch, is its sole identity. This is modeled on Signal's architecture — Freewire stores no data that could link a key to a person. Freewire cannot answer questions about who used the service, when, or from where — not because it refuses, but because the data does not exist.

5. **Self-hosted cloud support** — resolved: Amazon Web Services (AWS) at launch, via one-click deploy (AWS Marketplace AMI or CloudFormation template). Additional providers post-launch.

6. **Kill switch default** — resolved: on by default. Users may disable it in settings with a plain-language explanation of the tradeoff. Rationale: the primary use case is protection on hostile public networks; defaulting to maximum protection is consistent with the product's purpose.

7. **Server region count** — resolved: one region at launch. Additional regions added post-launch based on usage.

8. **macOS distribution** — resolved: direct download (signed, notarized DMG) is the primary launch channel. Sparkle framework handles automatic updates. Mac App Store submission follows in a subsequent release.

9. **iOS distribution** — deferred. iOS is post-launch. When iOS work resumes, distribution will be via TestFlight first (requires `NEPacketTunnelProvider` entitlement in provisioning profile); App Store follows after entitlement approval. See `apple-entitlement-application.md`.

10. **Self-host config contents** — resolved: server address and public key only. Private key never leaves the server. An intercepted config cannot impersonate the server.

11. **Self-host config expiry** — resolved: QR code and config file expire after 24 hours. Already-connected devices are unaffected.

12. **iOS notification permission** — resolved: requested after first successful connection on the connected confirmation screen. Notifies user when kill switch activates and when reconnection fails after 3 attempts.

13. **macOS quit behavior** — resolved: tunnel disconnects automatically on quit. No confirmation dialog. Kill switch releases on quit even if in Reconnecting state.

14. **Self-host server updates** — resolved: automatic. Server software updates itself with no user action or in-app notification required.

15. **iOS captive portal banner** — resolved: Freewire handles silently. Fallback chain continues in background. No Freewire-specific guidance shown when iOS "Sign in to network" banner appears.

16. **Client language** — resolved: Swift for iOS and macOS. WireGuardKit (the official open-source Swift/Objective-C wrapper around the reference WireGuard implementation) handles the WireGuard protocol layer. Custom DNS tunnel code is written in Swift on top of that foundation.

17. **Server language** — resolved: Go. wireguard-go (the reference userspace WireGuard implementation) is in Go; the authoritative DNS tunnel server and Privacy Pass token issuer are also built in Go. Compiles to a single static binary for the CloudFormation/AMI deploy.

18. **DoH resolver** — resolved: hardcoded to Cloudflare 1.1.1.1. Not user-configurable at launch. Consumer users should not need to know what a DNS resolver is. User-configurable resolver may be added as an advanced setting post-launch.

19. **Software license** — resolved: Freewire is proprietary, closed-source software. The codebase is not published. Dependencies (WireGuardKit, wireguard-go) are MIT-licensed and permit proprietary use with no copyleft obligation. Server software is distributed to self-hosting users as a prebuilt binary only.

20. **Privacy Pass token issuance timing** — resolved: client requests initial token batch on first connection attempt (not at launch). Client refreshes in the background when the batch drops below 3 tokens remaining. Re-issuance is silent — no user-visible state. If re-issuance fails, connection continues and the client retries silently on the next connection attempt.

---

## 11. Success Metrics

- **Captive portal success rate:** ≥90% of connection attempts on captive portal networks succeed without user intervention
- **Onboarding completion rate:** ≥80% of users who start onboarding reach a first successful connection
- **Managed path time-to-connected:** 80th percentile ≤ 2 minutes from app launch
- **Self-hosted setup completion rate:** ≥70% of users who choose self-hosted path complete setup
- **Client crash rate:** <0.5% of sessions end in an unexpected crash
- **Tunnel reliability:** ≥99% of sessions that are connected for >60 seconds maintain connection or recover automatically
