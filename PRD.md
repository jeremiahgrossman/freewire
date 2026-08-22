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
- The tunnel is established before the captive portal is satisfied — Freewire does not require the user to authenticate with the captive portal first. **This is the product's central claim and it is not yet demonstrable.** Getting through an unauthenticated portal depends on the DNS tunnel, which needs the tunnel zone delegated to the server so the portal's own resolver forwards its queries. No such delegation exists (OQ-4). Every other transport is blocked by a portal until the user logs in, so today the client detects the portal, opens it, and connects afterwards — correct behaviour, but not this requirement.
- If all fallback paths fail, the client displays a plain-language explanation and offers a manual retry
- Captive portal detection and bypass require no manual network configuration by the user
- The active tunnel path (DNS, HTTP CONNECT, or TLS/443) is displayed in the client for transparency

**Protocol Fallback Chain:**

The client attempts each path in order, moving to the next on failure:

1. **HTTP CONNECT probe** — Attempt TCP tunnel through the captive portal's HTTP proxy on port 443. Fast; works on portals that expose HTTP CONNECT. ~5% of networks.
2. **TLS/443 direct** — Connect to Freewire server on port 443 with traffic that presents a valid TLS handshake. Works on portals that leave 443 open without deep packet inspection. ~80% of networks.
3. **DNS tunnel** — Encode all traffic as DNS queries to Freewire's authoritative Domain Name System (DNS) server for `t.pinghop.net`. Works on any network where DNS queries reach the public internet, which captive portals must allow to display their own portal page. ~14% of remaining networks.
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
- The client presents available server regions and allows the user to select one. **Not built.** One region exists and the client connects to a configured server address, so there is nothing to choose between. This becomes real when a second region does.
- Connection to a managed server must succeed within 10 seconds under normal network conditions
- Server availability is displayed in the client (connected, degraded, unavailable). **Partially built.** The client surfaces connected, reconnecting, blocked, portal and no-network states, and the server reports capacity, but there is no degraded indicator distinct from a failed connection.
- Freewire's managed servers are free to use with no in-app payment or donation mechanism
- Freewire's managed servers support the captive portal bypass protocol (6.1)

---

### 6.3 Self-Hosted Server Setup

**Description:** Users can deploy and connect to their own VPN server on a cloud provider, with Freewire providing the server software and a guided setup flow.

**Requirements:**
- Amazon Web Services (AWS) is the supported cloud provider at launch
- The setup flow guides a non-technical user through deploying a Freewire server on AWS; setup must complete in under 15 minutes for a user who has never deployed a server before
- Freewire provides a one-click deploy mechanism via AWS Marketplace (AMI and CloudFormation template); this is the sole distribution path for the server binary. **Not built.** Deployment today is `deploy/launch-aws.sh` and `deploy/provision.sh`, which stand up a working server on EC2 in one command but assume an operator with AWS credentials and a terminal. That is sufficient for the single-user scope and does not meet the "non-technical user in under 15 minutes" requirement above, which the Marketplace path exists to satisfy.
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
- Kill switch is implemented via `pf` firewall rules managed by a privileged helper installed at first launch. **Superseded in detail:** `SMJobBless` was deprecated in macOS 13 and the design moved to `SMAppService`. Neither is installed yet — see §6.6 and OQ-5.
- Network change detection uses `NWPathMonitor`.
- Distribution is signed + notarized DMG only. Mac App Store distribution is permanently incompatible with direct utun access.
- The client routes all device traffic through the tunnel when connected (full-tunnel mode)
- The client shows current connection status: disconnected, connecting, connected, error
- The client shows which server (managed or self-hosted) is active and in which region. **Region is not shown** — one region exists, so there is nothing to disambiguate. Becomes real alongside the region picker in §6.2.
- The client reconnects automatically when the network changes (NWPathMonitor detects path changes)
- Kill switch is enabled by default; all traffic is blocked via pf rules if the VPN tunnel drops unexpectedly until the tunnel is restored or the user explicitly disconnects. **Not yet true, and the default is currently the opposite:** while the switch is unenforced the preference defaults to off, so no user carries a stored `true` that implies protection they do not have. Restored to on when the helper ships.
- The kill switch can be disabled by the user in settings, with a plain-language explanation of the tradeoff shown before the setting is changed. **Currently the control is disabled entirely,** with the caption "Not available yet. When the VPN drops, traffic is not blocked." — per `error-states-spec.md` §Interim. There is nothing to opt out of until the helper ships.
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
- Permission prompts (VPN configuration, notifications) are explained in plain language immediately before they appear. **The macOS prompt is not the one described:** with no NetworkExtension there is no VPN-configuration prompt. The privileged step is administrator authorisation for the tunnel helper, which is what onboarding must explain instead.
- On completion, the user is connected and the app shows confirmation

---

### 6.6 Connection Reliability and Reconnection

**Description:** The VPN maintains a stable tunnel across network changes and recovers automatically from drops.

**Requirements:**
- The client detects network changes (wifi → cellular, network switch) and re-establishes the tunnel automatically without user action
- Reconnection attempt begins within 3 seconds of detecting a dropped tunnel
- If reconnection fails after 3 attempts, the user is notified and shown a manual retry option
- On reconnection, the kill switch remains active (no traffic leaks during reconnect). **Not yet true.** The kill switch is unimplemented: the privileged helper's rule generation is written and tested, and the pf logic is now runnable, but nothing in the app invokes it and it has never run against live pf. Until it ships, traffic flows unprotected during reconnection and the UI says so verbatim (SESSION-1, SESSION-2, and the disabled preferences toggle in `error-states-spec.md` §Interim). That section is deleted and this requirement restored when the helper lands.
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
- The macOS app is distributed via direct download (DMG containing a signed and notarized application bundle). **Corrected:** this previously said "Mac App Store submission follows in a subsequent release", contradicting §6.4, which states the App Store is *permanently* incompatible with direct `utun` access. §6.4 is the accurate one: sandboxing rules out the interface the tunnel depends on, so there is no subsequent release in which this becomes possible without abandoning the architecture. Direct download is the only macOS channel.
- See Decision #8 for rationale
- The direct download app is signed with a valid Apple Developer ID certificate and notarized by Apple's notarization service — Gatekeeper will block unsigned or un-notarized builds on default macOS settings
- The direct download path hosts the DMG on Freewire's own infrastructure; the download URL is stable and versioned
- On first launch, the app requests administrator authorisation to install the tunnel helper. **Not a VPN configuration prompt:** that prompt belongs to NetworkExtension, which macOS does not use here.
- The app supports macOS versions: current major version and the two prior at launch

**macOS System Extension — no longer applicable.**

This block described NEPacketTunnelProvider running as a System Extension, with
its approval prompt and entitlement. None of it applies: the macOS client drives
a `utun` device directly and ships no system extension. The privileged component
is a launchd daemon applying `pf` rules, which needs a Developer ID for
`SMAppService` registration but no NetworkExtension entitlement and no Apple
approval beyond notarization. Retained as a record of the original design, which
was reversed when the transports turned out to need socket control that
NEPacketTunnelProvider does not expose.

**Shared distribution requirements (iOS and macOS):**
- App version numbers follow semantic versioning (major.minor.patch)
- App Store listings (iOS only — see above) are maintained under a single Apple Developer account
- Crash reporting is integrated and reports are reviewed before each release; no release ships with a known crash rate above 0.5% in the beta channel

- The direct download (signed and notarized DMG) is the **only** macOS distribution channel. There is no Mac App Store path: sandboxing rules out direct `utun` access, so submission is not deferred, it is architecturally excluded.
- The direct download app uses the Sparkle framework for automatic updates; the app checks for updates on launch and notifies the user when one is available, with a one-click install flow

---

### 6.9 Network Path Intelligence

**Status: specified, deliberately not built.** The requirements below stand as written; the implementation is declined for now. Two things changed after they were drafted. Reconnect learned to remember the last working transport, so a device's own history already goes straight to the right path and the crowdsourced hint only helps on a first connection to an unseen network. And a BSSID hash turns out not to be anonymous in the way the word implies: the input space is small and heavily enumerated, so anyone holding a wardriving database can hash it and reverse these by lookup, making this the one feature that would transmit a location signal. The preferences toggle in the requirements below must not be added while this stands — a toggle for a feature that does nothing is its own false claim. See `DECISIONS.md` §NETWORK-INTELLIGENCE for what would make it acceptable.

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

- **DNS over HTTPS (DoH):** *Implemented, with a documented exception.* The client runs a DoH forwarder on loopback, points the system resolver at it, and relays every query over HTTPS to Cloudflare 1.1.1.1. Queries cross the tunnel as TLS to port 443, so Freewire's servers cannot read them. The resolver is hardcoded; not user-configurable at launch.

  **The exception:** DoH is not used on the DNS and ICMP transports. A DoH round trip over those paths measured 5–10 seconds, and because the takeover is system-wide, every application on the machine pays it — which stops the machine working rather than merely slowing the VPN. On those two transports the system resolver is left alone and queries go to the network's own resolver in cleartext. The user is told (DNS-1 in `error-states-spec.md`). See `DECISIONS.md` §DNS-ON-SLOW-TRANSPORTS for the alternatives considered and what would reverse this.

- **Encrypted Client Hello (ECH):** *Removed from scope. The requirement as written cannot be implemented by a VPN.* ECH encrypts the SNI in a TLS handshake, but the handshake carrying a user's destination is end-to-end between their browser and the site; Freewire only relays those packets and cannot rewrite or encrypt them without breaking the connection. ECH is deployed by the browser and the destination, never by an intermediary. Freewire benefits passively wherever both ends already support it and can do nothing to bring that about.

  ECH would still apply to Freewire's *own* TLS connection to its server, to stop a portal blocking by hostname. On a server addressed by bare IP that is also worth nothing, since SNI cannot carry an IP and the client's ClientHello contains no hostname at all (confirmed by packet capture). It becomes worth building only for a managed server reached by name. See `DECISIONS.md` §WHAT-THE-SERVER-CAN-SEE.

**Explicit limitation to document for users:**

- Freewire's managed servers are trusted intermediaries that decrypt VPN traffic to forward it. They can observe destination IP addresses, the hostnames in TLS handshakes they relay, traffic timing, and volume during active sessions. **Destination visibility is structural:** a server that forwards a packet must know where to send it, and no single-hop VPN can avoid this. What Freewire does instead is not keep it — connections are counted into hourly totals and never logged individually, enforced by tests that fail if a per-connection log statement is reintroduced. The claim that survives scrutiny is "we do not keep it", not "we cannot see it". The product's user-facing copy was corrected to say so. Users with the highest privacy requirements should use the self-hosted path, where they control the server.

**Post-launch design goal:**

- **Two-relay architecture:** Route traffic through two independently operated relays in separate jurisdictions. Relay A knows the user's IP but not the destination. Relay B knows the destination but not the user's IP. No single party ever knows both. This is the architecture used by Apple's iCloud Private Relay. This is a post-launch objective that requires server infrastructure redesign.

---

## 7. Integrations

- **Cloud provider APIs** (for self-hosted setup flow): DigitalOcean, AWS, or equivalent — to be determined
- **Apple NetworkExtension framework**: NEPacketTunnelProvider (iOS only) — **not used on macOS.** The macOS client drives a `utun` device directly with wireguard-go, because the transports need raw socket and routing control that NEPacketTunnelProvider does not expose, and because that choice permanently rules out the Mac App Store. Required before TestFlight distribution; required before App Store submission; NEHotspotHelper (iOS) — separate entitlement, enables automatic captive portal authentication, degrades gracefully without it. Both require explicit Apple approval. See `apple-entitlement-application.md`.
- **Apple Developer ID + Notarization**: Required for the macOS direct download path
- **TestFlight**: Beta distribution for iOS pre-release builds
- **Sparkle**: Auto-update for macOS direct download path (decided; see §6.8)
- **Protocol libraries**: wireguard-go over `utun` (fast path on open networks), custom DNS and ICMP tunnel implementations in Go (captive portal bypass), uTLS for the TLS/443 and HTTP CONNECT paths — **not the platform TLS stack**, because the fingerprint has to be rotated among real browser profiles so a portal's DPI cannot identify the handshake. The control plane uses `Network.framework` with its own verification, since App Transport Security rejects a self-signed certificate before any pinning code is consulted.
- **Authoritative DNS infrastructure**: Single authoritative DNS server for `t.pinghop.net` at launch (US-East, unicast). Anycast (BGP, multi-region) is a post-launch optimization — see `anycast-dns-infrastructure.md`

---

## 8. Non-Functional Requirements

> **Measured against the build, 2026-08-22.** Throughput on TLS/443 (166 Mbps
> against a 50 Mbps floor) and time to connected (2.6s against a 10s ceiling)
> are met with margin. Two remain untested rather than failed: latency overhead
> was never isolated — 108 ms was measured through the tunnel to us-east-1, but
> overhead is that minus the direct RTT to the same host, which was not
> recorded — and DNS tunnel throughput has never been measured at all, only its
> ability to carry traffic. Uptime does not apply to a single development
> server.

- **Latency overhead:** VPN tunnel must add no more than 20ms average latency on TLS/443 and open-network paths; DNS tunnel path is exempt (inherent protocol latency)
- **Throughput (TLS/443 and open-network paths):** Must support at least 50 Mbps sustained throughput on managed servers
- **Throughput (DNS tunnel path):** Must sustain at least 500 Kbps; target 1–2 Mbps with optimized implementation
- **Uptime:** Managed server availability must be ≥99.5% per region per calendar month
- **Client startup time:** App must reach the connected state within 10 seconds on a normal network after a user taps Connect
- **Cross-platform parity:** Feature set must be equivalent across all platforms *that ship*; no platform may ship a materially reduced feature set labeled as MVP. **Corrected:** this said "all four platforms at launch", which contradicts Decision 2 — only macOS ships at launch, with iOS, Android and Windows post-launch. The parity requirement binds whenever a second platform appears, not at launch.
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
- IPv6-only network support (nice-to-have, not required at launch). **The build goes further than "not supported":** the tunnel disables IPv6 on every active network service for the duration of a session and restores it on teardown. Carrying v6 inside the tunnel is the better answer and is not in scope; until it is, leaving v6 enabled would send v6-reachable traffic outside the tunnel in the clear while the client reported "Protected". On an IPv6-only network the client therefore does not degrade — it has no connectivity at all.
- Pricing, subscriptions, or any paid tier (out of scope for this document)
- Mobile device management (MDM) or corporate deployment

---

## 10. Open Questions → Decisions Log

> **Synced with the implementation on 2026-08-22.** Requirements that the build
> diverged from are marked in place rather than rewritten, so the original
> intent stays legible next to what was actually done and why. Decisions 21–27
> were taken during implementation and had no entry here.
>
> `DECISIONS.md` carries the long form for the five choices that traded one
> stated goal against another, including what evidence supports each and what
> would justify reopening it. This log is the index; that file is the argument.

### Open Questions

- **OQ-4 (delegation done; field test pending):** DNS tunnel delegation. The transport needs its zone delegated to the server so a portal's own resolver forwards its queries. `freewire.com` belongs to a third party, so a dedicated domain was registered instead: **`pinghop.net`** (Cloudflare registrar), tunnel zone **`t.pinghop.net`**. The code no longer hardcodes the zone — the server config owns it and advertises it to the client (default `t.pinghop.net`), so a rotation is a config change, not a rebuild. **Delegation verified live 2026-08-22:** the parent zone answers `t.pinghop.net NS ns1.pinghop.net` with a glue `A ns1.pinghop.net 52.203.246.145` in the ADDITIONAL section (confirmed with a non-recursive query straight to Cloudflare, so it does not depend on the server being up). **Server redeployed 2026-08-22** with the server-supplied-zone binary (WireGuard key unchanged, so the client pin still holds); `/v1/server/config` now advertises `t.pinghop.net`. **Protocol proven end to end through real recursive resolvers (2026-08-22).** Beyond a bogus-name reachability check, the full DNS tunnel handshake — ClientHello, ServerHello, ClientConfirm, then a data-plane poll — completes through the delegation via four independent resolvers: Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9 `9.9.9.9`, and a home router forwarding to a consumer ISP resolver (the closest analog to a captive portal's own resolver). Each ran in 250–420 ms and the server issued a distinct session token each time, so these are genuinely separate handshakes, not a cache. Exercised with `freewire-tunnel --dns-probe --resolver <ip>`, which runs only the handshake and touches no system routing or resolver, so it is safe on a machine in use. **What remains for the field test:** a *hostile* portal's resolver that rate-limits or runs DNS-tunnelling detection, and sustained throughput (the probe is a handshake plus one poll, not a data transfer). The mechanism works; what is unproven is whether an adversarial network lets it keep working. A separate domain for the API endpoint (so a block on one does not take out both) is a later registration.
- **OQ-5 (open):** Kill switch delivery. `SMAppService` registration requires a Developer ID; the machine has none. The helper is buildable and runnable under `sudo`, which is enough to develop and test against real pf, but not to ship. Distribution needs the certificate regardless, and no workaround should be entertained — the alternatives all end in instructing users to bypass Gatekeeper to install a VPN that asks for root.
- **OQ-2 (closed):** ~~Server software open-source repository location~~ — resolved: Freewire software is proprietary. No public repository. Server software is distributed as a deployable binary only. Decision #18.
- **OQ-3 (closed):** ~~Privacy Pass token issuance timing~~ — resolved: Decision #19.

### Decisions Log

1. **Protocol selection** — resolved: DNS tunnel (custom authoritative server) as universal fallback, with a prioritized upgrade chain: HTTP CONNECT probe → TLS/443 → DNS tunnel → ICMP tunnel. Once any path is established, the client renegotiates to the fastest available path. DNS tunnel uses Freewire's custom authoritative DNS server with EDNS0, parallel pipelining, and multi-record responses to target 500 Kbps–2 Mbps throughput. See `technical-architecture.md`.

2. **Launch platforms** — resolved: macOS at launch. iOS post-launch (deferred — requires Apple NetworkExtension entitlement and a separate NE-based architecture). Android and Windows post-launch.

3. **Managed server sustainability** — resolved: free with no in-app payment or donation mechanism. No paywall, no subscription, no ads.

4. **Identity model** — resolved: No accounts. No login. A device's WireGuard public key, generated locally at first launch, is its sole identity. This is modeled on Signal's architecture — Freewire stores no data that could link a key to a person. Freewire cannot answer questions about who used the service, when, or from where — not because it refuses, but because the data does not exist.

5. **Self-hosted cloud support** — resolved: Amazon Web Services (AWS) at launch, via one-click deploy (AWS Marketplace AMI or CloudFormation template). Additional providers post-launch.

6. **Kill switch default** — resolved: on by default *as the end state*; currently off, because the switch is unenforced and a stored `true` would imply protection that does not exist. Users may disable it in settings with a plain-language explanation of the tradeoff. Rationale: the primary use case is protection on hostile public networks; defaulting to maximum protection is consistent with the product's purpose.

7. **Server region count** — resolved: one region at launch. Additional regions added post-launch based on usage.

8. **macOS distribution** — resolved: direct download (signed, notarized DMG) is the *only* channel. Sparkle handles automatic updates. **Corrected:** this said Mac App Store submission follows in a subsequent release, which contradicts the architecture — sandboxing rules out the direct `utun` access the tunnel depends on, so there is no later release in which it becomes possible short of rebuilding on NetworkExtension.

9. **iOS distribution** — deferred. iOS is post-launch. When iOS work resumes, distribution will be via TestFlight first (requires `NEPacketTunnelProvider` entitlement in provisioning profile); App Store follows after entitlement approval. See `apple-entitlement-application.md`.

10. **Self-host config contents** — resolved: server address and public key only. Private key never leaves the server. An intercepted config cannot impersonate the server.

11. **Self-host config expiry** — resolved: QR code and config file expire after 24 hours. Already-connected devices are unaffected.

12. **iOS notification permission** — resolved: requested after first successful connection on the connected confirmation screen. Notifies user when kill switch activates and when reconnection fails after 3 attempts.

13. **macOS quit behavior** — resolved: tunnel disconnects automatically on quit. No confirmation dialog. Kill switch releases on quit even if in Reconnecting state.

14. **Self-host server updates** — resolved: automatic. Server software updates itself with no user action or in-app notification required.

15. **iOS captive portal banner** — resolved: Freewire handles silently. Fallback chain continues in background. No Freewire-specific guidance shown when iOS "Sign in to network" banner appears.

16. **Client language** — **superseded.** Originally: Swift throughout, with WireGuardKit handling the protocol layer and the DNS tunnel written in Swift on top. As built: the macOS app is Swift, but the tunnel is a separate Go binary (`tunnel/cmd/freewire-tunnel`) using wireguard-go over a `utun` device, and every transport — HTTP CONNECT, TLS/443 with uTLS, the DNS tunnel, ICMP/UDP — is Go. WireGuardKit is explicitly not used on macOS. The split exists because the transports need raw socket and routing control that a NetworkExtension-shaped API does not give, and because the same Go code then runs on both ends of the DNS and ICMP protocols, so the two implementations cannot drift. The privileged work (routing, DNS takeover, pf) lives in that binary, which runs as root; the app never does.

17. **Server language** — resolved: Go. wireguard-go (the reference userspace WireGuard implementation) is in Go; the authoritative DNS tunnel server and Privacy Pass token issuer are also built in Go. Compiles to a single static binary for the CloudFormation/AMI deploy.

18. **DoH resolver** — resolved: hardcoded to Cloudflare 1.1.1.1. Not user-configurable at launch. Consumer users should not need to know what a DNS resolver is. User-configurable resolver may be added as an advanced setting post-launch.

19. **Software license** — resolved: Freewire is proprietary, closed-source software. The codebase is not published. Dependencies (wireguard-go, uTLS, cloudflare/circl for the blind signatures) are MIT- or BSD-licensed and permit proprietary use with no copyleft obligation. Server software is distributed to self-hosting users as a prebuilt binary only.

20. **Privacy Pass token issuance timing** — resolved: client requests initial token batch on first connection attempt (not at launch). Client refreshes in the background when the batch drops below 3 tokens remaining. Re-issuance is silent — no user-visible state. If re-issuance fails, connection continues and the client retries silently on the next connection attempt.

21. **Rate-limiting token issuance** — resolved: proof of work, plus a global budget as an absolute ceiling. Issuance is unauthenticated by design, so without a cost anyone could mint tokens freely and the rate limit those tokens exist to impose would be free to bypass. Every ordinary rate-limit key was unavailable: the client IP must not exist in the process, a device handle would defeat blind signing by making issuance correlatable with redemption, and there are no accounts. Proof of work charges the caller in CPU rather than in identity — a challenge is an HMAC over a coarse time window, verifiable without being stored, and each solution is single-use. A batch costs roughly 0.08s on one core. The global budget remains because work alone cannot cap an attacker with more cores; its cost is that one heavy caller can exhaust it for everyone, accepted while there is one user.

22. **Token expiry** — resolved: a coarse expiry in whole UTC days, carried inside the signed message. Wire format is `type(2) || expiry(4) || nonce(32) || signature(256)`. Previously a token was valid forever while its spent record was dropped after thirty days, so anyone holding one past that window could replay it indefinitely. An issuer key epoch was the alternative and was rejected as more machinery than the problem needs; it would also have closed CRYPTO-09, which consequently stays open. Two non-obvious properties: the issuer signs blindly and cannot set the expiry, so the client does and the server refuses anything over-dated at redemption; and the granularity is whole days because a finer timestamp would partition tokens into cohorts small enough to identify a device, undoing the blinding. See `DECISIONS.md` §TOKEN-EXPIRY.

23. **Server trust for self-hosted deployments** — resolved: two independent pins. The server's WireGuard public key is pinned out of band by the user, and the certificate's public key is pinned trust-on-first-use. The second exists because accepting any certificate — justified by the WireGuard pin — left `POST /v1/peers` carrying a Privacy Pass token an interceptor could read and spend, since that pin is checked after the fact and only on the config response. A user pin is scoped to the host it was set for, so pinning a self-hosted server no longer disables CA validation for the managed one.

24. **Privacy Pass issuer key trust** — resolved: pinned trust-on-first-use, and a changed key is refused rather than followed. Blind signing hides the token from the issuer but not which key signed it, so an issuer handing every client a distinct keypair learns at redemption exactly which client a token came from, with every signature still verifying and no error raised anywhere. A key-consistency check is the only thing that catches it.

25. **What the server records** — resolved: counts, not events. Registrations, transport sessions and evictions each used to write a timestamped line. None named a client IP, but a timestamped record that a connection happened is what the privacy policy says does not exist, and on a small server that timeline approximates a usage history. Those events are counted and reported as hourly rollups. Two tests hold the line: one fails if any source file logs a single connection event, the other requires the rollup to emit only numeric fields. wireguard-go's own logger, which names peers by public-key fragment from vendored code, is wrapped to redact them.

26. **Multipath transports** — resolved: not pursued for throughput; the redundancy half was implemented instead. Running permitted transports in parallel does not pay, because the paths differ by roughly 300× (166 Mbps measured on TLS/443 against 0.5–2 Mbps for the DNS tunnel), and WireGuard's 8128-packet anti-replay window would reject traffic arriving late on the slow path while TCP inside the tunnel thrashed its retransmit timer across the mismatched latencies. What did pay: reconnect now names the transport that was working instead of restarting the chain from the top, which on a portal permitting only the DNS tunnel had been spending most of the fallback budget to arrive back where it started, with the user unprotected throughout. See `technical-architecture.md` §10.

27. **DNS and ICMP handshake authentication** — deferred until Freewire serves people other than its operator. See `DECISIONS.md` §DNS-ICMP-HANDSHAKE-AUTH. Both handshakes use unauthenticated ephemeral DH, so the on-path adversary those transports exist to defeat can sit in the middle of them. An active attacker gains transport framing and the ability to disrupt; they do not gain traffic, because the WireGuard session inside is authenticated by the pinned server key. The fix when picked up is to mix the server's known public key into the handshake, needing no new key material — it is deferred because it is a protocol change to both ends of both transports, and because today the on-path adversary is a portal the sole operator chose to connect to.

---

## 11. Success Metrics

> **None of these are measured.** They require a user population and telemetry
> that deliberately does not exist — the client collects no usage analytics, and
> the server counts connections without retaining anything per session. Metrics
> like onboarding completion and crash rate would need instrumentation that
> contradicts §6.7 and Decision 25. Reconciling that is unresolved: either these
> targets are assessed some other way (beta cohorts reporting by hand), or the
> product accepts it cannot measure them. Recorded here rather than left as
> numbers nobody can check.

- **Captive portal success rate:** ≥90% of connection attempts on captive portal networks succeed without user intervention
- **Onboarding completion rate:** ≥80% of users who start onboarding reach a first successful connection
- **Managed path time-to-connected:** 80th percentile ≤ 2 minutes from app launch
- **Self-hosted setup completion rate:** ≥70% of users who choose self-hosted path complete setup
- **Client crash rate:** <0.5% of sessions end in an unexpected crash
- **Tunnel reliability:** ≥99% of sessions that are connected for >60 seconds maintain connection or recover automatically
