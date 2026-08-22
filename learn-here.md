# Freewire VPN — Learn Here

Knowledge base, terminology, and document index for the Freewire VPN project.

---

## Core Concepts

**Captive portal** — A network mechanism that intercepts all HTTP/HTTPS traffic and redirects users to a login or payment page before granting general internet access. Common in hotels, airports, cafés, and transit systems. Standard VPN clients fail on these networks because the tunnel cannot be established before the portal is satisfied.

**Captive portal bypass** — Freewire's ability to establish a VPN tunnel on a captive portal network without requiring the user to pay or authenticate first. This is Freewire's primary technical differentiator. The mechanism routes tunnel traffic over a port and protocol (typically 443/TLS) that captive portals must leave open to display their own payment pages.

**Managed server** — A VPN server operated by Freewire. Users connect to these without deploying any infrastructure. Freewire is responsible for uptime, maintenance, and the privacy posture of these servers.

**Self-hosted server** — A VPN server that the user deploys themselves on a cloud provider of their choice. Freewire provides the server software and a guided setup flow. The user owns and controls the server.

**Full-tunnel mode** — All device traffic (every app, every connection) routes through the VPN tunnel. Freewire operates in full-tunnel mode only. Split-tunnel (routing only some traffic through the VPN) is out of scope at launch.

**Kill switch** — A safety mechanism that blocks all network traffic if the VPN tunnel drops unexpectedly. Prevents traffic from leaking on an unprotected network while the client attempts to reconnect.

**Protocol fallback chain** — Freewire's ordered sequence of tunnel paths, attempted automatically on each connection: (1) HTTP CONNECT probe, (2) TLS/443 direct, (3) DNS tunnel, (4) ICMP tunnel. The client tries each in order and upgrades to the fastest available path once any tunnel is established.

**DNS tunnel** — Freewire's universal fallback tunnel path. Encodes all VPN traffic as DNS queries and responses to Freewire's authoritative DNS server for `tunnel.freewire.com`. Works on any network where DNS queries reach the public internet, which captive portals must allow to display their own portal page.

**EDNS0 (Extension Mechanisms for DNS)** — A DNS protocol extension that allows response packets larger than the original 512-byte limit, up to 4096 bytes. Freewire's DNS tunnel negotiates EDNS0 to maximize inbound payload per round trip.

**Sliding window** — A pipelining technique used in Freewire's DNS tunnel protocol. Instead of waiting for each DNS query to be answered before sending the next, the client keeps a window of outstanding queries in flight simultaneously. Increases throughput by hiding round-trip latency.

**Anycast** — A network addressing method where multiple servers share the same IP address, and traffic is automatically routed to the nearest one. Freewire's DNS tunnel target architecture uses anycast to minimize resolver-to-server latency; at launch, `tunnel.freewire.com` runs on a single unicast server in US-East. See `anycast-dns-infrastructure.md`.

**HTTP CONNECT** — An HTTP method that asks a proxy server to open a raw TCP connection to a destination. Some captive portals expose an HTTP proxy that supports CONNECT, which Freewire exploits to establish a full-speed TCP tunnel before any other path is tried.

**ICMP (Internet Control Message Protocol)** — A network protocol used for diagnostic messages like ping. Freewire's last-resort tunnel path encodes VPN traffic in ICMP echo request/reply payloads on networks where DNS forwarding is blocked but ICMP to external IPs is allowed.

**uTLS** — A library that allows a TLS client to mimic the exact TLS fingerprint of a real browser (Chrome, Firefox, etc.). Freewire uses this on the TLS/443 path to avoid deep packet inspection detection.

**DH (Diffie-Hellman) key exchange** — A cryptographic protocol for establishing a shared secret over an untrusted channel. Used in Freewire's DNS tunnel handshake to establish session encryption before any payload data flows.

**WireGuard** — A modern VPN protocol used by Freewire on open networks (no captive portal). Fast and efficient. Uses UDP, which captive portals block — WireGuard is not used on captive portal paths.

**WireGuardKit** — Apple's official open-source Swift/Objective-C wrapper around the reference WireGuard implementation. Used by the official WireGuard iOS and macOS apps. Freewire uses WireGuardKit for the WireGuard protocol layer on both Apple platforms; custom tunnel code (DNS tunnel, TLS/443 path, HTTP CONNECT) is built in Swift on top of it.

**Shadowsocks** — A proxy protocol originally designed for censorship circumvention. Evaluated as a captive portal bypass candidate; not selected. Freewire's custom DNS tunnel approach provides more universal coverage.

**NetworkExtension** — Apple's framework for implementing VPN clients on iOS and macOS. Required for any VPN distributed via TestFlight or the App Store.

**VpnService** — Android's API for implementing VPN clients. Required for Play Store VPN apps.

**WFP (Windows Filtering Platform)** — The Windows kernel API used to intercept and route network traffic for VPN clients.

---

## Quick Reference

### Platform VPN APIs

| Platform | API | Notes |
|---|---|---|
| iOS | NetworkExtension (NEPacketTunnelProvider) | Requires entitlement — required before TestFlight distribution and App Store submission |
| iOS | NetworkExtension (NEHotspotHelper) | Second entitlement — automatic portal auth; degrades gracefully without it |
| macOS | NetworkExtension (NEPacketTunnelProvider) | Requires entitlement — required before TestFlight distribution and App Store submission |
| Android | VpnService | Requires BIND_VPN_SERVICE permission |
| Windows | WFP / TAP adapter / WinTun | WinTun preferred for WireGuard |

### Key thresholds (from PRD §8)

| Metric | Threshold |
|---|---|
| Latency overhead | ≤ 20ms avg vs. direct connection |
| Throughput (managed) | ≥ 50 Mbps sustained |
| Managed server uptime | ≥ 99.5% per region per month |
| Time-to-connected | ≤ 10 seconds (normal network) |

---

## Document Index

| File | Purpose | Authoritative for |
|---|---|---|
| `start-here.md` | Entry point; what's decided, what's open, reading list | Project orientation |
| `PRD.md` | Full product requirements | All product decisions |
| `learn-here.md` | Terminology and document index | Definitions and concepts |
| `technical-architecture.md` | Protocol design: fallback chain, DNS tunnel server, TLS/443 and ICMP paths | Architecture reasoning and design detail |
| `product-review-checklist.md` | 60-item quality gate across 11 sections with fast-track gate and cadence guide | Quality review process |
| `ux-workflows.md` | All user-facing flows for iOS client, macOS client (menu bar), and AWS server setup | UX flows, states, and information hierarchy |
| `data-model.md` | Data model with Signal-level privacy architecture; what is stored, what is not, and why | Data storage decisions and privacy guarantees |
| `error-states-spec.md` | 34 error states across 7 categories (connection, session, permissions, self-host, privacy, system, updates) | Error handling behavior and user-facing messages |
| `engineering-handoff.md` | Engineering orientation: build order, decisions, open questions, pre-launch checklist | Engineering starting point |
| `client-server-api-spec.md` | HTTP API between Freewire client and managed server | API contract between client and server teams |
| `dns-tunnel-protocol-spec.md` | Wire protocol for the DNS tunnel: subdomain encoding, handshake, sliding window, encryption | DNS tunnel implementation |
| `privacy-pass-spec.md` | Privacy Pass blind token implementation: token type, issuance flow, redemption, storage | Rate-limiting implementation |
| `cloudformation-spec.md` | AWS CloudFormation template and AMI: resources, security groups, IAM, outputs | Self-hosted deploy infrastructure |
| `build-and-release-pipeline.md` | CI/CD for iOS, macOS, and server: build, sign, notarize, release process | Build and release process |
| `sparkle-update-feed-spec.md` | Sparkle appcast format, EdDSA signing, CDN hosting for macOS auto-update | macOS auto-update |
| `certificate-management.md` | TLS certificate provisioning and renewal for all Freewire domains and signing identities | Certificate lifecycle |
| `anycast-dns-infrastructure.md` | Anycast DNS PoP deployment, BGP configuration, health monitoring for tunnel.freewire.com | Post-launch DNS tunnel infrastructure |
| `captive-portal-testing-guide.md` | How to simulate captive portal networks locally and test all four fallback paths | Captive portal testing |
| `apple-entitlement-application.md` | Application guidance for the Apple NetworkExtension entitlement | App Store submission prerequisite |
| `icmp-tunnel-protocol-spec.md` | ICMP tunnel wire protocol: packet format, handshake, encryption, sliding window, rate limiting | ICMP tunnel implementation |
| `server-dashboard-api-spec.md` | HTTP API for the self-hosted server web dashboard: auth, device management, config/QR generation | Self-hosted dashboard implementation |
| `path-upgrade-manager-spec.md` | Path upgrade manager: state machine, probe schedule, migration procedure, re-probe intervals | Client path upgrade implementation |
| `testing-plan.md` | Full waterfall testing process: 8 stages, 3 environments, launch gate checklist | Testing process and release gates |
| `privacy-policy.md` | Public-facing privacy policy draft — what Freewire collects, what it structurally cannot collect, user rights | Privacy commitments and pre-launch legal review |
