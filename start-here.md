# Freewire VPN — Start Here

## What is Freewire?

Freewire is a free consumer VPN that works everywhere — including captive portal networks (hotel, airport, and café wifi that require payment or login before granting internet access). Users can connect to Freewire's managed servers or deploy their own. Setup is designed to take minutes, not hours.

## What has been decided

- **Free to users.** No subscription, no paywall, no ads, no in-app donation mechanism.
- **Hybrid server model.** Users choose between Freewire-managed servers or self-hosting on AWS.
- **Captive portal bypass is the core technical differentiator.** Speed-ordered carrier chain (9 carriers): wireguard → udp443 → http_connect → tls443 → wss443 → cdn_wss → dns_tcp → dns → icmp_udp. `dns_tcp` (added 2026-08-28, field-validated 2026-08-30) is WireGuard over TCP/53 -- real backpressure instead of the UDP dns carrier's tail-drop-and-collapse failure. The client commits to the fastest that actually carries traffic. See `technical-architecture.md` §3.
- **macOS at launch.** iOS, Android, and Windows are post-launch.
- **Consumer-first UX.** Setup must require no technical knowledge.
- **No user accounts. No identity required.** Each device generates a WireGuard keypair locally at first launch. The device's public key is its identity. No email, Apple ID, or login of any kind. This is the same principle as Signal: Freewire cannot answer questions it never collected data to answer.
- **Anonymous by design.** Freewire stores no connection logs, no IP addresses, no session timing, and no destination data. See `data-model.md`.
- **One managed server region at launch.** More added post-launch based on demand.
- **Self-hosted on AWS** via one-click deploy (Marketplace AMI or CloudFormation).
- **Kill switch on by default.** Users may disable in settings.
- **macOS client language: Swift**, using `wireguard-go` (userspace) via direct `utun` interface — no NetworkExtension. Kill switch via `pf` + `SMAppService` privileged helper. Sparkle for auto-update.
- **Server language: Go.** WireGuard's reference userspace implementation (wireguard-go) is in Go; the authoritative DNS tunnel server and Privacy Pass token issuer are also Go. Deploys as a single static binary.
- **macOS: direct download (signed + notarized DMG + Sparkle auto-update) at launch.** Mac App Store permanently incompatible with direct `utun` access.
- **iOS: deferred.** Will use Swift + WireGuardKit + NetworkExtension (NEPacketTunnelProvider) when resumed. Apply for the NE entitlement when iOS work begins — approval takes days to weeks.

## Actions required before engineering begins

> **Privacy policy requires legal review before launch.** A draft exists at `privacy-policy.md`. It needs a legal review, an effective date, and a published URL before launch.

> **When iOS work begins:** Apply for the Apple `NEPacketTunnelProvider` entitlement at that time — approval takes days to weeks. See `apple-entitlement-application.md`.

## What is still open

- **Privacy policy draft exists** (`privacy-policy.md`) — needs legal review, effective date, and published URL before launch.

## Reading list

### Everyone
1. `start-here.md` ← you are here
2. `PRD.md` — full product requirements

### Engineers
→ Start with `engineering-handoff.md`. Everything else is linked from there.

### Business / product
1. `PRD.md` — sections 1–4 (Overview, Background, Goals, Competitive Positioning)

---

> **For engineers:** Start with `engineering-handoff.md`. It contains the build order, architecture overview, all decisions made, and resolved engineering questions. Everything else is linked from there.
