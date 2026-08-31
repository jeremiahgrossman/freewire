# Apple NetworkExtension Entitlement — Application Guidance

**Apply at:** https://developer.apple.com/contact/request/network-extension/  
**Entitlement needed:** `com.apple.developer.networking.networkextension`  
**Required before:** TestFlight distribution (must be in the provisioning profile for any build using NetworkExtension APIs). Also required before App Store submission.

> **Superseded (2026-08-31):** this entitlement applies to iOS only, whenever that work resumes (currently fully deferred — see `CLAUDE.md`). The shipped macOS client deliberately does **not** use NetworkExtension — it's a locked tech-stack decision: `wireguard-go` over a direct `utun` interface, no `NEPacketTunnelProvider`. macOS's own blocker is unrelated to this entitlement: the pf-based kill switch needs a Developer ID certificate to install its `SMAppService` privileged helper, not this NetworkExtension entitlement. The suggested application description below (`NEPacketTunnelProvider`, "for iOS and macOS") is accurate only for a future iOS build, not for the current macOS app.

---

## How to frame the application

Apple approves consumer VPN apps routinely. The goal is to present Freewire in the most familiar, well-established terms — not as something novel or unusual.

**Lead with privacy and security, not captive portal bypass.**

"Consumer VPN providing privacy and security on public networks" is a category Apple approves daily. "Bypass captive portals" is unfamiliar and may read as helping users avoid paying for network access, even though the underlying capability is the same. Let the technical capability exist without leading with it.

---

## Suggested application description

> Freewire is a consumer VPN application for iOS and macOS that encrypts all device network traffic to protect users on public wifi networks. The app uses Apple's NetworkExtension framework (NEPacketTunnelProvider) to establish a WireGuard-based encrypted tunnel between the user's device and either a Freewire-operated server or a user-deployed server on their own infrastructure.
>
> The app routes all device traffic through the tunnel (full-tunnel mode) and includes a kill switch that blocks traffic if the tunnel drops unexpectedly. No user account is required — the device's WireGuard public key, generated locally at first launch, serves as its sole identity.
>
> Freewire is free to users and does not collect personal data, usage logs, IP addresses, or connection history. A privacy policy is drafted and will be published at a stable URL before App Store submission.

---

## What to avoid saying

- "Bypass captive portals" — frame as "works on all network types including restricted public wifi"
- "Skip hotel/airport wifi paywalls" — not relevant to the entitlement application
- Anything that implies circumventing network access controls as a primary purpose
- Anything about the DNS tunnel specifically — it's an implementation detail, not a product description

---

## Supporting points if Apple asks follow-up questions

- **Business model:** Free at launch; no in-app purchases, no subscriptions, no data monetization
- **Data collection:** None. No accounts, no logs, no IP addresses. Modeled on Signal's architecture.
- **Self-hosting:** Users can deploy their own server on AWS; the app supports both managed and self-hosted server paths
- **Protocol:** WireGuard via WireGuardKit (Apple's own open-source framework)
- **Entitlement scope:** NEPacketTunnelProvider only; no NEAppProxy, no content filtering, no DNS proxy

---

---

## NEHotspotHelper Entitlement

**Entitlement:** `com.apple.developer.networking.HotspotHelper`  
**Apply at:** https://developer.apple.com/contact/request/network-extension/ (same form, different entitlement checkbox)  
**Required for:** Fully automatic captive portal authentication (no user interaction). The app functions without this — it falls back to the in-app browser flow. Apply in parallel with NEPacketTunnelProvider; approval timelines are independent.

### What NEHotspotHelper does

Registers the app as a network helper. When the device joins any wifi network, iOS calls the app to evaluate it. Freewire uses this to detect and silently complete captive portal authentication before the user ever taps Connect — the portal is already satisfied by the time they initiate a VPN connection.

### How to frame the application

Apple grants NEHotspotHelper to apps that provide legitimate network onboarding assistance. Frame it as a quality-of-life improvement for users on public wifi, not as circumvention.

**Suggested description for the NEHotspotHelper request:**

> Freewire requests the HotspotHelper entitlement to improve the experience of connecting to VPN on public wifi networks. Many public networks (hotels, airports, cafés) require users to interact with a captive portal before network access is granted. Without this entitlement, users must manually open a browser, authenticate with the portal, return to Freewire, and reconnect — a multi-step process that interrupts their workflow.
>
> With HotspotHelper, Freewire can detect when a network requires portal authentication and, for networks that use simple terms-acceptance flows (no credentials, no payment), complete that authentication silently in the background. For portals that require user input (room number, email, payment), the entitlement is not used — Freewire presents an in-app browser for the user to complete manually.
>
> The entitlement is used exclusively to facilitate legitimate network access, not to bypass any access controls or avoid any fees. Freewire never submits user credentials or payment information on behalf of the user.

### Supporting points

- **Scope:** Used only for portal probe and simple accept-terms automation. Not used to bypass authentication portals that require credentials.
- **No data collection:** The portal probe is a local network interaction. No data about the portal or the network leaves the device.
- **Fallback:** If the entitlement is not granted, the app degrades gracefully to the in-app browser flow — no user-visible feature disappears.

---

## Other App Store submission notes

- Privacy policy must be written and published before submission
- App Store description should emphasize privacy and security on public networks
- Screenshots should show the connection UI, server selection, and settings — not captive portal bypass flows
- The "what this VPN does and does not protect" explanation (required per PRD §6.7) satisfies Apple's transparency requirement for VPN apps
