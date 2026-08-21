# Freewire VPN: Product Review Checklist

---

## How to Use This Checklist

This checklist has **60 items across 11 sections**. Running all items every session is not the goal. Use the cadence guide to pick the right depth for the moment.

---

### Cadence Guide

| Tag | When to run |
|---|---|
| **Every session** | After any substantive change to a spec, flow, or design decision |
| **Pre-engineering** | Before any engineering phase begins: once per phase |
| **At launch** | One-time gate before the app is publicly available |
| **Quarterly** | Competitive reviews, post-launch health checks, protocol validation |
| **Post-launch** | After production data is available |

| Section | Cadence | Est. time |
|---|---|---|
| Quality Control (1–5) | Every session | 20 min |
| Cross-Document Consistency (6–9) | Every session | 20 min |
| Product Logic (10–18) | Pre-engineering | 1.5 hours |
| Customer Onboarding and Time-to-Value (19–27) | Pre-engineering, at launch | 1.5 hours |
| Infrastructure Security (28–33) | Pre-engineering | 1 hour |
| Failure Mode Review (34–38) | Pre-engineering | 45 min |
| Privacy and Data Handling (39–42) | At launch, quarterly | 45 min |
| Performance Review (43–46) | Pre-engineering | 45 min |
| Competitive Differentiation (47–49) | Quarterly | 30 min |
| Launch Readiness Gates (50–52) | At launch | 30 min |
| UX Behavior Verification (53–60) | Pre-engineering, at launch | 1 hour |

---

### Fast-Track Gate: 12 Items Before Any Engineering Sprint

Run these 12 items as a quick pre-sprint gate (target: 60 minutes). If any fail, resolve before engineering begins.

| # | Check |
|---|---|
| FT-1 | All specs for this phase are complete — no section reads "TBD" or references an unresolved open question |
| FT-2 | The captive portal bypass fallback chain is fully specified for each path (HTTP CONNECT, TLS/443, DNS tunnel, ICMP) |
| FT-3 | No new feature introduces a failure mode where the user's traffic leaks unprotected without notification |
| FT-4 | Apple NetworkExtension (NE) entitlement has been applied for — required before TestFlight distribution; required before App Store submission |
| FT-5 | The DNS tunnel protocol spec is complete enough that an engineer can implement it without asking design questions |
| FT-6 | Kill switch behavior is specified for every tunnel-drop scenario: what the user sees, what traffic does, when it recovers |
| FT-7 | Device key lifecycle is specified: generation at first launch, Keychain storage, behavior on device restore/migration, and key reset flow |
| FT-8 | Every new in-app string is in plain language — no technical VPN or networking terminology visible to users |
| FT-9 | Cross-document consistency: any spec added this session agrees with the PRD on platform scope, protocol decisions, and terminology |
| FT-10 | AWS self-hosted setup flow is specified completely enough to verify the "under 15 minutes" requirement |
| FT-11 | Privacy policy commitment matches implementation: if we say we don't log traffic, verify no component logs it |
| FT-12 | Performance targets for each tunnel path are defined and testable (TLS/443: 50 Mbps; DNS tunnel: 500 Kbps minimum) |

---

### Role Tags

- **P**: Product — design decisions, UX, positioning, onboarding
- **E**: Engineering — implementation, protocol, performance, security
- **S**: Security — adversarial review, threat model, data handling
- **B**: Business — competitive, sustainability model, legal

---

## Quality Control

### 1. Verify Acronym Discipline Across All Documents
`Every session` | `P`

Review every document for acronym usage. Every acronym must be spelled out on first use within each document, with the acronym in parentheses. Subsequent uses in the same document use the acronym alone.

Acronyms to specifically check: VPN, DNS, ICMP, TLS, HTTPS, NE (NetworkExtension), AWS, DMG, EDNS0, DH (Diffie-Hellman), ALPN, SNI, MITM, API, UUID, CDN, WFP, DPI, NTP, QR.

Flag any acronym used in a user-facing context (onboarding copy, error messages, app UI) without a plain-language explanation — the full form of an acronym is not sufficient for a non-expert audience.

**Stress-test prompt:** "Read each document as someone who uses VPNs but has no networking background. Which acronyms stop you? Which appear in copy a user would read?"

---

### 2. Verify Terminology Consistency
`Every session` | `P`

Check that product terminology is used consistently across all documents:
- "captive portal" — not "gated network," "walled garden," or "paywall wifi"
- "tunnel" — not "connection" or "pipe" when referring to the VPN tunnel specifically
- "managed server" — not "Freewire server" or "cloud server" (the PRD term is managed server)
- "self-hosted server" — not "personal server" or "own server"
- "kill switch" — consistent capitalization and hyphenation
- "fallback chain" — not "fallback path" or "backup protocols"

Flag any document where these terms are used differently.

---

### 3. Verify UX Documents Describe Experience, Not Visual Design
`Every session` | `P`

Review all UX-related documents and flag any instance of: color names, typography specifications, component library references, spacing values, or animation descriptions. These are engineering decisions, not product decisions. Replace with functional descriptions of state, information hierarchy, and available actions.

**Acceptable:** "The connection status is displayed prominently at the top of the screen with the server name and active tunnel path."
**Not acceptable:** "A large green circle indicates connected state."

---

### 4. Check Platform Scope Consistency
`Every session` | `P, E`

Confirm that every document reflects the current platform scope decision: iOS and macOS at launch, Android and Windows post-launch. Flag any document that implies features for Android or Windows as launch requirements, or that uses language like "all platforms" without qualification.

---

### 5. Verify No Pricing Discussion in Product Documents
`Every session` | `P`

Scan all product documents for pricing language. Pricing is explicitly out of scope. Flag any mention of price points, subscription tiers, or cost comparisons in engineering or product documents. Competitive analysis may reference competitor pricing factually but must not discuss Freewire's own pricing.

---

## Cross-Document Consistency

### 6. Check Internal Consistency Across All Documents
`Every session` | `P`

Read across the full document set and verify:

- **Platform scope:** Every document agrees iOS and macOS are launch platforms. Android and Windows are post-launch.
- **Protocol decisions:** Every document that references the tunnel mechanism agrees on the fallback chain order: HTTP CONNECT → TLS/443 → DNS tunnel → ICMP. No document implies a different protocol stack.
- **Identity model:** Every document agrees there are no user accounts. Device identity is a locally generated WireGuard public key. No Sign in with Apple, no email, no login.
- **Server model:** Every document agrees on the hybrid model (managed + self-hosted on AWS).
- **Kill switch:** Every document agrees the kill switch is on by default.
- **Open questions:** No document has open questions that have been resolved elsewhere without the originating document being updated.

---

### 7. Identify Flawed or Unsupported Logic
`Every session` | `P`

Examine reasoning chains in the documentation and identify conclusions that do not follow from their premises, or that rest on unvalidated assumptions.

Specifically: Does the DNS tunnel throughput target (500 Kbps minimum) follow from the protocol design in `technical-architecture.md`? Does the "under 5 minutes" onboarding claim follow from the specified steps? Are captive portal bypass success rate claims (90%) grounded in how the fallback chain actually behaves?

**Stress-test prompt:** "Which performance or success claims in the documentation are stated with more confidence than the design supports? What would a skeptical engineer ask to challenge them?"

---

### 8. Surface Internal Conflicts
`Every session` | `P`

Look for places where two documents make incompatible claims:
- A feature described as launch scope in one document but deferred in another
- A performance target in the PRD that conflicts with what `technical-architecture.md` describes as achievable
- A UX flow that requires a feature not defined in the PRD
- An open question answered in one document but still marked open in another

---

### 9. Find Missing Specifications
`Every session` | `P, E`

Identify any area referenced across multiple documents but never fully defined. The test: if an engineer were handed the full document set today and asked to build the product, where would they get stuck?

Current known gaps (update as resolved):
- All core specification documents are complete: `ux-workflows.md`, `data-model.md`, `error-states-spec.md`, `engineering-handoff.md`
- All engineering questions resolved — see `engineering-handoff.md` §Open Engineering Questions
- Privacy policy: drafted in `privacy-policy.md` — requires legal review and effective date before launch

---

## Product Logic

### 10. Validate the Captive Portal Bypass Claim
`Pre-engineering` | `P, E`

The core product claim is that Freewire works on captive portal networks before the user pays or authenticates. Examine where this claim holds and where it does not.

Specifically: Is there a class of captive portal (fully local DNS resolver, deep packet inspection on 443, ICMP blocked externally) where none of the four fallback paths succeed? If so, is this documented as a known limitation, and is the product's marketing claim scoped appropriately? Does the product communicate clearly when bypass has failed, or does it leave the user uncertain?

**Stress-test prompt:** "Describe a real hotel or airport wifi network configuration where Freewire would fail to establish a tunnel on all four paths. Is this scenario common enough to affect the 90% success rate target?"

---

### 11. Validate the DNS Tunnel Protocol Design
`Pre-engineering` | `E, S`

The DNS tunnel is the universal fallback and the most novel technical component. Examine the design in `technical-architecture.md` for internal consistency and correctness.

- Does the sliding window protocol handle out-of-order DNS responses correctly?
- What happens when a captive portal's DNS resolver strips EDNS0 options? Does the protocol detect this and fall back gracefully to 512-byte responses?
- What happens when the resolver caches tunnel subdomain responses despite TTL=0? Does the protocol detect stale responses?
- Is the Diffie-Hellman (DH) key exchange completable within DNS label size constraints in a reasonable number of round trips?
- Does the encryption layer prevent a passive observer (the captive portal's DNS resolver) from reading tunnel content?

**Stress-test prompt:** "Walk through the DNS tunnel establishment on a network where the resolver strips EDNS0 and caches responses for 30 seconds. Does the protocol recover, degrade gracefully, or fail?"

---

### 12. Validate the Upgrade-to-Faster-Path Logic
`Pre-engineering` | `E`

Once any fallback path establishes a tunnel, the client attempts to upgrade to a faster path. Examine this upgrade logic:

- What is the exact trigger for attempting an upgrade? Is it attempted once on connection, or periodically?
- If TLS/443 is available through the DNS tunnel but was not available before it, what changed? Does the DNS tunnel actually enable TLS/443 access, or is this assumption wrong for most captive portals?
- If the upgrade attempt fails, does the client retry? At what interval?
- If the upgrade succeeds and then the faster path drops, does the client fall back to the DNS tunnel automatically?

**Stress-test prompt:** "On a network where only DNS tunneling works, does the upgrade probe succeed or fail? If it fails, how many times does the client attempt it before giving up?"

---

### 13. Validate Kill Switch Behavior Across All Tunnel-Drop Scenarios
`Pre-engineering` | `P, E`

The kill switch blocks all traffic when the tunnel drops. Verify the design handles every tunnel-drop scenario:

- Tunnel drops due to server-side issue: kill switch fires immediately, traffic blocked
- Tunnel drops due to network change (wifi → cellular): kill switch fires, client detects network change, reconnects, kill switch releases
- Tunnel drops due to captive portal interception mid-session: kill switch fires, client detects captive portal, attempts bypass via fallback chain
- User manually disconnects: kill switch does not fire; traffic flows freely
- App is force-quit while connected: kill switch must persist at the OS level via NetworkExtension; traffic must not leak during app restart
- Device sleeps while connected: kill switch behavior during sleep and wake must be defined

For each scenario: what does the user see? How long does it last? What action can they take?

**Stress-test prompt:** "A user is on public wifi at an airport. Their phone locks and the screen turns off. When they unlock 10 minutes later, what is the VPN state? Did any traffic leak during the sleep period?"

---

### 14. Validate Device Key Lifecycle
`Pre-engineering` | `E`

There are no accounts. A device is identified by its WireGuard public key, generated locally at first launch. Verify the design covers:

- Generation: keypair is generated at first launch, stored in the iOS Keychain / macOS Keychain — never in UserDefaults, plist files, or unprotected storage
- Key is never transmitted to Freewire in any form other than the public key presented during WireGuard handshake
- Device restore / migration (iCloud backup, new iPhone): what happens to the keypair? Does restoring from backup restore the key? If not, does the app regenerate cleanly on first launch?
- Key reset: the user taps Reset Device Key. New keypair generated, old peer slot orphaned on the managed server. Self-hosted users must re-import config — is this clearly communicated?
- Key loss (app deleted and reinstalled): new keypair generated, no recovery needed for managed servers (no account), self-hosted users must re-import config

**Stress-test prompt:** "A user gets a new iPhone and restores from iCloud backup. What is their Freewire state on first launch of the restored app? Do they need to do anything to reconnect?"

---

### 15. Validate the Self-Hosted AWS Setup Flow
`Pre-engineering` | `P, E`

The self-hosted setup claims completion in under 15 minutes with no technical knowledge. Examine whether this is achievable on AWS:

- What does the user need before starting? An AWS account? A credit card? IAM (Identity and Access Management) permissions?
- Does the one-click deploy (Marketplace AMI or CloudFormation) require any configuration steps after deployment, or is the server immediately ready?
- How does the Freewire app discover the user's self-hosted server? Does the user paste an IP address, a config file, or scan a QR code?
- What does the user see if the AWS deployment fails? Is the error message actionable?
- What does ongoing maintenance look like? Does the server need updates? Who applies them?

**Stress-test prompt:** "A user with an AWS account but no cloud infrastructure experience follows the self-hosted setup flow. Where do they get stuck? What is the most likely failure point?"

---

### 16. Validate That the Product Communicates Its Limitations Honestly
`Pre-engineering, at launch` | `P`

Freewire makes a strong claim (works on any network) that has edge cases where it fails. Verify the product communicates these honestly:

- Is there an in-app explanation of what a VPN does and does not protect against?
- Is the known failure case (fully local DNS resolver + DPI on 443 + ICMP blocked) documented anywhere the user can find it?
- Does the product distinguish between "not connected because the network is blocking all paths" and "not connected because of a server issue"?
- Does the product describe itself as reducing exposure rather than eliminating risk?

---

### 17. Challenge the Free Sustainability Assumption
`Quarterly` | `P, B`

The product is free with no in-app revenue mechanism. Examine the sustainability assumption:

- What is the infrastructure cost model for managed servers at scale? At 10K users? 100K users?
- If infrastructure costs exceed budget, what is the documented contingency? (Pause managed servers, introduce a paid tier, open-source and shut down managed infrastructure?)
- Is there a runway estimate — how long can Freewire operate managed servers before needing a revenue decision?

**Stress-test prompt:** "Freewire has 100,000 active managed server users and no revenue. What is the monthly infrastructure cost? What is the plan?"

---

### 18. Validate Onboarding Path Decision Logic
`Pre-engineering` | `P`

Onboarding defaults to the managed server path. Self-hosting is a secondary link ("Running your own server? Set up self-hosting →"), not a co-equal option on the first screen. Examine whether this hierarchy is clear and whether switching paths mid-flow is handled:

- Is it clear from the first screen that managed is the default and self-hosting requires additional setup?
- Is the self-hosting link discoverable without feeling buried or penalizing users who want it?
- Can a user who followed the self-hosting link switch to managed mid-flow without starting over?
- Can a user who completed managed onboarding add a self-hosted server later without re-onboarding?
- Does the copy avoid the term "self-hosted" where consumer-friendly alternatives exist ("use your own server", "set up your own server")?

---

## Customer Onboarding and Time-to-Value

### 19. Walk the Entire Install-to-Connected Path
`Pre-engineering` | `P`

Starting from TestFlight (iOS) or the download page (macOS), walk every step through to the first successful VPN connection. Document every decision point, every permission prompt, every piece of information the user must provide, and every step that requires leaving the Freewire app.

**Target:** Under 5 minutes for the managed server path. Under 15 minutes for the self-hosted path.

For each step: Is it necessary? Could it be eliminated or deferred? Does the user understand what they're doing and why?

**Stress-test prompt:** "Walk the managed server onboarding path as someone who has never used a VPN. Where do you pause, hesitate, or need to read something twice?"

---

### 20. Audit Every Permission Prompt
`Pre-engineering` | `P`

List every system permission prompt the user sees during onboarding (VPN configuration, notifications, Sign in with Apple, macOS System Extension). For each:

- Is there an in-app explanation immediately before the system prompt that explains what the permission is and why it is needed, in plain language?
- Does the explanation describe the consequence of denying the permission?
- If the user denies a permission, what does the product do? Is there a recovery path or is onboarding blocked?

Permission prompts at onboarding: VPN configuration (iOS and macOS), notifications (iOS — requested after first successful connection), macOS System Extension approval. There is no Sign in with Apple prompt — Freewire has no accounts.

The user should never see a system permission prompt without understanding why they are being asked.

---

### 21. Verify the macOS System Extension Approval Flow
`Pre-engineering` | `P, E`

macOS requires explicit user approval of the NetworkExtension (NE) System Extension via a system prompt. This is a mandatory, unavoidable step. Verify:

- The in-app explanation before this prompt is clear and non-technical
- The system prompt that macOS shows is not surprising or alarming to the user given the explanation they just read
- If the user dismisses the system prompt without approving, the app detects this and explains what to do (System Preferences → Privacy & Security → Allow)
- The approval step is not confused with the VPN configuration permission, which is a separate prompt

**Stress-test prompt:** "A user dismisses the System Extension approval prompt by accident. What does the app show them? Can they recover without knowing what a System Extension is?"

---

### 22. Verify the App Communicates Connection State Unambiguously
`Pre-engineering` | `P`

At every moment during the app's lifecycle, the user must know exactly what state their VPN is in. Define and verify each state:

- **Disconnected:** Not connected, no tunnel active. Traffic flowing unprotected.
- **Connecting:** Attempting to establish tunnel. Kill switch not yet active. Status line cycles through plain-language descriptions as fallback paths are tried — "Finding the best path...", "Trying secure connection...", "Switching to alternate method...", "Almost there..." — without naming protocols.
- **Captive portal authentication needed (CONN-2a):** All paths failed due to an unauthenticated portal. In-app browser opened. Status: "One more step — authenticate with this network." User action: complete portal login. Auto-retry fires on browser dismiss.
- **Connected:** Tunnel active. Which server is shown.
- **Reconnecting:** Tunnel dropped, kill switch active, attempting to reconnect. "Disconnect and restore unprotected access" is available from the first second — not delayed.
- **Blocked (CONN-2b):** Kill switch active, all paths failed, captive portal probe confirms genuine block. "This network blocks VPNs / Freewire tried every method." Options: try again, cancel.
- **Error:** Something went wrong that requires user action.

For each state: what exactly does the user see? What actions are available? Is the state name the same as the plain-language description shown to the user?

---

### 23. Verify the Captive Portal Bypass Is Transparent to the User
`Pre-engineering` | `P`

The fallback chain is an implementation detail. The user should experience it as "Freewire connected" — not as "Freewire tried HTTP CONNECT, failed, tried TLS/443, failed, fell back to DNS tunnel." Verify:

- The connecting status line uses plain-language descriptions ("Finding the best path...", "Almost there..."), not protocol names ("Trying TLS/443...", "Starting DNS tunnel..."). The status line communicates effort and progress without exposing the fallback chain.
- If the DNS tunnel is the active path, the user sees "Connected" with a note that speed may be reduced — not a technical explanation of why.
- The user is never asked to choose a path or troubleshoot protocol failures manually.
- The specific path in use is available somewhere in Settings or a connection detail view for users who want it — but it is not surfaced by default.

---

### 24. Check That the First Connected Experience Feels Valuable
`Pre-engineering` | `P`

The moment the user first connects successfully is the most important moment in retention. Verify the design makes this moment feel meaningful:

- Does the app communicate what protection is now active in terms the user understands?
- Is there any indication of what threat was just mitigated (e.g., "Your traffic on this network is now encrypted")?
- Is the connection confirmation clear enough that the user doesn't wonder if it worked?

**Stress-test prompt:** "A user connects to Freewire for the first time at a coffee shop. What do they see in the app the moment it connects? Do they feel confident it's working, or do they have to wonder?"

---

### 25. Verify Setup Failure States Are Handled Gracefully
`Pre-engineering` | `P, E`

During onboarding, things will go wrong. Verify each failure is handled:

- VPN configuration permission denied: user is told exactly what to do to grant it
- No managed server available (server outage): user is told service is temporarily unavailable, not left with a spinner
- Self-hosted AWS deploy fails: user sees a plain-language error and is not stuck in the AWS console without guidance
- Cannot connect on any path: user sees a clear explanation that this network may not be supported, not a generic error

For each: does the user know what happened? Do they know what to do? Can they recover without contacting support?

---

### 26. Verify QR Code / Config File Flow for Self-Hosted Multi-Device
`Pre-engineering` | `P, E`

Users who self-host can add additional devices by sharing a QR code or config file. Verify:

- QR codes can be generated from either an already-configured client device (Settings → My server → Share config) or from the server web dashboard (§4.4)
- The QR code can be scanned on a second Apple device to connect it to the same self-hosted server
- The config file is a valid WireGuard-compatible format that the Freewire app can import
- No account or sign-in is required to import a config — consistent with the no-account identity model

---

### 27. Measure and Verify Onboarding Step Count
`Pre-engineering, at launch` | `P`

Count the number of discrete steps in each onboarding path. A step is any screen where the user must take an action before proceeding.

**Target:** Managed path — no more than 5 steps from app open to connected. Self-hosted path — no more than 12 steps.

For each step: is it necessary? Could it be combined with the previous step? Could it be deferred to after first connection?

---

## Infrastructure Security

### 28. Audit the DNS Tunnel Server as an Attack Surface
`Pre-engineering` | `E, S`

Freewire's authoritative DNS server for `tunnel.freewire.com` is a publicly accessible server that receives traffic from captive portal networks. Evaluate:

- If the DNS server is flooded with queries (DNS amplification or volumetric attack), does it degrade gracefully without affecting connected clients?
- Can an adversary send malicious query payloads that exploit the DNS tunnel parsing logic? Is all input validated and length-checked before processing?
- Does the server leak any information about connected clients (IPs, session state) through DNS error responses?
- Is the session key established in the tunnel handshake isolated per-client? Can one client's session be affected by another's?

**Stress-test prompt:** "An adversary sends 10 million crafted DNS queries to `tunnel.freewire.com` in one minute. What happens to existing connected clients?"

---

### 29. Verify the VPN Gateway Does Not Log User Traffic
`Pre-engineering, at launch` | `E, S`

The privacy policy commits to not logging user traffic content. Verify at the implementation level:

- No component in the VPN gateway pipeline writes packet payloads to any log, database, or monitoring system
- Connection metadata that is logged (timestamps, bytes transferred) cannot be used to reconstruct traffic content
- Third-party monitoring tools (crash reporting, infrastructure monitoring) are scoped to exclude user traffic data
- This verification is documented and repeatable — not just a statement of intent

---

### 30. Validate Kill Switch Implementation at the OS Level
`Pre-engineering` | `E, S`

The kill switch must be implemented at the OS level (NetworkExtension on Apple platforms), not just in application logic. Verify:

- If the Freewire app crashes while connected, the OS-level tunnel configuration continues to block traffic until the app restarts and the tunnel reconnects or the user explicitly disconnects
- The kill switch is not bypassable by putting the device in Airplane mode and back (which may reset the VPN state)
- The kill switch behavior is tested on both iOS and macOS — NetworkExtension behaves differently between the two platforms in some edge cases

---

### 31. Verify Privacy Pass Token Issuance and Device Key Storage
`Pre-engineering` | `E, S`

Two sensitive cryptographic assets must be handled correctly: the device WireGuard private key and Privacy Pass tokens.

**Device private key:**
- Stored in the iOS Keychain / macOS Keychain — never in UserDefaults, plist files, or app container storage
- Never logged in crash reports, analytics, or any external service
- Never transmitted — only the public key is sent to managed servers

**Privacy Pass tokens:**
- Issuance timing: resolved — initial batch requested on first connection attempt; background refresh when < 3 tokens remain; re-issuance is silent (Decision DM-3)
- Token storage: resolved — encrypted local file in app's protected data container (`FileProtection.completeUntilFirstUserAuthentication`); not in Keychain (tokens are anonymous credentials, not device secrets). See `privacy-pass-spec.md` §6.
- Spent token hashes are submitted to the server — verify this submission does not include any device-identifying data
- Token batch exhaustion: resolved — silent background re-issuance; never blocks the user

---

### 32. Validate AWS Self-Hosted Server Security Posture
`Pre-engineering` | `E, S`

The AWS AMI or CloudFormation template deploys user-owned infrastructure. Verify:

- The deployed server does not expose any management ports (SSH, HTTP admin console) to the public internet — management is done through the VPN tunnel itself or through AWS-native controls
- The server software automatically applies security updates or notifies the user when updates are available
- The server's VPN credentials are unique per deployment and are not shared with Freewire
- If a self-hosted server is compromised, the blast radius is limited to that user's own traffic — no Freewire infrastructure is affected

---

### 33. Verify the Direct Download macOS App Is Signed and Notarized
`At launch` | `E`

Before the macOS direct download ships:

- The application bundle is signed with a valid Apple Developer ID certificate
- The application has been submitted to and approved by Apple's notarization service
- Gatekeeper on a default macOS installation allows the app to open without a security warning
- The Sparkle auto-update mechanism verifies update signatures before applying them — malicious update payloads are rejected

---

## Failure Mode Review

### 34. Map Every Silent Failure Mode
`Pre-engineering` | `E, S`

A silent failure is one where the product stops protecting the user without notifying them. These are the most dangerous failures for a security product.

For each component, identify every condition under which it can fail silently:

- **Kill switch fails to activate on tunnel drop:** Traffic leaks unprotected without the user knowing. Under what conditions could this happen?
- **DNS tunnel established but throughput falls to zero:** The app shows "Connected" but no traffic is passing. How is this detected?
- **Managed server unreachable but app shows Connected:** Stale connection state. How quickly is this detected?
- **Sparkle update download fails silently:** User runs an outdated version with a known vulnerability. How is this surfaced?

For each: how quickly is the failure detected? What does the user see? Is there a way to make this failure visible rather than silent?

---

### 35. Verify Recovery Paths Are Defined for Every Failure Mode
`Pre-engineering` | `P, E`

For each failure mode in item 34:
- Is recovery automatic, user-initiated, or requires support?
- Is the recovery time bounded?
- Does the user understand what happened and what to do?

A failure mode with no documented recovery path is a design gap.

---

### 36. Validate Reconnection Behavior Across Network Changes
`Pre-engineering` | `E`

The app must reconnect automatically when the underlying network changes. Verify:

- Wifi → cellular handoff: tunnel drops, reconnect begins within 3 seconds, kill switch remains active during reconnect
- Wifi network change (coffee shop → airport): same as above
- Network temporarily unavailable (elevator, tunnel): app detects no network, waits, reconnects when network returns
- VPN reconnect on the new network: does the client re-run the fallback chain (the new network may have different captive portal behavior) or assume the same path works?
- After reconnect: is the user notified that a reconnect occurred? Should they be?

---

### 37. Verify Behavior When All Fallback Paths Fail
`Pre-engineering` | `P, E`

When HTTP CONNECT, TLS/443, DNS tunnel, and ICMP all fail, the client immediately runs a captive portal probe before showing any error. This probe determines which of two branches to take:

**CONN-2a (portal detected — probe returns redirect or unexpected body):**
- In-app browser opens automatically (SFSafariViewController / sheet)
- Status: "One more step — authenticate with this network."
- On browser dismiss, client automatically retries the fallback chain — no user tap required
- This is a soft state, not a final failure

**CONN-2b (genuine block — probe times out or connection refused):**
- Kill switch remains active, no traffic flows
- User sees: "This network blocks VPNs / Freewire tried every method."
- Options: try again, cancel (disable kill switch and browse unprotected)
- The app does not retry in a tight loop — retry is user-initiated

**Both branches:**
- The failure is logged internally for diagnostic purposes, but no user-identifying data is logged
- The probe adds at most 1 second to the total failure time
- A slow network must not misclassify CONN-2b as CONN-2a (1-second probe timeout is the gate)

---

### 38. Validate Sparkle Auto-Update Failure Modes
`Pre-engineering` | `E`

The macOS direct download relies on Sparkle for updates. Verify:

- If the update server is unreachable, the app continues to function normally and retries on the next launch
- If an update download fails mid-way, the partial download is discarded and the existing version continues to run
- If an update signature fails verification, the update is rejected and the user is notified
- Security-critical updates can be marked mandatory — the app prompts the user to update and may restrict functionality until they do

---

## Privacy and Data Handling

### 39. Audit What Freewire Collects, Stores, and Transmits
`At launch, quarterly` | `P, S`

Document every category of data Freewire handles:

- **Identity data:** No Apple identity token, no email, no user identifier. Device public key is the sole identity. Verify nothing beyond the public key is stored server-side.
- **Connection metadata:** Aggregate only — hourly rollups per server (peak connection count, latency percentiles). No per-device or per-connection records. Verify at the implementation level.
- **Crash reports:** What is included? Does any crash report include user identifiers, IP addresses, or tunnel state that could reveal what the user was doing?
- **Traffic content:** Must not be logged anywhere under any circumstances. Verify at the implementation level.
- **Analytics:** Any in-app analytics must require explicit opt-in consent (PRD requirement). Verify no analytics fire before consent is obtained.

**Stress-test prompt:** "A law enforcement request arrives asking for the traffic logs of a specific user for a specific date. What can Freewire provide? What can it not provide? Does the answer match what the privacy policy says?"

---

### 40. Verify the Privacy Policy Matches Implementation
`At launch` | `P, S`

Every claim in the privacy policy must be verifiable at the implementation level:

- "We do not log your traffic": verify no component logs packet payloads
- "We do not sell your data": verify no data is shared with third parties for commercial purposes
- "We collect [X]": verify exactly X is collected — neither more nor less

Flag any discrepancy between what the policy says and what the implementation does.

---

### 41. Verify Consent Is Obtained Before Analytics Fire
`Pre-engineering` | `E`

If any analytics, telemetry, or crash reporting is present:

- No data is transmitted before the user is informed and consents
- Consent is explicit — pre-checked boxes or continued use as implied consent are not sufficient
- The user can withdraw consent at any time in settings
- Withdrawing consent stops all data transmission immediately

---

### 42. Verify Self-Hosted Users Have No Data Exposure to Freewire
`Pre-engineering` | `P, E`

Users who self-host on AWS route their traffic through their own server. Freewire should have no visibility into their traffic. Verify:

- The self-hosted server software does not phone home with traffic metadata
- Connection credentials between the Freewire app and a self-hosted server are generated locally — Freewire's backend does not hold them
- There are no Freewire accounts — all users (managed and self-hosted) use device-key-only identity. Verify no code path requires or assumes an account exists.

---

## Performance Review

### 43. Verify Performance Targets Are Testable
`Pre-engineering` | `E`

Every performance target in the PRD must be testable with a defined method. For each target, document how it will be measured:

| Target | Measurement method |
|---|---|
| TLS/443 path: ≥50 Mbps sustained | iperf3 between client and managed server, 60-second run |
| DNS tunnel: ≥500 Kbps minimum | Custom DNS tunnel benchmark, sustained for 60 seconds |
| Time-to-connected (normal network): ≤10 seconds | Stopwatch from Connect tap to Connected state |
| Latency overhead (TLS/443): ≤20ms avg | ping comparison: direct vs. through tunnel |
| Fallback chain total: ≤10 seconds | Measure time from captive portal detection to tunnel established |

---

### 44. Validate DNS Tunnel Throughput Target Is Achievable
`Pre-engineering` | `E`

The 500 Kbps minimum DNS tunnel throughput is achievable in theory with the optimizations in `technical-architecture.md`. Verify before engineering begins:

- Is 500 Kbps achievable with the sliding window size and EDNS0 response sizes specified?
- What round-trip latency does the calculation assume? At launch (single US-East server), what is the expected latency for US, EU, and APAC users, and is the resulting throughput still usable?
- Has the throughput calculation been validated with a prototype or simulation, or is it theoretical?
- What is the degraded throughput if EDNS0 is stripped by the resolver? Is it still usable?

**Stress-test prompt:** "A user is on a captive portal network with 150ms round-trip DNS latency. What is the theoretical maximum throughput of the DNS tunnel at that latency? Is it enough to load a webpage?"

---

### 45. Verify Connection Speed Does Not Degrade Under Load
`Pre-engineering` | `E`

Managed server performance must not degrade significantly as user count increases. Define:

- What is the maximum concurrent user count per managed server before throughput degrades below the 50 Mbps target?
- What is the horizontal scaling mechanism? (Adding servers? Load balancing?)
- Is there a per-user bandwidth cap, or is it shared infrastructure?
- Are DNS tunnel sessions more expensive than TLS/443 sessions? If so, how does a high DNS-tunnel-to-TLS ratio affect server capacity?

---

### 46. Verify Battery and CPU Impact on Mobile
`Pre-engineering` | `E`

A VPN that runs continuously on iOS drains the battery. Measure and verify:

- The NetworkExtension packet tunnel provider does not run in a tight loop when idle
- DNS tunnel keepalive query frequency is low enough that it does not measurably affect battery life
- The app does not prevent the device from entering low-power mode when the screen is off
- Background reconnection does not cause CPU spikes that drain the battery

---

## Competitive Differentiation

### 47. Verify Competitive Claims Are Current and Accurate
`Quarterly` | `P, B`

Review the competitive positioning in PRD §4. For each competitor listed, verify the claims about their product are still accurate:

- Do NordVPN, ExpressVPN, and Surfshark still fail on captive portal networks? (If they add this capability, our differentiation narrows.)
- Is Outline VPN's self-hosted positioning still as described?
- Has Google One VPN's deprecation status changed?
- Are the stated prices for competitors still current?

Flag any claim that is more than 6 months old without reverification.

---

### 48. Stress-Test the Core Differentiation
`Quarterly` | `P`

Freewire's differentiation rests on three claims: free, easy to set up, works on captive portals. For each:

- **Free:** Could a competitor launch a free tier that eliminates this advantage? How quickly could that happen?
- **Easy to set up:** Is the setup actually easier than a competitor like Outline, or just differently documented?
- **Captive portal bypass:** If NordVPN or Cloudflare WARP adds reliable captive portal bypass, what is Freewire's remaining differentiation?

**Stress-test prompt:** "Cloudflare announces WARP works on all captive portal networks for free, today. What is Freewire's competitive position tomorrow?"

---

### 49. Verify the Product Does Not Overstate Its Security Guarantees
`At launch` | `P`

A VPN encrypts traffic between the device and the VPN server. It does not: protect against malware on the device, protect against phishing, prevent the VPN server from seeing traffic destinations (unless using DNS-over-VPN), or protect against tracking via device fingerprint or cookies.

Verify no marketing copy, in-app text, or documentation implies protections Freewire does not provide. Plain-language explanations of what a VPN does and does not protect against must be present and accurate.

---

## Launch Readiness Gates

### 50. Apple Entitlement Status
`At launch` | `[CRITICAL for TestFlight]`

Two entitlements require manual Apple approval. Both have no guaranteed timeline; apply for them simultaneously when the NE integration phase begins.

**NEPacketTunnelProvider** (`com.apple.developer.networking.networkextension`) — Required before TestFlight distribution. Must be in the provisioning profile for any build that uses NetworkExtension APIs.
- Application submitted: ☐ Not yet / ☐ Submitted on [date] / ☐ Approved

**NEHotspotHelper** (`com.apple.developer.networking.HotspotHelper`) — Enables fully automatic captive portal authentication for simple accept-terms portals. The app degrades gracefully without it; this is not a launch blocker, but is a significant UX improvement.
- Application submitted: ☐ Not yet / ☐ Submitted on [date] / ☐ Approved

**NEPacketTunnelProvider must be approved before TestFlight distribution begins.** Both entitlements must be approved before App Store submission (post-launch for iOS).

Application guidance — including recommended framing for both entitlements — is in `apple-entitlement-application.md`.

---

### 51. Verify the App Passes App Store Review Requirements
`Post-launch (iOS App Store submission)` | `P, E`

iOS launches via TestFlight; App Store submission is a subsequent milestone. When preparing for App Store submission, Apple has specific requirements for VPN apps:

- The app must not collect or transmit user data without explicit disclosure
- The app must use VPN APIs only for their intended purpose (routing user traffic through a legitimate VPN)
- The privacy policy URL must be present in the App Store listing and the app itself
- The app must not misrepresent its capabilities (no claims of anonymity the product does not provide)

Verify the app and its listing are compliant before App Store submission.

---

### 52. Verify Managed Server Infrastructure Sustainability Plan
`At launch` | `P, B`

Freewire has no revenue mechanism. Before launch:

- Infrastructure cost per user is estimated and documented
- A runway figure exists: how long can managed servers run at projected launch-day user counts before a funding decision is required?
- A contingency is documented for the scenario where costs exceed budget (pause managed servers, introduce paid tier, transition to fully community-hosted model)

---

## UX Behavior Verification

These items verify that specific UX behaviors introduced in the design work as specified. Each involves a one-time event, a state machine branch, or opt-in logic that is easy to get subtly wrong.

### 53. Verify CONN-2a vs. CONN-2b Detection and Divergence
`Pre-engineering` | `P, E`

After all four fallback paths fail, the client runs a captive portal probe. Verify the two outcomes are handled correctly and never conflated:

- **CONN-2a (portal detected):** The probe returns a 3xx redirect or unexpected body. The client auto-opens SFSafariViewController (iOS) or a sheet browser (macOS) without requiring the user to tap anything first. The status line shows "One more step — authenticate with this network." — not a generic error.
- **CONN-2b (genuine block):** The probe times out or connection is refused. The client shows "This network blocks VPNs / Freewire tried every method." — a hard error with a try-again option, no browser opens.
- The probe itself has a 1-second timeout. Verify a slow network does not misclassify CONN-2b as CONN-2a (browser opens for a non-portal block).
- After the in-app browser is dismissed (CONN-2a), the client automatically retries the fallback chain. Verify retry fires without user tapping Connect again.

**Stress-test prompt:** "A user is on a hotel network that has been fully shut down by IT — no internet at all. What does the captive portal probe return? Does the user see CONN-2a or CONN-2b? Does a browser open?"

---

### 54. Verify First Captive Portal Success Moment Fires Once
`Pre-engineering` | `P, E`

The first time Freewire successfully connects via a captive portal path (CONN-2a resolved to connected), the app shows a one-time success message: "Connected on a network that blocks standard VPNs." Verify:

- The message fires on the first captive portal success, regardless of which subsequent path was used (DNS, ICMP, etc.)
- The message never fires again on subsequent captive portal connections — it is shown exactly once, ever
- The one-time flag is stored durably (survives app restart, not just in-memory)
- The message does not fire on normal connections (TLS/443 on open networks)
- If the user never connects on a captive portal, the message never appears

---

### 55. Verify Network Intelligence Opt-In Prompt Timing and Recurrence
`Pre-engineering` | `P, E`

The network intelligence opt-in bottom sheet must fire at the right moment and never reappear:

- The sheet appears a few seconds after the first captive portal success moment (item 54) — not immediately, not before connected state is confirmed
- The sheet text: "Help others connect faster / Share that this connection method worked on this network. No location data or personal information is collected. / [Share anonymously] [No thanks]"
- The sheet is shown exactly once ever, regardless of whether the user taps Share or No thanks
- If the user dismisses with the system swipe-down gesture (no button tap), the dismissal counts as "No thanks" — the sheet does not reappear
- The network intelligence feature default is OFF. Tapping [Share anonymously] sets it to ON and submits the current network report. Tapping [No thanks] leaves it OFF.
- The opt-in state persists across app restarts and device reboots

---

### 56. Verify Kill Switch First-Connect Tooltip Fires Once
`Pre-engineering` | `P, E`

On the first successful VPN connection where kill switch is enabled, a tooltip appears: "Kill switch is on: if this connection drops, your traffic stays blocked until Freewire reconnects. You can change this in Settings. [Got it]" Verify:

- The tooltip fires only on the first connection where kill switch is active, not on every connection
- The tooltip auto-dismisses after 6 seconds even without a tap
- The tooltip never reappears after being shown once or dismissed
- The one-time flag persists across app restarts
- The tooltip does not fire if kill switch is disabled at time of connection
- If the user disables kill switch, then re-enables it, the tooltip does not fire again

---

### 57. Verify "What Freewire Sees" Privacy Screen
`Pre-engineering, at launch` | `P`

The Settings → Privacy section must include a "What Freewire sees" screen. Verify:

- The screen is accessible from Settings on both iOS and macOS
- The screen lists: ✕ Your IP address / ✕ What you browse / ✕ When you connected / ✕ Your identity / ✓ Anonymous rate-limit tokens (unlinked, deleted 30 days)
- The items displayed match what the privacy policy actually says — no discrepancies
- A "Read our privacy policy" link at the bottom opens the live privacy policy URL
- The "Improve detection [OFF]" toggle in Settings controls network intelligence opt-in and matches the state set by the bottom sheet (item 55)

---

### 58. Verify macOS "Connect Automatically" Toggle
`Pre-engineering` | `P, E`

macOS Preferences must include a "Connect automatically [ON]" toggle. Verify:

- The toggle defaults to ON for managed server connections
- When ON, Freewire connects automatically on launch and on network changes without user interaction
- When OFF, Freewire starts in disconnected state and requires user to tap Connect
- The toggle state persists across app restarts
- Toggling does not disconnect an active tunnel — the change takes effect on the next connection event

---

### 59. Verify Device Name Pre-Population in Self-Hosted QR Flow
`Pre-engineering` | `P, E`

When a user scans a self-hosted server QR code, the app may optionally share the device model name with the server admin. Verify:

- During the import confirmation screen, the user sees: "Share your device name with the server admin?" with a clear Yes / No choice — not a pre-checked box
- If the user taps Yes, the device model (e.g., "iPhone 16 Pro") is included in the `POST /v1/peers` request and stored as `device_name` on the server
- If the user taps No, no device name is transmitted — the field is absent from the request
- The server dashboard shows the `device_name` in the device list when present, falls back to showing the key fingerprint when absent
- This prompt appears only in the self-hosted QR scan flow, not in managed server onboarding

---

### 60. Verify NEHotspotHelper Graceful Degradation
`Pre-engineering` | `P, E`

The app must function correctly whether or not the NEHotspotHelper entitlement is granted. Verify:

- Without the entitlement: the app follows the standard CONN-2a flow — captive portal probe fires after all paths fail, in-app browser opens, user authenticates manually, auto-retry fires on dismiss. No visible feature is missing.
- With the entitlement: for simple accept-terms portals, authentication completes silently before the user taps Connect. The user sees the normal "Connected" state with no interruption.
- With the entitlement, for portals requiring user input (email, room number, payment): `NEHotspotHelperResult.unsupported` is returned, and the normal CONN-2a in-app browser flow takes over. The entitlement does not break complex portals.
- The presence or absence of the entitlement is not communicated to the user — the UX is identical from the user's perspective, just faster when the entitlement is available.

---



Run at the end of every session. Scan the documents touched this session for:

- ✓ "captive portal" — consistent
- ✓ "managed server" / "self-hosted server" — consistent
- ✓ "tunnel" — consistent
- ✓ "kill switch" — consistent
- ✓ No acronyms introduced without definition on first use
- ✓ No pricing discussion in product documents
- ✓ No visual design language in UX documents
