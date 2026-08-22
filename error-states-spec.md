# Freewire VPN — Error States Specification

**Version:** 0.2  
**Status:** Draft

---

## Interim: kill switch not yet enforced

**Applies until `FreewireHelper` ships.** Every "kill switch active / traffic is blocked" behavior in this document describes the intended end state. None of it is enforced today: `FreewireHelper` does not exist, no `pf` rules are installed, and traffic flows normally whenever the tunnel is down.

Until the helper ships, the UI must not claim protection it cannot deliver. A user on hotel or airport wifi who reads "traffic is blocked" and is not blocked is worse off than one who was told nothing.

Interim copy, to be implemented verbatim and reverted when the helper lands:

| Location | Interim copy |
|---|---|
| Preferences toggle | Label: "Kill switch" — control **disabled**. Caption: "Not available yet. When the VPN drops, traffic is not blocked. Coming in a future release." |
| SESSION-1 (reconnecting) | "Attempt {n} of 3. Your traffic is not protected while reconnecting." |
| SESSION-2 (blocked) | "Reconnection failed. Your traffic is not protected. Reconnect or disconnect." |
| First-connect tooltip | Suppressed entirely. |

The kill switch preference must also default to **off** while unenforced, so no user carries a stored `true` that implies protection.

When `FreewireHelper` ships: restore the copy specified in SESSION-1, SESSION-2, and `ux-workflows.md`, restore the default to on, and delete this section.

**Resolved design decision (2026-08-21):** if the privileged helper dies unexpectedly while the tunnel is up, `pf` rules **persist** — fail closed. Traffic stays blocked until the user explicitly reconnects or disconnects, consistent with `engineering-handoff.md` §5 ("kill switch never releases automatically without user action"). The tradeoff is accepted: a helper crash can leave the machine without network until Freewire is relaunched.

---

## Local tunnel failures (TUN)

Failures of the `freewire-tunnel` helper on the client, before or instead of a
server-side error. These are distinct from the CONN states: no connection was
attempted or the attempt never reached the network.

Copy is specified here because it is shown to users verbatim. It was previously
invented in `TunnelManager.swift` with no spec entry, which left crash reports
and support tickets with no way to match a reported message to a known state.

| ID | Condition | User-visible message | Type |
|---|---|---|---|
| TUN-1 | The helper binary is missing from the bundle | "Freewire is missing a component it needs. Reinstalling should fix it." | Hard block |
| TUN-2 | The helper cannot get administrator rights | "Freewire needs administrator access to create the tunnel." | Hard block |
| TUN-3 | The helper exited with a diagnostic | "The tunnel could not start. {detail}" | Hard block |
| TUN-4 | The helper produced unreadable output | "The tunnel reported something unexpected. Try connecting again." | Soft warning |
| TUN-5 | The helper did not report ready within 30s | "The tunnel took too long to start. Try connecting again." | Soft warning |

TUN-3 carries the helper's own text. It is the one message with interpolated
content, because the underlying causes are open-ended and a generic string would
discard the only diagnostic available.

Note that `allPathsFailed` is not listed: it is not surfaced as an error. It
routes to CONN-2a or CONN-2b after the captive portal probe.

---

## Awaiting portal authentication (CONN-2a continued)

CONN-2a tells the user "Authenticate with this network, then Freewire will
reconnect automatically." The client must stay in a state that reflects that
promise while it waits, rather than dropping to "Not protected" the moment the
login page opens — which contradicts the sentence the user just read and hides
the fact that Freewire is still watching.

| State | User-visible message | Behavior |
|---|---|---|
| Awaiting portal | "Waiting for you to finish signing in…" with a spinner. Secondary: "Freewire will connect as soon as this network lets it through." | Polls the portal probe; connects automatically once the intercept clears. A Cancel affordance returns to disconnected. |
| Portal wait exhausted | "Still not connected. Finish signing in to this network, then try again." | Offered after the wait elapses. Retry re-enters the wait rather than failing outright. |

The wait must not expire silently. Hotel portals routinely involve a payment
form, an SMS code, or a room-number lookup, all of which take longer than a
short timer; a user who completes login after the timer has lapsed would
otherwise see nothing happen and the promise silently broken.

---

## Server identity (TRUST)

The API is where a client learns the server's WireGuard public key. Whoever
supplies that key can terminate the tunnel and read everything inside it, so it
is the trust anchor for the entire product.

Transport security alone is not sufficient. A CA-signed certificate proves the
client reached the host it asked for; it does not prove the key that host
returned is the right one, and a single mis-issued certificate would be enough
to substitute it. The key is therefore pinned independently of the certificate
that delivered it.

| ID | Condition | User-visible message | Type |
|---|---|---|---|
| TRUST-1 | No pinned key is configured for this server | "Freewire does not have a trusted key for this server. Add the server's key before connecting." | Hard block |
| TRUST-2 | The server returned a key that does not match the pin | "This server's identity does not match the one Freewire trusts. Connection refused." | Hard block |
| TRUST-3 | The server rejected the connection token (HTTP 402) | "Freewire could not verify this connection. Try again in a moment." | Retry once, then surface |
| TRUST-4 | The Privacy Pass issuer key changed since first use | "This server's identity does not match the one Freewire trusts. Connection refused." | Hard block |

TRUST-2 is never retried automatically and never offers "connect anyway". A
mismatch is either a server that rotated its key without publishing the
successor, or an attacker — and the client cannot distinguish them. Offering a
bypass would hand the user the one decision they have no way to make correctly.

Rotation is handled by accepting more than one key: the successor is published
and shipped before the server switches, so no client is ever stranded.

TRUST-3 covers a token the server declined — spent, malformed, or signed under a
key it no longer holds. The copy says nothing about tokens because the user has
no token to act on: they never see one, cannot inspect one, and the fix in every
case is a fresh batch, which the client requests on its own. One silent retry
covers the ordinary case of a stale batch.

TRUST-4 shares TRUST-2's copy deliberately. Both are the same event to the user
— the server is not the one this client trusts — and the distinction between a
WireGuard key and a token-issuer key is not one the message should ask them to
hold. It is a hard block for the reason blind signing exists: an issuer that
gives each client its own key can identify that client at redemption, every
signature still verifies, and nothing else in the system notices.

---

## App Transport Security and self-signed servers

A server on a bare IP cannot hold a CA-signed certificate, and **ATS rejects a
self-signed certificate before the authentication challenge delegate is
consulted** — so key pinning never gets the chance to accept it. The connection
fails with `NSURLErrorSecureConnectionFailed` (-1200) even though the pin is
present and correct.

This is not visible from a command-line build: ATS applies to app bundles, so
the same code succeeds outside one and fails inside.

**Resolved.** The control plane no longer uses URLSession. `PinnedHTTPClient`
speaks HTTP/1.1 over `Network.framework` and installs a verify block, so
certificate validation happens in the app's own code rather than being an
override bolted onto the system's — which is what a pinning client wants in any
case. ATS is fully enforced, with no `NSAllowsArbitraryLoads`.

A self-signed certificate is accepted only when the user has pinned a key out
of band; a real hostname gets the system's normal chain validation. Verified
both ways: the correct pin connects with ATS enforced, and a wrong pin is
refused.

---

## Error Type Taxonomy

- **Silent failure** — logged internally; user not notified; connection continues or degrades gracefully
- **Soft warning** — user informed but can continue or retry; no permanent block
- **Hard block** — user cannot proceed until the error is resolved; all traffic remains blocked (kill switch active if tunnel was established)

---

## 1. Connection Errors (CONN)

Errors that occur before a tunnel is established.

---

### CONN-1 — No network connectivity

**Trigger:** Device has no network access (airplane mode, no wifi, no cellular signal).

**Behavior:**
- System detects unreachable network before attempting any tunnel path
- No connection attempt is made
- User sees: [WARNING] "No internet connection. Connect to a network and try again."
- Retry button available; connection attempt resumes automatically when network becomes available
- Type: **Hard block**

---

### CONN-2 — All tunnel paths failed

**Trigger:** HTTP CONNECT, TLS/443, DNS tunnel, and ICMP paths all fail sequentially during the protocol fallback chain.

**Per-path timeout allocation (10-second total budget):**
| Path | Timeout | Notes |
|---|---|---|
| HTTP CONNECT | 2s | TCP connect + CONNECT method response |
| TLS/443 | 3s | TCP + TLS handshake + first keepalive response |
| DNS tunnel | 3s | 3 DH handshake round trips at ~1s each |
| ICMP | 2s | 3 echo request/reply cycles |
| Captive portal probe | 1s | `http://captive.apple.com` — fires after all paths fail |

Total: ≤11s to CONN-2a or CONN-2b.

After all four paths fail, the client immediately runs a **captive portal probe**: it makes an HTTP request to a known plain-HTTP endpoint (`http://captive.apple.com` or `http://neverssl.com`). The response determines which of two sub-states applies.

---

#### CONN-2a — Captive portal authentication required

**Probe result:** HTTP request returns a redirect (3xx) or a non-expected response body — indicating a captive portal is intercepting traffic but has not been authenticated.

**Behavior:**
- Kill switch remains inactive (no tunnel established)
- Client automatically opens the portal's redirect URL in an in-app browser (`SFSafariViewController` on iOS; `WKWebView` sheet on macOS)
- No error message is shown before the browser opens — user sees a portal authentication screen, not a Freewire error
- Status message during browser: "Authenticate with this network, then Freewire will reconnect automatically."
- When the in-app browser is dismissed (user completes portal interaction) OR when network state changes to indicate authenticated, client immediately retries the full fallback chain
- If retry succeeds: browser closes, tunnel establishes, user sees "Connected" — no error state reached
- If retry fails (portal authenticated but network still blocks all paths): fall through to CONN-2b
- Type: **Soft warning** (portal prompt is not a failure state; it is a guided authentication step)

**NEHotspotHelper (fully automatic, where entitlement is granted):**
For simple accept-terms portals that require only an HTTP GET to confirm acceptance, `NEHotspotHelper` can complete authentication silently in the background with no in-app browser shown. When this path succeeds, the user sees only the normal "Connecting..." state followed by "Connected" — portal interaction is invisible. See `apple-entitlement-application.md` §NEHotspotHelper.

---

#### CONN-2b — Genuine network block

**Probe result:** HTTP request to the probe endpoint times out, or returns the expected response (no redirect) — indicating traffic is genuinely blocked, not just unauthenticated.

**Behavior:**
- Kill switch remains inactive
- User sees: [WARNING] "This network is blocking secure connections."
  Sub-text: "Freewire tried every available method. This network may restrict all VPN traffic."
- Manual retry button shown
- Type: **Hard block**

---

### CONN-3 — Managed server unreachable

**Trigger:** The Freewire managed server endpoint does not respond within the connection timeout on an otherwise functional network.

**Behavior:**
- Client retries up to 3 times with exponential backoff (2s, 4s, 8s)
- After 3 failed attempts, connection terminates
- User sees: [WARNING] "Freewire's servers are unreachable right now. Try again in a moment."
- Retry button shown; error logged internally for server monitoring
- Type: **Soft warning** (transient) → **Hard block** after retries exhausted

---

### CONN-4 — Managed server at capacity

**Trigger:** Managed server rejects the peer connection because the maximum concurrent peer count has been reached.

**Behavior:**
- At launch (one region): no automatic failover available
- User sees: [WARNING] "Freewire's servers are at capacity. Try again in a few minutes."
- Retry button shown; error logged internally for capacity monitoring
- Post-launch (multiple regions): client automatically attempts next available region before showing error
- Type: **Hard block** (at launch)

---

### CONN-5 — Connection timeout (open network)

**Trigger:** Connection attempt on a normal (non-captive portal) network exceeds 10 seconds without establishing a tunnel.

**Behavior:**
- Client retries once automatically
- If retry also times out, connection terminates
- User sees: [WARNING] "Connection timed out. Check your network and try again."
- Retry button shown
- Type: **Soft warning** → **Hard block** after retry

---

## 2. Active Session Errors (SESSION)

Errors that occur after a tunnel has been established.

---

### SESSION-1 — Unexpected tunnel drop — kill switch activates

**Trigger:** An established tunnel drops for any reason other than a user-initiated disconnect (network change, NE process crash, server restart, etc.).

**Behavior:**
- Kill switch activates immediately — all network traffic is blocked at the OS level
- Automatic reconnection begins within 3 seconds
- While reconnecting: user sees [WARNING] "Connection dropped. Reconnecting..." with a spinner
- Traffic remains blocked during reconnection (kill switch stays active)
- If user has granted notification permission: push notification sent — "Freewire reconnecting. Traffic blocked until restored."
- Type: **Soft warning** (auto-recovers) → SESSION-2 if reconnection fails

---

### SESSION-2 — Reconnection failed after 3 attempts

**Trigger:** 3 automatic reconnection attempts all fail following a tunnel drop (SESSION-1).

**Behavior:**
- Kill switch remains active — all traffic blocked
- Automatic retry stops; user must take action
- User sees: [URGENT] "Reconnection failed. Your traffic is blocked."  
  Two actions: [ Retry ] [ Disconnect ]
  - Retry: begins a fresh connection attempt
  - Disconnect: releases kill switch, traffic flows unprotected, user is warned before this happens
- If user has granted notification permission: push notification sent — "Freewire couldn't reconnect. Tap to retry."
- Type: **Hard block** (with user-controlled escape via Disconnect)

---

### SESSION-3 — Network change mid-session

**Trigger:** Device switches networks during an active tunnel (wifi → cellular, one wifi network → another).

**Behavior:**
- NE framework detects network change and triggers automatic reconnection
- If reconnection completes within 3 seconds: silent; no user notification
- If reconnection takes longer than 3 seconds: brief [WARNING] "Switching networks..." shown, resolves automatically on success
- If reconnection fails: escalates to SESSION-1
- Type: **Silent failure** (if seamless) / **Soft warning** (if brief delay)

---

### SESSION-4 — NetworkExtension process killed by OS

**Trigger:** iOS or macOS kills the NE extension process due to system memory pressure or OS-level termination.

**Behavior:**
- Kill switch remains active at the OS level even after process termination (NE framework behavior)
- Traffic is blocked until the app reconnects or the user disconnects
- On next app foreground: app detects terminated NE process, shows [WARNING] "VPN was interrupted by the system. Reconnect?"
- Actions: [ Reconnect ] [ Disconnect ]
- Type: **Soft warning**

---

## 3. Permission Errors (PERM)

Errors caused by missing or revoked OS permissions.

---

### PERM-1 — VPN permission denied during onboarding (iOS)

**Trigger:** User taps Deny on the iOS VPN configuration system prompt during onboarding.

**Behavior:**
- Onboarding cannot complete; no tunnel can be established without this permission
- User sees: [WARNING] "VPN permission needed"  
  "Freewire needs permission to set up a VPN connection. Go to Settings → General → VPN & Device Management to allow it."
- Actions: [ Open Settings ] [ Try Again ]
  - Open Settings: deep-links to iOS VPN settings
  - Try Again: re-triggers the system permission prompt if not permanently denied
- Type: **Hard block**

---

### PERM-2 — VPN permission revoked after setup (iOS)

**Trigger:** User removes the Freewire VPN configuration in iOS Settings after completing onboarding.

**Behavior:**
- Detected on next connect attempt or app foreground
- User sees: [WARNING] "VPN configuration removed"  
  "Freewire's VPN configuration was removed from your device. Tap below to restore it."
- Action: [ Restore VPN Configuration ] — re-triggers permission prompt
- Type: **Hard block**

---

### PERM-3 — macOS System Extension approval dismissed

**Trigger:** User clicks "Not Now" or dismisses the System Extension approval dialog during macOS onboarding.

**Behavior:**
- Onboarding cannot complete without System Extension approval
- User sees recovery screen: [WARNING] "System Extension approval needed"  
  "Open System Settings → Privacy & Security and click Allow next to Freewire."
- Action: [ Open System Settings ] — deep-links to Privacy & Security panel
- The app checks periodically (every 5 seconds while this screen is shown) for approval; proceeds automatically when granted
- Type: **Hard block**

---

### PERM-4 — macOS System Extension revoked after setup

**Trigger:** User removes the Freewire System Extension from System Settings → Privacy & Security after setup.

**Behavior:**
- Detected on next connect attempt
- User sees: [WARNING] "System Extension removed"  
  "Freewire's system extension was removed. Reinstall Freewire to restore it."
- Action: [ Download Freewire ] — links to direct download page
- Type: **Hard block**

---

## 4. Self-Host Errors (SELFHOST)

Errors specific to users running their own server.

---

### SELFHOST-1 — Config import failed (invalid format)

**Trigger:** User imports a config file (.conf or QR scan) that is malformed, missing required fields, or uses an incompatible format.

**Behavior:**
- Import rejected immediately; no partial config saved
- User sees: [WARNING] "Couldn't import this config"  
  "The file doesn't look like a valid Freewire server config. Generate a new one from your server's setup page."
- Action: [ Try Again ]
- Type: **Hard block**

---

### SELFHOST-2 — QR code expired

**Trigger:** User attempts to scan a QR code that has passed its 24-hour expiry window.

**Behavior:**
- QR scan is rejected on the client after checking the embedded expiry timestamp
- User sees: [WARNING] "QR code expired"  
  "This QR code is no longer valid. Visit your server's setup page to generate a new one."
- Action: [ Try Again ]
- Type: **Hard block**

---

### SELFHOST-3 — Self-hosted server unreachable

**Trigger:** The user's self-hosted server does not respond to connection attempts (AWS instance stopped, billing lapse, misconfigured security group, etc.).

**Behavior:**
- Client retries up to 3 times with exponential backoff
- After retries exhausted, connection terminates
- User sees: [WARNING] "Couldn't reach your server"  
  "Your server isn't responding. Check that it's running in your AWS console."
- Action: [ Retry ]
- Type: **Hard block**

---

### SELFHOST-4 — Server key mismatch (server re-deployed)

**Trigger:** The self-hosted server has been re-deployed with a new WireGuard keypair, but the client still holds the old server public key in its config.

**Behavior:**
- WireGuard handshake fails with authentication error
- Client detects repeated handshake failure (not a network issue)
- User sees: [WARNING] "Server config has changed"  
  "Your server may have been updated or re-deployed. Import a new config from your server's setup page."
- Actions: [ Import New Config ] [ Retry ]
- Type: **Hard block**

---

### SELFHOST-5 — CloudFormation deployment failed (server setup flow)

**Trigger:** The AWS CloudFormation stack creation fails during the self-hosted server setup flow.

**Behavior:**
- Setup flow detects failure (via AWS status page or polling)
- User sees: [WARNING] "Server setup failed"  
  "Something went wrong deploying your server on AWS. Check your AWS console for details, then try again."
- Action: [ View in AWS Console ] [ Try Again ]
- Setup flow does not proceed past this step; no config is generated for a failed stack
- Type: **Hard block** (in setup flow)

---

## 5. Privacy Degradation Errors (PRIVACY)

Errors where Freewire's cryptographic privacy guarantees are reduced but the connection continues.

---

### PRIVACY-1 — DoH resolver unreachable (DNS over HTTPS fallback)

**Trigger:** The configured DoH resolver (e.g., Cloudflare 1.1.1.1) is unreachable — either the network blocks DoH or the resolver is down.

**Behavior:**
- Client falls back to system DNS (unencrypted, DNS queries may be visible to the network)
- Connection continues; tunnel is still active and traffic is still encrypted
- User sees: [WARNING] "Reduced privacy: DNS not encrypted"  
  "Freewire couldn't reach its secure DNS resolver. DNS queries may be visible to your network provider until this resolves."
- Logged internally
- Client retries DoH resolver in background every 60 seconds; warning dismisses automatically when DoH is restored
- Type: **Soft warning**

---

### PRIVACY-2 — ECH negotiation failure

**Trigger:** The destination server does not support Encrypted Client Hello (ECH). This is the expected behavior for the majority of destinations.

**Behavior:**
- Client falls back to standard TLS with visible SNI (hostname visible to Freewire's managed server)
- No user notification — this is the expected current state of the internet
- Logged internally for aggregate reporting only
- Type: **Silent failure** (expected; not an error in practice)

---

## 6. System and App Errors (SYS)

---

### SYS-1 — App version incompatible with server

**Trigger:** The Freewire server rejects a connection from a client that is too old to be supported (future scenario after a breaking protocol update).

**Behavior:**
- Connection rejected by server with an incompatible-version signal
- User sees: [URGENT] "Update required"  
  "This version of Freewire is no longer supported. Update to continue."
- iOS: [ Update in TestFlight ]
- macOS: [ Download Update ] — links to direct download; Sparkle update also triggered if available
- No connection possible until updated
- Type: **Hard block**

---

### SYS-2 — Device keychain unavailable

**Trigger:** The device keychain is unavailable or locked when the app attempts to read the WireGuard private key (e.g., device not yet unlocked after reboot).

**Behavior:**
- Connection cannot proceed without the private key
- User sees: [WARNING] "Unlock your device to connect"  
  "Freewire needs access to your device's keychain. Unlock your device and try again."
- Action: [ Try Again ]
- Type: **Hard block** (resolves when device is unlocked)

---

## 7. macOS Update Errors (UPDATE)

---

### UPDATE-1 — Sparkle update download failed

**Trigger:** The Sparkle auto-update framework cannot download an available update (network error, CDN issue).

**Behavior:**
- **Non-security update:** Silent failure. App continues running current version. Retry attempted on next launch.
- **Security update:** [WARNING] "Security update available but couldn't download automatically."  
  Action: [ Download Manually ] — links to direct download page
- Type: **Silent failure** (non-security) / **Soft warning** (security)

---

### UPDATE-2 — Sparkle update installation failed

**Trigger:** Update downloaded successfully but installation fails (permissions issue, disk space, interrupted install).

**Behavior:**
- App remains on current version
- User sees: [WARNING] "Update couldn't be installed. Download it manually to stay up to date."
- Action: [ Download Manually ]
- Type: **Soft warning**

---

## Error State Summary

| ID | Name | Type | Platform |
|---|---|---|---|
| CONN-1 | No network connectivity | Hard block | iOS, macOS |
| CONN-2a | Captive portal authentication required | Soft warning | iOS, macOS |
| CONN-2b | Genuine network block | Hard block | iOS, macOS |
| CONN-3 | Managed server unreachable | Soft warning → Hard block | iOS, macOS |
| CONN-4 | Managed server at capacity | Hard block | iOS, macOS |
| CONN-5 | Connection timeout | Soft warning → Hard block | iOS, macOS |
| SESSION-1 | Tunnel drop — kill switch activates | Soft warning | iOS, macOS |
| SESSION-2 | Reconnection failed after 3 attempts | Hard block | iOS, macOS |
| SESSION-3 | Network change mid-session | Silent / Soft warning | iOS, macOS |
| SESSION-4 | NE process killed by OS | Soft warning | iOS, macOS |
| PERM-1 | VPN permission denied (onboarding) | Hard block | iOS |
| PERM-2 | VPN permission revoked | Hard block | iOS |
| PERM-3 | System Extension approval dismissed | Hard block | macOS |
| PERM-4 | System Extension revoked | Hard block | macOS |
| SELFHOST-1 | Config import failed | Hard block | iOS, macOS |
| SELFHOST-2 | QR code expired | Hard block | iOS, macOS |
| SELFHOST-3 | Self-hosted server unreachable | Hard block | iOS, macOS |
| SELFHOST-4 | Server key mismatch | Hard block | iOS, macOS |
| SELFHOST-5 | CloudFormation deployment failed | Hard block | iOS, macOS |
| PRIVACY-1 | DoH resolver unreachable | Soft warning | iOS, macOS |
| PRIVACY-2 | ECH negotiation failure | Silent failure | iOS, macOS |
| SYS-1 | App version incompatible | Hard block | iOS, macOS |
| SYS-2 | Device keychain unavailable | Hard block | iOS, macOS |
| UPDATE-1 | Sparkle update download failed | Silent / Soft warning | macOS |
| UPDATE-2 | Sparkle update installation failed | Soft warning | macOS |

---

## Resolved Engineering Questions

All questions are resolved. See `engineering-handoff.md` §Open Engineering Questions for full rationale.

1. **Per-path timeouts** — HTTP CONNECT 2s, TLS/443 3s, DNS tunnel 3s, ICMP 2s. Total 10s + 1s captive portal probe = ≤11s. See CONN-2 §Per-path timeout allocation above.

2. **At capacity vs. unreachable signal** — `capacity_available: false` in `GET /v1/server/config` response, or 503 `PEER_LIMIT_REACHED` on `POST /v1/peers` → CONN-4. Connection timeout or DNS failure → CONN-3. See `client-server-api-spec.md`.

3. **SESSION-4 detection** — Subscribe to `NEVPNStatusDidChange` notifications. Track `userInitiatedDisconnect` flag. Any `.disconnected` transition without that flag = SESSION-4.

4. **SELFHOST-4 threshold** — 3 consecutive failures to reach `NEVPNStatus.connected` within 15s each, on a confirmed-reachable network. See `engineering-handoff.md` Q4.

5. **Kill switch during sleep** — Kill switch holds during any reconnection attempt. Releases only on user action (Reconnect or Disconnect). Notification fires after 3 failed reconnection attempts.

6. **iCloud backup** — Keypair IS backed up (`kSecAttrAccessible.afterFirstUnlock`). New device inherits identity on restore. Users can reset identity via Settings → "Reset Device Key". See `data-model.md`.
