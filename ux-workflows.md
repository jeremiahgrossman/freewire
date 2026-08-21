# Freewire VPN — UX Workflows

**Status:** Draft v0.3  
**Last updated:** 2026-06-17  

This document defines all user-facing flows, states, and information hierarchy for Freewire VPN. It covers three components: the iOS client, the macOS client, and the server setup flow. Visual design (colors, typography, spacing, component choices) is an engineering decision and is not specified here.

---

## Contents

1. Shared Concepts and State Model
2. iOS Client
   - 2.1 Install and First Launch
   - 2.2 Onboarding — Freewire Path
   - 2.3 Onboarding — Self-Host Path
   - 2.4 Main Screen States
   - 2.5 Connecting on a Captive Portal Network
   - 2.6 Kill Switch and Reconnection
   - 2.7 Settings
   - 2.8 Device Identity
3. macOS Client (Menu Bar)
   - 3.1 Install and First Launch
   - 3.2 System Extension Approval
   - 3.3 Onboarding — Freewire Path
   - 3.4 Onboarding — Self-Host Path
   - 3.5 Menu Bar States
   - 3.6 Menu Bar Panel
   - 3.7 Kill Switch and Reconnection
   - 3.8 Preferences
   - 3.9 Sparkle Update Flow
4. Server Setup (Self-Host)
   - 4.1 AWS Deploy
   - 4.2 Getting the Connection Config
   - 4.3 Adding a Second Device
   - 4.4 Server Web Dashboard

---

## 1. Shared Concepts and State Model

### 1.1 Connection States

Every client (iOS and macOS) is always in exactly one of the following states. State names are used consistently throughout this document and in all in-app copy.

| State | What it means | Kill switch active? |
|---|---|---|
| **Disconnected** | No tunnel active. Traffic flows unprotected. | No |
| **Connecting** | Tunnel establishment in progress. Fallback chain running. | No |
| **Connected** | Tunnel active. All traffic routed through Freewire. | — |
| **Reconnecting** | Tunnel dropped. Kill switch active. Attempting to restore. | Yes |
| **Blocked** | Reconnection failed or network unavailable. Kill switch active. User action needed. | Yes |
| **Error** | A specific problem prevents connection. Described in context. | No |

### 1.2 Server Types

Two server types are used throughout:

- **Freewire servers** — Freewire-operated. No setup required. Selected during onboarding.
- **Self-host server** — User-deployed on AWS. Set up by the user. Connected via a config imported during onboarding.

### 1.3 Tunnel Paths

The active tunnel path is shown in the Connected state for transparency. Users are never asked to choose a path — it is selected automatically. Labels shown in the UI:

- **Protected** — TLS/443 path (fast, normal conditions)
- **Protected** — HTTP CONNECT path (fast, some networks)
- **Protected — Reduced speed** — DNS tunnel path (slower, captive portal fallback)
- **Protected — Reduced speed** — ICMP path (slowest, last resort)

The label "Protected" is shown in all cases. "Reduced speed" is added only on the DNS and ICMP paths to set expectations. No technical path names are shown to the user.

### 1.4 Onboarding Paths

Two onboarding paths are offered at first launch:

- **Freewire** — Connect to Freewire-operated servers. No account or sign-in required. No server setup.
- **Self-host** — Connect to a server the user deploys on AWS. No account required. Requires AWS setup.

---

## 2. iOS Client

### 2.1 Install and First Launch

**Distribution:** TestFlight at launch. App Store submission is post-launch.

**Install flow:**
The user installs Freewire via TestFlight (at launch). No steps outside the standard TestFlight install flow are required before first launch.

**First launch — before onboarding begins:**

```
┌─────────────────────────────────┐
│                                 │
│         [Freewire logo]         │
│                                 │
│   Protect your connection       │
│   on any network.               │
│                                 │
│   Works on hotel, airport, and  │
│   café wifi — even before       │
│   you've paid.                  │
│                                 │
│         [ Get Started ]         │
│                                 │
│   Free, always.                 │
│                                 │
└─────────────────────────────────┘
```

- One action: Get Started.
- No account prompt yet.
- Tagline communicates the core value proposition and the free model.

---

### 2.2 Onboarding — Freewire Path

**Step 1: VPN permission**

The app skips the path selection screen entirely on first launch — Freewire's managed servers are the default. The app generates a WireGuard keypair in the background immediately.

```
┌─────────────────────────────────┐
│                                 │
│  One permission needed          │
│                                 │
│  iOS will ask you to allow      │
│  Freewire to set up a VPN.      │
│  This is how the app routes     │
│  your traffic securely.         │
│                                 │
│  Tap Allow when iOS asks.       │
│                                 │
│       [ Continue ]              │
│                                 │
│  ─────────────────────────────  │
│  Running your own server?       │
│  Set up self-hosting →          │
│                                 │
└─────────────────────────────────┘
```

- Default path: managed Freewire servers. No selection required.
- "Set up self-hosting →" is a secondary link that opens the self-host onboarding flow (§2.3).
- User taps Continue to trigger the iOS VPN configuration system prompt.

The app generates a WireGuard keypair in the background at this point. No user action required; no sign-in or account creation.

---

**Step 2: Allow VPN configuration**

- User taps Continue, which triggers the iOS VPN configuration system prompt.
- If the user denies the prompt:

```
┌─────────────────────────────────┐
│  VPN permission needed          │
│                                 │
│  Freewire needs permission to   │
│  set up a VPN connection.       │
│                                 │
│  Go to Settings → General →     │
│  VPN & Device Management to     │
│  allow it.                      │
│                                 │
│  [ Open Settings ]  [ Try Again]│
│                                 │
└─────────────────────────────────┘
```

---

**Step 3: Connected + notification permission**

```
┌─────────────────────────────────┐
│                                 │
│         ✓ You're protected      │
│                                 │
│  Freewire is on. Your traffic   │
│  is encrypted on this network.  │
│                                 │
│  Server: Freewire — US          │
│                                 │
│  ─────────────────────────────  │
│  Get notified if your           │
│  connection drops.              │
│                                 │
│  [ Allow Notifications ]        │
│  [ Not Now ]                    │
│                                 │
└─────────────────────────────────┘
```

- The app connects automatically after permission is granted.
- Notification permission is requested on the connected confirmation screen — after the user has seen value — not during onboarding setup.
- "Allow Notifications" triggers the iOS system notification permission prompt.
- "Not Now" skips it. The user can enable notifications later in Settings.
- If notifications are granted, Freewire will notify the user when: the kill switch activates (tunnel dropped, traffic blocked) and reconnection has failed after 3 attempts.
- Done (or after handling notification prompt) takes the user to the main screen in the Connected state.
- Total steps: 3. Total decisions: 2 (path choice, notifications). No account creation, no sign-in.

---

### 2.3 Onboarding — Self-Host Path

**Step 1:** User taps **"Set up self-hosting →"** on the initial onboarding screen (see §2.2 Step 1).

---

**Step 2: What self-hosting means**

```
┌─────────────────────────────────┐
│  Run your own server            │
│                                 │
│  You'll deploy a Freewire       │
│  server on your AWS account.    │
│  Your traffic goes through      │
│  your server — not ours.        │
│                                 │
│  Takes about 10–15 minutes.     │
│  You'll need an AWS account.    │
│                                 │
│  [ I have an AWS account ]      │
│  [ Back ]                       │
│                                 │
└─────────────────────────────────┘
```

---

**Step 3: Deploy to AWS**

```
┌─────────────────────────────────┐
│  Deploy your server             │
│                                 │
│  Tap the button below to open   │
│  the AWS deployment page in     │
│  your browser.                  │
│                                 │
│  Follow the steps there, then   │
│  come back here.                │
│                                 │
│  [ Open AWS Deploy Page ]       │
│                                 │
│  Need help? See the guide ›     │
│                                 │
└─────────────────────────────────┘
```

- Opens the Freewire AWS deploy page in Safari (one-click CloudFormation or AMI).
- The user completes deployment in the browser, then returns to the Freewire app.
- See §4.1 for the AWS deploy flow in detail.

---

**Step 4: Import your server config**

```
┌─────────────────────────────────┐
│  Connect to your server         │
│                                 │
│  Once your server is running,   │
│  scan the QR code shown on the  │
│  AWS deployment page.           │
│                                 │
│  [ Scan QR Code ]               │
│                                 │
│  ── or ──                       │
│                                 │
│  [ Import config file ]         │
│                                 │
└─────────────────────────────────┘
```

- QR scan opens the device camera.
- Config file import opens the Files picker.
- On successful import, the app shows the server details for confirmation:

```
┌─────────────────────────────────┐
│  Your server                    │
│                                 │
│  Region:  us-east-1             │
│  Address: 54.23.x.x             │
│                                 │
│  [ Connect to this server ]     │
│  [ Scan again ]                 │
│                                 │
└─────────────────────────────────┘
```

---

**Step 5: Allow VPN configuration**

Same as §2.2 Step 3.

---

**Step 6: Connected + notification permission**

```
┌─────────────────────────────────┐
│                                 │
│         ✓ You're protected      │
│                                 │
│  Connected to your server       │
│  in us-east-1.                  │
│                                 │
│  ─────────────────────────────  │
│  Get notified if your           │
│  connection drops.              │
│                                 │
│  [ Allow Notifications ]        │
│  [ Not Now ]                    │
│                                 │
└─────────────────────────────────┘
```

- Same notification permission flow as the Freewire path (§2.2 Step 4).

---

### 2.4 Main Screen States

The main screen is the primary interface after onboarding. It has one job: show the user their current protection status and let them connect or disconnect.

**Disconnected state:**

```
┌─────────────────────────────────┐
│  [Server name]          [⚙ ]   │
│                                 │
│                                 │
│       Not protected             │
│                                 │
│   Your traffic is not           │
│   encrypted on this network.    │
│                                 │
│                                 │
│         [ Connect ]             │
│                                 │
└─────────────────────────────────┘
```

- Server name shown at top (e.g., "Freewire — US" or "My server — us-east-1").
- Settings icon in top right.
- Connect is the only primary action.

---

**Connecting state:**

The status line below "Connecting..." updates as the fallback chain progresses. Copy is surfaced at each phase transition, not on a timer.

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│                                 │
│       Connecting...             │
│                                 │
│   [status line — see below]     │
│                                 │
│                                 │
│         [ Cancel ]              │
│                                 │
└─────────────────────────────────┘
```

Status line progression:

| Phase | Status line copy |
|---|---|
| Initial / HTTP CONNECT probe | "Finding the best path for this network." |
| TLS/443 attempt | "Trying secure connection..." |
| DNS tunnel attempt | "Switching to alternate method..." |
| ICMP attempt | "Almost there..." |
| CONN-2a: portal detected | "One more step — authenticate with this network." |

- No technical path names (no "TLS", "DNS", "ICMP") are ever shown to the user.
- Status lines communicate effort without exposing implementation.
- Cancel stops the connection attempt and returns to Disconnected at any phase.

---

**Connected state:**

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│                                 │
│         ✓  Protected            │
│                                 │
│   Connected · 14 min            │
│   [Reduced speed on this        │
│    network]  ← shown only on    │
│    DNS/ICMP path                │
│                                 │
│                                 │
│        [ Disconnect ]           │
│                                 │
└─────────────────────────────────┘
```

- Connected duration shown.
- "Reduced speed on this network" shown only when DNS tunnel or ICMP path is active.
- Disconnect is the only primary action.

---

**Reconnecting state:**

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│                                 │
│       Reconnecting...           │
│                                 │
│   Your traffic is blocked       │
│   until reconnected.            │
│                                 │
│                                 │
│   [ Disconnect and restore      │
│     unprotected access ]        │
│                                 │
└─────────────────────────────────┘
```

- Kill switch is active from the moment reconnection begins — communicated plainly, not with technical language.
- Disconnect is shown immediately (not after a delay) with full plain-language consequence: "restore unprotected access." User has agency from the first second.
- No spinner timeout before showing the option — the user can always see the exit.

---

**Blocked state (reconnection failed):**

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│                                 │
│       [!] Connection lost       │
│                                 │
│   Freewire couldn't reconnect.  │
│   Your traffic is blocked.      │
│                                 │
│   [ Try Again ]                 │
│   [ Disconnect ]                │
│                                 │
└─────────────────────────────────┘
```

- Two options: try again, or disconnect (which releases the kill switch).
- Disconnect copy here should clarify: "Disconnect (your traffic won't be protected)."

---

**All-paths-failed state — CONN-2a (portal, authentication failed or cancelled):**

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│     [!] Authentication needed   │
│                                 │
│   Complete this network's       │
│   login page, then reconnect.   │
│                                 │
│   [ Authenticate with network ] │
│   [ Cancel ]                    │
│                                 │
└─────────────────────────────────┘
```

- Shown when portal was detected but the user cancelled the in-app browser, or authentication did not open the network.
- "Authenticate with network" re-opens the portal browser sheet.

**All-paths-failed state — CONN-2b (genuine block):**

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│                                 │
│   [!] This network blocks VPNs  │
│                                 │
│   Freewire tried every method.  │
│   This network restricts all    │
│   secure connections.           │
│                                 │
│   [ Try Again ]                 │
│   [ Cancel ]                    │
│                                 │
└─────────────────────────────────┘
```

- Distinguished from CONN-2a — network is genuinely restrictive, not just unauthenticated.
- Does not quote statistics or claim rarity — just explains what happened.

---

### 2.5 Connecting on a Captive Portal Network

The fallback chain runs automatically during the Connecting state. The user sees the status line update as paths are tried (§2.4). They never see protocol names or error codes from the fallback chain.

**CONN-2a: Portal detected — in-app browser flow**

When all four paths fail and the captive portal probe detects an unauthenticated portal (see `error-states-spec.md` §CONN-2a), the app automatically opens an in-app browser sheet showing the portal's authentication page. No error message is shown before the browser appears.

```
┌─────────────────────────────────┐
│  ─────────────────────────────  │
│                                 │
│  Authenticate with this         │
│  network to continue.           │
│                                 │
│  ┌─────────────────────────┐    │
│  │  [Portal page — hotel   │    │
│  │   login, accept terms,  │    │
│  │   etc.]                 │    │
│  │                         │    │
│  │                         │    │
│  └─────────────────────────┘    │
│                                 │
│       [ Cancel ]                │
│                                 │
└─────────────────────────────────┘
```

- The portal page is shown inside the app via `SFSafariViewController`.
- When the portal sheet is dismissed (user completes authentication, or taps Cancel), the app immediately retries the full fallback chain automatically — no tap required.
- If retry succeeds, the portal sheet closes and the app transitions to Connected.
- Cancel returns to Disconnected without retrying.

**First captive portal success — one-time moment**

The first time a user successfully connects on a captive portal network (detected by: fallback chain path was not the standard open-network WireGuard path), the Connected state shows an additional one-time message:

```
┌─────────────────────────────────┐
│  Freewire — US          [ ⚙ ]  │
│                                 │
│         ✓  Protected            │
│                                 │
│  Connected on a network that    │
│  blocks standard VPNs.          │  ← one-time only
│                                 │
│  Connected · 0 min              │
│  Reduced speed on this network  │
│                                 │
│        [ Disconnect ]           │
└─────────────────────────────────┘
```

This message appears once, ever — not on every captive portal connection. It is the product's core value prop demonstrated at the moment of maximum impact.

**Network intelligence opt-in — shown here**

Immediately after the first captive portal success (same session, one or two seconds after Connected state appears), the network intelligence opt-in prompt is shown as a bottom sheet:

```
┌─────────────────────────────────┐
│                                 │
│  Help others connect faster     │
│                                 │
│  Share that this connection     │
│  method worked on this          │
│  network. No location data      │
│  or personal information        │
│  is collected.                  │
│                                 │
│  [ Share anonymously ]          │
│  [ No thanks ]                  │
│                                 │
└─────────────────────────────────┘
```

- Shown once, on the first captive portal success only.
- "Share anonymously" enables the network intelligence feature and submits this connection's report.
- "No thanks" declines. The prompt never reappears.
- The feature can be enabled or disabled later in Settings → Privacy.

**iOS "Sign in to network" banner**

iOS sometimes shows its own system banner when a captive portal is detected. Freewire handles this silently — the fallback chain continues running in the background regardless of whether the banner appears. If the user taps the banner and is taken to Safari, the Freewire connection attempt continues. When the user returns to Freewire, the app shows the current state: connected if the fallback chain succeeded, or retrying if it failed. No Freewire-specific guidance is shown in response to the banner.

---

### 2.6 Kill Switch and Reconnection

**Kill switch first-connect tooltip**

On the very first successful connection (any path, any network), a one-time tooltip is shown briefly below the Connected status:

```
  Kill switch is on: if this connection drops, your
  traffic stays blocked until Freewire reconnects.
  You can change this in Settings.         [ Got it ]
```

Shown once, dismissed by tapping "Got it" or after 6 seconds. This explains the default state before the user ever encounters a reconnection event — so the Reconnecting state isn't their first exposure to what the kill switch does.

**Behavior when the tunnel drops unexpectedly:**

1. Kill switch activates immediately — all traffic blocked
2. App transitions to Reconnecting state
3. Reconnection attempts begin within 3 seconds
4. On each attempt, the fallback chain re-runs (the network may have changed)
5. If reconnection succeeds: transitions to Connected, kill switch releases
6. If 3 attempts fail: transitions to Blocked state

**Behavior when the network changes (wifi → cellular, etc.):**

Same as above. The app detects the network change and immediately begins reconnection.

**User control over kill switch:**

The kill switch is on by default. The user can disable it in Settings → Kill Switch. When navigating to this setting, the user sees an explanation:

```
┌─────────────────────────────────┐
│  Kill Switch                    │
│                                 │
│  When on, your traffic is       │
│  blocked if the VPN drops.      │
│  This prevents accidental       │
│  exposure on public networks.   │
│                                 │
│  When off, traffic flows        │
│  normally if the VPN drops.     │
│                                 │
│  [  ON  ●────────────]          │
│                                 │
└─────────────────────────────────┘
```

No confirmation dialog is required for toggling — the explanation on the screen is sufficient context.

---

### 2.7 Settings

Settings are accessed via the gear icon on the main screen.

```
┌─────────────────────────────────┐
│  Settings                 [ ✕ ]│
│                                 │
│  SERVER                         │
│  Freewire — US          [ › ]  │
│                                 │
│  PROTECTION                     │
│  Kill Switch              [ON]  │
│                                 │
│  PRIVACY                        │
│  What Freewire sees     [ › ]  │
│  Improve detection       [OFF]  │
│                                 │
│  DEVICE                         │
│  Key: AB:CD:EF:12:34    [ › ]  │
│                                 │
│  ABOUT                          │
│  What is a VPN?         [ › ]  │
│  Privacy Policy         [ › ]  │
│  Version 1.0.0                  │
│                                 │
└─────────────────────────────────┘
```

**"What Freewire sees" screen:**

```
┌─────────────────────────────────┐
│  What Freewire sees     [ ‹ ]  │
│                                 │
│  ✕  Your IP address             │
│     We never log it.            │
│                                 │
│  ✕  What you browse             │
│     We see only encrypted       │
│     data.                       │
│                                 │
│  ✕  When you connected          │
│     No connection logs.         │
│                                 │
│  ✕  Your identity               │
│     No account. No email.       │
│                                 │
│  ✓  Anonymous rate-limit tokens │
│     Cryptographically unlinked  │
│     to your device.             │
│     Deleted after 30 days.      │
│                                 │
│  [ Read our privacy policy ]    │
│                                 │
└─────────────────────────────────┘
```

This screen exists as an in-app plain-language summary — not a link to a legal document. It answers the question every VPN user has ("what does this company actually know about me?") in a format that builds trust rather than requiring legal comprehension.

**"Improve detection" toggle:**

The network intelligence opt-in setting. Default: OFF. Label: "Help improve captive portal detection." Sub-label: "Shares which connection method worked on this wifi — no personal data." This is the same setting that the one-time prompt (§2.5) can enable; the toggle reflects its current state and can be changed at any time.

**Server section:**
- Shows the currently active server (Freewire region or self-host server name).
- Tapping opens a server selection screen (see below).

**Server selection screen:**

```
┌─────────────────────────────────┐
│  Choose Server          [ ‹ ]  │
│                                 │
│  FREEWIRE SERVERS               │
│  ● US                  Active   │
│    EU                           │
│                                 │
│  MY SERVERS                     │
│    My AWS server       [ › ]   │
│                                 │
│  [ Add a self-host server ]     │
│                                 │
└─────────────────────────────────┘
```

- Tapping a Freewire server selects it and reconnects if currently connected.
- Tapping a self-host server shows its details and allows connecting or removing.
- "Add a self-host server" opens the QR / config import flow from §2.3 Step 4.

**What is a VPN? screen:**

Plain-language explanation of:
- What a VPN does (encrypts your traffic, hides your activity from the network you're on)
- What a VPN does not do (does not make you anonymous, does not protect against malware or phishing, does not hide what you do from the VPN server itself)

This screen is always accessible, not hidden behind onboarding completion.

---

### 2.8 Device Identity

Tapping the DEVICE row in Settings opens the Device Identity screen. There is no account — a device is identified only by its WireGuard public key, generated locally at first launch.

```
┌─────────────────────────────────┐
│  This Device            [ ‹ ]  │
│                                 │
│  Your device key                │
│  AB:CD:EF:12:34:56:78:9A        │
│                                 │
│  This key identifies your       │
│  device on Freewire servers.    │
│  It is not linked to your       │
│  name or Apple ID.              │
│                                 │
│  ─────────────────────────────  │
│                                 │
│  [ Reset Device Key ]           │
│                                 │
│  [ Remove Freewire ]            │
│                                 │
└─────────────────────────────────┘
```

**Reset Device Key:**
- Generates a new WireGuard keypair. The old key is abandoned.
- Warning shown before action: "Resetting your key will disconnect you. If you use a self-hosted server, you'll need to re-import a new config from your server's setup page."
- Confirmation required: [ Reset Key ] / [ Cancel ]
- On confirm: new keypair generated, existing VPN configuration removed, user reconnects from the main screen. Self-host users must re-import config.

**Remove Freewire:**
- Removes all Freewire data from the device: keypair, VPN configuration, server list.
- Warning shown: "This removes Freewire from this device. Your traffic will no longer be protected. This cannot be undone."
- Confirmation required: [ Remove ] / [ Cancel ]
- On confirm: all data deleted, user returned to first-launch screen.

---

## 3. macOS Client (Menu Bar)

### 3.1 Install and First Launch

**Distribution:** Direct download (signed, notarized DMG).

**Install flow:**

1. User downloads the DMG from freewire.com
2. User opens the DMG and drags Freewire.app to the Applications folder (standard macOS DMG install)
3. User opens Freewire from Applications or Launchpad
4. macOS Gatekeeper verifies the signature — no security warning appears for a signed, notarized app
5. Freewire's icon appears in the menu bar
6. An onboarding window opens automatically

---

### 3.2 System Extension Approval

The NetworkExtension System Extension must be approved before the VPN can function. This happens once, on first launch.

**Before the system prompt:**

```
┌────────────────────────────────────────────────┐
│  One step to get started                       │
│                                                │
│  macOS needs your permission to let Freewire   │
│  set up a secure connection.                   │
│                                                │
│  A system dialog will appear. Click Allow.     │
│                                                │
│                    [ Continue ]                │
│                                                │
└────────────────────────────────────────────────┘
```

- Tapping Continue triggers the macOS System Extension system prompt.
- The system prompt asks the user to allow the Freewire network extension.

**If the user dismisses the system prompt without clicking Allow:**

```
┌────────────────────────────────────────────────┐
│  Permission needed                             │
│                                                │
│  Freewire needs the network extension          │
│  to be approved before it can protect          │
│  your connection.                              │
│                                                │
│  Open System Settings → Privacy & Security    │
│  and look for "Freewire" under Security.       │
│                                                │
│  [ Open System Settings ]    [ Try Again ]     │
│                                                │
└────────────────────────────────────────────────┘
```

- "Open System Settings" opens Privacy & Security directly.
- "Try Again" re-triggers the system prompt.

---

### 3.3 Onboarding — Freewire Path (macOS)

The onboarding window appears after System Extension approval. The flow mirrors §2.2 (iOS Freewire path). No account or sign-in required — the app generates a WireGuard keypair in the background after path selection.

Steps:
1. Path selection (same layout as iOS, scaled for a window)
2. VPN configuration permission (macOS shows a system prompt for VPN configuration, distinct from the System Extension prompt already completed)
3. Connected confirmation

The onboarding window closes after step 4. The menu bar icon updates to Connected state.

---

### 3.4 Onboarding — Self-Host Path (macOS)

Mirrors §2.3 (iOS self-host path). The AWS deploy page opens in the default browser. QR scan is replaced with camera access (macOS has camera access) or config file import via the standard file picker.

---

### 3.5 Menu Bar States

The Freewire menu bar icon communicates connection state at a glance. State is conveyed through the icon appearance (defined by engineering) and a tooltip on hover.

| State | Tooltip on hover |
|---|---|
| Disconnected | "Freewire — Not connected" |
| Connecting | "Freewire — Connecting..." |
| Connected | "Freewire — Protected" |
| Reconnecting | "Freewire — Reconnecting... Traffic blocked" |
| Blocked | "Freewire — Connection lost. Click to reconnect." |

---

### 3.6 Menu Bar Panel

Clicking the menu bar icon opens a compact panel. This is the primary interaction surface on macOS.

**Disconnected:**

```
┌──────────────────────────────┐
│  Freewire            [⚙]    │
│  ─────────────────────────   │
│  Not protected               │
│  Traffic is not encrypted.   │
│                              │
│  Freewire — US       [▾]    │
│                              │
│       [ Connect ]            │
│                              │
│  ─────────────────────────   │
│  What is a VPN?              │
│  Quit Freewire               │
└──────────────────────────────┘
```

- Server selector (▾) opens an inline server list within the panel.
- Gear icon opens Preferences window.

**Connected:**

```
┌──────────────────────────────┐
│  Freewire            [⚙]    │
│  ─────────────────────────   │
│  ✓ Protected                 │
│  Freewire — US · 22 min      │
│  [Reduced speed] ← DNS/ICMP  │
│  path only                   │
│                              │
│       [ Disconnect ]         │
│                              │
│  ─────────────────────────   │
│  What is a VPN?              │
│  Quit Freewire               │
└──────────────────────────────┘
```

**Reconnecting:**

```
┌──────────────────────────────┐
│  Freewire            [⚙]    │
│  ─────────────────────────   │
│  Reconnecting...             │
│  Traffic is blocked.         │
│                              │
│  [ Disconnect and restore    │
│    unprotected access ]      │
│                              │
└──────────────────────────────┘
```

**Blocked:**

```
┌──────────────────────────────┐
│  Freewire            [⚙]    │
│  ─────────────────────────   │
│  [!] Connection lost         │
│  Traffic is blocked.         │
│                              │
│  [ Try Again ]               │
│  [ Disconnect ]              │
│                              │
└──────────────────────────────┘
```

---

### 3.7 Kill Switch and Reconnection (macOS)

Identical behavior to iOS (§2.6). The kill switch persists at the OS level — if Freewire is quit while connected and in Reconnecting state, traffic remains blocked until the app is reopened.

**Quitting while connected:** When the user quits Freewire (Cmd+Q or Quit Freewire from the menu bar panel), the tunnel disconnects automatically. No confirmation dialog is shown. The VPN configuration is removed from the OS. Traffic flows unprotected after quit.

If Freewire is quit while in Reconnecting state (kill switch active), the tunnel disconnects and the kill switch releases — traffic flows immediately on quit. This is consistent with the automatic disconnect behavior and avoids stranding the user with blocked traffic and no app running.

---

### 3.8 Preferences

The Preferences window opens from the gear icon in the menu bar panel.

```
┌────────────────────────────────────────────────┐
│  Freewire Preferences                          │
│                                                │
│  GENERAL                                       │
│  Launch at login              [ON]             │
│  Connect automatically        [ON]             │
│  Show in menu bar             [ON] (always on) │
│                                                │
│  SERVER                                        │
│  Active server: Freewire — US         [Change] │
│                                                │
│  PROTECTION                                    │
│  Kill switch                  [ON]             │
│  [description of kill switch]                  │
│                                                │
│  PRIVACY                                       │
│  What Freewire sees               [ › ]        │
│  Improve detection            [OFF]            │
│                                                │
│  DEVICE                                        │
│  Key: AB:CD:EF:12:34:56:78:9A                 │
│  [ Reset Device Key ]  [ Remove Freewire ]     │
│                                                │
│  ABOUT                                         │
│  Version 1.0.0                                 │
│  [ Check for Updates ]                         │
│  [ Privacy Policy ]                            │
│  [ What is a VPN? ]                            │
│                                                │
└────────────────────────────────────────────────┘
```

- "Launch at login" defaults to ON.
- **"Connect automatically"** — new toggle, defaults to ON. When on, Freewire connects automatically when the app launches. Useful for power users who want constant protection. Disable for users who prefer to connect manually. Both "Launch at login" and "Connect automatically" must be ON for the VPN to be up without any user action after a reboot.
- "Show in menu bar" is always on and cannot be disabled (menu bar is the only interface).
- "Check for Updates" manually triggers Sparkle.
- **"What Freewire sees"** — same in-app privacy transparency screen as iOS (§2.7). Plain-language breakdown of what is and isn't logged.
- **"Improve detection"** — network intelligence opt-in toggle (same as iOS §2.7).

---

### 3.9 Sparkle Update Flow

Sparkle checks for updates on each app launch. When an update is available:

**Non-critical update (minor version):**

A notification appears in the menu bar panel:

```
┌──────────────────────────────┐
│  Update available            │
│  Freewire 1.1.0              │
│  [ Install Update ]  [ Later]│
└──────────────────────────────┘
```

- "Install Update" downloads and applies the update, then relaunches the app.
- "Later" dismisses the notification until the next launch.

**Security update (critical):**

The update notification cannot be dismissed. "Later" is not shown. The user must install or quit.

```
┌──────────────────────────────┐
│  Security update required    │
│  Freewire 1.0.2              │
│  This update fixes a         │
│  security issue. Install     │
│  now to stay protected.      │
│  [ Install Update ]          │
└──────────────────────────────┘
```

---

## 4. Server Setup (Self-Host)

### 4.1 AWS Deploy

The user is directed to the AWS deploy page from the Freewire app (§2.3 Step 3 or §3.4). This page is a web page hosted by Freewire.

**AWS deploy page — what the user sees:**

```
┌────────────────────────────────────────────────────┐
│  Deploy your Freewire server on AWS                │
│                                                    │
│  This will create a small server on your AWS       │
│  account. Your traffic will go through your        │
│  server, not Freewire's.                           │
│                                                    │
│  Estimated cost: ~$5–10/month on AWS.              │
│  (This is charged by AWS, not Freewire.)           │
│                                                    │
│  What you need:                                    │
│  ✓ An AWS account                                  │
│  ✓ About 10 minutes                               │
│                                                    │
│  [ Deploy to AWS ]                                 │
│                                                    │
│  ── What happens when I click Deploy? ──           │
│  It opens AWS and runs a setup template.           │
│  You'll review it and click Create.                │
│  That's it.                                        │
│                                                    │
└────────────────────────────────────────────────────┘
```

"Deploy to AWS" opens the AWS CloudFormation or Marketplace page with the Freewire template pre-loaded.

---

**AWS CloudFormation / Marketplace page:**

This is an AWS-native experience. Freewire has no control over the visual design. The user:
1. Reviews the template (Freewire provides a plain-language summary of what it creates)
2. Selects an AWS region
3. Clicks Create / Launch

**Server updates:** The deployed server software updates itself automatically. The user never needs to take action to keep their self-hosted server current. No in-app notification is shown for server updates.

Freewire's deploy page shows a status indicator while waiting for the stack to complete:

```
┌────────────────────────────────────────────────────┐
│  Setting up your server...                         │
│                                                    │
│  This takes about 3–5 minutes.                     │
│  You can leave this page and come back.            │
│                                                    │
│  [████████░░░░░░] Deploying...                     │
│                                                    │
└────────────────────────────────────────────────────┘
```

When the server is ready:

```
┌────────────────────────────────────────────────────┐
│  ✓ Your server is ready                            │
│                                                    │
│  Scan this QR code in the Freewire app             │
│  to connect.                                       │
│                                                    │
│  [QR CODE]                                         │
│                                                    │
│  ── Can't scan? ──                                 │
│  [ Download config file ]                          │
│                                                    │
│  Keep this page bookmarked — you'll need           │
│  it to connect other devices.                      │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

### 4.2 Getting the Connection Config

The QR code and config file contain the information the Freewire app needs to connect to the self-hosted server: the server's address and public key. The server's private key never leaves the server and is not included in the config. If a config is intercepted, it cannot be used to impersonate the server.

The config does not contain any Freewire account credentials.

**Expiry:** The QR code and config file expire after a set time (specific duration to be decided by engineering — recommended: 24 hours). After expiry, the user must revisit the Freewire AWS deploy status page to generate a new one. The expiry applies only to the QR code shown on the deploy page — a device that has already imported the config and connected successfully is not affected by expiry.

The QR code / config is regenerated each time the user loads the AWS deploy status page. It is not stored by Freewire.

**When a config expires before being scanned:**

```
┌────────────────────────────────────────────────────┐
│  This QR code has expired                          │
│                                                    │
│  For security, setup codes expire after 24 hours.  │
│                                                    │
│  [ Generate a new code ]                           │
│                                                    │
└────────────────────────────────────────────────────┘
```

---

### 4.3 Adding a Second Device

A self-hosted user who wants to connect a second Apple device (e.g., add their Mac after setting up on iPhone):

1. On the already-configured device: Settings → My server → Share config
2. A QR code is displayed on screen (generated from the stored config — no AWS login required)
3. On the new device: install Freewire → onboarding → Self-host → Scan QR code

Alternatively, the user can visit their server's web dashboard directly to generate a new config.

---

### 4.4 Server Web Dashboard

The server web dashboard is a lightweight web page hosted on the user's self-hosted server (e.g., `https://<server-ip>:8443`). It is accessed in a browser — no app required. This is the ongoing management interface for the server after initial setup.

**Main dashboard:**

```
┌──────────────────────────────────────────────┐
│  Freewire Server                             │
│  my-server.us-east-1.amazonaws.com           │
│                                              │
│  STATUS                                      │
│  ● Running        Uptime: 14 days            │
│  Version: 1.2.0   [ Update available 1.3.0 ] │
│                                              │
│  CONNECTED DEVICES                  2 / 50  │
│  ┌──────────────────────────────────────┐   │
│  │  AB:CD:EF:12:34   Last seen: now     │   │
│  │                         [ Revoke ]   │   │
│  ├──────────────────────────────────────┤   │
│  │  99:88:77:66:55   Last seen: 2h ago  │   │
│  │                         [ Revoke ]   │   │
│  └──────────────────────────────────────┘   │
│                                              │
│  ADD A DEVICE                                │
│  [ Show QR Code ]  [ Download Config ]       │
│                                              │
└──────────────────────────────────────────────┘
```

**Status section:**
- Shows server running state, uptime, and current software version
- If an update is available: "Update available X.X.X" link — updates are automatic (see Decisions Log item 6 and PRD Decision #14) but the dashboard surfaces this for visibility
- No IP addresses are shown — the dashboard does not log or display client IPs

**Connected devices section:**
- Lists connected device key fingerprints (truncated, same format shown in the iOS/macOS app)
- "Last seen" shows relative time since last tunnel activity
- [ Revoke ] removes the device from the server's peer list immediately; the device cannot reconnect until it imports a new config
- Device count shown (current / max capacity)

**Add a device section:**
- [ Show QR Code ] — generates a new time-limited QR code (24-hour expiry). Each generation creates a fresh code; prior codes expire immediately on new generation.
- [ Download Config ] — downloads a `.conf` file with the same content as the QR code
- Both generate a new peer slot config. The server does not reuse peer configs across devices.

**Revoke confirmation:**

```
┌──────────────────────────────────────────────┐
│  Revoke this device?                         │
│                                              │
│  Key: AB:CD:EF:12:34                         │
│                                              │
│  This device will be disconnected and        │
│  will need a new config to reconnect.        │
│                                              │
│  [ Revoke ]          [ Cancel ]              │
└──────────────────────────────────────────────┘
```

**Dashboard access:**
- The dashboard is protected by a one-time setup password generated during CloudFormation deployment and shown once on the setup completion screen (§4.1)
- No Freewire account is involved — authentication is local to the server
- HTTPS is required; the server generates a self-signed certificate on first launch. The browser will show an untrusted certificate warning on first access — the setup flow explains this

---

## Open Questions

*(None. All UX questions resolved. New questions will be added here as error states and data model work surfaces them.)*

## Decisions Log

1. **Config contents** — Server address and public key only. Private key never leaves the server and is not included in the config. An intercepted config cannot impersonate the server.
2. **Config expiry** — QR code / config expires after 24 hours. Already-connected devices are unaffected. Expired code shows a plain-language message with a regenerate option.
3. **Captive portal iOS banner** — Handled silently. Freewire continues the fallback chain in the background. No Freewire-specific guidance is shown when the iOS banner appears.
4. **Notification permission (iOS)** — Requested after first successful connection, on the connected confirmation screen. Notifications fire when the kill switch activates and when reconnection fails after 3 attempts. "Not Now" is always available; user can enable later in Settings.
5. **macOS quit behavior** — Tunnel disconnects automatically on quit. No confirmation dialog. Kill switch releases on quit even if in Reconnecting state.
6. **Self-host server updates** — Automatic. Server software updates itself. No user action required, no in-app notification.
