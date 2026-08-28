# Freewire VPN — Data Model

**Version:** 0.1  
**Status:** Draft

---

## Governing Principle

Freewire's data model is designed around one rule: **collect the minimum necessary for the product to function, and make it architecturally impossible to reveal what we never collected.**

This is not a privacy policy. It is a structural constraint. The goal is that Freewire cannot answer certain questions even under legal compulsion — not because we refuse, but because the data does not exist.

This approach is modeled on Signal's architecture:
- No user accounts, no identity verification
- No connection logs
- No IP address records
- No traffic metadata
- Devices are identified only by cryptographic public keys, which are not linked to real-world identity

---

## Identity Model

There are no user accounts.

A "user" in Freewire is a device, identified by a WireGuard public key. That key is generated locally on the device at first launch. Freewire's servers never see the private key. The public key is not linked to any name, email address, Apple ID, phone number, or any other identifier.

**Multi-device:** Each device is independent. A user with Freewire on their iPhone and MacBook has two separate identities in the system. There is no account to link them.

**Self-hosted users:** Freewire's backend has zero knowledge of self-hosted users. The server software is deployed by the user on their own infrastructure. Device configuration is generated and exchanged via QR code locally. Freewire's infrastructure is never contacted for self-hosted setup or operation.

---

## What Is Stored

### `managed_server`

The inventory of Freewire-operated VPN servers. Admin-managed, not user-facing.

| Field | Type | Purpose |
|---|---|---|
| `id` | UUID | Internal identifier |
| `region` | string | Geographic region (e.g., `us-east`) |
| `endpoint` | string | IP address and port clients connect to |
| `public_key` | string | WireGuard server public key — sent to clients at app launch |
| `capacity` | integer | Max concurrent peer connections |
| `active` | boolean | Whether to offer this server to clients |
| `created_at` | timestamp | Admin record-keeping |

**Not stored:** client IP addresses, connection history, traffic volumes, peer public keys from past connections.

---

### `rate_limit_token`

Abuse prevention for managed servers, implemented using **Privacy Pass** (RFC 9576) blind token issuance. This means Freewire issues tokens that a device can spend to prove it is rate-limit compliant — without Freewire being able to link a spent token back to the device that received it.

**How it works:**
1. On first use, the device requests a batch of blind tokens from Freewire's token issuer. The issuer signs the tokens without seeing the unblinded values — it cannot link the issued tokens to the device.
2. The device unblinds the tokens locally. Only the device knows which token corresponds to which issuance.
3. On each connection, the device presents one token. Freewire verifies the signature but cannot determine which device the token came from.
4. Spent tokens are recorded to prevent double-spending, but the record contains only the token hash — not the device key, IP, or any identifier.

| Field | Type | Purpose |
|---|---|---|
| `spent_token_hash` | string | SHA-256 of a spent token — prevents replay |
| `spent_at` | timestamp | When it was spent |

**What this is not:** The spent token hash cannot be linked to any device, IP address, or user. It exists only to prevent a single token from being used twice.

**Not stored:** device public key, IP address, which device received which token batch, any identity information.

**Retention:** Spent token hashes are retained for 30 days (the token validity window), then deleted.

---

### `network_path_hint`

> ⚠️ **DECLINED — this table does not exist and is not to be built.** The network
> intelligence feature was deliberately not implemented (a hashed BSSID is a
> reversible location identifier, and reconnect already remembers the last working
> transport). See `DECISIONS.md` §NETWORK-INTELLIGENCE and `CLAUDE.md`. Retained
> below for history only.

A crowdsourced, opt-in database mapping wifi networks to the tunnel path most likely to succeed. Enables the client to skip earlier fallback steps on known networks, reducing time-to-connected.

**Collection is opt-in.** The client only submits a report if the user has enabled "Help improve captive portal detection" in Settings. This setting is off by default and requires an explicit user action to enable. See `privacy-policy.md` §network-intelligence.

**How anonymization works:**

The raw BSSID (wifi access point MAC address) is a location identifier — public databases can resolve it to a physical location. Freewire never receives the raw BSSID. The client hashes the BSSID with SHA-256 locally before transmission. The server stores and serves only the hash. The hash cannot be reversed without exhaustively enumerating every known BSSID, which requires deliberate attack effort.

A **k-anonymity threshold of 5** applies: a network's hint is only returned to clients once at least 5 independent opt-in connections have reported it. This prevents any single user's report from creating a traceable entry.

No IP address, device key, timestamp, or user identifier is submitted with or stored alongside the report.

| Field | Type | Purpose |
|---|---|---|
| `bssid_hash` | string (64-char hex) | SHA-256 of the BSSID, computed on-device before transmission |
| `successful_paths` | string[] | Ordered list of paths that established a tunnel (e.g., `["tls443", "dns_tunnel"]`) |
| `failed_paths` | string[] | Paths that were attempted and failed before a successful path was found |
| `report_count` | integer | Number of independent opt-in connections that have reported this network. Hint is only served to clients when `report_count >= 5`. |
| `updated_week` | string | ISO week of last report (e.g., `"2026-W25"`). Week-granularity only — no exact timestamp. |

**What is not stored:** raw BSSID, SSID, geolocation, IP address, device public key, connection time, user identity of any kind.

**Retention:** Network entries with no new reports for 6 months are deleted. Captive portal behavior changes over time; stale hints are worse than no hint.

**Privacy guarantee:** Freewire cannot answer "which networks did this device report from" — the device is never associated with any report. Freewire cannot answer "what location does this hash correspond to" — resolving the hash requires an external enumeration attack.

---

### `aggregate_metrics` (optional, for capacity planning)

If Freewire collects any operational metrics, they are aggregate-only — never per-device, never per-connection.

| Field | Type | Purpose |
|---|---|---|
| `server_id` | UUID (FK → managed_server) | Which server |
| `hour` | timestamp | Rounded to the hour |
| `peak_connections` | integer | Max simultaneous peers during this hour |
| `p50_latency_ms` | integer | Median tunnel latency |
| `p95_latency_ms` | integer | 95th percentile tunnel latency |

**Not stored:** anything per-device, per-connection, per-IP, or per-destination.

---

## What Is Explicitly Not Stored

This section is as important as the section above.

| Data | Why it doesn't exist |
|---|---|
| User accounts | No account model. Identity = device public key only. |
| Email addresses | Never collected. Not required for setup. |
| Apple IDs | Not used. Sign in with Apple is not part of the product. |
| Client IP addresses | Not logged anywhere — not on connection, not in error logs. |
| Session start/end times | Not recorded per device. |
| Session duration | Not recorded. |
| Destination IP addresses | Not recorded. Freewire sees the tunnel, not what the user browses. |
| Traffic content | Never seen. End-to-end encryption means Freewire sees only encrypted bytes. |
| Protocol or application metadata | Not logged. |
| Device identifiers (UDID, IDFA, etc.) | Not collected. |
| Location data | Not collected. The network intelligence feature stores a SHA-256 hash of the BSSID — not the BSSID itself, and not any geolocation. Opt-in only. |
| DNS queries | Not logged — not even on the DNS tunnel path where Freewire operates the authoritative server. The tunnel carries encrypted payload; the DNS labels are not inspectable without the session key, and session keys are ephemeral. |

---

## Questions Freewire Cannot Answer Even if Asked

By design, Freewire cannot truthfully answer the following, even under legal compulsion:

- **"Did this person use Freewire on this date?"** — No account, no connection log.
- **"What IP address did this device connect from?"** — Client IPs are never stored.
- **"What websites did this user visit?"** — Destination traffic is not logged.
- **"Who owns this device key?"** — Device keys are not linked to any identity.
- **"How long was this device connected?"** — Session duration is not recorded.

---

## Self-Hosted: Zero Freewire Footprint

Self-hosted users interact with Freewire's infrastructure only to download the server software. After that:

- The server runs on the user's own AWS account
- Device configuration is generated locally (WireGuard keypair) and exchanged via QR code or file export
- Freewire's backend is not contacted for authentication, connection, or operation
- Freewire has no record of self-hosted server deployments, connected devices, or usage

---

## Device Key Lifecycle

| Event | What happens |
|---|---|
| **First launch** | App generates a WireGuard keypair locally. Private key stored in device keychain only. Public key used to request a peer slot from the managed server. |
| **Connection** | Client presents its public key to the server. Server grants a peer slot in WireGuard's in-memory config. No persistent record created. |
| **Disconnection** | Peer slot may be retained in server memory for reconnection window; cleared when server restarts or after idle timeout. Nothing written to disk. |
| **App reinstall** | A new keypair is generated. The previous key is orphaned and eventually evicted from server memory. No account recovery needed — there is no account. |
| **iCloud backup / device restore** | The WireGuard keypair is backed up to iCloud Keychain (`kSecAttrAccessible.afterFirstUnlock`). On restore, the new device inherits the same peer identity — no re-onboarding required. Users can reset their identity via Settings → "Reset Device Key". See DM-5. |

---

## Cryptographic Properties

| Property | Implementation |
|---|---|
| **Forward secrecy** | WireGuard's noise protocol provides perfect forward secrecy. Past sessions cannot be decrypted even if the device key is later compromised. |
| **Session keys** | Ephemeral per session. Never stored. |
| **DNS tunnel encryption** | Session key established via DH exchange at tunnel start. Key material is ephemeral. DNS labels in transit carry only encrypted payload. |
| **Key storage** | Private keys stored in device keychain (iOS Secure Enclave / macOS Keychain) — never in app storage, never transmitted. |

---

## Open Questions

| # | Question | Decision needed by |
|---|---|---|
| OQ-2 | What is the exact idle eviction timeout for WireGuard peer slots on managed servers? | Engineering — use WireGuard's native ~3-minute session expiry as the baseline; tune based on capacity testing |
| ~~OQ-4~~ | ~~When does the client request its initial Privacy Pass token batch?~~ | Closed — see Decision DM-3 |

## Decisions Log

| # | Decision |
|---|---|
| DM-2 | **Collect aggregate metrics.** Hourly rollups (peak connections, p50/p95 latency) per server are collected for capacity planning and incident detection. Aggregation happens server-side in real time; raw per-connection measurements are never written to storage. Only rollups are persisted. |
| DM-1 | **Rate limiting at launch using Privacy Pass blind tokens.** Rate limiting is implemented at launch. The mechanism is Privacy Pass (RFC 9576) blind token issuance — cryptographically anonymous, cannot be linked back to any device or identity. Simpler opaque tokens were considered but rejected because they allow Freewire to correlate connections to the same device over time. |
| DM-3 | **Privacy Pass token issuance timing.** Client requests initial token batch on first connection attempt (not at app launch). Client refreshes in the background when batch drops below 3 tokens remaining. Re-issuance is silent — no user-visible state. If re-issuance fails, the connection continues and the client retries silently on the next connection attempt. |
| DM-4 | **Network path intelligence is opt-in and BSSID-hashed.** The client may submit path success/failure reports to build a crowdsourced captive portal hint database. Submission requires explicit user opt-in (off by default). The client hashes the BSSID with SHA-256 before transmission — raw BSSIDs never reach Freewire servers. Reports contain no IP, no device key, no timestamp beyond week granularity. K-anonymity threshold of 5: hints are only served once at least 5 independent reports exist for a network. |
| DM-5 | **WireGuard keypair is backed up to iCloud Keychain.** Accessibility class: `kSecAttrAccessible.afterFirstUnlock` — backed up, encrypted, available after first device unlock on restore. Rationale: seamless device migration outweighs the marginal benefit of device-local key isolation. The keypair is not a credential — users can reset it. Users who want to generate a new identity (e.g., before selling a device) use Settings → "Reset Device Key". |
