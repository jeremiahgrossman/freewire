# Freewire VPN — Server Dashboard API Specification

**Audience:** Server engineers and frontend engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Applies to:** Self-hosted servers only. Managed Freewire servers do not expose a dashboard.

---

## Overview

Every self-hosted Freewire server exposes a local web dashboard at `https://<server-ip>:8443`. This dashboard is the admin interface for device management: adding devices, revoking access, generating connection configs and QR codes, and monitoring server health.

The dashboard is a single-page web app served directly by the `freewire-server` binary. The frontend communicates with the backend via the HTTP API described in this document.

This is a **separate API surface from the VPN control plane** described in `client-server-api-spec.md`. The VPN control plane (`/v1/*`) is for Freewire client apps. The dashboard API (`/dashboard/v1/*`) is for the server admin.

---

## Base URL

```
https://<server-ip>:8443/dashboard/v1
```

The server certificate is self-signed (generated on first boot). See `certificate-management.md` §3. Admin browsers must accept the certificate fingerprint, which is displayed on the setup screen and in the CloudFormation output.

---

## Authentication

All dashboard API endpoints require authentication. The dashboard uses **HTTP Bearer token authentication**.

### Login

```
POST /dashboard/v1/auth/login
```

**Request:**
```json
{
  "password": "<setup-password>"
}
```

The setup password is set via the `SetupPassword` CloudFormation parameter and is available in the CloudFormation Outputs section.

**Response (200 OK):**
```json
{
  "token": "<session-token>",
  "expires_at": "2026-06-18T14:30:00Z"
}
```

**Response (401 Unauthorized):**
```json
{
  "error": "invalid_password"
}
```

Dashboard sessions are valid for **8 hours**. The token is a 32-byte random hex string. Tokens are stored in memory only — server restart invalidates all sessions.

**Rate limiting:** 5 failed login attempts per IP per 10 minutes triggers a 10-minute lockout.

### Using the token

Pass the token in the `Authorization` header for all subsequent requests:

```
Authorization: Bearer <session-token>
```

All endpoints except `/dashboard/v1/auth/login` return `401 Unauthorized` if the token is missing, invalid, or expired.

### Logout

```
POST /dashboard/v1/auth/logout
```

No request body. Invalidates the current session token. Returns `204 No Content`.

---

## Endpoints

### Server Status

```
GET /dashboard/v1/status
```

Returns current server health and configuration.

**Response (200 OK):**
```json
{
  "version": "1.2.3",
  "build": 47,
  "uptime_seconds": 86400,
  "wireguard": {
    "public_key": "base64-encoded-wireguard-public-key",
    "endpoint": "54.210.13.7:51820",
    "peer_count": 3,
    "peer_limit": 50
  },
  "tunnel_paths_enabled": ["wireguard", "tls443", "dns", "icmp"],
  "certificate_fingerprint": "sha256:AABBCC...",
  "last_updated": "2026-06-17T12:00:00Z"
}
```

| Field | Description |
|---|---|
| `version` | Server software version |
| `build` | Monotonic build number |
| `uptime_seconds` | Seconds since server process started |
| `wireguard.public_key` | Server's WireGuard public key (base64) — same as returned by CloudFormation |
| `wireguard.endpoint` | `<public-ip>:<port>` that clients connect to |
| `wireguard.peer_count` | Number of currently registered peers |
| `wireguard.peer_limit` | Maximum peers supported on this instance type |
| `tunnel_paths_enabled` | Which tunnel paths are active on this server |
| `certificate_fingerprint` | SHA-256 fingerprint of the dashboard's self-signed certificate |
| `last_updated` | Timestamp of last configuration change |

---

### List Devices

```
GET /dashboard/v1/devices
```

Returns all registered devices (WireGuard peers). No pagination — self-hosted servers have a hard peer limit per instance type (50 for t3.small, 200 for t3.medium).

**Response (200 OK):**
```json
{
  "devices": [
    {
      "peer_token": "tok_abc123",
      "device_name": "iPhone 16 Pro",
      "public_key_fingerprint": "AB:CD:EF:...",
      "registered_at": "2026-06-17T10:00:00Z",
      "last_handshake": "2026-06-17T14:25:00Z",
      "connected": true,
      "label": "iPhone"
    },
    {
      "peer_token": "tok_def456",
      "public_key_fingerprint": "12:34:56:...",
      "registered_at": "2026-06-16T08:00:00Z",
      "last_handshake": null,
      "connected": false,
      "label": null
    }
  ],
  "total": 2
}
```

| Field | Description |
|---|---|
| `peer_token` | Opaque token identifying the peer registration. Used for revocation. |
| `public_key_fingerprint` | SHA-256 fingerprint of the device's WireGuard public key, colon-delimited hex. The full public key is never returned — the fingerprint is sufficient for display. |
| `registered_at` | ISO 8601 timestamp when the device registered. |
| `last_handshake` | ISO 8601 timestamp of the most recent WireGuard handshake. `null` if the device has never connected. |
| `connected` | `true` if a WireGuard handshake occurred within the last 3 minutes. |
| `label` | Optional human-readable label set by the admin. `null` if not set. |

**Privacy note:** The full WireGuard public key and tunnel IP are not returned. The server stores them (they are required for WireGuard peering) but the dashboard does not expose them. The fingerprint is sufficient for the admin to identify which device is which.

---

### Revoke a Device

```
DELETE /dashboard/v1/devices/{peer_token}
```

Removes the device's WireGuard peer configuration. The device's tunnel is dropped immediately. The device will not be able to reconnect without re-importing a new config.

**Response (204 No Content):** Device revoked successfully.

**Response (404 Not Found):**
```json
{
  "error": "device_not_found"
}
```

This operation is **irreversible**. The device's public key registration is deleted. If the user wants to reconnect, they must generate a new config from the dashboard and re-import it on their device.

---

### Label a Device

```
PATCH /dashboard/v1/devices/{peer_token}
```

Sets a human-readable label for a device. Labels are admin-only — they are not shown to the device owner.

**Request:**
```json
{
  "label": "MacBook Pro"
}
```

`label` must be a string of 1–64 characters. Set to `null` or `""` to clear the label.

**Response (200 OK):** Returns the updated device object (same shape as in the device list).

**Response (404 Not Found):**
```json
{
  "error": "device_not_found"
}
```

---

### Generate Connection Config

```
POST /dashboard/v1/config/generate
```

Generates a one-time connection config for a new device. The config contains the server's WireGuard public key, endpoint, tunnel IP assignment, and certificate fingerprint. The client imports this config during the self-host onboarding flow.

**Request:** No body required.

**Response (200 OK):**
```json
{
  "config_token": "cfg_xyz789",
  "expires_at": "2026-06-18T14:30:00Z",
  "qr_url": "/dashboard/v1/config/cfg_xyz789/qr",
  "download_url": "/dashboard/v1/config/cfg_xyz789/download",
  "tunnel_ip": "10.0.0.4",
  "device_label": null
}
```

| Field | Description |
|---|---|
| `config_token` | Opaque token identifying this config. Used to retrieve the QR code and download file. |
| `expires_at` | 24 hours from generation. After expiry, the config token is invalid. |
| `qr_url` | Path to the QR code image for this config. |
| `download_url` | Path to the WireGuard config file download. |
| `tunnel_ip` | The tunnel IP that will be assigned to the device that imports this config. |

**Config expiry:** The config token expires after **24 hours** regardless of whether it has been used. This is the same window referenced in the UX workflows and the engineering handoff. An already-connected device is not affected by config expiry — expiry only blocks new imports of an old token.

**Single use:** A config token can be imported by exactly one device. After the device registers (calls `POST /v1/peers` on the VPN control plane with this config), the token is consumed and cannot be used again. Attempting to re-use a consumed token returns `410 Gone`.

---

### Get QR Code

```
GET /dashboard/v1/config/{config_token}/qr
```

Returns a QR code image encoding the connection config. The admin shows this on-screen for the user to scan with their iPhone or Mac.

**Response (200 OK):**
- Content-Type: `image/png`
- Body: PNG image, 400×400 pixels

The QR code encodes a URI in the following format:
```
freewire://connect?endpoint=54.210.13.7%3A51820
  &pubkey=<base64-wireguard-pubkey>
  &token=<config-token>
  &fp=sha256%3A<certificate-fingerprint>
  &tip=10.0.0.4
```

The Freewire client app handles `freewire://` URI scheme deep links. Scanning the QR code opens the app directly into the self-host connection confirmation screen.

**Device name pre-population:** When the client app completes registration after scanning the QR code, it may include its device model name in the `POST /v1/peers` request (opt-in, user-confirmed during the self-host import confirmation screen). If provided, the server stores it as the `device_name` for that peer in the dashboard device list, pre-populated as the label — so the admin sees "iPhone 16 Pro" instead of a raw key fingerprint. The user is shown "Share your device name with the server admin?" during the import confirmation step and can decline.

**Response (404 Not Found):** Config token does not exist.

**Response (410 Gone):** Config token has expired or was already consumed.

---

### Download Config File

```
GET /dashboard/v1/config/{config_token}/download
```

Returns a WireGuard `.conf` file the user can import manually (for desktop clients that cannot scan QR codes).

**Response (200 OK):**
- Content-Type: `text/plain`
- Content-Disposition: `attachment; filename="freewire-server.conf"`
- Body:

```ini
[Interface]
PrivateKey = <client-will-fill-this-in>
Address = 10.0.0.4/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-wireguard-pubkey>
Endpoint = 54.210.13.7:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25

# Freewire metadata — do not edit
# ConfigToken = cfg_xyz789
# DashboardFingerprint = sha256:AABBCC...
```

The `PrivateKey` field is left blank — the Freewire client generates its own keypair and fills it in during import. The import flow is described in `ux-workflows.md` §4.3.

**Response (404 Not Found):** Config token does not exist.

**Response (410 Gone):** Config token expired or consumed.

---

### Change Admin Password

```
POST /dashboard/v1/auth/change-password
```

Changes the dashboard admin password. Requires the current password.

**Request:**
```json
{
  "current_password": "<current>",
  "new_password": "<new>"
}
```

Password requirements: minimum 12 characters. No other constraints.

**Response (204 No Content):** Password changed. All existing sessions (including the current one) are invalidated. The admin must log in again with the new password.

**Response (401 Unauthorized):**
```json
{
  "error": "invalid_password"
}
```

---

## Error Response Format

All error responses follow this format:

```json
{
  "error": "<error_code>",
  "message": "<human-readable description>"
}
```

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON or missing required field |
| 401 | `unauthorized` | Missing or invalid auth token |
| 401 | `invalid_password` | Wrong password on login |
| 403 | `session_expired` | Auth token has expired — log in again |
| 404 | `device_not_found` | No device with this peer_token |
| 404 | `config_not_found` | No config with this config_token |
| 409 | `label_too_long` | Label exceeds 64 characters |
| 410 | `config_expired` | Config token expired (24-hour window passed) |
| 410 | `config_consumed` | Config token already used by a device |
| 429 | `rate_limited` | Too many failed login attempts |
| 500 | `internal_error` | Server-side error; retry after a moment |

---

## Dashboard Web App

The dashboard web app is a single-page application served from `GET /dashboard/` by the `freewire-server` binary. It is compiled into the binary at build time (Go `embed.FS`). No separate frontend deployment is required.

The web app communicates exclusively with the API endpoints described in this document. No server-side rendering — all pages are client-rendered.

The web app stores the auth token in `sessionStorage` (not `localStorage`) so it is cleared when the browser tab is closed.

---

## Security Considerations

- All traffic is HTTPS. The self-signed certificate is verified via fingerprint pinning in the Freewire client app (for QR import), and via manual fingerprint confirmation in the browser (admin must accept the certificate on first visit).
- The dashboard is only accessible on port 8443. The CloudFormation security group opens this port to `0.0.0.0/0` by default — the admin should restrict this to their own IP in the AWS Console for additional security. The dashboard requires password authentication regardless. See `cloudformation-spec.md` §security-group.
- The dashboard does not have a "forgot password" flow. If the admin loses the password, they must destroy and redeploy the CloudFormation stack.
- Config tokens are single-use and 24-hour expiry. There is no mechanism to extend a token's expiry — generate a new one.
- The device list never exposes raw WireGuard public keys or assigned tunnel IPs. Only fingerprints are shown.
