# Freewire VPN — Client-Server API Specification

**Audience:** Client and server engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

## Overview

This document specifies the HTTP API between the Freewire client (iOS/macOS) and the Freewire managed server. It is the contract both sides must implement consistently.

The client and server never need to agree on a user identity. All device identity is a WireGuard public key — Base64-encoded, 44 characters, generated locally on the device.

---

## Base URL

**Managed servers:** `https://<server-ip>/v1/` (the dev/managed deployment is IP-addressed — currently `52.203.246.145`; `vpn.freewire.com` is an aspirational name, not the live host). The API port is 8080 (HTTPS). An ACME hostname `origin.pinghop.net` fronts the TLS *carriers* but is not the API base.  
**Self-hosted servers:** `https://<server-ip>/v1/` (self-signed TLS certificate; client pins the server's WireGuard key trust-on-first-use)

All endpoints are HTTPS only. HTTP requests are rejected with `301 Moved Permanently`.

API versioning is path-based (`/v1/`). Breaking changes increment the version. Clients must check `SYS-1` (version incompatible) error state if the server returns `410 Gone` on any endpoint.

---

## Authentication

All requests that register or interact with a peer use a **Privacy Pass token** in the request header:

```
Authorization: PrivateToken token=<base64url-encoded-token>
```

Tokens are issued via the `/v1/tokens/issue` endpoint (see §Tokens). Token verification is done server-side using the blind signature scheme — the server can verify the token is valid without linking it to the device that received it.

Endpoints that do not require a token: `/v1/server/config`, `/v1/health`.

---

## Endpoints

### GET /v1/server/config

Returns the server's WireGuard configuration that the client needs to establish a tunnel.

**Authentication:** None required.

**Request:** No body.

**Response `200 OK`:** (field set as sent by `server/internal/api/config_handler.go`)
```json
{
  "public_key": "base64-encoded-wireguard-public-key==",
  "endpoint_host": "52.203.246.145",
  "endpoint_port": 51820,
  "tls_endpoint_host": "52.203.246.145",
  "tls_endpoint_port": 443,
  "dns_tunnel_port": 53,
  "icmp_udp_port": 4500,
  "dns_tunnel_domain": "tunnel.freewire.com",
  "endpoint_host_v6": "2001:db8::1",
  "cdn_host": "d29cubp361kpm8.cloudfront.net",
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "server_version": "1.4.2",
  "min_client_version": "1.0.0",
  "region": "us-east",
  "capacity_available": true,
  "privacy_pass_key_n": "base64url-modulus",
  "privacy_pass_key_e": 65537,
  "privacy_pass_key_id": "base64url-key-id"
}
```

| Field | Description |
|---|---|
| `public_key` | Server's WireGuard public key. Client uses this to authenticate the tunnel. |
| `endpoint_host` | Server IP for standard WireGuard UDP connection (open networks). The deployment is IP-addressed; no DNS name is required. |
| `endpoint_port` | UDP port for WireGuard (default 51820). |
| `tls_endpoint_host` | Host for the TLS carriers (tls443/wss443). **Currently MUST equal `endpoint_host`** — no client plumbs a distinct TLS host, so a divergent value is silently ignored and the TLS carriers would go unreachable. Advertised for a future deployment that fronts TLS on a separate host (e.g. an ACME hostname). See `server/internal/api/config_handler.go`. |
| `tls_endpoint_port` | Port for the TLS carriers (443). |
| `dns_tunnel_port` | UDP port for the DNS-tunnel carrier (default 53). |
| `icmp_udp_port` | UDP port for the ICMP-tunnel carrier (default 4500). |
| `dns_tunnel_domain` | Apex domain for DNS tunnel (`tunnel.freewire.com` for managed servers). Optional; the client falls back to its own default when empty. |
| `endpoint_host_v6` | Server global IPv6 address, `omitempty`. Advertised for the IPv6 carrier (server-side ready; the leak-safe client routing is deferred — see `IPV6-CARRIER-REMAINING.md`). |
| `cdn_host` | CDN hostname that fronts the server (e.g. a CloudFront distribution), `omitempty`. Enables the `cdn_wss` carrier client-side; empty disables it. |
| `allowed_ips` | WireGuard AllowedIPs for full-tunnel mode. |
| `server_version` | Current server software version. |
| `min_client_version` | Oldest client version the server will accept. If client version is below this, return `SYS-1` error. |
| `region` | Human-readable region label shown in the client UI. |
| `capacity_available` | `false` if the server is at or near peer capacity. Client should surface `CONN-4` if false. |
| `privacy_pass_key_n` / `privacy_pass_key_e` / `privacy_pass_key_id` | Privacy Pass issuer RSA public key (modulus, exponent, key id), `omitempty`. Absent on self-hosted servers with no issuer. The client pins this trust-on-first-use. |

**Response `503 Service Unavailable`:** Server is in maintenance mode. Client should surface `CONN-3`.

---

### POST /v1/peers

Register a device as a WireGuard peer. The server adds the device's public key to its in-memory WireGuard peer list and returns the client's assigned tunnel IP address.

**Authentication:** Privacy Pass token required.

**Request body:**
```json
{
  "public_key": "base64-encoded-device-wireguard-public-key=="
}
```

| Field | Required | Description |
|---|---|---|
| `public_key` | Yes | Device's WireGuard public key (Base64, 44 chars) |

> **`public_key` is the ONLY field.** `client_version` and `device_name` were
> removed and MUST NOT be reintroduced: any caller attribute submitted alongside
> a Privacy Pass token is a handle the anonymous issuance can be correlated
> against, which breaks the redemption-anonymity guarantee (non-negotiable
> constraint #3 in `CLAUDE.md`). The server (`server/internal/api/peers_handler.go`)
> decodes `public_key` only. See also `data-model.md` and the redaction rationale
> in the handler comment.

**Response `201 Created`:**
```json
{
  "tunnel_ip": "10.0.0.47",
  "tunnel_ip_v6": "fd00::2f",
  "keepalive_interval": 25,
  "peer_token": "opaque-short-lived-session-token"
}
```

| Field | Description |
|---|---|
| `tunnel_ip` | IPv4 address assigned to this peer inside the tunnel. |
| `tunnel_ip_v6` | IPv6 address assigned to this peer inside the tunnel. |
| `keepalive_interval` | Seconds between WireGuard keepalive packets the client should send. 25s is the standard value for NAT traversal. |
| `peer_token` | Short-lived opaque token used to identify this session for `DELETE /v1/peers` and keepalive. Not cryptographically sensitive — it cannot be used to impersonate the peer. Expires with the session. |

**Response `402 Payment Required`:** Privacy Pass token is invalid or already spent. Client must request a new token batch and retry. Surface `CONN-3` to user during retry.

**Response `429 Too Many Requests`:** Rate limit exceeded beyond token-based protection (abuse signal). Retry after `Retry-After` header value.

**Response `503 Service Unavailable`:** Server at capacity. Surface `CONN-4`.

**Response `410 Gone`:** Client version is below `min_client_version`. Surface `SYS-1` (update required).

---

### DELETE /v1/peers/{peer_token}

Gracefully remove a peer when the user explicitly disconnects. The server removes the public key from its WireGuard peer list.

This is a best-effort call. If it fails (network loss, server restart), the peer slot expires naturally via WireGuard's idle eviction timeout (~3 minutes). Clients must not block disconnect UX waiting for this response.

**Authentication:** None required (the peer token is the credential).

**Path parameter:** `peer_token` — the value returned by `POST /v1/peers`.

**Request:** No body.

**Response `204 No Content`:** Peer removed.

**Response `404 Not Found`:** Peer token not recognized (already expired or evicted). Safe to ignore.

---

### POST /v1/tokens/issue

Request a batch of Privacy Pass blind tokens. The client sends blinded token values; the server signs them without seeing the unblinded values and returns the signed tokens.

The client unblinds the tokens locally. The server cannot link a signed token back to the device that requested it.

See `privacy-pass-spec.md` for the full cryptographic protocol.

**Authentication:** None required for issuance. (The rate limiting this protects against is enforced by requiring a token to register a peer — a device that abuses issuance still cannot connect without spending a valid token.)

**Request body:**
```json
{
  "blinded_tokens": [
    "base64url-encoded-blinded-token-1",
    "base64url-encoded-blinded-token-2",
    "...up to 20 tokens per request"
  ],
  "client_version": "1.2.0"
}
```

**Batch size:** Minimum 1, maximum 20 tokens per request. Client should request 10 tokens per batch (enough for 10 connections; background refresh when < 3 remain).

**Response `200 OK`:**
```json
{
  "signed_tokens": [
    "base64url-encoded-signed-blinded-token-1",
    "base64url-encoded-signed-blinded-token-2"
  ],
  "public_key": "base64url-encoded-issuer-public-key"
}
```

The `public_key` is the server's token issuance public key. The client uses this to verify the signatures after unblinding. The client should cache this key and verify it matches on subsequent issuance calls — a key change may indicate a server update.

**Response `429 Too Many Requests`:** Issuance rate limit hit. Client should back off and retry silently. Do not surface to user unless all retries fail.

---

### GET /v1/health

Returns server health and current load. Used by the client to display server status in the UI and for pre-connection capacity checks.

**Authentication:** None required.

**Response `200 OK`:**
```json
{
  "status": "ok",
  "region": "us-east",
  "current_peers": 847,
  "capacity": 1000,
  "capacity_available": true,
  "server_version": "1.4.2",
  "uptime_seconds": 1209600
}
```

`status` values: `"ok"` | `"degraded"` | `"maintenance"`

**Response `503 Service Unavailable`:** Server is offline or in emergency maintenance.

---

## Network Intelligence API

> ⚠️ **DECLINED — NOT BUILT, and not to be built.** These endpoints were
> deliberately not implemented. Reconnect already remembers the last working
> transport, so a crowdsourced hint would only help a first connection to an
> unseen network, while a hashed BSSID is a location identifier public wardriving
> databases can reverse. See `DECISIONS.md` §NETWORK-INTELLIGENCE and `CLAUDE.md`
> ("Network intelligence is deliberately not built"). No server implements
> `/v1/network/*`; no client calls it; the `network_path_hint` table does not
> exist. The spec below is retained for history only. Do NOT add the preferences
> toggle — a toggle for a feature that does nothing is its own false claim.

These two endpoints WOULD power a crowdsourced captive portal hint feature, opt-in only. See `data-model.md` §network_path_hint and `privacy-policy.md` §network-intelligence.

Self-hosted servers do not implement these endpoints. The client skips them when connected to a self-hosted server.

---

### Submit a Path Report

```
POST /v1/network/report
```

Called after a connection attempt completes (success or full failure). Reports which paths succeeded and which failed on the current network, keyed by the SHA-256 hash of the BSSID. The raw BSSID is never sent — hashing is performed on-device before transmission.

**Called only when:**
- User has opted in to network intelligence
- A BSSID is available (wifi network; not cellular)
- The connection attempt resulted in a definitive outcome (success or CONN-2)

**Request:**

```json
{
  "bssid_hash": "a3f1b2c4d5e6...",
  "successful_path": "dns_tunnel",
  "failed_paths": ["http_connect", "tls443"],
  "client_version": "1.2.3"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `bssid_hash` | string (64-char hex) | Yes | SHA-256 of the raw BSSID, computed on-device. |
| `successful_path` | string or null | Yes | The path that established the tunnel: `"http_connect"`, `"tls443"`, `"dns_tunnel"`, `"icmp"`, or `null` if all paths failed. |
| `failed_paths` | string[] | Yes | Paths attempted before the successful path, or all paths on full failure. May be empty if the first path succeeded. |
| `client_version` | string | Yes | Client version string, for filtering stale reports. |

The server **must not log the client IP address** for this request. Strip it at the ingestion layer, not after storage. The request carries no device identifier — there is no `Authorization` header on this endpoint.

**Response (204 No Content):** Report accepted.

**Response (400 Bad Request):**
```json
{ "error": "invalid_request", "message": "bssid_hash must be 64 hex characters" }
```

**Response (429 Too Many Requests):** Rate limited. Retry after `Retry-After` seconds. Rate limit: 10 reports per IP per hour (applied server-side only for DoS protection; this is not stored as IP-keyed data).

---

### Get Path Hint

```
GET /v1/network/hint?bssid_hash=<hex>
```

Called before starting the fallback chain. Returns the historically best-performing path for the given network, if enough reports exist.

**Called only when:**
- User has opted in to network intelligence
- A BSSID is available
- A hint would actually change probe order (skip if already on the fastest known path)

**Query parameter:**

| Parameter | Description |
|---|---|
| `bssid_hash` | SHA-256 of the BSSID, 64-char hex |

**Response (200 OK) — hint available:**

```json
{
  "hint_available": true,
  "recommended_path": "dns_tunnel",
  "skip_paths": ["http_connect", "tls443"],
  "report_count": 23,
  "confidence": "high"
}
```

| Field | Description |
|---|---|
| `hint_available` | `true` if `report_count >= 5` and a reliable recommendation exists |
| `recommended_path` | Path to try first for this network |
| `skip_paths` | Paths that have consistently failed on this network — client may skip their probe (but must not skip them in CONN-2 determination) |
| `report_count` | Number of opt-in reports this hint is based on |
| `confidence` | `"high"` (≥20 reports, consistent), `"medium"` (5–19 reports), `"low"` (5–19 reports, mixed results) |

**Response (200 OK) — no hint:**

```json
{
  "hint_available": false
}
```

Returned when `report_count < 5` or the network is unknown. Client proceeds with default fallback chain order.

**Client behavior with hint:**

The hint reorders the probe sequence — it does not skip paths entirely. If the `recommended_path` fails, the client falls back to the full chain in default order. This ensures that stale or wrong hints degrade gracefully rather than preventing connection.

Example: hint says `recommended_path: dns_tunnel`, `skip_paths: ["http_connect", "tls443"]`. Client probes `dns_tunnel` first. If it fails, client tries `http_connect` and `tls443` before giving up — the hint speeds up the happy path without creating a new failure mode.

---

## Error Response Format

All error responses use a consistent envelope:

```json
{
  "error": {
    "code": "PEER_LIMIT_REACHED",
    "message": "Server is at capacity.",
    "retry_after": 300
  }
}
```

| `code` | HTTP status | Maps to error state |
|---|---|---|
| `PEER_LIMIT_REACHED` | 503 | CONN-4 |
| `SERVER_UNAVAILABLE` | 503 | CONN-3 |
| `TOKEN_INVALID` | 402 | Retry with new token |
| `TOKEN_SPENT` | 402 | Retry with new token |
| `VERSION_UNSUPPORTED` | 410 | SYS-1 |
| `RATE_LIMITED` | 429 | Back off per Retry-After |

---

## Self-Hosted Server API

Self-hosted servers implement the same API with two differences:

1. The base URL is `https://<server-ip>/v1/` with a self-signed TLS certificate.
2. The `/v1/tokens/issue` endpoint is disabled — self-hosted servers do not use Privacy Pass. The `Authorization` header on `POST /v1/peers` is omitted; the self-hosted server accepts any registered device key.

The self-hosted server's web dashboard (see `ux-workflows.md` §4.4) adds additional endpoints under `/dashboard/` that are not part of the client API and are not documented here.

---

## Client Behavior

### On app launch
1. Call `GET /v1/server/config` — cache the response for 1 hour.

### On connect
1. ~~*(network intelligence opt-in)* Call `GET /v1/network/hint`~~ — **DECLINED, not built** (see the Network Intelligence banner above). The client does NOT call this; instead reconnect remembers the last working transport locally.
2. Check the cached `GET /v1/server/config` response. If `capacity_available` is `false`, surface `CONN-4` and stop.
3. If `min_client_version` is above the current client version, surface `SYS-1` and stop.
4. If token batch is empty or below 3 tokens, call `POST /v1/tokens/issue` first.
5. Call `POST /v1/peers` with the device public key and one Privacy Pass token.
6. Use the returned `tunnel_ip` and `peer_token` to configure the WireGuard interface.
7. Send WireGuard keepalives at `keepalive_interval` seconds.
8. ~~*(network intelligence opt-in)* call `POST /v1/network/report`~~ — **DECLINED, not built** (see banner above).

### On disconnect
1. Call `DELETE /v1/peers/{peer_token}` as a best-effort fire-and-forget.
2. Tear down the WireGuard interface immediately regardless of response.

### Token batch management
- Request initial batch on first connect attempt.
- After each successful `POST /v1/peers`, decrement local token count.
- When count drops below 3, request a new batch of 10 in the background.
- If issuance fails, continue with remaining tokens. Retry issuance on next connection attempt.
- Token storage: encrypted local file in the app's protected data container. Not in Keychain (tokens are not secrets — they are anonymous credentials). See `privacy-pass-spec.md` §Storage.
