# Freewire VPN — DNS Tunnel Wire Protocol Specification

**Audience:** Server and client engineers implementing the DNS tunnel  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Depends on:** `technical-architecture.md` (read first for design rationale)

---

## Overview

The DNS tunnel encodes arbitrary binary data as DNS queries and responses. It is the third path in the fallback chain, used when HTTP CONNECT and TLS/443 are both blocked. It works on any captive portal network that forwards unknown DNS queries to the public internet.

This document specifies the exact wire format. `technical-architecture.md` explains why the design works. This document explains how to implement it.

---

## Domain Structure

All DNS tunnel traffic uses subdomains of `tunnel.freewire.com`. Freewire operates the authoritative DNS server for this domain.

### Control plane subdomains

```
<prefix>.<session-token>.<payload>.tunnel.freewire.com
```

| Prefix | Purpose |
|---|---|
| `h` | Handshake — initiate a session, negotiate parameters |
| `u` | Upgrade probe — test whether TLS/443 is now reachable |
| `k` | Keepalive — maintain resolver cache entry, confirm liveness |
| `t` | Data — tunnel payload |

### Session token

A 10-character Base32 string assigned by the server during the handshake. Identifies the session for the duration of the connection. Encoded as the second label in all subsequent queries.

Example: `MFRA2XBPCD`

### Payload encoding

All payload data is Base32-encoded (RFC 4648, no padding) before embedding in DNS labels. Base32 is used — not Base64 — because DNS labels are case-insensitive and Base64 uses characters (`+`, `/`, `=`) not valid in DNS labels.

**DNS label constraints:**
- Each label: max 63 characters
- Total domain name: max 253 characters including dots and apex
- Available for payload before `.tunnel.freewire.com` (22 chars): ~230 characters
- Available labels before apex: 3–4 labels of up to 63 characters each
- Practical encoded payload per query: ~150 bytes of raw data (encoded as ~240 Base32 characters across 4 labels)

---

## Handshake

The handshake establishes the session: exchanges a session token, negotiates EDNS0 capability and window size, and performs a Diffie-Hellman (DH) key exchange for tunnel encryption.

The handshake spans multiple DNS queries due to the size constraints of DNS labels. The minimum number of round trips for a complete DH handshake is **3**.

### Handshake query format

```
h.<step>.<data>.tunnel.freewire.com
```

`<step>` is a single digit (1, 2, 3). `<data>` is Base32-encoded binary.

### Step 1 — Client Hello (client → server)

The client sends its DH public key and capabilities.

**Binary format of `<data>` in step 1 (36 bytes):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  |    Flags      |        EDNS0 Max Size         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Client DH Public Key                       |
|                       (32 bytes, Curve25519)                  |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|---|---|---|
| Version | 1 byte | Protocol version. Current: `0x01`. |
| Flags | 1 byte | Bit 0: EDNS0 supported. Bit 1: ICMP fallback available. Bits 2–7: reserved (0). |
| EDNS0 Max Size | 2 bytes, big-endian | Maximum DNS response payload the client can accept (typically 4096). |
| Client DH Public Key | 32 bytes | Ephemeral Curve25519 public key for this session. Generated fresh for every handshake. |

Base32-encoded, this is 58 characters — fits in a single DNS label.

Query example:
```
h.1.AEBQAAQQAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==.tunnel.freewire.com
```

**Server response:** TXT record containing the step 2 payload (see below). TTL=0.

---

### Step 2 — Server Hello (server → client, in TXT response to step 1)

The server responds with its DH public key, the assigned session token, and negotiated parameters.

**Binary format of TXT record data (56 bytes):**

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  |    Flags      |  Negotiated EDNS0 Max Size    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Initial Window Size   |   Session Token (10 bytes)    |
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Server DH Public Key                       |
|                       (32 bytes, Curve25519)                  |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Description |
|---|---|---|
| Version | 1 byte | Must match client version or handshake fails. |
| Flags | 1 byte | Bit 0: EDNS0 confirmed. Bit 1: Multi-record responses enabled. |
| Negotiated EDNS0 Max Size | 2 bytes | `min(client_requested, 4096)`. |
| Initial Window Size | 2 bytes | Number of simultaneous in-flight queries. Computed from observed latency. Initial value: 8. |
| Session Token | 10 bytes | ASCII Base32 string. Used in all subsequent queries as the second label. |
| Server DH Public Key | 32 bytes | Server's ephemeral Curve25519 public key. |

After receiving step 2, both sides compute the shared secret:
```
shared_secret = X25519(client_private_key, server_public_key)
                = X25519(server_private_key, client_public_key)
```

The session encryption key is derived from this shared secret using HKDF-SHA256:
```
session_key = HKDF-SHA256(
  ikm  = shared_secret,
  salt = session_token (10 bytes),
  info = "freewire-dns-tunnel-v1",
  len  = 32 bytes
)
```

---

### Step 3 — Client Confirm (client → server)

The client confirms the handshake is complete and the shared secret was successfully derived. This is a MAC over the session token, proving the client derived the same key.

```
h.3.<session-token>.<mac>.tunnel.freewire.com
```

`<mac>` is the first 16 bytes of HMAC-SHA256(session_key, session_token), Base32-encoded.

**Server response:** TXT record `"OK"` if MAC verifies, or `"FAIL"` if not (client must restart handshake with a new ephemeral key).

---

## Data Transfer

After the handshake, all tunnel data is exchanged using the `t.` prefix.

### Query format (client → server, outbound data)

```
t.<session-token>.<seq>.<data-chunk>[.<data-chunk>...].tunnel.freewire.com
```

| Label | Content |
|---|---|
| `t` | Data prefix |
| `<session-token>` | 10-char Base32 session token from handshake |
| `<seq>` | Sequence number, Base32-encoded, 4 bytes big-endian (0–4294967295, wraps) |
| `<data-chunk>` | Up to 63 Base32 characters (~37 bytes raw) per label; use multiple labels to pack maximum payload |

**Maximum payload per query:** With 4 labels of 63 chars each, minus overhead for seq and session token: approximately 150 bytes of raw (encrypted) data per query.

All data is encrypted with the session key using ChaCha20-Poly1305 before Base32 encoding:
```
ciphertext = ChaCha20-Poly1305.Seal(
  key   = session_key,
  nonce = seq || 0x000000 (seq as 4 bytes big-endian, padded to 12 bytes),
  plaintext = raw_payload_chunk
)
```

### Response format (server → client, inbound data)

Responses use EDNS0 and multi-record encoding to maximize inbound payload per round trip.

The server responds to each data query with a DNS response containing:

- **TXT records:** Up to 4 TXT records, each carrying up to 255 bytes of Base32-encoded ciphertext
- **A records:** Up to 8 A records; each 4-byte IP is a payload chunk (not a real IP address)
- **AAAA records:** Up to 4 AAAA records; each 16-byte IPv6 address is a payload chunk
- **MX records:** Priority field (2 bytes) + exchange field (up to 63 chars) used as additional payload

**Response payload encoding:**

Each record in the response carries a 2-byte header before the payload:

```
[ack_seq: 2 bytes big-endian][payload: variable]
```

`ack_seq` is the sequence number of the query being acknowledged. The remaining bytes are ciphertext.

**Total inbound payload per response with EDNS0:**
- 4 × TXT: ~1000 bytes
- 8 × A: 32 bytes  
- 4 × AAAA: 64 bytes
- 4 × MX: ~250 bytes
- **Total: ~1350 bytes raw encrypted payload per response**

With EDNS0 at 4096 bytes (stripped of overhead): ~3500 bytes per response. Without EDNS0 (512-byte limit): ~250 bytes per response.

### EDNS0-degraded mode

Some resolver middleboxes strip the EDNS0 OPT record from queries. The server detects this (no OPT record in the received query) and signals it via Flags Bit 0 = 0 in the Step 2 handshake response.

When the client receives Bit 0 = 0:
- Enter **EDNS0-degraded mode**: reduce per-response payload expectation to ~250 bytes
- Compensate by increasing query frequency by 4× (window size × 4 to maintain throughput)
- Expected throughput in degraded mode: ~500 Kbps (vs. 1–2 Mbps with EDNS0)
- Degraded mode is logged internally for monitoring but not surfaced to the user

### Stale cache detection

Some resolvers cache DNS responses despite TTL=0. Stale responses cause sequence number mismatches in the sliding window.

Detection: Every query payload includes a 4-byte sequence number. The server echoes the sequence number in the encrypted response. If the client receives a response whose echoed sequence number is outside the current sliding window (i.e., older than the oldest outstanding query):

1. Mark the response as stale (discard payload)
2. **Rotate the subdomain prefix**: derive a new 8-character entropy prefix from a monotonic counter (`seq_base % 2^32` formatted as Base32)
3. Re-issue outstanding queries under the new prefix
4. The new prefix is a guaranteed cache miss — no resolver has seen it before

Stale cache events are tracked internally. If >10% of responses are stale over a 30-second window, log a diagnostic event.

---

## Sliding Window Protocol

The sliding window allows multiple in-flight queries simultaneously, eliminating the serial query → wait → response latency penalty.

### Window parameters

| Parameter | Initial value | Range | Adjustment |
|---|---|---|---|
| Window size | 8 | 1–64 | Additive increase / multiplicative decrease |
| Max sequence inflight | window_size | — | — |
| Retransmit timeout | 2× observed RTT | 500ms–10s | Per-query exponential backoff |

### Flow

```
Client maintains:
  send_base    = lowest unacknowledged sequence number
  next_seq     = next sequence number to send
  window_size  = current window size

Rule: next_seq - send_base < window_size

On receiving ACK for seq N:
  send_base = max(send_base, N + 1)
  window_size = min(window_size + 1, 64)  // additive increase

On retransmit timeout for seq N:
  retransmit query with seq N
  window_size = max(window_size / 2, 1)   // multiplicative decrease
```

### Out-of-order handling

Responses may arrive out of order. The client maintains a reorder buffer indexed by sequence number. Data is delivered to the tunnel in order; out-of-order responses are buffered until gaps are filled.

Buffer size: 2× window size. If the buffer fills, the oldest buffered packet is delivered in-order and a retransmit is triggered for the missing sequences.

---

## Keepalive

When no data is flowing, the client sends a keepalive every 30 seconds to maintain the resolver's cache entry for the session and confirm the tunnel is alive.

```
k.<session-token>.tunnel.freewire.com
```

No payload. Server responds with a TXT record `"K"`. If the server does not respond within 5 seconds, the client treats this as a tunnel drop and escalates to SESSION-1.

---

## Upgrade Probe

After the DNS tunnel is established, the client probes whether TLS/443 is now reachable. If it is, the client upgrades transparently.

```
u.<session-token>.tunnel.freewire.com
```

Server responds with TXT record containing the TLS endpoint:
```
"upgrade:vpn.freewire.com:443"
```

The client attempts a TLS/443 connection to the returned endpoint. If successful, the client tears down the DNS tunnel and switches to TLS/443. The session key does not transfer — the TLS/443 path uses its own TLS session.

**Upgrade probe timing:** Sent once, 5 seconds after DNS tunnel establishment. If the probe itself fails (NXDOMAIN from local resolver, no response), no retry — the client stays on DNS tunnel for the session.

---

## Session Termination

When the user disconnects, the client sends a teardown notice:

```
t.<session-token>.<seq>.AAAAAAAAAAAAAAAA.tunnel.freewire.com
```

Where the data chunk is 10 bytes of zero — a sentinel value the server recognizes as a teardown signal. The server removes the session from its table.

If the client disconnects without sending teardown (app killed, crash, network loss), the server evicts the session after 90 seconds of no keepalive or data.

---

## Error Handling

| Condition | Client behavior |
|---|---|
| Handshake step 2 not received within 3s | Retry step 1 up to 3 times, then abandon DNS tunnel path |
| Handshake MAC verification fails | Generate new ephemeral DH key, restart handshake |
| No response to data query within retransmit timeout | Retransmit; if 5 consecutive retransmits fail, treat as tunnel drop (SESSION-1) |
| NXDOMAIN response to any tunnel subdomain | DNS resolver is local-only; abort DNS tunnel, fall through to ICMP path |
| SERVFAIL response | Transient resolver error; retry once after 1s |
| Session token not found (server evicted session) | Restart full handshake |

---

## Security Properties

- **Confidentiality:** All payload is ChaCha20-Poly1305 encrypted with the session key. The DNS resolver sees random-looking Base32 strings, not plaintext data.
- **Integrity:** ChaCha20-Poly1305 provides authenticated encryption. Tampered responses are rejected.
- **Forward secrecy:** Session keys use ephemeral Curve25519 DH. Compromising the server's long-term key after the fact does not decrypt past sessions.
- **Passive observer:** A network observer can see that queries are going to `*.tunnel.freewire.com` and that Freewire is in use, but cannot read the tunnel content.
- **Replay prevention:** Nonces are derived from sequence numbers. A replayed query with the same sequence number produces the same ciphertext, which the server detects and drops (duplicate sequence within window).

---

## Reference Implementation Notes

- Use `github.com/miekg/dns` (Go) for DNS server implementation
- Curve25519 DH: `golang.org/x/crypto/curve25519`
- ChaCha20-Poly1305: `golang.org/x/crypto/chacha20poly1305`
- HKDF: `golang.org/x/crypto/hkdf`
- Client-side (Swift): `CryptoKit` provides Curve25519, ChaChaPoly, and HKDF
- Base32: RFC 4648 without padding, uppercase; Swift: custom encoder; Go: `encoding/base32` with `StdEncoding.WithPadding(base32.NoPadding)`
