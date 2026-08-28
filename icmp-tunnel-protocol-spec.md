# Freewire VPN — ICMP Tunnel Protocol Specification

**Audience:** Server and client engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Depends on:** `technical-architecture.md` §7, `dns-tunnel-protocol-spec.md` (reference for shared concepts)

---

## Overview

The ICMP tunnel is Freewire's last-resort fallback path (path 4 in the fallback chain). It encodes all VPN traffic in ICMP echo request and reply payloads. It activates only when the DNS tunnel fails — specifically, when the captive portal's DNS resolver is fully local and does not forward unknown domains to the public internet.

Coverage: ~1% of captive portal networks that block DNS forwarding but allow outbound ICMP echo to external IPs.

Throughput target: 100–500 Kbps sustained.

---

## ICMP Basics

ICMP echo request (type 8) and echo reply (type 0) packets carry an **identifier** field, a **sequence number** field, and a variable-length **data payload**. Freewire encodes tunnel data in this payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┼───────────────────────────────────┤
│  Type (8/0)   │   Code (0)    │           Checksum                │
├───────────────────────────────┼───────────────────────────────────┤
│          Identifier           │         Sequence Number           │
├───────────────────────────────┴───────────────────────────────────┤
│                          Data (variable)                          │
└───────────────────────────────────────────────────────────────────┘
```

For IPv4, the maximum safe ICMP payload is **1440 bytes** (MTU 1500 − IP header 20 − ICMP header 8 = 1472, minus 32 bytes for Freewire's own header and encryption tag).

---

## Freewire Payload Header

Every ICMP packet Freewire sends (request or reply) begins with a fixed 8-byte Freewire header inside the ICMP data field, before the encrypted payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┼───────────────────────────────────┤
│  Version (1)  │  Type (1)     │         Session Token (2)         │
├───────────────────────────────┴───────────────────────────────────┤
│                     Sequence Number (4)                           │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Size | Description |
|---|---|---|
| Version | 1 byte | Protocol version. Currently `0x01`. |
| Type | 1 byte | Packet type (see below). |
| Session Token | 2 bytes | Low 2 bytes of the 10-byte session token negotiated during handshake. Used to demultiplex sessions sharing the same ICMP identifier. |
| Sequence Number | 4 bytes | Monotonically increasing per-session sequence number. Used for pipelining, ordering, and loss detection. |

### Packet types

| Type | Value | Direction | Description |
|---|---|---|---|
| HANDSHAKE_HELLO | `0x01` | Client → Server | Step 1 of handshake |
| HANDSHAKE_ACK | `0x02` | Server → Client | Step 2 of handshake |
| HANDSHAKE_CONFIRM | `0x03` | Client → Server | Step 3 of handshake |
| DATA | `0x10` | Both | Encrypted tunnel payload |
| KEEPALIVE | `0x20` | Both | Liveness check |
| UPGRADE_PROBE | `0x30` | Client → Server | Test if TLS/443 is now reachable |
| TERMINATE | `0xFF` | Both | Session teardown |

The ICMP **identifier** field is set to the low 2 bytes of the session token for all packets after handshake completion. During handshake, it is set to `0xFEED` (fixed sentinel to identify Freewire handshake packets).

---

## Handshake Protocol

The handshake establishes a session key using Curve25519 Diffie-Hellman, identical in cryptographic construction to the DNS tunnel handshake. Three packets.

### Step 1 — Client Hello

Client sends an ICMP echo request to the server's IP.

**ICMP fields:**
- Type: 8 (echo request)
- Identifier: `0xFEED`
- Sequence: `0x0001`

**Freewire header:**
- Version: `0x01`
- Type: `0x01` (HANDSHAKE_HELLO)
- Session Token: `0x0000` (not yet assigned)
- Sequence: `0x00000000`

**Payload after header (40 bytes):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┼───────────────────────────────────┤
│  Version (1)  │  Flags (1)    │         Max Payload (2)           │
├───────────────────────────────┴───────────────────────────────────┤
│                                                                   │
│               Client Curve25519 Public Key (32 bytes)             │
│                                                                   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Value | Notes |
|---|---|---|
| Version | `0x01` | ICMP tunnel protocol version |
| Flags | `0x00` | Reserved; must be zero |
| Max Payload | `0x05A0` (1440) | Maximum ICMP payload the client can receive |
| Client Curve25519 Public Key | 32 bytes | Ephemeral keypair generated for this session |

---

### Step 2 — Server Acknowledgment

Server responds with an ICMP echo reply.

**ICMP fields:**
- Type: 0 (echo reply)
- Identifier: `0xFEED`
- Sequence: `0x0001` (mirrors the client's sequence)

**Freewire header:**
- Version: `0x01`
- Type: `0x02` (HANDSHAKE_ACK)
- Session Token: low 2 bytes of the assigned session token
- Sequence: `0x00000000`

**Payload after header (52 bytes):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
├───────────────┬───────────────┼───────────────────────────────────┤
│  Version (1)  │  Window (1)   │         Max Payload (2)           │
├───────────────────────────────────────────────────────────────────┤
│                  Full Session Token (10 bytes)                    │
│                  (split across two rows for display)              │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│               Server Curve25519 Public Key (32 bytes)             │
│                                                                   │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

| Field | Value | Notes |
|---|---|---|
| Version | `0x01` | |
| Window | `0x04` | Initial sliding window size (4 packets) |
| Max Payload | Server's maximum ICMP payload | |
| Session Token | 10 bytes | Full session token; client uses this for all subsequent packets |
| Server Curve25519 Public Key | 32 bytes | Ephemeral keypair generated for this session |

**Session key derivation** (identical to DNS tunnel):
```
shared_secret = X25519(client_private_key, server_public_key)
session_key   = HKDF-SHA256(
    ikm  = shared_secret,
    salt = session_token (10 bytes),
    info = "freewire-icmp-tunnel-v1",
    len  = 32 bytes
)
```

---

### Step 3 — Client Confirmation

Client sends an ICMP echo request to confirm it derived the correct session key.

**ICMP fields:**
- Type: 8 (echo request)
- Identifier: low 2 bytes of session token
- Sequence: `0x0002`

**Freewire header:**
- Type: `0x03` (HANDSHAKE_CONFIRM)
- Session Token: low 2 bytes of session token
- Sequence: `0x00000001` (first data-phase sequence number)

**Payload after header (16 bytes):**

```
HMAC-SHA256(session_key, session_token)[0:16]
```

First 16 bytes of HMAC-SHA256 over the session token, keyed with the derived session key. Server verifies this before accepting any data packets.

On verification failure, server discards the session and does not respond.

Handshake round trips: **2** (Hello → ACK → Confirm; Confirm has no reply).

---

## Data Packets

After handshake confirmation, all traffic flows as DATA packets.

### Client → Server (ICMP echo request)

- ICMP type: 8
- ICMP identifier: low 2 bytes of session token
- ICMP sequence: lower 16 bits of the Freewire sequence number (for network compatibility)
- Freewire header type: `0x10` (DATA)
- Freewire sequence: full 32-bit sequence number

**Encrypted payload:**

```
ChaCha20-Poly1305(
    key   = session_key,
    nonce = seq_num (4 bytes) || 0x00000000 (8 bytes),
    aad   = Freewire header (8 bytes),
    pt    = tunnel data
)
```

The Poly1305 authentication tag (16 bytes) is appended. Maximum plaintext per packet: **1416 bytes** (1440 − 8 header − 16 tag).

### Server → Client (ICMP echo reply)

Same structure, mirroring the client's ICMP sequence number. Freewire sequence is the server's own sequence number for the inbound data stream.

### Sequence number space

Client and server maintain **independent** sequence number spaces (one for each direction). Sequence numbers start at 1 and increment by 1 for each DATA packet. Sequence number 0 is reserved for the handshake. Sequence numbers wrap at 2³²−1 → 1.

---

## Sliding Window

The ICMP tunnel uses the same AIMD sliding window as the DNS tunnel, with smaller parameters to respect ICMP rate limits.

| Parameter | Value |
|---|---|
| Initial window size | 4 packets |
| Minimum window size | 1 packet |
| Maximum window size | 16 packets |
| Additive increase | +1 per RTT without loss |
| Multiplicative decrease | ×0.5 on loss detection |
| Retransmit timeout | 3× observed RTT, minimum 500ms |
| Packet loss detection | Missing ACK after retransmit timeout |

**Maximum send rate: 20 packets/second.** This is a hard cap independent of the window size, applied to prevent ICMP rate limiting at the network level. At maximum payload (1416 bytes), this yields a theoretical ceiling of ~227 Kbps. Typical throughput with real-world round-trip latency: 100–500 Kbps.

The server sends replies as fast as it receives requests (within its own window). The client's 20 packets/second cap is the binding constraint.

---

## Keepalive

- Client sends a KEEPALIVE packet every **15 seconds** of inactivity (no DATA packets sent).
- Server responds with a KEEPALIVE reply.
- If the client receives no reply within 3 KEEPALIVE periods (45 seconds), it considers the session dead and triggers reconnection.
- KEEPALIVE payload: 4 bytes of the current Unix timestamp (big-endian uint32), unencrypted.

Keepalive interval is 15 seconds (vs. 30 seconds for DNS tunnel) because ICMP state in intermediate network devices is shorter-lived.

---

## Upgrade Probe

Once the ICMP tunnel is established, the client sends a single UPGRADE_PROBE packet to test whether TLS/443 has become reachable (as described in `path-upgrade-manager-spec.md`).

- Sent 5 seconds after ICMP tunnel establishment.
- Sent once only. If TLS/443 is reachable, the path upgrade manager handles the transition.
- The UPGRADE_PROBE packet carries no payload beyond the Freewire header. It serves as a signal to the upgrade manager to initiate its own TLS/443 probe out-of-band.

---

## Session Termination

### Graceful

Either party sends a TERMINATE packet:

- Freewire header type: `0xFF`
- Payload: 10 zero bytes (sentinel)

The receiving party evicts the session immediately and sends a TERMINATE reply.

### Idle timeout

Server evicts a session with no activity (no DATA or KEEPALIVE) for **90 seconds**. No notification is sent.

### Client reconnect

On network change detection (iOS: `NWPathMonitor`; macOS: `SCNetworkReachability`), the client sends TERMINATE and starts a new handshake. The old session token is discarded.

---

## Server-Side Session Table

The server maintains a session table for active ICMP sessions. Each entry:

| Field | Type | Description |
|---|---|---|
| session_token | [10]byte | Full session token |
| session_key | [32]byte | Derived ChaCha20-Poly1305 key |
| client_ip | net.IP | Source IP of the last received packet (for reply routing) |
| last_seen | time.Time | Last packet received time |
| rx_seq | uint32 | Highest client sequence number received |
| tx_seq | uint32 | Server's next outbound sequence number |

Session tokens are 10 bytes of cryptographically random data, generated by the server during the handshake. The probability of collision for 10,000 simultaneous sessions is negligible.

---

## OS-Level Considerations

### Sending raw ICMP (server)

The server binary sends and receives raw ICMP packets using a raw socket:
```go
conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
```
Requires `CAP_NET_RAW` on Linux. The CloudFormation AMI runs the server binary as root; for production, use `setcap cap_net_raw=ep /usr/local/bin/freewire-server` instead.

### Receiving ICMP on client (macOS today; iOS deferred)

**Shipped macOS mechanism:** the client is the Go `freewire-tunnel` binary running
as a userspace helper (wireguard-go over a `utun` interface, NOT NetworkExtension).
The ICMP carrier lives in that binary (`tunnel/cmd/freewire-tunnel`, `icmp_client.go`)
and uses the ICMP-over-UDP approach below — it does not open raw ICMP sockets and
does not use a `NEPacketTunnelProvider`. (iOS, when resumed, WILL use
`NEPacketTunnelProvider`; that path is deferred — see `CLAUDE.md` tech stack.)

### ICMP-over-UDP (client)

The client uses an **ICMP-over-UDP** approach so it needs no raw-socket entitlement:

- Client sends UDP packets to the server's `icmp_udp_port` (default 4500, from `/v1/config`; IKEv2 port, often open on captive portals)
- The UDP payload is a Freewire ICMP tunnel packet (same format as above)
- The server receives UDP, extracts the Freewire ICMP payload, and responds in UDP

From the server's BGP/network perspective, this is UDP. From Freewire's application layer, the protocol is the ICMP tunnel protocol described in this document. The client negotiates this mode by setting Flag bit `0x01` in the HANDSHAKE_HELLO.

If UDP 4500 is also blocked, the ICMP path fails and the fallback chain reports CONN-2 (no path available).

---

## Error Handling

| Condition | Behavior |
|---|---|
| Handshake HMAC verification fails | Server silently discards; does not respond |
| DATA packet with unknown session token | Server silently discards |
| DATA packet with sequence number more than 64 behind window | Server discards (replay protection) |
| DATA decryption fails (Poly1305 tag mismatch) | Packet discarded; sequence number is still consumed to prevent retransmit loops |
| No reply to 3 consecutive KEEPALIVEs | Client treats as unexpected tunnel drop → triggers SESSION-1 (kill switch activates, automatic reconnect via fallback chain) |
| Server at capacity | Server sends TERMINATE with payload `0xCACA...` (10 bytes of `0xCA`) — client maps to CONN-3 |
