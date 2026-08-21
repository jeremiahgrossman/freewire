# Freewire VPN — Privacy Pass Implementation Specification

**Audience:** Server and client engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Depends on:** `data-model.md` §rate_limit_token, `client-server-api-spec.md` §POST /v1/tokens/issue

---

## Purpose

Privacy Pass prevents a single device from abusing Freewire's managed servers (e.g., opening thousands of peer slots) without allowing Freewire to track which device made which connection. A device proves it is rate-limit compliant by spending a cryptographic token — but the token cannot be linked back to the issuance event or the device's public key.

---

## Token Type: Public Verifiable Tokens (Type 1)

Freewire uses **Privacy Pass Public Verifiable Tokens** as defined in RFC 9578 (Token Type 0x0001).

This type uses **RSA Blind Signatures** (RSA-PSS with SHA-384, 2048-bit key). The issuer (Freewire server) signs blinded tokens without seeing the unblinded values. The client unblinds the signature locally. When the client presents the token for redemption, the server can verify the signature but cannot determine which issuance request produced it.

**Why Type 1 and not Type 2 (Private State Tokens / VOPRF)?**
- Type 1 is simpler to implement correctly — no elliptic curve VOPRF required
- Type 1 tokens are publicly verifiable: the issuer public key is all that's needed to verify a spent token, which allows the verification path to be stateless
- Type 2 provides stronger unlinkability guarantees but requires server-side state during issuance; for Freewire's use case (anonymous rate limiting with a single issuer) Type 1 is sufficient

---

## Cryptographic Parameters

| Parameter | Value |
|---|---|
| Token type | 0x0001 (Public Verifiable Token) |
| Signature scheme | RSASSA-PSS |
| Hash | SHA-384 |
| RSA key size | 2048 bits |
| Blinding scheme | RSA blind signature (per RFC 9474) |
| Token nonce size | 32 bytes (256 bits) |
| Token validity window | 30 days |
| Batch size per issuance request | 10 tokens (client default); max 20 |

---

## Issuance Flow

### 1. Client generates token nonces

For each token in the batch, the client generates a random 32-byte nonce:
```
nonce_i = SecureRandom(32 bytes)
```

The nonce is stored locally alongside the blinding factor (see step 3). It is never transmitted.

### 2. Client prepares the token request message

For each nonce, compute the token request input (per RFC 9578 §6.1):
```
token_input = 0x0001 || nonce_i
```

Where `0x0001` is the 2-byte token type identifier.

### 3. Client blinds the token

Using the issuer's RSA public key (`n`, `e`) and a fresh random blinding factor `r`:

```
blinded_msg_i = (H(token_input)^e * r^e) mod n
```

Where `H` is the hash-to-field function defined in RFC 9474. The blinding factor `r` is stored locally alongside `nonce_i`. It is never transmitted.

The `blinded_msg_i` is Base64url-encoded and sent to the server in `POST /v1/tokens/issue`.

### 4. Server signs the blinded token

The server uses its RSA private key to sign each blinded message:

```
blind_sig_i = blinded_msg_i^d mod n
```

The server cannot see `nonce_i` or recover it from `blinded_msg_i`. The server returns `blind_sig_i` values in the response.

### 5. Client unblinds the signature

```
sig_i = blind_sig_i * r^(-1) mod n
```

This yields a valid RSA-PSS signature over `H(token_input)` — i.e., a valid signature over `nonce_i` — without the server ever having seen `nonce_i`.

The client verifies:
```
RSA-PSS-Verify(issuer_public_key, H(token_input_i), sig_i) == valid
```

If verification fails for any token, that token is discarded. Remaining tokens are stored.

### 6. Token storage

Each token is stored as a tuple:
```
{
  token_type:  0x0001,
  nonce:       32 bytes,
  signature:   256 bytes (2048-bit RSA signature),
  issuer_key:  SHA-256 fingerprint of the issuer public key (32 bytes)
}
```

**Storage location:** Encrypted local file in the app's protected data container (`FileProtection.completeUntilFirstUserAuthentication`). Not in the Keychain — tokens are anonymous credentials, not secrets tied to device identity.

**File path (iOS):** `<app-container>/Library/Application Support/freewire_tokens.bin`  
**File path (macOS):** `~/Library/Application Support/Freewire/tokens.bin`

The file is a length-prefixed binary sequence of token tuples. On first launch the file does not exist; it is created after the first successful issuance.

---

## Redemption Flow

When the client calls `POST /v1/peers`, it presents one token in the `Authorization` header.

### Token serialization for the wire

Per RFC 9578 §6.3, the token is serialized as:

```
token = token_type (2 bytes) || nonce (32 bytes) || token_authenticator (Nkey bytes)
```

Where `token_authenticator` is the RSA-PSS signature (`sig_i`, 256 bytes for 2048-bit key).

Total token size: 2 + 32 + 256 = **290 bytes**, Base64url-encoded = **387 characters**.

This is placed in the Authorization header:
```
Authorization: PrivateToken token=<base64url(token)>
```

### Server verification

1. Parse the token: extract token type, nonce, authenticator.
2. Verify the RSA-PSS signature: `RSA-PSS-Verify(issuer_public_key, H(0x0001 || nonce), authenticator)`
3. Check the nonce has not been spent: look up `SHA-256(nonce)` in the `rate_limit_token` table.
4. If not spent: record `SHA-256(nonce)` in `rate_limit_token` with `spent_at = now()`. Proceed with peer registration.
5. If already spent: return `402` with error code `TOKEN_SPENT`.

The server stores only `SHA-256(nonce)` — not the nonce itself, not the signature, not any device identifier. This is the only record of the token's existence. It is retained for 30 days (the token validity window) then deleted.

### Key rotation

The issuer RSA keypair should be rotated every 90 days. When a new keypair is generated:
1. The new public key is returned in `POST /v1/tokens/issue` responses.
2. The old public key remains valid for verification for 30 days (the token validity window) after rotation.
3. Clients that cached the old key discover the mismatch when verifying unblinded tokens and automatically re-request issuance with the new key.

---

## Batch Management

### Initial batch
Requested on the client's first connection attempt. Batch size: 10 tokens.

### Background refresh
After each successful `POST /v1/peers`, the client decrements its local token count. When count drops below 3, a background task requests a new batch of 10 tokens. This runs silently — no user-visible state.

### Exhaustion handling
If the token count reaches 0 before a background refresh completes:
1. Attempt issuance synchronously as part of the connection flow (adds ~200ms).
2. If issuance fails (server unreachable, rate limited), attempt connection without a token.
3. If the server rejects the tokenless request with `402`, surface a soft warning and retry after 30 seconds.

### Rate limit on issuance
The server rate-limits issuance per source IP to prevent a single device from hoarding tokens:
- Maximum 20 tokens per issuance request
- Maximum 100 tokens per 24-hour window per IP address
- This limit is soft — it prevents bulk abuse, not legitimate use

---

## Self-Hosted Servers

Self-hosted servers do not implement Privacy Pass. The `/v1/tokens/issue` endpoint returns `501 Not Implemented`. The `POST /v1/peers` endpoint does not require an `Authorization` header.

Self-hosted server security relies on the user controlling which device public keys are registered via the server web dashboard. There is no anonymous rate limiting on self-hosted servers.

---

## Libraries

| Platform | Library |
|---|---|
| Go (server) | `github.com/cloudflare/circl` — provides RSA blind signatures compatible with RFC 9474 |
| Swift (client) | `Security.framework` for RSA operations; custom blinding layer per RFC 9474 |

Note: As of 2026, there is no stable first-party Swift implementation of RFC 9474 RSA blind signatures. The client must implement the blinding/unblinding operations using `SecKey` primitives. Reference the Cloudflare `pat-go` library for a Go reference implementation to verify against.
