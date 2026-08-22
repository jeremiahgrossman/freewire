# Third audit: adjudication of the unverified tail

The third audit ran 147 agents. Its verification stage died partway through on a
spend limit, so it returned 8 confirmed findings and left 209 unique candidates
with no verdict. Those 8 are fixed and recorded in `CLAUDE.md`. This file
accounts for the other 209.

Every candidate was checked against the tree at the time of writing rather than
against the tree the finders saw. That distinction does most of the work here:
the finders ran concurrently with the first two audits' fixes, so a large share
of the tail describes code that no longer exists.

Nothing below is "assumed fine". Each group states what was checked and what the
check showed.

---

## Closed by earlier fixes (≈120 candidates)

These describe defects that were real when reported and are no longer present.
Verified by reading the current code, not by assuming the fix landed.

| Reported defect | Why it is closed | Verified by |
|---|---|---|
| `spent.go` eviction is O(n²) under the mutex | Replaced by generational maps; rotation is a map drop | no `evictOldestLocked`; `rotateIfDueLocked` is O(1) |
| Client IPs reach logs via wrapped `net.OpError` | `netErrCause` strips addresses; every call site converted | `grep -c 'zap.Error(err)'` is 0 in all three transports |
| Replay window committed before AEAD verification (DNS and ICMP) | Split into `check` then `commit`; commit only after `Open` succeeds | `rx.check`/`rx.commit` call sites in both servers |
| Reconnect and path upgrade register without a token | All three paths funnel through one `registerPeer()` that takes a token | `TunnelManager.swift:257` |
| ICMP has no pending-session ceiling | 256 pending, 10s TTL, `evicted` flag | `maxPendingICMPSessions` |
| Issuer key fetched with no pinning | Trust-on-first-use `--issuer-pin` plus advertised-key-id check | verified live against the AWS server |
| Token issuance unmetered | Proof of work plus a global budget | `proofofwork.go`, `ratelimit.go` |
| Duplicate public key locks a device out permanently | Re-registration displaces the stale entry | `reserveSlot` |
| DNS `evictLoop` races `handleClientConfirm` | Decision and flag set together under `sess.mu` | `dns_server.go` evict loop |
| Invented user-facing copy for token rejection | Specified as TRUST-3 and TRUST-4 | `error-states-spec.md` |
| Token file plaintext / no-op file protection | AES-GCM under a Keychain-held file key | `TokenStore.save` |
| ATS forces `NSAllowsArbitraryLoads` | `PinnedHTTPClient` replaced URLSession | no ATS key anywhere in `macos/` |

The duplicate rate is high because 12 finder agents covered overlapping ground:
the O(n²) eviction alone was reported 9 times under 9 different ids.

---

## Confirmed and fixed in this pass

| Id(s) | Severity | Defect | Fix |
|---|---|---|---|
| FW-S02, SEC-008 | critical | `iptables -A FORWARD -s $TUNNEL_CIDR -j ACCEPT` let anything in the tunnel reach `169.254.169.254`, which hands out the instance role's IAM credentials to any unauthenticated GET, and the whole VPC besides | link-local, RFC 1918 and loopback rejected ahead of the accept, with the tunnel's own subnet re-allowed above them |
| CRYPTO-008, CRYPTO-04, FW-S10 | high | Certificate verification disabled wholesale whenever a key was pinned. The WireGuard pin is checked after the fact and only on the config response, so `POST /v1/peers` carried a Privacy Pass token an interceptor could read and spend | certificate public key pinned trust-on-first-use in `CertificatePin.swift` |
| FW-S16 | high | A user pin applied to every host, so pinning a self-hosted server also switched off CA validation for the managed one | pin scoped to `pinnedServerHost` |
| FW-S19, SEC-014, CRYPTO-016/017 | medium | `newToken` discarded the RNG error, and `rand.Read` leaves the buffer zeroed on failure — every affected caller would get the same all-zero peer token, guessable and mutually displacing | returns an error; registration fails instead |
| PP-07, FW-A15, REL-018, FW-L01 | medium | The token was spent before capacity was checked, so a 503 destroyed it and the obvious retry cost another | `SpentStore.Refund`, called on every post-spend failure |
| PP-03, SEC-011, FW-C-020 | high | The spent store was memory-only, so a restart made every outstanding token replayable | persisted to `spent-tokens`; verified live across a restart |
| PP-11, PP-12 | low | `device_name` and `client_version` travelled with the redemption | both removed from the schema and the client |
| FW-S12, FW-C-015 | medium | Header values were concatenated with no CR/LF check, and tokens were trimmed of spaces but not newlines — a token from a subprocess's stdout could split the request | header values validated; tokens trimmed of newlines and checked against the base64url alphabet |
| REL-10, REL-010, FW-M05, FW-C-014 | medium | The response body accumulated without a ceiling and was recopied per chunk | 256 KB cap, single buffer |
| REL-05 | high | The issuance subprocess had no timeout, so a hung helper held `connect()` open indefinitely | 8-second ceiling inside the 10-second connect budget |
| PP-04 | medium | Strict FIFO spend order preserved issuance order, telling the server which redemptions came from one batch | batch shuffled before storing |
| FW-A14, FW-A19, REL-016, REL-19, CRYPTO-15 | low/medium | `acceptAnyCertificate` was frozen at `ServerAPI` construction, so a pin added later needed a relaunch | evaluated per connection |
| FW-S08 | high | The root-privileged server resolved `ip`, `ifconfig` and `route` through `PATH`, so the inherited environment decided which binary got root | `firstExisting` over absolute paths, matching what the tunnel client already did |
| FW-S17 | medium | The SSH firewall rule came from an unvalidated third-party HTTP response | validated as a dotted quad, with an override and a hard stop |
| REL-22 | low | `log.Fatal` skipped every deferred cleanup, including the spent-store flush | exit code plus `return`; `os.Exit` deferred first so it runs last |
| CRYPTO-13, CRYPTO-14, FW-L02 | low | Scheme name `PrivateToken` contradicted the docs' `PrivacyPass`, and quote trimming used a cutset that would strip interior quotes | docs corrected to RFC 9577's `PrivateToken` (the code was right, the spec was wrong); at most one surrounding quote pair stripped |

---

## Still open, with reasons

Recorded rather than fixed. None is a privacy or key-handling defect.

**Needs a decision from the owner, not an implementation:**

- **PP-04 (high), CRYPTO-06 — tokens have no expiry, but spent records are
  dropped after 30 days.** A token whose record has aged out is replayable
  forever. The fix has several valid shapes (an expiry field in the token, an
  issuer key epoch, RFC 9577's `token_key_id` enabling the dual-key rotation
  the spec already describes) and they are not interchangeable — each changes
  the wire format differently. `CLAUDE.md` says not to guess on cryptographic
  key handling, so this is surfaced rather than chosen. Related: **CRYPTO-09**
  (the wire format omits `challenge_digest` and `token_key_id`, so tokens bind
  to no key or origin) is the same decision.
- **CRYPTO-11 (medium) — DNS and ICMP handshakes are unauthenticated anonymous
  DH,** so the on-path adversary those transports exist to defeat can sit in the
  middle of them. The tunnel inside is still WireGuard, which authenticates the
  server by its pinned key, so this costs confidentiality of the transport
  framing rather than of the traffic. Fixing it properly means binding the
  handshake to the server's known key — a protocol change to both ends.

**Genuine, deferred as lower value than the work:**

- REL-007, FW-S07, SEC-013, REL-12, REL-015, CRYPTO-010, FW-L03: unauthenticated
  connections cost the server memory, sockets and goroutines with no ceiling and
  no post-handshake deadline. Real resource exhaustion, reachable by anyone.
  This is the largest remaining cluster and the one to do next.
- FW-M02, FW-M03, REL-019: data races on `Peer.TunnelIP`, `sess.localConn`, and
  a non-atomic check-then-increment on the DNS pending counter. Narrow windows;
  `go test -race` does not currently reach them.
- CRYPTO-013: sequence counters wrap with no rekey, which would reuse a
  ChaCha20-Poly1305 nonce. Requires 2³² packets in one session — unreachable in
  practice, catastrophic if reached. Worth a refusal-to-send at the boundary.
- CRYPTO-007, CRYPTO-08: neither tunnel client applies a replay window to the
  server-to-client direction.
- The kill-switch cluster (SEC-004, FW-C-008, FW-S09, FW-H07, CRYPTO-011,
  REL-18, SEC-005, SEC-009, FW-M07, FW-C-009): the helper replaces the whole pf
  ruleset instead of loading its anchor, `release()` runs `pfctl -F all`,
  `isEngaged()` infers state from a file, and `sanitize()` strips hostile
  characters rather than rejecting them. All real. All blocked behind the same
  thing: the helper cannot be installed without a Developer ID, so none of it
  can be tested. Fixing untestable code here is how the pf ruleset broke the
  wifi earlier in this project.
- The UX and lifecycle cluster (FW-A*, REL-0*): CONN-1 is a terminal dead end,
  Cancel is inert on automatic retries, path upgrade shows "Protected" while it
  rebuilds the tunnel, several main-actor blocking calls, the CONNECT upgrade
  probe uses a hardcoded hostname, the fallback chain's worst case is ~32s
  against an 11s budget. Roughly 60 candidates. These are correctness bugs in
  the client's state machine and deserve their own pass rather than being
  folded into a security fix.
- FW-A10: the "What Freewire sees" sheet claims "No connection logs" while the
  server writes a line per connection. The line contains a redacted session
  token and a tunnel address, not a client IP, so the privacy guarantee holds —
  but the copy overstates it and should be reworded.

The raw list is in `.audit-tail.txt`, one line per candidate.
