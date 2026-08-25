# Desync carrier (Geneva/zapret-class) — scoping

**Status:** scoping, NOT recommended to build yet. **Date:** 2026-08-25.
**Trigger:** the 2026-08-25 café RST-rejected TCP/443, which read as "possibly
desyncable." On closer analysis it is not — and that finding is the point of this
doc.

## What desync is

Client-side packet manipulation that poisons a **stateful inline middlebox's**
view of a TCP flow so the flow survives, while the real server still sees a clean
stream. The primitives (Geneva's four: `duplicate`, `drop`, `tamper`, `fragment`;
zapret/GoodbyeDPI implement the same class):

- **Segment the ClientHello** so the SNI never appears contiguously in one packet
  a signature engine can match.
- **Inject decoy packets the middlebox accepts but the server rejects** — via a
  low IP TTL (they expire in transit, reaching the middlebox but not the server),
  a bad TCP checksum, or a wrong sequence number. These seed the middlebox's
  state with garbage.
- **TCB teardown** — inject a RST the censor's TCP state machine accepts (so it
  stops tracking the flow) but the server ignores.
- **Reordering** — deliver segments out of order to defeat naive reassemblers.

## The precondition that decides everything

**Desync only helps a middlebox that lets the TCP handshake COMPLETE and then
resets on CONTENT (the SNI).** All the tricks above operate on the data stream
*after* the connection is open. If there is no open connection, there is nothing
to manipulate.

The probe battery now distinguishes the two cases (see `classifyBlock`):

| Probe tag | What it means | Desync? |
|---|---|---|
| `[reset]` | TCP handshake completed, connection reset MID-STREAM (after the ClientHello) — content/SNI gating | **Viable** — this is the case desync targets |
| `[SYN-RST]` | the SYN itself was refused ("connection refused", a dial failure) — destination gating at L4 | **Futile** — no handshake exists to manipulate |
| `[timeout]` | silently dropped — hard L3 ACL | Futile |

## Why it does NOT help our café (2026-08-25)

That café returned **`connection refused` on the dial** — a **`[SYN-RST]`**. It
gates by **destination at L4**: our server's IP (and our CloudFront edge) get a
RST in response to the SYN, before any TLS or SNI is ever sent. There is no
handshake, so no ClientHello to split and no stream state to poison. **Desync
cannot touch this café.** The ways through a destination-SYN-RST café are the
ones we already have or have scoped: a *permitted destination* (CDN whose edge is
allow-listed — this café's was not; a different CDN/range might be), a *leaked
family* (IPv6 — this café had none), or **DNS**, which works here.

The earlier "RST → possibly desyncable" hint was too coarse; it is now split so a
destination SYN-RST is never mislabeled as desyncable.

## When it WOULD be worth building

A café/portal that shows **`[reset]`** in the battery — TCP connects, then the
session is reset once the SNI is visible. That is the SNI-filtering, GFW-style
middlebox desync is built for. **We have not encountered one.** Most captive
portals gate by destination (SYN-RST or drop), not by SNI content, because they
are allow-list boxes, not DPI censors. So the expected value of building desync
for the café population is low until the probe actually reports a `[reset]`.

## If we did build it — the macOS reality (the hard part)

This is why it is a large project, not a carrier variant:

- **ClientHello segmentation alone** (small, deliberately-split socket writes) is
  doable in userspace, no root — but it is the *weakest* desync technique and
  only defeats a middlebox that classifies on a single un-reassembled packet.
- **The decoy-packet techniques** (low-TTL / bad-checksum / RST injection) need
  **raw packet injection**, which on macOS means either a `NEPacketTunnelProvider`/
  `NEFilterDataProvider` **system extension** (Developer ID + entitlement — the
  same approval wall the pf kill-switch hit) or a BPF-write / raw-socket path
  that needs root and fights the OS. There is no `NFQUEUE` equivalent to hook
  cleanly. This is the "untestable pf-class code" the project has been burned by.
- It must run **on the physical path to the server**, coexisting with the tunnel
  routing — another routing-interaction surface to get right.

## Recommendation

**Do not build the desync carrier now.** It cannot help the café we found
(destination SYN-RST), the café population is mostly destination-gated (so the
expected payoff is low), and the macOS implementation is a system-extension-scale
effort gated behind the same Developer ID wall as the kill switch. The refined
probe now tells us, per café, whether desync could *ever* help — build it only if
and when a real café reports `[reset]` (post-handshake content reset). Until
then, DNS is the answer for hard captive portals, and the CDN/UDP-443/v6 carriers
cover the destination- and port-gated cases.
