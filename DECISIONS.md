# Decisions taken under uncertainty

Choices that traded one stated goal against another, recorded so they can be
revisited when the facts that forced them change. Each entry states what was
decided, what it costs, what was rejected, and what would justify reopening it.

This file is for decisions that are defensible but not obviously right. A
decision with no real alternative does not belong here.

---

## DNS-ON-SLOW-TRANSPORTS

**Decided 2026-08-22. Revisit if the DNS or ICMP transport gets materially
faster, or if the product's threat model puts captive-portal operators above
usability.**

### What was decided

Encrypted DNS (DoH) is used on the WireGuard, TLS/443 and HTTP CONNECT
transports. On the DNS and ICMP transports the takeover is skipped: the system
resolver is left alone and lookups go to the network's own resolver in
cleartext. The user is told, via DNS-1 in `error-states-spec.md`.

### What it costs

A stated privacy guarantee, on exactly the networks the product exists for. The
preferences sheet says "What you browse — We see only encrypted data". On a
captive portal that has blocked everything except DNS, the operator can see
every domain visited. They cannot see the traffic itself, which stays inside
WireGuard.

This is a partial retreat from a hole that was closed the same day: until
2026-08-21 the client did not take over DNS at all, so lookups always went to
the local network. DoH closed that. This decision reopens it for the two slowest
transports only.

### Why

DoH costs a full HTTPS round trip per uncached lookup. Measured on the DNS
transport against the live server, that is 5–10 seconds. Because the takeover is
system-wide, every application on the machine pays it — not just a browser.

That is not a slow VPN, it is an unusable computer. It was misdiagnosed twice as
a crash before the cause was understood, and it took the developer's machine
down three times, including the agent session driving the tests.

The user's realistic alternative on a last-resort transport is no connectivity
at all. A machine that cannot resolve anything does not protect them either.

### Rejected

- **DoH everywhere.** Correct on privacy, unusable in practice. Rejected on
  measurement, not principle.
- **DoH with a longer timeout.** Does not help: the cost is per lookup and the
  machine stalls regardless of whether the lookup eventually succeeds.
- **DoH with aggressive caching.** A TTL-respecting cache is implemented and
  helps repeat lookups, but cold lookups still pay full cost, and a browser
  opening one page issues many cold lookups.
- **Plain DNS to the VPN server, which then resolves over DoH.** Cheap — one
  round trip instead of a TLS session — and it defeats the point: the server is
  the party this was built to hide DNS from.

### What would reopen it

- The DNS tunnel's latency improving enough that a cold lookup lands within a
  second or so. The sliding window fix on 2026-08-22 took window drops from 2450
  to 0; the remaining cost is protocol round trips, so this would need a design
  change rather than tuning.
- A decision that captive-portal operators are a serious enough adversary to
  accept the usability cost — plausible for a specific deployment, e.g. a
  journalist on a hostile network, and a candidate for a user-visible setting
  rather than a global default.
- Someone measuring what fraction of sessions actually land on DNS or ICMP. If
  it is negligible, the usability argument weakens and DoH everywhere becomes
  cheap to prefer.

### Evidence

- 5–10s per cold DoH lookup on the DNS transport, measured against the live
  server on a session verified to be carrying traffic.
- Zero plaintext DNS on the server's uplink with DoH active on TLS/443,
  confirmed by packet capture; every domain legible without it.

---

## WHAT-THE-SERVER-CAN-SEE

**Decided 2026-08-22. Revisit if Freewire ever runs servers for people other
than their operator, or if ECH coverage becomes broad enough to change the
claim.**

### What was decided

The privacy copy now says Freewire's servers can see which sites you connect to
and do not record it, instead of claiming they see only encrypted data.

### Why

The old claim was false, in the app and in the privacy policy. Packet capture on
the server's own uplink, while connected over TLS/443, showed `wikipedia.org`,
`github.com` and `duckduckgo.com` in plain text in the TLS ClientHello.

Two separate causes, worth keeping distinct because only one is fixable:

- **Destination IP is structurally necessary.** A VPN server forwards packets to
  their destination and cannot do that without knowing the destination. No
  single-hop VPN can avoid it, and any that claims otherwise is wrong.
- **The hostname is incidental.** SNI travels in the clear inside the TLS
  handshake, which the server merely relays. It never needs to read it. ECH
  removes it with no effect on function.

The distinction matters because of shared hosting. An IP behind a CDN says only
"something at Cloudflare"; the SNI says which site. For much of the web the
hostname is far more revealing than the address, which is what makes ECH worth
building even though addresses stay visible.

### What this does not change

Nothing is recorded. Connections are counted into hourly totals and never logged
individually, with tests that fail if a per-connection log statement returns. The
claim that survived scrutiny is "we do not keep it", not "we cannot see it".

### Scope note

In the current single-user scope the server is the user's own machine on their
own AWS account, so "the server can see your destinations" means the user can see
their own traffic. The copy describes a hosted Freewire that other people trust,
which does not exist yet. It was still wrong to ship, because it is the one
screen a user opens specifically to check this.

### What would reopen it

- **ECH shipping with real coverage.** It hides the hostname for sites that
  support it, which is a meaningful share but not most sites. It would justify
  softening the claim, never removing it.
- **A multi-hop architecture.** Genuinely not knowing where a user goes requires
  two independent operators: one that knows who you are and not where you went,
  another that knows where you went and not who you are. This is how iCloud
  Private Relay and Tor are built. It is a different product with a different
  cost structure, not a feature to add — logged here because the question will
  come up again the first time someone asks why the copy is not stronger.
