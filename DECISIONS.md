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
- **The hostname is incidental, but Freewire cannot remove it.** SNI travels in
  the clear inside the TLS handshake, which the server merely relays. The server
  never needs to read it — but that handshake is end to end between the user's
  browser and the site, so Freewire cannot rewrite or encrypt it without
  breaking the connection. ECH is deployed by the browser and the destination,
  not by a VPN in the middle. Freewire benefits passively when both ends support
  it, and can do nothing to bring that about.

  This corrects an earlier claim in this file that ECH would close the gap. It
  will not. It was written from the assumption that ECH was ours to deploy.

The distinction still matters because of shared hosting. An IP behind a CDN says
only "something at Cloudflare"; the SNI says which site. For much of the web the
hostname is far more revealing than the address. But the party who can act on
that is the browser vendor and the site, not us.

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

- **Browsers and sites deploying ECH broadly.** Where both ends support it the
  hostname stops being visible to anything in the middle, Freewire included.
  That would justify softening the claim, never removing it, and it happens
  without us building anything.
- **A multi-hop architecture.** Genuinely not knowing where a user goes requires
  two independent operators: one that knows who you are and not where you went,
  another that knows where you went and not who you are. This is how iCloud
  Private Relay and Tor are built. It is a different product with a different
  cost structure, not a feature to add — logged here because the question will
  come up again the first time someone asks why the copy is not stronger.

---

## TOKEN-EXPIRY

**Decided 2026-08-22. Revisit if the spent store's retention changes, or if
issuer key rotation is implemented for another reason.**

### What was decided

Tokens carry a coarse expiry, in whole UTC days, inside the signed message. The
wire format is now `type(2) || expiry(4) || nonce(32) || signature(256)`.

### The problem

A token was valid forever while its spent record was dropped after thirty days.
Anyone holding one past that window could replay it indefinitely: the store had
forgotten it, and nothing in the token said it was stale.

### Why a field rather than key rotation

An issuer key epoch was the alternative, and it would also have closed CRYPTO-09
by binding tokens to a key. It was rejected as more machinery than the problem
needs: key rotation has to be scheduled, coordinated across a rotation window,
and carried in the token anyway as a key id. The field does the job in four
bytes. CRYPTO-09 stays open and is recorded as such.

### The part that is not obvious

The issuer signs blindly and never sees the expiry, so it cannot set it. The
client does. That is safe only because the value is judged at redemption: a
token dated further ahead than the issuer would ever have allowed is refused
there, which makes over-dating pointless. If that check were dropped the field
would be decorative, so it has a test of its own.

The expiry is inside the signed message for the same reason — outside it, anyone
holding a token could simply re-date it.

### Why whole days

A finer timestamp would be a fingerprint. Tokens carrying distinct expiries
partition into cohorts, and a cohort small enough to identify a device undoes
the blinding that produced the token. At day granularity every token issued
anywhere in the world on a given day carries the same value. There is a test
asserting the value does not vary within a UTC day.

Validity is 30 days, which must stay within the spent store's retention, or a
token could again outlive the record that stops it being replayed. A test
asserts that relationship rather than leaving it to a comment.

---

## DNS-ICMP-HANDSHAKE-AUTH

**Deferred 2026-08-22 until Freewire serves people other than its operator.**

### What was decided

The DNS and ICMP handshakes keep their unauthenticated ephemeral DH. The
limitation is recorded rather than fixed.

### What is exposed

Those two transports exist to get through an on-path adversary, and that same
adversary can sit in the middle of their handshake. Neither client checks the
server's ephemeral key against the pinned WireGuard key — there are zero
references to it in either file.

An active attacker gains the transport framing: session tokens, sequence
numbers, the ability to inject fragments and to disrupt. They do not gain
traffic. The WireGuard session inside is authenticated by the pinned server key,
so contents stay confidential and unforgeable, and disruption is something a
portal can achieve anyway by blocking.

### Why defer

On the current deployment the on-path adversary is a captive portal the operator
has chosen to connect to, and the operator is the only user. The calculus
changes entirely when strangers trust the service, which is the trigger for
picking this up.

### The fix when it is picked up

Mix the server's known WireGuard public key into the handshake — a static
ephemeral DH alongside the ephemeral one, so only the holder of the server's
private key can derive the session key. The client already has the public half
pinned and the server already has the private half in its config, so this needs
no new key material and no signatures. It is a protocol change to both ends of
both transports, which is the whole reason it is not a small job.

---

## NETWORK-INTELLIGENCE

**Deliberately not built, 2026-08-22. The spec stands; the implementation is
declined for now. Revisit if first-connect latency on hostile networks becomes a
real complaint, or if an anonymisation design lands that does not require
storing a location signal.**

### What it would do

`PRD.md` §6.9. On a wifi network the client reports which transport worked and
which failed, keyed by SHA-256 of the BSSID. Once five independent devices have
reported the same network, the server tells a sixth which path to try first. The
hint reorders the fallback chain and never removes paths, so a stale hint costs
one wasted attempt rather than a failure.

### Why it is not being built

**The payoff shrank.** The value was avoiding a walk down the fallback chain on
a network known to block most of it. Reconnect now remembers the last working
transport, so a device's own history already goes straight to the right path.
The hint only helps on the *first* connection to a network never used before;
after that, local memory is better than the crowd's and needs no reporting at
all.

**The cost is a location signal.** A BSSID hash is not anonymous in the way the
word "hash" suggests. The input space is small and heavily enumerated: public
wardriving databases map millions of BSSIDs to street addresses, so anyone
holding one can hash the lot and reverse these by lookup. `data-model.md`
acknowledges reversal "requires deliberate attack effort", which is a
preimage-resistance argument applied to a low-entropy input, where it does not
hold. The k-anonymity gate governs which hints are *served*; reports below the
threshold are still stored.

So the server would learn which physical places its users visit, in exchange for
saving a few seconds on a first connection.

**It cuts against everything else decided this week.** Per-connection logging was
replaced with counters, DNS was moved to DoH, and the privacy copy was corrected
where it claimed more than was true. Adding the one feature that transmits
something about the user's surroundings would be the only movement in the
opposite direction.

### What would make it acceptable

- Salted, per-epoch hashes with server-side aggregation that cannot retain
  sub-threshold reports, so a single device's report is unusable even to the
  operator holding the database.
- Or private set intersection, so the server answers "is this network known
  hostile" without learning which network was asked about.

Both are materially more work than the feature saves, which is the actual
argument here — not that crowdsourcing is wrong, but that this version buys
little and costs something the rest of the product is designed not to hold.

### Status

`PRD.md` §6.9, `client-server-api-spec.md` §Network Intelligence API and
`data-model.md` §network_path_hint remain as written. Nothing is implemented on
either side. The preferences toggle described in §6.9 is not present and should
not be added while this stands, since a toggle for a feature that does nothing
is its own kind of false claim.

---

## DNS-CARRIER-BACKPRESSURE (Stage 2)

**Deferred 2026-08-23. FIELD-TESTED 2026-08-24: the deferral holds, now for a
stronger reason — Stage 2 does not fix the real café, so it is not worth merging.**

### Field result (2026-08-24, second café — the parked branch tested on-site)

The worst-case pattern is NOT rare: 2 of 2 cafés tested block WireGuard-direct
(UDP 51820) and TLS/443 to the server and leave only DNS. So "rare and
field-unconfirmed" (the original defer reason) is wrong. BUT the parked Stage-2
branch (`claude/vibrant-bassi-823b06`, delegating `conn.Bind`) was built and run
at the café against its cached peer, and its backpressure did NOT make the café
usable:

- Backpressure engaged for real (`backpressure 7→25/s`, `queue 256/256`, no
  tail-drop) — the mechanism is sound.
- On server-direct (forced, apples-to-apples with main) it reached ~15–30 KB/s
  downstream — comparable to main — then the egress self-check failed to sustain
  and the tunnel tore down: **HTTPS BLOCKED, 0/10**, same user-visible outcome as
  main. The branch's "2/2 TUNNELLED through a throttle" claim did not reproduce
  in the field (matching the desk result, 0/3).

So the bottleneck is the café's DNS-to-server rate itself, which no client-side
change (pacing or backpressure) can raise. Stage 2 changes the failure mechanism
(block vs tail-drop) but not the outcome. **Do not merge the branch.** An open
sub-question worth a look before any further DNS-throughput work: the app's egress
self-check tears a slow-but-moving tunnel down before it can be judged — whether
relaxing it for slow transports would let ~15 KB/s carry light traffic is untested
(but 15 KB/s shared across the machine is marginal for real use regardless).

### Original decision

### What was decided

The DNS send path gets adaptive rate pacing (Stage 1, shipped) but NOT true
backpressure (Stage 2). When a portal throttles the DNS carrier below what the
machine offers, the bounded queue still tail-drops the excess and can starve the
active flow. That gap is recorded rather than closed.

### What was shipped instead

- **Stage 1 — adaptive carrier-rate pacing** (`dns_ratelimit.go`): per-direction
  AIMD limiters discover the path's sustainable rate at ~0 loss and pace to it,
  so the client no longer blasts a throttled portal into loss. Verified against a
  desk repro of the café throttle (`FREEWIRE_DNS_CARRIER_CAP`): the limiter
  converges to the cap at 0% carrier loss.
- **Fastest-transport selection** (`transport.go`): the chain now picks the
  fastest carrier a network allows (WireGuard-direct first), so a throttled DNS
  tunnel is only ever reached when every faster carrier is also blocked.

### What it costs

On a portal that blocks HTTP CONNECT, TLS/443, WireGuard-direct AND ICMP, and
also throttles DNS to the server, the tunnel comes up but the active connection
is starved by queue overflow — effectively unusable, as seen at the café. Stage 2
would make that case a slow-but-usable link.

### Why defer

The payoff is narrow and the risk is high and asymmetric:

- **Narrow:** fastest-transport selection already routes around throttling wherever
  a faster carrier exists. The unfixed case is the intersection "throttles DNS AND
  blocks every faster carrier", seen at exactly one café so far — frequency in the
  field is unknown.
- **Marginal even when it hits:** perfect backpressure turns that rare portal from
  unusable into a barely-usable ~72 Kbps.
- **High risk:** WireGuard uses one shared `conn.Bind` (the default UDP bind),
  created once before the carrier is chosen. Real backpressure means a custom Bind
  that can block WG's `Send`; a clean version rewrites the send/receive path for
  ALL transports, including the proven-working fast ones. Core changes of this
  shape are what broke wifi earlier in this project.

Trading a proven fast path against a marginal, rare, field-unconfirmed fallback
improvement is the wrong risk/reward until the field says otherwise.

### The fix when it is picked up

Give ONLY the DNS transport its own WireGuard device with a custom `conn.Bind`
whose `Send` blocks when the adaptive limiter is saturated — so WireGuard stops
reading the tun, the tun buffer fills, and the apps' own TCP paces itself to the
carrier instead of the queue tail-dropping. Keep the fast transports on the
existing shared device + default bind, untouched, so they cannot regress. Do NOT
do the full single-bind-for-all-transports refactor. The desk repro
(`FREEWIRE_DNS_CARRIER_CAP`, `testing/routed-test.sh`) already reproduces the
throttle, so the work is verifiable without a field trip.

### What would reopen it

Field evidence that portals which throttle DNS while blocking every faster
carrier are common enough to matter — i.e., repeated real-world sessions where
fastest-transport selection lands on DNS and the portal throttles it.
