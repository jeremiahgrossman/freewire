# How Freewire tunnels traffic over DNS

This explains the actual mechanism — not the wire-format reference (that's
`dns-tunnel-protocol-spec.md`), but *why* it works at all.

---

## The core exploit: DNS delegation, not evasion

Freewire doesn't trick DNS or exploit a bug in it. It's a completely
legitimate DNS authority whose answers happen to carry someone else's traffic.

1. Freewire registered `pinghop.net` and pointed its **NS records** — the
   records that tell the internet "whoever asks about this domain, go ask
   *this* server" — at its own EC2 instance. This is exactly what every domain
   owner does; there is nothing unusual about it.
2. A captive portal cannot block DNS entirely without breaking itself: it
   needs DNS to resolve its own payment page's domain, validate its own TLS
   certificate, and let a browser look up whatever it's redirecting to. So it
   forwards DNS queries to a resolver — its own, or a public one.
3. When a device queries `<something>.t.pinghop.net`, that resolver doesn't
   know the answer, so it does what every resolver does for every domain on
   earth: it walks the delegation chain (root → `.net` → `pinghop.net`'s
   nameservers) until it reaches whoever is authoritative for that zone.
4. Because Freewire's NS records point at Freewire's own server, **that chain
   always terminates there** — the same structural guarantee that makes
   resolving `google.com` always eventually ask Google's own nameservers.
   Freewire isn't intercepting anything; it's the legitimate authority for one
   small piece of DNS's global namespace.
5. The second half: DNS does not care what characters are in a hostname
   label, or what bytes are in a TXT record's value. Those are opaque strings
   to the protocol and to every resolver that forwards them. So the "hostname
   being looked up" can be ciphertext instead of a real name, and the
   "answer" can be ciphertext instead of a real address, and nothing in DNS
   itself objects.

Put together: the portal permits DNS because it has no choice → any resolver
forwarding the query is *required by how DNS works* to eventually reach
Freewire's server → and because DNS treats names and records as opaque data,
Freewire can put an encrypted WireGuard packet there instead.

---

## Anatomy of one query (the `dns` carrier)

A single DNS query name, dot-joined, carries one fragment of an encrypted
WireGuard packet:

```
h    .  1  .  <base32-encoded ciphertext>         . t.pinghop.net
step    seq    the actual payload — arbitrary       our delegated zone
marker  no.    binary data, base32-encoded so it's   (any resolver ends
                valid as DNS label characters         up asking us for it)
```

The handshake that establishes a session follows the same pattern before any
data flows:

1. **ClientHello** — query `h.1.<base32(client public key)>.<zone>`, type TXT
2. **ServerHello** — the TXT answer is `<base32(server public key)>.<base32(session token)>`
3. **ClientConfirm** — query `h.3.<base32(MAC)>.<base32(token)>.<zone>`, type TXT

After that, ordinary data queries carry ciphertext fragments the same way.

---

## Outbound: fragmenting across a sliding window

A WireGuard packet is usually too large for one query's payload. Rather than
sending fragments one at a time and paying a full DNS round trip for each,
the client keeps **up to 24 fragment queries in flight simultaneously** — a
sliding window that hides DNS's latency instead of serializing through it.
Freewire's server reassembles the fragments back into the original packet.

---

## Inbound: polling, because DNS has no server-push

This is the half that isn't obvious from the query anatomy alone. DNS is
strictly request-and-reply — a server can never initiate a message to a
client. So receiving data requires a different trick: the client
continuously **polls**, sending queries whose only purpose is "do you have
anything queued for me?"

The complication: if every poll query looked identical, a caching resolver
sitting in the middle — exactly the kind of resolver a captive portal runs —
would answer most of them from its own cache instead of forwarding to
Freewire's real server, collapsing many concurrent polls down to the
throughput of one. So **each poll carries a random nonce** the server ignores
but which makes every poll a distinct, uncacheable query, forcing all of them
through to the real answer. Freewire runs **up to 8 concurrent pollers**, and
packs *every* packet it's holding for that client into whichever single poll
replies first — so one round trip can carry many packets' worth of data.

The TXT answer format for a data poll: `<base32(sequence number)>.<base32(ciphertext)>`.

---

## Why this specific design, not something simpler

- **Base32, not base64:** DNS labels are case-insensitive and restricted in
  character set; base32 survives that. Base64 would get silently mangled by
  some resolvers.
- **EDNS0:** negotiates a larger response size (up to ~4096 bytes) so each
  poll's reply can carry more payload per round trip — the original 512-byte
  DNS limit would make this carrier far slower.
- **The nonce on polls specifically (not on data-send queries):** a data-send
  query's payload is already unique per fragment, so it's naturally
  uncacheable. A poll query, by contrast, has *nothing* unique about it unless
  one is added on purpose — hence the nonce exists only there.

---

## The contrast: `dns_tcp` doesn't do any of this

Everything above describes the original `dns` carrier (UDP-based query/answer
encoding). Freewire's newer `dns_tcp` carrier — the one that actually won at
a real destination-gated café, 2026-08-30 — works completely differently and
much more simply:

- It opens a **TCP connection to port 53** and speaks the exact framing real
  DNS-over-TCP uses (RFC 7766: a 2-byte length prefix, then the message) —
  except the "message" is a raw WireGuard packet, not a DNS packet at all.
- No query-name encoding, no base32 inflation, no fragmentation across
  separate queries, no polling for inbound data — TCP is already
  bidirectional and already has flow control, so none of the machinery above
  is needed.
- It borrows port 53 (which portals must often leave open, same reasoning as
  the `dns` carrier) and DNS-over-TCP's wire framing convention, but not
  DNS's actual message format or its request/reply constraint.

That's *why* `dns_tcp` measured roughly 56x faster than `dns` at the desk,
and why it held a full tunnel in the field where `dns` collapsed under load:
it pays none of the encoding overhead above, and TCP gives it real
backpressure instead of the sliding-window-and-polling machinery this
document describes.

---

## Source

Verified against the actual implementation, not generic DNS-tunneling
folklore:
- `tunnel/cmd/freewire-tunnel/dns_client.go` (handshake steps, base32
  encoding, `dnsSendConcurrency=24`, `dnsPollConcurrency=8`, the poll-nonce
  cache-defeat comment)
- `server/internal/transport/dns_server.go` (fragment reassembly,
  `maxFragConflicts`/`maxReassemblyTries`, piggyback packing)
- `tunnel/cmd/freewire-tunnel/dnstcp.go`, `server/internal/transport/dnstcp.go`
  (the `dns_tcp` carrier and its hello)
