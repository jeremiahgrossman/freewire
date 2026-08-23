# Field-test runbook — real captive portal

The one thing simulation can't confirm: does the app carry a **sustained session
through a real un-authenticated portal**, and **which transport the portal
allows**. Everything else is proven at the desk (delegation live; routed
WG-over-DNS carries HTTPS at ~65–71 KB/s via the *server-direct* carrier; the
recursor carrier moves packets but can't carry a TCP handshake; cache fallback
works in the config7 sim; false-Protected fixed; disconnect tears down on stdin
EOF).

## What the field test is actually deciding

On a captive portal, the fallback chain tries HTTP CONNECT → TLS/443 → DNS →
ICMP. Which one wins tells us the portal's shape:

- **TLS/443 wins** → the portal allows HTTPS to arbitrary IPs. Great result, full
  speed. (DNS not exercised — see "forcing DNS" below to test it anyway.)
- **DNS wins, carrier = server-direct** → portal blocks 443 but allows outbound
  53 to any IP. This is the DNS win we built: ~65–71 KB/s. The prize case.
- **DNS wins, carrier = system-resolver** → portal allows only its own resolver.
  Packets flow but HTTPS likely won't establish (recursor forward-rate limit).
  Expected to be marginal; documents the field reality.

## Before you leave (at home / open wifi)

1. **Start clean.** Reboot if the Mac has had heavy tunnel testing (clears stale
   `utun`s). Otherwise:
   ```
   sudo /Users/jeremiah/Claude/Projects/FreewireVPN/tunnel/freewire-tunnel --restore
   ```
2. **Use the current build** (server-direct-first DNS default, forceTransport
   pref, persistent peer, cache fallback, stdin-EOF teardown):
   ```
   open /Users/jeremiah/Library/Developer/Xcode/DerivedData/Freewire-elmajhbhindocnejdnjhxousdzrg/Build/Products/Debug/Freewire.app
   ```
3. **Populate the cache** — connect once on the open network. Registers the (now
   persistent) peer and saves the control-plane state the portal fallback needs.
   Confirm **Protected** + real egress (public IP becomes the server). Then
   **disconnect** — the peer stays registered.
4. **Confirm no stale overrides** (all should be empty/error):
   ```
   defaults read com.freewire.vpn.Freewire dnsResolverOverride
   defaults read com.freewire.vpn.Freewire skipRouting
   defaults read com.freewire.vpn.Freewire forceTransport
   ```

## At the café

**Run A — normal selection (what a real user gets).** Leave forceTransport unset.
1. Join the café wifi. If the OS login sheet appears, **Cancel it — do not log in.**
2. Click **Connect**.
3. Diagnostic (records egress timeline locally; ~45s, prints progress):
   ```
   /Users/jeremiah/Claude/Projects/FreewireVPN/testing/cafe-diagnostic.sh
   ```
4. Disconnect.

**Run B — force DNS (validate the DNS win specifically).** Only needed if Run A
selected TLS/443 (i.e. the portal allowed HTTPS) and you want to test DNS too:
```
defaults write com.freewire.vpn.Freewire forceTransport dns
```
Reconnect, run the diagnostic again, disconnect, then clear it:
```
defaults delete com.freewire.vpn.Freewire forceTransport
```

Switch back to your hotspot and tell Claude **"diagnostic done"** — it reads
`/tmp/freewire-cafe-diagnostic.log` and `/tmp/freewire-tunnel-stderr.log`
directly. No copy-paste.

## Reading the result

- The **`freewire-tunnel: dns carrier: <server-direct|system-resolver> (...)`**
  line in the stderr log says which DNS carrier was chosen (if DNS won).
- The transport that reached ready is in the `ready <iface> <ip> <transport>`
  line.
- **SUSTAINED, egress = server IP** → the tunnel carried a real session end to
  end. On DNS+server-direct, that's the marquee capability confirmed in the field.
- **INTERMITTENT / BLOCKED on DNS+system-resolver** → the recursor path's known
  ceiling; expected, not a regression.
- **NOT TUNNELLED / false Protected** → should not happen (sustained-egress check);
  if it does, the log shows the transport and why.

## If the machine goes sluggish

Routing everything over a slow DNS tunnel is slow by design. Recover:
```
sudo /Users/jeremiah/Claude/Projects/FreewireVPN/tunnel/freewire-tunnel --restore
```

## Known limits this test cannot get past

- **Recursor throughput.** Where the portal allows only its own resolver, the DNS
  tunnel is minimal (public/portal recursors rate-limit forwards of unique names
  to our auth server to ~14/s each). Server-direct is the path with real speed.
- **DNS hijacking.** A portal that answers every DNS query with its own IP (no
  recursion, and rewriting destination :53) kills the DNS tunnel. Fundamental.
- **macOS Captive Network Assistant.** The OS may gate app traffic while its login
  sheet is up; cancelling the sheet releases it.
