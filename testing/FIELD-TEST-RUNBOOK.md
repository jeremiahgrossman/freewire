# Field-test runbook — real captive portal

The one thing simulation can't confirm: does the app carry a **sustained session
through a real un-authenticated portal**. Everything else is proven at the desk
(delegation live, DNS carrier sustains ~400–500 Kbps at 0% loss through the
café's own resolver, cache fallback works in the config7 sim, false-Protected
fixed, disconnect tears down cleanly on stdin EOF).

## Before you leave (at home / open wifi)

1. **Start clean.** Reboot the Mac if it's had a lot of tunnel testing (clears any
   stale `utun` interfaces). Otherwise:
   ```
   sudo /Users/jeremiah/Claude/Projects/FreewireVPN/tunnel/freewire-tunnel --restore
   ```
2. **Use the current build** (all fixes: stdin-EOF teardown, false-Protected,
   cache fallback, native fonts):
   ```
   open /Users/jeremiah/Library/Developer/Xcode/DerivedData/Freewire-elmajhbhindocnejdnjhxousdzrg/Build/Products/Debug/Freewire.app
   ```
3. **Populate the cache** — connect once on the open network. This registers the
   (now persistent) peer and saves the control-plane state the portal fallback
   needs. Confirm it reaches **Protected** and real egress (public IP becomes the
   server). Then **disconnect** — the peer stays registered now.
4. **Confirm `dnsResolverOverride` is unset** (so DNS uses the network's resolver,
   the real-world path):
   ```
   defaults read com.freewire.vpn.Freewire dnsResolverOverride    # should error / be empty
   ```

## At the café

1. Join the café wifi. If the OS login sheet appears, **Cancel it — do not log in.**
2. Click **Connect** in Freewire.
3. Run the diagnostic (records the egress timeline locally; ~45s, prints progress):
   ```
   /Users/jeremiah/Claude/Projects/FreewireVPN/testing/cafe-diagnostic.sh
   ```
4. Switch back to your hotspot and tell Claude **"diagnostic done"** — it reads
   `/tmp/freewire-cafe-diagnostic.log` and `/tmp/freewire-tunnel-stderr.log`
   directly. No copy-paste.

## Reading the result

- **SUSTAINED, egress = server IP** → the marquee capability works end to end. Done.
- **INTERMITTENT** → the portal throttles sustained DNS (the resolver itself does
  not, so this would be portal/network-level). Points to the DNS-as-bootstrap
  pivot.
- **NOT TUNNELLED / false Protected** → should no longer happen (sustained-egress
  check added); if it does, the log shows which transport and why.

## If the machine goes sluggish

Routing everything over a ~400 Kbps DNS tunnel is slow by design. Recover:
```
sudo /Users/jeremiah/Claude/Projects/FreewireVPN/tunnel/freewire-tunnel --restore
```

## Known limits this test cannot get past

- **DNS hijacking.** A portal that answers every DNS query with its own IP (rather
  than allowing recursion) kills the DNS tunnel entirely. Starbucks allowed
  recursion; other venues may not. This is a fundamental limit, not a bug.
- **macOS Captive Network Assistant.** The OS may gate app traffic while its login
  sheet is up; cancelling the sheet is what releases it.
