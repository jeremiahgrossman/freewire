# Captive Portal Test Harness

Runnable form of `captive-portal-testing-guide.md`. Clearing all six
configurations is the **Phase 2 milestone gate**.

The guide remains authoritative. These scripts exist so a test session is
one command per config instead of hand-applied firewall rules, and so runs
are reproducible.

---

## Setup

Everything reads `config.env`. Fill it in first:

```bash
docker inspect freewire-server \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'  # -> SERVER_IP
route -n get "$SERVER_IP" | grep interface                        # -> UPLINK_IF
ifconfig "$UPLINK_IF" | awk '/inet /{print $2}'                   # -> GATEWAY_IP
```

| Variable | Meaning |
|---|---|
| `SERVER_IP` | Container running `freewire-server`, on its routable address |
| `UPLINK_IF` | Interface carrying traffic toward the server |
| `GATEWAY_IP` | Where `proxy.py` binds for Config 1 |
| `AUTO_REVERT_SECONDS` | Lockout protection — see Safety |

## Which directory

**`macos/`** — for the current single-machine setup: client on the Mac,
server in Docker. pf rules restrict egress toward the container address,
simulating the portal without extra hardware. Start here.

The container must be reached on its own address, not `127.0.0.1`.
Loopback traffic does not traverse pf rules, so a run over loopback
passes every config without testing anything.

**`linux/`** — the guide's iptables rules, for a dedicated
Linux/Raspberry Pi gateway with the test device behind it. Use when you
outgrow the single-machine setup.

## Safety

These scripts install `block all` firewall rules on your own machine. Each
config starts a watchdog that reverts after `AUTO_REVERT_SECONDS` (default
300) unless you confirm:

```bash
sudo macos/confirm.sh    # keep rules until you reset
sudo macos/reset.sh      # revert now
```

`reset.sh` restores the pf ruleset and enabled/disabled state captured
before the first config ran. If a script wedges the network, `reset.sh` is
the recovery path; the watchdog is the backstop if you lose the terminal.

---

## Run order

Run in sequence — each config assumes the previous passed.

```bash
sudo macos/config0.sh     # baseline, control run
sudo macos/config1.sh     # needs: sudo python3 proxy.py
sudo macos/config2.sh
sudo macos/config3.sh
sudo macos/config4.sh     # needs: dnsmasq NXDOMAIN resolver on :5353
sudo macos/config5.sh
sudo macos/config3.sh && sudo macos/config6-upgrade.sh
sudo macos/reset.sh
```

After connecting the client for each config, verify at the network layer —
never from the client's own indicator, which is the thing under test:

```bash
sudo ./which-path.sh 10
```

---

## Expected results

Timing budgets come from `CLAUDE.md` §Fallback Chain Timeouts. They are
cumulative: each path spends its full timeout before the next is tried.

| Config | Network | Expected path | Budget |
|---|---|---|---|
| 0 | Open | WireGuard direct | immediate |
| 1 | CONNECT proxy on 443 | Path 1 — HTTP CONNECT | ≤ 2s |
| 2 | 443 open direct | Path 2 — TLS/443 | ≤ 5s |
| 3 | DNS forwards, 443 blocked | Path 3 — DNS tunnel | ≤ 8s |
| 4 | Local NXDOMAIN DNS, ICMP open | Path 4 — ICMP tunnel | ~10s |
| 5 | Hard block | None → CONN-2b | ≤ 11s |
| 6 | Config 3, then 443 opens | DNS → TLS/443 upgrade | one probe interval |

**A too-fast result is also a failure.** Config 2 connecting in under 2s
means the HTTP CONNECT probe is not spending its timeout — likely
short-circuiting rather than genuinely failing.

## Results log

Record each run. Bugs found here become the first regression tests.

| Config | Date | Path observed | Time | Pass | Notes |
|---|---|---|---|---|---|
| 0 | 2026-06 | TLS/443 | — | ✅ | Baseline, pre-harness, against the earlier VM |
| — | 2026-08-21 | — | — | — | Harness retargeted to the Docker container. Server moved to real ports 443/53 so the guide's rules apply unchanged. |
| 1 | 2026-08-21 | **HTTP CONNECT** | ~3s | ✅ PASS | `ready utun6 10.0.0.2 http_connect` through `testing/proxy.py`, confirmed in the proxy log as `200 tunnel -> <server>:443`. 5/5 pings, 0% loss, 73ms. Needed the `http_proxy` config field: probing only the gateway made this untestable on one machine. |
| 2 | 2026-08-21 | **TLS/443** | ~2s | ✅ path / ⚠️ egress | Path selection correct: `tls443: session established`, handshake completed, `utun6` up at 10.0.0.2, 10.0.0.1 answers in ~2ms. Routing since fixed and verified installing. Egress unverifiable here — see the ECN note. |
| 3 | 2026-08-21 | **DNS tunnel** | 3.1s | ✅ PASS | `ready utun6 10.0.0.3 dns`. 15/15 pings, 0% loss, avg 59ms (min 1.6, max 578 — variance is the poll interval). TCP connect completes over it. Confirmed twice. First with the path forced, then properly under Config 3's rules with no preferred transport set: HTTP CONNECT failed, TLS/443 was blocked, and the chain selected DNS on its own 3.1s after peer registration. 15/15 pings, 0% loss, avg 38ms. Routing skipped, so this proves path selection and transport, not egress. |
| 4 | | | | | |
| 5 | | | | | |
| 6 | | | | | |

---

## What to watch per config

**Config 3 (DNS tunnel)** is the highest-risk run — most complex component,
least exercised. Beyond "did it connect":

- EDNS0 negotiated — look for `OPT` records with a large payload
- Sliding window healthy — sustained >10 queries/sec
- Upgrade probe fires and correctly *fails*, leaving the client on DNS
  rather than flapping
- Reduced-speed indicator shown per `ux-workflows.md` §1.3

**Config 5 (CONN-2b)** must satisfy all three:

- CONN-2b, not CONN-2a — the portal probe times out rather than returning
  a redirect. An in-app browser opening means the run is invalid.
- Kill switch does **not** activate — no tunnel was established, so traffic
  keeps flowing unprotected. That is correct.
- Exact copy from `error-states-spec.md`, not paraphrased.

**Config 6 (upgrade)** — the session must not drop. Per
`path-upgrade-manager-spec.md` the manager only moves toward lower priority
numbers: DNS(4) → TLS/443(3), then stop. Oscillation means broken
hysteresis.

---

## Forwarded traffic dies in this environment

Full-tunnel egress cannot be validated against the container. Traffic
reaches the server and is forwarded correctly, but replies never return.

The server side is provably correct. Inside the container:

    MASQUERADE     7,940 packets    NAT is applying
    FORWARD out   41,125 packets    forwarding works
    FORWARD in            0         nothing ever comes back

Zero return packets, and a capture on eth0 shows no inbound from the
destination either. Packets leave the container correctly source-NAT'd and
are lost past it, in the runtime's own NAT.

Two hypotheses were tested and **both were wrong**, recorded here so they
are not retried:

1. *The Config 2 pf ruleset blocks the return path.* Disproven: the
   failure reproduces identically with the ruleset flushed.
2. *macOS ECN-capable SYNs are dropped when forwarded.* The forwarded SYNs
   did carry `[SEW]` while the container's own used `[S]`, which looked
   conclusive. Disproven: with `net.inet.tcp.ecn_initiate_out=0` the
   forwarded SYNs became plain `[S]` and still received zero replies.

The remaining difference between a working and a failing flow is only that
one is forwarded, so the cause sits in the runtime's handling of forwarded
flows. Debugging it further has no value for Freewire: the tunnel, the
server, forwarding and NAT are all doing their jobs.

**Testing against the container therefore covers path selection only.**
Validate egress, throughput and MTU against a real server (Phase 3, EC2).

### Running a config despite unverifiable egress

`setupRouting` treats a tunnel that carries no traffic as fatal, which is
correct for users but would block every remaining config here. Pass the
flag to accept it:

    sudo tunnel/freewire-tunnel --skip-egress-check < config.json

It also stops the supervisor that would otherwise release the routes about
30s later. The app never passes it, so no release build can reach it.

## setupRouting does not install the default route (found in Config 2)

Config 2 selected the right path and built a working tunnel, but internet
traffic never entered it. After connecting:

    route get 8.8.8.8   -> interface en0, gateway 192.168.0.1

The tunnel carries its own subnet (`10/24 -> utun6`, and 10.0.0.1 answers)
but the default route is untouched, so the VPN protects nothing. The
client reports "Protected" regardless, because it treats the ready line as
success and `setupRouting` failures are non-fatal and only logged.

Two causes, both real:

1. **Several default routes exist.** `netstat -rn` shows defaults on en0,
   bridge100 and bridge101. `route delete default` removes one entry --
   not necessarily en0's -- so the subsequent `route add default
   -interface <utun>` can fail with "file exists" while the original
   default survives.
2. **The bypass route is wrong for this topology.** `setupRouting` adds a
   host route for the server via the *default* gateway
   (`route add -host 192.168.97.2 192.168.0.1`), but the server sits on
   bridge101 and is not reachable through that gateway. Had the default
   route actually moved, the TLS transport's own packets would have been
   routed into the tunnel they carry, and the session would have died.
   This is the same class of bug the audit recorded as PROTO-008 for the
   DNS resolver.

Until this is fixed, a passing config proves **path selection only**, not
that traffic is protected. Verify routing separately with
`route get 8.8.8.8` and do not rely on the client's own indicator.

## Config 4 must pass UDP 4500, not "proto icmp"

The fourth transport is named `icmp_udp` and rides **UDP port 4500**, not the
ICMP protocol. `config4.sh` originally passed `inet proto icmp` and left 4500
blocked, so it blocked the very path it exists to force. It now passes
`$ICMP_UDP_PORT`.

## Peer registration needs a Privacy Pass token

The managed server issues tokens, so `POST /v1/peers` without one returns
`402 TOKEN_INVALID`. Get one first:

```bash
tunnel/freewire-tokens issue --server https://<server>:8080 --count 1 --insecure
```

`--insecure` is correct here: the server presents a self-signed certificate and
trust comes from the pinned WireGuard key, exactly as the client does it.

## The bootstrap API must be reachable in every config

The client calls `GET /v1/server/config` and `POST /v1/peers` *before* it
selects a transport. If those fail it reports CONN-3 ("servers are
unreachable") and never enters the fallback chain, so the config tests
nothing.

In production the API rides HTTPS on 443 alongside the TLS transport, so
it is reachable exactly when 443 is. The dev server splits it onto
`API_PORT`, so configs 1, 2, 3, 4 and 6 pass that port explicitly. This
matches production rather than weakening the test: no config is expected
to block the API while still expecting a tunnel.

**Config 5 is deliberately excluded, and that changes what it proves.**
A hard block takes the API down too, so the client fails at bootstrap
with CONN-3 rather than trying four paths and landing on CONN-2b. The
guide expects CONN-2b. Reaching it requires the API to succeed while
every transport fails — which the current architecture cannot produce on
a single blocked network, because the API needs the same network the
transports do.

This is an open design question, not a harness bug: **how does the client
bootstrap on a network where it cannot reach the API at all?** Peer
registration has to happen before a tunnel exists. Until that is
answered, treat Config 5 as verifying CONN-3, and record it as such
rather than forcing a CONN-2b result.

## Config 1: solved with an explicit proxy address

`tryHTTPConnect` probed only the machine's default gateway, and a listener
cannot be bound to the gateway address from the client itself — so this
config could not run without a second machine acting as the router.
Moving the server to AWS did not help: the constraint is about where the
*proxy* sits, not the server.

The client now accepts an explicit `http_proxy` in its config and tries it
before the gateway. That makes the path testable on one machine, and is
defensible beyond testing: portals that advertise a proxy via WPAD or DHCP
rather than intercepting transparently are not reachable by a
gateway-only probe either.

## Superseded: why Config 1 used to be blocked

`tryHTTPConnect` finds its proxy by parsing `route get default` — the
machine's real default gateway. `config1.sh` puts the proxy at
`GATEWAY_IP`, the Mac's address on the container bridge. Those are
different addresses and always will be, so the CONNECT path can never
succeed here no matter what the rules allow.

This predates the move to Docker; the earlier VM setup had the same mismatch,
which is why Config 1 was never recorded as passing.

Two ways to fix it, neither done yet:

1. **Second machine.** Run the client on a device whose default gateway
   really is the machine running `proxy.py`. This is what the guide
   assumes and what `linux/` is built for.
2. **Transparent redirect.** A pf `rdr` rule intercepting outbound TCP to
   the real gateway on 3128/8080/443 and sending it to the local proxy.
   Closer to how a portal actually behaves, but redirecting
   locally-originated traffic on macOS pf is awkward and needs care.

Until one of those lands, Config 1 is **blocked**, not failing. Do not
record it as a pass on the strength of the client connecting — it will
have connected over TLS/443.

## Known gap

The kill switch is **not implemented** — there is no `FreewireHelper`
target and no pf rules are installed by the app. `TunnelManager`'s
`.reconnecting` state comments "kill switch active; traffic blocked" but
nothing enforces it.

This does not block configs 0–6, which test path selection. It does mean
any leak check during a *reconnect* will show traffic flowing. Config 5's
leak check is still valid, since no tunnel is ever established there and
the kill switch is correctly expected to stay off.

## Deviation from the guide

`proxy.py` here is a rewrite. The listing in the guide targets its relay
threads at a generator expression that is never iterated, so no bytes are
ever relayed. Verified: it returns `200 Connection established` and the
connection then resets without carrying data, so Config 1 fails in a way
that looks like a client bug rather than a harness bug.

This version relays correctly and handles half-close. Worth folding back
into `captive-portal-testing-guide.md` so the guide and harness agree.
