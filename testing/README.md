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
route -n get 192.168.64.2 | grep interface   # -> UPLINK_IF
ipconfig getifaddr bridge100                 # -> GATEWAY_IP
```

| Variable | Meaning |
|---|---|
| `SERVER_IP` | UTM VM running `freewire-server` |
| `UPLINK_IF` | Interface carrying traffic toward the server |
| `GATEWAY_IP` | Where `proxy.py` binds for Config 1 |
| `AUTO_REVERT_SECONDS` | Lockout protection — see Safety |

## Which directory

**`macos/`** — for the current Mac + UTM VM setup. pf rules on the Mac
restrict egress toward the VM, simulating the portal without extra
hardware. Start here.

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
| 0 | 2026-06 | TLS/443 | — | ✅ | Baseline confirmed pre-harness |
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
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
