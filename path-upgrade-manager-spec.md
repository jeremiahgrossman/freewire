# Freewire VPN — Path Upgrade Manager Specification

**Audience:** Client engineers  
**Version:** 1.0  
**Last updated:** 2026-06-17  
**Depends on:** `technical-architecture.md` §3, `error-states-spec.md`

---

## Overview

Once the fallback chain establishes a tunnel on any path, the path upgrade manager runs in the background to find a faster path. The user sees "Connected" and is never interrupted. If a faster path is confirmed reachable, the tunnel migrates silently.

The upgrade manager is client-side only. The server treats all paths equally once a WireGuard session is established.

---

> ## Superseded (2026-08-30)
>
> Everything below this point through "Probing" describes the original design intent, kept for historical context — **the shipped `PathUpgradeManager` (macOS) does not implement it.** The real mechanism is much narrower:
>
> - It does **not** treat every faster carrier as a probe candidate. It only probes two specific transitions: `.dns` (only from ICMP — the sole path from which DNS is actually a faster target) and `.udp443` (from any slower carrier, via a magic UDP probe to the server's port 443 that can't roam the active session's WireGuard identity).
> - It deliberately **declines** to probe `wireguard`, `tls443`, `wss443`, or `cdn_wss` as upgrade targets — a cheap reachability probe can't predict whether one of these actually carries traffic once routed, so the fallback chain (not the upgrade manager) is what's trusted to discover them correctly.
> - It never probes raw `wireguard` (port 51820) directly, on purpose: a real handshake there would use the device's real key and cause the server to roam the peer to that endpoint, tearing down the active carrier session mid-upgrade. `udp443` gets the same practical win (near line-rate UDP) without that hazard.
> - There is no five-state PROBING/UPGRADING state machine, no generic "N paths, priority-ordered, probe everything faster" loop, and no fixed 5-second MONITORING delay or 60-second STABLE re-probe interval as literal, generally-applicable timers — those numbers describe the original design, not the shipped code path-by-path.
> - The 9-carrier reality (not the 5 listed in "Path Priority Order" below) is `wireguard`, `udp443`, `http_connect`, `tls443`, `wss443`, `cdn_wss`, `dns_tcp`, `dns`, `icmp_udp`, in that fallback-chain order. `dns_tcp` (added 2026-08-28) sits between `cdn_wss` and `dns`, and is itself a live upgrade candidate would need scoping the same way `.dns`/`.udp443` were — not yet done.
>
> See `CLAUDE.md`'s Current State (search "PathUpgradeManager") for the exact shipped behavior and the reasoning behind each of these deliberate exclusions.

---

## Why Upgrade?

The fallback chain tries paths in order and stops at the first success. On a captive portal network that only allows DNS:

1. HTTP CONNECT — fails (2s)
2. TLS/443 — fails (3s)
3. DNS tunnel — **succeeds** (3s)

The client is now connected via the DNS tunnel. But once the DNS tunnel is established and Freewire's server is reachable, TLS/443 might also be reachable (some captive portals block inbound 443 connections to unknown IPs but allow them once a DNS query has been made — this varies). The upgrade manager checks.

Without upgrading, users on DNS tunnel get 500 Kbps–2 Mbps. With an upgrade to TLS/443, they get 50+ Mbps. The user's experience improves significantly with no action required.

---

## State Machine

```
 ┌────────────────────────────────────────────────────────────────┐
 │  IDLE (no tunnel active)                                       │
 └──────────────────────────────┬─────────────────────────────────┘
                                │ Tunnel established on any path
                                ▼
 ┌────────────────────────────────────────────────────────────────┐
 │  MONITORING                                                    │
 │  Wait 5 seconds after tunnel establishment.                    │
 │  If established path is already the fastest available,         │
 │  skip to STABLE.                                               │
 └──────────────────────────────┬─────────────────────────────────┘
                                │ 5s elapsed
                                ▼
 ┌────────────────────────────────────────────────────────────────┐
 │  PROBING                                                       │
 │  Probe all paths faster than the current path.                 │
 │  Run probes in parallel, each with a 2-second timeout.         │
 └──────────────┬───────────────────────────────┬─────────────────┘
                │ No faster path found           │ Faster path found
                ▼                                ▼
 ┌──────────────────────────────┐  ┌─────────────────────────────┐
 │  STABLE                      │  │  UPGRADING                  │
 │  No upgrade available.       │  │  Migrating to faster path.  │
 │  Re-probe every 60 seconds   │  └──────────────┬──────────────┘
 │  (network conditions change).│                 │ Migration complete
 └──────────────────────────────┘                 ▼
                                   ┌─────────────────────────────┐
                                   │  MONITORING (on new path)   │
                                   │  Check if an even faster    │
                                   │  path is now reachable.     │
                                   └─────────────────────────────┘
```

---

## Path Priority Order

Paths from fastest to slowest. The upgrade manager only ever upgrades — it never downgrades.

| Priority | Path | Typical throughput |
|---|---|---|
| 1 (fastest) | Open WireGuard (UDP 51820) | 100+ Mbps |
| 2 | HTTP CONNECT | 50+ Mbps |
| 3 | TLS/443 | 50+ Mbps |
| 4 | DNS tunnel | 0.5–2 Mbps |
| 5 (slowest) | ICMP tunnel | 0.1–0.5 Mbps |

If the client is on path 3 (TLS/443), the upgrade manager probes only paths 1 and 2. It never re-probes paths 4 or 5.

If the client is on path 1 (open WireGuard), the upgrade manager skips probing entirely and goes directly to STABLE. There is no faster path.

---

## Probing

Probes run **through the established tunnel**, not directly. This is what distinguishes a probe from the initial fallback chain attempt.

The initial fallback chain runs before any tunnel exists — it's testing whether a direct connection to Freewire's server is possible through the captive portal. The upgrade manager probes from behind the tunnel — it's testing whether a new direct path has become available, which can happen after the initial DNS or ICMP handshake proves the portal allows traffic to Freewire's IP.

### Probe mechanism

For each candidate path faster than the current one, the client:

1. Attempts to establish that path's handshake (the first packet/request only).
2. Waits up to **2 seconds** for a valid response.
3. If a response arrives, the probe succeeds.
4. If no response within 2 seconds, the probe fails.

Probes for different paths run in **parallel**. Total probe time is capped at 2 seconds (one round of probes), not 2 seconds × number of paths.

### Probe results

- **All probes fail:** No upgrade available. Go to STABLE. Re-probe after 60 seconds.
- **One or more probes succeed:** Select the fastest successful path. Begin migration.
- **Multiple probes succeed simultaneously:** Always select the highest-priority (fastest) path.

---

## Migration (UPGRADING State)

Migration must not drop the existing tunnel. The user must not see "Disconnecting" or "Reconnecting."

### Migration procedure

1. **Establish the new path** — Complete the full handshake on the new path (all handshake steps, not just the probe packet). Do not tear down the existing tunnel during this step.
2. **Register the new WireGuard endpoint** — For TLS/443, HTTP CONNECT, and open WireGuard: the WireGuard traffic now flows over the new path. Update the tunnel interface to use the new path's virtual endpoint. The WireGuard session (keys, IPs, peers) remains unchanged.
3. **Verify continuity** — Send a keepalive on the new path. Confirm a response arrives within 1 second.
4. **Tear down the old path** — Close the old path's transport connection and release its resources. Do this only after the new path keepalive succeeds.
5. **Update state** — Set current path to the new path. Transition to MONITORING.

If any step fails (new handshake fails, keepalive on new path times out), abort migration. Remain on the existing path. Log the failure silently. Next re-probe is in 60 seconds.

### WireGuard session continuity

The WireGuard session is defined by the keypair and peer configuration — not the underlying transport. Migration changes the transport (from DNS-encoded UDP to real TCP/TLS, for example) but keeps the same WireGuard session. No WireGuard renegotiation occurs. In-flight packets may be briefly reordered during the switchover; WireGuard's replay protection window handles this.

---

## Re-probe Schedule

After a STABLE state is reached (no upgrade found), the manager continues probing on a schedule in case network conditions change (the captive portal's policy may change after initial authentication, or the user may move to a different network segment).

| Time since establishment | Re-probe interval |
|---|---|
| 0–5 minutes | Every 60 seconds |
| 5–30 minutes | Every 2 minutes |
| 30+ minutes | Every 5 minutes |

Re-probes follow the same mechanism as the initial probe. If a faster path is found at any re-probe, begin migration immediately.

Re-probes stop when:
- The tunnel disconnects.
- The current path is already the fastest (priority 1).
- The app is backgrounded on iOS (OS suspends NE extension activity; probes resume on foreground).

---

## Network Change Events

On network change (device moves to a different wifi network, wifi drops and restores, etc.):

1. The existing tunnel is dropped and re-established via the fallback chain.
2. The upgrade manager resets to IDLE.
3. After the new tunnel is established, the upgrade manager starts fresh from MONITORING.

Network change detection:
- iOS: `NWPathMonitor` path update callback in the NE provider.
- macOS: `SCNetworkReachability` change callback.

---

## User-Visible Behavior

The upgrade manager is **fully silent**. At no point does the user see any indication that a path upgrade is occurring. The connection status remains "Connected" throughout.

The current path name is not exposed to the user. The app does show a **speed tier indicator** (normal speed vs. reduced speed) per `ux-workflows.md` §1.3 — this reflects whether the user is on a high-throughput path (HTTP CONNECT, TLS/443, or WireGuard) versus a constrained path (DNS tunnel, ICMP tunnel), but does not name the path. Engineers can observe path transitions via debug logging (disabled in production builds).

---

## Logging (Debug Only)

When debug logging is enabled (dev/TestFlight builds only):

```
[PathUpgrade] Established: dns_tunnel. Starting upgrade manager.
[PathUpgrade] Probing: tls443, http_connect (parallel, 2s timeout)
[PathUpgrade] Probe result: tls443=success (140ms), http_connect=fail
[PathUpgrade] Migrating: dns_tunnel → tls443
[PathUpgrade] Migration step 1: tls443 handshake complete
[PathUpgrade] Migration step 3: keepalive confirmed (12ms)
[PathUpgrade] Migration step 4: dns_tunnel torn down
[PathUpgrade] Now on: tls443. Re-probe in 60s.
```

No path information is logged in production builds.
