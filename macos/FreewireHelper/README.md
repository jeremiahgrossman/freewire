# FreewireHelper

The privileged helper that enforces the kill switch. **Not yet installable** —
see Status.

## Why it exists

Loading `pf` rules needs root. The app must not run as root, so the privileged
work is isolated in a helper that does one thing: apply and release a firewall
ruleset.

## Status

| Piece | State |
|---|---|
| `KillSwitchRules` (rule generation) | Done, 16 assertions in `macos/Tests` |
| `KillSwitchController` (apply/release) | Written, unverified — needs root |
| SMAppService registration | Not written |
| XPC interface | Not written |
| Signing | **Blocked** — no Developer ID on this machine |

`SMAppService` requires the helper signed with a Developer ID whose team
matches the app's. `security find-identity -v -p codesigning` currently returns
no identities, so the helper cannot be registered or tested end to end. The
logic above is written and the pure part is covered; the packaging is not.

## Design decisions

**`SMAppService`, not `SMJobBless`.** SMJobBless is deprecated as of macOS 13.

**Fail closed.** If the helper dies while the switch is engaged, the rules stay
loaded and traffic stays blocked. A crash that silently unblocks traffic is
worse than one that visibly breaks the network: the user believes they are
protected either way, and only one of those is recoverable by noticing.

The accepted cost is that a crash can leave the machine with no network until
Freewire is relaunched. Recovery without the app:

```sh
sudo pfctl -F all -X "$(cat /etc/freewire/pf.token)"
```

or simply `sudo pfctl -F all -d`.

**Released only on user action.** Disconnecting or quitting. Never on a timer,
and never because reconnection failed — that is exactly when the protection
matters.

**Validated before loading.** `pfctl -n -f` first. A rejected ruleset would
otherwise leave pf enabled with whatever was loaded previously, which may be
nothing at all: unprotected, while the UI says otherwise.

**Local network blocked by default.** It makes printers and NAS unreachable
while the tunnel is down, but a captive portal lives on the local network too —
allowing it hands traffic to the party most likely to be watching.

## What remains

1. A Developer ID certificate.
2. An `SMAppService` daemon target, with the app registering it on first use.
3. An XPC interface for engage/release, with the app as the only allowed peer.
4. Wiring to `TunnelManager`: engage when a tunnel comes up, release on
   explicit disconnect, and hold through reconnection.
5. Restoring the copy in `error-states-spec.md` — it currently states the kill
   switch is unenforced, and that must stay accurate until this ships.
