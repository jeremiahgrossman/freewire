#!/usr/bin/env bash
# One-command regression gate. Runs the checks that catch what static analysis
# can't -- this project's recurring pain is "critical bugs only found by running"
# -- and prints a single PASS/FAIL. Safe: everything here is non-routed except
# the optional --full tier.
#
#   testing/regression.sh          # build + unit tests + app build + live transport probe
#
# Exit 0 only if every check passed. Meant to run on any network; the transport
# probe reports what THIS network allows (so a captive portal is a valid place to
# run it -- results just differ).
#
# These are the checks that are reliable to run unattended. The two HEAVY
# end-to-end tests launch the real app and manipulate routing, which does not
# nest cleanly inside a backgrounded runner (the app is not a child process), so
# run them on their own and read their logs:
#   testing/verify-reconnect.sh    # kills the tunnel, asserts the app reconnects
#   testing/routed-test.sh dns     # routed egress through the server (~45s)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fails=0
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { echo "  PASS: $1"; }
bad()  { echo "  FAIL: $1"; fails=$((fails+1)); }

step "build (tunnel + server)"
# The client binary is built into the tree, not just compiled: the server's
# WSS interop test runs the real freewire-tunnel binary against the real
# listener, and skips itself when the binary is absent. Building it here is what
# turns that cross-module test on.
if (cd "$ROOT/tunnel" && go build ./... && go build -o freewire-tunnel ./cmd/freewire-tunnel) && (cd "$ROOT/server" && go build ./...); then ok "both build"; else bad "build error"; fi

step "unit tests -race (tunnel + server)"
if (cd "$ROOT/tunnel" && go test -race ./... >/tmp/reg-tun.txt 2>&1); then ok "tunnel tests"; else bad "tunnel tests"; tail -5 /tmp/reg-tun.txt|sed 's/^/    /'; fi
if (cd "$ROOT/server" && go test -race ./... >/tmp/reg-srv.txt 2>&1); then ok "server tests"; else bad "server tests"; tail -5 /tmp/reg-srv.txt|sed 's/^/    /'; fi

step "macOS app builds"
if xcodebuild build -project "$ROOT/macos/Freewire/Freewire.xcodeproj" -scheme Freewire -configuration Debug CODE_SIGNING_ALLOWED=NO >/tmp/reg-xc.txt 2>&1 && grep -q "BUILD SUCCEEDED" /tmp/reg-xc.txt; then ok "app builds"; else bad "app build"; tail -5 /tmp/reg-xc.txt|sed 's/^/    /'; fi

step "live transport probe (what this network allows)"
PROBE="$(bash "$ROOT/testing/probe-transports.sh" 2>&1)"
echo "$PROBE" | grep -E "wireguard|tls443|wss443|dns|icmp_udp|http_connect" | sed 's/^/  /'
# At least one carrier must reach the server, or the client can't connect at all.
if echo "$PROBE" | grep -qE "(wireguard|tls443|wss443|dns|icmp_udp).*OK"; then ok "at least one carrier reachable"; else bad "no carrier reachable"; fi

printf '\n================  %s  ================\n' "$([ $fails -eq 0 ] && echo 'CORE CHECKS PASSED' || echo "$fails CHECK(S) FAILED")"
echo "Heavy end-to-end (run standalone): testing/verify-reconnect.sh, testing/routed-test.sh dns"
exit "$fails"
