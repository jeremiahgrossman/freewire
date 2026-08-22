#!/usr/bin/env bash
# Tear the test tunnel down and check the machine was put back as it was.
#
# The teardown is the half that can strand a machine: it restores resolvers,
# routes, IPv6 and pinned host routes. Verifying it is the point of this script,
# not a courtesy -- a stale pinned route on a home router broke wifi earlier in
# this project.
set -uo pipefail

STATE="/tmp/freewire-test"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if pgrep -f "freewire-tunnel$" >/dev/null 2>&1; then
  echo "==> stopping tunnel"
  # `--stop` sends SIGTERM to the recorded pid and waits for the process to
  # finish restoring routes, resolvers and IPv6. SIGKILL would leave exactly the
  # state the recovery paths exist for, which is a different test.
  #
  # The tunnel binary is the only command with a passwordless sudo rule, and
  # deliberately so: stopping used to go through `sudo pkill`, which needed a
  # second rule letting anything running as this user kill any process on the
  # machine as root.
  sudo -n "$ROOT/tunnel/freewire-tunnel" --stop 2>/dev/null
  for _ in $(seq 1 20); do
    pgrep -f "freewire-tunnel$" >/dev/null 2>&1 || break
    sleep 0.5
  done
fi

if pgrep -f "freewire-tunnel$" >/dev/null 2>&1; then
  echo "tunnel did not exit on SIGTERM" >&2
  exit 1
fi

# Give up the peer slot. Not required -- the server evicts idle peers -- but a
# test that leaks a slot every run eventually fails for the wrong reason.
if [[ -f "$STATE/peer-token" ]]; then
  curl -sk --max-time 8 -X DELETE \
    "https://$SERVER:8080/v1/peers/$(cat "$STATE/peer-token")" >/dev/null 2>&1
  rm -f "$STATE/peer-token"
fi

echo "==> verifying the machine was put back"
fail=0

routes="$(netstat -rn -f inet | awk '$1=="0/1" || $1=="128.0/1"')"
if [[ -n "$routes" ]]; then
  echo "  FAIL split-default routes still present:"; echo "$routes" | sed 's/^/        /'
  fail=1
else
  echo "  ok   split-default routes removed"
fi

if ifconfig utun6 >/dev/null 2>&1 && ifconfig utun6 | grep -q "inet "; then
  echo "  FAIL utun6 still has an address"
  fail=1
else
  echo "  ok   tunnel interface gone"
fi

resolvers="$(scutil --dns | grep -m2 'nameserver\[' | awk '{print $3}' | tr '\n' ' ')"
if [[ "$resolvers" == *"1.1.1.1"* ]]; then
  echo "  FAIL resolvers still point at the tunnel's: $resolvers"
  fail=1
else
  echo "  ok   resolvers restored: $resolvers"
fi

for f in /var/run/freewire-saved-dns /var/run/freewire-pinned-routes; do
  if [[ -e "$f" ]]; then
    echo "  FAIL leftover state file $f"
    fail=1
  else
    echo "  ok   no leftover $(basename "$f")"
  fi
done

pins="$(netstat -rn -f inet | awk -v s="$SERVER" '$1==s')"
if [[ -n "$pins" ]]; then
  echo "  FAIL server host route still pinned: $pins"
  fail=1
else
  echo "  ok   no pinned host route for the server"
fi

v6="$(networksetup -getinfo "Wi-Fi" 2>/dev/null | grep -m1 'IPv6:')"
if [[ "$v6" == *"Off"* ]]; then
  echo "  FAIL IPv6 left disabled"
  fail=1
else
  echo "  ok   IPv6 restored (${v6:-unknown})"
fi

ip="$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null)"
if [[ "$ip" == "$SERVER" ]]; then
  echo "  FAIL traffic still egressing via the server"
  fail=1
else
  echo "  ok   egress back to the local network ($ip)"
fi

exit $fail
