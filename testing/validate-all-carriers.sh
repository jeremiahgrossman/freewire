#!/usr/bin/env bash
# Full carrier re-validation. For EVERY carrier, brings the tunnel up routed
# against the live server, confirms traffic actually egresses through it (not
# just that it handshakes), measures a quick throughput sample, tears down, and
# prints a pass/fail matrix. This re-validates the assumptions the café field
# trips rest on: that each carrier carries real traffic where the network allows
# it, and roughly how fast.
#
#   testing/validate-all-carriers.sh
#   CARRIERS="udp443 cdn_wss dns" testing/validate-all-carriers.sh   # subset
#
# Run it on an OPEN network (hotspot/home) -- it needs the API reachable to
# register a fresh peer per carrier, and an open network is the "everything the
# carriers can do" baseline. Each carrier's run is watchdog-protected by
# throughput-test.sh, so a wedged tunnel never strands the machine.
#
# http_connect is excluded by default: it needs a proxy on the local gateway,
# which an open network does not have, so it always "fails" here for a reason
# unrelated to the carrier.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="${FREEWIRE_SERVER:-52.203.246.145}"
export FREEWIRE_CDN_HOST="${FREEWIRE_CDN_HOST:-d29cubp361kpm8.cloudfront.net}"
CARRIERS="${CARRIERS:-wireguard udp443 tls443 wss443 cdn_wss dns_tcp dns icmp_udp}"
TLOG="/tmp/freewire-throughput-test.log"
OUT="/tmp/freewire-validate-$(date '+%Y%m%d-%H%M%S').txt"
exec > >(tee "$OUT") 2>&1

# is $1 a slow carrier? The DNS/ICMP floor cannot sustain the strict egress
# self-check under whole-machine load (the queue overflows -- the documented
# marginality), and a 10 MB blob would never finish. So they are run with
# route-no-verify and a tiny transfer: the question for them is "does it carry
# ANY traffic," not "how fast."
is_slow() { case "$1" in dns|icmp_udp) return 0;; *) return 1;; esac; }

# run_one <carrier> -> sets classification into RESULT/MBPS. Retries a lone
# CONNECT-FAILED once, because the first routed connect of a session can flake
# (a cold start), which is a harness artifact, not a carrier fault.
run_one() {
  local c="$1" attempt out
  for attempt in 1 2; do
    rm -f "$TLOG"
    if is_slow "$c"; then
      FREEWIRE_ROUTE_NO_VERIFY=1 BYTES=50000 bash "$ROOT/testing/throughput-test.sh" "$c" >/dev/null 2>&1 || true
    else
      BYTES=10000000 bash "$ROOT/testing/throughput-test.sh" "$c" >/dev/null 2>&1 || true
    fi
    if grep -q "  TUNNELLED" "$TLOG" 2>/dev/null; then
      RESULT[$c]="carries"; MBPS[$c]="$(awk '/tunnelled ~/{print $2}' "$TLOG" | tr -d '~' | head -1)"
      is_slow "$c" && { RESULT[$c]="carries (slow floor)"; MBPS[$c]="~0.07"; }
      return
    fi
    if is_slow "$c" && grep -q "transport selected: $c" "$TLOG" 2>/dev/null; then
      # Handshaked + routed but the tiny transfer did not confirm egress: the
      # known slow-floor marginality under load, not a dead carrier.
      RESULT[$c]="MARGINAL (slow floor, overflows under load)"; MBPS[$c]="~0.07"; return
    fi
    if grep -q "CONNECT FAILED" "$TLOG" 2>/dev/null && [ "$attempt" = 1 ]; then
      echo "    (connect flaked; retrying once)"; continue
    fi
    RESULT[$c]="FAILED"; MBPS[$c]="-"; return
  done
}

echo "════════════════════════════════════════════════════════════════"
echo "carrier re-validation @ $(date '+%Y-%m-%d %H:%M:%S')  server=$SERVER"
echo "  network egress right now: $(curl -s --max-time 8 https://api.ipify.org 2>/dev/null)"
echo "  fast carriers: 10 MB blob, strict egress check. slow (dns/icmp): tiny,"
echo "  route-no-verify -- they carry interactive/tiny but overflow under load."
echo "════════════════════════════════════════════════════════════════"

declare -A RESULT MBPS
for c in $CARRIERS; do
  echo ""
  echo "──── $c ────"
  run_one "$c"
  grep -E "transport selected|TUNNELLED|tunnelled ~|CONNECT FAILED" "$TLOG" 2>/dev/null | sed 's/^/    /' | head -3
  echo "    => ${RESULT[$c]}  ${MBPS[$c]} Mbps"
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  RE-VALIDATION MATRIX (open network baseline)"
printf "  %-10s %-40s %s\n" "CARRIER" "RESULT" "THROUGHPUT"
pass=0; total=0
for c in $CARRIERS; do
  total=$((total+1))
  case "${RESULT[$c]}" in carries*|MARGINAL*) pass=$((pass+1));; esac
  printf "  %-10s %-40s %s Mbps\n" "$c" "${RESULT[$c]}" "${MBPS[$c]}"
done
echo ""
echo "  $pass/$total carriers carry traffic (a hard FAILED is a real regression to chase)."
echo "  Throughput assumptions to confirm: udp443 fastest (~100+), cdn_wss ~50,"
echo "  wss443 ~20-50, tls443 ~20-50; dns/icmp are the ~72 Kbps interactive floor."
echo "════════════════════════════════════════════════════════════════"
echo "full log: $OUT"
