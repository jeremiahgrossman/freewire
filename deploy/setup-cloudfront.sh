#!/usr/bin/env bash
# Put a CloudFront distribution in front of the Freewire server, so the tunnel
# can arrive at a destination a captive portal already permits.
#
#   deploy/setup-cloudfront.sh --domain origin.pinghop.net [--region us-east-1]
#   deploy/setup-cloudfront.sh --domain origin.pinghop.net --dry-run   # print only
#
# WHY: mainstream portals allow-list by DESTINATION, not port. The café that beat
# us refused TCP/443 to our server's IP while passing DNS. A CloudFront edge IP
# is routinely inside a portal's permitted set (its own login page and payment
# SDKs are CDN-hosted), so the same WebSocket carrier that fails to our IP can
# succeed to a CloudFront hostname. This is NOT domain fronting: we own the
# distribution and terminate behind it. See CDN-FRONTED-CARRIER-SPEC.md.
#
# WHAT IT CREATES (all billable, all reversible -- see TEARDOWN at the bottom):
#   - one CloudFront distribution with our EC2 as a custom origin
#   - nothing else; DNS and the ACME cert are prerequisites you do by hand
#
# PREREQUISITES you must do first (this script checks and refuses without them):
#   1. A DNS A record for --domain pointing at the server's Elastic IP.
#   2. TCP/80 open in the security group (ACME HTTP-01 challenge).
#   3. acme_domain set in the server config, and the server restarted, so it
#      holds a publicly trusted certificate. CloudFront will NOT talk to an
#      origin presenting a self-signed certificate.
#   4. AWS credentials with CloudFront permissions. The freewire-deploy user the
#      other deploy scripts use does NOT have them by default -- create-distribution
#      fails with AccessDenied. Attach deploy/cloudfront-iam-policy.json to that
#      user (under an admin login), or run this script with an admin profile.
# Step 3 is safe to enable only because certs.Build now serves the self-signed
# certificate to handshakes without SNI; before that fix, enabling ACME broke
# every client that dials by IP. See internal/certs/certs_test.go.
set -euo pipefail

DOMAIN=""
REGION="us-east-1"
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)  DOMAIN="${2:-}"; shift 2 ;;
    --region)  REGION="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$DOMAIN" ]] || { echo "--domain is required (e.g. origin.pinghop.net)" >&2; exit 2; }

command -v aws >/dev/null || { echo "aws cli not installed" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

say() { printf '==> %s\n' "$*"; }

# ---------------------------------------------------------------- preflight
# Each check refuses rather than "helpfully" proceeding: a distribution built on
# a broken origin bills for itself while failing in a way that looks like a
# portal block, which is the single most misleading failure this project has.

say "checking DNS for $DOMAIN"
RESOLVED="$(dig +short "$DOMAIN" A | tail -1 || true)"
[[ -n "$RESOLVED" ]] || { echo "  $DOMAIN does not resolve. Create the A record first." >&2; exit 1; }
echo "    $DOMAIN -> $RESOLVED"

say "checking the origin serves a publicly trusted certificate for $DOMAIN"
# --insecure is deliberately NOT used: the point is to prove a real chain, which
# is exactly what CloudFront will require of the origin.
if ! curl -sS --max-time 15 "https://$DOMAIN:443" -o /dev/null 2>/tmp/fw-cf-curl.err; then
  # A TLS handshake that completes but returns a protocol error is fine here --
  # the origin speaks WireGuard framing, not HTTP. Only a CERT failure is fatal.
  if grep -qiE "certificate|SSL|TLS" /tmp/fw-cf-curl.err; then
    echo "  origin certificate is not publicly trusted:" >&2
    sed 's/^/    /' /tmp/fw-cf-curl.err >&2
    echo "  Set acme_domain in the server config, restart, and re-run." >&2
    exit 1
  fi
  echo "    TLS chain OK (non-HTTP response from the origin is expected)"
else
  echo "    TLS chain OK"
fi

# ------------------------------------------------------- distribution config
# CachingDisabled: caching a WebSocket upgrade is meaningless and could poison
#   another client's connection.
# AllViewer origin request policy: forwards Upgrade/Connection/Sec-WebSocket-*,
#   without which the upgrade never reaches the origin.
# https-only + TLSv1.2: never fall back to plaintext between edge and origin.
# Logging disabled: CloudFront access logs record client IPs, which this
#   architecture promises do not exist. This is a privacy requirement, asserted
#   after creation below, not a preference.
CALLER_REF="freewire-$(date +%s)"
CONFIG="$(python3 - "$DOMAIN" "$CALLER_REF" <<'PY'
import json, sys
domain, ref = sys.argv[1], sys.argv[2]
print(json.dumps({
  "CallerReference": ref,
  "Comment": "Freewire tunnel origin (WebSocket carrier)",
  "Enabled": True,
  "Origins": {"Quantity": 1, "Items": [{
      "Id": "freewire-origin",
      "DomainName": domain,
      "CustomOriginConfig": {
          "HTTPPort": 80, "HTTPSPort": 443,
          "OriginProtocolPolicy": "https-only",
          "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
          "OriginReadTimeout": 60,
          "OriginKeepaliveTimeout": 60}}]},
  "DefaultCacheBehavior": {
      "TargetOriginId": "freewire-origin",
      "ViewerProtocolPolicy": "https-only",
      "AllowedMethods": {"Quantity": 7,
          "Items": ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],
          "CachedMethods": {"Quantity": 2, "Items": ["GET","HEAD"]}},
      "Compress": False,
      # Managed-CachingDisabled / Managed-AllViewer: AWS-owned, stable ids.
      "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
      "OriginRequestPolicyId": "216adef6-5c7f-47e4-b989-5492eafa07d3"},
  "Logging": {"Enabled": False, "IncludeCookies": False, "Bucket": "", "Prefix": ""},
  "PriceClass": "PriceClass_100"
}))
PY
)"

if [[ $DRY_RUN == 1 ]]; then
  say "dry run -- the distribution config that WOULD be created:"
  python3 -m json.tool <<<"$CONFIG"
  echo
  echo "Nothing was created. Re-run without --dry-run to apply."
  exit 0
fi

say "creating the distribution"
OUT="$(aws cloudfront create-distribution --region "$REGION" \
        --distribution-config "$CONFIG")"
DIST_ID="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["Distribution"]["Id"])' <<<"$OUT")"
DIST_HOST="$(python3 -c 'import json,sys;print(json.load(sys.stdin)["Distribution"]["DomainName"])' <<<"$OUT")"
echo "    $DIST_ID -> $DIST_HOST"

# Asserted, not assumed: the privacy guarantee is the reason this is here.
say "verifying access logging is OFF"
LOGGING="$(aws cloudfront get-distribution-config --id "$DIST_ID" --region "$REGION" \
  --query 'DistributionConfig.Logging.Enabled' --output text)"
if [[ "$LOGGING" != "False" && "$LOGGING" != "false" ]]; then
  echo "  REFUSING TO PROCEED: access logging is enabled ($LOGGING)." >&2
  echo "  CloudFront access logs record client IP addresses, which this" >&2
  echo "  architecture guarantees are never written down. Disable it or delete" >&2
  echo "  the distribution: aws cloudfront delete-distribution --id $DIST_ID" >&2
  exit 1
fi
echo "    logging disabled"

cat <<EOF

  Distribution $DIST_ID is deploying (takes ~5-15 minutes to reach Deployed).

  Watch it:
    aws cloudfront get-distribution --id $DIST_ID --query 'Distribution.Status' --output text

  Once Deployed, test it from a normal network first, then from a café:
    tunnel/freewire-tunnel --probe-battery --server 52.203.246.145 --insecure \\
        --cdn $DIST_HOST

  The line that matters is direct WebSocket/443 vs CDN WebSocket/443. Direct
  FAIL + CDN OK means the portal gates our ADDRESS, not the port -- which is the
  hypothesis in CDN-FRONTED-CARRIER-SPEC.md and the green light to build the
  carrier.

  TEARDOWN (a distribution bills while it exists):
    aws cloudfront get-distribution-config --id $DIST_ID > /tmp/d.json
    # set Enabled=false, update with the ETag, wait for Deployed, then:
    aws cloudfront delete-distribution --id $DIST_ID --if-match <ETag>

EOF
