package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"
)

// wgProbe surveys which well-known destinations a captive portal permits
// pre-login -- its walled garden -- to answer the question the field raised:
// the café refused OUR CloudFront edge, so is ANY fronting destination allowed
// there? If, say, Cloudflare's range connects while CloudFront does not, a
// Cloudflare-Worker-fronted carrier would beat a café where cdn_wss failed.
//
//	freewire-tunnel --walled-garden
//
// Rootless, non-routed: each line is one TCP/443 connect (and a TLS handshake to
// confirm it is really open, not just a portal accepting then redirecting). It
// changes nothing. Run it pre-login on a captive portal; whatever connects is in
// the walled garden.
//
// The destinations span the providers a portal is most likely to allow (its own
// login/payment infra and the OS captive-detection endpoints are usually hosted
// on these), plus our own server and CDN as the baseline that a gating café
// blocks.
func wgProbe(args []string) int {
	for _, a := range args {
		fmt.Fprintf(os.Stderr, "walled-garden: unknown argument %q\n", a)
		return 2
	}

	type dest struct {
		label  string
		host   string
		verify bool // verify the real cert (a real public site) vs TCP+any-TLS (our self-signed server)
		why    string
	}
	// host:443 each, all real HTTPS sites so a valid-cert handshake distinguishes
	// "genuinely reached" from "portal intercepted 443". Grouped by provider so a
	// whole-range-allowed pattern is visible.
	dests := []dest{
		{"Apple captive-detect", "captive.apple.com", true, "17.0.0.0/8; iOS/macOS hit it at join, portals often allow"},
		{"Apple Pay gateway", "apple-pay-gateway.apple.com", true, "paid-wifi portals allow it to take payment"},
		{"Google", "www.google.com", true, "Google range; Android captive-detect lives here"},
		{"Cloudflare DNS (1.1.1.1)", "one.one.one.one", true, "Cloudflare edge range; a Worker could front here"},
		{"Cloudflare site", "www.cloudflare.com", true, "Cloudflare CDN range"},
		{"Fastly site", "www.fastly.com", true, "Fastly CDN range; a Compute@Edge could front here"},
		{"CloudFront (generic)", "d1.awsstatic.com", true, "a DIFFERENT CloudFront edge than ours -- is ANY CloudFront allowed?"},
		{"Akamai site", "www.akamai.com", true, "Akamai range"},
		{"--- baseline ---", "", false, ""},
		{"OUR server", "52.203.246.145", false, "expected BLOCKED at a gating café (self-signed, so TCP+TLS only)"},
		{"OUR CloudFront edge", "d29cubp361kpm8.cloudfront.net", true, "was blocked at café #2 -- edge not allow-listed there"},
	}

	fmt.Fprintln(os.Stderr, "walled-garden: which destinations does THIS network permit on TCP/443 pre-login?")
	fmt.Fprintln(os.Stderr, "  (whatever connects is in the portal's allow-list; it tells us what fronting could work)")
	fmt.Fprintf(os.Stderr, "\n  %-26s %-12s %s\n", "DESTINATION", "RESULT", "WHY IT MATTERS")

	permitted := map[string]bool{}
	for _, d := range dests {
		if d.host == "" {
			fmt.Fprintf(os.Stderr, "  %-26s\n", d.label)
			continue
		}
		res, ok := wgReach(d.host, d.verify)
		permitted[d.label] = ok
		fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", d.label, res, d.why)
	}

	// The actionable read: if a frontable provider (Cloudflare/Fastly/CloudFront)
	// is permitted while our own paths are not, a carrier fronted through that
	// provider would beat this café.
	fmt.Fprintln(os.Stderr)
	frontable := []string{"Cloudflare (1.1.1.1)", "Cloudflare site", "Fastly site", "CloudFront (generic)"}
	var open []string
	for _, f := range frontable {
		if permitted[f] {
			open = append(open, f)
		}
	}
	switch {
	case len(open) > 0 && !permitted["OUR CloudFront edge"]:
		fmt.Fprintf(os.Stderr, "walled-garden: this café permits %v but not our edge.\n", open)
		fmt.Fprintln(os.Stderr, "  => a carrier fronted through a permitted provider would likely get through here.")
	case len(open) == 0:
		fmt.Fprintln(os.Stderr, "walled-garden: no frontable CDN/cloud range is permitted pre-login.")
		fmt.Fprintln(os.Stderr, "  => fronting cannot help this café; DNS (or login) is the only way through.")
	default:
		fmt.Fprintln(os.Stderr, "walled-garden: our own paths are permitted too -- this network is not gating us.")
	}
	return 0
}

// wgReach reports whether host:443 accepts a TCP connection and a TLS handshake.
//
// When verify is true (a real public site), the certificate is checked: a portal
// that intercepts 443 to inject its login page cannot present a valid chain for,
// say, captive.apple.com, so a verified handshake means the destination is
// genuinely reachable, not intercepted. When verify is false (our own
// self-signed server) the handshake still runs but the cert is not checked, so a
// self-signed identity is not miscounted as interception -- the TCP+TLS reach is
// what matters for the baseline.
func wgReach(host string, verify bool) (string, bool) {
	addr := net.JoinHostPort(host, "443")
	start := time.Now()
	raw, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return "-- no " + blockTag(err), false
	}
	defer raw.Close()

	raw.SetDeadline(time.Now().Add(4 * time.Second)) //nolint:errcheck
	tc := tls.Client(raw, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !verify, //nolint:gosec // false only for our own self-signed baseline
	})
	if err := tc.Handshake(); err != nil {
		if verify {
			return "intercepted " + blockTag(err), false
		}
		return "-- no " + blockTag(err), false
	}
	return fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()), true
}
