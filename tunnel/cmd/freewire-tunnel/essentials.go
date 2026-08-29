package main

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Essentials Mode: a destination-allowlist split tunnel for a hard-throttled
// carrier. Instead of routing the whole machine (0/0) into the tunnel -- which
// overflows a throttled DNS carrier's queue and collapses the tunnel (the café #3
// field failure: queue 256/256, tail-drop, egress-check timeout -> CONN-2a) --
// route only a small low-bandwidth IP allowlist into the tunnel and leave
// everything else on the physical path, where a captive portal blackholes it.
// Admission control by SCOPE, not pacing. See ESSENTIALS-MODE-SPEC.md.
//
// MVP: IP prefixes only, no in-tunnel DNS resolution. 17.0.0.0/8 (Apple push +
// iMessage) needs no DNS to reach; the operator's mail server can be pinned by IP.
// Domain entries + a scoped resolver are Phase 2.
//
// Activation is an env var, deliberately NOT a server-set config field: like the
// other routing test flags, nothing the server sends can turn a client into
// reduced-scope mode, and a release build reaches it only if the launching shell
// sets it. The app-facing opt-in (a user choice when full-tunnel-over-DNS fails)
// is a later step; this is the buildable, desk-testable core.
const essentialsEnv = "FREEWIRE_ESSENTIALS"

// essentialsSeed is the default allowlist when FREEWIRE_ESSENTIALS=1: Apple's
// netblock, which carries APNs push and iMessage and needs no DNS.
var essentialsSeed = []string{"17.0.0.0/8"}

// essentialsConfigAllowlist is the allowlist from the client-assembled stdin
// config (Config.EssentialsAllowlist), set in main after the config is parsed.
// This is the path the app uses; it survives sudo, unlike an env var, and is NOT
// the server's /v1/config, so a server cannot flip a client into reduced scope.
var essentialsConfigAllowlist []string

// essentialsAllowlist returns the parsed CIDR allowlist and whether Essentials
// Mode is active. Source order: the FREEWIRE_ESSENTIALS env var (a direct-binary
// test override) wins; otherwise the stdin config's essentials_allowlist.
//
//	FREEWIRE_ESSENTIALS=1                       -> the seed (17.0.0.0/8)
//	FREEWIRE_ESSENTIALS=17.0.0.0/8,203.0.113.9  -> exactly these (a bare IP = /32)
//	(config) essentials_allowlist: ["17.0.0.0/8", ...]
//
// Invalid entries are reported and skipped; if none parse, the mode is inactive
// (fail safe to full tunnel rather than silently tunnelling nothing).
func essentialsAllowlist() (nets []*net.IPNet, domains []string, active bool) {
	var specs []string
	if raw := strings.TrimSpace(os.Getenv(essentialsEnv)); raw != "" {
		switch raw {
		case "1", "default", "on":
			specs = essentialsSeed
		default:
			specs = strings.Split(raw, ",")
		}
	} else {
		specs = essentialsConfigAllowlist
	}
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// An IP or CIDR is a static route; everything else is a domain suffix,
		// resolved and routed dynamically by the scoped resolver (Phase 2).
		cidr := s
		if !strings.Contains(cidr, "/") && net.ParseIP(cidr) != nil {
			cidr += "/32"
		}
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
			continue
		}
		if d := normalizeEssentialsDomain(s); d != "" {
			domains = append(domains, d)
			continue
		}
		fmt.Fprintf(os.Stderr,
			"freewire-tunnel: essentials: skipping invalid allowlist entry %q (not an IP/CIDR or domain)\n", s)
	}
	return nets, domains, len(nets)+len(domains) > 0
}

// normalizeEssentialsDomain lowercases, strips a leading "*." and a trailing dot,
// and checks the result looks like a hostname (at least one dot, hostname chars
// only). Returns "" if it does not qualify as a domain.
func normalizeEssentialsDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if !strings.Contains(d, ".") {
		return "" // require a dot; bare labels like "localhost" are not essentials
	}
	for _, r := range d {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return ""
		}
	}
	return d
}

// essentialsUpstream picks a public resolver for the scoped resolver to forward
// allowlisted lookups to. Its IP is routed INTO the tunnel, so it must NOT be one
// the carrier pinned OUTSIDE the tunnel (the DNS carrier's own recursor): routing
// the same address both ways would break whichever lost the tie. Returns "ip:53".
func essentialsUpstream(carrierResolvers []string) string {
	pinned := map[string]bool{}
	for _, cr := range carrierResolvers {
		ip := cr
		if h, _, e := net.SplitHostPort(cr); e == nil {
			ip = h
		}
		pinned[ip] = true
	}
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		if !pinned[ip] {
			return ip + ":53"
		}
	}
	return "1.1.1.1:53" // every candidate is a carrier resolver (unlikely)
}

// domainAllowed reports whether qname is an allowlisted domain or a subdomain of
// one. "signal.org" matches "signal.org" and "chat.signal.org", but NOT
// "notsignal.org" (a suffix match on a label boundary, not a substring).
func domainAllowed(qname string, domains []string) bool {
	q := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	for _, d := range domains {
		if q == d || strings.HasSuffix(q, "."+d) {
			return true
		}
	}
	return false
}

// essentialsCIDRs renders the allowlist as canonical CIDR strings, for route
// commands and for cleanup tracking.
func essentialsCIDRs(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// essentialsProbeTarget returns a representative IP inside the first allowlist
// prefix, used to confirm the scope routed INTO the tunnel (allowlisted ->
// utun). For a /32 it is the address itself; otherwise the network address, which
// is enough for a route lookup (interfaceForDest does not send a packet).
func essentialsProbeTarget(nets []*net.IPNet) string {
	if len(nets) == 0 {
		return ""
	}
	return nets[0].IP.String()
}
