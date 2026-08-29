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
func essentialsAllowlist() (nets []*net.IPNet, active bool) {
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
	if len(specs) == 0 {
		return nil, false
	}
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"freewire-tunnel: essentials: skipping invalid allowlist entry %q: %v\n", s, err)
			continue
		}
		nets = append(nets, n)
	}
	return nets, len(nets) > 0
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
