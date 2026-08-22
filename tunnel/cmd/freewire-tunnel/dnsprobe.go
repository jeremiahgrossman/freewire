package main

import (
	"fmt"
	"os"
	"time"
)

// dnsProbe runs only the DNS tunnel handshake against a resolver and reports
// whether it completes. It proves the DNS transport works end to end through
// that resolver's delegation path -- ClientHello, ServerHello and ClientConfirm
// carried inside DNS queries a recursive resolver forwards to the authoritative
// server -- without ever touching system routing or the system resolver. That
// distinction is deliberate: the full tunnel takes over DNS and the default
// route, which on a slow transport makes the whole machine unusable. This does
// not, so it is safe to run on a machine in use.
//
//	freewire-tunnel --dns-probe [--resolver 1.1.1.1] [--domain t.pinghop.net]
//
// A bare reachability check (dig for a bogus name) only shows the resolver can
// reach the server. This exercises the protocol: the server has to issue a real
// session token and derive a shared key, and the client has to confirm it.
func dnsProbe(args []string) int {
	resolver := "1.1.1.1"
	domain := "" // empty -> effectiveDNSTunnelDomain falls back to the default

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--resolver":
			if i+1 < len(args) {
				resolver = args[i+1]
				i++
			}
		case "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		default:
			fmt.Fprintf(os.Stderr, "dns-probe: unknown argument %q\n", args[i])
			return 2
		}
	}

	cfg := Config{DNSTunnelDomain: domain}
	zone := effectiveDNSTunnelDomain(cfg)
	fmt.Fprintf(os.Stderr, "dns-probe: handshake for zone %q via resolver %s\n", zone, resolver)

	start := time.Now()
	sess, err := dnsHandshake(cfg, resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns-probe: FAIL handshake: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dns-probe: handshake OK in %s (server issued session token %s)\n",
		time.Since(start).Round(time.Millisecond), sess.tokenB32)

	// Prove the post-handshake data-plane query path round-trips too. A probe
	// carries no WireGuard traffic, so the server has nothing queued and poll
	// returns (nil, nil); an error means the data-plane query itself failed.
	if _, err := sess.poll(); err != nil {
		fmt.Fprintf(os.Stderr, "dns-probe: WARN post-handshake poll failed: %v\n", err)
		return 3
	}
	fmt.Fprintln(os.Stderr, "dns-probe: post-handshake poll OK -- DNS transport is live end to end")
	return 0
}
