package main

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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

// dnsThroughput measures how many DNS round trips per second the resolver,
// delegation and server sustain, and translates that into an upper bound on
// upstream tunnel throughput. It does not route traffic or take over the system
// resolver, so it is safe on a machine in use.
//
//	freewire-tunnel --dns-throughput [--resolver 1.1.1.1] [--count 300] [--concurrency 8]
//
// The number that matters for the DNS tunnel is not bandwidth to the server --
// the server has 166 Mbps -- but how fast a resolver will carry a stream of
// queries to a single zone before its own rate limits or a slow recursion path
// throttle it. That, times the ciphertext each query carries (dnsFragCipherBytes),
// bounds real upstream throughput. Concurrency mirrors the tunnel's sliding
// window: the live tunnel pipelines queries rather than sending them one at a
// time, so a serial measurement would understate capacity.
func dnsThroughput(args []string) int {
	resolver := "1.1.1.1"
	domain := ""
	count := 300
	concurrency := 8

	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch args[i] {
		case "--resolver":
			if v, ok := next(); ok {
				resolver = v
			}
		case "--domain":
			if v, ok := next(); ok {
				domain = v
			}
		case "--count":
			if v, ok := next(); ok {
				if n, err := strconv.Atoi(v); err == nil {
					count = n
				}
			}
		case "--concurrency":
			if v, ok := next(); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					concurrency = n
				}
			}
		default:
			fmt.Fprintf(os.Stderr, "dns-throughput: unknown argument %q\n", args[i])
			return 2
		}
	}

	cfg := Config{DNSTunnelDomain: domain}
	zone := effectiveDNSTunnelDomain(cfg)
	perQuery := dnsFragCipherBytes(zone)
	fmt.Fprintf(os.Stderr, "dns-throughput: zone %q via %s, %d queries at concurrency %d (%d ciphertext bytes/query)\n",
		zone, resolver, count, concurrency, perQuery)

	sess, err := dnsHandshake(cfg, resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns-throughput: FAIL handshake: %v\n", err)
		return 1
	}

	var done, failed int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for atomic.AddInt64(&done, 1) <= int64(count) {
				if _, err := sess.poll(); err != nil {
					atomic.AddInt64(&failed, 1)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	fails := atomic.LoadInt64(&failed)
	ok := int64(count) - fails
	qps := float64(ok) / elapsed.Seconds()
	// Upper bound: every query carrying a full ciphertext fragment upstream.
	kbps := qps * float64(perQuery) * 8 / 1000

	fmt.Fprintf(os.Stderr, "dns-throughput: %d/%d queries ok in %s\n", ok, count, elapsed.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "dns-throughput: %.0f queries/sec  ->  ~%.0f Kbps upstream ceiling\n", qps, kbps)
	if fails > 0 {
		fmt.Fprintf(os.Stderr, "dns-throughput: %d queries failed (resolver throttling or loss)\n", fails)
	}
	return 0
}
