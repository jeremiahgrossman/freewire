package main

import (
	"fmt"
	"net"
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

// icmpProbe runs only the ICMP/UDP tunnel handshake against the server and
// reports whether it completes. Unlike the DNS transport it talks straight to
// the server's UDP port (no resolver, no delegation), so it proves the ICMP
// carrier end to end. Like the DNS probes it starts no forwarding goroutine and
// changes no system state, so it is safe on a machine in use.
//
//	freewire-tunnel --icmp-probe [--server 52.203.246.145] [--port 4500]
func icmpProbe(args []string) int {
	server := "52.203.246.145" // current deployment; override with --server
	port := 4500

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				server = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					port = n
				}
				i++
			}
		default:
			fmt.Fprintf(os.Stderr, "icmp-probe: unknown argument %q\n", args[i])
			return 2
		}
	}

	fmt.Fprintf(os.Stderr, "icmp-probe: handshake to %s:%d\n", server, port)
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "icmp-probe: resolve: %v\n", err)
		return 1
	}
	uc, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "icmp-probe: dial: %v\n", err)
		return 1
	}
	defer uc.Close()

	cfg := Config{ServerHost: server, ICMPUDPPort: port}
	start := time.Now()
	sess, err := icmpHandshake(cfg, uc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "icmp-probe: FAIL handshake: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "icmp-probe: handshake OK in %s (server issued session token %x)\n",
		time.Since(start).Round(time.Millisecond), sess.sessionToken)

	// A keepalive round trip proves the post-handshake data-plane path too.
	if err := sess.sendKeepalive(); err != nil {
		fmt.Fprintf(os.Stderr, "icmp-probe: WARN post-handshake keepalive failed: %v\n", err)
		return 3
	}
	fmt.Fprintln(os.Stderr, "icmp-probe: post-handshake keepalive OK -- ICMP/UDP transport is live end to end")
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
	duration := time.Duration(0) // >0 runs for a wall-clock span instead of a fixed count

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
		case "--duration":
			if v, ok := next(); ok {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					duration = time.Duration(n) * time.Second
				}
			}
		default:
			fmt.Fprintf(os.Stderr, "dns-throughput: unknown argument %q\n", args[i])
			return 2
		}
	}

	if duration > 0 {
		return dnsThroughputSustained(domain, resolver, duration, concurrency)
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

// dnsThroughputSustained runs the DNS transport at full tilt for a wall-clock
// span, sampling per second. A burst measurement can miss what only appears
// under duration: a resolver that allows a short burst then throttles, sliding
// window collapse, growing loss, or reassembly falling behind. A real session
// runs for minutes, so this is the shape that matches it.
func dnsThroughputSustained(domain, resolver string, duration time.Duration, concurrency int) int {
	cfg := Config{DNSTunnelDomain: domain}
	zone := effectiveDNSTunnelDomain(cfg)
	perQuery := dnsFragCipherBytes(zone)
	fmt.Fprintf(os.Stderr, "dns-throughput: zone %q via %s, sustained %s at concurrency %d (%d bytes/query)\n",
		zone, resolver, duration, concurrency, perQuery)

	sess, err := dnsHandshake(cfg, resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns-throughput: FAIL handshake: %v\n", err)
		return 1
	}

	var ok, failed int64
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if _, err := sess.poll(); err != nil {
					atomic.AddInt64(&failed, 1)
				} else {
					atomic.AddInt64(&ok, 1)
				}
			}
		}()
	}

	// Sample once a second so a mid-run collapse is visible, not just the average.
	start := time.Now()
	prev := int64(0)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var minKbps, maxKbps float64 = 1e18, 0
	for sec := 1; time.Now().Before(deadline); sec++ {
		<-ticker.C
		cur := atomic.LoadInt64(&ok)
		delta := cur - prev
		prev = cur
		kbps := float64(delta) * float64(perQuery) * 8 / 1000
		if kbps < minKbps {
			minKbps = kbps
		}
		if kbps > maxKbps {
			maxKbps = kbps
		}
		fmt.Fprintf(os.Stderr, "  t+%2ds: %4d q/s  ~%4.0f Kbps\n", sec, delta, kbps)
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := atomic.LoadInt64(&ok)
	fails := atomic.LoadInt64(&failed)
	avgQps := float64(total) / elapsed.Seconds()
	avgKbps := avgQps * float64(perQuery) * 8 / 1000
	lossPct := 0.0
	if total+fails > 0 {
		lossPct = float64(fails) / float64(total+fails) * 100
	}
	fmt.Fprintf(os.Stderr, "dns-throughput: sustained %.0f Kbps avg (min %.0f, max %.0f) over %s\n",
		avgKbps, minKbps, maxKbps, elapsed.Round(time.Second))
	fmt.Fprintf(os.Stderr, "dns-throughput: %d ok, %d failed (%.1f%% loss)\n", total, fails, lossPct)
	return 0
}
