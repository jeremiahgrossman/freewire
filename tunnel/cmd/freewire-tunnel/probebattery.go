package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The probe battery: one command that measures, at a real captive portal, which
// carriers this network actually passes to OUR server -- the only test that
// matters under destination-based walled gardens, where "UDP/443 reaches Google"
// says nothing about whether it reaches us.
//
//	freewire-tunnel --probe-battery --server 52.203.246.145 [--insecure]
//	                [--server6 2600:1f18:...]   # also probe our server over IPv6
//
// Non-routed and rootless: every probe is a single connection or datagram to the
// server (or, for the v6-egress line, a reachability check). It changes no
// routes, no resolver, no utun, so it is safe to run on a machine in use, from a
// café table. See PORTAL-CARRIER-IDEATION-2026-08-24.md.
//
// The UDP probes speak the server's ProbeResponder wire format. These constants
// MUST match server/internal/transport/probe.go.
var probeMagic = []byte("FWPROBE1")

const (
	probeNonceLen   = 16
	probeMinRequest = 64
)

func probeBattery(args []string) int {
	server := ""
	server6 := ""
	insecure := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				server = args[i+1]
				i++
			}
		case "--server6":
			if i+1 < len(args) {
				server6 = args[i+1]
				i++
			}
		case "--insecure":
			insecure = true
		default:
			fmt.Fprintf(os.Stderr, "probe-battery: unknown argument %q\n", args[i])
			return 2
		}
	}
	if server == "" {
		fmt.Fprintln(os.Stderr, "probe-battery: --server is required")
		return 2
	}

	fmt.Fprintf(os.Stderr, "probe-battery: measuring what THIS network passes to %s\n", server)
	fmt.Fprintln(os.Stderr, "  (each line probes OUR server -- the only test that matters under")
	fmt.Fprintln(os.Stderr, "   destination-based walled gardens)")
	fmt.Fprintf(os.Stderr, "\n  %-24s %-11s %s\n", "CARRIER", "RESULT", "NOTE")

	cfg := Config{ServerHost: server, TLSPort: 443, InsecureTLS: insecure}

	type row struct {
		name string
		open bool
	}
	var rows []row

	// Fast carriers we already ship (TCP side), in speed order.
	rows = append(rows, row{"wireguard UDP/51820", reportCarrier("wireguard UDP/51820",
		func() (net.Conn, error) { return dialUDPProbeless(server, 51820) },
		"socket only; a real select completes the WG handshake")})
	rows = append(rows, row{"raw TLS/443", reportCarrier("raw TLS/443",
		func() (net.Conn, error) { return tryTLS443(cfg) },
		"a raw TLS session to our IP on 443")})
	rows = append(rows, row{"WebSocket/443", reportCarrier("WebSocket/443",
		func() (net.Conn, error) { return tryWSS443(cfg) },
		"looks like a website; passes 'web-443-only' portals")})

	// New carriers we are deciding whether to build (UDP side), via the server's
	// ProbeResponder. A pass means the portal forwards arbitrary UDP to our
	// server on that port -- the green light to build the carrier.
	rows = append(rows, row{"UDP/443 (QUIC-class)",
		reportUDPProbe("UDP/443 (QUIC-class)", net.JoinHostPort(server, "443"),
			"near-line-rate IF this passes; block-QUIC is off by default")})
	rows = append(rows, row{"UDP/123 (NTP-class)",
		reportUDPProbe("UDP/123 (NTP-class)", net.JoinHostPort(server, "123"),
			"raw UDP tunnel IF this passes; portals allow NTP for clock sync")})

	// IPv6 egress: a whole-address-family bypass when a v4-only portal leaks v6.
	rows = append(rows, row{"IPv6 egress", reportV6(server6)})

	// Verdict.
	fmt.Fprintln(os.Stderr)
	best := ""
	for _, r := range rows {
		if r.open {
			best = r.name
			break // rows are in speed order
		}
	}
	if best == "" {
		fmt.Fprintln(os.Stderr, "probe-battery: NOTHING reached the server. This network blocks every carrier tested.")
		fmt.Fprintln(os.Stderr, "  If it also gated our server's IP specifically, the next lever is a CDN-fronted")
		fmt.Fprintln(os.Stderr, "  carrier (see PORTAL-CARRIER-IDEATION-2026-08-24.md), which this battery cannot test yet.")
		return 1
	}
	fmt.Fprintf(os.Stderr, "probe-battery: fastest carrier that reached the server: %s\n", best)
	for _, r := range rows {
		switch r.name {
		case "UDP/443 (QUIC-class)":
			if r.open {
				fmt.Fprintln(os.Stderr, "  *** UDP/443 passes to our server: build the QUIC-class carrier -- it beats WSS (no TCP-over-TCP). ***")
			}
		case "IPv6 egress":
			if r.open {
				fmt.Fprintln(os.Stderr, "  *** IPv6 egress reaches our server: a v6 WireGuard endpoint would run at full speed here. ***")
			}
		}
	}
	return 0
}

// reportCarrier runs one stream-carrier open, prints a line, returns whether it
// opened. Opening is the bar (not carrying real traffic): the battery is a
// reachability survey; the fall-through selection is what proves traffic later.
func reportCarrier(label string, open func() (net.Conn, error), note string) bool {
	start := time.Now()
	conn, err := open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", trimErr(err))
		return false
	}
	conn.Close()
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()), note)
	return true
}

// reportUDPProbe sends a magic probe to the server's ProbeResponder at addr and
// reports whether the echo returns -- i.e. whether the portal forwards arbitrary
// UDP to our server on that port.
func reportUDPProbe(label, addr, note string) bool {
	rtt, ok, err := udpReachProbe(addr, 3*time.Second)
	if !ok {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", noteOrBlocked(err))
		return false
	}
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", rtt.Milliseconds()), note)
	return true
}

// udpReachProbe sends probeMagic+nonce (padded to the responder's minimum) and
// waits for the echoed nonce. A reply that does not echo our nonce is treated as
// not-ours (an unrelated datagram on the port), not a pass.
func udpReachProbe(addr string, timeout time.Duration) (time.Duration, bool, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()

	nonce := make([]byte, probeNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return 0, false, err
	}
	req := make([]byte, 0, probeMinRequest)
	req = append(req, probeMagic...)
	req = append(req, nonce...)
	for len(req) < probeMinRequest {
		req = append(req, 0)
	}

	start := time.Now()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck
	if _, err := conn.Write(req); err != nil {
		return 0, false, err
	}
	// A portal that silently drops the datagram gives a read timeout, which is
	// the expected "blocked" outcome, not an error worth surfacing loudly.
	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil {
		return 0, false, nil
	}
	if n >= len(probeMagic)+probeNonceLen &&
		bytes.HasPrefix(resp[:n], probeMagic) &&
		bytes.Equal(resp[len(probeMagic):len(probeMagic)+probeNonceLen], nonce) {
		return time.Since(start), true, nil
	}
	return 0, false, nil
}

// reportV6 reports whether this network offers IPv6 egress. With server6 set it
// probes our server's ProbeResponder over v6 (the definitive test). Otherwise it
// checks for a global v6 default route and reachability to a public v6 anchor --
// a weaker signal (destination gating means public-v6-reachable does not
// guarantee our-server-reachable), reported as MAYBE and not counted as a pass.
func reportV6(server6 string) bool {
	const label = "IPv6 egress"
	if !hasGlobalV6Route() {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", "no global IPv6 default route on this network")
		return false
	}
	if server6 != "" {
		rtt, ok, _ := udpReachProbe(net.JoinHostPort(server6, "443"), 3*time.Second)
		if ok {
			fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
				fmt.Sprintf("OK %dms", rtt.Milliseconds()), "UDP reached OUR server over IPv6")
			return true
		}
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", "v6 route present but our server unreachable over v6")
		return false
	}
	// No v6 server address to aim at: fall back to a public v6 reachability
	// check. Cloudflare's v6 resolver is a stable anchor.
	c, err := net.DialTimeout("tcp", "[2606:4700:4700::1111]:443", 3*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", "v6 route present but no v6 egress (null-routed pre-auth?)")
		return false
	}
	c.Close()
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "MAYBE",
		"v6 egress to a public host works; give --server6 to confirm OURS")
	return false
}

// hasGlobalV6Route reports whether the machine has an IPv6 default route -- the
// precondition for any v6 egress. macOS `route -n get -inet6 default` names the
// route's gateway/interface, or says it is not in the table.
func hasGlobalV6Route() bool {
	out, err := exec.Command("route", "-n", "get", "-inet6", "default").CombinedOutput()
	if err != nil {
		return false
	}
	s := string(out)
	if strings.Contains(s, "not in table") || strings.Contains(s, "route has not been found") {
		return false
	}
	return strings.Contains(s, "gateway:") || strings.Contains(s, "interface:")
}

// dialUDPProbeless opens a UDP socket to host:port. For direct WireGuard this is
// as far as a rootless, non-handshaking probe can go -- a real selection would
// complete the WireGuard handshake -- so it is reported honestly as a socket
// check, not a working tunnel.
func dialUDPProbeless(host string, port int) (net.Conn, error) {
	return net.DialTimeout("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), 2*time.Second)
}

func trimErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s)-i < 40 {
		return s[i+2:]
	}
	if len(s) > 52 {
		return s[:52]
	}
	return s
}

func noteOrBlocked(err error) string {
	if err != nil {
		return trimErr(err)
	}
	return "blocked (no reply)"
}
