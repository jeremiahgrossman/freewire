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
//	                [--server6 2600:1f18:...]      # also probe our server over IPv6
//	                [--cdn d123.cloudfront.net]    # also probe a CDN that fronts us
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
	cdnHost := ""
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
		case "--cdn":
			if i+1 < len(args) {
				cdnHost = args[i+1]
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
	blockSynRST, blockContentRST, blockTimeouts = 0, 0, 0 // fresh accounting per run

	type row struct {
		name string
		open bool
	}
	var rows []row

	// Fast carriers we already ship (TCP side), in speed order.
	rows = append(rows, row{"wireguard UDP/51820", reportCarrier("wireguard UDP/51820",
		func() (net.Conn, error) { return dialUDPProbeless(server, 51820) },
		"socket only; a real select completes the WG handshake")})
	// http_connect is the one shipped carrier that does NOT talk to our server to
	// establish: it asks the LOCAL gateway (3128/8080/443) for a CONNECT proxy and
	// tunnels through it. So it cannot be inferred from any server-directed row --
	// it has to be probed on its own, which is why the field survey needs it
	// explicitly. A "-- no" here just means this portal offers no open CONNECT
	// proxy (the common case); a hit means a whole extra path is available.
	rows = append(rows, row{"HTTP CONNECT (gateway)", reportCarrier("HTTP CONNECT (gateway)",
		func() (net.Conn, error) { return tryHTTPConnect(cfg) },
		"asks the LOCAL gateway for a CONNECT proxy; independent of our server")})
	rows = append(rows, row{"raw TLS/443", reportCarrier("raw TLS/443",
		func() (net.Conn, error) { return tryTLS443(cfg) },
		"a raw TLS session to our IP on 443")})
	wssDirectOK := reportCarrier("WebSocket/443",
		func() (net.Conn, error) { return tryWSS443(cfg) },
		"looks like a website; passes 'web-443-only' portals")
	rows = append(rows, row{"WebSocket/443", wssDirectOK})

	// The CDN-fronted carrier: same WebSocket, but to a CDN edge IP and hostname
	// instead of our server's IP. This is the line that answers "does this portal
	// gate our ADDRESS, or the port?" -- the question that decides whether the
	// CDN-fronted carrier is worth building. See CDN-FRONTED-CARRIER-SPEC.md §9.
	cdnTested := cdnHost != ""
	cdnOK := false
	if cdnTested {
		cdnOK = reportCDN(cdnHost)
		rows = append(rows, row{"CDN WebSocket/443", cdnOK})
	}

	// New carriers we are deciding whether to build (UDP side), via the server's
	// ProbeResponder. A pass means the portal forwards arbitrary UDP to our
	// server on that port -- the green light to build the carrier.
	rows = append(rows, row{"UDP/443 (QUIC-class)",
		reportUDPProbe("UDP/443 (QUIC-class)", net.JoinHostPort(server, "443"),
			"near-line-rate IF this passes; block-QUIC is off by default")})
	rows = append(rows, row{"UDP/123 (NTP-class)",
		reportUDPProbe("UDP/123 (NTP-class)", net.JoinHostPort(server, "123"),
			"raw UDP tunnel IF this passes; portals allow NTP for clock sync")})

	// DNS carrier, server-direct on UDP/53. This is the historical winner at hard
	// captive portals: a portal MUST pass some DNS pre-auth to serve its own
	// redirect, and where it lets outbound 53 reach our authoritative server, the
	// DNS tunnel works (throttled but real). A full handshake, not a reachability
	// ping -- the server has to issue a session token and the client confirm it,
	// so a portal's own resolver answering for a bogus name does not read as OK.
	// Rootless (plain UDP queries). ICMP needs raw sockets (root), so it is NOT in
	// this battery -- run probe-transports.sh with the passwordless-sudo rule for
	// the ICMP carrier.
	rows = append(rows, row{"DNS/53 (server-direct)", reportDNS(cfg, server)})

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
	// The direct-vs-CDN comparison, stated as the engineering decision it drives.
	// Both use the SAME protocol on the SAME port and differ only in destination,
	// so a split between them isolates address gating from port gating -- which
	// is what decides whether the CDN-fronted carrier is worth building.
	// See CDN-FRONTED-CARRIER-SPEC.md §9.
	if cdnTested {
		switch {
		case !wssDirectOK && cdnOK:
			fmt.Fprintln(os.Stderr, "probe-battery: *** THIS PORTAL GATES OUR ADDRESS, NOT THE PORT. ***")
			fmt.Fprintln(os.Stderr, "  Same protocol, same port, different destination: direct FAILED, CDN-fronted WORKED.")
			fmt.Fprintln(os.Stderr, "  This is the hypothesis in CDN-FRONTED-CARRIER-SPEC.md §9 confirmed -- build the carrier.")
		case wssDirectOK && cdnOK:
			fmt.Fprintln(os.Stderr, "probe-battery: both direct and CDN-fronted work; this network is not gating us.")
			fmt.Fprintln(os.Stderr, "  No evidence for or against the CDN carrier here -- it needs a portal that blocks direct.")
		case wssDirectOK && !cdnOK:
			fmt.Fprintln(os.Stderr, "probe-battery: direct works but CDN does not -- unexpected.")
			fmt.Fprintln(os.Stderr, "  Check the distribution is up and serving WebSocket before reading anything into this.")
		default:
			fmt.Fprintln(os.Stderr, "probe-battery: neither direct nor CDN-fronted reached us on 443.")
			fmt.Fprintln(os.Stderr, "  Either a live-SNI portal (CDN-fronting cannot help) or 443 is blocked outright.")
		}
		fmt.Fprintln(os.Stderr)
	}

	// How the blocked carriers were blocked, whenever any were -- it decides what,
	// if anything, is left to try. See classifyBlock for why the RST KIND matters.
	if blockSynRST > 0 || blockContentRST > 0 || blockTimeouts > 0 {
		if blockContentRST > 0 {
			fmt.Fprintln(os.Stderr, "probe-battery: a carrier was RESET AFTER the TCP handshake -- content/SNI gating.")
			fmt.Fprintln(os.Stderr, "  Desync (Geneva/zapret) MIGHT slip past this; see DESYNC-CARRIER-SPEC.md.")
		}
		if blockSynRST > 0 {
			fmt.Fprintln(os.Stderr, "probe-battery: TCP SYN was REFUSED (destination-gated at L4). There is no handshake")
			fmt.Fprintln(os.Stderr, "  to manipulate, so DESYNC CANNOT HELP here. The ways through are a permitted")
			fmt.Fprintln(os.Stderr, "  destination (CDN, if its edge is allow-listed) or a leaked family (v6), or DNS.")
		}
		if blockTimeouts > 0 && blockSynRST == 0 && blockContentRST == 0 {
			fmt.Fprintln(os.Stderr, "probe-battery: blocked carriers were SILENTLY DROPPED (timeout) -- a hard L3 ACL;")
			fmt.Fprintln(os.Stderr, "  no client trick beats it. The ways out are a permitted destination (CDN) or v6.")
		}
	}

	if best == "" {
		fmt.Fprintln(os.Stderr, "probe-battery: NOTHING reached the server. This network blocks every carrier tested.")
		if !cdnTested {
			fmt.Fprintln(os.Stderr, "  If it gated our server's IP specifically, the next lever is a CDN-fronted carrier:")
			fmt.Fprintln(os.Stderr, "  re-run with --cdn <distribution>.cloudfront.net to test that. See CDN-FRONTED-CARRIER-SPEC.md.")
		}
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
		recordBlock(err)
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s%s\n", label, "-- no", blockTag(err), trimErr(err))
		return false
	}
	conn.Close()
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()), note)
	return true
}

// Block-type accounting. The distinction that matters is WHERE the reject
// happens, because it decides whether client-side desync (Geneva/zapret) could
// ever help:
//
//   - syn-rst: the TCP SYN itself is refused ("connection refused" -- a dial
//     failure). The portal gates by DESTINATION at L4, before any TLS/SNI. There
//     is no handshake to manipulate, so desync CANNOT help. This is what the café
//     did on 2026-08-25.
//   - content-rst: the TCP handshake COMPLETED and the connection was reset later
//     ("connection reset by peer" mid-stream, i.e. after dial). The portal gates
//     on CONTENT (the SNI). Desync -- splitting the ClientHello, low-TTL/bad-
//     checksum decoys to poison the middlebox's stream state -- MIGHT slip past.
//   - timeout: silently dropped. A hard L3 ACL; no client trick beats it.
//
// Lumping the two RST kinds together (the earlier version did) gives a
// misleading "possibly desyncable" for a destination SYN-RST, which is exactly
// the case desync cannot touch. So they are counted separately.
var blockSynRST, blockContentRST, blockTimeouts int

func recordBlock(err error) {
	switch classifyBlock(err) {
	case "syn-rst":
		blockSynRST++
	case "content-rst":
		blockContentRST++
	case "timeout":
		blockTimeouts++
	}
}

func classifyBlock(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "syn-rst" // RST in response to the SYN: destination-gated at L4
	case strings.Contains(s, "reset"):
		return "content-rst" // reset after the handshake: content/SNI-gated
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"), strings.Contains(s, "no route"):
		return "timeout"
	default:
		return ""
	}
}

func blockTag(err error) string {
	switch classifyBlock(err) {
	case "syn-rst":
		return "[SYN-RST] "
	case "content-rst":
		return "[reset] "
	case "timeout":
		return "[timeout] "
	default:
		return ""
	}
}

// reportDNS runs a real server-direct DNS-tunnel handshake to server:53 and
// reports whether it completes -- i.e. whether the portal passes outbound UDP/53
// to our authoritative server, which is what the DNS carrier needs.
func reportDNS(cfg Config, server string) bool {
	const label = "DNS/53 (server-direct)"
	start := time.Now()
	dcfg := cfg
	dcfg.ServerHost = server
	// Query our authoritative server directly, bypassing any recursor -- the
	// server-direct path is the one that actually carries throughput.
	_, err := dnsHandshake(dcfg, []string{net.JoinHostPort(server, "53")}, dnsHandshakeTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s%s\n", label, "-- no", blockTag(err), trimErr(err))
		recordBlock(err)
		return false
	}
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()),
		"the fallback that survives hard captive portals (throttled but real)")
	return true
}

// reportCDN opens a WebSocket to a CDN hostname that fronts our server, and
// reports the edge IP it landed on.
//
// It reuses tryWSS443 unchanged, so the probe exercises the exact code path the
// CDN carrier would use -- with two deliberate differences from the direct
// carriers: the dial targets the CDN hostname (so DNS picks a nearby edge), and
// InsecureTLS is forced OFF. A real CDN hostname has a real certificate chain,
// so accepting an invalid one here would be accepting a portal's MITM rather
// than tolerating our origin's self-signed cert.
//
// The edge IP is printed because it is field data we need twice over: it
// identifies which CDN range the portal is letting through, and it is the
// address the carrier would have to pin outside the tunnel (spec §2 -- pinning
// only our server's IP would loop the carrier's own packets back into the
// tunnel).
func reportCDN(cdnHost string) bool {
	const label = "CDN WebSocket/443"
	cfg := Config{ServerHost: cdnHost, TLSPort: 443, InsecureTLS: false}

	start := time.Now()
	conn, err := tryWSS443(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", trimErr(err))
		return false
	}
	edge := ""
	if ra := conn.RemoteAddr(); ra != nil {
		if h, _, e := net.SplitHostPort(ra.String()); e == nil {
			edge = h
		}
	}
	conn.Close()
	fmt.Fprintf(os.Stderr, "  %-24s %-11s via edge %s\n", label,
		fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()), edge)
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
