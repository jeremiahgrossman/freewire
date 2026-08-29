package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
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
		// shipped marks a carrier the app can actually select. The "fastest carrier
		// that reached the server" verdict must consider ONLY these -- a candidate
		// probe (UDP/123, IPv6) that has no client carrier must never be crowned
		// fastest, or the survey would name a path the app cannot take.
		shipped bool
	}
	var rows []row

	// Rows are emitted in the app's REAL carrier order (defaultCandidates in
	// transport.go), so the "fastest that reached the server" verdict names the
	// same carrier the app would actually pick: wireguard -> udp443 -> http_connect
	// -> tls443 -> wss443 -> cdn_wss -> dns. Keep this in sync with that chain.

	// 1. WireGuard direct, UDP/51820. Fastest; what an open network lands on.
	rows = append(rows, row{"wireguard UDP/51820", reportCarrier("wireguard UDP/51820",
		func() (net.Conn, error) { return dialUDPProbeless(server, 51820) },
		"socket only; a real select completes the WG handshake"), true})

	// 2. udp443: WireGuard straight over UDP/443. SAME speed as direct (no
	// TCP-over-TCP), one port portals pass far more often -- so it is the app's #2,
	// not a sixth-place candidate. Probed via the server's ProbeResponder; a pass
	// means the portal forwards arbitrary UDP to us on 443.
	rows = append(rows, row{"UDP/443 (udp443 carrier)",
		reportUDPProbe("UDP/443 (udp443 carrier)", net.JoinHostPort(server, "443"),
			"near-line-rate, no TCP-over-TCP; the app's #2 carrier"), true})

	// 2b. UDP/123: a CANDIDATE raw-UDP tunnel (not built), grouped with the UDP
	// probes for readability. Not shipped, so it is excluded from the verdict.
	rows = append(rows, row{"UDP/123 (NTP-class, candidate)",
		reportUDPProbe("UDP/123 (NTP-class, candidate)", net.JoinHostPort(server, "123"),
			"raw UDP tunnel IF built; portals allow NTP for clock sync"), false})

	// 3. http_connect: the one shipped carrier that does NOT talk to our server to
	// establish -- it asks the LOCAL gateway (3128/8080/443) for a CONNECT proxy
	// and tunnels through it. It cannot be inferred from any server-directed row,
	// so the field survey has to probe it explicitly. A "-- no" just means this
	// portal offers no open CONNECT proxy (the common case); a hit means a whole
	// extra path is available.
	rows = append(rows, row{"HTTP CONNECT (gateway)", reportCarrier("HTTP CONNECT (gateway)",
		func() (net.Conn, error) { return tryHTTPConnect(cfg) },
		"asks the LOCAL gateway for a CONNECT proxy; independent of our server"), true})

	// 3b. TCP/80: a CANDIDATE (not built). Worth a line for a reason peculiar to
	// captive portals: a portal MUST do something with :80 to serve its own
	// redirect, and one that transparently PROXIES it rather than dropping it
	// will forward a Host-carrying request to our origin -- which a WebSocket
	// upgrade away is a carrier. The probe fetches a magic path and checks the
	// echoed nonce, so a portal's own login page answering on :80 reads as a
	// miss, not a pass.
	rows = append(rows, row{"TCP/80 (HTTP, candidate)", reportHTTP80(server),
		false})

	// 4. tls443: a raw TLS session to our IP on 443.
	rows = append(rows, row{"raw TLS/443", reportCarrier("raw TLS/443",
		func() (net.Conn, error) { return tryTLS443(cfg) },
		"a raw TLS session to our IP on 443"), true})

	// 5. wss443: WebSocket over TLS/443; passes 'web-443-only' portals.
	wssDirectOK := reportCarrier("WebSocket/443",
		func() (net.Conn, error) { return tryWSS443(cfg) },
		"looks like a website; passes 'web-443-only' portals")
	rows = append(rows, row{"WebSocket/443", wssDirectOK, true})

	// 6. cdn_wss: same WebSocket, but to a CDN edge IP and hostname instead of our
	// server's IP. The line that answers "does this portal gate our ADDRESS, or the
	// port?" -- and the only carrier that beats destination gating. Skipped unless
	// a CDN host was given. See CDN-FRONTED-CARRIER-SPEC.md §9.
	cdnTested := cdnHost != ""
	cdnOK := false
	if cdnTested {
		cdnOK = reportCDN(cdnHost)
		rows = append(rows, row{"CDN WebSocket/443", cdnOK, true})
	}

	// 6b. dns_tcp: WireGuard over a TCP connection to our port 53. SHIPPED, and
	// it sits here because that is its place in the real chain: below the
	// 443-family carriers (same TCP-over-TCP penalty, less throughput) and above
	// the UDP DNS tunnel, which it beats by ~56x measured (32 Mbps vs ~0.57).
	// The magic exchange matters more here than anywhere else in this battery:
	// port 53 is the port most likely to be intercepted by a transparent DNS
	// proxy, so a connection that merely opens proves nothing.
	rows = append(rows, row{"TCP/53 (dns_tcp carrier)",
		reportTCPProbe("TCP/53 (dns_tcp carrier)", net.JoinHostPort(server, "53"),
			"WireGuard over TCP/53; ~56x the UDP DNS tunnel, and TCP gives real backpressure"), true})

	// 7. dns: server-direct on UDP/53. The historical winner at hard captive
	// portals: a portal MUST pass some DNS pre-auth to serve its own redirect, and
	// where it lets outbound 53 reach our authoritative server, the DNS tunnel
	// works (throttled but real). A full handshake, not a reachability ping -- the
	// server issues a session token and the client confirms it, so a portal's own
	// resolver answering for a bogus name does not read as OK. Rootless (plain UDP
	// queries). ICMP needs raw sockets (root), so it is NOT in this battery -- run
	// probe-transports.sh with the passwordless-sudo rule for the ICMP carrier.
	rows = append(rows, row{"DNS/53 (server-direct)", reportDNS(cfg, server), true})

	// 7c. TCP/853: a CANDIDATE (not built). DoT's port, which walled gardens
	// sometimes pass because Android Private DNS breaks without it.
	rows = append(rows, row{"TCP/853 (DoT-class)",
		reportTCPProbe("TCP/853 (DoT-class)", net.JoinHostPort(server, "853"),
			"portals sometimes pass it so Android Private DNS keeps working"), false})

	// IPv6 egress: a whole-address-family bypass IF a v4-only portal leaks v6. The
	// client carrier (leak-safe v6 routing) is NOT built yet, so this is a
	// candidate, excluded from the verdict.
	rows = append(rows, row{"IPv6 egress", reportV6(server6), false})

	// Verdict.
	fmt.Fprintln(os.Stderr)
	best := ""
	for _, r := range rows {
		if r.open && r.shipped {
			best = r.name
			break // rows are in the app's real speed order; shipped-only
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
		case "TCP/53 (dns_tcp carrier)":
			if r.open {
				fmt.Fprintln(os.Stderr, "  *** TCP/53 reaches our server: the dns_tcp carrier works here, at roughly 56x the")
				fmt.Fprintln(os.Stderr, "      UDP DNS tunnel and with real backpressure instead of tail-drop. ***")
			}
		case "TCP/80 (HTTP, candidate)":
			if r.open {
				fmt.Fprintln(os.Stderr, "  *** TCP/80 reaches OUR origin: this portal proxies or passes :80, so a plain-HTTP")
				fmt.Fprintln(os.Stderr, "      WebSocket carrier would work here even though 443 does not. ***")
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

// reportTCPProbe opens a TCP connection to addr and runs the same magic probe
// the UDP lines run, against the server's TCP ProbeResponder.
//
// Why the magic exchange and not a bare connect: a captive portal that
// intercepts a port answers the SYN itself, so a successful dial proves only
// that SOMETHING accepted, not that we reached our server. Echoing our nonce is
// what distinguishes our origin from the portal. This is the same reason
// reportDNS runs a full handshake rather than a reachability ping.
func reportTCPProbe(label, addr, note string) bool {
	rtt, ok, err := tcpReachProbe(addr, 3*time.Second)
	if !ok {
		// Deliberately NOT recorded in the block accounting, matching the other
		// candidate probes (UDP/123, IPv6). These ports are answered only by a
		// server built after 2026-08-28, so before a redeploy they fail on OUR
		// side, and counting them would print "hard L3 ACL" on an open network.
		// The inline tag still reports how each was blocked.
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s%s\n", label, "-- no", blockTag(err), noteOrBlocked(err))
		return false
	}
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", rtt.Milliseconds()), note)
	return true
}

// tcpReachProbe sends probeMagic+nonce (padded to the responder's minimum) over
// TCP and waits for the echoed nonce.
//
// A reply that does not echo our nonce is NOT a pass: it means something other
// than our server accepted the connection, which on a captive portal is the
// expected interception, not reachability. That case returns a nil error, since
// "answered by the wrong host" is a portal behaviour rather than a transport
// error, and classifying it as a block kind would misreport what happened.
func tcpReachProbe(addr string, timeout time.Duration) (time.Duration, bool, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
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
		// A write that fails after a successful dial is a mid-stream reject,
		// which classifyBlock reads as content gating -- worth surfacing.
		return 0, false, err
	}
	want := len(probeMagic) + probeNonceLen
	resp := make([]byte, want)
	if _, err := io.ReadFull(conn, resp); err != nil {
		// A portal that accepts the SYN and then says nothing (or resets) lands
		// here. Return the error so the block kind is classified.
		return 0, false, err
	}
	if bytes.HasPrefix(resp, probeMagic) && bytes.Equal(resp[len(probeMagic):want], nonce) {
		return time.Since(start), true, nil
	}
	return 0, false, nil
}

// httpProbePath must match server/internal/transport/probe.go's HTTPProbePath.
const httpProbePath = "/.freewire-probe"

// reportHTTP80 fetches the magic path over plain HTTP on port 80 and checks the
// echoed nonce.
//
// Port 80 cannot use the raw magic protocol: on an ACME deployment autocert owns
// that port for the HTTP-01 challenge, so our responder rides along as its
// fallback handler and speaks HTTP. That is also the right shape for the
// question being asked -- a portal that transparently proxies :80 forwards HTTP,
// not arbitrary bytes, so an HTTP request is what would actually get through.
func reportHTTP80(server string) bool {
	const label = "TCP/80 (HTTP, candidate)"
	start := time.Now()
	ok, detail := httpProbe(net.JoinHostPort(server, "80"))
	if !ok {
		fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label, "-- no", detail)
		return false
	}
	fmt.Fprintf(os.Stderr, "  %-24s %-11s %s\n", label,
		fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()),
		"the portal passes or proxies :80 to us; a plain-HTTP WS carrier would work")
	return true
}

// httpProbeOK is httpProbe's boolean half, for tests.
func httpProbeOK(hostport string) bool {
	ok, _ := httpProbe(hostport)
	return ok
}

// httpProbe fetches the magic path from hostport and reports whether OUR origin
// answered, plus a human-readable reason when it did not.
func httpProbe(hostport string) (bool, string) {
	nonce := make([]byte, probeNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return false, trimErr(err)
	}
	url := fmt.Sprintf("http://%s%s?nonce=%s", hostport, httpProbePath, hex.EncodeToString(nonce))

	// No redirect following: a portal's answer to :80 is a redirect to its login
	// page, and chasing it would turn an interception into a 200 that looks like
	// a pass. The nonce check would still catch it, but not following makes the
	// intent explicit and keeps the probe from touching the portal's login host.
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(url)
	if err != nil {
		// Not recorded in the block accounting: see reportTCPProbe. Port 80
		// answers the probe only on a server built after 2026-08-28.
		return false, blockTag(err) + trimErr(err)
	}
	defer resp.Body.Close()

	want := len(probeMagic) + probeNonceLen
	body := make([]byte, want)
	if _, err := io.ReadFull(resp.Body, body); err != nil ||
		!bytes.HasPrefix(body, probeMagic) || !bytes.Equal(body[len(probeMagic):want], nonce) {
		// Reached something on :80, but not us. On a captive portal this is the
		// normal case (the login page), so it is reported as a miss with the
		// reason rather than as a transport error -- it is portal behaviour, not
		// a block kind, and counting it as one would skew the verdict.
		return false, fmt.Sprintf("answered by something else (HTTP %d), not our origin", resp.StatusCode)
	}
	return true, ""
}
