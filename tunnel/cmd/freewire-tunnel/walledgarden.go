package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
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
	server := defaultWGServer
	cdnHost := defaultWGCDNHost
	domain := defaultDNSTunnelDomain
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				server, i = args[i+1], i+1
			}
		case "--cdn":
			if i+1 < len(args) {
				cdnHost, i = args[i+1], i+1
			}
		case "--domain":
			if i+1 < len(args) {
				domain, i = args[i+1], i+1
			}
		default:
			fmt.Fprintf(os.Stderr, "walled-garden: unknown argument %q\n", args[i])
			return 2
		}
	}

	type dest struct {
		label  string
		host   string
		verify bool // verify the real cert (a real public site) vs TCP+any-TLS (our self-signed server)
		why    string
		// frontable marks a provider we could actually host a fronted carrier on.
		// It lives HERE rather than in a second list of label strings: the verdict
		// below used to re-state the labels, and one of them ("Cloudflare
		// (1.1.1.1)" vs the actual "Cloudflare DNS (1.1.1.1)") never matched, so
		// that provider was silently dropped from the verdict no matter what the
		// café did. Deriving it from the list makes that class of drift impossible.
		frontable bool
	}
	// host:443 each, all real HTTPS sites so a valid-cert handshake distinguishes
	// "genuinely reached" from "portal intercepted 443". Grouped by provider so a
	// whole-range-allowed pattern is visible.
	dests := []dest{
		{"Apple captive-detect", "captive.apple.com", true, "17.0.0.0/8; iOS/macOS hit it at join, portals often allow", false},
		{"Apple Pay gateway", "apple-pay-gateway.apple.com", true, "paid-wifi portals allow it to take payment", false},
		{"Google", "www.google.com", true, "Google range; Android captive-detect lives here", false},
		{"Cloudflare DNS (1.1.1.1)", "one.one.one.one", true, "Cloudflare edge range; a Worker could front here", true},
		{"Cloudflare site", "www.cloudflare.com", true, "Cloudflare CDN range", true},
		{"Fastly site", "www.fastly.com", true, "Fastly CDN range; a Compute@Edge could front here", true},
		{"CloudFront (generic)", "d1.awsstatic.com", true, "a DIFFERENT CloudFront edge than ours -- is ANY CloudFront allowed?", true},
		{"Akamai site", "www.akamai.com", true, "Akamai range", false},
		{"--- baseline ---", "", false, "", false},
		{"OUR server", server, false, "expected BLOCKED at a gating café (self-signed, so TCP+TLS only)", false},
		{"OUR CloudFront edge", cdnHost, true, "was blocked at café #2 -- edge not allow-listed there", false},
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

	// TCP/80 and DNS/53, the two other things a portal must decide about. See
	// wgHTTP80Section / wgDNS53Section for why each is worth a line.
	http80OK := wgHTTP80Section(server)
	dnsUDPOK, dnsTCPOK := wgDNS53Section(server, domain)

	// The actionable read: if a frontable provider (Cloudflare/Fastly/CloudFront)
	// is permitted while our own paths are not, a carrier fronted through that
	// provider would beat this café.
	fmt.Fprintln(os.Stderr)
	var open []string
	for _, d := range dests {
		if d.frontable && permitted[d.label] {
			open = append(open, d.label)
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

	if http80OK {
		fmt.Fprintln(os.Stderr, "walled-garden: *** TCP/80 reached OUR ORIGIN. This portal passes or proxies :80 to us,")
		fmt.Fprintln(os.Stderr, "  so a plain-HTTP WebSocket carrier would work here even if 443 is gated. ***")
	}
	if dnsUDPOK {
		fmt.Fprintln(os.Stderr, "walled-garden: a PUBLIC RECURSOR reaches our authoritative server -- the recursor")
		fmt.Fprintln(os.Stderr, "  DNS path is available here (slow: ~14 unique names/s forwarded, the documented cap).")
	}
	if dnsTCPOK {
		fmt.Fprintln(os.Stderr, "walled-garden: TCP/53 to a public resolver is permitted. Our DNS carrier is UDP-only,")
		fmt.Fprintln(os.Stderr, "  so this is the portal-policy half of the DNS-over-TCP question; --probe-battery's")
		fmt.Fprintln(os.Stderr, "  TCP/53 line answers whether it reaches US.")
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

// Defaults for the survey's own targets, so the deployed server and CDN are not
// restated in three places.
const (
	defaultWGServer  = "52.203.246.145"
	defaultWGCDNHost = "d29cubp361kpm8.cloudfront.net"
)

// wgHTTP80Section surveys TCP/80, and reports whether OUR origin was reached.
//
// Port 80 is the one port a captive portal cannot simply drop: it has to do
// something with it to serve its own redirect. Which of the three things it does
// is what this section separates, and each is actionable:
//
//   - drops it: nothing to build on.
//   - INTERCEPTS it (answers with its login page): the normal pre-login case, and
//     the reason every line here uses a DETERMINISTIC expected response rather
//     than "something answered". A portal returning HTTP 200 for its login page
//     would otherwise read as success on every row.
//   - PROXIES or passes it to the real origin: then a plain-HTTP WebSocket
//     carrier works, even where 443 is gated by destination.
//
// Only endpoints with a known exact response are listed, which is what makes
// "intercepted" provable instead of guessed: the OS captive-detection endpoints
// (whose whole purpose is a fixed response), and our own /.freewire-probe, which
// echoes a nonce no portal can forge.
func wgHTTP80Section(server string) bool {
	type dest struct {
		label, host, path, why string
		wantStatus             int    // 0 = any
		wantBody               string // "" = any
	}
	dests := []dest{
		{"Apple captive-detect", "captive.apple.com", "/hotspot-detect.html",
			"macOS probes this at join; the portal almost always answers it", 200, "Success"},
		{"Google captive-detect", "connectivitycheck.gstatic.com", "/generate_204",
			"Android's equivalent; 204 means the real origin answered", 204, ""},
		{"Cloudflare captive-detect", "cp.cloudflare.com", "/generate_204",
			"Cloudflare's edge; a 204 means their range is reachable on :80", 204, ""},
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "walled-garden: TCP/80 -- does this portal DROP, INTERCEPT, or PASS plain HTTP?")
	fmt.Fprintln(os.Stderr, "  (each row has a known exact response, so an intercepting login page cannot read as OK)")
	fmt.Fprintf(os.Stderr, "\n  %-26s %-12s %s\n", "DESTINATION", "RESULT", "WHY IT MATTERS")

	for _, d := range dests {
		res := wgHTTP80(d.host, d.path, d.wantStatus, d.wantBody)
		fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", d.label, res, d.why)
	}

	// Our own origin, via the nonce-echoing probe path the server gained with the
	// TCP/80 battery line. This is the row that decides whether a plain-HTTP
	// carrier is possible here, so it reuses the battery's exact check rather
	// than a second implementation that could drift from it.
	ok, detail := httpProbe(net.JoinHostPort(server, "80"))
	res := "OK"
	if !ok {
		res = "-- no"
	}
	note := "a plain-HTTP WS carrier would work here"
	if !ok {
		note = detail
	}
	fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", "OUR origin (:80 probe)", res, note)
	return ok
}

// wgHTTP80 fetches one URL over plain HTTP and reports whether the REAL origin
// answered, judged against a known status and/or body marker.
//
// Redirects are not followed: a portal's answer to :80 is a redirect to its
// login page, and following it would turn an interception into a 200 that looks
// like a pass. It also keeps the probe from touching the portal's login host.
func wgHTTP80(host, path string, wantStatus int, wantBody string) string {
	client := &http.Client{
		Timeout:       4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	start := time.Now()
	resp, err := client.Get("http://" + host + path)
	if err != nil {
		return "-- no " + blockTag(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if wantStatus != 0 && resp.StatusCode != wantStatus {
		return "intercepted" // answered, but not by the real origin
	}
	if wantBody != "" && !strings.Contains(string(body), wantBody) {
		return "intercepted"
	}
	return fmt.Sprintf("OK %dms", time.Since(start).Milliseconds())
}

// wgDNS53Section surveys DNS/53 to PUBLIC resolvers, and reports whether the
// recursor path and TCP/53 are permitted.
//
// This is the destination question for DNS. --probe-battery asks whether DNS
// reaches OUR server directly; this asks whether third-party resolvers are
// reachable at all, which is what the recursor carrier path needs.
//
// The UDP rows run a REAL DNS-tunnel handshake through each resolver rather than
// resolving some public name. Resolving google.com through a portal's hijacked
// resolver succeeds and proves nothing; completing our handshake proves the full
// recursor path to our authoritative server, which is the thing the carrier
// actually needs. It is also why a pass here is worth little in throughput terms
// and is labelled accordingly: a recursor forwards roughly 14 unique names/s.
func wgDNS53Section(server, domain string) (udpOK, tcpOK bool) {
	resolvers := []struct{ label, addr string }{
		{"Cloudflare 1.1.1.1", "1.1.1.1:53"},
		{"Google 8.8.8.8", "8.8.8.8:53"},
		{"Quad9 9.9.9.9", "9.9.9.9:53"},
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "walled-garden: DNS/53 -- which PUBLIC resolvers does this portal permit?")
	fmt.Fprintln(os.Stderr, "  (UDP rows complete a real tunnel handshake THROUGH the resolver, so a hijacked")
	fmt.Fprintln(os.Stderr, "   resolver answering for some other name cannot read as a pass)")
	fmt.Fprintf(os.Stderr, "\n  %-26s %-12s %s\n", "RESOLVER", "RESULT", "WHY IT MATTERS")

	cfg := Config{ServerHost: server, DNSTunnelDomain: domain}
	for _, r := range resolvers {
		start := time.Now()
		_, err := dnsHandshake(cfg, []string{r.addr}, dnsHandshakeTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", r.label+" (udp)", "-- no", trimErr(err))
			continue
		}
		udpOK = true
		fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", r.label+" (udp)",
			fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()),
			"the recursor DNS path works here (slow: ~14 unique names/s)")
	}

	// TCP/53 is measured as plain reachability, not as a carrier: our DNS carrier
	// is UDP-only on both ends, so there is nothing to hand a TCP connection yet.
	// The question this answers is portal POLICY -- whether TCP/53 is permitted at
	// all -- which is half of whether a DNS-over-TCP carrier is worth building.
	// --probe-battery's TCP/53 line answers the other half (does it reach US).
	for _, r := range resolvers {
		res, ok := wgDNSOverTCP(r.addr)
		if ok {
			tcpOK = true
		}
		fmt.Fprintf(os.Stderr, "  %-26s %-12s %s\n", r.label+" (tcp)", res,
			"TCP/53 permitted? our carrier is UDP-only, so this is the policy half")
	}
	return udpOK, tcpOK
}

// wgDNSOverTCP sends one length-prefixed DNS query (RFC 7766) for a well-known
// name and reports whether a matching reply came back.
//
// The reply's transaction ID must match ours: a portal that accepts TCP/53 and
// answers with anything at all would otherwise count as permitted.
func wgDNSOverTCP(addr string) (string, bool) {
	query, id := wgBuildDNSQuery("captive.apple.com")
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return "-- no " + blockTag(err), false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second)) //nolint:errcheck

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := c.Write(framed); err != nil {
		return "-- no " + blockTag(err), false
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return "-- no " + blockTag(err), false
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 65535 {
		return "bad reply", false
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(c, reply); err != nil {
		return "-- no " + blockTag(err), false
	}
	if binary.BigEndian.Uint16(reply[:2]) != id {
		return "wrong id", false // answered, but not to our query
	}
	return fmt.Sprintf("OK %dms", time.Since(start).Milliseconds()), true
}

// wgBuildDNSQuery builds a minimal A-record query and returns it with its
// transaction ID, so the caller can check the reply belongs to it.
func wgBuildDNSQuery(name string) ([]byte, uint16) {
	var idb [2]byte
	rand.Read(idb[:]) //nolint:errcheck // a predictable id would only weaken the reply check
	id := binary.BigEndian.Uint16(idb[:])

	msg := make([]byte, 12, 32+len(name))
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)          // root label
	msg = append(msg, 0x00, 0x01) // QTYPE A
	msg = append(msg, 0x00, 0x01) // QCLASS IN
	return msg, id
}
