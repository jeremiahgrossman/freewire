package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// Per-path budgets from the fallback chain spec. Each is the ceiling for the
// whole path, including every retry inside it, so the chain reaches a verdict
// within its ~10s total.
const (
	httpConnectBudget = 2 * time.Second
	tls443Budget      = 3 * time.Second
)

// Fallback order (per spec, ~10s total budget):
//
//	HTTP CONNECT (2s) → TLS/443 (3s) → DNS tunnel (3s) → ICMP/UDP (2s) → direct WireGuard
//
// transportCandidate is one rung of the fallback chain.
type transportCandidate struct {
	name string
	// open establishes the transport. localProxy is the UDP socket WireGuard
	// will point at; transport is the stream to bridge, or nil when the
	// implementation runs its own bridge (DNS and ICMP do).
	open func(Config) (localProxy net.PacketConn, transport net.Conn, err error)
}

// transportCandidates lists the chain in priority order.
//
// Selection deliberately stops at "the transport established", not "the tunnel
// works". Whether WireGuard can actually complete a handshake over it is the
// caller's job to decide, because that is what lets a candidate that connects
// but carries nothing fall through to the next one.
func transportCandidates() []transportCandidate {
	return orderCandidates(defaultCandidates(), "")
}

// orderCandidates moves preferred to the front, leaving the rest in priority
// order so an upgrade that fails still falls through the normal chain.
func orderCandidates(all []transportCandidate, preferred string) []transportCandidate {
	if preferred == "" {
		return all
	}
	out := make([]transportCandidate, 0, len(all))
	for _, c := range all {
		if c.name == preferred {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return all // unknown name: ignore rather than refuse to connect
	}
	for _, c := range all {
		if c.name != preferred {
			out = append(out, c)
		}
	}
	return out
}

// defaultCandidates lists transports in speed order, fastest first, so the chain
// selects the best carrier a network allows rather than the first in an arbitrary
// order. Direct WireGuard (no tunnel overhead) leads; the encapsulated paths
// follow; the slow DNS/ICMP tunnels are last resorts. On a captive portal the
// fast paths fail quickly (short handshake budgets) and it falls through to
// whatever carries; on an open network it lands on WireGuard-direct immediately.
func defaultCandidates() []transportCandidate {
	return []transportCandidate{
		{
			// Direct WireGuard UDP: no proxy, no bridge. Fastest when the network
			// allows UDP 51820 to the server; tried first so an open network never
			// settles for a slower encapsulation.
			name: "wireguard",
			open: func(Config) (net.PacketConn, net.Conn, error) { return nil, nil, nil },
		},
		{
			name: "http_connect",
			open: func(cfg Config) (net.PacketConn, net.Conn, error) {
				tc, err := tryHTTPConnect(cfg)
				if err != nil {
					return nil, nil, err
				}
				lp, err := newLocalUDPProxy()
				if err != nil {
					tc.Close()
					return nil, nil, err
				}
				return lp, tc, nil
			},
		},
		{
			name: "tls443",
			open: func(cfg Config) (net.PacketConn, net.Conn, error) {
				tc, err := tryTLS443(cfg)
				if err != nil {
					return nil, nil, err
				}
				lp, err := newLocalUDPProxy()
				if err != nil {
					tc.Close()
					return nil, nil, err
				}
				return lp, tc, nil
			},
		},
		{
			name: "dns",
			open: func(cfg Config) (net.PacketConn, net.Conn, error) {
				lp, err := runDNSTunnel(cfg)
				return lp, nil, err
			},
		},
		{
			name: "icmp_udp",
			open: func(cfg Config) (net.PacketConn, net.Conn, error) {
				lp, err := runICMPUDPTunnel(cfg)
				return lp, nil, err
			},
		},
	}
}

// tryHTTPConnect attempts HTTP CONNECT through a captive portal proxy.
// It tries the default gateway on ports 3128, 8080, and 443 with a 2s total deadline.
// On success it upgrades the CONNECT tunnel to TLS and returns the TLS connection.
func tryHTTPConnect(cfg Config) (net.Conn, error) {
	// Candidate proxies, in order: an explicitly configured one, then the
	// gateway on the ports portals commonly use.
	var candidates []string
	if cfg.HTTPProxy != "" {
		candidates = append(candidates, cfg.HTTPProxy)
	}
	if gw, gwErr := getDefaultGateway(); gwErr == nil {
		for _, port := range []string{"3128", "8080", "443"} {
			candidates = append(candidates, net.JoinHostPort(gw, port))
		}
	} else if len(candidates) == 0 {
		return nil, fmt.Errorf("http-connect: no gateway and no configured proxy: %w", gwErr)
	}

	// The proxy is asked to reach the configured server, not a hardcoded name.
	// This used to be the literal "vpn.freewire.com:443" while tryTLS443 used
	// cfg.ServerHost, so the two paths disagreed about where the server was: on
	// any self-hosted or development server the proxy opened a tunnel to the
	// wrong host, and if that name resolved at all the client talked to a server
	// it had never registered its peer with.
	host := cfg.ServerHost
	if host == "" {
		if h, _, e := net.SplitHostPort(cfg.ServerEndpoint); e == nil {
			host = h
		}
	}
	if host == "" {
		return nil, fmt.Errorf("http-connect: no server host configured")
	}
	target := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.TLSPort))

	// The spec budgets 2s for this path in total, not per candidate. Every dial,
	// CONNECT exchange, and TLS handshake below shares this one deadline so
	// several unreachable candidates cannot stretch the chain past its budget.
	overall := time.Now().Add(httpConnectBudget)

	for _, proxyAddr := range candidates {
		remaining := time.Until(overall)
		if remaining <= 0 {
			break
		}

		c, dialErr := net.DialTimeout("tcp", proxyAddr, remaining)
		if dialErr != nil {
			continue
		}
		c.SetDeadline(overall) //nolint:errcheck

		// Send HTTP CONNECT request.
		req := "CONNECT " + target + " HTTP/1.1\r\n" +
			"Host: " + target + "\r\n" +
			"Proxy-Connection: keep-alive\r\n" +
			"\r\n"
		if _, writeErr := io.WriteString(c, req); writeErr != nil {
			c.Close()
			continue
		}

		// Read first response line — expect "200".
		br := bufio.NewReader(c)
		line, readErr := br.ReadString('\n')
		if readErr != nil || !strings.Contains(line, "200") {
			c.Close()
			continue
		}
		// Drain remainder of response headers.
		for {
			hdr, hdrErr := br.ReadString('\n')
			if hdrErr != nil || strings.TrimSpace(hdr) == "" {
				break
			}
		}

		c.SetDeadline(time.Time{}) //nolint:errcheck

		// Upgrade to TLS inside the CONNECT tunnel, mimicking a browser
		// fingerprint so DPI cannot identify the handshake.
		hsBudget := time.Until(overall)
		if hsBudget <= 0 {
			c.Close()
			break
		}
		tlsConn, hsErr := utlsHandshake(c, host, cfg.InsecureTLS, hsBudget)
		if hsErr != nil {
			c.Close()
			continue
		}
		return tlsConn, nil
	}

	return nil, fmt.Errorf("http-connect: no proxy accepted a CONNECT")
}

// getDefaultGateway parses `route get default` output to find the gateway IP.
func getDefaultGateway() (string, error) {
	// -n, or route resolves the gateway address to a name and this parses a
	// hostname where it expects an IP. On a home network whose router answers
	// reverse DNS -- "gateway: modem" -- ParseIP fails and the HTTP CONNECT
	// path reports no gateway, so it was never probed at all. Config 1 passed
	// only because it was given an explicit proxy. The Swift copy of this
	// lookup in PathUpgradeManager always passed -n; this one did not.
	out, err := exec.Command(routeBin, "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				gw := parts[1]
				if net.ParseIP(gw) != nil {
					return gw, nil
				}
			}
		}
	}
	return "", fmt.Errorf("route get default: no gateway found in output")
}

// tryTLS443 connects directly via TLS to cfg.ServerHost:cfg.TLSPort with a 3s timeout.
func tryTLS443(cfg Config) (net.Conn, error) {
	host := cfg.ServerHost
	if host == "" {
		h, _, err := net.SplitHostPort(cfg.ServerEndpoint)
		if err != nil {
			return nil, fmt.Errorf("tls443: no server host: %w", err)
		}
		host = h
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", cfg.TLSPort))
	overall := time.Now().Add(tls443Budget)
	raw, err := net.DialTimeout("tcp", addr, tls443Budget)
	if err != nil {
		return nil, fmt.Errorf("tls443: dial: %w", err)
	}
	c, err := utlsHandshake(raw, host, cfg.InsecureTLS, time.Until(overall))
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls443: %w", err)
	}
	return c, nil
}

// runLocalProxy bridges between wireguard-go (via localProxy UDP) and the
// transport (TCP/TLS).
//
// Packet format over TCP: [uint16 big-endian length][packet bytes].
//
// The function blocks on the transport→WireGuard direction. The
// WireGuard→transport direction runs in a goroutine. Both directions exit
// when either connection errors.
func runLocalProxy(localProxy net.PacketConn, transport net.Conn) {
	peerCh := make(chan net.Addr, 1)

	// Closing both sides unblocks whichever direction is parked in a read, so
	// neither goroutine outlives the connection.
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			transport.Close()
			localProxy.Close()
		})
	}
	defer closeAll()

	// Closed when the reader below exits, so the peer wait can give up as soon
	// as the connection is gone instead of sitting out its full timeout.
	readerDone := make(chan struct{})

	// Single goroutine reads all WireGuard datagrams. Captures the peer address
	// from the first packet (WireGuard's handshake initiation) and forwards all
	// packets length-framed to the transport.
	go func() {
		defer close(readerDone)
		defer closeAll()
		// Length prefix and body share one buffer so each packet is a single
		// Write, and therefore a single TLS record.
		frame := make([]byte, 2+(1<<16))
		first := true
		for {
			n, peer, err := localProxy.ReadFrom(frame[2:])
			if err != nil {
				return
			}
			if first {
				first = false
				peerCh <- peer
			}
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			if _, err := transport.Write(frame[:2+n]); err != nil {
				return
			}
		}
	}()

	// Wait for the WireGuard peer address (comes from first handshake packet).
	//
	// The reader's exit is watched as well as the clock, so abandoning a
	// candidate does not leave this parked for the full timeout on a connection
	// that is already closed.
	//
	// An audit finding claimed this made the fallback chain's worst case ~32s
	// against an 11s budget. That did not reproduce: measured against a host
	// that accepts TLS but speaks no WireGuard, the chain takes 8.3s with this
	// fix and 8.4s without it. wireguard-go emits its handshake initiation as
	// soon as it is configured, so peerCh is almost always ready long before
	// the timeout matters. The guard stays because an unbounded wait on a
	// closed connection is wrong regardless of how often it is reached, but it
	// is not the timing fix the finding described.
	var wgPeer net.Addr
	select {
	case wgPeer = <-peerCh:
	case <-readerDone:
		return
	case <-time.After(10 * time.Second):
		return
	}

	// Bridge transport → WireGuard.
	buf := make([]byte, 1<<16)
	lb := make([]byte, 2)
	for {
		if _, err := io.ReadFull(transport, lb); err != nil {
			return
		}
		pktLen := binary.BigEndian.Uint16(lb)
		if int(pktLen) > len(buf) {
			return
		}
		if _, err := io.ReadFull(transport, buf[:pktLen]); err != nil {
			return
		}
		if _, err := localProxy.WriteTo(buf[:pktLen], wgPeer); err != nil {
			return
		}
	}
}

// newLocalUDPProxy creates a UDP PacketConn on 127.0.0.1:0.
func newLocalUDPProxy() (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("local udp proxy: %w", err)
	}
	return pc, nil
}

// handshakeBudget is how long one candidate gets to prove WireGuard can carry
// traffic over it before the chain moves on.
//
// The tunnelled paths need more than the direct ones: a WireGuard handshake
// over DNS is several fragmented queries plus a poll round trip to collect the
// reply, none of which the 3s that suits a TCP transport can cover.
func handshakeBudgetFor(name string) time.Duration {
	switch name {
	case "dns":
		return 8 * time.Second
	case "icmp_udp":
		return 5 * time.Second
	case "wireguard":
		// Tried first now. A WireGuard handshake over a working network is one
		// round trip (well under a second), so a short budget still succeeds on an
		// open network while falling through fast on a portal that blocks UDP
		// 51820 -- the common captive case -- instead of stalling the whole chain.
		return 2 * time.Second
	default:
		return 3 * time.Second
	}
}

// establishTunnel walks the fallback chain and returns the first transport over
// which WireGuard actually completes a handshake.
//
// The device is created once and re-pointed at each candidate's local proxy, so
// a failed rung costs a teardown of the transport rather than of the TUN
// interface. Failure to hand back a working transport means every rung was
// tried, including direct WireGuard.
//
// excluded names transports already tried and found NOT to carry real traffic:
// the caller routes the winner and checks egress, and if a transport handshakes
// but carries nothing (a portal that whitelists a verb or throttles a carrier to
// death), it calls back in with that transport excluded so the chain falls
// through to the next one instead of committing to a dead path. A nil map tries
// everything.
func establishTunnel(
	cfg Config,
	wgDev *device.Device,
	privKeyHex, pubKeyHex string,
	keepalive int,
	excluded map[string]bool,
) (name string, localProxy net.PacketConn, transport net.Conn, err error) {
	upped := false

	candidates := orderCandidates(defaultCandidates(), cfg.PreferredTransport)
	if forced := forcedTransport(); forced != "" {
		filtered := candidates[:0:0]
		for _, c := range candidates {
			if c.name == forced {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return "", nil, nil, fmt.Errorf("--force-transport %q matches no known transport", forced)
		}
		fmt.Fprintf(os.Stderr, "freewire-tunnel: forced to transport %q; other rungs skipped\n", forced)
		candidates = filtered
	}
	// One greppable record of what each rung did, logged as a summary when a
	// transport is finally selected. The per-rung lines below say why each failed;
	// this consolidates "what this network allowed and which we chose" into a
	// single line for field diagnostics.
	var attempts []string
	for _, candidate := range candidates {
		if excluded[candidate.name] {
			// Already tried and proven not to carry real traffic on this network.
			// Skip it so the chain falls through to the next-fastest carrier.
			attempts = append(attempts, candidate.name+"=no-traffic")
			continue
		}
		lp, tc, openErr := candidate.open(cfg)
		if openErr != nil {
			// Say why. A candidate that failed to open was skipped in silence,
			// so a transport that never worked was indistinguishable from one
			// that was never reached -- which made diagnosing "why did it pick
			// TLS when I asked for DNS" a matter of guessing.
			fmt.Fprintf(os.Stderr, "freewire-tunnel: %s unavailable: %v\n",
				candidate.name, openErr)
			attempts = append(attempts, candidate.name+"=unavailable")
			continue
		}

		// Point WireGuard at this candidate. Direct WireGuard has no proxy, so
		// it uses the server endpoint itself.
		endpoint := cfg.ServerEndpoint
		if lp != nil {
			endpoint = lp.LocalAddr().String()
		}

		// replace_allowed_ips makes the allowed_ip lines authoritative rather
		// than additive, which matters here because this runs once per
		// candidate against the same device.
		ipcConf := "private_key=" + privKeyHex + "\n" +
			"public_key=" + pubKeyHex + "\n" +
			"endpoint=" + endpoint + "\n" +
			"replace_allowed_ips=true\n" +
			"allowed_ip=0.0.0.0/0\n" +
			"allowed_ip=::/0\n" +
			fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive) +
			"\n"

		if ipcErr := wgDev.IpcSetOperation(strings.NewReader(ipcConf)); ipcErr != nil {
			closeCandidate(lp, tc)
			continue
		}
		if !upped {
			if upErr := wgDev.Up(); upErr != nil {
				closeCandidate(lp, tc)
				return "", nil, nil, fmt.Errorf("device up: %w", upErr)
			}
			upped = true
		}

		baseline := handshakeTime(wgDev)

		// Bridge, for the transports that need one.
		var bridgeDone chan struct{}
		if lp != nil && tc != nil {
			bridgeDone = make(chan struct{})
			go func() {
				defer close(bridgeDone)
				runLocalProxy(lp, tc)
			}()
		}

		// Baseline taken per candidate: success means a handshake that happened
		// after this transport was configured, not one left over from a
		// previous rung of the chain.
		if waitForHandshake(wgDev, handshakeBudgetFor(candidate.name), baseline) {
			attempts = append(attempts, candidate.name+"=SELECTED")
			fmt.Fprintf(os.Stderr, "freewire-tunnel: transport selected: %s [%s]\n",
				candidate.name, strings.Join(attempts, " "))
			return candidate.name, lp, tc, nil
		}

		// The transport carried nothing. Tear it down and try the next rung
		// rather than declaring the whole network blocked.
		fmt.Fprintf(os.Stderr,
			"freewire-tunnel: %s connected but no WireGuard handshake; trying the next path\n",
			candidate.name)
		attempts = append(attempts, candidate.name+"=no-handshake")
		closeCandidate(lp, tc)
		if bridgeDone != nil {
			// Bounded. The sockets are already closed, so the bridge is
			// unwinding; waiting on it without a limit made the chain's pace
			// depend on how promptly a failed transport's goroutines noticed.
			// Anything still running here holds only closed descriptors.
			select {
			case <-bridgeDone:
			case <-time.After(500 * time.Millisecond):
			}
		}
	}

	return "", nil, nil, fmt.Errorf("no transport carried a WireGuard handshake")
}

func closeCandidate(lp net.PacketConn, tc net.Conn) {
	if tc != nil {
		tc.Close()
	}
	if lp != nil {
		lp.Close()
	}
}
