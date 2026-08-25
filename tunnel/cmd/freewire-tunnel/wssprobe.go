package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// wssProbe tests both carriers that share port 443 and reports each separately.
//
//	freewire-tunnel --wss-probe --server 52.203.246.145 [--port 443] [--insecure]
//
// The comparison is the whole point. A café's log line "tls443: connection
// refused" reads as "this network blocks 443", but portal gateways routinely
// pass 443 that completes an HTTP Upgrade -- it looks like a website -- while
// resetting a raw TLS session to an arbitrary IP. Those two cases are
// indistinguishable from the raw carrier's failure alone and produce opposite
// engineering conclusions:
//
//	raw FAIL, wss FAIL  -> the network really does block 443. Fall to DNS/ICMP.
//	raw FAIL, wss OK    -> it blocks NON-WEB 443. The WebSocket carrier is the
//	                       fast path here, and the DNS fallback was never needed.
//	raw OK,  wss OK     -> open enough for either; the chain picks raw (cheaper).
//
// It changes no system state and needs no root: no routing, no resolver, no
// utun. Safe to run on a machine in use, from a café table.
func wssProbe(args []string) int {
	server := ""
	port := 443
	insecure := false
	expectEcho := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 < len(args) {
				server = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &port) //nolint:errcheck
				i++
			}
		case "--insecure":
			insecure = true
		case "--expect-echo":
			// Test-only: requires the framed packet to come back, which proves
			// the carrier bidirectionally. A real server does NOT echo -- the
			// packet reaches wireguard-go, which discards it as unauthentic --
			// so this is never used in the field.
			expectEcho = true
		default:
			fmt.Fprintf(os.Stderr, "wss-probe: unknown argument %q\n", args[i])
			return 2
		}
	}
	if server == "" {
		fmt.Fprintln(os.Stderr, "wss-probe: --server is required")
		return 2
	}

	cfg := Config{ServerHost: server, TLSPort: port, InsecureTLS: insecure}
	fmt.Fprintf(os.Stderr, "wss-probe: testing both carriers on %s:%d\n\n", server, port)

	rawOK := probeCarrier("raw TLS/443 ", expectEcho, func() (net.Conn, error) { return tryTLS443(cfg) })
	wssOK := probeCarrier("WebSocket/443", expectEcho, func() (net.Conn, error) { return tryWSS443(cfg) })

	fmt.Fprintln(os.Stderr)
	switch {
	case rawOK && wssOK:
		fmt.Fprintln(os.Stderr, "wss-probe: this network allows both. The chain will pick raw TLS/443 (cheaper).")
	case !rawOK && wssOK:
		fmt.Fprintln(os.Stderr, "wss-probe: *** this network blocks NON-WEB 443 but passes web 443. ***")
		fmt.Fprintln(os.Stderr, "wss-probe: the WebSocket carrier is the fast path here; DNS fallback is not needed.")
	case rawOK && !wssOK:
		fmt.Fprintln(os.Stderr, "wss-probe: raw works but the upgrade does not -- something is terminating HTTP on 443.")
	default:
		fmt.Fprintln(os.Stderr, "wss-probe: this network blocks 443 outright. The chain must fall to DNS/ICMP.")
	}

	if !rawOK && !wssOK {
		return 1
	}
	return 0
}

// probeCarrier opens one carrier, proves it moves bytes, and reports timing.
//
// Opening is not enough to report success: the failure this product keeps
// hitting is a carrier that connects and then carries nothing. So the probe
// writes a length-framed packet and requires the connection to survive it --
// the same framing the real bridge uses, so a middlebox that mangles the stream
// shows up here rather than as a mysteriously dead tunnel later.
func probeCarrier(label string, expectEcho bool, open func() (net.Conn, error)) bool {
	start := time.Now()
	conn, err := open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  %s  FAIL  %v\n", label, err)
		return false
	}
	defer conn.Close()
	established := time.Since(start)

	// A WireGuard-shaped packet: type 1 (handshake initiation), zeroed body.
	// Against a real server the bridge hands it to wireguard-go, which discards
	// it as unauthentic -- so nothing comes back, and that is fine. What is
	// tested here is that the carrier accepts a framed write and stays open, not
	// that WireGuard replies.
	pkt := make([]byte, 148)
	pkt[0] = 1
	frame := make([]byte, 2+len(pkt))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(pkt)))
	copy(frame[2:], pkt)

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(frame); err != nil {
		fmt.Fprintf(os.Stderr, "  %s  FAIL  established in %s but the first write failed: %v\n",
			label, established.Round(time.Millisecond), err)
		return false
	}

	if expectEcho {
		// Test-only: an echo listener sends the frame straight back, which
		// exercises the server->client direction of the codec (unmasked frames)
		// that a real, discarding server never would.
		conn.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			fmt.Fprintf(os.Stderr, "  %s  FAIL  wrote a frame but read nothing back: %v\n", label, err)
			return false
		}
		n := binary.BigEndian.Uint16(lb[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			fmt.Fprintf(os.Stderr, "  %s  FAIL  short read on echo: %v\n", label, err)
			return false
		}
		if int(n) != len(pkt) || body[0] != 1 {
			fmt.Fprintf(os.Stderr, "  %s  FAIL  echo mismatch (len %d, first 0x%02X)\n", label, n, body[0])
			return false
		}
	}

	fmt.Fprintf(os.Stderr, "  %s  OK    established in %s, carried a framed packet\n",
		label, established.Round(time.Millisecond))
	return true
}
