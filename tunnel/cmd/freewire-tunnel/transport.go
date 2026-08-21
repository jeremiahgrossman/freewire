package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Per-path budgets from the fallback chain spec. Each is the ceiling for the
// whole path, including every retry inside it, so the chain reaches a verdict
// within its ~10s total.
const (
	httpConnectBudget = 2 * time.Second
	tls443Budget      = 3 * time.Second
)

// selectTransport tries each path in order per the fallback chain spec.
// Returns transport name, a local UDP PacketConn to bridge, the transport
// net.Conn, and error. If transport is "wireguard", localProxy and conn are nil.
//
// Fallback order (per spec, 10s total budget):
//
//	HTTP CONNECT (2s) → TLS/443 (3s) → DNS tunnel (3s) → ICMP/UDP (2s) → direct WireGuard
func selectTransport(cfg Config) (name string, localProxy net.PacketConn, transport net.Conn, err error) {
	// 1. HTTP CONNECT
	if tc, e := tryHTTPConnect(cfg); e == nil {
		lp, e2 := newLocalUDPProxy()
		if e2 == nil {
			return "http_connect", lp, tc, nil
		}
		tc.Close()
	}

	// 2. TLS/443
	if tc, e := tryTLS443(cfg); e == nil {
		lp, e2 := newLocalUDPProxy()
		if e2 == nil {
			return "tls443", lp, tc, nil
		}
		tc.Close()
	}

	// 3. DNS tunnel
	if lp, e := runDNSTunnel(cfg); e == nil {
		return "dns", lp, nil, nil
	}

	// 4. ICMP/UDP tunnel
	if lp, e := runICMPUDPTunnel(cfg); e == nil {
		return "icmp_udp", lp, nil, nil
	}

	// 5. Direct WireGuard UDP (last resort fallback)
	return "wireguard", nil, nil, nil
}

// tryHTTPConnect attempts HTTP CONNECT through a captive portal proxy.
// It tries the default gateway on ports 3128, 8080, and 443 with a 2s total deadline.
// On success it upgrades the CONNECT tunnel to TLS and returns the TLS connection.
func tryHTTPConnect(cfg Config) (net.Conn, error) {
	gw, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("http-connect: no gateway: %w", err)
	}

	ports := []string{"3128", "8080", "443"}
	target := "vpn.freewire.com:443"

	// The spec budgets 2s for this path in total, not per port. Every dial,
	// CONNECT exchange, and TLS handshake below shares this one deadline so
	// three unreachable ports cannot stretch the fallback chain past its budget.
	overall := time.Now().Add(httpConnectBudget)

	for _, port := range ports {
		remaining := time.Until(overall)
		if remaining <= 0 {
			break
		}

		proxyAddr := net.JoinHostPort(gw, port)
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
		tlsConn, hsErr := utlsHandshake(c, "vpn.freewire.com", cfg.InsecureTLS, hsBudget)
		if hsErr != nil {
			c.Close()
			continue
		}
		return tlsConn, nil
	}

	return nil, fmt.Errorf("http-connect: all proxy ports failed")
}

// getDefaultGateway parses `route get default` output to find the gateway IP.
func getDefaultGateway() (string, error) {
	out, err := exec.Command("route", "get", "default").CombinedOutput()
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

	// Single goroutine reads all WireGuard datagrams. Captures the peer address
	// from the first packet (WireGuard's handshake initiation) and forwards all
	// packets length-framed to the transport.
	go func() {
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
	var wgPeer net.Addr
	select {
	case wgPeer = <-peerCh:
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
