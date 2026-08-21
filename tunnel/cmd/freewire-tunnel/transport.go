package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"
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

	for _, port := range ports {
		proxyAddr := net.JoinHostPort(gw, port)
		c, dialErr := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if dialErr != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck

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

		// Upgrade to TLS inside the CONNECT tunnel.
		tlsCfg := &tls.Config{
			ServerName:         "vpn.freewire.com",
			InsecureSkipVerify: cfg.InsecureTLS, //nolint:gosec
		}
		tlsConn := tls.Client(c, tlsCfg)
		tlsConn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		if hsErr := tlsConn.Handshake(); hsErr != nil {
			tlsConn.Close()
			continue
		}
		tlsConn.SetDeadline(time.Time{}) //nolint:errcheck
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

// tryTLS443 connects directly via TLS to cfg.ServerHost:443 with a 3s timeout.
func tryTLS443(cfg Config) (net.Conn, error) {
	host := cfg.ServerHost
	if host == "" {
		h, _, err := net.SplitHostPort(cfg.ServerEndpoint)
		if err != nil {
			return nil, fmt.Errorf("tls443: no server host: %w", err)
		}
		host = h
	}
	addr := net.JoinHostPort(host, "443")
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg.InsecureTLS, //nolint:gosec
	}
	c, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
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

	// Single goroutine reads all WireGuard datagrams. Captures the peer address
	// from the first packet (WireGuard's handshake initiation) and forwards all
	// packets length-framed to the transport.
	go func() {
		buf := make([]byte, 1<<16)
		lb := make([]byte, 2)
		first := true
		for {
			n, peer, err := localProxy.ReadFrom(buf)
			if err != nil {
				return
			}
			if first {
				first = false
				peerCh <- peer
			}
			binary.BigEndian.PutUint16(lb, uint16(n))
			if _, err := transport.Write(lb); err != nil {
				return
			}
			if _, err := transport.Write(buf[:n]); err != nil {
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
