package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/freewire/server/internal/certs"
	"go.uber.org/zap"
)

// The TCP/443 listener accepts an HTTP CONNECT preface before the TLS handshake,
// for the http_connect carrier's path where a forwarding proxy hands us the
// CONNECT verbatim (a client that treats our server as the proxy). limits_test.go
// pins the parsing limits; this pins the HAPPY PATH end to end so the branch
// cannot silently break: CONNECT -> 200 -> TLS -> raw length-framed bridge ->
// (mock) WireGuard and back. Without this, a regression in the pre-TLS peek or
// the CONNECT reply would make http_connect connect-but-carry-nothing, the exact
// failure class this project keeps guarding against.
func TestTLS443CONNECTThenTLSBridges(t *testing.T) {
	// Mock local WireGuard: a UDP echo standing in for wireguard-go on wgPort, so
	// a bridged packet comes straight back and proves BOTH directions carry.
	wgConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer wgConn.Close()
	_, wgPortStr, _ := net.SplitHostPort(wgConn.LocalAddr().String())
	wgPort, _ := strconv.Atoi(wgPortStr)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := wgConn.ReadFrom(buf)
			if err != nil {
				return
			}
			wgConn.WriteTo(buf[:n], from) //nolint:errcheck
		}
	}()

	dir := t.TempDir()
	tlsCfg, err := certs.Build(
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		certs.ACMEOptions{}, zap.NewNop())
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}

	port := freePort(t)
	srv, err := NewTLS443Server(tlsCfg, wgPort, zap.NewNop())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx, port) //nolint:errcheck
	waitForListener(t, port)

	// 1. Raw TCP, then a CONNECT request -- the forwarding-proxy preface.
	raw, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	fmt.Fprintf(raw, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", port)

	// 2. The server must answer 200 and then wait for TLS. Read exactly the status
	// line and headers up to the blank line, leaving the socket at the TLS boundary.
	br := bufio.NewReader(raw)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("CONNECT was not accepted with 200: %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// The server sent only the CONNECT response and is now waiting for the TLS
	// ClientHello, so nothing should be buffered past the blank line. If it is,
	// handing raw to tls.Client would drop those bytes -- assert it is clean.
	if n := br.Buffered(); n != 0 {
		t.Fatalf("%d bytes buffered after the CONNECT response; the TLS boundary is not clean", n)
	}

	// 3. TLS handshake over the same connection (self-signed, like a fresh deploy).
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test against our self-signed server
	tc.SetDeadline(time.Now().Add(5 * time.Second))               //nolint:errcheck
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake after CONNECT 200: %v", err)
	}

	// 4. Send a raw length-framed packet. Length 4 keeps the high length byte 0x00
	// (not 'G'), so the in-TLS discriminator takes the raw carrier path, not the
	// WebSocket one.
	payload := []byte{wgTransportData, 0xAA, 0xBB, 0xCC}
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(payload)))
	copy(frame[2:], payload)
	if _, err := tc.Write(frame); err != nil {
		t.Fatalf("write framed packet: %v", err)
	}

	// 5. The mock WireGuard echoes it; the bridge frames the reply back to us.
	tc.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	lb := make([]byte, 2)
	if _, err := io.ReadFull(tc, lb); err != nil {
		t.Fatalf("read reply length (nothing bridged back over the CONNECT+TLS path): %v", err)
	}
	got := make([]byte, binary.BigEndian.Uint16(lb))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("read reply body: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("bridged echo mismatch: got %x, want %x", got, payload)
	}
}
