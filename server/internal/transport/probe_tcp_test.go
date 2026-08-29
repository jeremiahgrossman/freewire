package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
)

// sendTCPProbe crafts a probe matching the client wire format (freewire-tunnel's
// tcpReachProbe) and returns the reply.
func sendTCPProbe(t *testing.T, addr string, magic, nonce []byte, pad int) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	req := append([]byte{}, magic...)
	req = append(req, nonce...)
	for len(req) < pad {
		req = append(req, 0)
	}
	c.SetDeadline(time.Now().Add(time.Second)) //nolint:errcheck
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	resp := make([]byte, len(probeMagic)+probeNonceLen)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func TestProbeResponderTCPEchoesNonce(t *testing.T) {
	port := freePortTCP(t)
	r := NewProbeResponder(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.RunTCP(ctx, []int{port}) //nolint:errcheck
	waitForTCP(t, port)

	nonce := bytes.Repeat([]byte{0xCD}, probeNonceLen)
	reply, err := sendTCPProbe(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		probeMagic, nonce, probeMinRequest)
	if err != nil {
		t.Fatalf("tcp probe got no reply: %v", err)
	}
	want := append(append([]byte{}, probeMagic...), nonce...)
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = %x, want magic+nonce %x", reply, want)
	}
}

// A connection that does not open with the magic must be closed unanswered, or
// TCP/53 and TCP/853 become general-purpose services rather than probe points.
func TestProbeResponderTCPIgnoresNonProbes(t *testing.T) {
	port := freePortTCP(t)
	r := NewProbeResponder(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.RunTCP(ctx, []int{port}) //nolint:errcheck
	waitForTCP(t, port)

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if _, err := sendTCPProbe(t, addr, []byte("NOTMAGIC"), bytes.Repeat([]byte{1}, probeNonceLen), probeMinRequest); err == nil {
		t.Fatal("responder answered a connection with the wrong magic")
	}
	// Below the request floor: the responder blocks for the full floor and must
	// time out rather than answer a short write.
	if _, err := sendTCPProbe(t, addr, probeMagic, bytes.Repeat([]byte{1}, probeNonceLen), 24); err == nil {
		t.Fatal("responder answered a connection below the size floor")
	}
}

// The HTTP probe is what answers on port 80, where autocert owns the listener.
// A well-formed nonce echoes; anything else must 404, so the path is not a
// generic endpoint a portal or scanner can use to fingerprint the server.
func TestHTTPProbeHandler(t *testing.T) {
	r := NewProbeResponder(zap.NewNop())
	h := r.HTTPProbeHandler()

	nonce := bytes.Repeat([]byte{0x5A}, probeNonceLen)
	req := httptest.NewRequest(http.MethodGet, HTTPProbePath+"?nonce="+hex.EncodeToString(nonce), nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	want := append(append([]byte{}, probeMagic...), nonce...)
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("body = %x, want magic+nonce %x", w.Body.Bytes(), want)
	}

	for _, bad := range []string{"", "zz", hex.EncodeToString(bytes.Repeat([]byte{1}, probeNonceLen-1))} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, HTTPProbePath+"?nonce="+bad, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("nonce %q: status = %d, want 404", bad, w.Code)
		}
	}

	// Any other path must 404 too: on an ACME server this handler is autocert's
	// fallback for the whole of port 80.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("root path: status = %d, want 404", w.Code)
	}
}

// The client (tunnel/cmd/freewire-tunnel/probebattery.go) hardcodes this path as
// httpProbePath. It is a cross-module wire contract: changing one side alone
// makes the TCP/80 line read "blocked" on every network regardless of the portal.
func TestHTTPProbePathMatchesClient(t *testing.T) {
	if HTTPProbePath != "/.freewire-probe" {
		t.Errorf("HTTPProbePath = %q, want /.freewire-probe (client httpProbePath)", HTTPProbePath)
	}
	if probeNonceQuery != "nonce" {
		t.Errorf("probeNonceQuery = %q, want nonce (client builds ?nonce=)", probeNonceQuery)
	}
}

func freePortTCP(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForTCP(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tcp probe responder never bound port %d", port)
}
