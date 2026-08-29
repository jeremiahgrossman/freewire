package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockTCPResponder mimics the server's TCP ProbeResponder (RunTCP): it reads the
// request floor, echoes probeMagic+nonce for a well-formed probe, and closes
// unanswered otherwise. It lets tcpReachProbe be tested end to end without a
// real server.
func mockTCPResponder(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(time.Second)) //nolint:errcheck
				req := make([]byte, probeMinRequest)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				if !bytes.HasPrefix(req, probeMagic) {
					return
				}
				c.Write(append(append([]byte{}, probeMagic...), //nolint:errcheck
					req[len(probeMagic):len(probeMagic)+probeNonceLen]...))
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestTCPReachProbeSucceedsAgainstResponder(t *testing.T) {
	addr, stop := mockTCPResponder(t)
	defer stop()

	rtt, ok, err := tcpReachProbe(addr, 2*time.Second)
	if err != nil {
		t.Fatalf("tcpReachProbe error: %v", err)
	}
	if !ok {
		t.Fatal("tcpReachProbe did not accept a correct magic+nonce echo")
	}
	if rtt <= 0 {
		t.Errorf("rtt = %v, want a positive duration", rtt)
	}
}

// A portal that accepts the SYN and answers with something that is not our
// server must read as a MISS. This is the case that matters in the field: on an
// intercepted port the dial always succeeds, so a bare connect would report
// every intercepted port as reachable.
func TestTCPReachProbeRejectsWrongResponder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// A portal's own service: answers, but not with our magic.
			c.Write(bytes.Repeat([]byte{0x7F}, probeMinRequest)) //nolint:errcheck
			c.Close()
		}
	}()

	if _, ok, _ := tcpReachProbe(ln.Addr().String(), 2*time.Second); ok {
		t.Fatal("tcpReachProbe treated a non-Freewire responder as reachable")
	}
}

// A refused connection must classify as syn-rst, which is what tells the field
// that the portal gates by destination at L4 and that desync cannot help.
func TestTCPReachProbeClassifiesRefusal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listening now: the SYN is refused

	_, ok, err := tcpReachProbe(addr, 2*time.Second)
	if ok {
		t.Fatal("tcpReachProbe passed against a closed port")
	}
	if got := classifyBlock(err); got != "syn-rst" {
		t.Fatalf("classifyBlock = %q, want syn-rst (err: %v)", got, err)
	}
}

// The server (server/internal/transport/probe.go) serves this exact path and
// query parameter. Changing one side alone makes the TCP/80 line read "blocked"
// on every network regardless of what the portal does.
func TestHTTPProbePathMatchesServer(t *testing.T) {
	if httpProbePath != "/.freewire-probe" {
		t.Errorf("httpProbePath = %q, want /.freewire-probe (server HTTPProbePath)", httpProbePath)
	}
}

// reportHTTP80 against a server that echoes correctly, and against one that
// answers with a login page the way a captive portal does.
func TestReportHTTP80(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != httpProbePath {
			http.NotFound(w, r)
			return
		}
		nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(nonce) != probeNonceLen {
			http.NotFound(w, r)
			return
		}
		w.Write(probeMagic) //nolint:errcheck
		w.Write(nonce)      //nolint:errcheck
	}))
	defer echo.Close()

	// reportHTTP80 pins port 80; httpProbe is its host:port-taking core, so the
	// echo/interception distinction is exercised against a test server here.
	if !httpProbeOK(echo.Listener.Addr().String()) {
		t.Fatal("httpProbeOK rejected a correct magic+nonce echo")
	}

	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://login.example/", http.StatusFound)
	}))
	defer portal.Close()
	if httpProbeOK(portal.Listener.Addr().String()) {
		t.Fatal("httpProbeOK treated a captive-portal redirect as our origin")
	}
}
