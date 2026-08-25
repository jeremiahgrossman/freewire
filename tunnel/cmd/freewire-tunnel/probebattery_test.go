package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// mockResponder mimics the server's ProbeResponder: it echoes probeMagic+nonce
// for a well-formed probe and ignores everything else. It lets the client's
// udpReachProbe be tested end to end without a real server or root.
func mockResponder(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < probeMinRequest || !bytes.HasPrefix(buf[:n], probeMagic) {
				continue
			}
			reply := append(append([]byte{}, probeMagic...), buf[len(probeMagic):len(probeMagic)+probeNonceLen]...)
			pc.WriteTo(reply, src) //nolint:errcheck
		}
	}()
	return pc.LocalAddr().String(), func() { pc.Close(); close(done) }
}

func TestUDPReachProbeSucceedsAgainstResponder(t *testing.T) {
	addr, stop := mockResponder(t)
	defer stop()

	rtt, ok, err := udpReachProbe(addr, time.Second)
	if err != nil {
		t.Fatalf("probe error: %v", err)
	}
	if !ok {
		t.Fatal("probe did not get its nonce echoed back from a conforming responder")
	}
	if rtt <= 0 {
		t.Fatalf("nonsensical rtt %v", rtt)
	}
}

// A silent port (nothing listening) must read as blocked, not as an error the
// battery would surface loudly -- that is the ordinary captive-portal-drop case.
func TestUDPReachProbeBlockedIsQuiet(t *testing.T) {
	// A port we do not listen on. Discard any reply by pointing at a closed
	// local socket's former address is unreliable, so use a documentation-range
	// address that will not answer within the timeout.
	_, ok, err := udpReachProbe("192.0.2.1:443", 300*time.Millisecond)
	if ok {
		t.Fatal("got a pass from an address that should never answer")
	}
	if err != nil {
		// A connectivity error (e.g. no route) is acceptable, but a plain drop
		// should surface as (false, nil). Either way it must not be a pass.
		t.Logf("probe returned err (acceptable): %v", err)
	}
}

// A responder that replies with the wrong nonce must not count as a pass: it is
// an unrelated datagram on the port, not our echo.
func TestUDPReachProbeRejectsWrongNonce(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_ = n
			// Reply with magic but a DIFFERENT nonce (all 0xFF).
			reply := append(append([]byte{}, probeMagic...), bytes.Repeat([]byte{0xFF}, probeNonceLen)...)
			pc.WriteTo(reply, src) //nolint:errcheck
		}
	}()

	_, ok, _ := udpReachProbe(pc.LocalAddr().String(), time.Second)
	if ok {
		t.Fatal("counted a reply with the wrong nonce as a pass")
	}
}
