package transport

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"
)

// sendProbe crafts a probe matching the client wire format and returns the reply.
func sendProbe(t *testing.T, addr string, magic []byte, nonce []byte, pad int) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("udp", addr, time.Second)
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
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func TestProbeResponderEchoesNonce(t *testing.T) {
	port := freePortUDP(t)
	r := NewProbeResponder(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, []int{port}) //nolint:errcheck
	waitForUDP(t, port)

	nonce := bytes.Repeat([]byte{0xAB}, probeNonceLen)
	reply, err := sendProbe(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		probeMagic, nonce, probeMinRequest)
	if err != nil {
		t.Fatalf("probe got no reply: %v", err)
	}
	want := append(append([]byte{}, probeMagic...), nonce...)
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply = %x, want magic+nonce %x", reply, want)
	}
	// Non-amplifying: the reply must be smaller than the smallest accepted
	// request, or a spoofed source turns this into an amplifier.
	if len(reply) >= probeMinRequest {
		t.Fatalf("reply (%d bytes) is not smaller than the request floor (%d): amplification risk",
			len(reply), probeMinRequest)
	}
}

// A datagram without the magic, or below the size floor, must be ignored --
// otherwise the port is a general reflector.
func TestProbeResponderIgnoresNonProbes(t *testing.T) {
	port := freePortUDP(t)
	r := NewProbeResponder(zap.NewNop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx, []int{port}) //nolint:errcheck
	waitForUDP(t, port)

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	// Wrong magic, right size: must be dropped.
	if _, err := sendProbe(t, addr, []byte("NOTMAGIC"), bytes.Repeat([]byte{1}, probeNonceLen), probeMinRequest); err == nil {
		t.Fatal("responder answered a datagram with the wrong magic")
	}
	// Right magic, below the size floor: must be dropped (a short magic packet
	// could otherwise be an amplification lever).
	if _, err := sendProbe(t, addr, probeMagic, bytes.Repeat([]byte{1}, probeNonceLen), 24); err == nil {
		t.Fatal("responder answered a datagram below the size floor")
	}
}

func freePortUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func waitForUDP(t *testing.T, port int) {
	t.Helper()
	// A magic probe to a not-yet-listening port simply gets no reply; give the
	// goroutine a moment to bind. This is a test-only settle, not production code.
	time.Sleep(50 * time.Millisecond)
}
