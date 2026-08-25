package transport

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Validated against RFC 6455's published examples rather than against the
// client implementation: testing the two ends against each other would pass
// just as happily if both were wrong in the same way, and the point of this
// carrier is that a gateway parsing WebSocket accepts what we emit.

func TestWSAcceptKeyMatchesRFCExample(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := wsAcceptKey(key); got != want {
		t.Fatalf("wsAcceptKey(%q) = %q, want %q", key, got, want)
	}
}

type fakeConn struct {
	net.Conn
	r  io.Reader
	w  bytes.Buffer
	mu sync.Mutex
}

func (f *fakeConn) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.Write(p)
}
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeConn) written() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.w.Bytes()...)
}

func readerConn(b []byte) *fakeConn { return &fakeConn{r: bytes.NewReader(b)} }

// RFC 6455 §5.7: a masked client frame, which is what this end always receives.
func TestWSServerReadsMaskedClientFrame(t *testing.T) {
	frame := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), false)

	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "Hello" {
		t.Fatalf("got %q, want Hello", got)
	}
}

// A server MUST NOT mask (RFC 6455 §5.1).
func TestWSServerWriteIsUnmasked(t *testing.T) {
	fc := readerConn(nil)
	c := newWSConn(fc, bufio.NewReader(fc), false)

	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := fc.written()
	if out[0] != 0x82 {
		t.Fatalf("first byte = 0x%02X, want 0x82 (FIN|binary)", out[0])
	}
	if out[1]&0x80 != 0 {
		t.Fatal("server frame is masked; RFC 6455 §5.1 forbids it")
	}
	if !bytes.Equal(out[2:], []byte("abc")) {
		t.Fatalf("payload = %q", out[2:])
	}
}

func TestWSExtendedLengthEncoding(t *testing.T) {
	fc := readerConn(nil)
	c := newWSConn(fc, bufio.NewReader(fc), false)

	payload := bytes.Repeat([]byte{0xAB}, 300)
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := fc.written()
	if out[1]&0x7F != 126 {
		t.Fatalf("length marker = %d, want 126", out[1]&0x7F)
	}
	if n := binary.BigEndian.Uint16(out[2:4]); int(n) != len(payload) {
		t.Fatalf("extended length = %d, want %d", n, len(payload))
	}
}

// An unauthenticated peer must not be able to name an arbitrary allocation.
func TestWSRejectsOversizedFrame(t *testing.T) {
	frame := []byte{0x82, 0x7F}
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], 1<<40)
	frame = append(frame, ext[:]...)

	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), false)
	buf := make([]byte, 16)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("accepted a 1 TiB frame length")
	}
}

// Oversized control frames are a protocol violation (§5.5) and must not be
// allocated for.
func TestWSRejectsOversizedControlFrame(t *testing.T) {
	// Ping claiming a 200-byte payload; the ceiling is 125.
	frame := []byte{0x89, 126, 0x00, 0xC8}
	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), false)
	buf := make([]byte, 4)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("accepted a 200-byte control frame")
	}
}

// A ping between packets is answered and does not desynchronize the stream.
func TestWSPingIsAnsweredAndStreamContinues(t *testing.T) {
	var stream []byte
	stream = append(stream, 0x89, 0x02, 'h', 'i')      // ping
	stream = append(stream, 0x82, 0x03, 'a', 'b', 'c') // binary
	fc := readerConn(stream)
	c := newWSConn(fc, bufio.NewReader(fc), false)

	got := make([]byte, 3)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read after ping: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q, want abc", got)
	}
	out := fc.written()
	if len(out) < 2 || out[0]&0x0F != wsOpPong {
		t.Fatalf("ping not answered with a pong: %v", out)
	}
	if out[1]&0x80 != 0 {
		t.Fatal("server pong is masked")
	}
	if !bytes.Equal(out[2:], []byte("hi")) {
		t.Fatalf("pong payload = %q, want hi", out[2:])
	}
}

func TestWSCloseEndsStream(t *testing.T) {
	fc := readerConn([]byte{0x88, 0x00})
	c := newWSConn(fc, bufio.NewReader(fc), false)
	if _, err := c.Read(make([]byte, 4)); err != io.EOF {
		t.Fatalf("read after close = %v, want io.EOF", err)
	}
}

// The carrier must be transparent: the [len][packet] framing above it is
// unchanged, so bridgeToWireGuard works identically on both carriers.
func TestWSRoundTripPreservesStream(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	client := newWSConn(a, bufio.NewReader(a), true)
	server := newWSConn(b, bufio.NewReader(b), false)

	sizes := []int{1, 32, 125, 126, 127, 148, 300, 1420}
	go func() {
		for _, n := range sizes {
			if _, err := client.Write(bytes.Repeat([]byte{byte(n)}, n)); err != nil {
				return
			}
		}
	}()
	var want []byte
	for _, n := range sizes {
		want = append(want, bytes.Repeat([]byte{byte(n)}, n)...)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream corrupted across the WebSocket carrier")
	}
}

// The handshake accepts a conforming upgrade and answers with the derived
// token, which is the only thing that proves to the client it reached us and
// not a portal.
func TestWSServerHandshakeAcceptsConformingRequest(t *testing.T) {
	req := "GET / HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	fc := readerConn([]byte(req))
	br := bufio.NewReader(fc)

	if err := wsServerHandshake(fc, br); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	resp := string(fc.written())
	if !strings.HasPrefix(resp, "HTTP/1.1 101 Switching Protocols\r\n") {
		t.Fatalf("response did not start with 101:\n%s", resp)
	}
	if !strings.Contains(resp, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Fatalf("wrong or missing accept token:\n%s", resp)
	}
}

// Malformed or non-WebSocket requests are refused rather than half-upgraded.
func TestWSServerHandshakeRejectsBadRequests(t *testing.T) {
	cases := []struct {
		name string
		req  string
	}{
		{"not a GET", "POST / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"},
		{"no upgrade header", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"no key", "GET / HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n"},
		{"wrong version", "GET / HTTP/1.1\r\nUpgrade: websocket\r\n" +
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := readerConn([]byte(tc.req))
			if err := wsServerHandshake(fc, bufio.NewReader(fc)); err == nil {
				t.Fatal("accepted a malformed upgrade request")
			}
		})
	}
}

// An unbounded header count or line length is a memory budget set by whoever is
// on the other end, before anything is authenticated.
func TestWSServerHandshakeBoundsHeaders(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < maxWSHeaders+10; i++ {
		sb.WriteString("X-Filler: y\r\n")
	}
	sb.WriteString("\r\n")
	fc := readerConn([]byte(sb.String()))
	if err := wsServerHandshake(fc, bufio.NewReader(fc)); err == nil {
		t.Fatal("accepted unbounded headers")
	}
}

// The two carriers share port 443 and are told apart by one byte read inside
// the TLS session. This asserts the discriminator can never confuse them: a raw
// carrier's first byte is the high byte of a uint16 length, bounded by
// tlsMaxFrame, and 'G' is far above that range.
func TestCarrierDiscriminatorIsUnambiguous(t *testing.T) {
	if 'G' <= tlsMaxFrame>>8 {
		t.Fatalf("a raw frame length prefix can begin with 'G' (tlsMaxFrame=%d); "+
			"the carriers on port 443 would be ambiguous", tlsMaxFrame)
	}
	// Every legal raw-carrier first byte must be distinguishable from 'G'.
	for n := 0; n <= tlsMaxFrame; n++ {
		if byte(n>>8) == 'G' {
			t.Fatalf("frame length %d starts with 'G'", n)
		}
	}
}
