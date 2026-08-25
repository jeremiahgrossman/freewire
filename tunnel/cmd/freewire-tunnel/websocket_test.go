package main

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

// The framing is validated against RFC 6455's own published examples rather
// than against our other implementation. Testing the two ends against each
// other would pass just as happily if both were wrong in the same way, and the
// entire point of this carrier is that a gateway parsing WebSocket accepts what
// we emit.

// RFC 6455 §1.3 worked example of the handshake token derivation.
func TestWSAcceptKeyMatchesRFCExample(t *testing.T) {
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	const want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got := wsAcceptKey(key); got != want {
		t.Fatalf("wsAcceptKey(%q) = %q, want %q", key, got, want)
	}
}

// fakeConn adapts a byte stream to net.Conn for the codec, recording writes.
type fakeConn struct {
	net.Conn
	r   io.Reader
	w   bytes.Buffer
	mu  sync.Mutex
	eof bool
}

func (f *fakeConn) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.w.Write(p)
}
func (f *fakeConn) Close() error                     { f.eof = true; return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }
func (f *fakeConn) written() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.w.Bytes()...)
}

func readerConn(b []byte) *fakeConn { return &fakeConn{r: bytes.NewReader(b)} }

// RFC 6455 §5.7: a single-frame unmasked text message "Hello".
func TestWSReadRFCUnmaskedFrame(t *testing.T) {
	frame := []byte{0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), true)

	got, err := io.ReadAll(io.LimitReader(c, 5))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "Hello" {
		t.Fatalf("got %q, want %q", got, "Hello")
	}
}

// RFC 6455 §5.7: the same message masked, as a client sends it. The server end
// must unmask it to the identical plaintext.
func TestWSReadRFCMaskedFrame(t *testing.T) {
	frame := []byte{0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58}
	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), false) // server end: does not mask outbound

	got, err := io.ReadAll(io.LimitReader(c, 5))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "Hello" {
		t.Fatalf("got %q, want %q", got, "Hello")
	}
}

// A client MUST mask (RFC 6455 §5.1). A gateway that parses WebSocket drops an
// unmasked client frame, so this is load-bearing for the carrier's whole point.
func TestWSClientWriteIsMaskedAndDecodes(t *testing.T) {
	fc := readerConn(nil)
	c := newWSConn(fc, bufio.NewReader(fc), true)

	payload := []byte("wireguard-packet-bytes")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := fc.written()

	if out[0] != 0x82 {
		t.Fatalf("first byte = 0x%02X, want 0x82 (FIN|binary)", out[0])
	}
	if out[1]&0x80 == 0 {
		t.Fatal("client frame is not masked; a conforming gateway would drop it")
	}
	if n := int(out[1] & 0x7F); n != len(payload) {
		t.Fatalf("length field = %d, want %d", n, len(payload))
	}
	key := out[2:6]
	body := append([]byte(nil), out[6:]...)
	for i := range body {
		body[i] ^= key[i%4]
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("unmasked payload = %q, want %q", body, payload)
	}
}

// A server MUST NOT mask.
func TestWSServerWriteIsUnmasked(t *testing.T) {
	fc := readerConn(nil)
	c := newWSConn(fc, bufio.NewReader(fc), false)

	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := fc.written()
	if out[1]&0x80 != 0 {
		t.Fatal("server frame is masked; RFC 6455 §5.1 forbids it")
	}
	if !bytes.Equal(out[2:], []byte("abc")) {
		t.Fatalf("payload = %q", out[2:])
	}
}

// RFC 6455 §5.2: payloads of 126..65535 use the 16-bit extended length. Our
// packets land here, so the encoding must be exact.
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
	if !bytes.Equal(out[4:], payload) {
		t.Fatal("payload corrupted")
	}
}

// A 64-bit length field lets the other end name any size it likes. Refuse
// before allocating.
func TestWSRejectsOversizedFrame(t *testing.T) {
	var frame []byte
	frame = append(frame, 0x82, 0x7F)
	var ext [8]byte
	binary.BigEndian.PutUint64(ext[:], 1<<40)
	frame = append(frame, ext[:]...)

	fc := readerConn(frame)
	c := newWSConn(fc, bufio.NewReader(fc), true)
	if _, err := io.ReadAll(io.LimitReader(c, 16)); err == nil {
		t.Fatal("accepted a 1 TiB frame length")
	}
}

// Control frames must not desynchronize the data stream: a ping arriving
// between packets is answered and the following packet still reads correctly.
func TestWSPingIsAnsweredAndStreamContinues(t *testing.T) {
	var stream []byte
	stream = append(stream, 0x89, 0x02, 'h', 'i')      // ping "hi", unmasked
	stream = append(stream, 0x82, 0x03, 'a', 'b', 'c') // binary "abc"
	fc := &fakeConn{r: bytes.NewReader(stream)}
	c := newWSConn(fc, bufio.NewReader(fc), true)

	got := make([]byte, 3)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read after ping: %v", err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q, want abc", got)
	}

	out := fc.written()
	if len(out) == 0 || out[0]&0x0F != wsOpPong {
		t.Fatalf("ping was not answered with a pong; wrote %v", out)
	}
	// The pong echoes the ping payload, and being the client end it is masked.
	if out[1]&0x80 == 0 {
		t.Fatal("client pong is not masked")
	}
	key := out[2:6]
	body := append([]byte(nil), out[6:]...)
	for i := range body {
		body[i] ^= key[i%4]
	}
	if string(body) != "hi" {
		t.Fatalf("pong payload = %q, want hi", body)
	}
}

// A close frame ends the stream cleanly rather than surfacing as a protocol
// error, so the carrier tears down like any other closed connection.
func TestWSCloseEndsStream(t *testing.T) {
	stream := []byte{0x88, 0x00}
	fc := readerConn(stream)
	c := newWSConn(fc, bufio.NewReader(fc), true)

	buf := make([]byte, 4)
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("read after close = %v, want io.EOF", err)
	}
}

// The carrier's contract with the rest of the client: whatever bytes go in come
// out unchanged, so the [len][packet] framing above it is untouched. Exercised
// through a real socket pair with both ends of the codec.
func TestWSRoundTripPreservesStream(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	client := newWSConn(clientSide, bufio.NewReader(clientSide), true)
	server := newWSConn(serverSide, bufio.NewReader(serverSide), false)

	// Packets of the sizes WireGuard actually emits, including ones that cross
	// the 7-bit/16-bit length-encoding boundary.
	sizes := []int{1, 32, 125, 126, 127, 148, 300, 1420}
	var want []byte
	go func() {
		for _, n := range sizes {
			pkt := bytes.Repeat([]byte{byte(n)}, n)
			if _, err := client.Write(pkt); err != nil {
				return
			}
		}
	}()
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

// The handshake must reject anything that is not a real 101 with the derived
// token. This is what makes a captive portal's interception visible at the
// handshake instead of later as a tunnel that carries nothing.
func TestWSClientHandshakeRejectsPortalInterception(t *testing.T) {
	cases := []struct {
		name string
		resp string
	}{
		{
			// The classic captive-portal response: a redirect to the login page.
			name: "portal redirect",
			resp: "HTTP/1.1 302 Found\r\nLocation: http://portal.example/login\r\n\r\n",
		},
		{
			// A transparent proxy that answers 200 with its own page.
			name: "portal 200 page",
			resp: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>login</html>",
		},
		{
			// 101 but the token is wrong: something is terminating the upgrade
			// that did not see our key.
			name: "101 with bad accept token",
			resp: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
				"Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
		},
		{
			name: "101 with no accept token",
			resp: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := readerConn([]byte(tc.resp))
			if _, err := wsClientHandshake(fc, "example.test"); err == nil {
				t.Fatal("accepted an intercepted upgrade")
			}
		})
	}
}

// The happy path: a conforming 101 is accepted, and bytes the server pipelined
// behind it are not lost.
func TestWSClientHandshakeAcceptsConformingUpgrade(t *testing.T) {
	// Drive a real handshake: read the client's request to learn its key, then
	// answer with the token derived from it.
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	go func() {
		br := bufio.NewReader(serverSide)
		var key string
		for {
			line, err := readLineLimited(br, 8192)
			if err != nil {
				return
			}
			if strings.TrimSpace(line) == "" {
				break
			}
			if name, value, ok := strings.Cut(line, ":"); ok &&
				strings.EqualFold(strings.TrimSpace(name), "sec-websocket-key") {
				key = strings.TrimSpace(value)
			}
		}
		io.WriteString(serverSide, "HTTP/1.1 101 Switching Protocols\r\n"+ //nolint:errcheck
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: "+wsAcceptKey(key)+"\r\n\r\n")
		// Pipelined immediately behind the 101, as a busy server would.
		serverSide.Write([]byte{0x82, 0x03, 'x', 'y', 'z'}) //nolint:errcheck
	}()

	conn, err := wsClientHandshake(clientSide, "example.test")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	got := make([]byte, 3)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read pipelined frame: %v", err)
	}
	if string(got) != "xyz" {
		t.Fatalf("got %q, want xyz; bytes pipelined behind the 101 were dropped", got)
	}
}

// The request must look like a browser's, since a gateway that inspects it is
// exactly the audience this carrier is for.
func TestWSClientHandshakeRequestLooksLikeABrowser(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	reqCh := make(chan string, 1)
	go func() {
		br := bufio.NewReader(serverSide)
		var sb strings.Builder
		for {
			line, err := readLineLimited(br, 8192)
			if err != nil {
				return
			}
			sb.WriteString(line + "\n")
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		reqCh <- sb.String()
		serverSide.Close()
	}()

	wsClientHandshake(clientSide, "example.test") //nolint:errcheck // only the request matters

	req := <-reqCh
	for _, want := range []string{
		"GET / HTTP/1.1",
		"Host: example.test",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Version: 13",
		"Sec-WebSocket-Key:",
		"User-Agent: Mozilla/5.0",
	} {
		if !strings.Contains(req, want) {
			t.Errorf("upgrade request missing %q:\n%s", want, req)
		}
	}
}
