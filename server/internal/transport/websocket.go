package transport

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 fixes SHA-1 for the accept token; not a security primitive here
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// WebSocket carrier (RFC 6455) for WireGuard over TLS/443.
//
// Why this exists: a captive portal commonly passes 443 that completes an HTTP
// Upgrade -- it looks like a website -- and resets a raw TLS session to an
// arbitrary IP on the same port. The field test on 2026-08-24 saw exactly that
// ("tls443: connection refused", an active reset), which reads as "blocks 443"
// but is more likely "blocks non-web 443". A WebSocket handshake presents as a
// real web request and clears that class of gateway.
//
// The framing deliberately carries the SAME [uint16 length][packet] stream the
// raw TLS carrier uses, inside WebSocket binary frames. wsConn is a transparent
// net.Conn, so bridgeToWireGuard is unchanged and the two carriers differ only
// in how bytes reach the wire. One Write becomes one binary frame, so frames
// map 1:1 onto WireGuard datagrams.
//
// Only the subset both ends need is implemented: binary data frames, plus the
// control frames a conforming middlebox or peer may send (ping/pong/close).
// Fragmented data frames are accepted on read; we never generate them.

// wsGUID is the fixed value RFC 6455 §1.3 concatenates with Sec-WebSocket-Key
// to derive Sec-WebSocket-Accept.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WebSocket opcodes (RFC 6455 §5.2).
const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// wsMaxPayload bounds a single frame's payload.
//
// The payload is one length-prefixed WireGuard packet (2 + tlsMaxFrame). The
// ceiling is generous against that and small against what an unauthenticated
// peer could otherwise ask the server to allocate: without it, a 64-bit length
// field lets a stranger name any size it likes.
const wsMaxPayload = 2 + tlsMaxFrame

// wsHandshakeLimits bound the HTTP upgrade request, which is parsed before
// anything is authenticated.
const (
	maxWSRequestLine = 8 * 1024
	maxWSHeaders     = 64
)

// wsAcceptKey computes the Sec-WebSocket-Accept response token for a client's
// Sec-WebSocket-Key (RFC 6455 §4.2.2).
func wsAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec // mandated by RFC 6455
	io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsConn frames a byte stream as WebSocket binary frames.
//
// maskOutbound follows RFC 6455 §5.1: a client MUST mask the frames it sends
// and a server MUST NOT. Reads accept either, because rejecting an unmasked
// client frame would only turn a protocol error into a connection reset for a
// peer we already control on both ends.
type wsConn struct {
	net.Conn
	br           *bufio.Reader // may already hold bytes buffered past the handshake
	maskOutbound bool

	wmu sync.Mutex // serializes writes; a pong can be emitted from the read path

	// Read state for the frame currently being consumed.
	remaining  int64
	maskKey    [4]byte
	masked     bool
	maskOffset int
}

// newWSConn wraps conn, reading through br so bytes buffered past the handshake
// are not lost.
func newWSConn(conn net.Conn, br *bufio.Reader, maskOutbound bool) *wsConn {
	return &wsConn{Conn: conn, br: br, maskOutbound: maskOutbound}
}

// Read returns payload bytes from binary data frames, transparently handling
// control frames. It may return fewer bytes than a full frame; callers upstream
// use io.ReadFull, which is what the length-prefixed framing inside expects.
func (c *wsConn) Read(p []byte) (int, error) {
	for c.remaining == 0 {
		// Between frames: read the next header, answering control frames until
		// a data frame arrives.
		if err := c.nextFrame(); err != nil {
			return 0, err
		}
	}
	n := len(p)
	if int64(n) > c.remaining {
		n = int(c.remaining)
	}
	n, err := c.br.Read(p[:n])
	if n > 0 {
		if c.masked {
			for i := 0; i < n; i++ {
				p[i] ^= c.maskKey[(c.maskOffset+i)%4]
			}
			c.maskOffset += n
		}
		c.remaining -= int64(n)
	}
	return n, err
}

// nextFrame reads one frame header. Control frames are handled here and the
// method loops in Read; data frames leave their payload for Read to consume.
func (c *wsConn) nextFrame() error {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return err
	}
	opcode := hdr[0] & 0x0F
	masked := hdr[1]&0x80 != 0
	length := int64(hdr[1] & 0x7F)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return err
		}
		length = int64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return err
		}
		u := binary.BigEndian.Uint64(ext[:])
		// Reject before allocating or trusting it: the high bit MUST be 0 per
		// §5.2, and anything past our ceiling is a corrupt stream rather than
		// traffic worth carrying.
		if u > uint64(wsMaxPayload) {
			return fmt.Errorf("websocket: frame payload %d exceeds %d", u, wsMaxPayload)
		}
		length = int64(u)
	}
	if length > wsMaxPayload {
		return fmt.Errorf("websocket: frame payload %d exceeds %d", length, wsMaxPayload)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.br, maskKey[:]); err != nil {
			return err
		}
	}

	switch opcode {
	case wsOpBinary, wsOpContinuation, wsOpText:
		// Data. Hand the payload to Read. Continuation is accepted so a peer
		// that fragments is understood, even though we never fragment.
		c.remaining = length
		c.masked = masked
		c.maskKey = maskKey
		c.maskOffset = 0
		return nil

	case wsOpPing, wsOpPong, wsOpClose:
		// Control frames carry at most 125 bytes (§5.5) and must not be
		// fragmented. Read the payload so the stream stays aligned.
		if length > 125 {
			return fmt.Errorf("websocket: control frame payload %d exceeds 125", length)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
		switch opcode {
		case wsOpPing:
			// Answer, so a middlebox or peer that probes liveness sees a
			// conforming endpoint rather than a silent one.
			if err := c.writeFrame(wsOpPong, payload); err != nil {
				return err
			}
		case wsOpClose:
			c.writeFrame(wsOpClose, nil) //nolint:errcheck // closing anyway
			return io.EOF
		}
		return nil

	default:
		return fmt.Errorf("websocket: unknown opcode 0x%X", opcode)
	}
}

// Write sends p as a single binary frame.
func (c *wsConn) Write(p []byte) (int, error) {
	if err := c.writeFrame(wsOpBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFrame emits one complete (FIN) frame, masking if this end is the client.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	// Header, extended length, mask key and payload go out in one Write, so a
	// frame is one TLS record rather than several.
	buf := make([]byte, 0, 14+len(payload))
	buf = append(buf, 0x80|opcode) // FIN set: we never fragment

	n := len(payload)
	var maskBit byte
	if c.maskOutbound {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n <= 0xFFFF:
		buf = append(buf, maskBit|126, byte(n>>8), byte(n))
	default:
		return fmt.Errorf("websocket: payload %d too large to frame", n)
	}

	if c.maskOutbound {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		buf = append(buf, key[:]...)
		start := len(buf)
		buf = append(buf, payload...)
		for i := 0; i < n; i++ {
			buf[start+i] ^= key[i%4]
		}
	} else {
		buf = append(buf, payload...)
	}

	_, err := c.Conn.Write(buf)
	return err
}

// wsServerHandshake reads a WebSocket upgrade request and answers 101.
//
// br carries the reader so bytes the client pipelined behind the request --
// commonly its first data frame in the same TLS record -- are not dropped.
func wsServerHandshake(conn net.Conn, br *bufio.Reader) error {
	line, err := readLineLimited(br, maxWSRequestLine)
	if err != nil {
		return fmt.Errorf("websocket: read request line: %w", err)
	}
	if !strings.HasPrefix(line, "GET ") {
		return fmt.Errorf("websocket: expected GET, got %q", line)
	}

	var (
		key       string
		upgrade   bool
		version13 bool
	)
	for i := 0; ; i++ {
		if i >= maxWSHeaders {
			return fmt.Errorf("websocket: too many headers")
		}
		hdr, err := readLineLimited(br, maxWSRequestLine)
		if err != nil {
			return fmt.Errorf("websocket: read header: %w", err)
		}
		if strings.TrimSpace(hdr) == "" {
			break
		}
		name, value, ok := strings.Cut(hdr, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "sec-websocket-key":
			key = value
		case "upgrade":
			upgrade = strings.EqualFold(value, "websocket")
		case "sec-websocket-version":
			version13 = value == "13"
		}
	}
	if !upgrade || key == "" {
		return fmt.Errorf("websocket: not an upgrade request")
	}
	if !version13 {
		return fmt.Errorf("websocket: unsupported version")
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"
	if _, err := io.WriteString(conn, resp); err != nil {
		return fmt.Errorf("websocket: write 101: %w", err)
	}
	return nil
}
