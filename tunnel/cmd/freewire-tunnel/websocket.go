package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 fixes SHA-1 for the accept token; not a security primitive here
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// WebSocket carrier (RFC 6455): WireGuard inside WSS frames on port 443.
//
// Why this carrier exists, given we already have TLS/443: a captive portal
// commonly passes 443 that completes an HTTP Upgrade -- it looks like a website
// -- while resetting a raw TLS session to an arbitrary IP on the same port. The
// café field test on 2026-08-24 logged "tls443: dial 443: connection refused",
// an active reset, which reads as "blocks 443" but is more likely "blocks
// non-web 443". This carrier presents as a real web request, so it can clear
// the gateway that refused the raw one. See TRANSPORT-RESEARCH-2026-08-24.md.
//
// It deliberately carries the SAME [uint16 length][packet] stream as the raw
// TLS carrier, inside binary frames: wsConn is a transparent net.Conn, so
// runLocalProxy is unchanged and the carriers differ only in how bytes reach
// the wire. One Write becomes one binary frame, so frames map 1:1 onto
// WireGuard datagrams.

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

// wsMaxPayload bounds one frame's payload: a length-prefixed WireGuard packet.
// Generous against a real datagram, small against what a 64-bit length field
// would otherwise let the other end ask us to allocate.
const wsMaxPayload = 2 + 4096

// wsAcceptKey computes Sec-WebSocket-Accept from a Sec-WebSocket-Key
// (RFC 6455 §4.2.2).
func wsAcceptKey(key string) string {
	h := sha1.New() //nolint:gosec // mandated by RFC 6455
	io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsConn frames a byte stream as WebSocket binary frames.
//
// maskOutbound follows RFC 6455 §5.1: a client MUST mask what it sends, a
// server MUST NOT. This end is always the client, so it always masks -- a
// gateway that parses WebSocket would drop an unmasked client frame, which is
// exactly the inspection this carrier exists to satisfy.
type wsConn struct {
	net.Conn
	br           *bufio.Reader
	maskOutbound bool

	wmu sync.Mutex // serializes writes; a pong can be emitted from the read path

	remaining  int64
	maskKey    [4]byte
	masked     bool
	maskOffset int
}

func newWSConn(conn net.Conn, br *bufio.Reader, maskOutbound bool) *wsConn {
	return &wsConn{Conn: conn, br: br, maskOutbound: maskOutbound}
}

// Read returns payload bytes from data frames, handling control frames
// transparently. It may return less than a full frame; upstream uses
// io.ReadFull, which is what the length-prefixed framing inside expects.
func (c *wsConn) Read(p []byte) (int, error) {
	for c.remaining == 0 {
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

// nextFrame reads one frame header, answering control frames in place.
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
		c.remaining = length
		c.masked = masked
		c.maskKey = maskKey
		c.maskOffset = 0
		return nil

	case wsOpPing, wsOpPong, wsOpClose:
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

// writeFrame emits one complete (FIN) frame in a single Write, so a frame is
// one TLS record rather than several.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	buf := make([]byte, 0, 14+len(payload))
	buf = append(buf, 0x80|opcode) // FIN: we never fragment

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

// wsClientHandshake performs the upgrade over an established TLS connection and
// returns a transparent net.Conn carrying binary frames.
//
// The Sec-WebSocket-Accept token is verified rather than ignored. That is what
// makes a captive portal's interception visible HERE, at the handshake, instead
// of later as a tunnel that carries nothing: a portal answering with its own
// login page cannot produce the token, so the carrier fails cleanly and the
// chain falls through to the next one.
func wsClientHandshake(conn net.Conn, host string) (net.Conn, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("websocket: nonce: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(nonce[:])

	// A request a gateway will read as an ordinary browser opening a WebSocket.
	// Header order and set follow what browsers send; Origin is included because
	// its absence is itself unusual for a browser-originated upgrade.
	req := "GET " + wsPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: https://" + host + "\r\n" +
		"User-Agent: " + wsUserAgent + "\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("websocket: write upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	status, err := readLineLimited(br, wsMaxResponseLine)
	if err != nil {
		return nil, fmt.Errorf("websocket: read status: %w", err)
	}
	if !strings.Contains(status, "101") {
		// A portal's interception lands here: it answered the upgrade with
		// something else (a redirect to its login page, or a 200 of HTML).
		return nil, fmt.Errorf("websocket: upgrade refused: %q", strings.TrimSpace(status))
	}

	var accept string
	for i := 0; ; i++ {
		if i >= wsMaxResponseHeaders {
			return nil, fmt.Errorf("websocket: too many response headers")
		}
		line, err := readLineLimited(br, wsMaxResponseLine)
		if err != nil {
			return nil, fmt.Errorf("websocket: read header: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "sec-websocket-accept") {
			accept = strings.TrimSpace(value)
		}
	}

	want := wsAcceptKey(key)
	if subtle.ConstantTimeCompare([]byte(accept), []byte(want)) != 1 {
		return nil, fmt.Errorf("websocket: bad accept token (upgrade intercepted?)")
	}

	// br carries any bytes the server pipelined behind the 101.
	return newWSConn(conn, br, true), nil
}

// Bounds on the upgrade response, parsed before the carrier is trusted.
const (
	wsMaxResponseLine    = 8 * 1024
	wsMaxResponseHeaders = 64

	// wsPath and wsUserAgent shape how the request looks to a gateway. A root
	// path and a mainstream desktop UA are the least remarkable combination; a
	// distinctive path would be a signature to match on.
	wsPath      = "/"
	wsUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

// readLineLimited reads through the next newline, giving up past limit bytes.
// Unbounded line reads let the other end choose our memory budget.
func readLineLimited(br *bufio.Reader, limit int) (string, error) {
	var sb strings.Builder
	for {
		b, err := br.ReadByte()
		if err != nil {
			return sb.String(), err
		}
		if b == '\n' {
			return sb.String(), nil
		}
		if sb.Len() >= limit {
			return "", fmt.Errorf("line exceeds %d bytes", limit)
		}
		sb.WriteByte(b)
	}
}
