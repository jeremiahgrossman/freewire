package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed") || strings.Contains(s, "EOF")
}

// TLS443Server listens on port 443 (TLS), accepts WireGuard-over-TLS connections,
// and also handles HTTP CONNECT upgrades.
//
// Packet framing over TLS: [uint16 big-endian length][WireGuard packet bytes]
//
// For each accepted TLS connection the server creates a dedicated UDP socket
// dialing 127.0.0.1:wgPort and bridges packets bidirectionally.
type TLS443Server struct {
	tlsConfig *tls.Config
	wgPort    int
	log       *zap.Logger
}

// ACMEOptions configures automatic Let's Encrypt certificate management.
// Domain empty means ACME is disabled and the server falls back to
// certFile/keyFile or a generated self-signed certificate.

// NewTLS443Server creates a TLS443Server over a prebuilt TLS configuration.
//
// The configuration is built once for the process and shared with the API
// listener; see the certs package for why.
func NewTLS443Server(tlsCfg *tls.Config, wgPort int, log *zap.Logger) (*TLS443Server, error) {
	if tlsCfg == nil {
		return nil, fmt.Errorf("tls443: nil tls config")
	}
	return &TLS443Server{
		tlsConfig: tlsCfg,
		wgPort:    wgPort,
		log:       log,
	}, nil
}

// Run starts listening on port and serves until ctx is cancelled.
func (s *TLS443Server) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tls443: listen: %w", err)
	}
	s.log.Info("tls443 listening", zap.Int("port", port))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("tls443: accept", zap.Error(err))
			continue
		}
		go s.handleConn(conn)
	}
}

// handleConn upgrades to TLS and then bridges WireGuard packets.
// It also handles HTTP CONNECT: if the first bytes look like a CONNECT request,
// it responds 200 before proceeding with the TLS bridge.
func (s *TLS443Server) handleConn(rawConn net.Conn) {
	// Peek the first byte to detect HTTP CONNECT vs raw TLS ClientHello.
	// TLS ClientHello starts with 0x16 (content type handshake).
	// HTTP CONNECT starts with 'C' (0x43).
	buf := make([]byte, 1)
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := io.ReadFull(rawConn, buf); err != nil {
		rawConn.Close()
		return
	}
	rawConn.SetReadDeadline(time.Time{}) //nolint:errcheck

	// Reconstruct a connection that re-emits the peeked byte. Typed as net.Conn
	// because the CONNECT path may wrap it again to preserve buffered bytes.
	var pc net.Conn = &peekedConn{Conn: rawConn, peeked: buf[0]}

	if buf[0] == 'C' || buf[0] == 'G' || buf[0] == 'P' || buf[0] == 'H' {
		// Looks like HTTP. Attempt CONNECT handling.
		// The reader is carried across the CONNECT boundary: it may already hold
		// the first bytes of the client's TLS handshake.
		br, err := s.handleHTTPConnect(pc)
		if err != nil {
			s.log.Error("tls443: http connect", zap.Error(err))
			rawConn.Close()
			return
		}
		if br.Buffered() > 0 {
			pc = &bufConn{Conn: pc, r: br}
		}
		// After CONNECT + 200, the client will do a TLS handshake.
		// Fall through to TLS upgrade.
	}

	// TLS handshake.
	tlsConn := tls.Server(pc, s.tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if err := tlsConn.Handshake(); err != nil {
		s.log.Error("tls443: tls handshake", zap.Error(err))
		tlsConn.Close()
		return
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck

	s.log.Info("tls443: session established")
	s.bridgeToWireGuard(tlsConn)
}

// handleHTTPConnect reads an HTTP CONNECT request from conn and responds 200.
//
// The reader is returned rather than discarded: a client commonly pipelines the
// start of its TLS handshake in the same segment as the CONNECT headers, and
// those bytes are already buffered. Dropping them left the handshake reading a
// stream missing its opening bytes.
func (s *TLS443Server) handleHTTPConnect(conn net.Conn) (*bufio.Reader, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read connect line: %w", err)
	}
	if !strings.HasPrefix(line, "CONNECT") {
		return nil, fmt.Errorf("expected CONNECT, got: %q", line)
	}
	// Drain headers.
	for {
		hdr, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(hdr) == "" {
			break
		}
	}
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return nil, err
	}
	return br, nil
}

// bridgeToWireGuard reads length-framed packets from transport, forwards them to
// the local WireGuard UDP port, reads WireGuard responses, and writes them back
// length-framed.
func (s *TLS443Server) bridgeToWireGuard(transport net.Conn) {
	wgAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", s.wgPort))
	if err != nil {
		s.log.Error("tls443: resolve wg addr", zap.Error(err))
		transport.Close()
		return
	}
	udpConn, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		s.log.Error("tls443: dial wg udp", zap.Error(err))
		transport.Close()
		return
	}

	// closeOnce ensures both connections are closed exactly once when either
	// direction encounters an error, unblocking the other direction's read.
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			transport.Close()
			udpConn.Close()
		})
	}
	defer closeAll()

	// Transport → WireGuard UDP.
	go func() {
		defer closeAll()
		buf := make([]byte, 1<<16)
		lb := make([]byte, 2)
		for {
			if _, err := io.ReadFull(transport, lb); err != nil {
				if !isClosedErr(err) {
					s.log.Error("tls443: bridge: read length from transport", zap.Error(err))
				}
				return
			}
			pktLen := binary.BigEndian.Uint16(lb)
			if int(pktLen) > len(buf) {
				s.log.Error("tls443: bridge: packet too large", zap.Uint16("len", pktLen))
				return
			}
			if _, err := io.ReadFull(transport, buf[:pktLen]); err != nil {
				if !isClosedErr(err) {
					s.log.Error("tls443: bridge: read packet from transport", zap.Error(err))
				}
				return
			}
			if _, err := udpConn.Write(buf[:pktLen]); err != nil {
				s.log.Error("tls443: bridge: write to wg udp", zap.Error(err))
				return
			}
		}
	}()

	// WireGuard UDP → transport.
	//
	// The length prefix and body go out in one Write. Splitting them emitted two
	// TLS records per packet, doubling record overhead and syscalls.
	frame := make([]byte, 2+tlsMaxFrame)
	for {
		n, err := udpConn.Read(frame[2:])
		if err != nil {
			if !isClosedErr(err) {
				s.log.Error("tls443: bridge: read from wg udp", zap.Error(err))
			}
			return
		}
		binary.BigEndian.PutUint16(frame[:2], uint16(n))
		if _, err := transport.Write(frame[:2+n]); err != nil {
			if !isClosedErr(err) {
				s.log.Error("tls443: bridge: write packet to transport", zap.Error(err))
			}
			return
		}
	}
}

// bufConn wraps net.Conn so reads come from a bufio.Reader that already holds
// buffered bytes.
//
// The CONNECT handler reads its request line and headers through a
// bufio.Reader. Anything the client pipelined behind them -- typically the
// start of the TLS ClientHello, arriving in the same TCP segment -- sits in
// that buffer. Dropping the reader discarded those bytes and the handshake then
// read a stream missing its opening, failing as a record-layer error.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// tlsMaxFrame bounds a single bridged packet.
//
// The bridge previously allocated two 64 KB buffers per connection, before the
// peer had proven anything, so opening connections was enough to make the
// server commit 128 KB each. A WireGuard datagram cannot approach that: the
// tunnel MTU plus WireGuard and AEAD overhead stays well under 2 KB, and
// anything larger is a corrupt stream rather than traffic worth carrying.
const tlsMaxFrame = 4096

// peekedConn wraps net.Conn and prepends one already-read byte to the read stream.
type peekedConn struct {
	net.Conn
	peeked byte
	used   bool
}

func (p *peekedConn) Read(b []byte) (int, error) {
	if !p.used {
		p.used = true
		if len(b) == 0 {
			return 0, nil
		}
		b[0] = p.peeked
		if len(b) == 1 {
			return 1, nil
		}
		n, err := p.Conn.Read(b[1:])
		return n + 1, err
	}
	return p.Conn.Read(b)
}
