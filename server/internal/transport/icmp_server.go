package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ICMPServer listens on a UDP port and speaks the Freewire ICMP-over-UDP tunnel
// protocol per icmp-tunnel-protocol-spec.md.
//
// Freewire header: Version(1) + Type(1) + SessionToken(2) + Seq(4) = 8 bytes
// Handshake:  HANDSHAKE_HELLO(0x01), HANDSHAKE_ACK(0x02), HANDSHAKE_CONFIRM(0x03)
// Data:       DATA(0x10)
// Keepalive:  KEEPALIVE(0x20)
// Encryption: ChaCha20-Poly1305, AAD = Freewire header (8 bytes)
//
// Sessions are keyed by the 2-byte session token assigned during handshake.
type ICMPServer struct {
	wgPort   int
	sessions sync.Map // uint16 → *icmpSrvSession
	log      *zap.Logger
}

// icmpSrvSession holds the server-side state for one ICMP/UDP tunnel session.
type icmpSrvSession struct {
	sessionToken [2]byte
	sessionKey   [32]byte
	// Client address — all responses go here.
	clientAddr *net.UDPAddr
	// Per-session WG bridge socket.
	localConn *net.UDPConn
	// Sequence counters.
	txSeq    uint32
	mu       sync.Mutex
	lastSeen time.Time
	// Pending handshake state (before ClientConfirm).
	serverPriv [32]byte
	activated  bool
	// Inbound WG packets to forward to client.
	wgInbound chan []byte
}

// NewICMPServer creates an ICMPServer bridging to WireGuard on wgPort.
func NewICMPServer(wgPort int, log *zap.Logger) *ICMPServer {
	return &ICMPServer{wgPort: wgPort, log: log}
}

// Run listens on the given UDP port and serves until ctx is cancelled.
func (s *ICMPServer) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("icmp server: listen: %w", err)
	}
	s.log.Info("icmp tunnel listening", zap.Int("port", port))

	go s.evictLoop(ctx)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	uc := ln.(*net.UDPConn)
	buf := make([]byte, 1600)
	for {
		n, srcAddr, err := uc.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("icmp server: read", zap.Error(err))
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handlePacket(pkt, srcAddr, uc)
	}
}

// evictLoop removes sessions idle for more than 90 seconds.
func (s *ICMPServer) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(k, v any) bool {
				sess := v.(*icmpSrvSession)
				sess.mu.Lock()
				ls := sess.lastSeen
				sess.mu.Unlock()
				if now.Sub(ls) > 90*time.Second {
					s.sessions.Delete(k)
					if sess.localConn != nil {
						sess.localConn.Close() // causes wgInbound reader to exit and close the channel
					}
					s.log.Info("icmp server: session evicted")
				}
				return true
			})
		}
	}
}

// handlePacket parses the Freewire header and dispatches to the appropriate handler.
func (s *ICMPServer) handlePacket(pkt []byte, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	if len(pkt) < 8 {
		return
	}
	if pkt[0] != 0x01 { // version check
		return
	}
	pktType := pkt[1]
	var token [2]byte
	copy(token[:], pkt[2:4])
	tokenKey := binary.BigEndian.Uint16(token[:])

	switch pktType {
	case 0x01: // HANDSHAKE_HELLO
		s.handleHello(pkt, srcAddr, conn)
	case 0x03: // HANDSHAKE_CONFIRM
		v, ok := s.sessions.Load(tokenKey)
		if !ok {
			return
		}
		s.handleConfirm(pkt, srcAddr, conn, v.(*icmpSrvSession))
	case 0x10: // DATA
		v, ok := s.sessions.Load(tokenKey)
		if !ok {
			return
		}
		s.handleData(pkt, srcAddr, conn, v.(*icmpSrvSession))
	case 0x20: // KEEPALIVE
		v, ok := s.sessions.Load(tokenKey)
		if !ok {
			return
		}
		sess := v.(*icmpSrvSession)
		sess.mu.Lock()
		sess.lastSeen = time.Now()
		sess.mu.Unlock()
		// Respond with a keepalive echo.
		resp := make([]byte, 8)
		resp[0] = 0x01
		resp[1] = 0x20
		copy(resp[2:4], token[:])
		conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
	}
}

// handleHello processes HANDSHAKE_HELLO and sends HANDSHAKE_ACK.
// Payload (starting at offset 8): clientPub (32 bytes).
func (s *ICMPServer) handleHello(pkt []byte, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	if len(pkt) < 8+32 {
		return
	}
	clientPub := pkt[8 : 8+32]

	// Generate server ephemeral keypair.
	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		return
	}
	serverPriv[0] &= 248
	serverPriv[31] = (serverPriv[31] & 127) | 64

	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		return
	}

	// DH shared secret.
	shared, err := curve25519.X25519(serverPriv[:], clientPub)
	if err != nil {
		return
	}

	// Assign session token (2 random bytes).
	var token [2]byte
	if _, err := rand.Read(token[:]); err != nil {
		return
	}

	// Derive session key.
	var sessionKey [32]byte
	hk := hkdf.New(sha256.New, shared, token[:], []byte("freewire-icmp-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return
	}

	sess := &icmpSrvSession{
		sessionToken: token,
		sessionKey:   sessionKey,
		serverPriv:   serverPriv,
		clientAddr:   srcAddr,
		activated:    false,
		lastSeen:     time.Now(),
		wgInbound:    make(chan []byte, 32),
	}
	tokenKey := binary.BigEndian.Uint16(token[:])
	s.sessions.Store(tokenKey, sess)

	// Send HANDSHAKE_ACK: header(8) + serverPub(32) + token(2) = 42 bytes.
	ack := make([]byte, 8+32+2)
	ack[0] = 0x01
	ack[1] = 0x02 // HANDSHAKE_ACK
	copy(ack[2:4], token[:])
	// Seq = 0
	copy(ack[8:], serverPub)
	copy(ack[40:], token[:])
	conn.WriteToUDP(ack, srcAddr) //nolint:errcheck
}

// handleConfirm verifies the client MAC and activates the session.
func (s *ICMPServer) handleConfirm(pkt []byte, srcAddr *net.UDPAddr, conn *net.UDPConn, sess *icmpSrvSession) {
	if len(pkt) < 8+16 {
		return
	}
	clientMAC := pkt[8 : 8+16]

	sess.mu.Lock()
	defer sess.mu.Unlock()

	expectedMAC := icmpSrvConfirmMAC(sess.sessionKey, sess.sessionToken)
	if !icmpHmacEqual(clientMAC, expectedMAC) {
		s.log.Error("icmp server: confirm MAC mismatch")
		return
	}

	// Open WG bridge socket.
	wgAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", s.wgPort))
	if err != nil {
		return
	}
	uc, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		s.log.Error("icmp server: dial wg udp", zap.Error(err))
		return
	}
	sess.localConn = uc
	sess.activated = true
	sess.lastSeen = time.Now()

	// Read WG inbound packets for delivery to client.
	// Closing wgInbound on exit unblocks the push goroutine below.
	go func() {
		defer close(sess.wgInbound)
		buf := make([]byte, 1<<16)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case sess.wgInbound <- pkt:
			default:
			}
		}
	}()

	// Goroutine to push WG inbound to client.
	udpConn := conn
	go func() {
		for pkt := range sess.wgInbound {
			sess.mu.Lock()
			seq := sess.txSeq
			sess.txSeq++
			key := sess.sessionKey
			tok := sess.sessionToken
			clientA := sess.clientAddr
			sess.mu.Unlock()

			hdr := make([]byte, 8)
			hdr[0] = 0x01
			hdr[1] = 0x10 // DATA
			copy(hdr[2:4], tok[:])
			binary.BigEndian.PutUint32(hdr[4:8], seq)

			aead, err := chacha20poly1305.New(key[:])
			if err != nil {
				continue
			}
			nonce := icmpSrvMakeNonce(seq)
			ciphertext := aead.Seal(nil, nonce, pkt, hdr)
			out := append(hdr, ciphertext...)
			udpConn.WriteToUDP(out, clientA) //nolint:errcheck
		}
	}()

	s.log.Info("icmp server: session activated")
}

// handleData decrypts an inbound data packet and forwards to WireGuard.
func (s *ICMPServer) handleData(pkt []byte, srcAddr *net.UDPAddr, conn *net.UDPConn, sess *icmpSrvSession) {
	if len(pkt) < 8 {
		return
	}
	sess.mu.Lock()
	if !sess.activated {
		sess.mu.Unlock()
		return
	}
	sess.lastSeen = time.Now()
	key := sess.sessionKey
	sess.mu.Unlock()

	hdr := pkt[:8]
	ciphertext := pkt[8:]
	seq := binary.BigEndian.Uint32(hdr[4:8])

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return
	}
	nonce := icmpSrvMakeNonce(seq)
	plain, err := aead.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		s.log.Error("icmp server: decrypt data", zap.Error(err))
		return
	}

	sess.localConn.Write(plain) //nolint:errcheck
}

// icmpSrvConfirmMAC = SHA256(sessionKey || "confirm" || sessionToken)[:16].
func icmpSrvConfirmMAC(key [32]byte, token [2]byte) []byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("confirm"))
	h.Write(token[:])
	return h.Sum(nil)[:16]
}

// icmpSrvMakeNonce builds a 12-byte nonce: seq(4B big-endian) || 0x00(8B).
func icmpSrvMakeNonce(seq uint32) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[:4], seq)
	return nonce
}

// icmpHmacEqual compares two byte slices in constant time.
func icmpHmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
