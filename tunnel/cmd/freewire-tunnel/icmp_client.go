package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ICMP-over-UDP tunnel implementation per icmp-tunnel-protocol-spec.md.
//
// Freewire header: Version(1) + Type(1) + SessionToken(2) + Seq(4) = 8 bytes
// Handshake:  HANDSHAKE_HELLO(0x01), HANDSHAKE_ACK(0x02), HANDSHAKE_CONFIRM(0x03)
// Data:       DATA(0x10)
// Keepalive:  KEEPALIVE(0x20)
// Encryption: ChaCha20-Poly1305, AAD = Freewire header (8 bytes)
// Max payload: 1416 bytes
// Rate limit: 20 packets/second hard cap
// Keepalive:  every 15s when idle

const (
	icmpVersion     = 0x01
	icmpTypeHello   = 0x01
	icmpTypeACK     = 0x02
	icmpTypeConfirm = 0x03
	icmpTypeData    = 0x10
	icmpTypeKA      = 0x20

	icmpHeaderLen   = 8
	icmpMaxPayload  = 1416
	icmpWindowInit  = 4
	icmpWindowMax   = 16
	icmpKeepalive   = 15 * time.Second
	icmpHandshakeTO = 2 * time.Second
	icmpRateLimit   = 20 // packets/second hard cap
)

// icmpClientSession holds the state for an active ICMP/UDP tunnel session.
type icmpClientSession struct {
	sessionToken [2]byte  // 2-byte session token (low 2 bytes of full token)
	sessionKey   [32]byte // ChaCha20-Poly1305 key
	txSeq        uint32   // outbound sequence (atomic)
	windowSize   int      // current sliding window size
	conn         *net.UDPConn
	mu           sync.Mutex

	// Rate limiter: token bucket, refilled every 50ms (20 pkt/s = 1 per 50ms).
	rateMu    sync.Mutex
	rateAvail int
	rateLast  time.Time
}

// runICMPUDPTunnel establishes the ICMP/UDP tunnel and returns a local UDP
// PacketConn bridging wireguard-go ↔ ICMP/UDP tunnel.
// Returns error if the handshake fails within icmpHandshakeTO.
func runICMPUDPTunnel(cfg Config) (net.PacketConn, error) {
	host := cfg.ServerHost
	if host == "" {
		h, _, err := net.SplitHostPort(cfg.ServerEndpoint)
		if err != nil {
			return nil, fmt.Errorf("icmp tunnel: no server host: %w", err)
		}
		host = h
	}

	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, "4500"))
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: resolve addr: %w", err)
	}
	uc, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("icmp tunnel: dial: %w", err)
	}

	sess, err := icmpHandshake(cfg, uc)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("icmp tunnel: handshake: %w", err)
	}

	lp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("icmp tunnel: local proxy: %w", err)
	}

	go sess.run(lp)
	return lp, nil
}

// icmpHandshake performs the 3-step ICMP handshake.
//
// Step 1: Send HANDSHAKE_HELLO with client ephemeral DH public key.
// Step 2: Receive HANDSHAKE_ACK with server DH public key + session token.
// Step 3: Send HANDSHAKE_CONFIRM with derived-key MAC.
func icmpHandshake(cfg Config, uc *net.UDPConn) (*icmpClientSession, error) {
	deadline := time.Now().Add(icmpHandshakeTO)
	uc.SetDeadline(deadline) //nolint:errcheck
	defer uc.SetDeadline(time.Time{}) //nolint:errcheck

	// Generate ephemeral Curve25519 keypair.
	var clientPriv [32]byte
	if _, err := rand.Read(clientPriv[:]); err != nil {
		return nil, fmt.Errorf("generate dh key: %w", err)
	}
	clientPriv[0] &= 248
	clientPriv[31] = (clientPriv[31] & 127) | 64

	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive dh public key: %w", err)
	}

	// Step 1: HANDSHAKE_HELLO
	// Header: Version(1) + Type=HELLO(1) + SessionToken=0(2) + Seq=0(4) = 8 bytes
	// Payload: clientPub (32 bytes)
	hello := make([]byte, icmpHeaderLen+32)
	hello[0] = icmpVersion
	hello[1] = icmpTypeHello
	// SessionToken = 0x0000, Seq = 0x00000000 (already zero)
	copy(hello[icmpHeaderLen:], clientPub)
	if _, err := uc.Write(hello); err != nil {
		return nil, fmt.Errorf("send hello: %w", err)
	}

	// Step 2: Receive HANDSHAKE_ACK
	// Expected: Header(8) + serverPub(32) + sessionToken(2) = 42 bytes
	ackBuf := make([]byte, 256)
	n, err := uc.Read(ackBuf)
	if err != nil {
		return nil, fmt.Errorf("recv ack: %w", err)
	}
	if n < icmpHeaderLen+34 {
		return nil, fmt.Errorf("ack too short: %d bytes", n)
	}
	if ackBuf[1] != icmpTypeACK {
		return nil, fmt.Errorf("expected HANDSHAKE_ACK(0x02), got 0x%02x", ackBuf[1])
	}
	serverPub := ackBuf[icmpHeaderLen : icmpHeaderLen+32]
	var sessionToken [2]byte
	copy(sessionToken[:], ackBuf[icmpHeaderLen+32:icmpHeaderLen+34])

	// Derive shared secret.
	shared, err := curve25519.X25519(clientPriv[:], serverPub)
	if err != nil {
		return nil, fmt.Errorf("dh exchange: %w", err)
	}

	// Derive session key: HKDF-SHA256(ikm=shared, salt=sessionToken, info="freewire-icmp-tunnel-v1").
	var sessionKey [32]byte
	hk := hkdf.New(sha256.New, shared, sessionToken[:], []byte("freewire-icmp-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	// Step 3: HANDSHAKE_CONFIRM
	// Payload: MAC = SHA256(sessionKey || "confirm" || sessionToken)[:16]
	mac := icmpConfirmMAC(sessionKey, sessionToken)
	confirm := make([]byte, icmpHeaderLen+16)
	confirm[0] = icmpVersion
	confirm[1] = icmpTypeConfirm
	copy(confirm[2:4], sessionToken[:])
	// Seq = 1
	binary.BigEndian.PutUint32(confirm[4:8], 1)
	copy(confirm[icmpHeaderLen:], mac)
	if _, err := uc.Write(confirm); err != nil {
		return nil, fmt.Errorf("send confirm: %w", err)
	}

	sess := &icmpClientSession{
		sessionToken: sessionToken,
		sessionKey:   sessionKey,
		txSeq:        2, // 0=hello, 1=confirm, data starts at 2
		windowSize:   icmpWindowInit,
		conn:         uc,
		rateAvail:    icmpRateLimit,
		rateLast:     time.Now(),
	}
	return sess, nil
}

// icmpConfirmMAC = SHA256(sessionKey || "confirm" || sessionToken)[:16].
func icmpConfirmMAC(key [32]byte, token [2]byte) []byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("confirm"))
	h.Write(token[:])
	return h.Sum(nil)[:16]
}

// run bridges localProxy UDP ↔ ICMP/UDP tunnel.
func (s *icmpClientSession) run(lp net.PacketConn) {
	ka := time.NewTicker(icmpKeepalive)
	defer ka.Stop()

	var wgPeer net.Addr
	var peerOnce sync.Once
	peerCh := make(chan net.Addr, 1)

	// WireGuard → ICMP/UDP.
	go func() {
		buf := make([]byte, icmpMaxPayload)
		for {
			n, peer, err := lp.ReadFrom(buf)
			if err != nil {
				return
			}
			peerOnce.Do(func() { peerCh <- peer })
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			go s.sendData(pkt) //nolint:errcheck
		}
	}()

	// ICMP/UDP → WireGuard.
	go func() {
		buf := make([]byte, icmpHeaderLen+icmpMaxPayload+16+16) // header + overhead
		for {
			n, err := s.conn.Read(buf)
			if err != nil {
				return
			}
			if n < icmpHeaderLen {
				continue
			}
			if buf[1] != icmpTypeData {
				continue
			}
			data, err := s.decryptData(buf[:n])
			if err != nil {
				continue
			}
			if wgPeer != nil {
				lp.WriteTo(data, wgPeer) //nolint:errcheck
			}
		}
	}()

	for {
		select {
		case peer := <-peerCh:
			wgPeer = peer
		case <-ka.C:
			s.sendKeepalive() //nolint:errcheck
		}
	}
}

// rateCheck returns true if a packet can be sent (token bucket, 20 pkt/s).
func (s *icmpClientSession) rateCheck() bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	elapsed := now.Sub(s.rateLast)
	// Refill: 20 tokens/second = 1 token per 50ms.
	refill := int(elapsed.Milliseconds() / 50)
	if refill > 0 {
		s.rateAvail += refill
		if s.rateAvail > icmpRateLimit {
			s.rateAvail = icmpRateLimit
		}
		s.rateLast = now
	}
	if s.rateAvail <= 0 {
		return false
	}
	s.rateAvail--
	return true
}

// sendData encrypts and sends a data packet over the ICMP/UDP connection.
func (s *icmpClientSession) sendData(payload []byte) error {
	if len(payload) > icmpMaxPayload {
		payload = payload[:icmpMaxPayload]
	}
	if !s.rateCheck() {
		return fmt.Errorf("rate limit exceeded")
	}

	seq := atomic.AddUint32(&s.txSeq, 1) - 1
	aead, err := chacha20poly1305.New(s.sessionKey[:])
	if err != nil {
		return fmt.Errorf("aead: %w", err)
	}

	// Build header (8 bytes): Version + Type + SessionToken(2) + Seq(4).
	hdr := make([]byte, icmpHeaderLen)
	hdr[0] = icmpVersion
	hdr[1] = icmpTypeData
	copy(hdr[2:4], s.sessionToken[:])
	binary.BigEndian.PutUint32(hdr[4:8], seq)

	// Nonce: seq(4B big-endian) || 0x00(8B).
	nonce := icmpMakeNonce(seq)
	// AAD = header.
	ciphertext := aead.Seal(nil, nonce, payload, hdr)

	pkt := append(hdr, ciphertext...)
	_, err = s.conn.Write(pkt)
	return err
}

// decryptData decrypts an inbound ICMP/UDP data packet.
func (s *icmpClientSession) decryptData(pkt []byte) ([]byte, error) {
	if len(pkt) < icmpHeaderLen {
		return nil, fmt.Errorf("pkt too short")
	}
	hdr := pkt[:icmpHeaderLen]
	ciphertext := pkt[icmpHeaderLen:]
	seq := binary.BigEndian.Uint32(hdr[4:8])

	aead, err := chacha20poly1305.New(s.sessionKey[:])
	if err != nil {
		return nil, fmt.Errorf("aead: %w", err)
	}
	nonce := icmpMakeNonce(seq)
	return aead.Open(nil, nonce, ciphertext, hdr)
}

// sendKeepalive sends a KEEPALIVE packet.
func (s *icmpClientSession) sendKeepalive() error {
	seq := atomic.AddUint32(&s.txSeq, 1) - 1
	pkt := make([]byte, icmpHeaderLen)
	pkt[0] = icmpVersion
	pkt[1] = icmpTypeKA
	copy(pkt[2:4], s.sessionToken[:])
	binary.BigEndian.PutUint32(pkt[4:8], seq)
	_, err := s.conn.Write(pkt)
	return err
}

// icmpMakeNonce builds a 12-byte ChaCha20-Poly1305 nonce: seq(4B big-endian) || 0x00(8B).
func icmpMakeNonce(seq uint32) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[:4], seq)
	return nonce
}
