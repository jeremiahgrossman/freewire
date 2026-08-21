package main

import (
	"crypto/cipher"
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

	icmpHeaderLen  = 8
	icmpMaxPayload = 1416
	// Read buffers are sized past the largest datagram the tunnel can produce.
	// net.PacketConn.ReadFrom discards whatever does not fit, so a buffer at
	// exactly icmpMaxPayload silently truncated full-size packets, which were
	// then encrypted and shipped as corrupt.
	icmpReadBuf     = 2048
	icmpWindowInit  = 4
	icmpWindowMax   = 16
	icmpKeepalive   = 15 * time.Second
	icmpHandshakeTO = 2 * time.Second
	icmpRateLimit   = 20 // packets/second hard cap
	// Outbound send pool. Small on purpose: the rate cap above already bounds
	// throughput, so more workers would only reorder packets.
	icmpSendWorkers = 2
	icmpSendQueue   = 64
)

// icmpClientSession holds the state for an active ICMP/UDP tunnel session.
type icmpClientSession struct {
	sessionToken [2]byte  // 2-byte session token (low 2 bytes of full token)
	sessionKey   [32]byte // authenticates the ClientConfirm MAC only
	// Directional keys. Both peers number packets from zero, so one shared
	// key would repeat the (key, nonce) pair across directions.
	keyC2S [32]byte // client → server: client seals with this
	keyS2C [32]byte // server → client: client opens with this
	// AEADs built once at handshake rather than per packet, matching the
	// server, which already does this in the same forwarding path.
	aeadTx     cipher.AEAD
	aeadRx     cipher.AEAD
	txSeq      uint32 // outbound sequence (atomic)
	windowSize int    // current sliding window size
	conn       *net.UDPConn
	mu         sync.Mutex

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

	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.ICMPUDPPort)))
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
	uc.SetDeadline(deadline)          //nolint:errcheck
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
	// Three 32-byte reads off one stream: the confirm-MAC key, then one key per
	// direction. Directional separation is what keeps nonces unique — both sides
	// number packets from zero, so a shared key would repeat (key, nonce).
	var sessionKey, keyC2S, keyS2C [32]byte
	hk := hkdf.New(sha256.New, shared, sessionToken[:], []byte("freewire-icmp-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	if _, err := io.ReadFull(hk, keyC2S[:]); err != nil {
		return nil, fmt.Errorf("derive c2s key: %w", err)
	}
	if _, err := io.ReadFull(hk, keyS2C[:]); err != nil {
		return nil, fmt.Errorf("derive s2c key: %w", err)
	}

	// Step 3: HANDSHAKE_CONFIRM
	// Payload: MAC = SHA256(sessionKey || "confirm" || sessionToken)[:16]
	mac := icmpConfirmMAC(sessionKey, sessionToken)
	aeadTx, err := chacha20poly1305.New(keyC2S[:])
	if err != nil {
		return nil, fmt.Errorf("icmp handshake: aead tx: %w", err)
	}
	aeadRx, err := chacha20poly1305.New(keyS2C[:])
	if err != nil {
		return nil, fmt.Errorf("icmp handshake: aead rx: %w", err)
	}

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
		keyC2S:       keyC2S,
		keyS2C:       keyS2C,
		aeadTx:       aeadTx,
		aeadRx:       aeadRx,
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

	// done is closed when the local proxy goes away. Without it the keepalive
	// loop below ran forever against a dead socket, holding the session and both
	// goroutines for the lifetime of the process.
	done := make(chan struct{})
	var closeOnce sync.Once
	finish := func() { closeOnce.Do(func() { close(done) }) }

	// wgPeer is written by the main loop and read by the inbound goroutine.
	var peerMu sync.Mutex
	var wgPeer net.Addr

	var peerOnce sync.Once
	peerCh := make(chan net.Addr, 1)

	// WireGuard → ICMP/UDP.
	//
	// Sends go through a small bounded pool rather than a goroutine per packet.
	// A burst from wireguard-go used to map one-to-one onto goroutines, with no
	// ceiling, and reordered packets on the way out -- which pushed the server's
	// replay window harder than necessary for no benefit.
	sendCh := make(chan []byte, icmpSendQueue)
	for i := 0; i < icmpSendWorkers; i++ {
		go func() {
			for pkt := range sendCh {
				s.sendData(pkt) //nolint:errcheck
			}
		}()
	}

	go func() {
		defer finish()
		defer close(sendCh)
		buf := make([]byte, icmpReadBuf)
		for {
			n, peer, err := lp.ReadFrom(buf)
			if err != nil {
				return
			}
			peerOnce.Do(func() { peerCh <- peer })
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case sendCh <- pkt:
			default:
				// Queue full: drop rather than grow without bound. The 20 pkt/s
				// rate cap means a backlog is never going to drain in time.
			}
		}
	}()

	// ICMP/UDP → WireGuard.
	go func() {
		defer finish()
		buf := make([]byte, icmpReadBuf)
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
			peerMu.Lock()
			peer := wgPeer
			peerMu.Unlock()
			if peer != nil {
				lp.WriteTo(data, peer) //nolint:errcheck
			}
		}
	}()

	for {
		select {
		case <-done:
			s.conn.Close() //nolint:errcheck
			return
		case peer := <-peerCh:
			peerMu.Lock()
			wgPeer = peer
			peerMu.Unlock()
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
		// Truncating here produced a packet that failed the peer's tag check
		// with no diagnostic. Refuse it instead.
		return fmt.Errorf("send data: payload %d exceeds the %d-byte budget", len(payload), icmpMaxPayload)
	}
	if !s.rateCheck() {
		return fmt.Errorf("rate limit exceeded")
	}

	seq := atomic.AddUint32(&s.txSeq, 1) - 1
	aead, err := chacha20poly1305.New(s.keyC2S[:])
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

	aead, err := chacha20poly1305.New(s.keyS2C[:])
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
