package transport

import (
	"context"
	"crypto/cipher"
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
	// Directional keys. Both peers number their packets from zero, so a single
	// shared key would produce the same (key, nonce) pair for the first packet
	// in each direction — catastrophic for ChaCha20-Poly1305. Separate keys per
	// direction keep every nonce unique under its own key.
	keyC2S [32]byte // client → server: server opens with this
	keyS2C [32]byte // server → client: server seals with this
	// sessionKey is retained only to authenticate the ClientConfirm MAC.
	sessionKey [32]byte
	// AEADs built once at activation. Constructing them per packet showed up as
	// pure overhead in the forwarding path.
	aeadRx cipher.AEAD // opens client → server
	aeadTx cipher.AEAD // seals server → client
	// Client address — all responses go here.
	clientAddr *net.UDPAddr
	// Per-session WG bridge socket.
	localConn *net.UDPConn
	// Sequence counters.
	txSeq    uint32
	mu       sync.Mutex
	lastSeen time.Time
	// Anti-replay state for the inbound direction: the highest sequence seen and
	// a bitmap of the 64 below it. Without this a captured packet can be replayed
	// indefinitely — it decrypts cleanly every time, since its nonce is valid.
	rxHighest uint32
	rxBitmap  uint64
	// Pending handshake state (before ClientConfirm).
	serverPriv [32]byte
	activated  bool
	// Inbound WG packets to forward to client.
	wgInbound chan []byte
}

// Worker pool sizing for the UDP read loop.
const (
	icmpWorkers    = 16
	icmpQueueDepth = 256
)

// icmpReplayWindow is how far behind the highest received sequence a packet may
// arrive and still be accepted. Matches the WireGuard/IPsec convention.
const icmpReplayWindow = 64

// checkReplay reports whether seq is fresh, recording it when so.
// Callers must hold sess.mu.
func (sess *icmpSrvSession) checkReplay(seq uint32) bool {
	switch {
	case seq > sess.rxHighest:
		// Advance the window, shifting the bitmap by the gap.
		shift := seq - sess.rxHighest
		if shift >= icmpReplayWindow {
			sess.rxBitmap = 0
		} else {
			sess.rxBitmap <<= shift
		}
		sess.rxBitmap |= 1
		sess.rxHighest = seq
		return true

	case sess.rxHighest-seq >= icmpReplayWindow:
		// Too old to prove it is not a replay.
		return false

	default:
		bit := uint64(1) << (sess.rxHighest - seq)
		if sess.rxBitmap&bit != 0 {
			return false // already seen
		}
		sess.rxBitmap |= bit
		return true
	}
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

	// Bounded worker pool. Spawning a goroutine per datagram let any burst -- or
	// a flood -- create unbounded goroutines and heap copies.
	type job struct {
		pkt  []byte
		addr *net.UDPAddr
	}
	jobs := make(chan job, icmpQueueDepth)
	defer close(jobs)
	for i := 0; i < icmpWorkers; i++ {
		go func() {
			for j := range jobs {
				s.handlePacket(j.pkt, j.addr, uc)
			}
		}()
	}

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
		select {
		case jobs <- job{pkt: pkt, addr: srcAddr}:
		default:
			// Queue full: drop rather than block the read loop. The tunnel
			// protocol already tolerates loss.
		}
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

	// Assign session token (2 random bytes). The space is only 65536 wide, so
	// collisions are realistic; storing over a live entry would strand that
	// session's goroutines with no one left to close their channel.
	var token [2]byte
	var tokenKey uint16
	claimed := false
	sess := &icmpSrvSession{}
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(token[:]); err != nil {
			return
		}
		tokenKey = binary.BigEndian.Uint16(token[:])
		if _, loaded := s.sessions.LoadOrStore(tokenKey, sess); !loaded {
			claimed = true
			break
		}
	}
	if !claimed {
		s.log.Error("icmp server: could not allocate a free session token")
		return
	}

	// Derive the session key plus one key per direction. Reading 96 bytes from a
	// single HKDF stream keeps all three independent.
	var sessionKey, keyC2S, keyS2C [32]byte
	hk := hkdf.New(sha256.New, shared, token[:], []byte("freewire-icmp-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(hk, keyC2S[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(hk, keyS2C[:]); err != nil {
		return
	}

	*sess = icmpSrvSession{
		sessionToken: token,
		sessionKey:   sessionKey,
		keyC2S:       keyC2S,
		keyS2C:       keyS2C,
		serverPriv:   serverPriv,
		clientAddr:   srcAddr,
		activated:    false,
		lastSeen:     time.Now(),
		wgInbound:    make(chan []byte, 32),
	}

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

	// Activation is idempotent. A retransmitted CONFIRM would otherwise open a
	// second bridge socket and start a second pair of goroutines, orphaning the
	// first pair against a socket nothing will close.
	if sess.activated {
		return
	}

	expectedMAC := icmpSrvConfirmMAC(sess.sessionKey, sess.sessionToken)
	if !icmpHmacEqual(clientMAC, expectedMAC) {
		s.log.Error("icmp server: confirm MAC mismatch")
		return
	}

	// Build both AEADs once; the keys are fixed for the session lifetime.
	aeadRx, err := chacha20poly1305.New(sess.keyC2S[:])
	if err != nil {
		return
	}
	aeadTx, err := chacha20poly1305.New(sess.keyS2C[:])
	if err != nil {
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
	sess.aeadRx = aeadRx
	sess.aeadTx = aeadTx
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
			aead := sess.aeadTx
			tok := sess.sessionToken
			clientA := sess.clientAddr
			sess.mu.Unlock()

			hdr := make([]byte, 8)
			hdr[0] = 0x01
			hdr[1] = 0x10 // DATA
			copy(hdr[2:4], tok[:])
			binary.BigEndian.PutUint32(hdr[4:8], seq)

			var nonce [12]byte
			icmpSrvNonceInto(seq, &nonce)
			ciphertext := aead.Seal(nil, nonce[:], pkt, hdr)
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
	aead := sess.aeadRx
	seq := binary.BigEndian.Uint32(pkt[4:8])
	fresh := sess.checkReplay(seq)
	sess.mu.Unlock()

	if !fresh {
		// Replayed or too old to verify. Dropping before decryption also keeps
		// a replay flood from costing any AEAD work.
		return
	}

	hdr := pkt[:8]
	ciphertext := pkt[8:]

	var nonce [12]byte
	icmpSrvNonceInto(seq, &nonce)
	plain, err := aead.Open(nil, nonce[:], ciphertext, hdr)
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

// icmpSrvNonceInto writes a 12-byte nonce into out: seq(4B big-endian) || 0x00(8B).
// Filling a caller-owned array keeps the nonce off the heap in the packet path.
func icmpSrvNonceInto(seq uint32, out *[12]byte) {
	*out = [12]byte{}
	binary.BigEndian.PutUint32(out[:4], seq)
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
