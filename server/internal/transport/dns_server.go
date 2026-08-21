package transport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DNSServer is an authoritative DNS server for tunnel.freewire.com.
// It handles the Freewire DNS tunnel protocol:
//
//   h.1.<b32(clientPub)>.tunnel.freewire.com  → ClientHello
//   h.3.<b32(mac)>.<b32(token)>.tunnel.freewire.com → ClientConfirm
//   t.<b32(seq)>.<b32(token)>.<...data...>.tunnel.freewire.com → data
//   k.<b32(token)>.tunnel.freewire.com → keepalive
type DNSServer struct {
	wgPort   int
	sessions sync.Map // base32(token) → *dnsSession
	log      *zap.Logger
}

// dnsSession holds the server-side state for one DNS tunnel session.
type dnsSession struct {
	token      [10]byte
	// sessionKey authenticates the ClientConfirm MAC only.
	sessionKey [32]byte
	// Directional keys. Both peers number packets from zero, so a single shared
	// key would repeat the (key, nonce) pair across directions.
	keyC2S [32]byte // client → server: server opens with this
	keyS2C [32]byte // server → client: server seals with this
	// Each session gets its own UDP socket dialing the local WG port.
	localConn *net.UDPConn
	wgAddr    *net.UDPAddr
	// Sequence counters.
	rxSeq  uint32
	txSeq  uint32
	mu     sync.Mutex
	// Handshake state: pending until ClientConfirm received.
	serverPriv  [32]byte
	serverPub   []byte
	confirmMAC  []byte // expected MAC from client
	activated   bool
	lastSeen    time.Time
	// Inbound WG packets queued for piggybacking in data responses.
	wgInbound chan []byte
}

var srvB32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewDNSServer creates a DNSServer that bridges to WireGuard on wgPort.
func NewDNSServer(wgPort int, log *zap.Logger) *DNSServer {
	return &DNSServer{wgPort: wgPort, log: log}
}

// Run starts the authoritative DNS UDP listener on port and serves until ctx is done.
func (s *DNSServer) Run(ctx context.Context, port int) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dns server: listen: %w", err)
	}
	s.log.Info("dns tunnel listening", zap.Int("port", port))

	go s.evictLoop(ctx)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	buf := make([]byte, 4096)
	uc := ln.(*net.UDPConn)
	for {
		n, srcAddr, err := uc.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("dns server: read", zap.Error(err))
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleQuery(pkt, srcAddr, uc)
	}
}

// evictLoop removes sessions that haven't been seen in 90 seconds.
func (s *DNSServer) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(k, v any) bool {
				sess := v.(*dnsSession)
				sess.mu.Lock()
				ls := sess.lastSeen
				sess.mu.Unlock()
				if now.Sub(ls) > 90*time.Second {
					s.sessions.Delete(k)
					if sess.localConn != nil {
						sess.localConn.Close()
					}
					s.log.Info("dns server: session evicted")
				}
				return true
			})
		}
	}
}

// handleQuery dispatches an incoming DNS query to the appropriate handler.
func (s *DNSServer) handleQuery(buf []byte, srcAddr *net.UDPAddr, conn *net.UDPConn) {
	if len(buf) < 12 {
		return
	}
	qid := buf[:2] // DNS query ID to echo in response

	// Parse the question QNAME.
	name, err := extractQNAME(buf, 12)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	name = strings.ToUpper(strings.TrimSuffix(name, "."))
	suffix := strings.ToUpper("." + "TUNNEL.FREEWIRE.COM")
	if !strings.HasSuffix(name, suffix) {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	// Strip the tunnel domain suffix.
	label := strings.TrimSuffix(name, strings.ToUpper(".TUNNEL.FREEWIRE.COM"))

	parts := strings.Split(label, ".")
	if len(parts) < 2 {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	switch strings.ToUpper(parts[0]) {
	case "H":
		s.handleHandshake(conn, srcAddr, qid, parts[1:])
	case "T":
		s.handleData(conn, srcAddr, qid, parts[1:])
	case "K":
		s.handleKeepalive(conn, srcAddr, qid, parts[1:])
	default:
		s.sendNXDomain(conn, srcAddr, qid)
	}
}

// handleHandshake dispatches h.1.* (ClientHello) and h.3.* (ClientConfirm).
func (s *DNSServer) handleHandshake(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte, parts []string) {
	if len(parts) < 1 {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	switch parts[0] {
	case "1":
		// ClientHello: parts[1] = b32(clientPub)
		if len(parts) < 2 {
			s.sendNXDomain(conn, srcAddr, qid)
			return
		}
		s.handleClientHello(conn, srcAddr, qid, parts[1])
	case "3":
		// ClientConfirm: parts[1] = b32(mac), parts[2] = b32(token)
		if len(parts) < 3 {
			s.sendNXDomain(conn, srcAddr, qid)
			return
		}
		s.handleClientConfirm(conn, srcAddr, qid, parts[1], parts[2])
	default:
		s.sendNXDomain(conn, srcAddr, qid)
	}
}

// handleClientHello processes a ClientHello query and sends ServerHello TXT response.
// TXT value: <b32(serverPub)>.<b32(token)>
func (s *DNSServer) handleClientHello(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte, clientPubB32 string) {
	clientPub, err := srvB32enc.DecodeString(clientPubB32)
	if err != nil {
		s.log.Error("dns: decode client pub", zap.Error(err))
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Generate server ephemeral keypair.
	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	serverPriv[0] &= 248
	serverPriv[31] = (serverPriv[31] & 127) | 64

	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// DH shared secret.
	shared, err := curve25519.X25519(serverPriv[:], clientPub)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Generate session token (10 bytes).
	var token [10]byte
	if _, err := rand.Read(token[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Derive the confirm-MAC key plus one key per direction off a single HKDF
	// stream. Directional separation keeps every (key, nonce) pair unique even
	// though both peers number their packets from zero.
	var sessionKey, keyC2S, keyS2C [32]byte
	hk := hkdf.New(sha256.New, shared, token[:], []byte("freewire-dns-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	if _, err := io.ReadFull(hk, keyC2S[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	if _, err := io.ReadFull(hk, keyS2C[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Compute expected ClientConfirm MAC.
	mac := dnsSrvConfirmMAC(sessionKey, token[:])

	// Create session (not yet activated — waiting for ClientConfirm).
	sess := &dnsSession{
		token:      token,
		sessionKey: sessionKey,
		keyC2S:     keyC2S,
		keyS2C:     keyS2C,
		serverPriv: serverPriv,
		serverPub:  serverPub,
		confirmMAC: mac,
		activated:  false,
		lastSeen:   time.Now(),
		wgInbound:  make(chan []byte, 32),
	}
	key := srvB32enc.EncodeToString(token[:])
	s.sessions.Store(key, sess)

	// Build TXT response: <b32(serverPub)>.<b32(token)>
	txt := srvB32enc.EncodeToString(serverPub) + "." + srvB32enc.EncodeToString(token[:])
	resp := buildDNSTXTResponse(qid, txt)
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleClientConfirm activates the session after verifying the client's MAC.
func (s *DNSServer) handleClientConfirm(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte, macB32, tokenB32 string) {
	v, ok := s.sessions.Load(strings.ToUpper(tokenB32))
	if !ok {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	sess := v.(*dnsSession)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	clientMAC, err := srvB32enc.DecodeString(macB32)
	if err != nil || !hmacEqual(clientMAC, sess.confirmMAC) {
		s.log.Error("dns: client confirm MAC mismatch")
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Activate session: open per-session WG bridge socket.
	wgAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", s.wgPort))
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	uc, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		s.log.Error("dns: dial wg udp", zap.Error(err))
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	sess.localConn = uc
	sess.wgAddr = wgAddr
	sess.activated = true
	sess.lastSeen = time.Now()

	// Start goroutine to read WG responses for piggybacking.
	go func() {
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
				// Drop if backpressured.
			}
		}
	}()

	s.log.Info("dns: session activated")
	resp := buildDNSTXTResponse(qid, "OK")
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleData processes a data query: decrypt, forward to WG, piggyback response.
func (s *DNSServer) handleData(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte, parts []string) {
	// parts[0] = b32(seq), parts[1] = b32(token), parts[2..] = b32(ciphertext) chunks
	if len(parts) < 3 {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	tokenB32 := parts[1]
	v, ok := s.sessions.Load(strings.ToUpper(tokenB32))
	if !ok {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	sess := v.(*dnsSession)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if !sess.activated {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	sess.lastSeen = time.Now()

	seqBytes, err := srvB32enc.DecodeString(parts[0])
	if err != nil || len(seqBytes) != 4 {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	seq := binary.BigEndian.Uint32(seqBytes)

	// Join all remaining label chunks as the ciphertext (they were split at 63 chars).
	cipherB32 := strings.Join(parts[2:], "")
	ciphertext, err := srvB32enc.DecodeString(cipherB32)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	rxAEAD, err := chacha20poly1305.New(sess.keyC2S[:])
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	nonce := srvDNSMakeNonce(seq)
	plain, err := rxAEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		s.log.Error("dns: decrypt data", zap.Error(err))
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}

	// Forward plaintext to WireGuard.
	sess.localConn.Write(plain) //nolint:errcheck

	// Piggyback any pending WG inbound response.
	var wgPkt []byte
	select {
	case wgPkt = <-sess.wgInbound:
	default:
	}

	if len(wgPkt) == 0 {
		// Nothing to piggyback — send empty ACK.
		resp := buildDNSTXTResponse(qid, "")
		conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
		return
	}

	// Encrypt WG response packet.
	txSeq := sess.txSeq
	sess.txSeq++
	txAEAD, err := chacha20poly1305.New(sess.keyS2C[:])
	if err != nil {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	txNonce := srvDNSMakeNonce(txSeq)
	encrypted := txAEAD.Seal(nil, txNonce, wgPkt, nil)

	// Encode response: <b32(txSeq)>.<b32(encrypted)>
	txSeqB32 := srvB32enc.EncodeToString(uint32BESrv(txSeq))
	encB32 := srvB32enc.EncodeToString(encrypted)
	txt := txSeqB32 + "." + encB32
	resp := buildDNSTXTResponse(qid, txt)
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleKeepalive updates the session lastSeen timestamp and responds with "K".
func (s *DNSServer) handleKeepalive(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte, parts []string) {
	if len(parts) < 1 {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	v, ok := s.sessions.Load(strings.ToUpper(parts[0]))
	if !ok {
		s.sendNXDomain(conn, srcAddr, qid)
		return
	}
	sess := v.(*dnsSession)
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	sess.mu.Unlock()

	resp := buildDNSTXTResponse(qid, "K")
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// sendNXDomain sends a DNS NXDOMAIN response.
func (s *DNSServer) sendNXDomain(conn *net.UDPConn, srcAddr *net.UDPAddr, qid []byte) {
	resp := buildDNSNXDomain(qid)
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// extractQNAME parses the DNS question section QNAME starting at offset in buf.
func extractQNAME(buf []byte, offset int) (string, error) {
	var labels []string
	for offset < len(buf) {
		length := int(buf[offset])
		offset++
		if length == 0 {
			break
		}
		if length >= 0xC0 {
			// Pointer — for our purposes we don't follow it; just stop.
			return strings.Join(labels, ".") + ".", nil
		}
		if offset+length > len(buf) {
			return "", fmt.Errorf("qname label overflows buffer")
		}
		labels = append(labels, string(buf[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, ".") + ".", nil
}

// buildDNSTXTResponse builds a minimal DNS TXT response packet.
// A single TXT character-string is limited to 255 bytes by RFC 1035 §3.3.14.
// Longer payloads are split into multiple character-strings within one RDATA.
func buildDNSTXTResponse(qid []byte, txt string) []byte {
	var buf []byte
	buf = append(buf, qid...)
	buf = append(buf, 0x84, 0x00) // flags: QR=1, AA=1, RCODE=0
	buf = append(buf, 0x00, 0x00) // QDCOUNT = 0 (we omit the question section in response)
	buf = append(buf, 0x00, 0x01) // ANCOUNT = 1
	buf = append(buf, 0x00, 0x00) // NSCOUNT = 0
	buf = append(buf, 0x00, 0x00) // ARCOUNT = 0

	buf = append(buf, 0x00)       // NAME = root label
	buf = append(buf, 0x00, 0x10) // TYPE = TXT (16)
	buf = append(buf, 0x00, 0x01) // CLASS = IN
	buf = append(buf, 0x00, 0x00, 0x00, 0x3C) // TTL = 60

	// Build RDATA: one or more length-prefixed character-strings of ≤255 bytes each.
	var rdata []byte
	if txt == "" {
		rdata = append(rdata, 0x00) // single empty string
	} else {
		b := []byte(txt)
		for len(b) > 0 {
			chunk := b
			if len(chunk) > 255 {
				chunk = b[:255]
			}
			rdata = append(rdata, byte(len(chunk)))
			rdata = append(rdata, chunk...)
			b = b[len(chunk):]
		}
	}
	buf = append(buf, byte(len(rdata)>>8), byte(len(rdata)))
	buf = append(buf, rdata...)
	return buf
}

// buildDNSNXDomain builds a minimal DNS NXDOMAIN response.
func buildDNSNXDomain(qid []byte) []byte {
	var buf []byte
	buf = append(buf, qid...)
	buf = append(buf, 0x84, 0x03) // flags: QR=1, AA=1, RCODE=NXDOMAIN(3)
	buf = append(buf, 0x00, 0x00) // QDCOUNT=0
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0
	return buf
}

// srvDNSMakeNonce builds a 12-byte ChaCha20-Poly1305 nonce: seq(4B big-endian) || 0x00(8B).
func srvDNSMakeNonce(seq uint32) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[:4], seq)
	return nonce
}

// uint32BESrv encodes a uint32 as 4-byte big-endian.
func uint32BESrv(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// dnsSrvConfirmMAC = SHA256(sessionKey || "confirm" || token)[:16].
func dnsSrvConfirmMAC(key [32]byte, token []byte) []byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("confirm"))
	h.Write(token)
	return h.Sum(nil)[:16]
}

// hmacEqual compares two byte slices in constant time.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
