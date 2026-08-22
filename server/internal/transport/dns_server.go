package transport

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DNSServer is an authoritative DNS server for tunnel.freewire.com.
// It handles the Freewire DNS tunnel protocol:
//
//	h.1.<b32(clientPub)>.tunnel.freewire.com  → ClientHello
//	h.3.<b32(mac)>.<b32(token)>.tunnel.freewire.com → ClientConfirm
//	t.<b32(seq)>.<b32(token)>.<...data...>.tunnel.freewire.com → data
//	k.<b32(token)>.tunnel.freewire.com → keepalive
type DNSServer struct {
	wgPort   int
	sessions sync.Map // base32(token) → *dnsSession
	// pending counts sessions awaiting a ClientConfirm, tracked separately so a
	// hello flood cannot displace established tunnels.
	pending atomic.Int64
	log     *zap.Logger
}

// dnsSession holds the server-side state for one DNS tunnel session.
type dnsSession struct {
	token [10]byte
	// sessionKey authenticates the ClientConfirm MAC only.
	sessionKey [32]byte
	// Directional keys. Both peers number packets from zero, so a single shared
	// key would repeat the (key, nonce) pair across directions.
	keyC2S [32]byte // client → server: server opens with this
	keyS2C [32]byte // server → client: server seals with this
	// AEADs built once at activation rather than per packet.
	aeadRx cipher.AEAD
	aeadTx cipher.AEAD
	// Each session gets its own UDP socket dialing the local WG port.
	localConn *net.UDPConn
	wgAddr    *net.UDPAddr
	// Sequence counters.
	txSeq uint32
	mu    sync.Mutex
	// Anti-replay for the inbound direction. The ICMP transport received this
	// protection; the DNS one did not, so a captured query decrypted cleanly
	// every time it was resent -- and on this path the local resolver and the
	// portal operator both see every query. See replayWindow.
	rx replayWindow
	// Handshake state: pending until ClientConfirm received.
	serverPriv [32]byte
	serverPub  []byte
	confirmMAC []byte // expected MAC from client
	activated  bool
	lastSeen   time.Time
	// Inbound WG packets queued for piggybacking in data responses.
	wgInbound chan []byte
	// Fragment reassembly, keyed by the client's packet sequence. A WireGuard
	// datagram does not fit in one DNS name, so the client splits the ciphertext
	// and the server rebuilds it before decrypting.
	frags map[uint32]*dnsFragAssembly
}

// dnsFragAssembly collects the fragments of one packet.
type dnsFragAssembly struct {
	chunks   [][]byte
	received int
	total    int
	started  time.Time
}

// maxDNSAssemblies caps how many partially received packets a session may hold.
// Fragments are unauthenticated until the packet is whole and decrypts, so a
// sender emitting first-fragments alone must not be able to grow this without
// bound.
const maxDNSAssemblies = 64

// dnsAssemblyTTL discards partial packets whose remaining fragments never
// arrived, which is ordinary loss on this transport.
const dnsAssemblyTTL = 10 * time.Second

// Worker pool sizing for the UDP read loop.
const (
	dnsWorkers    = 16
	dnsQueueDepth = 256
)

// maxPendingDNSSessions caps sessions that have completed a ClientHello but not
// a ClientConfirm.
//
// A hello is unauthenticated -- possession is only proven by the confirm that
// follows -- so without a ceiling anyone can allocate sessions at line rate.
// Each carries two keys, a 32-slot channel and map overhead, and lived for the
// full 90s eviction window. Pending sessions are also evicted far sooner than
// established ones, so a flood cannot crowd out live tunnels.
const (
	maxPendingDNSSessions = 256
	pendingDNSSessionTTL  = 10 * time.Second
)

var srvB32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsTunnelSuffix is the authoritative zone, uppercased once at init rather
// than rebuilt per query.
const dnsTunnelSuffix = ".TUNNEL.FREEWIRE.COM"

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

	uc := ln.(*net.UDPConn)

	// Bounded worker pool, same rationale as the ICMP listener: a goroutine per
	// query is unbounded under load.
	type job struct {
		pkt  []byte
		addr *net.UDPAddr
	}
	jobs := make(chan job, dnsQueueDepth)
	defer close(jobs)
	for i := 0; i < dnsWorkers; i++ {
		go func() {
			for j := range jobs {
				s.handleQuery(j.pkt, j.addr, uc)
			}
		}()
	}

	buf := make([]byte, 4096)
	for {
		n, srcAddr, err := uc.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("dns server: read", zap.String("cause", netErrCause(err)))
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case jobs <- job{pkt: pkt, addr: srcAddr}:
		default:
			// Queue full: drop. A dropped query looks like packet loss to the
			// client, which the tunnel already handles.
		}
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
				active := sess.activated
				sess.mu.Unlock()

				ttl := 90 * time.Second
				if !active {
					ttl = pendingDNSSessionTTL
				}
				if now.Sub(ls) > ttl {
					s.sessions.Delete(k)
					if !active {
						s.pending.Add(-1)
					}
					if sess.localConn != nil {
						sess.localConn.Close()
					}
					s.log.Info("dns server: session evicted", zap.Bool("established", active))
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
	// The whole request travels with the handlers: responses must echo the
	// question section, not just the ID.
	req := buf

	// Parse the question QNAME.
	name, err := extractQNAME(buf, 12)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	name = strings.ToUpper(strings.TrimSuffix(name, "."))
	if !strings.HasSuffix(name, dnsTunnelSuffix) {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	// Strip the tunnel domain suffix.
	label := strings.TrimSuffix(name, dnsTunnelSuffix)

	parts := strings.Split(label, ".")
	if len(parts) < 2 {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	switch strings.ToUpper(parts[0]) {
	case "H":
		s.handleHandshake(conn, srcAddr, req, parts[1:])
	case "T":
		s.handleData(conn, srcAddr, req, parts[1:])
	case "K":
		s.handleKeepalive(conn, srcAddr, req, parts[1:])
	default:
		s.sendNXDomain(conn, srcAddr, req)
	}
}

// handleHandshake dispatches h.1.* (ClientHello) and h.3.* (ClientConfirm).
func (s *DNSServer) handleHandshake(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte, parts []string) {
	if len(parts) < 1 {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	switch parts[0] {
	case "1":
		// ClientHello: parts[1] = b32(clientPub)
		if len(parts) < 2 {
			s.sendNXDomain(conn, srcAddr, req)
			return
		}
		s.handleClientHello(conn, srcAddr, req, parts[1])
	case "3":
		// ClientConfirm: parts[1] = b32(mac), parts[2] = b32(token)
		if len(parts) < 3 {
			s.sendNXDomain(conn, srcAddr, req)
			return
		}
		s.handleClientConfirm(conn, srcAddr, req, parts[1], parts[2])
	default:
		s.sendNXDomain(conn, srcAddr, req)
	}
}

// handleClientHello processes a ClientHello query and sends ServerHello TXT response.
// TXT value: <b32(serverPub)>.<b32(token)>
func (s *DNSServer) handleClientHello(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte, clientPubB32 string) {
	clientPub, err := srvB32enc.DecodeString(clientPubB32)
	if err != nil {
		s.log.Error("dns: decode client pub", zap.String("cause", netErrCause(err)))
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Generate server ephemeral keypair.
	var serverPriv [32]byte
	if _, err := rand.Read(serverPriv[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	serverPriv[0] &= 248
	serverPriv[31] = (serverPriv[31] & 127) | 64

	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// DH shared secret.
	shared, err := curve25519.X25519(serverPriv[:], clientPub)
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Refuse to allocate past the pending ceiling.
	if s.pending.Load() >= maxPendingDNSSessions {
		s.log.Warn("dns: pending session limit reached; rejecting hello")
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Generate session token (10 bytes).
	var token [10]byte
	if _, err := rand.Read(token[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Derive the confirm-MAC key plus one key per direction off a single HKDF
	// stream. Directional separation keeps every (key, nonce) pair unique even
	// though both peers number their packets from zero.
	var sessionKey, keyC2S, keyS2C [32]byte
	hk := hkdf.New(sha256.New, shared, token[:], []byte("freewire-dns-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	if _, err := io.ReadFull(hk, keyC2S[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	if _, err := io.ReadFull(hk, keyS2C[:]); err != nil {
		s.sendNXDomain(conn, srcAddr, req)
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
		frags:      make(map[uint32]*dnsFragAssembly),
	}
	key := srvB32enc.EncodeToString(token[:])
	s.sessions.Store(key, sess)
	s.pending.Add(1)

	// Build TXT response: <b32(serverPub)>.<b32(token)>
	txt := srvB32enc.EncodeToString(serverPub) + "." + srvB32enc.EncodeToString(token[:])
	resp := buildDNSTXTResponse(req, txt)
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleClientConfirm activates the session after verifying the client's MAC.
func (s *DNSServer) handleClientConfirm(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte, macB32, tokenB32 string) {
	v, ok := s.sessions.Load(strings.ToUpper(tokenB32))
	if !ok {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	sess := v.(*dnsSession)
	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Activation is idempotent. The client retransmits CONFIRM whenever the OK
	// response is lost, which is routine on the lossy networks this transport
	// exists for. Re-activating would dial a second bridge socket, overwrite
	// localConn, and strand the first socket and its reader goroutine with
	// nothing left holding a reference to close them. The ACK is re-sent
	// because dropping the retransmit silently leaves the client waiting out
	// its handshake timeout.
	if sess.activated {
		sess.lastSeen = time.Now()
		conn.WriteToUDP(buildDNSTXTResponse(req, "OK"), srcAddr) //nolint:errcheck
		return
	}

	clientMAC, err := srvB32enc.DecodeString(macB32)
	if err != nil || !hmacEqual(clientMAC, sess.confirmMAC) {
		s.log.Error("dns: client confirm MAC mismatch")
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Build both AEADs once; the keys are fixed for the session lifetime.
	aeadRx, err := chacha20poly1305.New(sess.keyC2S[:])
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	aeadTx, err := chacha20poly1305.New(sess.keyS2C[:])
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Activate session: open per-session WG bridge socket.
	wgAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("127.0.0.1:%d", s.wgPort))
	if err != nil {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	uc, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		s.log.Error("dns: dial wg udp", zap.String("cause", netErrCause(err)))
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	sess.aeadRx = aeadRx
	sess.aeadTx = aeadTx
	sess.localConn = uc
	sess.wgAddr = wgAddr
	sess.activated = true
	s.pending.Add(-1) // promoted from pending to established
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
	resp := buildDNSTXTResponse(req, "OK")
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleData processes a data query: decrypt, forward to WG, piggyback response.
func (s *DNSServer) handleData(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte, parts []string) {
	// parts[0] = b32(seq), parts[1] = b32(frag), parts[2] = b32(token),
	// parts[3..] = b32(ciphertext) chunks
	if len(parts) < 4 {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	tokenB32 := parts[2]
	v, ok := s.sessions.Load(strings.ToUpper(tokenB32))
	if !ok {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	sess := v.(*dnsSession)

	// Take everything needed from the session under the lock, then release it
	// before any network I/O. A blocked UDP write while holding sess.mu would
	// stall every other query on this session.
	sess.mu.Lock()
	if !sess.activated {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	sess.lastSeen = time.Now()
	rxAEAD := sess.aeadRx
	txAEAD := sess.aeadTx
	localConn := sess.localConn
	txSeq := sess.txSeq
	sess.txSeq++

	seqBytes, decErr := srvB32enc.DecodeString(parts[0])
	if decErr != nil || len(seqBytes) != 4 {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	seq := binary.BigEndian.Uint32(seqBytes)

	fragBytes, fragErr := srvB32enc.DecodeString(parts[1])
	if fragErr != nil || len(fragBytes) != 2 {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	fragIndex, fragTotal := int(fragBytes[0]), int(fragBytes[1])
	if fragTotal == 0 || fragIndex >= fragTotal {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Join this fragment's label chunks.
	cipherB32 := strings.Join(parts[3:], "")
	chunk, err := srvB32enc.DecodeString(cipherB32)
	if err != nil {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Collect the fragment. Nothing here is authenticated yet -- the tag covers
	// the whole packet -- so the assembly is bounded and expires.
	asm := sess.frags[seq]
	if asm == nil {
		if len(sess.frags) >= maxDNSAssemblies {
			// Drop the oldest rather than refuse the newest, so a stalled
			// packet cannot wedge the session.
			var oldestSeq uint32
			var oldest time.Time
			for k, a := range sess.frags {
				if oldest.IsZero() || a.started.Before(oldest) {
					oldest, oldestSeq = a.started, k
				}
			}
			delete(sess.frags, oldestSeq)
		}
		asm = &dnsFragAssembly{
			chunks:  make([][]byte, fragTotal),
			total:   fragTotal,
			started: time.Now(),
		}
		sess.frags[seq] = asm
	}
	if asm.total != fragTotal || fragIndex >= len(asm.chunks) {
		sess.mu.Unlock()
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	if asm.chunks[fragIndex] == nil {
		asm.chunks[fragIndex] = chunk
		asm.received++
	}

	// Expire assemblies whose remaining fragments never arrived.
	for k, a := range sess.frags {
		if time.Since(a.started) > dnsAssemblyTTL {
			delete(sess.frags, k)
		}
	}

	if asm.received < asm.total {
		// Acknowledge without a payload; the packet is not whole yet.
		sess.mu.Unlock()
		conn.WriteToUDP(buildDNSTXTResponse(req, ""), srcAddr) //nolint:errcheck
		return
	}
	delete(sess.frags, seq)

	var ciphertext []byte
	for _, c := range asm.chunks {
		ciphertext = append(ciphertext, c...)
	}

	// Check only, and only once the packet is whole. The window must not move
	// for anything unauthenticated: on this transport the sequence rides in the
	// query name in cleartext, so any resolver or portal operator on the path
	// can read it and forge a packet with a maximal sequence. Committing here
	// would let them push the window past every real packet and kill a live
	// tunnel without holding any key.
	fresh := sess.rx.check(seq)
	sess.mu.Unlock()

	if !fresh {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	var nonce [12]byte
	srvDNSNonceInto(seq, &nonce)
	plain, err := rxAEAD.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		s.log.Error("dns: decrypt data", zap.String("cause", netErrCause(err)))
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Authenticated: the window may move now. Re-checked under the lock so two
	// copies that both passed the earlier check cannot both be forwarded.
	sess.mu.Lock()
	stillFresh := sess.rx.check(seq)
	if stillFresh {
		sess.rx.commit(seq)
	}
	sess.mu.Unlock()
	if !stillFresh {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}

	// Forward plaintext to WireGuard.
	localConn.Write(plain) //nolint:errcheck

	// Piggyback any pending WG inbound response.
	var wgPkt []byte
	select {
	case wgPkt = <-sess.wgInbound:
	default:
	}

	if len(wgPkt) == 0 {
		// Nothing to piggyback — send empty ACK.
		resp := buildDNSTXTResponse(req, "")
		conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
		return
	}

	var txNonce [12]byte
	srvDNSNonceInto(txSeq, &txNonce)
	encrypted := txAEAD.Seal(nil, txNonce[:], wgPkt, nil)

	// Encode response: <b32(txSeq)>.<b32(encrypted)>
	txSeqB32 := srvB32enc.EncodeToString(uint32BESrv(txSeq))
	encB32 := srvB32enc.EncodeToString(encrypted)
	txt := txSeqB32 + "." + encB32
	resp := buildDNSTXTResponse(req, txt)
	conn.WriteToUDP(resp, srcAddr) //nolint:errcheck
}

// handleKeepalive updates the session lastSeen timestamp and responds with "K".
func (s *DNSServer) handleKeepalive(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte, parts []string) {
	if len(parts) < 1 {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	v, ok := s.sessions.Load(strings.ToUpper(parts[0]))
	if !ok {
		s.sendNXDomain(conn, srcAddr, req)
		return
	}
	sess := v.(*dnsSession)

	// A keepalive doubles as a poll.
	//
	// DNS is request/response: the server has no way to send unsolicited data,
	// so anything WireGuard produces waits for a query to ride back on. Data
	// queries alone are not enough -- after the client sends a handshake it has
	// nothing more to send and simply waits, while the reply sits in the queue.
	// Answering polls with pending data is what lets the tunnel carry a
	// handshake at all.
	sess.mu.Lock()
	sess.lastSeen = time.Now()
	if !sess.activated {
		sess.mu.Unlock()
		conn.WriteToUDP(buildDNSTXTResponse(req, "K"), srcAddr) //nolint:errcheck
		return
	}
	txAEAD := sess.aeadTx
	txSeq := sess.txSeq
	sess.txSeq++
	sess.mu.Unlock()

	var wgPkt []byte
	select {
	case wgPkt = <-sess.wgInbound:
	default:
	}
	if len(wgPkt) == 0 {
		conn.WriteToUDP(buildDNSTXTResponse(req, "K"), srcAddr) //nolint:errcheck
		return
	}

	var txNonce [12]byte
	srvDNSNonceInto(txSeq, &txNonce)
	encrypted := txAEAD.Seal(nil, txNonce[:], wgPkt, nil)
	txt := srvB32enc.EncodeToString(uint32BESrv(txSeq)) + "." + srvB32enc.EncodeToString(encrypted)
	conn.WriteToUDP(buildDNSTXTResponse(req, txt), srcAddr) //nolint:errcheck
}

// sendNXDomain sends a DNS NXDOMAIN response.
func (s *DNSServer) sendNXDomain(conn *net.UDPConn, srcAddr *net.UDPAddr, req []byte) {
	resp := buildDNSNXDomain(req)
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
func buildDNSTXTResponse(req []byte, txt string) []byte {
	id, question := dnsIDAndQuestion(req)

	var buf []byte
	buf = append(buf, id...)
	buf = append(buf, 0x84, 0x00) // flags: QR=1, AA=1, RCODE=0
	// The question section is echoed back. Emitting QDCOUNT=0 and starting the
	// answer at offset 12 makes every RFC 1035 parser -- including this
	// project's own client -- read the answer RR as the question and then take
	// RDLENGTH from inside RDATA.
	if len(question) > 0 {
		buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	} else {
		buf = append(buf, 0x00, 0x00)
	}
	buf = append(buf, 0x00, 0x01) // ANCOUNT = 1
	buf = append(buf, 0x00, 0x00) // NSCOUNT = 0
	buf = append(buf, 0x00, 0x00) // ARCOUNT = 0
	buf = append(buf, question...)

	if len(question) > 0 {
		// Compression pointer back to the question name at offset 12.
		buf = append(buf, 0xC0, 0x0C)
	} else {
		buf = append(buf, 0x00) // NAME = root label
	}
	buf = append(buf, 0x00, 0x10)             // TYPE = TXT (16)
	buf = append(buf, 0x00, 0x01)             // CLASS = IN
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
func buildDNSNXDomain(req []byte) []byte {
	id, question := dnsIDAndQuestion(req)

	var buf []byte
	buf = append(buf, id...)
	buf = append(buf, 0x84, 0x03) // flags: QR=1, AA=1, RCODE=NXDOMAIN(3)
	if len(question) > 0 {
		buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	} else {
		buf = append(buf, 0x00, 0x00)
	}
	buf = append(buf, 0x00, 0x00) // ANCOUNT=0
	buf = append(buf, 0x00, 0x00) // NSCOUNT=0
	buf = append(buf, 0x00, 0x00) // ARCOUNT=0
	buf = append(buf, question...)
	return buf
}

// dnsIDAndQuestion splits a request into its 2-byte ID and the raw bytes of its
// question section (QNAME + QTYPE + QCLASS), ready to be echoed verbatim.
//
// Callers may pass a bare 2-byte ID, in which case the question is empty.
func dnsIDAndQuestion(req []byte) (id, question []byte) {
	if len(req) < 2 {
		return make([]byte, 2), nil
	}
	id = req[:2]
	if len(req) < 12 {
		return id, nil
	}

	// Walk the QNAME labels to find where the question ends.
	off := 12
	for off < len(req) {
		l := int(req[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer: 2 bytes, no further labels
			off += 2
			break
		}
		off += l + 1
	}
	off += 4 // QTYPE + QCLASS
	if off > len(req) {
		return id, nil
	}
	return id, req[12:off]
}

// srvDNSNonceInto writes a 12-byte ChaCha20-Poly1305 nonce into out:
// seq(4B big-endian) || 0x00(8B). Filling a caller-owned array keeps the nonce
// off the heap in the packet path.
func srvDNSNonceInto(seq uint32, out *[12]byte) {
	*out = [12]byte{}
	binary.BigEndian.PutUint32(out[:4], seq)
}

// uint32BESrv encodes a uint32 as 4-byte big-endian.
func uint32BESrv(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// dnsSrvConfirmMAC = SHA256(sessionKey || "confirm" || token)[:16].
func dnsSrvConfirmMAC(key [32]byte, token []byte) []byte {
	h := hmac.New(sha256.New, key[:])
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
