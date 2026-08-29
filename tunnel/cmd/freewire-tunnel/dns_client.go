package main

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// DNS tunnel implementation per dns-tunnel-protocol-spec.md.
//
// All payload is Base32-encoded (RFC 4648, no padding, uppercase).
// Session key: X25519 → HKDF-SHA256(ikm=shared, salt=token, info="freewire-dns-tunnel-v1", len=32)
// Encryption:  ChaCha20-Poly1305, nonce = seq(4B big-endian) || 0x00000000(8B)
// Flow control: bounded send queue + worker pool, paced by separate adaptive
//   AIMD limiters per direction that discover the path's sustainable rate (see
//   dns_ratelimit.go). Unlike the old sliding window, the limiter never drops a
//   packet -- it only makes a worker wait -- so it cannot trigger a retransmit
//   storm.
// Domain: *.<tunnel zone>, taken from the server config; see defaultDNSTunnelDomain.

const (
	// defaultDNSTunnelDomain is used only when the server config does not name a
	// zone. The server is the source of truth (it advertises dns_tunnel_domain),
	// so a domain rotation happens server-side and needs no client rebuild. This
	// default exists for tests and for a server old enough not to send the field.
	defaultDNSTunnelDomain = "t.pinghop.net"
	dnsKeepaliveEvery      = 30 * time.Second
	// Poll interval while the tunnel is active.
	//
	// DNS gives the server no way to push, so pending data waits for a query.
	// Without polling, a client that has sent a WireGuard handshake and is now
	// waiting for the reply would not ask again until the keepalive 30s later,
	// long after any handshake budget has expired -- the tunnel would activate
	// and then starve.
	dnsPollFast = 60 * time.Millisecond
	dnsPollIdle = 700 * time.Millisecond
	// How long after real traffic to keep polling at the fast rate.
	dnsPollBusyWindow   = 3 * time.Second
	dnsHandshakeTimeout = 3 * time.Second

	// Send-path concurrency and flow control.
	//
	// The old model kept a per-packet AIMD window and DROPPED packets when it was
	// full. Under a WireGuard burst it filled at 8, dropped most packets, and
	// WireGuard retransmitted the drops -- a congestion collapse (see the routed
	// diagnosis in CLAUDE.md). Dropping is the trigger: a lost packet makes
	// WireGuard resend, which pushes more into an already-full window.
	//
	// Instead: a bounded queue absorbs bursts (a burst is delayed, not dropped,
	// which is what stops the retransmit storm), a pool of senders drains it, and
	// separate per-direction ADAPTIVE limiters (dns_ratelimit.go) pace concurrent
	// queries to the rate the path sustains -- learned at runtime, not fixed -- so
	// continuous pollers cannot starve senders and neither direction blasts a
	// throttled portal into loss.
	//
	// Queue SIZE is a latency budget, not just burst absorption. The queue holds
	// ~depth/carrier-rate seconds of packets before it drops; at the recursor
	// carrier's ~50 pkt/s a depth of 256 is ~5s of buffering (bufferbloat), which
	// balloons the inner RTT past a TCP handshake's patience even though almost
	// nothing is lost. A shallow queue signals congestion early and keeps the
	// buffered RTT low, so TCP establishes and then paces itself -- the AQM
	// principle. Kept a var so it can be tuned per carrier speed.
)

// dnsSendQueue bounds buffered upstream packets. Default 256, the depth proven on
// the fast server-direct path (~71 KB/s). A shallow queue was tested as AQM for
// the slow recursor path and did NOT help: through public recursors the upstream
// is capped near ~50 pkt/s by their forward-rate limit, so the queue overflows at
// any size and the depth is not the lever. Env-tunable for further sweeps.
var dnsSendQueue = envInt("FREEWIRE_DNS_QUEUE", 256)

// Send-path concurrency, socket pool, and worker count. Vars, not consts, so a
// test run can sweep them via env (FREEWIRE_DNS_CONCURRENCY / _POOL / _WORKERS)
// to find the routed bottleneck without a rebuild. Defaults match the measured-
// safe standalone value. Pool and workers track concurrency by default: the pool
// must hold at least as many sockets as there are in-flight queries or every
// query past the pool churns a dial, and workers must be at least concurrency or
// the query slots sit idle.
var (
	// Upstream (send) and downstream (poll) get SEPARATE concurrency budgets, not
	// one shared pool. Sharing let the pollers -- which re-poll continuously -- hog
	// the slots and starve the send workers, so the send queue overflowed and
	// tail-dropped ~75% of upstream (measured: a routed ping saw 75% loss with the
	// send queue pinned at 256/256). Upstream loss breaks TCP handshakes outright,
	// so sends get the larger budget; downstream still gets enough to carry a
	// handshake's return path. Total = send + poll, which the socket pool matches.
	dnsSendConcurrency = envInt("FREEWIRE_DNS_SEND_CONCURRENCY", 24)
	dnsPollConcurrency = envInt("FREEWIRE_DNS_POLL_CONCURRENCY", 8)
	udpPoolPerServer   = envInt("FREEWIRE_DNS_POOL", dnsSendConcurrency+dnsPollConcurrency)
	dnsSendWorkers     = envInt("FREEWIRE_DNS_WORKERS", dnsSendConcurrency)
	dnsPollWorkers     = envInt("FREEWIRE_DNS_POLLERS", dnsPollConcurrency)
)

// envInt reads a positive integer from env, or returns def.
func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

var b32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsClientSession holds the state for an active DNS tunnel session.
type dnsClientSession struct {
	token      []byte   // 10-byte opaque session token
	sessionKey [32]byte // authenticates the ClientConfirm MAC only
	// Directional keys. Both peers number packets from zero, so a single shared
	// key would repeat the (key, nonce) pair across directions.
	keyC2S   [32]byte // client → server: client seals with this
	keyS2C   [32]byte // server → client: client opens with this
	tokenB32 string   // base32(token), cached: it is constant for the session
	// AEADs built once at handshake rather than per packet, matching the server.
	aeadTx cipher.AEAD // client → server
	aeadRx cipher.AEAD // server → client
	txSeq  uint32      // next outbound sequence number (atomic add)
	// dnsServers is the carrier resolver set, fanned across round-robin by rr so
	// no single recursor's per-auth-server forward limit caps throughput. The
	// server keys sessions by token, not source, so queries for one session may
	// arrive via any resolver. rr is an atomic cursor into dnsServers.
	dnsServers []string
	rr         atomic.Uint64
	// tunnelDomain is the authoritative zone every query name is suffixed with.
	// Carried per session because it is server-supplied and can change between
	// connections, and because the per-query payload budget depends on its
	// length -- a longer zone leaves fewer bytes for data (see dnsFragCipherBytes).
	tunnelDomain string
	mu           sync.Mutex
	// rx guards against replay of server->client responses, whose sequence
	// number rides in the response in cleartext. rxMu serializes the
	// check/open/commit so the window only advances for an authenticated packet.
	rx   replayWindow
	rxMu sync.Mutex
	// pollNonce makes each poll query name unique. Concurrent pollers all query
	// the same k.<token> name, so a recursive resolver would dedupe or cache them
	// and answer most from one upstream query -- collapsing the return path to a
	// single poll's worth of data. A per-poll nonce label (which the server
	// ignores) forces every poll to miss the cache and reach the authoritative
	// server.
	pollNonce atomic.Uint64
}

// effectiveDNSTunnelDomain is the zone the client queries: whatever the server
// advertised, or the compiled-in default if it advertised nothing.
func effectiveDNSTunnelDomain(cfg Config) string {
	if cfg.DNSTunnelDomain != "" {
		return cfg.DNSTunnelDomain
	}
	return defaultDNSTunnelDomain
}

// runDNSTunnel establishes the DNS tunnel handshake and returns a local UDP
// PacketConn that bridges wireguard-go UDP ↔ DNS tunnel.
// Returns an error if the handshake fails within dnsHandshakeTimeout.
func runDNSTunnel(cfg Config) (net.PacketConn, error) {
	if cfg.DNSTestCarrierCap > 0 && testCarrierThrottle == nil {
		testCarrierThrottle = newTestThrottle(cfg.DNSTestCarrierCap)
		fmt.Fprintf(os.Stderr, "freewire-tunnel: TEST carrier throttle active: %d q/s\n", cfg.DNSTestCarrierCap)
	}
	// Try each resolver strategy in order; the first whose handshake completes
	// wins. The default order prefers the authoritative server directly (the fast
	// path, ~71 KB/s where the portal allows outbound 53) and falls back to the
	// system resolver (the minimal path where only the portal's resolver is
	// allowed). An explicit config collapses to a single strategy.
	var sess *dnsClientSession
	var lastErr error
	for _, st := range dnsResolverStrategies(cfg) {
		s, err := dnsHandshake(cfg, st.resolvers, st.timeout)
		if err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "freewire-tunnel: dns %s handshake failed: %v\n", st.name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "freewire-tunnel: dns carrier: %s (%v)\n", st.name, st.resolvers)
		sess = s
		break
	}
	if sess == nil {
		return nil, fmt.Errorf("dns tunnel: handshake: %w", lastErr)
	}

	// Local UDP proxy: WireGuard sends packets here, we encode and query DNS.
	lp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("dns tunnel: local proxy: %w", err)
	}

	go sess.run(lp)
	return lp, nil
}

// dnsStrategy is one resolver set to attempt, with a handshake budget.
type dnsStrategy struct {
	name      string
	resolvers []string
	timeout   time.Duration
}

// dnsResolverStrategies orders the carrier resolver attempts.
//
// An explicit resolver set from config (DNSResolvers/DNSResolver, used by tests,
// the dev server, and the harness) is honored as the single strategy. Otherwise
// the default is server-direct first, then the system resolver: server-direct is
// the only path that carries HTTPS at usable speed, so it is worth a short probe
// before falling back to the recursor path, which moves packets but cannot carry
// a TCP handshake (see the DNS characterization in CLAUDE.md). Server-direct gets
// a shorter budget so a portal that blocks outbound 53 falls back quickly.
func dnsResolverStrategies(cfg Config) []dnsStrategy {
	if explicit := carrierResolvers(cfg); len(explicit) > 0 {
		return []dnsStrategy{{name: "configured", resolvers: explicit, timeout: dnsHandshakeTimeout}}
	}
	var out []dnsStrategy
	if cfg.ServerHost != "" {
		port := cfg.DNSTunnelPort
		if port == 0 {
			port = 53
		}
		serverDirect := net.JoinHostPort(cfg.ServerHost, strconv.Itoa(port))
		out = append(out, dnsStrategy{name: "server-direct", resolvers: []string{serverDirect}, timeout: 2 * time.Second})
	}
	if r, err := resolveLocalDNSServer(); err == nil {
		out = append(out, dnsStrategy{name: "system-resolver", resolvers: []string{r}, timeout: dnsHandshakeTimeout})
	}
	return out
}

// carrierResolvers returns the explicit resolver set from config: the list if
// given, else the single resolver if given, else empty (caller falls back to the
// system resolver). Order is preserved; the first is used for the handshake.
func carrierResolvers(cfg Config) []string {
	if len(cfg.DNSResolvers) > 0 {
		out := make([]string, 0, len(cfg.DNSResolvers))
		for _, r := range cfg.DNSResolvers {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	if cfg.DNSResolver != "" {
		return []string{cfg.DNSResolver}
	}
	return nil
}

// resolveLocalDNSServer returns the first DNS server from /etc/resolv.conf,
// falling back to 8.8.8.8 if the file cannot be read.
func resolveLocalDNSServer() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				ip := net.ParseIP(parts[1])
				// Loopback is skipped. Once the tunnel points the system at its
				// own forwarder on 127.0.0.1, a later run reading resolv.conf
				// would find that address and try to reach the authoritative
				// server through it -- and after an unclean exit the forwarder
				// is not there at all. The DNS transport needs a resolver that
				// exists independently of this process.
				if ip != nil && !ip.IsLoopback() {
					return parts[1], nil
				}
			}
		}
	}
	// Fallback: use a public resolver.
	return "8.8.8.8", nil
}

// nextResolver returns the next carrier resolver round-robin, spreading queries
// so no single recursor's forward rate-limit caps throughput.
func (s *dnsClientSession) nextResolver() string {
	if len(s.dnsServers) == 1 {
		return s.dnsServers[0]
	}
	i := s.rr.Add(1) - 1
	return s.dnsServers[i%uint64(len(s.dnsServers))]
}

// dnsHandshake performs the 3-step handshake and returns an initialized session.
//
// Step 1: ClientHello — query h.1.<b32(clientPub)>.<zone> TXT
// Step 2: ServerHello — parse TXT: <b32(serverPub)>.<b32(token)>
// Step 3: ClientConfirm — query h.3.<b32(mac)>.<b32(token)>.<zone> TXT
func dnsHandshake(cfg Config, dnsServers []string, timeout time.Duration) (*dnsClientSession, error) {
	deadline := time.Now().Add(timeout)
	domain := effectiveDNSTunnelDomain(cfg)
	// The handshake runs over the first resolver; data and polls fan across all.
	dnsServer := dnsServers[0]

	// Generate ephemeral Curve25519 keypair for DH.
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

	// Step 1: ClientHello
	clientPubB32 := b32enc.EncodeToString(clientPub)
	helloName := "h.1." + clientPubB32 + "." + domain + "."

	resp, err := dnsQuery(dnsServer, helloName, time.Until(deadline), dnsSendLimiter)
	if err != nil {
		return nil, fmt.Errorf("client hello: %w", err)
	}
	if isDNSNXDomain(resp) {
		return nil, fmt.Errorf("client hello: NXDOMAIN — DNS tunnel not available on this network")
	}

	txtVal, err := parseTXTResponse(resp)
	if err != nil {
		return nil, fmt.Errorf("client hello: parse response: %w", err)
	}

	// TXT value format: <b32(serverPub)>.<b32(token)>
	parts := strings.SplitN(txtVal, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("client hello: unexpected TXT format: %q", txtVal)
	}
	serverPub, err := b32enc.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("client hello: decode server pub: %w", err)
	}
	token, err := b32enc.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("client hello: decode token: %w", err)
	}

	// DH shared secret.
	shared, err := curve25519.X25519(clientPriv[:], serverPub)
	if err != nil {
		return nil, fmt.Errorf("dh exchange: %w", err)
	}

	// Derive session key via HKDF-SHA256.
	var sessionKey, keyC2S, keyS2C [32]byte
	hk := hkdf.New(sha256.New, shared, token, []byte("freewire-dns-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	if _, err := io.ReadFull(hk, keyC2S[:]); err != nil {
		return nil, fmt.Errorf("derive c2s key: %w", err)
	}
	if _, err := io.ReadFull(hk, keyS2C[:]); err != nil {
		return nil, fmt.Errorf("derive s2c key: %w", err)
	}

	// Compute MAC for ClientConfirm: SHA256(sessionKey || "confirm" || token)[:16].
	mac := dnsConfirmMAC(sessionKey, token)
	macB32 := b32enc.EncodeToString(mac)
	tokenB32 := b32enc.EncodeToString(token)

	// Step 3: ClientConfirm
	confirmName := "h.3." + macB32 + "." + tokenB32 + "." + domain + "."
	resp2, err := dnsQuery(dnsServer, confirmName, time.Until(deadline), dnsSendLimiter)
	if err != nil {
		return nil, fmt.Errorf("client confirm: %w", err)
	}
	confirmTxt, err := parseTXTResponse(resp2)
	if err != nil || !strings.EqualFold(confirmTxt, "ok") {
		return nil, fmt.Errorf("client confirm: server rejected (got %q)", confirmTxt)
	}

	aeadTx, err := chacha20poly1305.New(keyC2S[:])
	if err != nil {
		return nil, fmt.Errorf("client confirm: aead tx: %w", err)
	}
	aeadRx, err := chacha20poly1305.New(keyS2C[:])
	if err != nil {
		return nil, fmt.Errorf("client confirm: aead rx: %w", err)
	}

	return &dnsClientSession{
		token:        token,
		tokenB32:     tokenB32,
		aeadTx:       aeadTx,
		aeadRx:       aeadRx,
		sessionKey:   sessionKey,
		keyC2S:       keyC2S,
		keyS2C:       keyS2C,
		dnsServers:   dnsServers,
		tunnelDomain: domain,
	}, nil
}

// dnsConfirmMAC computes SHA256(sessionKey || "confirm" || token)[:16].
func dnsConfirmMAC(key [32]byte, token []byte) []byte {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte("confirm"))
	h.Write(token)
	return h.Sum(nil)[:16]
}

// run bridges localProxy UDP ↔ DNS tunnel. Runs until localProxy is closed.
func (s *dnsClientSession) run(lp net.PacketConn) {
	ka := time.NewTicker(dnsKeepaliveEvery)
	defer ka.Stop()

	// done is closed when the local proxy goes away, which is the signal that
	// the tunnel is finished. Every goroutine below selects on it so none
	// outlives the session.
	done := make(chan struct{})
	inboundCh := make(chan []byte, 64)
	peerCh := make(chan net.Addr, 1)
	var peerOnce sync.Once

	// wgPeer is written by the main loop and read by the inbound writer, so it
	// needs a lock rather than a bare variable.
	var peerMu sync.Mutex
	var wgPeer net.Addr

	// WireGuard → DNS.
	//
	// A bounded queue absorbs WireGuard's bursts, and a fixed pool of senders
	// drains it. Bursts are delayed, not dropped -- which is the whole point: the
	// previous code dropped whenever its window was full, and every drop made
	// WireGuard retransmit, piling more onto a full window until the transport
	// carried nothing (measured: 2450 of 3139 packets dropped). Concurrency is
	// capped globally in dnsQuery (dnsMaxConcurrentQueries), so the number of
	// senders here only needs to be enough to keep that many queries busy.
	sendQ := make(chan []byte, dnsSendQueue)
	// Diagnostic counters: sent = packets a worker handed to the carrier, dropped
	// = tail-drops when the queue was full. A healthy session shows sent climbing
	// with dropped at or near zero; sustained drops mean the carrier can't drain
	// as fast as WireGuard offers, and the queue/rate needs tuning. Logged
	// periodically below so a routed test captures the shape without a code change.
	var sentCount, dropCount, dsBytes, pollBytes atomic.Uint64
	for i := 0; i < dnsSendWorkers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				case p := <-sendQ:
					pkts, err := s.sendPacket(p)
					if err == nil {
						sentCount.Add(1)
					}
					for _, data := range pkts {
						select {
						case inboundCh <- data:
						case <-done:
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		var lastSent, lastDrop, lastQOK, lastQErr, lastDS, lastPoll uint64
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s, d := sentCount.Load(), dropCount.Load()
				qok, qerr := dnsQueryOK.Load(), dnsQueryErr.Load()
				dsb, pb := dsBytes.Load(), pollBytes.Load()
				ds, dd := s-lastSent, d-lastDrop
				dqok, dqerr := qok-lastQOK, qerr-lastQErr
				dsRate, pollRate := (dsb-lastDS)/5, (pb-lastPoll)/5
				lastSent, lastDrop, lastQOK, lastQErr, lastDS, lastPoll = s, d, qok, qerr, dsb, pb
				fmt.Fprintf(os.Stderr,
					"freewire-tunnel: dns send %d/s, tail-drop %d/s (queue %d/%d); queries ok %d/s err %d/s; downstream %d B/s (poll %d B/s); limit send=%.1f poll=%.1f\n",
					ds/5, dd/5, len(sendQ), dnsSendQueue, dqok/5, dqerr/5, dsRate, pollRate,
					dnsSendLimiter.currentLimit(), dnsPollLimiter.currentLimit())
			}
		}
	}()

	go func() {
		defer close(done)
		// Sized past the largest datagram the tunnel can produce: ReadFrom
		// discards whatever does not fit, so a buffer at exactly the payload
		// budget silently truncated full-size packets.
		buf := make([]byte, 2048)
		for {
			n, peer, err := lp.ReadFrom(buf)
			if err != nil {
				return
			}
			peerOnce.Do(func() { peerCh <- peer })
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			select {
			case sendQ <- pkt:
			default:
				// Queue full: a sustained overload past what the carrier can
				// drain. Tail-drop one packet, which the inner TCP reads as
				// congestion and backs off on -- unlike the old per-packet drop,
				// this only happens after 256 packets are already buffered.
				dropCount.Add(1)
			}
		}
	}()

	// Inbound → WireGuard.
	go func() {
		for {
			select {
			case <-done:
				return
			case data := <-inboundCh:
				peerMu.Lock()
				peer := wgPeer
				peerMu.Unlock()
				if peer != nil {
					lp.WriteTo(data, peer) //nolint:errcheck
					dsBytes.Add(uint64(len(data)))
				}
			}
		}
	}()

	// Poll pool: several return-path queries in flight at once, not one at a
	// time. A worker that got data re-polls immediately (draining a burst as fast
	// as the carrier allows); a worker that got nothing backs off -- fast while a
	// transfer was recently active so the pool re-saturates the instant data
	// resumes, idle otherwise so a quiet tunnel is not a query flood. lastActivity
	// is shared across the pool, refreshed by any downstream receipt (poll or the
	// data-send piggyback path).
	var lastActivityNano atomic.Int64
	lastActivityNano.Store(time.Now().UnixNano())
	for i := 0; i < dnsPollWorkers; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				pkts, err := s.poll()
				if err != nil || len(pkts) == 0 {
					interval := dnsPollIdle
					if time.Since(time.Unix(0, lastActivityNano.Load())) < dnsPollBusyWindow {
						interval = dnsPollFast
					}
					select {
					case <-time.After(interval):
					case <-done:
						return
					}
					continue
				}
				lastActivityNano.Store(time.Now().UnixNano())
				for _, data := range pkts {
					pollBytes.Add(uint64(len(data)))
					select {
					case inboundCh <- data:
					case <-done:
						return
					}
				}
			}
		}()
	}

	for {
		select {
		case <-done:
			return
		case peer := <-peerCh:
			peerMu.Lock()
			wgPeer = peer
			peerMu.Unlock()
		case <-ka.C:
			go s.sendKeepalive() //nolint:errcheck
		}
	}
}

// poll asks the server whether it has anything queued, and decrypts it if so.
func (s *dnsClientSession) poll() ([][]byte, error) {
	// Unique nonce label after the token so a recursive resolver treats every
	// poll as a distinct name (no dedup/cache); the server ignores extra labels.
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], s.pollNonce.Add(1))
	nonce := b32enc.EncodeToString(nb[:])
	name := "k." + s.tokenB32 + "." + nonce + "." + s.tunnelDomain + "."
	resp, err := dnsQuery(s.nextResolver(), name, 2*time.Second, dnsPollLimiter)
	if err != nil {
		return nil, err
	}
	txt, err := parseTXTResponse(resp)
	if err != nil || txt == "" || txt == "K" {
		return nil, nil // nothing queued
	}
	return s.decodePiggybackTXT(txt)
}

// sendPacket encrypts pkt, transmits via DNS TXT query, and returns any
// decrypted inbound data from the response.
// DNS name budget. RFC 1035 caps a domain name at 255 bytes on the wire, where
// every label costs its length plus one, and the terminating root label costs
// one more. Nothing enforced this before: a full WireGuard datagram encoded to
// roughly 2.4 KB of name across 37 labels, which every resolver rejects. That
// is why the DNS transport never carried a packet.
const (
	dnsMaxName  = 253 // usable name length, excluding the root label
	dnsMaxLabel = 63

	// Plaintext carried per query. Derived from the budget below and kept
	// deliberately conservative so a longer tunnel domain cannot silently push
	// a name over the limit.
	dnsFragPayload = 96
)

// dnsNameWireLen reports how many bytes name occupies in a DNS message.
func dnsNameWireLen(name string) int {
	n := 1 // root label
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		n += 1 + len(label)
	}
	return n
}

// sendPacket splits pkt across as many queries as the name budget requires and
// returns any payload the server piggybacked on the final response.
//
// The ciphertext is produced once for the whole packet and then fragmented, so
// the server reassembles before it decrypts and the sequence number covers the
// whole packet rather than each piece.
func (s *dnsClientSession) sendPacket(pkt []byte) ([][]byte, error) {
	seq := atomic.AddUint32(&s.txSeq, 1) - 1
	// Same construction as the ICMP transport, same hazard: the nonce is
	// derived from the sequence number, so a wrap repeats a (key, nonce) pair
	// and ChaCha20-Poly1305 loses both confidentiality and authentication.
	// End the session instead. See maxSessionSeq.
	if seq >= maxSessionSeq {
		return nil, fmt.Errorf("session sequence space exhausted; reconnect to rekey")
	}

	var nonce [12]byte
	dnsNonceInto(seq, &nonce)
	ciphertext := s.aeadTx.Seal(nil, nonce[:], pkt, nil)

	// Fragment the ciphertext so each query's encoded chunk fits the budget.
	chunks := splitCiphertext(ciphertext, dnsFragCipherBytes(s.tunnelDomain))
	if len(chunks) > 255 {
		return nil, fmt.Errorf("send packet: %d fragments exceeds the 255 the header allows", len(chunks))
	}

	seqB32 := b32enc.EncodeToString(uint32BE(seq))

	// Build every fragment's query name up front, so a name-too-long error fails
	// before any query is sent.
	names := make([]string, len(chunks))
	for i, chunk := range chunks {
		// frag carries index and total so the server knows when it is complete.
		fragB32 := b32enc.EncodeToString([]byte{byte(i), byte(len(chunks))})
		dataB32 := b32enc.EncodeToString(chunk)
		labels := chunkLabels(dataB32, dnsMaxLabel)

		name := "t." + seqB32 + "." + fragB32 + "." + s.tokenB32 + "." +
			strings.Join(labels, ".") + "." + s.tunnelDomain + "."

		if l := dnsNameWireLen(name); l > dnsMaxName {
			return nil, fmt.Errorf("send packet: fragment %d/%d builds a %d-byte name, over the %d limit",
				i+1, len(chunks), l, dnsMaxName)
		}
		names[i] = name
	}

	// Send a packet's fragments concurrently rather than one round trip at a time.
	// Sequential sending made a 12-fragment packet take ~12 round trips (~1.66s
	// measured). The server reassembles by fragment index and tolerates
	// out-of-order arrival. No per-packet bound is needed here: every dnsQuery
	// acquires a slot on the send-side adaptiveLimiter (dnsSendLimiter), so total
	// in-flight queries across all packets and fragments stay capped there.
	type fragResult struct {
		resp []byte
		err  error
	}
	results := make(chan fragResult, len(names))
	for _, name := range names {
		go func(name string) {
			resp, err := dnsQuery(s.nextResolver(), name, 3*time.Second, dnsSendLimiter)
			results <- fragResult{resp, err}
		}(name)
	}

	// A failed fragment means the packet never completed on the server (a lost
	// fragment loses the whole packet), so report it -- the window backs off and
	// the inner TCP retransmits, matching the old sequential behavior. The
	// piggybacked downstream data rides on whichever fragment completed the packet
	// server-side, which under concurrent arrival is not necessarily the last
	// index, so scan every response; only the completing one carries data.
	var firstErr error
	var piggyback [][]byte
	for range names {
		r := <-results
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}
		if pkts, err := s.decodePiggyback(r.resp); err == nil && len(pkts) > 0 {
			piggyback = append(piggyback, pkts...)
		}
	}
	if firstErr != nil {
		return nil, fmt.Errorf("send packet seq %d (%d frags): %w", seq, len(names), firstErr)
	}
	return piggyback, nil
}

// dnsFragCipherBytes is how many ciphertext bytes fit in one query, worked out
// from the actual encoded overhead rather than assumed.
func dnsFragCipherBytes(domain string) int {
	// Fixed labels: "t", seq, frag, token, plus the tunnel domain and root.
	overhead := dnsNameWireLen("t." +
		b32enc.EncodeToString(make([]byte, 4)) + "." +
		b32enc.EncodeToString(make([]byte, 2)) + "." +
		b32enc.EncodeToString(make([]byte, 10)) + "." +
		domain + ".")

	budget := dnsMaxName - overhead
	if budget <= 0 {
		return 1
	}
	// Each 63-char label costs 64 bytes on the wire.
	fullLabels := budget / (dnsMaxLabel + 1)
	chars := fullLabels * dnsMaxLabel
	if rem := budget % (dnsMaxLabel + 1); rem > 1 {
		chars += rem - 1
	}
	// base32 expands 5 bytes to 8 characters.
	n := chars / 8 * 5
	if n < 1 {
		return 1
	}
	return n
}

// splitCiphertext divides b into pieces of at most size bytes.
func splitCiphertext(b []byte, size int) [][]byte {
	if size < 1 {
		size = 1
	}
	var out [][]byte
	for len(b) > size {
		out = append(out, b[:size])
		b = b[size:]
	}
	// A zero-length packet still needs one fragment so the server sees a total.
	out = append(out, b)
	return out
}

// splitDownstreamFrames splits a decrypted downstream plaintext into the WG
// packets it carries. The server packs multiple packets into one response to use
// the DNS response size (up to the client's advertised EDNS0 budget) instead of
// wasting all but one packet's worth of it: framing is [2-byte BE length][packet]
// repeated. A single packet is just the one-frame case, so the wire format is
// uniform. A malformed length (past the buffer) ends the scan rather than
// erroring: a truncated response yields the whole packets it did carry.
func splitDownstreamFrames(plain []byte) [][]byte {
	var pkts [][]byte
	for len(plain) >= 2 {
		n := int(binary.BigEndian.Uint16(plain[:2]))
		if n == 0 || 2+n > len(plain) {
			break
		}
		pkt := make([]byte, n)
		copy(pkt, plain[2:2+n])
		pkts = append(pkts, pkt)
		plain = plain[2+n:]
	}
	return pkts
}

// decodePiggyback decrypts a payload the server attached to a data response.
func (s *dnsClientSession) decodePiggyback(resp []byte) ([][]byte, error) {
	txt, err := parseTXTResponse(resp)
	if err != nil || txt == "" {
		return nil, nil
	}
	return s.decodePiggybackTXT(txt)
}

// decodePiggybackTXT decrypts a TXT payload of the form <b32(seq)>.<b32(data)>
// and returns the WG packets it framed.
func (s *dnsClientSession) decodePiggybackTXT(txt string) ([][]byte, error) {
	// Response TXT format: <b32(rxSeq)>.<b32(ciphertext)>
	rparts := strings.SplitN(txt, ".", 2)
	if len(rparts) != 2 {
		return nil, nil
	}
	rxSeqBytes, err := b32enc.DecodeString(rparts[0])
	if err != nil || len(rxSeqBytes) != 4 {
		return nil, nil
	}
	rxSeq := binary.BigEndian.Uint32(rxSeqBytes)

	rxCipher, err := b32enc.DecodeString(strings.ReplaceAll(rparts[1], ".", ""))
	if err != nil {
		return nil, nil
	}

	var rxNonce [12]byte
	dnsNonceInto(rxSeq, &rxNonce)

	// check -> open -> re-check+commit, with the AEAD open OUTSIDE the lock. The
	// pollers run this concurrently; holding rxMu across the decrypt serialized
	// every downstream packet through one mutex and its crypto, which throttled
	// the return path just as concurrent polling was meant to widen it. The
	// window still only advances for a packet that authenticated: the fast
	// check/commit stay locked, and the re-check under the lock drops a duplicate
	// that another goroutine committed while this one was decrypting. rxSeq is
	// attacker-visible, so a forged seq must not move the window -- the commit is
	// gated on a successful open, exactly as before.
	s.rxMu.Lock()
	fresh := s.rx.check(rxSeq)
	s.rxMu.Unlock()
	if !fresh {
		// Already accepted, or too old to prove fresh: a replayed response. Drop.
		return nil, nil
	}
	plain, err := s.aeadRx.Open(nil, rxNonce[:], rxCipher, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	s.rxMu.Lock()
	stillFresh := s.rx.check(rxSeq)
	if stillFresh {
		s.rx.commit(rxSeq)
	}
	s.rxMu.Unlock()
	if !stillFresh {
		return nil, nil
	}
	return splitDownstreamFrames(plain), nil
}

// sendKeepalive sends a DNS keepalive query k.<b32(token)>.<zone>.
func (s *dnsClientSession) sendKeepalive() error {
	tokenB32 := b32enc.EncodeToString(s.token)
	name := "k." + tokenB32 + "." + s.tunnelDomain + "."
	_, err := dnsQuery(s.nextResolver(), name, 3*time.Second, dnsSendLimiter)
	return err
}

// dnsNonceInto writes a 12-byte ChaCha20-Poly1305 nonce into out:
// seq(4B big-endian) || 0x00(8B). Filling a caller-owned array keeps the nonce
// off the heap in the packet path.
func dnsNonceInto(seq uint32, out *[12]byte) {
	*out = [12]byte{}
	binary.BigEndian.PutUint32(out[:4], seq)
}

// uint32BE encodes a uint32 as 4-byte big-endian slice.
func uint32BE(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// chunkLabels splits s into chunks of at most maxLen characters.
func chunkLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > maxLen {
		labels = append(labels, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		labels = append(labels, s)
	}
	return labels
}

// Separate ADAPTIVE limiters for upstream sends and downstream polls. Each
// discovers the rate its direction sustains on the current path (AIMD: grow while
// clean, back off on a failed query) instead of a fixed cap -- the field showed a
// fixed value is right on one network and wrong on the next. Kept separate so
// continuous pollers cannot starve senders. The configured concurrency values are
// now the MAX each limiter may grow to; their sum stays matched to
// udpPoolPerServer so an in-flight query always finds a pooled socket.
// dnsSendLimiter also covers the handshake and keepalives.
var (
	dnsSendLimiter = newAdaptiveLimiter(min(8, dnsSendConcurrency), 2, dnsSendConcurrency)
	dnsPollLimiter = newAdaptiveLimiter(min(4, dnsPollConcurrency), 2, dnsPollConcurrency)
)

// Query outcome counters, logged periodically by the run loop. They separate a
// slow carrier (queries timing out -- dnsQueryErr climbing) from a stalled send
// path (queries succeeding but the drain still low). Cheap atomics, tallied
// across every caller.
var dnsQueryOK, dnsQueryErr atomic.Uint64

// dnsQuery sends a DNS TXT query for name to server:53 and returns the raw
// response packet. lim is the adaptive limiter for this direction (send or poll):
// it gates in-flight concurrency and learns the path's rate from the outcome --
// a returned error (mostly a timeout) is the loss signal it backs off on.
//
// timeout bounds the network exchange and starts AFTER a limiter slot is
// acquired, not before: otherwise, under contention, a query could burn its whole
// budget waiting for a slot and then "time out" the instant it ran -- which the
// limiter would read as carrier loss and back off on, causing more waiting and a
// collapse to the floor. Waiting for a slot is not loss; only the wire is.
func dnsQuery(server, name string, timeout time.Duration, lim *adaptiveLimiter) (_ []byte, retErr error) {
	lim.acquire()
	defer func() { lim.release(retErr == nil) }()
	// TEST ONLY: simulate a portal that rate-limits DNS to the server. A dropped
	// query returns a timeout-shaped error, exactly what a real throttle produces,
	// so the adaptive limiter paces under it. No-op in production (throttle nil).
	if testCarrierThrottle != nil && !testCarrierThrottle.allow() {
		return nil, fmt.Errorf("dns query: simulated carrier throttle drop")
	}
	deadline := time.Now().Add(timeout)
	defer func() {
		if retErr != nil {
			dnsQueryErr.Add(1)
		} else {
			dnsQueryOK.Add(1)
		}
	}()

	c, err := dnsConnPool.get(server)
	if err != nil {
		return nil, fmt.Errorf("dns query: dial: %w", err)
	}
	// A socket is only returned to the pool after a clean exchange. Anything
	// that errors may have a stale datagram queued on it, which would be read
	// as the answer to somebody else's query.
	reusable := false
	defer func() {
		if reusable {
			dnsConnPool.put(server, c)
		} else {
			c.Close()
		}
	}()
	c.SetDeadline(deadline) //nolint:errcheck

	query := buildDNSQuery(name, 16 /* TXT */)
	if _, err := c.Write(query); err != nil {
		return nil, fmt.Errorf("dns query: write: %w", err)
	}
	wantID := binary.BigEndian.Uint16(query[:2])

	// Read until the transaction ID matches. Sockets are pooled and UDP is
	// unordered, so a late reply to an earlier query on this socket would
	// otherwise be accepted as the answer to this one -- decrypted under the
	// wrong sequence, and silently wrong rather than merely late.
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("dns query: read: %w", err)
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[:2]) == wantID {
			reusable = true
			out := make([]byte, n)
			copy(out, buf[:n])
			return out, nil
		}
		// Wrong ID: a stale reply. Keep reading until the deadline expires.
	}
}

// dnsConnPool reuses connected UDP sockets to the local resolver. Dialing per
// packet cost a socket create and teardown on every tunnel datagram.
var dnsConnPool = &udpConnPool{conns: map[string][]net.Conn{}}

type udpConnPool struct {
	mu    sync.Mutex
	conns map[string][]net.Conn
}

// udpPoolPerServer is defined as a var above (env-tunable for test sweeps).

func (p *udpConnPool) get(server string) (net.Conn, error) {
	p.mu.Lock()
	if list := p.conns[server]; len(list) > 0 {
		c := list[len(list)-1]
		p.conns[server] = list[:len(list)-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	return net.DialTimeout("udp", resolverAddr(server), 2*time.Second)
}

// resolverAddr accepts either a bare host or host:port.
//
// It used to append ":53" unconditionally, so a resolver given as "1.2.3.4:53"
// became "1.2.3.4:53:53" and the transport failed to open -- silently, because
// a candidate that could not open was skipped without a word, which made it
// look as though the preferred transport was being ignored. Accepting a port is
// also what lets the harness point at a resolver on :5353.
func resolverAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

func (p *udpConnPool) put(server string, c net.Conn) {
	c.SetDeadline(time.Time{}) //nolint:errcheck
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns[server]) >= udpPoolPerServer {
		c.Close()
		return
	}
	p.conns[server] = append(p.conns[server], c)
}

// buildDNSQuery constructs a minimal DNS query packet.
// Format: ID(2) + flags(2) + QDCOUNT=1(2) + 0(6) + QNAME + QTYPE(2) + QCLASS=IN(2)
func buildDNSQuery(name string, qtype uint16) []byte {
	var buf []byte

	// Random 2-byte query ID.
	id := make([]byte, 2)
	rand.Read(id) //nolint:errcheck
	buf = append(buf, id...)
	buf = append(buf, 0x01, 0x00) // flags: RD=1
	buf = append(buf, 0x00, 0x01) // QDCOUNT = 1
	buf = append(buf, 0x00, 0x00) // ANCOUNT = 0
	buf = append(buf, 0x00, 0x00) // NSCOUNT = 0
	buf = append(buf, 0x00, 0x01) // ARCOUNT = 1 (the EDNS0 OPT RR below)

	// QNAME: strip trailing dot, encode each label.
	qname := strings.TrimSuffix(name, ".")
	for _, label := range strings.Split(qname, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label

	// QTYPE + QCLASS = IN(1)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01)

	// EDNS0 OPT pseudo-RR (RFC 6891). Without it responses are capped at the
	// RFC 1035 512-byte limit, which truncates every tunnel data packet.
	var optClass [2]byte
	binary.BigEndian.PutUint16(optClass[:], dnsEDNS0PayloadSize)
	buf = append(buf, 0x00)                   // NAME = root
	buf = append(buf, 0x00, 0x29)             // TYPE = OPT (41)
	buf = append(buf, optClass[:]...)         // CLASS = advertised UDP payload size
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // extended RCODE, version 0, flags
	buf = append(buf, 0x00, 0x00)             // RDLENGTH = 0

	return buf
}

// dnsEDNS0PayloadSize is the UDP response size advertised to the resolver.
// 4096 is the common ceiling; larger values often fail to traverse middleboxes.
const dnsEDNS0PayloadSize uint16 = 4096

// isDNSNXDomain returns true if the DNS response has RCODE=3 (NXDOMAIN).
func isDNSNXDomain(resp []byte) bool {
	if len(resp) < 4 {
		return false
	}
	return resp[3]&0x0F == 3
}

// parseTXTResponse extracts the first TXT RDATA string from a DNS response.
func parseTXTResponse(resp []byte) (string, error) {
	if len(resp) < 12 {
		return "", fmt.Errorf("dns response too short")
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount == 0 {
		return "", fmt.Errorf("no answers in dns response")
	}

	offset := 12

	// Skip question QNAME.
	for offset < len(resp) {
		if resp[offset] == 0 {
			offset++
			break
		}
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += int(resp[offset]) + 1
	}
	offset += 4 // QTYPE + QCLASS

	if offset >= len(resp) {
		return "", fmt.Errorf("truncated after question section")
	}

	// Skip answer NAME.
	if offset < len(resp) && resp[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(resp) {
			if resp[offset] == 0 {
				offset++
				break
			}
			if resp[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(resp[offset]) + 1
		}
	}

	// Skip TYPE(2) + CLASS(2) + TTL(4) = 8 bytes.
	offset += 8
	if offset+2 > len(resp) {
		return "", fmt.Errorf("truncated before rdlength")
	}
	rdlength := int(binary.BigEndian.Uint16(resp[offset : offset+2]))
	offset += 2
	if offset+rdlength > len(resp) {
		return "", fmt.Errorf("truncated rdata")
	}

	rdata := resp[offset : offset+rdlength]
	if len(rdata) < 1 {
		return "", fmt.Errorf("empty rdata")
	}

	// TXT RDATA: one or more length-prefixed strings.
	var sb strings.Builder
	i := 0
	for i < len(rdata) {
		strLen := int(rdata[i])
		i++
		if i+strLen > len(rdata) {
			return "", fmt.Errorf("truncated txt string")
		}
		sb.Write(rdata[i : i+strLen])
		i += strLen
	}
	return sb.String(), nil
}
