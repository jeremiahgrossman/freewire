package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ProbeResponder answers reachability probes on ports we do not otherwise
// listen on, so a client can learn -- from a café table -- whether a captive
// portal passes arbitrary UDP to THIS server on a given port.
//
// Why this has to exist server-side: mainstream portals allow-list by
// destination, not port, so "UDP/443 reaches Google" says nothing about whether
// it reaches us. The only honest test sends bytes to our own IP and checks they
// arrive, which means our server has to answer. See
// PORTAL-CARRIER-IDEATION-2026-08-24.md.
//
// It is deliberately not a general service:
//   - Magic-gated. A datagram is answered only if it opens with probeMagic, so
//     the port is not a reflector for arbitrary traffic.
//   - Non-amplifying. The reply (probeMagic + the client's nonce, 24 bytes) is
//     smaller than the smallest accepted request (probeMinRequest, 64 bytes), so
//     even a spoofed source cannot turn this into an amplifier.
//   - Rate-limited globally, so it cannot be conscripted to pelt a third party.
//   - Stateless and silent otherwise: no per-probe logging, and never the source
//     address -- the privacy guarantee holds here too.
type ProbeResponder struct {
	log *zap.Logger
	// tcbitSuffix is the uppercased, dot-prefixed authoritative zone
	// (e.g. ".T.PINGHOP.NET"). Empty disables the TC-bit experiment's
	// DNS-over-TCP half, so the probe port stays probe-only.
	tcbitSuffix string

	// carrierBridge, when set, relays a DNS-over-TCP carrier connection to
	// WireGuard after the carrier hello. Port 53/tcp is shared three ways --
	// probe, TC-bit experiment, carrier -- because 53 is the port captive
	// portals actually pass, so everything that wants to reach us there has to
	// arrive on it. The dispatch is unambiguous; see handleTCPProbe.
	carrierBridge func(net.Conn)
}

// probeMagic opens every probe request and reply. Eight bytes, fixed, so a
// stray datagram on the port is ignored rather than answered.
var probeMagic = []byte("FWPROBE1")

const (
	// A request must be at least this large, and the reply is always smaller,
	// so the responder can never amplify. Clients pad up to this.
	probeMinRequest = 64

	// nonce length the client supplies and the responder echoes, so a client
	// cannot mistake a stale or injected datagram for its own reply.
	probeNonceLen = 16

	// Global ceiling on replies per second across all probe ports. A probe is a
	// handful of packets; this is far above real use and far below what makes
	// the responder useful as a weapon.
	probeMaxRepliesPerSec = 200
)

// NewProbeResponder builds a responder. It holds no per-connection state.
func NewProbeResponder(log *zap.Logger) *ProbeResponder {
	return &ProbeResponder{log: log}
}

// WithTCBitZone enables the TC-bit experiment's DNS-over-TCP half for zone
// (e.g. "t.pinghop.net"). Scaffolding; see tcbit.go.
func (p *ProbeResponder) WithTCBitZone(zone string) *ProbeResponder {
	if zone != "" {
		p.tcbitSuffix = "." + strings.ToUpper(strings.TrimSuffix(zone, "."))
	}
	return p
}

// WithDNSCarrier enables the DNS-over-TCP carrier on the probe's TCP port,
// relaying accepted carrier connections to WireGuard via bridge.
func (p *ProbeResponder) WithDNSCarrier(bridge func(net.Conn)) *ProbeResponder {
	p.carrierBridge = bridge
	return p
}

// Run listens on every port in ports (UDP, both v4 and v6 via a dual-stack
// socket) until ctx is cancelled. Ports already served by another listener must
// not appear here; the caller owns that.
func (p *ProbeResponder) Run(ctx context.Context, ports []int) error {
	if len(ports) == 0 {
		return nil
	}
	limiter := newProbeLimiter(probeMaxRepliesPerSec)

	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			p.serve(ctx, port, limiter)
		}(port)
	}
	wg.Wait()
	return nil
}

func (p *ProbeResponder) serve(ctx context.Context, port int, limiter *probeLimiter) {
	// "udp" (not "udp4") binds dual-stack, so one socket answers probes arriving
	// over both IPv4 and IPv6 -- the IPv6 reachability probe needs the v6 path
	// to be answered by the same server.
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		p.log.Error("probe responder listen", zap.Int("port", port), zap.String("cause", netErrCause(err)))
		return
	}
	p.log.Info("probe responder listening", zap.Int("port", port))

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Do not log src: a probe carries a client IP, which this server
			// does not record anywhere.
			continue
		}
		if n < probeMinRequest || !bytes.HasPrefix(buf[:n], probeMagic) {
			// Not a probe (or too small to be non-amplifying). Ignore silently;
			// answering would make the port a reflector.
			continue
		}
		if !limiter.allow() {
			continue
		}
		// Echo magic + the client's nonce, and nothing else. 24 bytes < the
		// 64-byte floor on requests, so this never amplifies.
		reply := make([]byte, 0, len(probeMagic)+probeNonceLen)
		reply = append(reply, probeMagic...)
		reply = append(reply, buf[len(probeMagic):len(probeMagic)+probeNonceLen]...)
		conn.WriteTo(reply, src) //nolint:errcheck // best-effort; a lost reply reads as "blocked", which is the safe error
	}
}

// probeLimiter is a coarse global token bucket. It exists so the responder
// cannot be used to flood a third party, not to shape real probe traffic (which
// is a few packets). Refills once per second.
type probeLimiter struct {
	mu       sync.Mutex
	tokens   int
	max      int
	lastFill time.Time
}

func newProbeLimiter(perSec int) *probeLimiter {
	return &probeLimiter{tokens: perSec, max: perSec}
}

func (l *probeLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// time.Now here is a rate-limit refill clock, not an event timestamp, so it
	// records nothing about any client.
	now := time.Now()
	if now.Sub(l.lastFill) >= time.Second {
		l.tokens = l.max
		l.lastFill = now
	}
	if l.tokens <= 0 {
		return false
	}
	l.tokens--
	return true
}

// ---------------------------------------------------------------------------
// TCP probes
//
// The UDP responder above answers "does this portal forward arbitrary UDP to
// us on port N". It cannot answer the TCP form of the same question, and three
// TCP ports are worth measuring at a portal and were never surveyed:
//
//   - TCP/53 (DNS-over-TCP, RFC 7766). The DNS carrier is UDP-only on both
//     ends. Our client-side AIMD limiter and a public recursor's forwarding cap
//     both meter QUERIES, not bytes, while DNS-over-TCP carries 64KB messages
//     behind a 2-byte length prefix against ~1232 usable bytes per EDNS0 UDP
//     exchange. Where a portal passes it, the same round trips move far more
//     payload. Whether portals that allow-list UDP/53 also allow TCP/53 is
//     unmeasured, which is what this line is for.
//   - TCP/853 (DoT-class). Walled gardens sometimes pass it because Android
//     Private DNS breaks without it.
//   - TCP/80, handled by HTTPProbeHandler below rather than here, because the
//     ACME HTTP-01 responder already owns that port.
//
// A TCP probe cannot be spoofed into an amplification vector (the handshake
// proves the source), so the non-amplification rule that shapes the UDP path
// does not bind here. The magic gate and the global limiter still apply: the
// port must not be a general-purpose service, and the responder must not be
// conscriptable.

// probeTCPIdleTimeout bounds a probe connection end to end. A probe is one
// small write and one small read, so anything slower is a stalled or hostile
// peer and is dropped rather than held.
const probeTCPIdleTimeout = 10 * time.Second

// RunTCP listens on every port in ports (TCP, dual-stack) until ctx is
// cancelled, answering the same magic-gated probe the UDP responder answers.
// Ports already served by another listener must not appear here; the caller
// owns that.
func (p *ProbeResponder) RunTCP(ctx context.Context, ports []int) error {
	if len(ports) == 0 {
		return nil
	}
	limiter := newProbeLimiter(probeMaxRepliesPerSec)

	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			p.serveTCP(ctx, port, limiter)
		}(port)
	}
	wg.Wait()
	return nil
}

func (p *ProbeResponder) serveTCP(ctx context.Context, port int, limiter *probeLimiter) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		p.log.Error("probe responder listen (tcp)", zap.Int("port", port), zap.String("cause", netErrCause(err)))
		return
	}
	p.log.Info("probe responder listening (tcp)", zap.Int("port", port))

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Do not log the peer: it carries a client IP, which this server
			// does not record anywhere.
			continue
		}
		// One goroutine per probe, so a peer that opens a connection and never
		// writes cannot block the next prober behind it.
		go p.handleTCPProbe(conn, limiter)
	}
}

func (p *ProbeResponder) handleTCPProbe(conn net.Conn, limiter *probeLimiter) {
	// Closed here UNLESS the connection is handed to the carrier bridge, which
	// then owns it. This cannot be a bare `defer conn.Close()` with an early
	// return: runtime.Goexit runs deferred calls too, so an "escape without
	// closing" via Goexit would still close the connection and kill every tunnel
	// the instant it was established.
	handedOff := false
	defer func() {
		if !handedOff {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(probeTCPIdleTimeout)) //nolint:errcheck

	// Peek two bytes to separate a probe from DNS-over-TCP, which shares this
	// port when it is 53. The two cannot be confused: a DNS-over-TCP stream opens
	// with a 2-byte BE length prefix, always small, while a probe opens with
	// "FW" = 0x4657 = 17943, an absurd length for a DNS message. Same peek trick
	// wss443 uses to tell a raw frame from an HTTP upgrade inside TLS.
	var head [2]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return
	}
	if !bytes.Equal(head[:], probeMagic[:2]) {
		handedOff = p.handleTCPDNS(conn, head, limiter)
		return
	}

	// Read the rest of the probe floor. A shorter write is not a probe, and
	// reading no more than this keeps the responder from being a byte sink.
	req := make([]byte, probeMinRequest)
	copy(req, head[:])
	if _, err := io.ReadFull(conn, req[2:]); err != nil {
		return
	}
	if !bytes.HasPrefix(req, probeMagic) {
		// Not a probe. Close without answering, so the port is not a service.
		return
	}
	if !limiter.allow() {
		return
	}
	reply := make([]byte, 0, len(probeMagic)+probeNonceLen)
	reply = append(reply, probeMagic...)
	reply = append(reply, req[len(probeMagic):len(probeMagic)+probeNonceLen]...)
	conn.Write(reply) //nolint:errcheck // best-effort; a lost reply reads as "blocked", the safe error
}

// HTTPProbePath is the URL the TCP/80 reachability probe fetches. It answers
// with probeMagic + the echoed nonce, so a client can tell OUR origin from a
// captive portal's own web server intercepting port 80 -- which is the whole
// point on a network that redirects :80 to a login page. Kept in sync with the
// client's probebattery.go.
const HTTPProbePath = "/.freewire-probe"

// probeNonceQuery is the query parameter carrying the client's hex nonce.
const probeNonceQuery = "nonce"

// HTTPProbeHandler serves HTTPProbePath and nothing else, so it is safe to hand
// to the ACME HTTP-01 responder as its fallback handler (autocert keeps the
// challenge paths for itself and passes everything else here).
//
// Port 80 is worth a probe line for a reason peculiar to captive portals: a
// portal MUST do something with :80 to serve its own redirect, and a portal
// that transparently PROXIES it rather than dropping it will forward a request
// carrying a Host header to our origin. Whether that happens is unmeasured.
func (p *ProbeResponder) HTTPProbeHandler() http.Handler {
	limiter := newProbeLimiter(probeMaxRepliesPerSec)
	mux := http.NewServeMux()
	mux.HandleFunc(HTTPProbePath, func(w http.ResponseWriter, r *http.Request) {
		nonce, err := hex.DecodeString(r.URL.Query().Get(probeNonceQuery))
		if err != nil || len(nonce) != probeNonceLen {
			// Magic-gate equivalent: without a well-formed nonce this is not our
			// probe, and answering would make the path a generic endpoint.
			http.NotFound(w, r)
			return
		}
		if !limiter.allow() {
			http.Error(w, "", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(probeMagic) //nolint:errcheck
		w.Write(nonce)      //nolint:errcheck
	})
	return mux
}

// handleTCPDNS serves the TC-bit experiment over DNS-over-TCP (RFC 7766) on the
// probe port, when that port is 53. head holds the two length bytes already read
// by the dispatch above.
//
// It answers ONLY the experiment name. Anything else is closed unanswered, so
// TCP/53 does not become a general resolver -- this is a measuring instrument,
// not a service, and it comes out with the rest of the scaffolding.
// handleTCPDNS serves the DNS-over-TCP half of port 53: the carrier hello, and
// the TC-bit experiment. head holds the two length bytes already read.
//
// It answers ONLY those two names. Anything else is closed unanswered, so TCP/53
// never becomes a general resolver. Returns true when the connection has been
// handed to the carrier bridge and must NOT be closed by the caller.
func (p *ProbeResponder) handleTCPDNS(conn net.Conn, head [2]byte, limiter *probeLimiter) bool {
	n := int(binary.BigEndian.Uint16(head[:]))
	if n < 12 || n > 4096 {
		return false
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(conn, query); err != nil {
		return false
	}
	name, err := extractQNAME(query, 12)
	if err != nil {
		return false
	}
	label := strings.ToUpper(strings.TrimSuffix(name, "."))
	if p.tcbitSuffix == "" || !strings.HasSuffix(label, p.tcbitSuffix) {
		return false
	}
	inner := strings.TrimSuffix(label, p.tcbitSuffix)

	// Carrier hello: <nonce>.C -- answered with a nonce-echoing TXT so the client
	// can tell OUR server from a portal's transparent DNS proxy, then the
	// connection becomes a WireGuard relay.
	if nonce, ok := parseDNSCarrierHello(inner); ok {
		if p.carrierBridge == nil {
			return false
		}
		if !limiter.allow() {
			return false
		}
		reply := dnsCarrierHelloReply(query, nonce)
		if reply == nil {
			return false
		}
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
		if _, err := conn.Write(out[:]); err != nil {
			return false
		}
		if _, err := conn.Write(reply); err != nil {
			return false
		}
		// Clear the probe's short deadline: the bridge sets its own rolling idle
		// deadline, and leaving this one would kill every tunnel after 10s.
		conn.SetDeadline(time.Time{}) //nolint:errcheck
		p.log.Info("dns-tcp carrier accepted")
		go p.carrierBridge(conn)
		return true
	}

	req, ok := parseTCBitQuery(inner)
	if !ok {
		return false
	}
	if !limiter.allow() {
		return false
	}
	reply := tcbitSizedReply(query, req.size)
	if reply == nil {
		return false
	}
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(len(reply)))
	conn.Write(out[:]) //nolint:errcheck
	conn.Write(reply)  //nolint:errcheck
	return false
}
