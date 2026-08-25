package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
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
