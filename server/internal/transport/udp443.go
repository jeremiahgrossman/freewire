package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/metrics"
)

// UDP443Server carries WireGuard directly over UDP/443, and answers reachability
// probes on the same port.
//
// Why UDP/443: portals are TCP-intercept machines. Blocking UDP/443 breaks HTTP/3
// to Google/Cloudflare/YouTube, so "block QUIC" is an off-by-default firewall
// feature and many portals pass UDP/443 pre-auth. When they do, this is the
// fastest carrier we have -- WireGuard is already UDP, so there is NO framing and
// NO TCP-over-TCP penalty, unlike the WebSocket carriers. See
// PORTAL-CARRIER-IDEATION-2026-08-24.md and FIELD-TEST-CONTINGENCIES.md.
//
// It shares the port with the reachability probe (so `--probe-battery` keeps
// working) by dispatching each datagram on its first bytes:
//   - probeMagic prefix, >= probeMinRequest bytes -> a probe; reply magic+nonce.
//   - WireGuard message type 1..4 in the first byte -> relay to local WireGuard.
//   - anything else -> drop.
//
// The relay is a per-source UDP NAT: each distinct client address gets its own
// socket to 127.0.0.1:wgPort, so wireguard-go sees each client as a distinct
// endpoint and sends its replies back to the right one. Idle sessions expire on
// the same ~WireGuard-session clock as the other carriers.
type UDP443Server struct {
	wgPort int
	log    *zap.Logger

	mu       sync.Mutex
	sessions map[string]*udpSession
	// sem bounds concurrent relay sessions, like the TLS listener: each costs a
	// socket and a goroutine before the peer has proven anything.
	sem chan struct{}
}

// WireGuard message types (RFC/whitepaper §5.4): the first byte of every packet.
// A datagram whose first byte is one of these is WireGuard; the rest of the type
// field is three reserved zero bytes, which we do not bother checking.
const (
	wgHandshakeInitiation = 1
	wgHandshakeResponse   = 2
	wgCookieReply         = 3
	wgTransportData       = 4
)

const (
	// A relay session with no traffic for this long is torn down. WireGuard
	// sends keepalives every 25s, so two minutes of silence is a dead tunnel --
	// matched to tlsIdleTimeout.
	udpSessionIdle = 120 * time.Second

	// Ceiling on concurrent relay sessions, matched to the TLS listener.
	maxUDPSessions = 256
)

type udpSession struct {
	wgConn   *net.UDPConn
	lastSeen time.Time
}

// NewUDP443Server builds the carrier. wgPort is the local WireGuard UDP port.
func NewUDP443Server(wgPort int, log *zap.Logger) *UDP443Server {
	return &UDP443Server{
		wgPort:   wgPort,
		log:      log,
		sessions: make(map[string]*udpSession),
		sem:      make(chan struct{}, maxUDPSessions),
	}
}

// Run listens on UDP/443 until ctx is cancelled.
func (s *UDP443Server) Run(ctx context.Context, port int) error {
	// Dual-stack ("udp"): a v6-reachable client can use this carrier too, and it
	// costs nothing here.
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("udp443: listen: %w", err)
	}
	udpConn := conn.(*net.UDPConn)
	s.log.Info("udp443 listening", zap.Int("port", port))

	go func() {
		<-ctx.Done()
		udpConn.Close()
	}()
	go s.reapLoop(ctx)

	limiter := newProbeLimiter(probeMaxRepliesPerSec)
	buf := make([]byte, 1500)
	for {
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue // do not log src: it carries a client IP
		}
		if n == 0 {
			continue
		}
		s.dispatch(udpConn, src, buf[:n], limiter)
	}
}

// dispatch routes one datagram to the probe responder or the WireGuard relay.
func (s *UDP443Server) dispatch(conn *net.UDPConn, src *net.UDPAddr, pkt []byte, limiter *probeLimiter) {
	// Probe first: it has a distinctive 8-byte magic and a size floor, so it can
	// never be confused with a WireGuard packet (whose first byte is 1..4).
	if len(pkt) >= probeMinRequest && startsWith(pkt, probeMagic) {
		if !limiter.allow() {
			return
		}
		reply := make([]byte, 0, len(probeMagic)+probeNonceLen)
		reply = append(reply, probeMagic...)
		reply = append(reply, pkt[len(probeMagic):len(probeMagic)+probeNonceLen]...)
		conn.WriteToUDP(reply, src) //nolint:errcheck
		return
	}

	switch pkt[0] {
	case wgHandshakeInitiation, wgHandshakeResponse, wgCookieReply, wgTransportData:
		s.relayToWireGuard(conn, src, pkt)
	default:
		// Not a probe and not WireGuard. Drop silently -- answering would make
		// the port a reflector, and this carrier is not a general UDP service.
	}
}

// relayToWireGuard forwards a client datagram to the local WireGuard port,
// creating a per-source session (and its reply pump) on first sight.
func (s *UDP443Server) relayToWireGuard(conn *net.UDPConn, src *net.UDPAddr, pkt []byte) {
	key := src.String()

	s.mu.Lock()
	sess := s.sessions[key]
	if sess != nil {
		sess.lastSeen = time.Now()
		s.mu.Unlock()
		sess.wgConn.Write(pkt) //nolint:errcheck
		return
	}
	s.mu.Unlock()

	// New client. Claim a slot before spending a socket + goroutine on it.
	select {
	case s.sem <- struct{}{}:
	default:
		s.log.Warn("udp443: session limit reached; dropping", zap.Int("limit", maxUDPSessions))
		return
	}

	wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: s.wgPort}
	wgConn, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		<-s.sem
		s.log.Error("udp443: dial wg", zap.String("cause", netErrCause(err)))
		return
	}

	sess = &udpSession{wgConn: wgConn, lastSeen: time.Now()}
	s.mu.Lock()
	s.sessions[key] = sess
	s.mu.Unlock()
	metrics.Global.UDP443Sessions.Add(1)

	// Reply pump: WireGuard's answers on this socket go back to this client. A
	// copy of src is captured, not the shared buffer's address.
	dst := *src
	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.sessions, key)
			s.mu.Unlock()
			wgConn.Close()
			<-s.sem
		}()
		rbuf := make([]byte, 1500)
		for {
			wgConn.SetReadDeadline(time.Now().Add(udpSessionIdle)) //nolint:errcheck
			n, err := wgConn.Read(rbuf)
			if err != nil {
				return // idle timeout or closed: end the session
			}
			if _, err := conn.WriteToUDP(rbuf[:n], &dst); err != nil {
				return
			}
		}
	}()

	sess.wgConn.Write(pkt) //nolint:errcheck
}

// reapLoop tears down sessions idle past udpSessionIdle. The reply pump already
// exits on its own read deadline; this closes the client->wg direction's view of
// a session whose client went silent without the wg side ever answering.
func (s *UDP443Server) reapLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-udpSessionIdle)
			s.mu.Lock()
			for _, sess := range s.sessions {
				if sess.lastSeen.Before(cutoff) {
					// Closing the socket unblocks its reply pump, which does the
					// map delete and slot release.
					sess.wgConn.Close()
				}
			}
			s.mu.Unlock()
		}
	}
}

func startsWith(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}
