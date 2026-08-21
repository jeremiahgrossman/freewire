package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
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
// Sliding window: initial 8, AIMD, max 64
// Domain: *.tunnel.freewire.com

const (
	dnsTunnelDomain     = "tunnel.freewire.com"
	dnsKeepaliveEvery   = 30 * time.Second
	dnsHandshakeTimeout = 3 * time.Second
	dnsWindowInit       = 8
	dnsWindowMax        = 64
)

var b32enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsClientSession holds the state for an active DNS tunnel session.
type dnsClientSession struct {
	token      []byte   // 10-byte opaque session token
	sessionKey [32]byte // derived ChaCha20-Poly1305 key
	txSeq      uint32   // next outbound sequence number (atomic add)
	windowSize int      // current sliding window size (AIMD)
	dnsServer  string   // resolved DNS server IP
	mu         sync.Mutex
}

// runDNSTunnel establishes the DNS tunnel handshake and returns a local UDP
// PacketConn that bridges wireguard-go UDP ↔ DNS tunnel.
// Returns an error if the handshake fails within dnsHandshakeTimeout.
func runDNSTunnel(cfg Config) (net.PacketConn, error) {
	dnsServer, err := resolveLocalDNSServer()
	if err != nil {
		return nil, fmt.Errorf("dns tunnel: resolve dns server: %w", err)
	}

	sess, err := dnsHandshake(cfg, dnsServer)
	if err != nil {
		return nil, fmt.Errorf("dns tunnel: handshake: %w", err)
	}

	// Local UDP proxy: WireGuard sends packets here, we encode and query DNS.
	lp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("dns tunnel: local proxy: %w", err)
	}

	go sess.run(lp)
	return lp, nil
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
				if len(parts) >= 2 && net.ParseIP(parts[1]) != nil {
					return parts[1], nil
				}
			}
		}
	}
	// Fallback: use a public resolver.
	return "8.8.8.8", nil
}

// dnsHandshake performs the 3-step handshake and returns an initialized session.
//
// Step 1: ClientHello — query h.1.<b32(clientPub)>.tunnel.freewire.com TXT
// Step 2: ServerHello — parse TXT: <b32(serverPub)>.<b32(token)>
// Step 3: ClientConfirm — query h.3.<b32(mac)>.<b32(token)>.tunnel.freewire.com TXT
func dnsHandshake(cfg Config, dnsServer string) (*dnsClientSession, error) {
	deadline := time.Now().Add(dnsHandshakeTimeout)

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
	helloName := "h.1." + clientPubB32 + "." + dnsTunnelDomain + "."

	resp, err := dnsQuery(dnsServer, helloName, deadline)
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
	var sessionKey [32]byte
	hk := hkdf.New(sha256.New, shared, token, []byte("freewire-dns-tunnel-v1"))
	if _, err := io.ReadFull(hk, sessionKey[:]); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}

	// Compute MAC for ClientConfirm: SHA256(sessionKey || "confirm" || token)[:16].
	mac := dnsConfirmMAC(sessionKey, token)
	macB32 := b32enc.EncodeToString(mac)
	tokenB32 := b32enc.EncodeToString(token)

	// Step 3: ClientConfirm
	confirmName := "h.3." + macB32 + "." + tokenB32 + "." + dnsTunnelDomain + "."
	resp2, err := dnsQuery(dnsServer, confirmName, deadline)
	if err != nil {
		return nil, fmt.Errorf("client confirm: %w", err)
	}
	confirmTxt, err := parseTXTResponse(resp2)
	if err != nil || !strings.EqualFold(confirmTxt, "ok") {
		return nil, fmt.Errorf("client confirm: server rejected (got %q)", confirmTxt)
	}

	return &dnsClientSession{
		token:      token,
		sessionKey: sessionKey,
		windowSize: dnsWindowInit,
		dnsServer:  dnsServer,
	}, nil
}

// dnsConfirmMAC computes SHA256(sessionKey || "confirm" || token)[:16].
func dnsConfirmMAC(key [32]byte, token []byte) []byte {
	h := sha256.New()
	h.Write(key[:])
	h.Write([]byte("confirm"))
	h.Write(token)
	return h.Sum(nil)[:16]
}

// run bridges localProxy UDP ↔ DNS tunnel. Runs until localProxy is closed.
func (s *dnsClientSession) run(lp net.PacketConn) {
	ka := time.NewTicker(dnsKeepaliveEvery)
	defer ka.Stop()

	inboundCh := make(chan []byte, 64)
	peerCh := make(chan net.Addr, 1)
	var wgPeer net.Addr
	var peerOnce sync.Once

	// WireGuard → DNS.
	go func() {
		buf := make([]byte, 1416)
		for {
			n, peer, err := lp.ReadFrom(buf)
			if err != nil {
				return
			}
			peerOnce.Do(func() { peerCh <- peer })
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			go func(p []byte) {
				data, err := s.sendPacket(p)
				if err == nil && len(data) > 0 {
					inboundCh <- data
				}
			}(pkt)
		}
	}()

	// Inbound → WireGuard.
	go func() {
		for data := range inboundCh {
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
			go s.sendKeepalive() //nolint:errcheck
		}
	}
}

// sendPacket encrypts pkt, transmits via DNS TXT query, and returns any
// decrypted inbound data from the response.
func (s *dnsClientSession) sendPacket(pkt []byte) ([]byte, error) {
	seq := atomic.AddUint32(&s.txSeq, 1) - 1

	aead, err := chacha20poly1305.New(s.sessionKey[:])
	if err != nil {
		return nil, fmt.Errorf("send packet: aead: %w", err)
	}

	nonce := dnsMakeNonce(seq)
	ciphertext := aead.Seal(nil, nonce, pkt, nil)

	tokenB32 := b32enc.EncodeToString(s.token)
	seqB32 := b32enc.EncodeToString(uint32BE(seq))

	// Encode ciphertext and split into ≤63-char DNS labels.
	dataB32 := b32enc.EncodeToString(ciphertext)
	labels := chunkLabels(dataB32, 63)

	name := "t." + seqB32 + "." + tokenB32 + "." + strings.Join(labels, ".") + "." + dnsTunnelDomain + "."

	deadline := time.Now().Add(3 * time.Second)
	resp, err := dnsQuery(s.dnsServer, name, deadline)
	if err != nil {
		return nil, fmt.Errorf("send packet: dns query: %w", err)
	}

	txt, err := parseTXTResponse(resp)
	if err != nil || txt == "" {
		return nil, nil
	}

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

	// Join remaining labels (ciphertext may have been split).
	rxCipher, err := b32enc.DecodeString(strings.ReplaceAll(rparts[1], ".", ""))
	if err != nil {
		return nil, nil
	}

	rxNonce := dnsMakeNonce(rxSeq)
	plain, err := aead.Open(nil, rxNonce, rxCipher, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt response: %w", err)
	}
	return plain, nil
}

// sendKeepalive sends a DNS keepalive query k.<b32(token)>.tunnel.freewire.com.
func (s *dnsClientSession) sendKeepalive() error {
	tokenB32 := b32enc.EncodeToString(s.token)
	name := "k." + tokenB32 + "." + dnsTunnelDomain + "."
	deadline := time.Now().Add(3 * time.Second)
	_, err := dnsQuery(s.dnsServer, name, deadline)
	return err
}

// dnsMakeNonce builds a 12-byte ChaCha20-Poly1305 nonce: seq(4B big-endian) || 0x00(8B).
func dnsMakeNonce(seq uint32) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint32(nonce[:4], seq)
	return nonce
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

// dnsQuery sends a DNS TXT query for name to server:53 and returns the raw response packet.
func dnsQuery(server, name string, deadline time.Time) ([]byte, error) {
	c, err := net.DialTimeout("udp", server+":53", 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dns query: dial: %w", err)
	}
	defer c.Close()
	c.SetDeadline(deadline) //nolint:errcheck

	query := buildDNSQuery(name, 16 /* TXT */)
	if _, err := c.Write(query); err != nil {
		return nil, fmt.Errorf("dns query: write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dns query: read: %w", err)
	}
	return buf[:n], nil
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
	buf = append(buf, 0x00, 0x00) // ARCOUNT = 0

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

	return buf
}

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
