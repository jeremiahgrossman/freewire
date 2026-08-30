package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// The DNS-over-TCP carrier: WireGuard over a TCP connection to the server's
// port 53. See server/internal/transport/dnstcp.go for why it exists; in short,
// it lifts two of the UDP DNS carrier's three ceilings (per-query payload, and
// the total absence of backpressure) and is not subject to the third at all,
// because it is server-direct and no recursor is in the path.
//
// It sits BELOW the 443-family carriers and ABOVE the UDP DNS tunnel: TCP to
// port 53 costs the same TCP-over-TCP penalty as tls443/wss443, so it is not
// faster than those, but it is far faster than the UDP DNS tunnel and it reaches
// networks that pass 53 while gating everything else. Whether a portal that
// allows UDP/53 also allows TCP/53 is exactly what --probe-battery's TCP/53 line
// measures, and it is the reason this carrier is worth having rather than
// assumed to work.

const (
	// dnsTCPHelloTimeout bounds the hello. It is one TCP round trip plus one DNS
	// exchange, so anything slower is a portal interfering rather than a slow
	// path, and the chain should fall through rather than wait.
	dnsTCPHelloTimeout = 5 * time.Second

	dnsCarrierNonceLen = 16
)

// dnsCarrierMagic must match server/internal/transport/dnstcp.go.
var dnsCarrierMagic = []byte("FWDNSTCP1")

// tryDNSTCP opens the carrier: a TCP connection to server:53, a DNS hello whose
// answer proves it reached OUR server, and then a stream the caller bridges to
// WireGuard.
//
// The nonce-echo check is the point of the hello. Port 53 is the port most
// likely to be intercepted by a transparent DNS proxy, so a connection that
// merely opens proves nothing -- a proxy will happily accept it and answer with
// its own NXDOMAIN. This distinguishes our server from an OBLIVIOUS transparent
// proxy that doesn't bother implementing the echo -- it does not prove the
// connection reached only our server, since dnsCarrierMagic is a public,
// hardcoded constant (compiled into this open-source client), not a secret; a
// targeted on-path adversary could reproduce the echo too. The real trust
// boundary is WireGuard's own authenticated Noise handshake carried over the
// bridged stream once this connects.
func tryDNSTCP(cfg Config) (net.Conn, error) {
	addr := net.JoinHostPort(cfg.ServerHost, "53")
	conn, err := net.DialTimeout("tcp", addr, dnsTCPHelloTimeout)
	if err != nil {
		return nil, fmt.Errorf("dns_tcp: dial: %w", err)
	}
	conn.SetDeadline(time.Now().Add(dnsTCPHelloTimeout)) //nolint:errcheck

	nonce := make([]byte, dnsCarrierNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	name := hex.EncodeToString(nonce) + ".c." + strings.TrimSuffix(effectiveDNSTunnelDomain(cfg), ".")
	query, id := tcbitBuildTXTQuery(name)

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: write hello: %w", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: read hello reply: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 4096 {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: implausible hello reply length %d", n)
	}
	reply := make([]byte, n)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: read hello reply: %w", err)
	}
	if binary.BigEndian.Uint16(reply[:2]) != id {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: hello reply id mismatch (answered by something else)")
	}
	want := append(append([]byte{}, dnsCarrierMagic...), nonce...)
	if !bytes.Contains(reply, want) {
		conn.Close()
		return nil, fmt.Errorf("dns_tcp: hello not answered by our server (no magic+nonce)")
	}

	// Hand the stream over with no deadline: from here the bridge's own idle
	// handling governs, and a leftover hello deadline would kill the tunnel
	// mid-session.
	conn.SetDeadline(time.Time{}) //nolint:errcheck
	return conn, nil
}
