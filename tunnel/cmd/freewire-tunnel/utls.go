package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// clientHelloIDs is the rotation set for TLS fingerprinting. Each entry makes
// the ClientHello indistinguishable from that browser's, so DPI cannot
// fingerprint the handshake as wireguard-go over TLS.
var clientHelloIDs = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloSafari_Auto,
	utls.HelloFirefox_Auto,
}

// pickClientHelloID returns a uniformly random fingerprint from the rotation
// set. Randomizing per connection prevents a network from learning that
// Freewire always presents one specific fingerprint.
func pickClientHelloID() utls.ClientHelloID {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(clientHelloIDs))))
	if err != nil {
		return clientHelloIDs[0]
	}
	return clientHelloIDs[n.Int64()]
}

// utlsHandshake wraps an established TCP connection in a uTLS client using a
// randomly chosen browser fingerprint, performs the handshake, and returns the
// TLS connection. The caller retains responsibility for closing raw on error.
func utlsHandshake(raw net.Conn, serverName string, insecure bool, deadline time.Duration) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: insecure, //nolint:gosec // dev-only; production sets false
		MinVersion:         utls.VersionTLS12,
	}

	c := utls.UClient(raw, cfg, pickClientHelloID())
	if err := c.SetDeadline(time.Now().Add(deadline)); err != nil {
		return nil, fmt.Errorf("utls: set deadline: %w", err)
	}
	if err := c.Handshake(); err != nil {
		return nil, fmt.Errorf("utls: handshake: %w", err)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("utls: clear deadline: %w", err)
	}
	return c, nil
}
