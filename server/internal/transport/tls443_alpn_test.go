package transport

import (
	"crypto/tls"
	"testing"

	"go.uber.org/zap"
)

// The 443 listener must never advertise h2. It speaks HTTP/1.1 (the WebSocket
// carrier) and our raw framing, not HTTP/2. If it offers h2, a peer that honors
// ALPN -- CloudFront most importantly -- speaks real HTTP/2 to us and its
// connection preface is misread as a giant raw frame, which is the exact bug
// that made the CDN-fronted path 502 while our own client (which ignores ALPN)
// kept working and hid it.
func TestTLS443NeverOffersH2(t *testing.T) {
	// A shared config carrying h2, as autocert's TLSConfig does once ACME is on.
	// NewTLS443Server only rewrites NextProtos, so no real certificate is needed.
	shared := &tls.Config{
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		MinVersion: tls.VersionTLS12,
	}
	s, err := NewTLS443Server(shared, 51820, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range s.tlsConfig.NextProtos {
		if p == "h2" {
			t.Fatalf("tls443 advertises h2 in ALPN (%v); CloudFront will speak HTTP/2 and the fronted path 502s", s.tlsConfig.NextProtos)
		}
	}
	if len(s.tlsConfig.NextProtos) != 1 || s.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("tls443 should offer http/1.1 only, got %v", s.tlsConfig.NextProtos)
	}

	// The clone must not have mutated the shared config the API listener uses --
	// the API server does speak HTTP/2 and should keep h2.
	foundH2 := false
	for _, p := range shared.NextProtos {
		if p == "h2" {
			foundH2 = true
		}
	}
	if !foundH2 {
		t.Fatal("cloning mutated the shared config; the API listener lost h2")
	}
}
