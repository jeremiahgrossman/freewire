package certs

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

// Enabling ACME must not break clients that connect by bare IP.
//
// Every current client dials the server by IP and sends no SNI. autocert's own
// config answers from a host whitelist and fails any handshake without a
// recognized name, so handing it over unmodified would turn "configure a
// hostname" into a total outage for the raw TLS/443 carrier, the WebSocket
// carrier and the API at once. This asserts the fallback that prevents that.
func TestACMEConfigStillServesHandshakesWithoutSNI(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Build(
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		ACMEOptions{Domain: "origin.example.test", CacheDir: filepath.Join(dir, "acme")},
		zap.NewNop())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("ACME config has no GetCertificate")
	}

	// No SNI: what a client dialing a bare IP sends.
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil {
		t.Fatalf("no-SNI handshake refused: %v -- this is the outage this test exists to prevent", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("no-SNI handshake returned an empty certificate")
	}

	// An unrecognized name (a CDN fronting this origin sends its own distribution
	// hostname as SNI) must also complete rather than fail the handshake.
	cert, err = cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "d123.cloudfront.net"})
	if err != nil {
		t.Fatalf("unknown-SNI handshake refused: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("unknown-SNI handshake returned an empty certificate")
	}
	// In this test ACME cannot actually issue (no network), so both the no-SNI
	// and unknown-SNI paths land on the self-signed fallback -- the point here is
	// only that neither REFUSES the handshake. The live behavior (unknown SNI ->
	// real ACME cert for our domain, which is what makes CloudFront accept the
	// origin) is exercised end to end against the deployed server, not here,
	// because it needs a genuinely issued certificate.
}

// With no ACME domain the behavior is unchanged: a self-signed certificate is
// generated and served directly.
func TestNoACMEUsesSelfSignedCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Build(
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"),
		ACMEOptions{}, zap.NewNop())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected exactly one static certificate, got %d", len(cfg.Certificates))
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}
}

// The self-signed identity must be stable across restarts, or a client that
// pins it is locked out by the next deploy.
func TestSelfSignedCertificateIsStableAcrossBuilds(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	first, err := Build(certFile, keyFile, ACMEOptions{}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(certFile, keyFile, ACMEOptions{}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificates[0].Certificate[0]) != string(second.Certificates[0].Certificate[0]) {
		t.Fatal("certificate changed between builds; a pinned client would be locked out")
	}
}
