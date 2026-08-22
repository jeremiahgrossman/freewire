// Package certs builds the TLS configuration shared by every listener.
//
// One configuration is built for the whole process and handed to each server.
// Building it per listener would create a second ACME manager racing the first
// for the port-80 challenge responder, and would double the certificate churn
// against Let's Encrypt's rate limits.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/acme/autocert"
)

// ACMEOptions configures Let's Encrypt provisioning.
type ACMEOptions struct {
	Domain   string
	Email    string
	CacheDir string
}

// Build returns the TLS configuration for all listeners.
//
// Selection, in order:
//  1. acme.Domain set — provision and auto-renew via Let's Encrypt. Requires
//     port 80 reachable for the HTTP-01 challenge.
//  2. certFile and keyFile point at readable files — use them.
//  3. Otherwise — generate a self-signed certificate, held in memory only.
//     Development, and clients must be told explicitly to trust it.
func Build(certFile, keyFile string, acme ACMEOptions, log *zap.Logger) (*tls.Config, error) {
	if acme.Domain != "" {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acme.Domain),
			Cache:      autocert.DirCache(acme.CacheDir),
			Email:      acme.Email,
		}
		go func() {
			srv := &http.Server{
				Addr:              ":80",
				Handler:           m.HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second,
			}
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error("acme http-01 responder", zap.Error(err))
			}
		}()
		cfg := m.TLSConfig()
		cfg.MinVersion = tls.VersionTLS12
		log.Info("acme enabled", zap.String("domain", acme.Domain))
		return cfg, nil
	}

	cert, err := loadOrGenerateCert(certFile, keyFile, log)
	if err != nil {
		return nil, fmt.Errorf("load cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// selfSignedPaths are where a generated certificate is kept when the operator
// has not supplied one.
const (
	defaultSelfSignedCert = "./self-signed-cert.pem"
	defaultSelfSignedKey  = "./self-signed-key.pem"
)

// loadOrGenerateCert loads a TLS certificate from certFile/keyFile, generating
// a self-signed P-256 one if there is none.
//
// The generated pair is persisted. It used to be made fresh in memory on every
// start, on the reasoning that a new one is cheap and writing key material to a
// shared directory is a risk. Both halves of that were wrong. The risk argument
// does not hold: the WireGuard private key already sits in the config file in
// the same directory at the same permissions, and it is the more sensitive of
// the two. And "cheap to regenerate" missed what a certificate is for -- an
// identity that changes on every restart cannot be pinned, so a client that
// pins it is locked out by the next deploy, and a client that does not pin it
// has no way to tell the server from anyone standing in front of it.
//
// A server with a real hostname uses ACME and never reaches this path.
func loadOrGenerateCert(certFile, keyFile string, log *zap.Logger) (tls.Certificate, error) {
	if certFile == "" {
		certFile = defaultSelfSignedCert
	}
	if keyFile == "" {
		keyFile = defaultSelfSignedKey
	}
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				log.Info("tls443: loaded existing certificate", zap.String("cert", certFile))
				return cert, nil
			}
			// A corrupt pair is replaced rather than fatal: refusing to start
			// leaves no way back in on a headless box.
			log.Warn("tls443: existing certificate unusable; generating a new one",
				zap.Error(err))
		}
	}

	log.Info("tls443: generating self-signed certificate", zap.String("cert", certFile))

	// Generate P-256 private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Freewire"},
			CommonName:   "vpn.freewire.com",
		},
		DNSNames:              []string{"vpn.freewire.com", "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Persist so the identity survives a restart. A write failure is not fatal
	// -- the process can serve from what it holds in memory -- but it does mean
	// the next start presents a different identity, so it is reported.
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		log.Warn("tls443: could not persist certificate; it will change on restart",
			zap.Error(err))
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		log.Warn("tls443: could not persist certificate key; it will change on restart",
			zap.Error(err))
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
