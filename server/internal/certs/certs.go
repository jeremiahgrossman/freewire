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

// loadOrGenerateCert loads a TLS certificate from certFile/keyFile.
// If either path is empty or the files don't exist, it generates an in-memory
// self-signed P-256 certificate.
//
// The generated key is never written to disk. A fresh one is cheap to make on
// each start, and writing it to a shared directory would leave key material
// readable by anything else running as root.
func loadOrGenerateCert(certFile, keyFile string, log *zap.Logger) (tls.Certificate, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				return tls.LoadX509KeyPair(certFile, keyFile)
			}
		}
	}

	log.Info("tls443: generating in-memory self-signed certificate")

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
	return tls.X509KeyPair(certPEM, keyPEM)
}
