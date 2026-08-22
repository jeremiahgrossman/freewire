package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/api"
	"github.com/freewire/server/internal/certs"
	"github.com/freewire/server/internal/config"
	"github.com/freewire/server/internal/privacypass"
	"github.com/freewire/server/internal/transport"
	"github.com/freewire/server/internal/tunnel"
)

func main() {
	log, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer log.Sync() //nolint:errcheck

	cfgPath := "freewire-server.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatal("load config", zap.Error(err))
	}

	log.Info("starting",
		zap.String("version", cfg.ServerVersion),
		zap.String("region", cfg.Region),
		zap.Int("wg_port", cfg.ListenPort),
		zap.Int("api_port", cfg.APIPort),
		zap.Int("tls_port", cfg.TLSPort),
		zap.Int("dns_port", cfg.DNSTunnelPort),
		zap.Int("icmp_port", cfg.ICMPUDPPort),
	)

	wg, err := tunnel.NewManager(cfg, log)
	if err != nil {
		log.Fatal("init tunnel", zap.Error(err))
	}
	defer wg.Close()

	// One TLS configuration for the whole process, shared by the API and the
	// TLS/443 transport. Building it twice would start two ACME managers racing
	// for the port-80 challenge responder.
	tlsCfg, err := certs.Build(cfg.TLSCertFile, cfg.TLSKeyFile, certs.ACMEOptions{
		Domain:   cfg.ACMEDomain,
		Email:    cfg.ACMEEmail,
		CacheDir: cfg.ACMECacheDir,
	}, log)
	if err != nil {
		log.Fatal("build tls config", zap.Error(err))
	}

	// Privacy Pass is a managed-server feature. A self-hosted server leaves
	// privacy_pass_key empty: its operator controls which keys are registered,
	// so anonymous rate limiting has nothing to add there.
	expiryStop := make(chan struct{})
	defer close(expiryStop)

	var issuer *privacypass.Issuer
	var spent *privacypass.SpentStore
	if cfg.PrivacyPassKey != "" {
		key, keyErr := config.ParseRSAPrivateKey(cfg.PrivacyPassKey)
		if keyErr != nil {
			log.Fatal("parse privacy pass key", zap.Error(keyErr))
		}
		issuer, err = privacypass.NewIssuer(key)
		if err != nil {
			log.Fatal("privacy pass issuer", zap.Error(err))
		}
		spent = privacypass.NewSpentStore(privacypass.DefaultTokenTTL)
		go spent.RunExpiry(time.Hour, expiryStop)
		log.Info("privacy pass enabled")
	}

	srv := api.NewServer(cfg, wg, tlsCfg, issuer, spent, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// TLS/443 transport.
	tls443, err := transport.NewTLS443Server(tlsCfg, cfg.ListenPort, log)
	if err != nil {
		log.Fatal("init tls443 server", zap.Error(err))
	}
	go func() {
		if err := tls443.Run(ctx, cfg.TLSPort); err != nil {
			log.Error("tls443 server error", zap.Error(err))
		}
	}()

	// DNS tunnel transport.
	dnsServer := transport.NewDNSServer(cfg.ListenPort, log)
	go func() {
		if err := dnsServer.Run(ctx, cfg.DNSTunnelPort); err != nil {
			log.Error("dns server error", zap.Error(err))
		}
	}()

	// ICMP/UDP tunnel transport.
	icmpServer := transport.NewICMPServer(cfg.ListenPort, log)
	go func() {
		if err := icmpServer.Run(ctx, cfg.ICMPUDPPort); err != nil {
			log.Error("icmp server error", zap.Error(err))
		}
	}()

	// HTTP API (blocks until shutdown).
	if err := srv.Run(ctx); err != nil {
		log.Fatal("server error", zap.Error(err))
	}

	log.Info("stopped")
}
