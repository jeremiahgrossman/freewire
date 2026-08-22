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
	"github.com/freewire/server/internal/metrics"
	"github.com/freewire/server/internal/privacypass"
	"github.com/freewire/server/internal/transport"
	"github.com/freewire/server/internal/tunnel"
)

func main() {
	// Registered first so it runs last: every other deferred cleanup below has
	// already completed by the time the process exits. Calling os.Exit directly
	// -- which log.Fatal does -- skips all of them, and one of them is the flush
	// that keeps spent tokens spent.
	exitCode := 0
	defer func() { os.Exit(exitCode) }()

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

	// Aggregate rollups replace the per-connection log lines the code used to
	// write. The privacy policy says a connection timeline is not kept, and an
	// hourly count is what can be published without keeping one.
	go metrics.RunRollup(log, time.Hour, expiryStop)

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
		// Persisted, because a restart that forgets which tokens were spent
		// makes every outstanding token replayable -- and a restart is the most
		// ordinary event in the server's life.
		spent, err = privacypass.NewPersistentSpentStore(
			privacypass.DefaultTokenTTL, cfg.SpentStorePath())
		if err != nil {
			log.Fatal("open spent token store", zap.Error(err))
		}
		defer spent.Close() //nolint:errcheck
		go spent.RunExpiry(time.Hour, expiryStop)
		log.Info("privacy pass enabled", zap.Int("spent_records_restored", spent.Len()))
	}

	srv := api.NewServer(cfg, wg, tlsCfg, issuer, spent, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// TLS/443 transport.
	tls443, err := transport.NewTLS443Server(tlsCfg, cfg.ListenPort, log)
	if err != nil {
		log.Error("init tls443 server", zap.Error(err))
		exitCode = 1
		return
	}
	go func() {
		if err := tls443.Run(ctx, cfg.TLSPort); err != nil {
			log.Error("tls443 server error", zap.Error(err))
		}
	}()

	// DNS tunnel transport.
	dnsServer := transport.NewDNSServer(cfg.ListenPort, cfg.DNSTunnelDomain, log)
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
	//
	// log.Fatal here would call os.Exit and skip every deferred cleanup above
	// it, including the spent-store flush -- so an API failure would be the one
	// exit path that loses the redemptions it was keeping.
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", zap.Error(err))
		exitCode = 1
		return
	}

	log.Info("stopped")
}
