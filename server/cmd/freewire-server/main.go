package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

const usage = `freewire-server -- Freewire VPN server

usage:
  freewire-server [config-path]

  config-path  path to the JSON config (default: freewire-server.json).
               If the file does not exist it is CREATED, and a fresh WireGuard
               keypair is generated into it -- so the path is the server's
               identity, not just its settings.

options:
  -h, --help   print this message and exit
`

// parseArgs resolves the config path, or exits after printing usage.
//
// It exists because the config path used to be taken as os.Args[1] with no
// validation, and config.Load CREATES a missing path with a freshly generated
// private key. So `freewire-server --help` -- the first thing anyone types --
// wrote a real keypair to a file literally named "--help", which then got
// committed. Rejecting anything that looks like a flag is the guard: an
// unrecognised option must never be able to mint an identity.
//
// Called before the exitCode defer below is registered, so os.Exit here skips
// no cleanup.
func parseArgs(args []string) string {
	path, msg, code, stop := resolveConfigPath(args)
	if stop {
		out := os.Stderr
		if code == 0 {
			out = os.Stdout
		}
		fmt.Fprint(out, msg)
		os.Exit(code)
	}
	return path
}

// resolveConfigPath is parseArgs without the exit, so the argument rules can be
// tested. It returns the config path, or a message plus an exit code and
// stop=true when the process should print and quit instead of starting.
func resolveConfigPath(args []string) (path, msg string, code int, stop bool) {
	const defaultPath = "freewire-server.json"
	if len(args) == 0 {
		return defaultPath, "", 0, false
	}
	if len(args) > 1 {
		return "", fmt.Sprintf("freewire-server: expected at most one argument, got %d\n\n%s", len(args), usage), 2, true
	}
	switch args[0] {
	case "-h", "--help", "help":
		return "", usage, 0, true
	}
	if strings.HasPrefix(args[0], "-") {
		// No flags are defined, so a leading dash is a typo or an unsupported
		// option. Treating it as a config path is what caused the bug above.
		return "", fmt.Sprintf("freewire-server: unknown option %q\n\n%s", args[0], usage), 2, true
	}
	return args[0], "", 0, false
}

func main() {
	cfgPath := parseArgs(os.Args[1:])

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
	//
	// The probe responder is built here rather than at its own wiring below
	// because the ACME manager needs its port-80 handler: autocert owns :80 for
	// the HTTP-01 challenge, so the only way the TCP/80 reachability probe can
	// be answered on an ACME server is as autocert's fallback handler.
	probe := transport.NewProbeResponder(log)
	tlsCfg, err := certs.Build(cfg.TLSCertFile, cfg.TLSKeyFile, certs.ACMEOptions{
		Domain:       cfg.ACMEDomain,
		Email:        cfg.ACMEEmail,
		CacheDir:     cfg.ACMECacheDir,
		HTTPFallback: probe.HTTPProbeHandler(),
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

	// WireGuard-over-UDP/443 carrier. The fastest carrier when a portal passes
	// QUIC-class UDP (no framing, no TCP-over-TCP). It owns UDP/443 and answers
	// the reachability probe on that port itself, so the standalone responder
	// below skips 443.
	udp443 := transport.NewUDP443Server(cfg.ListenPort, log)
	go func() {
		if err := udp443.Run(ctx, cfg.TLSPort); err != nil {
			log.Error("udp443 server error", zap.Error(err))
		}
	}()

	// Reachability probe responder. Magic-gated, non-amplifying, rate-limited:
	// it exists so a client behind a captive portal can learn whether the portal
	// passes arbitrary UDP to THIS server on a given port, which is the only
	// honest test under destination-based walled gardens. Ports colliding with a
	// listener above -- including UDP/443, now owned by the carrier above -- are
	// dropped rather than fought over.
	if probePorts := safeProbePorts(cfg, log); len(probePorts) > 0 {
		go func() {
			if err := probe.Run(ctx, probePorts); err != nil {
				log.Error("probe responder error", zap.Error(err))
			}
		}()
	}

	// The TCP half of the same survey. TCP/53 and TCP/853 are ports the field
	// has never been asked about: the DNS carrier is UDP-only on both ends, and
	// whether a portal that allow-lists UDP/53 also passes TCP/53 decides
	// whether a much higher-payload-per-query DNS carrier is even possible here.
	if probeTCPPorts := safeProbeTCPPorts(cfg, log); len(probeTCPPorts) > 0 {
		go func() {
			if err := probe.RunTCP(ctx, probeTCPPorts); err != nil {
				log.Error("probe responder error (tcp)", zap.Error(err))
			}
		}()
	}

	// Port 80 answers the probe too. With ACME on, that is autocert's fallback
	// handler wired above; with ACME off nothing listens there at all, so the
	// responder brings up its own server -- otherwise the TCP/80 line would read
	// "blocked" on every self-hosted deployment regardless of the portal.
	if cfg.ACMEDomain == "" {
		go func() {
			srv := &http.Server{
				Addr:              ":80",
				Handler:           probe.HTTPProbeHandler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				<-ctx.Done()
				srv.Close() //nolint:errcheck
			}()
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				// Port 80 needs privilege and is optional; a failure costs one
				// probe line, not the server.
				log.Warn("probe responder :80 unavailable", zap.Error(err))
			}
		}()
	}

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

// safeProbePorts returns the configured probe ports minus any that would collide
// with a UDP listener the server already runs. Binding a probe responder on the
// DNS (53), ICMP/UDP (4500), or WireGuard (51820) port would either fail to bind
// or shadow the real carrier, so those are dropped with a warning rather than
// risked. TCP/443 does not collide: the probe responder is UDP.
func safeProbePorts(cfg *config.Config, log *zap.Logger) []int {
	if cfg.ProbePorts == nil {
		return nil
	}
	reserved := map[int]bool{
		cfg.DNSTunnelPort: true,
		cfg.ICMPUDPPort:   true,
		cfg.ListenPort:    true, // WireGuard UDP
		cfg.TLSPort:       true, // UDP/443 is owned by the UDP443 carrier, which answers probes itself
	}
	var out []int
	for _, p := range *cfg.ProbePorts {
		if reserved[p] {
			log.Warn("probe port collides with an existing UDP listener; skipping", zap.Int("port", p))
			continue
		}
		out = append(out, p)
	}
	return out
}

// safeProbeTCPPorts returns the configured TCP probe ports minus any that would
// collide with a TCP listener the server already runs. TLS/443 serves the
// tls443 and wss443 carriers and the API's TLS port, and :80 is the ACME
// HTTP-01 responder (which answers the probe via HTTPProbeHandler instead), so
// both are dropped with a warning rather than fought over.
func safeProbeTCPPorts(cfg *config.Config, log *zap.Logger) []int {
	if cfg.ProbeTCPPorts == nil {
		return nil
	}
	reserved := map[int]bool{
		cfg.TLSPort: true, // TCP/443: tls443 + wss443 carriers
		cfg.APIPort: true,
		80:          true, // ACME HTTP-01 / the HTTP probe handler
	}
	var out []int
	for _, p := range *cfg.ProbeTCPPorts {
		if reserved[p] {
			log.Warn("tcp probe port collides with an existing TCP listener; skipping", zap.Int("port", p))
			continue
		}
		out = append(out, p)
	}
	return out
}
