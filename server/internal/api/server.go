package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/config"
	"github.com/freewire/server/internal/privacypass"
	"github.com/freewire/server/internal/tunnel"
)

type Server struct {
	cfg *config.Config
	wg  *tunnel.Manager
	tls *tls.Config
	// issuer is nil on self-hosted servers, which do not implement Privacy
	// Pass: the operator controls which keys are registered, so anonymous rate
	// limiting has nothing to add.
	issuer *privacypass.Issuer
	spent  *privacypass.SpentStore
	log    *zap.Logger
}

// NewServer creates the API server.
//
// tlsCfg is required. The API is where a client learns the server's WireGuard
// public key, which is the trust anchor for the entire tunnel: served over
// plaintext HTTP, anyone on the path could substitute their own key and
// endpoint and terminate the tunnel themselves, with uTLS and the tunnel's own
// cryptography protecting nothing. client-server-api-spec.md has always said
// HTTPS only.
func NewServer(
	cfg *config.Config,
	wg *tunnel.Manager,
	tlsCfg *tls.Config,
	issuer *privacypass.Issuer,
	spent *privacypass.SpentStore,
	log *zap.Logger,
) *Server {
	return &Server{cfg: cfg, wg: wg, tls: tlsCfg, issuer: issuer, spent: spent, log: log}
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/server/config", s.handleServerConfig)
	mux.HandleFunc("POST /v1/peers", s.handleRegisterPeer)
	mux.HandleFunc("DELETE /v1/peers/{token}", s.handleRemovePeer)
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/tokens/issue", s.handleIssueTokens)

	addr := fmt.Sprintf(":%d", s.cfg.APIPort)
	if s.tls == nil {
		return fmt.Errorf("api: refusing to serve without TLS")
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           http.MaxBytesHandler(mux, 64*1024),
		ReadHeaderTimeout: 5 * time.Second,
		// Without this a slow body holds a connection until the write deadline.
		// Every request here is a few hundred bytes.
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    s.tls,
	}

	s.log.Info("api listening (https)", zap.String("addr", addr))

	errCh := make(chan error, 1)
	go func() {
		// Certificates come from TLSConfig, so the file arguments are empty.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// writeJSON writes a JSON response. Never includes RemoteAddr.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorEnvelope{Error: errorBody{Code: code, Message: message}})
}
