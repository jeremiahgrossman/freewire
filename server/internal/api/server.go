package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/config"
	"github.com/freewire/server/internal/tunnel"
)

type Server struct {
	cfg *config.Config
	wg  *tunnel.Manager
	log *zap.Logger
}

func NewServer(cfg *config.Config, wg *tunnel.Manager, log *zap.Logger) *Server {
	return &Server{cfg: cfg, wg: wg, log: log}
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/server/config", s.handleServerConfig)
	mux.HandleFunc("POST /v1/peers", s.handleRegisterPeer)
	mux.HandleFunc("DELETE /v1/peers/{token}", s.handleRemovePeer)
	mux.HandleFunc("GET /v1/health", s.handleHealth)

	addr := fmt.Sprintf(":%d", s.cfg.APIPort)
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.MaxBytesHandler(mux, 64*1024),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	s.log.Info("api listening", zap.String("addr", addr))

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
