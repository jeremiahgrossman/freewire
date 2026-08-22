package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

type registerPeerRequest struct {
	PublicKey     string `json:"public_key"`
	ClientVersion string `json:"client_version"`
	DeviceName    string `json:"device_name,omitempty"`
}

type registerPeerResponse struct {
	TunnelIP          string `json:"tunnel_ip"`
	TunnelIPv6        string `json:"tunnel_ip_v6"`
	KeepaliveInterval int    `json:"keepalive_interval"`
	PeerToken         string `json:"peer_token"`
}

func (s *Server) handleRegisterPeer(w http.ResponseWriter, r *http.Request) {
	var req registerPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "public_key is required")
		return
	}

	// Phase 1: no Privacy Pass — all peers accepted (self-hosted mode).
	// Privacy Pass token verification is added in Phase 4.

	// Capacity check is enforced inside AddPeer atomically to avoid TOCTOU.
	peerToken := newToken()
	peer, err := s.wg.AddPeer(peerToken, req.PublicKey, s.cfg.Capacity)
	if err != nil {
		if err.Error() == "ip pool exhausted" || err.Error() == "server at capacity" {
			writeError(w, http.StatusServiceUnavailable, "PEER_LIMIT_REACHED", "server is at capacity")
			return
		}
		s.log.Error("add peer failed", zap.String("session", redactToken(peerToken)), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "SERVER_ERROR", "failed to register peer")
		return
	}

	writeJSON(w, http.StatusCreated, registerPeerResponse{
		TunnelIP:          peer.TunnelIP,
		TunnelIPv6:        peer.TunnelIPv6,
		KeepaliveInterval: 25,
		PeerToken:         peerToken,
	})
}

func (s *Server) handleRemovePeer(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	removed, err := s.wg.RemovePeer(token)
	if err != nil {
		s.log.Error("remove peer failed", zap.String("session", redactToken(token)), zap.Error(err))
	}
	// 204 for an unknown token told the client its removal succeeded when
	// nothing was removed. The spec distinguishes them, and the client relies on
	// 404 meaning "already gone" rather than "your token was wrong".
	if !removed {
		writeError(w, http.StatusNotFound, "PEER_NOT_FOUND", "No peer with that token.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

// redactToken renders a peer token safe to log.
//
// The token is the only credential that authorises removing a peer, so a log
// line containing one is a credential in a file that outlives the session and
// is read by more people than the peer. The prefix is enough to correlate
// entries without being enough to use.
func redactToken(token string) string {
	if len(token) <= 6 {
		return "redacted"
	}
	return token[:6] + "…"
}
