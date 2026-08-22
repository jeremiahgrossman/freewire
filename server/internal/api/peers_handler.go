package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/freewire/server/internal/privacypass"
	"net/http"
	"strings"

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

	// Spend a Privacy Pass token, on servers that issue them.
	//
	// Deliberately the only thing consulted: the token is verified and marked
	// spent, and nothing about the caller is examined or recorded. Attaching a
	// device identifier or an address to this step would let issuance and
	// redemption be correlated afterwards, which is precisely what the blind
	// signature exists to prevent -- and it would still verify, so the loss
	// would be silent.
	if s.issuer != nil {
		if code, msg := s.redeemToken(r); code != 0 {
			writeError(w, code, msg.code, msg.message)
			return
		}
	}

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

type tokenError struct {
	code    string
	message string
}

// redeemToken verifies and spends the token on a registration request.
//
// Returns 0 when the request may proceed, otherwise an HTTP status and the
// error to report.
func (s *Server) redeemToken(r *http.Request) (int, tokenError) {
	const scheme = "PrivateToken token="

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, scheme) {
		return http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "A token is required to register a peer."}
	}

	raw, err := base64.RawURLEncoding.DecodeString(strings.Trim(strings.TrimPrefix(auth, scheme), `"`))
	if err != nil {
		return http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token could not be decoded."}
	}

	tok, err := privacypass.ParseToken(raw)
	if err != nil {
		return http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token is malformed."}
	}
	if err := s.issuer.Verify(tok); err != nil {
		return http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token is not valid."}
	}

	// Verification and spending are separate questions and both must pass: a
	// perfectly valid token that has already been used is still refused.
	if !s.spent.Redeem(tok.NonceHash()) {
		return http.StatusPaymentRequired,
			tokenError{"TOKEN_SPENT", "This token has already been used."}
	}
	return 0, tokenError{}
}
