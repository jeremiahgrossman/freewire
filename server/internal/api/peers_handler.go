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

// registerPeerRequest carries the public key and nothing else.
//
// It used to accept `device_name` and `client_version` alongside the token.
// Neither was read, and both are exactly what must not travel here: this
// request is the redemption half of a blind signature, and any attribute of the
// caller attached to it is a handle the issuance half can be correlated
// against. A device name is self-evidently identifying; a version string is a
// narrower fingerprint but still one, and on a small server the population
// sharing a given build is small enough to matter. Accepting a field is enough
// to make it appear -- a future client would fill it in because the schema
// invited it -- so the fields are gone rather than ignored.
type registerPeerRequest struct {
	PublicKey string `json:"public_key"`
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
	var spentNonce [32]byte
	var didSpend bool
	if s.issuer != nil {
		nonce, code, msg := s.redeemToken(r)
		if code != 0 {
			writeError(w, code, msg.code, msg.message)
			return
		}
		spentNonce, didSpend = nonce, true
	}
	// A registration that fails after the token was spent must give it back.
	// Marking it spent and then rejecting the request destroyed the user's token
	// on every 503 -- they paid for a slot the server did not have, and the
	// obvious retry cost them another one.
	refund := func() {
		if didSpend {
			s.spent.Refund(spentNonce)
		}
	}

	// Capacity check is enforced inside AddPeer atomically to avoid TOCTOU.
	peerToken, err := newToken()
	if err != nil {
		refund()
		s.log.Error("peer token generation failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "SERVER_ERROR", "failed to register peer")
		return
	}
	peer, err := s.wg.AddPeer(peerToken, req.PublicKey, s.cfg.Capacity)
	if err != nil {
		if err.Error() == "ip pool exhausted" || err.Error() == "server at capacity" {
			refund()
			writeError(w, http.StatusServiceUnavailable, "PEER_LIMIT_REACHED", "server is at capacity")
			return
		}
		refund()
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

// newToken mints the credential that authorises removing a peer.
//
// The RNG error is not ignorable here. rand.Read leaves the buffer zeroed when
// it fails, so discarding the error handed every affected caller the same
// all-zero token: the second registration would displace the first, and anyone
// could guess the token and delete the peer. A registration that cannot be
// given a unique token must fail instead.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
// Returns a zero status when the request may proceed, along with the nonce hash
// that was spent so the caller can hand it back if the registration then fails.
//
// The scheme name is RFC 9577's `PrivateToken`, which is what the IETF settled
// on for the HTTP authentication scheme; `PrivacyPass` names the working group,
// not the header. CLAUDE.md and client-server-api-spec.md said the latter, and
// have been corrected to match the wire format both ends already speak.
func (s *Server) redeemToken(r *http.Request) ([32]byte, int, tokenError) {
	const scheme = "PrivateToken token="
	var none [32]byte

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, scheme) {
		return none, http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "A token is required to register a peer."}
	}

	// Strip at most one pair of surrounding quotes rather than every quote
	// anywhere in the value: trimming the whole cutset would silently accept a
	// token whose interior quotes were removed, changing what was verified.
	value := strings.TrimPrefix(auth, scheme)
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return none, http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token could not be decoded."}
	}

	tok, err := privacypass.ParseToken(raw)
	if err != nil {
		return none, http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token is malformed."}
	}
	if err := s.issuer.Verify(tok); err != nil {
		return none, http.StatusPaymentRequired,
			tokenError{"TOKEN_INVALID", "The token is not valid."}
	}

	// Verification and spending are separate questions and both must pass: a
	// perfectly valid token that has already been used is still refused.
	hash := tok.NonceHash()
	if !s.spent.Redeem(hash) {
		return none, http.StatusPaymentRequired,
			tokenError{"TOKEN_SPENT", "This token has already been used."}
	}
	return hash, 0, tokenError{}
}
