package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"

	"go.uber.org/zap"

	"github.com/freewire/server/internal/privacypass"
)

type issueRequest struct {
	// Base64url-encoded blinded messages, one per token requested.
	Blinded []string `json:"blinded"`
}

type issueResponse struct {
	// Base64url-encoded blind signatures, positionally matching the request.
	BlindSignatures []string `json:"blind_signatures"`
	// SHA-256 fingerprint of the issuer public key, so a client can notice a
	// rotation instead of silently failing to verify against a retired key.
	IssuerKeyID string `json:"issuer_key_id"`
	TokenType   int    `json:"token_type"`
}

// maxTokensPerRequest matches the spec's ceiling.
const maxTokensPerRequest = 20

// handleIssueTokens signs a batch of blinded messages.
//
// Nothing about the requester is recorded. The point of blind issuance is that
// this event cannot be correlated with the redemption that follows, and any
// log line naming the caller would defeat it just as surely as a broken
// signature would.
func (s *Server) handleIssueTokens(w http.ResponseWriter, r *http.Request) {
	if s.issuer == nil {
		// Self-hosted servers do not implement Privacy Pass; the user controls
		// which keys are registered, so anonymous rate limiting has no purpose.
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED",
			"This server does not issue tokens.")
		return
	}

	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid request body")
		return
	}
	if len(req.Blinded) == 0 {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "blinded is required")
		return
	}
	if len(req.Blinded) > maxTokensPerRequest {
		writeError(w, http.StatusBadRequest, "BATCH_TOO_LARGE",
			"Too many tokens requested in one batch.")
		return
	}

	// Charge the batch against the global issuance budget before signing any of
	// it. Unmetered issuance would make Privacy Pass ceremonial: the endpoint is
	// unauthenticated by design, so anyone could mint tokens without limit and
	// the rate limit those tokens exist to impose would cost nothing to bypass.
	//
	// 429 rather than 402: the API conventions reserve 402 for a token that was
	// presented and rejected, and the client maps the two to different retries.
	if s.issueLimit != nil {
		if ok, wait := s.issueLimit.allow(len(req.Blinded)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED",
				"Too many tokens requested. Try again shortly.")
			return
		}
	}

	sigs := make([]string, 0, len(req.Blinded))
	for _, b64 := range req.Blinded {
		blinded, err := base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "blinded message is not base64url")
			return
		}
		sig, err := s.issuer.BlindSign(blinded)
		if err != nil {
			// The message itself is not logged: it is the one value that could
			// later be correlated with a redemption.
			s.log.Error("blind sign failed", zap.Error(err))
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "blinded message could not be signed")
			return
		}
		sigs = append(sigs, base64.RawURLEncoding.EncodeToString(sig))
	}

	keyID := s.issuer.KeyID()
	writeJSON(w, http.StatusOK, issueResponse{
		BlindSignatures: sigs,
		IssuerKeyID:     base64.RawURLEncoding.EncodeToString(keyID[:]),
		TokenType:       int(privacypass.TokenType),
	})
}
