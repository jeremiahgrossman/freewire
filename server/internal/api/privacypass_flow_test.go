package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"go.uber.org/zap"

	"github.com/freewire/server/internal/privacypass"
)

// Exercises the whole exchange over HTTP: a client blinds a nonce, the issuance
// endpoint signs it, the client unblinds, and the result is redeemed. The
// server never sees the nonce until redemption, which is the property the
// scheme exists for.
func issueOverHTTP(t *testing.T, s *Server, iss *privacypass.Issuer) *privacypass.Token {
	t.Helper()

	var nonce [privacypass.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	client, err := blindrsa.NewClient(blindrsa.SHA384PSSDeterministic, iss.PublicKey())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	blinded, state, err := client.Blind(rand.Reader, privacypass.TokenInput(nonce))
	if err != nil {
		t.Fatalf("blind: %v", err)
	}

	body, _ := json.Marshal(issueRequest{
		Blinded: []string{base64.RawURLEncoding.EncodeToString(blinded)},
	})
	rec := httptest.NewRecorder()
	s.handleIssueTokens(rec, httptest.NewRequest("POST", "/v1/tokens/issue", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("issuance returned %d: %s", rec.Code, rec.Body.String())
	}
	var resp issueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.BlindSignatures) != 1 {
		t.Fatalf("got %d signatures, want 1", len(resp.BlindSignatures))
	}

	blindSig, err := base64.RawURLEncoding.DecodeString(resp.BlindSignatures[0])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	sig, err := client.Finalize(state, blindSig)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return &privacypass.Token{Type: privacypass.TokenType, Nonce: nonce, Signature: sig}
}

func testServer(t *testing.T) (*Server, *privacypass.Issuer) {
	t.Helper()
	key, err := privacypass.GenerateIssuerKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	iss, err := privacypass.NewIssuer(key)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return &Server{
		issuer: iss,
		spent:  privacypass.NewSpentStore(privacypass.DefaultTokenTTL),
		log:    zap.NewNop(),
	}, iss
}

func redeem(s *Server, tok *privacypass.Token) (int, string) {
	r := httptest.NewRequest("POST", "/v1/peers", nil)
	if tok != nil {
		r.Header.Set("Authorization",
			"PrivateToken token="+base64.RawURLEncoding.EncodeToString(tok.Marshal()))
	}
	code, e := s.redeemToken(r)
	return code, e.code
}

func TestTokenIssuedOverHTTPIsRedeemable(t *testing.T) {
	s, iss := testServer(t)
	tok := issueOverHTTP(t, s, iss)
	if code, _ := redeem(s, tok); code != 0 {
		t.Errorf("a freshly issued token was refused with %d", code)
	}
}

// The spec is explicit that a spent token is 402 TOKEN_SPENT, not 401 or 429:
// the client maps those to different retry behaviour.
func TestSpentTokenIsRefusedWith402(t *testing.T) {
	s, iss := testServer(t)
	tok := issueOverHTTP(t, s, iss)

	if code, _ := redeem(s, tok); code != 0 {
		t.Fatal("first redemption refused")
	}
	code, errCode := redeem(s, tok)
	if code != http.StatusPaymentRequired {
		t.Errorf("reuse returned %d, want 402", code)
	}
	if errCode != "TOKEN_SPENT" {
		t.Errorf("reuse returned %q, want TOKEN_SPENT", errCode)
	}
}

func TestMissingTokenIsRefused(t *testing.T) {
	s, _ := testServer(t)
	code, errCode := redeem(s, nil)
	if code != http.StatusPaymentRequired || errCode != "TOKEN_INVALID" {
		t.Errorf("missing token returned %d/%s, want 402/TOKEN_INVALID", code, errCode)
	}
}

func TestForgedTokenIsRefused(t *testing.T) {
	s, iss := testServer(t)
	tok := issueOverHTTP(t, s, iss)
	tok.Signature[10] ^= 0xFF

	code, errCode := redeem(s, tok)
	if code != http.StatusPaymentRequired || errCode != "TOKEN_INVALID" {
		t.Errorf("forged token returned %d/%s, want 402/TOKEN_INVALID", code, errCode)
	}
}

// A token from a different issuer must not be redeemable here.
func TestAnotherIssuersTokenIsRefused(t *testing.T) {
	s, _ := testServer(t)
	other, otherIss := testServer(t)
	tok := issueOverHTTP(t, other, otherIss)

	code, errCode := redeem(s, tok)
	if code != http.StatusPaymentRequired || errCode != "TOKEN_INVALID" {
		t.Errorf("foreign token returned %d/%s, want 402/TOKEN_INVALID", code, errCode)
	}
}

func TestBatchCeilingIsEnforced(t *testing.T) {
	s, _ := testServer(t)
	body, _ := json.Marshal(issueRequest{Blinded: make([]string, maxTokensPerRequest+1)})
	rec := httptest.NewRecorder()
	s.handleIssueTokens(rec, httptest.NewRequest("POST", "/v1/tokens/issue", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized batch returned %d, want 400", rec.Code)
	}
}

// A self-hosted server has no issuer and must say so rather than pretending.
func TestSelfHostedServerReportsNotImplemented(t *testing.T) {
	s := &Server{log: zap.NewNop()}
	rec := httptest.NewRecorder()
	body, _ := json.Marshal(issueRequest{Blinded: []string{"x"}})
	s.handleIssueTokens(rec, httptest.NewRequest("POST", "/v1/tokens/issue", bytes.NewReader(body)))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("returned %d, want 501", rec.Code)
	}
}
