package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	exp := privacypass.ExpiryForIssuance(time.Now())
	blinded, state, err := client.Blind(rand.Reader, privacypass.TokenInput(exp, nonce))
	if err != nil {
		t.Fatalf("blind: %v", err)
	}

	challenge, difficulty := s.pow.Challenge()
	body, _ := json.Marshal(issueRequest{
		Blinded:   []string{base64.RawURLEncoding.EncodeToString(blinded)},
		Challenge: challenge,
		Nonce:     solve(t, challenge, difficulty),
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
	return &privacypass.Token{Type: privacypass.TokenType, ExpiryDay: exp, Nonce: nonce, Signature: sig}
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
	// Wired the way NewServer wires it, so the test exercises issuance as it is
	// actually configured. Difficulty is lowered because the property under
	// test is that the proof is required and checked, not how long it takes.
	pow, err := newProofOfWork()
	if err != nil {
		t.Fatalf("proof of work: %v", err)
	}
	pow.difficulty = 8

	return &Server{
		issuer:     iss,
		spent:      privacypass.NewSpentStore(privacypass.DefaultTokenTTL),
		issueLimit: newTokenBucket(issueBurst, issuePerSec),
		pow:        pow,
		log:        zap.NewNop(),
	}, iss
}

func redeem(s *Server, tok *privacypass.Token) (int, string) {
	r := httptest.NewRequest("POST", "/v1/peers", nil)
	if tok != nil {
		r.Header.Set("Authorization",
			"PrivateToken token="+base64.RawURLEncoding.EncodeToString(tok.Marshal()))
	}
	_, code, e := s.redeemToken(r)
	return code, e.code
}

func TestTokenIssuedOverHTTPIsRedeemable(t *testing.T) {
	s, iss := testServer(t)
	tok := issueOverHTTP(t, s, iss)
	if code, _ := redeem(s, tok); code != 0 {
		t.Errorf("a freshly issued token was refused with %d", code)
	}
}

// The macOS client sends the token UNQUOTED (Authorization: PrivateToken
// token=<b64>), which `redeem` above exercises. RFC 9577 also permits the QUOTED
// form (token="<b64>"), and the parser strips one surrounding quote pair to accept
// it. Nothing tested that path, so a refactor could drop the quote-strip and
// silently break a spec-following client. This pins it: a valid token in the
// quoted form must redeem exactly like the unquoted one.
func TestQuotedTokenFormIsAccepted(t *testing.T) {
	s, iss := testServer(t)
	tok := issueOverHTTP(t, s, iss)

	r := httptest.NewRequest("POST", "/v1/peers", nil)
	r.Header.Set("Authorization",
		`PrivateToken token="`+base64.RawURLEncoding.EncodeToString(tok.Marshal())+`"`)
	_, code, e := s.redeemToken(r)
	if code != 0 {
		t.Errorf("quoted-form token refused with %d (%s); the parser's quote-strip is broken", code, e.code)
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

// Issuance without a proof of work must be refused, or the global budget is
// again the only thing standing between one caller and everyone else's tokens.
func TestIssuanceWithoutProofOfWorkIsRefused(t *testing.T) {
	s, _ := testServer(t)
	body, _ := json.Marshal(issueRequest{Blinded: []string{"x"}})
	rec := httptest.NewRecorder()
	s.handleIssueTokens(rec, httptest.NewRequest("POST", "/v1/tokens/issue", bytes.NewReader(body)))

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("unpaid issuance returned %d, want 429", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("PROOF_OF_WORK_REQUIRED")) {
		t.Errorf("body %q does not name the reason", rec.Body.String())
	}
}

// A solution is single-use, so a batch cannot be replayed for free tokens.
func TestIssuanceRefusesAReplayedProof(t *testing.T) {
	s, _ := testServer(t)

	challenge, difficulty := s.pow.Challenge()
	nonce := solve(t, challenge, difficulty)
	send := func() int {
		body, _ := json.Marshal(issueRequest{
			Blinded:   []string{"x"},
			Challenge: challenge,
			Nonce:     nonce,
		})
		rec := httptest.NewRecorder()
		s.handleIssueTokens(rec, httptest.NewRequest("POST", "/v1/tokens/issue", bytes.NewReader(body)))
		return rec.Code
	}
	// The first call gets past the proof and fails on the unparseable blinded
	// message, which is enough to show the proof was accepted and spent.
	if code := send(); code != http.StatusBadRequest {
		t.Fatalf("first use returned %d, want 400 (proof accepted, payload rejected)", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Errorf("replayed proof returned %d, want 429", code)
	}
}
