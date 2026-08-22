package privacypass

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
	"time"
)

func issuedToken(t *testing.T, iss *Issuer, expiry uint32) *Token {
	t.Helper()
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	client, err := blindrsa.NewClient(variant, iss.PublicKey())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	blinded, state, err := client.Blind(rand.Reader, TokenInput(expiry, nonce))
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	blindSig, err := iss.BlindSign(blinded)
	if err != nil {
		t.Fatalf("blind sign: %v", err)
	}
	sig, err := client.Finalize(state, blindSig)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	return &Token{Type: TokenType, ExpiryDay: expiry, Nonce: nonce, Signature: sig}
}

// The defect this closes: a token was good forever while its spent record was
// dropped after thirty days, so anyone holding one past that window could
// replay it indefinitely.
func TestExpiredTokenIsRefused(t *testing.T) {
	iss := newIssuer(t)
	now := time.Now()
	tok := issuedToken(t, iss, ExpiryForIssuance(now))

	// One day past its life. The spent store has long since forgotten it.
	later := now.Add((TokenValidityDays + 1) * 24 * time.Hour)
	if err := iss.VerifyAt(tok, later); err == nil {
		t.Error("a token past its expiry was accepted; it would be replayable forever")
	}
}

func TestTokenIsValidInsideItsWindow(t *testing.T) {
	iss := newIssuer(t)
	now := time.Now()
	tok := issuedToken(t, iss, ExpiryForIssuance(now))

	for _, age := range []time.Duration{0, 24 * time.Hour, (TokenValidityDays - 1) * 24 * time.Hour} {
		if err := iss.VerifyAt(tok, now.Add(age)); err != nil {
			t.Errorf("token refused %v after issuance: %v", age, err)
		}
	}
}

// The issuer signs blindly and never sees the expiry, so a client can write
// whatever it likes. The only place that can be judged is redemption, and if it
// is not judged there the field is decorative.
func TestOverDatedTokenIsRefused(t *testing.T) {
	iss := newIssuer(t)
	now := time.Now()
	greedy := ExpiryForIssuance(now) + 3650 // ten years
	tok := issuedToken(t, iss, greedy)

	if err := iss.VerifyAt(tok, now); err == nil {
		t.Error("a token dated ten years out was accepted; the expiry bound is not enforced")
	}
}

// The expiry is inside the signed message, so re-dating a token invalidates it.
// Outside the signature the field could simply be rewritten by whoever held it.
func TestExpiryCannotBeEditedAfterIssuance(t *testing.T) {
	iss := newIssuer(t)
	now := time.Now()
	tok := issuedToken(t, iss, ExpiryForIssuance(now))

	tok.ExpiryDay += 10
	if err := iss.VerifyAt(tok, now); err == nil {
		t.Error("a re-dated token still verified; the expiry is not covered by the signature")
	}
}

// A finer timestamp would partition tokens into cohorts by expiry, and a cohort
// small enough to identify a device undoes the blinding. Every token issued
// anywhere on a given day must carry the same value.
func TestExpiryIsIdenticalForEveryTokenIssuedToday(t *testing.T) {
	base := time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC)
	want := ExpiryForIssuance(base)
	for _, offset := range []time.Duration{
		time.Second, time.Hour, 7 * time.Hour, 23*time.Hour + 59*time.Minute,
	} {
		if got := ExpiryForIssuance(base.Add(offset)); got != want {
			t.Errorf("expiry differs by %v within the same UTC day (%d vs %d); "+
				"that partitions tokens into identifiable cohorts", offset, got, want)
		}
	}
}

// Token validity must not exceed how long the spent store remembers, or a token
// could outlive the record that stops it being replayed -- which is the defect
// this whole field exists to close.
func TestValidityFitsInsideSpentRetention(t *testing.T) {
	validity := TokenValidityDays * 24 * time.Hour
	if validity > DefaultTokenTTL {
		t.Errorf("tokens live %v but spent records are kept %v; a token can outlive its record",
			validity, DefaultTokenTTL)
	}
}
