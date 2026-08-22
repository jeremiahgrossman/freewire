package privacypass

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// issueToken performs the client half of the exchange so the round trip can be
// exercised end to end. The blinding and unblinding happen here, exactly as
// they would on a device; the issuer never sees the nonce.
func issueToken(t *testing.T, iss *Issuer) *Token {
	t.Helper()

	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	client, err := blindrsa.NewClient(variant, iss.PublicKey())
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	blinded, state, err := client.Blind(rand.Reader, TokenInput(nonce))
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
	return &Token{Type: TokenType, Nonce: nonce, Signature: sig}
}

func newIssuer(t *testing.T) *Issuer {
	t.Helper()
	key, err := GenerateIssuerKey()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	iss, err := NewIssuer(key)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss
}

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	iss := newIssuer(t)
	tok := issueToken(t, iss)
	if err := iss.Verify(tok); err != nil {
		t.Errorf("a freshly issued token failed verification: %v", err)
	}
}

// The whole construction rests on the issuer being unable to recognise the
// token it signed. If a blinded message ever equalled the token input, the
// scheme would be pointless.
func TestBlindedMessageDoesNotRevealTheToken(t *testing.T) {
	iss := newIssuer(t)
	var nonce [NonceSize]byte
	rand.Read(nonce[:]) //nolint:errcheck

	client, _ := blindrsa.NewClient(variant, iss.PublicKey())
	blinded, _, err := client.Blind(rand.Reader, TokenInput(nonce))
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	for i := 0; i+NonceSize <= len(blinded); i++ {
		if string(blinded[i:i+NonceSize]) == string(nonce[:]) {
			t.Fatal("the nonce appears verbatim in the blinded message")
		}
	}
}

func TestVerifyRejectsATamperedNonce(t *testing.T) {
	iss := newIssuer(t)
	tok := issueToken(t, iss)
	tok.Nonce[0] ^= 0xFF
	if err := iss.Verify(tok); err == nil {
		t.Error("accepted a token whose nonce was altered")
	}
}

func TestVerifyRejectsATamperedSignature(t *testing.T) {
	iss := newIssuer(t)
	tok := issueToken(t, iss)
	tok.Signature[0] ^= 0xFF
	if err := iss.Verify(tok); err == nil {
		t.Error("accepted a token whose signature was altered")
	}
}

// A token is only worth anything against the issuer that signed it.
func TestVerifyRejectsAnotherIssuersToken(t *testing.T) {
	a, b := newIssuer(t), newIssuer(t)
	tok := issueToken(t, a)
	if err := b.Verify(tok); err == nil {
		t.Error("one issuer accepted a token signed by another")
	}
}

func TestTokenWireFormatRoundTrips(t *testing.T) {
	iss := newIssuer(t)
	tok := issueToken(t, iss)

	raw := tok.Marshal()
	if len(raw) != TokenSize {
		t.Fatalf("marshalled to %d bytes, want %d", len(raw), TokenSize)
	}
	back, err := ParseToken(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.Nonce != tok.Nonce {
		t.Error("nonce did not survive the round trip")
	}
	if err := iss.Verify(back); err != nil {
		t.Errorf("a parsed token failed verification: %v", err)
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":     {},
		"too short": make([]byte, TokenSize-1),
		"too long":  make([]byte, TokenSize+1),
	} {
		if _, err := ParseToken(raw); err == nil {
			t.Errorf("%s: accepted a malformed token", name)
		}
	}
	// A valid length carrying an unsupported type must still be refused.
	wrongType := make([]byte, TokenSize)
	wrongType[1] = 0x02
	if _, err := ParseToken(wrongType); err == nil {
		t.Error("accepted an unsupported token type")
	}
}

// MARK: - Spent store

func TestRedeemAcceptsOnce(t *testing.T) {
	s := NewSpentStore(time.Hour)
	var h [32]byte
	h[0] = 1

	if !s.Redeem(h) {
		t.Fatal("first redemption rejected")
	}
	if s.Redeem(h) {
		t.Error("the same token was redeemed twice")
	}
}

// Two requests arriving together must not both see the token as unspent.
func TestConcurrentRedeemAcceptsExactlyOne(t *testing.T) {
	s := NewSpentStore(time.Hour)
	var h [32]byte
	h[0] = 7

	const racers = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0

	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			if s.Redeem(h) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Errorf("%d concurrent redemptions succeeded, want exactly 1", accepted)
	}
}

func TestExpiredTokenSlotIsReusable(t *testing.T) {
	s := NewSpentStore(time.Hour)
	now := time.Now()
	s.nowFn = func() time.Time { return now }

	var h [32]byte
	h[0] = 9
	if !s.Redeem(h) {
		t.Fatal("first redemption rejected")
	}

	// Past the validity window the token could not be used anyway.
	now = now.Add(2 * time.Hour)
	if !s.Redeem(h) {
		t.Error("a slot past its validity window was not reusable")
	}
}

func TestExpireDropsOldEntries(t *testing.T) {
	s := NewSpentStore(time.Hour)
	now := time.Now()
	s.nowFn = func() time.Time { return now }

	for i := 0; i < 50; i++ {
		var h [32]byte
		h[0] = byte(i)
		s.Redeem(h)
	}
	if s.Len() != 50 {
		t.Fatalf("recorded %d redemptions, want 50", s.Len())
	}

	now = now.Add(2 * time.Hour)
	if removed := s.Expire(); removed != 50 {
		t.Errorf("expired %d entries, want 50", removed)
	}
	if s.Len() != 0 {
		t.Errorf("%d entries remain after expiry", s.Len())
	}
}

func TestExpireKeepsLiveEntries(t *testing.T) {
	s := NewSpentStore(time.Hour)
	now := time.Now()
	s.nowFn = func() time.Time { return now }

	var old, fresh [32]byte
	old[0], fresh[0] = 1, 2
	s.Redeem(old)

	now = now.Add(90 * time.Minute)
	s.Redeem(fresh)

	s.Expire()
	if s.Len() != 1 {
		t.Errorf("%d entries remain, want only the fresh one", s.Len())
	}
	if s.Redeem(fresh) {
		t.Error("the fresh entry was expired")
	}
}

// A rotation must be detectable, or a client silently fails verification
// against a key that is no longer in use.
func TestKeyIDChangesWithTheKey(t *testing.T) {
	a, b := newIssuer(t), newIssuer(t)
	if a.KeyID() == b.KeyID() {
		t.Error("two different issuer keys produced the same key id")
	}
	if a.KeyID() != a.KeyID() {
		t.Error("key id is not stable for the same key")
	}
}

func TestNewIssuerRejectsUndersizedKeys(t *testing.T) {
	if _, err := NewIssuer(nil); err == nil {
		t.Error("accepted a nil key")
	}
}
