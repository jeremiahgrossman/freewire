package api

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"
)

// solve mirrors what the client does, at a difficulty low enough for a test.
func solve(t *testing.T, challenge string, difficulty uint8) string {
	t.Helper()
	for i := 0; i < 1<<24; i++ {
		nonce := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge + ":" + nonce))
		if leadingZeroBits(sum[:]) >= int(difficulty) {
			return nonce
		}
	}
	t.Fatalf("could not solve at difficulty %d", difficulty)
	return ""
}

func testPOW(t *testing.T) *proofOfWork {
	t.Helper()
	p, err := newProofOfWork()
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	p.difficulty = 8 // keep the test fast; the property under test is the same
	return p
}

func TestValidSolutionIsAccepted(t *testing.T) {
	p := testPOW(t)
	challenge, difficulty := p.Challenge()

	if err := p.Verify(challenge, solve(t, challenge, difficulty)); err != nil {
		t.Errorf("a correct solution was refused: %v", err)
	}
}

// The challenge is the same for everyone in a window, which is what lets it
// exist without a caller identity. That is only safe if a solution cannot be
// replayed.
func TestSolutionCannotBeReused(t *testing.T) {
	p := testPOW(t)
	challenge, difficulty := p.Challenge()
	nonce := solve(t, challenge, difficulty)

	if err := p.Verify(challenge, nonce); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if err := p.Verify(challenge, nonce); err == nil {
		t.Error("the same solution was accepted twice")
	}
}

func TestInsufficientWorkIsRefused(t *testing.T) {
	p := testPOW(t)
	p.difficulty = 24
	challenge, _ := p.Challenge()

	// A nonce solved at 8 bits will not meet 24 except by luck; retry a few
	// values so the test does not depend on one draw.
	for i := 0; i < 8; i++ {
		if err := p.Verify(challenge, strconv.Itoa(i)); err == nil {
			t.Fatal("a solution below the difficulty was accepted")
		}
	}
}

func TestForgedChallengeIsRefused(t *testing.T) {
	p := testPOW(t)
	// Not derived from the server secret, so it cannot be a challenge this
	// server issued.
	forged := "AAAAAAAAAAAAAAAAAAAAAA"
	if err := p.Verify(forged, solve(t, forged, 8)); err == nil {
		t.Error("a challenge the server never issued was accepted")
	}
}

// A client that fetched a challenge just before a window boundary must not be
// refused for being a moment late.
func TestPreviousWindowIsStillAccepted(t *testing.T) {
	now := time.Unix(0, 0)
	p := testPOW(t)
	p.nowFn = func() time.Time { return now }

	challenge, difficulty := p.Challenge()
	nonce := solve(t, challenge, difficulty)

	now = now.Add(p.window)
	if err := p.Verify(challenge, nonce); err != nil {
		t.Errorf("a solution from the previous window was refused: %v", err)
	}
}

func TestExpiredChallengeIsRefused(t *testing.T) {
	now := time.Unix(0, 0)
	p := testPOW(t)
	p.nowFn = func() time.Time { return now }

	challenge, difficulty := p.Challenge()
	nonce := solve(t, challenge, difficulty)

	now = now.Add(3 * p.window)
	if err := p.Verify(challenge, nonce); err == nil {
		t.Error("a solution from an expired window was accepted")
	}
}

func TestMalformedInputIsRefused(t *testing.T) {
	p := testPOW(t)
	challenge, _ := p.Challenge()

	for name, nonce := range map[string]string{
		"empty":      "",
		"whitespace": "abc def",
		"newline":    "abc\ndef",
		"oversize":   string(make([]byte, 65)),
	} {
		if err := p.Verify(challenge, nonce); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := p.Verify("", "abc"); err == nil {
		t.Error("empty challenge accepted")
	}
}

// The used-solution set must not grow without bound: it is reachable by anyone.
func TestUsedSetIsDroppedOnWindowTurnover(t *testing.T) {
	now := time.Unix(0, 0)
	p := testPOW(t)
	p.nowFn = func() time.Time { return now }

	challenge, difficulty := p.Challenge()
	p.Verify(challenge, solve(t, challenge, difficulty)) //nolint:errcheck
	if len(p.used) == 0 {
		t.Fatal("a spent solution was not recorded")
	}

	now = now.Add(p.window)
	fresh, d2 := p.Challenge()
	p.Verify(fresh, solve(t, fresh, d2)) //nolint:errcheck
	if len(p.used) != 1 {
		t.Errorf("used set holds %d entries after a window turned over, want 1", len(p.used))
	}
}

// A client that reconnects inside one window must still get a token.
//
// The challenge is constant within a window and each solution is spent once, so
// a client whose search is deterministic produces the same nonce every time and
// is refused from its second attempt onward. That made reconnecting within five
// minutes impossible against a token-issuing server. The property the server
// must uphold is that *distinct* solutions to the same challenge are all
// accepted; the client's job is to produce them.
func TestDistinctSolutionsToOneChallengeAreAllAccepted(t *testing.T) {
	p := testPOW(t)
	challenge, difficulty := p.Challenge()

	accepted := 0
	found := 0
	for i := 0; i < 1<<22 && found < 3; i++ {
		nonce := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(challenge + ":" + nonce))
		if leadingZeroBits(sum[:]) < int(difficulty) {
			continue
		}
		found++
		if err := p.Verify(challenge, nonce); err == nil {
			accepted++
		}
	}
	if found < 3 {
		t.Fatalf("only found %d solutions to search with", found)
	}
	if accepted != 3 {
		t.Errorf("%d of 3 distinct solutions accepted; a client reconnecting "+
			"within one window would be refused", accepted)
	}
}
