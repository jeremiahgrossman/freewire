package privacypass

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func randHash(t *testing.T) [32]byte {
	t.Helper()
	var h [32]byte
	if _, err := rand.Read(h[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return h
}

// The guarantee the store provides is "this nonce has been seen before". A
// process that forgets on every deploy provides it only between deploys, and an
// attacker who waits for a restart replays every token they hold.
func TestSpentTokensSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent")

	s, err := NewPersistentSpentStore(time.Hour, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	h := randHash(t)
	if !s.Redeem(h) {
		t.Fatal("a fresh token was refused")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := NewPersistentSpentStore(time.Hour, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close() //nolint:errcheck
	if reopened.Redeem(h) {
		t.Error("a token spent before the restart was redeemable after it")
	}
}

func TestRefundMakesATokenSpendableAgain(t *testing.T) {
	s := NewSpentStore(time.Hour)
	h := randHash(t)

	if !s.Redeem(h) {
		t.Fatal("a fresh token was refused")
	}
	if s.Redeem(h) {
		t.Fatal("a spent token was accepted twice")
	}
	// A registration that fails after the spend must not cost the user a token.
	s.Refund(h)
	if !s.Redeem(h) {
		t.Error("a refunded token was still treated as spent")
	}
}

func TestRefundDoesNotResurrectAnOlderGeneration(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewSpentStore(time.Hour)
	s.nowFn = func() time.Time { return now }
	s.rotated = now // NewSpentStore stamped this from the real clock

	h := randHash(t)
	s.Redeem(h) //nolint:errcheck
	now = now.Add(2 * time.Hour)
	s.Expire()

	// h now lives in the previous generation. Refunding must not reach it: that
	// spend belongs to a request that completed long ago.
	s.Refund(h)
	if s.Redeem(h) {
		t.Error("a refund un-spent a token from an earlier window")
	}
}

func TestRotationDropsTheOldestGenerationFromDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent")
	now := time.Unix(0, 0)

	s, err := NewPersistentSpentStore(time.Hour, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.nowFn = func() time.Time { return now }
	s.rotated = now // NewSpentStore stamped this from the real clock

	old := randHash(t)
	s.Redeem(old) //nolint:errcheck

	// Two rotations move `old` out of both generations.
	now = now.Add(2 * time.Hour)
	s.Expire()
	now = now.Add(2 * time.Hour)
	s.Expire()
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat: %v", err)
	} else if info.Size() != 0 {
		t.Errorf("journal is %d bytes after both generations aged out, want 0", info.Size())
	}
}

// A corrupt byte must not become an outage: skipping one line loses one nonce's
// protection, while refusing to start loses all of them.
func TestCorruptJournalLinesAreSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spent")
	good := randHash(t)

	s, err := NewPersistentSpentStore(time.Hour, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	s.Redeem(good) //nolint:errcheck
	s.Close()      //nolint:errcheck

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	f.WriteString("garbage\nc not-base64!!\nx \n") //nolint:errcheck
	f.Close()                                      //nolint:errcheck

	reopened, err := NewPersistentSpentStore(time.Hour, path)
	if err != nil {
		t.Fatalf("reopen refused to start on a corrupt journal: %v", err)
	}
	defer reopened.Close() //nolint:errcheck
	if reopened.Redeem(good) {
		t.Error("the valid record was lost along with the corrupt ones")
	}
}
