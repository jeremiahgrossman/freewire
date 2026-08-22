package transport

import "testing"

// Regression: handleData derived a nonce from the packet's sequence number but
// never checked whether that sequence had already been used. A captured packet
// replayed to the server decrypted cleanly every time.
func TestReplayRejectsDuplicate(t *testing.T) {
	var s replayWindow
	if !s.accept(1) {
		t.Fatal("first packet rejected")
	}
	if s.accept(1) {
		t.Error("same sequence accepted twice")
	}
}

func TestReplayAcceptsAscending(t *testing.T) {
	var s replayWindow
	for seq := uint32(1); seq <= 1000; seq++ {
		if !s.accept(seq) {
			t.Fatalf("in-order sequence %d rejected", seq)
		}
	}
}

func TestReplayAcceptsOutOfOrderInsideWindow(t *testing.T) {
	var s replayWindow
	if !s.accept(100) {
		t.Fatal("sequence 100 rejected")
	}
	// Arriving late but within the window is normal on a lossy path.
	for _, seq := range []uint32{99, 98, 50, 37} {
		if !s.accept(seq) {
			t.Errorf("in-window sequence %d rejected", seq)
		}
	}
	// Each of those is now spent.
	for _, seq := range []uint32{99, 98, 50, 37} {
		if s.accept(seq) {
			t.Errorf("sequence %d accepted twice", seq)
		}
	}
}

func TestReplayRejectsBelowWindow(t *testing.T) {
	var s replayWindow
	if !s.accept(200) {
		t.Fatal("sequence 200 rejected")
	}
	// 200-64 = 136 is the oldest provable sequence; anything at or below that
	// edge cannot be shown to be fresh.
	if s.accept(136) {
		t.Error("sequence at the window edge accepted")
	}
	if s.accept(10) {
		t.Error("far-below-window sequence accepted")
	}
}

func TestReplayLargeJumpClearsWindow(t *testing.T) {
	var s replayWindow
	for seq := uint32(1); seq <= 64; seq++ {
		s.accept(seq)
	}
	// A jump past the window width invalidates everything behind it.
	if !s.accept(10_000) {
		t.Fatal("large forward jump rejected")
	}
	if s.accept(50) {
		t.Error("pre-jump sequence accepted after the window moved past it")
	}
	if s.accept(10_000) {
		t.Error("the jump sequence itself was accepted twice")
	}
}

func TestReplayWindowBoundaryIsExact(t *testing.T) {
	var s replayWindow
	s.accept(100)
	// Exactly 63 back is the last accepted offset; 64 back is not.
	if !s.accept(100 - 63) {
		t.Error("offset 63 rejected, should be the last accepted slot")
	}
	if s.accept(100 - 64) {
		t.Error("offset 64 accepted, should fall outside the window")
	}
}

// A burst of the same captured packet must yield exactly one acceptance.
func TestReplayFloodAcceptsOnce(t *testing.T) {
	var s replayWindow
	s.accept(500)

	accepted := 0
	for i := 0; i < 10_000; i++ {
		if s.accept(499) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("replayed packet accepted %d times, want exactly 1", accepted)
	}
}

// The window used to be advanced by packets that had not been authenticated.
// The sequence number is attacker-visible on both transports -- on the DNS path
// it rides in the query name in cleartext -- so a single forged packet carrying
// a maximal sequence pushed `highest` to the ceiling and every real packet
// afterwards fell outside the window. The session stayed dead until eviction,
// and the attacker needed no key material at all.
func TestForgedSequenceCannotWedgeASession(t *testing.T) {
	var w replayWindow

	// A live session partway through its stream.
	for seq := uint32(1); seq <= 100; seq++ {
		if !w.accept(seq) {
			t.Fatalf("legitimate sequence %d rejected", seq)
		}
	}

	// A forged packet arrives claiming the largest possible sequence. It is
	// checked, fails authentication, and must therefore never be committed.
	const forged = ^uint32(0)
	if !w.check(forged) {
		t.Fatal("test assumption wrong: the forged sequence would not have been accepted")
	}
	// ...no commit, because the AEAD tag did not verify.

	// The real stream must continue undisturbed.
	for seq := uint32(101); seq <= 200; seq++ {
		if !w.accept(seq) {
			t.Fatalf("sequence %d rejected after a forged packet was rejected", seq)
		}
	}
}

// check must not mutate: calling it repeatedly cannot consume a sequence.
func TestCheckDoesNotConsume(t *testing.T) {
	var w replayWindow
	w.accept(10)

	for i := 0; i < 100; i++ {
		if !w.check(11) {
			t.Fatalf("check(11) returned false on call %d; it mutated state", i)
		}
	}
	if !w.accept(11) {
		t.Error("11 was consumed by check and could no longer be accepted")
	}
	if w.accept(11) {
		t.Error("11 was accepted twice after commit")
	}
}

func TestCommitAfterCheckIsIdempotentlySafe(t *testing.T) {
	var w replayWindow
	if !w.check(5) {
		t.Fatal("check(5) rejected on an empty window")
	}
	w.commit(5)
	if w.check(5) {
		t.Error("5 still passes check after being committed")
	}
}
