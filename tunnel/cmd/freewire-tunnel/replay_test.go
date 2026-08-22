package main

import "testing"

func TestReplayWindowFreshThenReject(t *testing.T) {
	var w replayWindow
	if !w.check(0) {
		t.Fatal("first packet (seq 0) must be accepted")
	}
	w.commit(0)
	if w.check(0) {
		t.Error("seq 0 accepted a second time -- replay not caught")
	}
}

func TestReplayWindowInOrder(t *testing.T) {
	var w replayWindow
	for seq := uint32(0); seq < 200; seq++ {
		if !w.check(seq) {
			t.Fatalf("in-order seq %d rejected", seq)
		}
		w.commit(seq)
		if w.check(seq) {
			t.Fatalf("seq %d accepted twice", seq)
		}
	}
}

func TestReplayWindowOutOfOrderWithinWindow(t *testing.T) {
	var w replayWindow
	// Accept 10, then a reordered 5 within the window, then reject both replays.
	w.commit(10)
	if !w.check(5) {
		t.Fatal("reordered seq 5 within the window must be accepted")
	}
	w.commit(5)
	if w.check(5) || w.check(10) {
		t.Error("a committed seq inside the window was accepted again")
	}
}

func TestReplayWindowTooOldRejected(t *testing.T) {
	var w replayWindow
	w.commit(1000)
	if w.check(1000 - replayWindowSize) {
		t.Error("a seq older than the window must be rejected, not replayable")
	}
	if !w.check(1000 - replayWindowSize + 1) {
		t.Error("a seq at the trailing edge of the window should still be acceptable")
	}
}

// A forged packet carrying a huge seq must not advance the window on a failed
// authentication: the caller commits only after Open succeeds. This asserts the
// window itself does not move on a bare check.
func TestReplayWindowCheckDoesNotAdvance(t *testing.T) {
	var w replayWindow
	w.commit(5)
	_ = w.check(0xFFFFFFFF) // an attacker's forged seq; never committed
	if !w.check(6) {
		t.Error("a real packet was locked out -- check() advanced the window")
	}
}
