package transport

import "testing"

// Regression: handleData derived a nonce from the packet's sequence number but
// never checked whether that sequence had already been used. A captured packet
// replayed to the server decrypted cleanly every time.
func TestReplayRejectsDuplicate(t *testing.T) {
	s := &icmpSrvSession{}
	if !s.checkReplay(1) {
		t.Fatal("first packet rejected")
	}
	if s.checkReplay(1) {
		t.Error("same sequence accepted twice")
	}
}

func TestReplayAcceptsAscending(t *testing.T) {
	s := &icmpSrvSession{}
	for seq := uint32(1); seq <= 1000; seq++ {
		if !s.checkReplay(seq) {
			t.Fatalf("in-order sequence %d rejected", seq)
		}
	}
}

func TestReplayAcceptsOutOfOrderInsideWindow(t *testing.T) {
	s := &icmpSrvSession{}
	if !s.checkReplay(100) {
		t.Fatal("sequence 100 rejected")
	}
	// Arriving late but within the window is normal on a lossy path.
	for _, seq := range []uint32{99, 98, 50, 37} {
		if !s.checkReplay(seq) {
			t.Errorf("in-window sequence %d rejected", seq)
		}
	}
	// Each of those is now spent.
	for _, seq := range []uint32{99, 98, 50, 37} {
		if s.checkReplay(seq) {
			t.Errorf("sequence %d accepted twice", seq)
		}
	}
}

func TestReplayRejectsBelowWindow(t *testing.T) {
	s := &icmpSrvSession{}
	if !s.checkReplay(200) {
		t.Fatal("sequence 200 rejected")
	}
	// 200-64 = 136 is the oldest provable sequence; anything at or below that
	// edge cannot be shown to be fresh.
	if s.checkReplay(136) {
		t.Error("sequence at the window edge accepted")
	}
	if s.checkReplay(10) {
		t.Error("far-below-window sequence accepted")
	}
}

func TestReplayLargeJumpClearsWindow(t *testing.T) {
	s := &icmpSrvSession{}
	for seq := uint32(1); seq <= 64; seq++ {
		s.checkReplay(seq)
	}
	// A jump past the window width invalidates everything behind it.
	if !s.checkReplay(10_000) {
		t.Fatal("large forward jump rejected")
	}
	if s.checkReplay(50) {
		t.Error("pre-jump sequence accepted after the window moved past it")
	}
	if s.checkReplay(10_000) {
		t.Error("the jump sequence itself was accepted twice")
	}
}

func TestReplayWindowBoundaryIsExact(t *testing.T) {
	s := &icmpSrvSession{}
	s.checkReplay(100)
	// Exactly 63 back is the last accepted offset; 64 back is not.
	if !s.checkReplay(100 - 63) {
		t.Error("offset 63 rejected, should be the last accepted slot")
	}
	if s.checkReplay(100 - 64) {
		t.Error("offset 64 accepted, should fall outside the window")
	}
}

// A burst of the same captured packet must yield exactly one acceptance.
func TestReplayFloodAcceptsOnce(t *testing.T) {
	s := &icmpSrvSession{}
	s.checkReplay(500)

	accepted := 0
	for i := 0; i < 10_000; i++ {
		if s.checkReplay(499) {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("replayed packet accepted %d times, want exactly 1", accepted)
	}
}
