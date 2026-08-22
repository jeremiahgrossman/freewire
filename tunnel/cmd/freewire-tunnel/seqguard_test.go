package main

import "testing"

// The nonce is derived from the sequence number in both tunnel transports, so a
// counter that wraps repeats a (key, nonce) pair. For ChaCha20-Poly1305 that
// leaks the XOR of two plaintexts and forfeits authentication outright, which
// is why the ceiling refuses to send rather than continuing.
func TestSequenceCeilingLeavesRoomBeforeWrap(t *testing.T) {
	const wrap = 1 << 32
	if maxSessionSeq >= wrap {
		t.Fatalf("maxSessionSeq (%d) does not prevent a wrap at %d", uint64(maxSessionSeq), uint64(wrap))
	}
	// Half the space is a wide margin: the ceiling is reached, and the session
	// ends, long before any counter can come round again.
	if maxSessionSeq > wrap/2 {
		t.Errorf("maxSessionSeq (%d) leaves less than half the space in reserve", uint64(maxSessionSeq))
	}
	if maxSessionSeq < 1<<20 {
		t.Errorf("maxSessionSeq (%d) is low enough to end ordinary sessions", uint64(maxSessionSeq))
	}
}
