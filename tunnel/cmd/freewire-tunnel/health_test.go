package main

import "testing"

// The tunnel owns the whole address space while it is up, so giving up too
// eagerly drops a working VPN and giving up too late leaves the host with no
// network at all. Both directions are worth pinning down.

func TestHealthTallyGivesUpAfterLimit(t *testing.T) {
	h := healthTally{limit: 3}
	if h.record(false) || h.record(false) {
		t.Fatal("gave up before reaching the limit")
	}
	if !h.record(false) {
		t.Error("did not give up on the third consecutive failure")
	}
}

func TestHealthTallyIgnoresIsolatedFailures(t *testing.T) {
	h := healthTally{limit: 3}
	// A flaky link that keeps recovering must never trigger a teardown.
	for i := 0; i < 100; i++ {
		if h.record(false) {
			t.Fatalf("gave up on an isolated failure at iteration %d", i)
		}
		if h.record(true) {
			t.Fatal("record(true) reported give-up")
		}
	}
}

func TestHealthTallySuccessResetsTheRun(t *testing.T) {
	h := healthTally{limit: 3}
	h.record(false)
	h.record(false)
	h.record(true) // recovery clears the two failures above
	if h.record(false) || h.record(false) {
		t.Fatal("failures before the recovery still counted")
	}
	if !h.record(false) {
		t.Error("did not give up after a fresh run of three")
	}
}

func TestHealthTallyStaysGivenUp(t *testing.T) {
	h := healthTally{limit: 2}
	h.record(false)
	if !h.record(false) {
		t.Fatal("did not give up at the limit")
	}
	// Past the limit it must keep saying so rather than wrapping.
	if !h.record(false) {
		t.Error("stopped reporting give-up after the limit was passed")
	}
}
