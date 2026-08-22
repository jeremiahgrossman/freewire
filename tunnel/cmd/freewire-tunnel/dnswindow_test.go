package main

import "testing"

// The window was a fixed 8 because nothing ever adjusted it, while the file
// header promised "initial 8, AIMD, max 64" and dnsWindowMax sat unused. On a
// live tunnel that dropped 2450 of 3139 packets for a full window.
func TestWindowGrowsOnSuccess(t *testing.T) {
	w := &dnsWindow{}
	w.limit.Store(int64(dnsWindowInit))

	// Growth is credited per full window of successes, not per packet, so it
	// takes a while by design. Well short of what a busy tunnel produces.
	for i := 0; i < 4000; i++ {
		w.increase()
	}
	if got := w.limit.Load(); got <= int64(dnsWindowInit) {
		t.Errorf("window still %d after sustained success; it never grows", got)
	}
	if got := w.limit.Load(); got > int64(dnsWindowMax) {
		t.Errorf("window grew to %d, past the %d ceiling", got, dnsWindowMax)
	}
}

func TestWindowHalvesOnFailure(t *testing.T) {
	w := &dnsWindow{}
	w.limit.Store(32)

	w.decrease()
	if got := w.limit.Load(); got != 16 {
		t.Errorf("window = %d after one failure, want 16", got)
	}
}

// Decrease must not fall below the initial window, or one bad patch of network
// leaves the tunnel permanently unable to recover.
func TestWindowNeverFallsBelowInitial(t *testing.T) {
	w := &dnsWindow{}
	w.limit.Store(int64(dnsWindowInit))

	for i := 0; i < 20; i++ {
		w.decrease()
	}
	if got := w.limit.Load(); got != int64(dnsWindowInit) {
		t.Errorf("window = %d after repeated failure, want the %d floor", got, dnsWindowInit)
	}
}

// acquire must admit exactly the window and refuse past it, or the bound is
// decorative.
func TestWindowBoundsInFlight(t *testing.T) {
	w := &dnsWindow{}
	w.limit.Store(3)

	for i := 0; i < 3; i++ {
		if !w.acquire() {
			t.Fatalf("acquire %d refused inside the window", i+1)
		}
	}
	if w.acquire() {
		t.Error("acquire admitted a fourth query past a window of 3")
	}
	w.release()
	if !w.acquire() {
		t.Error("a released slot was not reusable")
	}
}
