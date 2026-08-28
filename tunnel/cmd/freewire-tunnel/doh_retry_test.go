package main

import "testing"

// Once teardown has latched dohTornDown, a PRIVACY-1 recovery attempt must not
// re-take over DNS: it returns (stop retrying) and touches nothing. This is the
// race guard that keeps a 60s retry firing during teardown from pointing the
// system resolver at a forwarder that is about to disappear. It also lets the
// test exercise tryDoHRecovery without root (the real path runs scutil).
func TestDoHRecoveryStopsAfterTeardown(t *testing.T) {
	dohMu.Lock()
	dohActive = nil
	dohTornDown = true
	dohMu.Unlock()
	t.Cleanup(func() {
		dohMu.Lock()
		dohTornDown = false
		dohActive = nil
		dohMu.Unlock()
	})

	if !tryDoHRecovery(defaultDoHEndpoints) {
		t.Fatal("recovery should report done (true) once torn down, to stop the retry loop")
	}
	dohMu.Lock()
	defer dohMu.Unlock()
	if dohActive != nil {
		t.Fatal("recovery must not start a forwarder after teardown")
	}
}
