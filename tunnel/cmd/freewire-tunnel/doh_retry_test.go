package main

import (
	"os"
	"strings"
	"testing"
)

// dohStatus is the wire boundary the macOS app parses (DoHStatus.latestLeak in
// DoHStatus.swift). Pin the exact bytes: a drift here is a silent PRIVACY-1
// regression -- the warning would never show, or never clear -- because the app
// prefix-matches "doh down"/"doh up" on this same stdout channel as "ready".
func TestDoHStatusWireFormat(t *testing.T) {
	for _, tc := range []struct {
		up   bool
		want string
	}{
		{true, "doh up\n"},
		{false, "doh down\n"},
	} {
		got := captureStdout(t, func() { dohStatus(tc.up) })
		if got != tc.want {
			t.Errorf("dohStatus(%v) wrote %q, want %q", tc.up, got, tc.want)
		}
	}
}

// captureStdout redirects os.Stdout for the duration of f and returns what was
// written. dohStatus writes to os.Stdout (the channel the app reads), so the
// test has to swap the real one rather than inspect a buffer.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 256)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()

	f()
	w.Close()
	return <-done
}

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
