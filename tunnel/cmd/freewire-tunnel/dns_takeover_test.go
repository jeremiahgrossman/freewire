package main

import "testing"

// Regression coverage for a real incident: a force-killed freewire-tunnel run
// left a live machine's Wi-Fi and iPhone-hotspot DNS permanently pointed at
// the tunnel's loopback forwarder (127.0.0.1) with nothing listening there --
// total DNS failure on those services -- while Ethernet, never touched, kept
// working. No process was running and the marker file that should have let a
// later run auto-repair this was already gone, meaning an earlier restore had
// reported success while still leaving the override in place. Two gaps
// combined to cause it: restoreStaleDNS deleted the marker file even when a
// per-service restore silently failed, and setupDNS had no guard against
// re-capturing its own resolver as if it were a service's original.

func TestParseSavedDNSRoundTrip(t *testing.T) {
	entries := []dnsRestoreEntry{
		{Service: "Wi-Fi", Servers: "192.168.0.1 205.171.2.65"},
		{Service: "USB 10/100/1000 LAN", Servers: ""}, // DHCP, no static resolvers
	}
	roundTripped := parseSavedDNS(formatSavedDNS(entries))
	if len(roundTripped) != len(entries) {
		t.Fatalf("got %d entries, want %d: %+v", len(roundTripped), len(entries), roundTripped)
	}
	for i, e := range entries {
		if roundTripped[i] != e {
			t.Errorf("entry %d: got %+v, want %+v", i, roundTripped[i], e)
		}
	}
}

func TestParseSavedDNSSkipsMalformedLines(t *testing.T) {
	// A blank line, a line with no tab, and a line that is only whitespace
	// must all be skipped rather than producing a bogus entry -- this is
	// best-effort local state, not a format worth failing hard on.
	data := "Wi-Fi\t192.168.0.1\n\n   \nno-tab-here\niPhone USB\t\n"
	entries := parseSavedDNS(data)
	want := []dnsRestoreEntry{
		{Service: "Wi-Fi", Servers: "192.168.0.1"},
		{Service: "iPhone USB", Servers: ""},
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries %+v, want %d %+v", len(entries), entries, len(want), want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, entries[i], want[i])
		}
	}
}

func TestSetdnsArgsEmptyMeansDHCP(t *testing.T) {
	got := setdnsArgs("Wi-Fi", "")
	want := []string{"-setdnsservers", "Wi-Fi", "Empty"}
	if !equalStrings(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestSetdnsArgsSplitsRealServers(t *testing.T) {
	got := setdnsArgs("Wi-Fi", "192.168.0.1 205.171.2.65")
	want := []string{"-setdnsservers", "Wi-Fi", "192.168.0.1", "205.171.2.65"}
	if !equalStrings(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestDNSLooksLikeOursDetectsTunnelResolver(t *testing.T) {
	// This check is the direct fix for the incident: a service already
	// reading our own resolver must never be captured as "the original".
	if !dnsLooksLikeOurs("127.0.0.1") {
		t.Error("127.0.0.1 (the tunnel's own resolver) not detected as ours")
	}
	if dnsLooksLikeOurs("192.168.1.1") {
		t.Error("a real router resolver misidentified as ours")
	}
	if dnsLooksLikeOurs("") {
		t.Error("an empty (DHCP) reading misidentified as ours")
	}
}

func TestRestoreSucceededMatchesNormalizedValue(t *testing.T) {
	if !restoreSucceeded("192.168.0.1 205.171.2.65", "192.168.0.1  205.171.2.65\n") {
		t.Error("extra whitespace/newline in the reading should still count as a match")
	}
}

func TestRestoreSucceededTreatsThereArentAnyAsEmpty(t *testing.T) {
	if !restoreSucceeded("", "There aren't any DNS Servers set on Wi-Fi.\n") {
		t.Error("networksetup's \"nothing configured\" sentence should match a saved empty value")
	}
}

func TestRestoreSucceededRejectsMismatch(t *testing.T) {
	// Direct regression test for gap #1: a restore command can exit 0 while
	// the value did not actually take (the service was transiently gone from
	// networksetup's list). That must be caught here, not assumed from a nil
	// exec error.
	if restoreSucceeded("192.168.0.1", "127.0.0.1") {
		t.Error("a restore that left the service on 127.0.0.1 must not read as succeeded")
	}
}

func TestPlanDNSCaptureNormalPath(t *testing.T) {
	decision, value := planDNSCapture("192.168.0.1", nil)
	if decision != captureNormal || value != "192.168.0.1" {
		t.Errorf("got (%v, %q), want (captureNormal, \"192.168.0.1\")", decision, value)
	}
}

func TestPlanDNSCaptureSkipsPoisonedWithNoFallback(t *testing.T) {
	// Regression test for gap #2's worst case: no recoverable value anywhere.
	// Must not save 127.0.0.1 as if it were real.
	decision, _ := planDNSCapture("127.0.0.1", nil)
	if decision != captureSkipPoisoned {
		t.Errorf("got %v, want captureSkipPoisoned", decision)
	}
}

func TestPlanDNSCaptureRepairsFromMarkerWhenPoisoned(t *testing.T) {
	// Direct regression test for the entrenchment bug: current reads
	// poisoned, but the marker file still has the real original -- that must
	// win, not the poisoned live reading.
	marker := &dnsRestoreEntry{Service: "Wi-Fi", Servers: "8.8.8.8"}
	decision, value := planDNSCapture("127.0.0.1", marker)
	if decision != captureRepairFromMarker || value != "8.8.8.8" {
		t.Errorf("got (%v, %q), want (captureRepairFromMarker, \"8.8.8.8\")", decision, value)
	}
}

func TestPlanDNSCaptureIgnoresPoisonedMarkerEntry(t *testing.T) {
	// Defensive: if the marker itself also holds our own resolver (a double
	// failure), it must not be reused -- that would just re-save the same
	// corruption under a different name instead of refusing to guess.
	marker := &dnsRestoreEntry{Service: "Wi-Fi", Servers: "127.0.0.1"}
	decision, _ := planDNSCapture("127.0.0.1", marker)
	if decision != captureSkipPoisoned {
		t.Errorf("got %v, want captureSkipPoisoned (a poisoned marker entry must not be trusted)", decision)
	}
}

func TestFormatSavedDNSOmitsFullyRestoredEntries(t *testing.T) {
	// Regression test for gap #1: restoreStaleDNS must shrink the marker file
	// to only what is still owed, never delete it out from under an entry
	// that did not actually restore.
	stillOwed := []dnsRestoreEntry{{Service: "iPhone USB", Servers: "192.168.1.1"}}
	got := parseSavedDNS(formatSavedDNS(stillOwed))
	if len(got) != 1 || got[0] != stillOwed[0] {
		t.Errorf("got %+v, want exactly %+v", got, stillOwed)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
