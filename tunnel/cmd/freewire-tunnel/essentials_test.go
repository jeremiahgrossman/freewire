package main

import (
	"testing"
)

func TestEssentialsAllowlistInactiveWhenUnset(t *testing.T) {
	t.Setenv(essentialsEnv, "")
	if nets, active := essentialsAllowlist(); active || nets != nil {
		t.Fatalf("empty env must be inactive, got active=%v nets=%v", active, nets)
	}
}

func TestEssentialsAllowlistSeed(t *testing.T) {
	for _, v := range []string{"1", "default", "on"} {
		t.Setenv(essentialsEnv, v)
		nets, active := essentialsAllowlist()
		if !active {
			t.Fatalf("%q should activate essentials mode", v)
		}
		if got := essentialsCIDRs(nets); len(got) != 1 || got[0] != "17.0.0.0/8" {
			t.Fatalf("%q seed = %v, want [17.0.0.0/8]", v, got)
		}
	}
}

func TestEssentialsAllowlistExplicitCIDRsAndBareIP(t *testing.T) {
	// A bare IP is accepted as a /32; whitespace is trimmed.
	t.Setenv(essentialsEnv, "17.0.0.0/8, 203.0.113.9 ,198.51.100.0/24")
	nets, active := essentialsAllowlist()
	if !active {
		t.Fatal("explicit list should be active")
	}
	got := essentialsCIDRs(nets)
	want := []string{"17.0.0.0/8", "203.0.113.9/32", "198.51.100.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestEssentialsAllowlistSkipsInvalidButKeepsValid(t *testing.T) {
	t.Setenv(essentialsEnv, "17.0.0.0/8,not-an-ip,999.1.2.3/8")
	nets, active := essentialsAllowlist()
	if !active {
		t.Fatal("one valid entry should still activate")
	}
	if got := essentialsCIDRs(nets); len(got) != 1 || got[0] != "17.0.0.0/8" {
		t.Fatalf("invalid entries should be dropped, got %v", got)
	}
}

// If NOTHING parses, the mode must be INACTIVE (fail safe to full tunnel) rather
// than active with an empty allowlist, which would tunnel nothing at all.
func TestEssentialsAllowlistAllInvalidIsInactive(t *testing.T) {
	t.Setenv(essentialsEnv, "not-an-ip, also-bad")
	if nets, active := essentialsAllowlist(); active || nets != nil {
		t.Fatalf("all-invalid must be inactive (fail safe to full tunnel), got active=%v nets=%v", active, nets)
	}
}

func TestEssentialsProbeTarget(t *testing.T) {
	t.Setenv(essentialsEnv, "17.0.0.0/8,203.0.113.9")
	nets, _ := essentialsAllowlist()
	if got := essentialsProbeTarget(nets); got != "17.0.0.0" {
		t.Fatalf("probe target = %q, want 17.0.0.0 (network addr of the first prefix)", got)
	}
	if got := essentialsProbeTarget(nil); got != "" {
		t.Fatalf("empty allowlist probe target = %q, want empty", got)
	}
}
