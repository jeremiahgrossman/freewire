package main

import (
	"encoding/json"
	"testing"
)

// The Swift app sends the allowlist as the JSON key "essentials_allowlist"
// (TunnelConfig CodingKey). This pins that the Go Config decodes that exact key
// into EssentialsAllowlist and that it flows through to essentialsAllowlist() --
// a rename on either side of the boundary would silently disable Phase 2.
func TestConfigDecodesEssentialsAllowlist(t *testing.T) {
	const js = `{"private_key":"x","server_public_key":"y","essentials_allowlist":["17.0.0.0/8","signal.org"]}`
	var cfg Config
	if err := json.Unmarshal([]byte(js), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cfg.EssentialsAllowlist) != 2 || cfg.EssentialsAllowlist[1] != "signal.org" {
		t.Fatalf("EssentialsAllowlist = %v, want [17.0.0.0/8 signal.org]", cfg.EssentialsAllowlist)
	}
	// And it flows to the parser via the package var main() sets after decode.
	t.Setenv(essentialsEnv, "") // config is the source, not the env
	essentialsConfigAllowlist = cfg.EssentialsAllowlist
	defer func() { essentialsConfigAllowlist = nil }()
	nets, domains, active := essentialsAllowlist()
	if !active || len(nets) != 1 || len(domains) != 1 || domains[0] != "signal.org" {
		t.Fatalf("from decoded config: active=%v nets=%v domains=%v", active, nets, domains)
	}
}

func TestEssentialsAllowlistInactiveWhenUnset(t *testing.T) {
	t.Setenv(essentialsEnv, "")
	if nets, domains, active := essentialsAllowlist(); active || nets != nil || domains != nil {
		t.Fatalf("empty env must be inactive, got active=%v nets=%v", active, nets)
	}
}

func TestEssentialsAllowlistSeed(t *testing.T) {
	for _, v := range []string{"1", "default", "on"} {
		t.Setenv(essentialsEnv, v)
		nets, _, active := essentialsAllowlist()
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
	nets, _, active := essentialsAllowlist()
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
	nets, _, active := essentialsAllowlist()
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
	if nets, domains, active := essentialsAllowlist(); active || nets != nil || domains != nil {
		t.Fatalf("all-invalid must be inactive (fail safe to full tunnel), got active=%v nets=%v", active, nets)
	}
}

// The activation path the app uses: the allowlist arrives in the stdin config
// (essentialsConfigAllowlist), which survives sudo unlike an env var.
func TestEssentialsFromConfig(t *testing.T) {
	t.Setenv(essentialsEnv, "") // env off, so config is the source
	essentialsConfigAllowlist = []string{"17.0.0.0/8", "203.0.113.9"}
	defer func() { essentialsConfigAllowlist = nil }()
	nets, _, active := essentialsAllowlist()
	if !active {
		t.Fatal("config allowlist should activate essentials mode")
	}
	if got := essentialsCIDRs(nets); len(got) != 2 || got[0] != "17.0.0.0/8" || got[1] != "203.0.113.9/32" {
		t.Fatalf("config allowlist parsed to %v, want [17.0.0.0/8 203.0.113.9/32]", got)
	}
}

// Phase 2: the allowlist accepts domains alongside CIDRs/IPs. IPs become routes,
// everything hostname-shaped becomes a domain suffix for the scoped resolver.
func TestEssentialsAllowlistMixedIPsAndDomains(t *testing.T) {
	t.Setenv(essentialsEnv, "17.0.0.0/8, signal.org, 203.0.113.9, *.apple.com, chat.example.co.uk")
	nets, domains, active := essentialsAllowlist()
	if !active {
		t.Fatal("mixed list should be active")
	}
	if got := essentialsCIDRs(nets); len(got) != 2 || got[0] != "17.0.0.0/8" || got[1] != "203.0.113.9/32" {
		t.Fatalf("IP entries = %v, want [17.0.0.0/8 203.0.113.9/32]", got)
	}
	want := []string{"signal.org", "apple.com", "chat.example.co.uk"} // "*." stripped
	if len(domains) != len(want) {
		t.Fatalf("domains = %v, want %v", domains, want)
	}
	for i := range want {
		if domains[i] != want[i] {
			t.Fatalf("domain %d = %q, want %q (full %v)", i, domains[i], want[i], domains)
		}
	}
}

// A domain-only allowlist activates (the scoped resolver carries it; no static
// routes needed at setup time).
func TestEssentialsAllowlistDomainOnlyIsActive(t *testing.T) {
	t.Setenv(essentialsEnv, "signal.org")
	nets, domains, active := essentialsAllowlist()
	if !active || len(nets) != 0 || len(domains) != 1 || domains[0] != "signal.org" {
		t.Fatalf("domain-only: active=%v nets=%v domains=%v", active, nets, domains)
	}
}

// The env var is a direct-binary test override: when both are set, env wins.
func TestEssentialsEnvOverridesConfig(t *testing.T) {
	t.Setenv(essentialsEnv, "198.51.100.0/24")
	essentialsConfigAllowlist = []string{"17.0.0.0/8"}
	defer func() { essentialsConfigAllowlist = nil }()
	nets, _, active := essentialsAllowlist()
	if !active {
		t.Fatal("should be active")
	}
	if got := essentialsCIDRs(nets); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("env should override config, got %v, want [198.51.100.0/24]", got)
	}
}

func TestEssentialsProbeTarget(t *testing.T) {
	t.Setenv(essentialsEnv, "17.0.0.0/8,203.0.113.9")
	nets, _, _ := essentialsAllowlist()
	if got := essentialsProbeTarget(nets); got != "17.0.0.0" {
		t.Fatalf("probe target = %q, want 17.0.0.0 (network addr of the first prefix)", got)
	}
	if got := essentialsProbeTarget(nil); got != "" {
		t.Fatalf("empty allowlist probe target = %q, want empty", got)
	}
}
