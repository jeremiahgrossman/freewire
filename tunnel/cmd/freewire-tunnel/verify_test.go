package main

import "testing"

// The burst-prone transports must require more than one probe, or a captive
// portal that lets a single burst through produces a false "Protected" (the
// Starbucks field failure). The fast transports keep the single-probe behavior.
func TestSustainedProbesRequired(t *testing.T) {
	cases := map[string]int{
		"dns":          2,
		"icmp_udp":     2,
		"tls443":       1,
		"http_connect": 1,
		"wireguard":    1,
	}
	for transport, want := range cases {
		if got := sustainedProbesRequired(transport); got != want {
			t.Errorf("sustainedProbesRequired(%q) = %d, want %d", transport, got, want)
		}
	}
}

// The slow transports must demand strictly more than one, since one is exactly
// what a burst passes.
func TestSlowTransportsNeedMoreThanOneProbe(t *testing.T) {
	for _, transport := range []string{"dns", "icmp_udp"} {
		if sustainedProbesRequired(transport) <= 1 {
			t.Errorf("%q requires <=1 probe; a single burst would pass a stalling portal", transport)
		}
	}
}
