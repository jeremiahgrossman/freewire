package main

import "testing"

func TestSanitizeDoHEndpointsDropsPlaintext(t *testing.T) {
	got := sanitizeDoHEndpoints([]string{
		"https://9.9.9.9/dns-query",
		"http://8.8.8.8/dns-query", // plaintext: must be dropped
		"https://1.1.1.1/dns-query",
	})
	want := []string{"https://9.9.9.9/dns-query", "https://1.1.1.1/dns-query"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSanitizeDoHEndpointsFallsBackToDefault(t *testing.T) {
	// Nothing usable -> the default pair, never an empty list that would leave
	// the forwarder with no resolver at all.
	for _, in := range [][]string{nil, {}, {"http://insecure/dns-query"}, {"ftp://x"}} {
		got := sanitizeDoHEndpoints(in)
		if len(got) != len(defaultDoHEndpoints) || got[0] != defaultDoHEndpoints[0] {
			t.Errorf("input %v: got %v, want default %v", in, got, defaultDoHEndpoints)
		}
	}
}
