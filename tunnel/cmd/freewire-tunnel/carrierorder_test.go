package main

import "testing"

// The probe battery (probebattery.go) emits carriers in the app's REAL selection
// order so its "fastest that reached the server" verdict names the carrier the
// app would actually pick. That only holds if defaultCandidates() stays in this
// order. This test is the tripwire: reorder the chain (e.g. drop udp443 back
// below the TCP carriers, the bug this guards against) and it fails, pointing at
// the battery that must move with it.
//
// icmp_udp is last in the chain but absent from the rootless battery (it needs
// raw sockets); every other carrier appears in both, in this order. dns_tcp is
// in both, as "TCP/53 (dns_tcp carrier)".
//
// dns_tcp sits between cdn_wss and dns: it pays the same TCP-over-TCP penalty as
// the 443 carriers without their throughput, so it is not one of them, but it
// lifts two of the UDP DNS carrier's three ceilings, so it clearly outranks dns.
func TestCarrierChainOrderIsStable(t *testing.T) {
	want := []string{
		"wireguard",
		"udp443",
		"http_connect",
		"tls443",
		"wss443",
		"cdn_wss",
		"dns_tcp",
		"dns",
		"icmp_udp",
	}
	got := defaultCandidates()
	if len(got) != len(want) {
		t.Fatalf("chain has %d carriers, want %d: %v", len(got), len(want), names(got))
	}
	for i := range want {
		if got[i].name != want[i] {
			t.Fatalf("carrier %d = %q, want %q (full chain %v)\n"+
				"  if this reorder is intended, update the probe battery order to match",
				i, got[i].name, want[i], names(got))
		}
	}
}

// udp443 must rank immediately after wireguard-direct: it is the same speed (no
// TCP-over-TCP) on a port portals pass far more often, so a network that blocks
// UDP/51820 but not UDP/443 must reach it BEFORE any TCP carrier. This was the
// exact mismatch between the app and the survey the battery reorder fixed.
func TestUDP443RanksSecond(t *testing.T) {
	c := defaultCandidates()
	if c[0].name != "wireguard" || c[1].name != "udp443" {
		t.Fatalf("want wireguard then udp443 at the head; got %q, %q", c[0].name, c[1].name)
	}
	// And every TCP carrier must sit strictly after udp443.
	pos := map[string]int{}
	for i, x := range c {
		pos[x.name] = i
	}
	for _, tcp := range []string{"http_connect", "tls443", "wss443", "cdn_wss"} {
		if pos[tcp] <= pos["udp443"] {
			t.Errorf("%s ranks at %d, must be after udp443 at %d (udp443 has no TCP-over-TCP cost)",
				tcp, pos[tcp], pos["udp443"])
		}
	}
}

func candidateNames(cs []transportCandidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.name
	}
	return out
}
