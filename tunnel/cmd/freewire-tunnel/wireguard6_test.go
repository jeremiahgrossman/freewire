package main

import "testing"

// wireguard6Candidate is staged, not active (see its doc comment in
// transport.go) -- these tests cover the carrier's own logic in isolation,
// independent of whether/when it gets wired into defaultCandidates().

func TestWireguard6SkipsWithNoV6Address(t *testing.T) {
	c := wireguard6Candidate()
	_, _, err := c.open(Config{})
	if err == nil {
		t.Fatal("open succeeded with an empty ServerHostV6; want an error so the rung is skipped")
	}
}

func TestWireguard6OpensWithV6Address(t *testing.T) {
	c := wireguard6Candidate()
	lp, transport, err := c.open(Config{ServerHostV6: "2600:1f18:29ea:800::1"})
	if err != nil {
		t.Fatalf("open failed with ServerHostV6 set: %v", err)
	}
	if lp != nil || transport != nil {
		t.Fatalf("open returned (%v, %v), want (nil, nil): a direct carrier, no local proxy or bridge", lp, transport)
	}
}

func TestWireguard6EndpointUsesV6HostAndServerPort(t *testing.T) {
	c := wireguard6Candidate()
	got := c.endpoint(Config{
		ServerHostV6:   "2600:1f18:29ea:800::1",
		ServerEndpoint: "52.203.246.145:51820",
	})
	want := "[2600:1f18:29ea:800::1]:51820"
	if got != want {
		t.Errorf("endpoint = %q, want %q", got, want)
	}
}

func TestWireguard6EndpointDefaultsPortWhenServerEndpointUnparseable(t *testing.T) {
	c := wireguard6Candidate()
	got := c.endpoint(Config{ServerHostV6: "2600:1f18:29ea:800::1", ServerEndpoint: ""})
	want := "[2600:1f18:29ea:800::1]:51820"
	if got != want {
		t.Errorf("endpoint = %q, want %q (default 51820)", got, want)
	}
}

// The staged candidate must not silently join the active chain: this is the
// tripwire that would catch it if someone wired it into defaultCandidates()
// without also updating the Swift TunnelTransport enum in the same change
// (which the doc comment says must happen together, verified on a real v6
// network).
func TestWireguard6NotYetInDefaultCandidates(t *testing.T) {
	for _, c := range defaultCandidates() {
		if c.name == "wireguard6" {
			t.Fatal("wireguard6 is now in defaultCandidates() -- this test is the reminder " +
				"to also add TunnelTransport.wireguard6 on the Swift side (see transport.go's " +
				"wireguard6Candidate doc comment), then delete this test")
		}
	}
}
