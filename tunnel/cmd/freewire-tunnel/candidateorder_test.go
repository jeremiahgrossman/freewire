package main

import "testing"

func names(cs []transportCandidate) []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.name
	}
	return out
}

// Reconnect names the transport that was working. Without that the chain
// restarts from the top, re-testing paths the network has already refused and
// spending most of the fallback budget to arrive where it started -- with the
// user unprotected throughout.
func TestPreferredTransportIsTriedFirst(t *testing.T) {
	ordered := names(orderCandidates(defaultCandidates(), "dns"))
	if len(ordered) == 0 || ordered[0] != "dns" {
		t.Fatalf("order = %v, want dns first", ordered)
	}
}

// Everything else must still follow it. A remembered path that stops working --
// a different network, a portal that changed its mind -- has to cost one wasted
// attempt, not a failure to connect.
func TestPreferredTransportDoesNotRemoveTheRest(t *testing.T) {
	all := defaultCandidates()
	ordered := orderCandidates(all, "dns")
	if len(ordered) != len(all) {
		t.Fatalf("order has %d candidates, want all %d", len(ordered), len(all))
	}
	seen := map[string]bool{}
	for _, n := range names(ordered) {
		if seen[n] {
			t.Errorf("%s appears twice", n)
		}
		seen[n] = true
	}
	for _, c := range all {
		if !seen[c.name] {
			t.Errorf("%s was dropped from the chain", c.name)
		}
	}
}

// A name from an older client, or a transport since removed, must not empty the
// chain -- that would turn a cosmetic mismatch into a total failure to connect.
func TestUnknownPreferenceLeavesTheChainIntact(t *testing.T) {
	all := defaultCandidates()
	if got := len(orderCandidates(all, "no_such_transport")); got != len(all) {
		t.Errorf("unknown preference left %d candidates, want %d", got, len(all))
	}
	if got := len(orderCandidates(all, "")); got != len(all) {
		t.Errorf("empty preference left %d candidates, want %d", got, len(all))
	}
}
