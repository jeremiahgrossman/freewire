package main

import (
	"strings"
	"testing"
)

// A full WireGuard datagram used to encode to a ~2.4 KB name across 37 labels,
// against an RFC 1035 limit of 255. Every such query was rejected, which is why
// the DNS transport never carried a packet. These tests pin the budget.

func buildName(seqB32, fragB32, tokenB32 string, chunk []byte) string {
	labels := chunkLabels(b32enc.EncodeToString(chunk), dnsMaxLabel)
	return "t." + seqB32 + "." + fragB32 + "." + tokenB32 + "." +
		strings.Join(labels, ".") + "." + defaultDNSTunnelDomain + "."
}

func TestEveryFragmentFitsTheNameLimit(t *testing.T) {
	seqB32 := b32enc.EncodeToString(make([]byte, 4))
	fragB32 := b32enc.EncodeToString(make([]byte, 2))
	tokenB32 := b32enc.EncodeToString(make([]byte, 10))

	// Payload sizes spanning empty, typical, and a full-MTU datagram plus tag.
	for _, size := range []int{0, 1, 64, 96, 512, 1416, 1436, 2048} {
		cipher := make([]byte, size)
		for _, chunk := range splitCiphertext(cipher, dnsFragCipherBytes(defaultDNSTunnelDomain)) {
			name := buildName(seqB32, fragB32, tokenB32, chunk)
			if l := dnsNameWireLen(name); l > dnsMaxName {
				t.Errorf("payload %d: fragment builds a %d-byte name, over the %d limit",
					size, l, dnsMaxName)
			}
			for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
				if len(label) > dnsMaxLabel {
					t.Errorf("payload %d: label of %d bytes exceeds %d", size, len(label), dnsMaxLabel)
				}
			}
		}
	}
}

func TestFragmentsReassembleToTheOriginal(t *testing.T) {
	for _, size := range []int{0, 1, 95, 96, 97, 1436} {
		orig := make([]byte, size)
		for i := range orig {
			orig[i] = byte(i % 251)
		}
		var out []byte
		for _, c := range splitCiphertext(orig, dnsFragCipherBytes(defaultDNSTunnelDomain)) {
			out = append(out, c...)
		}
		if len(out) != len(orig) {
			t.Errorf("size %d: reassembled %d bytes", size, len(out))
			continue
		}
		for i := range orig {
			if out[i] != orig[i] {
				t.Errorf("size %d: byte %d differs", size, i)
				break
			}
		}
	}
}

// An empty packet still needs one fragment, or the server never learns a total.
func TestEmptyPayloadProducesOneFragment(t *testing.T) {
	if got := len(splitCiphertext(nil, dnsFragCipherBytes(defaultDNSTunnelDomain))); got != 1 {
		t.Errorf("empty payload produced %d fragments, want 1", got)
	}
}

// The fragment header carries index and total in one byte each.
func TestFullDatagramStaysWithinTheFragmentHeader(t *testing.T) {
	// 1420 MTU + 16-byte Poly1305 tag is the largest ciphertext expected.
	n := len(splitCiphertext(make([]byte, 1436), dnsFragCipherBytes(defaultDNSTunnelDomain)))
	if n > 255 {
		t.Errorf("a full datagram needs %d fragments, more than the header's 255", n)
	}
	if n < 2 {
		t.Errorf("a full datagram produced %d fragments; the budget looks wrong", n)
	}
	t.Logf("full datagram spans %d fragments (%d ciphertext bytes each)", n, dnsFragCipherBytes(defaultDNSTunnelDomain))
}

func TestFragmentBudgetIsPositive(t *testing.T) {
	if got := dnsFragCipherBytes(defaultDNSTunnelDomain); got < 32 {
		t.Errorf("fragment budget is %d bytes, too small to make progress", got)
	}
}

// A path upgrade relaunches the tunnel asking for a specific transport. Without
// honouring that, the chain restarted from the top and reselected the same path
// it had just been told to leave, so the upgrade tore the tunnel down and
// rebuilt exactly what was there before -- then upgraded again, forever.
func TestPreferredTransportGoesFirst(t *testing.T) {
	all := defaultCandidates()
	got := orderCandidates(all, "dns")
	if got[0].name != "dns" {
		t.Errorf("preferred path is %q, want dns first", got[0].name)
	}
	if len(got) != len(all) {
		t.Errorf("ordering returned %d candidates, want all %d", len(got), len(all))
	}
}

// The rest of the chain must survive, so a preferred path that fails still
// falls through instead of stranding the client.
func TestPreferredTransportKeepsTheRestOfTheChain(t *testing.T) {
	all := defaultCandidates()
	got := orderCandidates(all, "icmp_udp")

	seen := map[string]bool{}
	for _, c := range got {
		if seen[c.name] {
			t.Errorf("candidate %q appears twice", c.name)
		}
		seen[c.name] = true
	}
	for _, c := range all {
		if !seen[c.name] {
			t.Errorf("candidate %q was dropped", c.name)
		}
	}
	// Remaining candidates keep their original relative order.
	var rest []string
	for _, c := range got[1:] {
		rest = append(rest, c.name)
	}
	var want []string
	for _, c := range all {
		if c.name != "icmp_udp" {
			want = append(want, c.name)
		}
	}
	for i := range want {
		if rest[i] != want[i] {
			t.Errorf("chain order after the preferred path: got %v, want %v", rest, want)
			break
		}
	}
}

func TestUnknownPreferredTransportIsIgnored(t *testing.T) {
	all := defaultCandidates()
	got := orderCandidates(all, "carrier-pigeon")
	if len(got) != len(all) || got[0].name != all[0].name {
		t.Error("an unknown preferred name should leave the chain untouched")
	}
}

func TestNoPreferenceKeepsSpeedOrder(t *testing.T) {
	// Speed order, fastest first: direct WireGuard leads so an open network never
	// settles for a slower encapsulation; the slow tunnels are last resorts.
	//
	// wss443 sits directly after tls443: same port, same TLS cost, one extra
	// round trip for the HTTP Upgrade, so it is only worth reaching when the raw
	// carrier was refused -- which is what a portal passing "web 443" but
	// resetting raw 443 does.
	want := []string{"wireguard", "http_connect", "tls443", "wss443", "cdn_wss", "dns", "icmp_udp"}
	got := orderCandidates(defaultCandidates(), "")
	for i, name := range want {
		if got[i].name != name {
			t.Errorf("position %d is %q, want %q", i, got[i].name, name)
		}
	}
}

// The health probe and the route check both used a fixed address. That address
// is also a plausible DNS resolver, and the resolver gets pinned outside the
// tunnel so the DNS transport keeps working — so both checks could end up
// measuring the bypass route instead of the tunnel, and would pass on a tunnel
// carrying nothing at all.
func TestProbeAvoidsPinnedAddresses(t *testing.T) {
	defer func() { bypassRoutes = nil }()

	bypassRoutes = nil
	if got := probeAddr(); got != probeCandidates[0] {
		t.Errorf("with nothing pinned, probe = %q, want the first candidate", got)
	}

	// Pin the first candidate, as would happen if it were the resolver.
	bypassRoutes = []string{"1.1.1.1"}
	got := probeAddr()
	if got == probeCandidates[0] {
		t.Error("probe chose a pinned address, so it measures the bypass route")
	}
	if got != probeCandidates[1] {
		t.Errorf("probe = %q, want the next unpinned candidate", got)
	}
}

func TestProbeSkipsSeveralPinnedAddresses(t *testing.T) {
	defer func() { bypassRoutes = nil }()
	bypassRoutes = []string{"1.1.1.1", "8.8.8.8"}
	if got := probeAddr(); got != probeCandidates[2] {
		t.Errorf("probe = %q, want the third candidate", got)
	}
}

// Every candidate pinned should still yield something to probe: skipping the
// check entirely is worse than probing an imperfect address.
func TestProbeStillReturnsWhenAllPinned(t *testing.T) {
	defer func() { bypassRoutes = nil }()
	bypassRoutes = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if probeAddr() == "" {
		t.Error("probe returned nothing, so the health check would be skipped")
	}
}

func TestIsPinnedMatchesExactly(t *testing.T) {
	defer func() { bypassRoutes = nil }()
	bypassRoutes = []string{"1.1.1.1"}
	if !isPinned("1.1.1.1") {
		t.Error("a pinned address was not recognised")
	}
	if isPinned("1.1.1.10") {
		t.Error("a prefix match was treated as pinned")
	}
}
