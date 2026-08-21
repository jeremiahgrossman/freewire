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
		strings.Join(labels, ".") + "." + dnsTunnelDomain + "."
}

func TestEveryFragmentFitsTheNameLimit(t *testing.T) {
	seqB32 := b32enc.EncodeToString(make([]byte, 4))
	fragB32 := b32enc.EncodeToString(make([]byte, 2))
	tokenB32 := b32enc.EncodeToString(make([]byte, 10))

	// Payload sizes spanning empty, typical, and a full-MTU datagram plus tag.
	for _, size := range []int{0, 1, 64, 96, 512, 1416, 1436, 2048} {
		cipher := make([]byte, size)
		for _, chunk := range splitCiphertext(cipher, dnsFragCipherBytes()) {
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
		for _, c := range splitCiphertext(orig, dnsFragCipherBytes()) {
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
	if got := len(splitCiphertext(nil, dnsFragCipherBytes())); got != 1 {
		t.Errorf("empty payload produced %d fragments, want 1", got)
	}
}

// The fragment header carries index and total in one byte each.
func TestFullDatagramStaysWithinTheFragmentHeader(t *testing.T) {
	// 1420 MTU + 16-byte Poly1305 tag is the largest ciphertext expected.
	n := len(splitCiphertext(make([]byte, 1436), dnsFragCipherBytes()))
	if n > 255 {
		t.Errorf("a full datagram needs %d fragments, more than the header's 255", n)
	}
	if n < 2 {
		t.Errorf("a full datagram produced %d fragments; the budget looks wrong", n)
	}
	t.Logf("full datagram spans %d fragments (%d ciphertext bytes each)", n, dnsFragCipherBytes())
}

func TestFragmentBudgetIsPositive(t *testing.T) {
	if got := dnsFragCipherBytes(); got < 32 {
		t.Errorf("fragment budget is %d bytes, too small to make progress", got)
	}
}
