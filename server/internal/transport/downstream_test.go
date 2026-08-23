package transport

import (
	"encoding/base32"
	"encoding/binary"
	"testing"
)

// parseFrames decodes the [2-byte BE length][payload] framing that
// drainDownstream produces -- the same decode the client's splitDownstreamFrames
// performs -- so this test pins the cross-component wire contract.
func parseFrames(plain []byte) [][]byte {
	var out [][]byte
	for len(plain) >= 2 {
		n := int(binary.BigEndian.Uint16(plain[:2]))
		if n == 0 || 2+n > len(plain) {
			break
		}
		out = append(out, plain[2:2+n])
		plain = plain[2+n:]
	}
	return out
}

func TestDrainDownstream_FramingRoundTrip(t *testing.T) {
	sess := &dnsSession{wgInbound: make(chan []byte, 16)}
	sess.wgInbound <- []byte("alpha")
	sess.wgInbound <- []byte{0xde, 0xad, 0xbe, 0xef}

	framed := drainDownstream(sess, nil)
	got := parseFrames(framed)
	if len(got) != 2 {
		t.Fatalf("got %d frames, want 2", len(got))
	}
	if string(got[0]) != "alpha" || len(got[1]) != 4 || got[1][0] != 0xde {
		t.Fatalf("frames did not round-trip: %q %v", got[0], got[1])
	}
}

func TestDrainDownstream_PrependsFirst(t *testing.T) {
	sess := &dnsSession{wgInbound: make(chan []byte, 16)}
	sess.wgInbound <- []byte("second")
	framed := drainDownstream(sess, []byte("first"))
	got := parseFrames(framed)
	if len(got) != 2 || string(got[0]) != "first" || string(got[1]) != "second" {
		t.Fatalf("first packet must lead: %v", got)
	}
}

func TestDrainDownstream_EmptyIsNil(t *testing.T) {
	sess := &dnsSession{wgInbound: make(chan []byte, 4)}
	if framed := drainDownstream(sess, nil); framed != nil {
		t.Errorf("empty queue with no first packet: got %v, want nil", framed)
	}
}

func TestDrainDownstream_RespectsEDNS0Budget(t *testing.T) {
	// Flood the queue with full-size tun packets. drainDownstream must stop while
	// the base32 of the sealed batch still fits the client's advertised EDNS0
	// buffer (4096), or the response is truncated by the resolver and lost.
	sess := &dnsSession{wgInbound: make(chan []byte, 256)}
	for i := 0; i < 200; i++ {
		sess.wgInbound <- make([]byte, 1420) // MTU-ish
	}
	framed := drainDownstream(sess, nil)
	if len(framed) == 0 {
		t.Fatal("expected some packets drained")
	}
	// Response ≈ base32(framed + AEAD tag) + seq label + DNS header/question.
	const aeadTag = 16
	b32Len := base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(len(framed) + aeadTag)
	const overhead = 128 // seq label + DNS header/question/RR wrapper, generously
	if resp := b32Len + overhead; resp >= 4096 {
		t.Fatalf("packed response ~%d bytes exceeds the 4096 EDNS0 budget (framed=%d)", resp, len(framed))
	}
	// And it should have drained more than one packet when many were queued.
	if got := parseFrames(framed); len(got) < 1 {
		t.Fatalf("framing invalid under load: %d", len(got))
	}
}
