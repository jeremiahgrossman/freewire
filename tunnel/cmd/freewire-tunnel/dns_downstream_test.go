package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// frame builds the server's downstream wire format for one packet:
// [2-byte BE length][payload]. Mirrors drainDownstream on the server so the test
// exercises the actual contract splitDownstreamFrames must decode.
func frame(pkts ...[]byte) []byte {
	var out []byte
	for _, p := range pkts {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

func TestSplitDownstreamFrames_RoundTrip(t *testing.T) {
	a := []byte("first")
	b := []byte{0x00, 0x01, 0x02, 0x03}
	c := make([]byte, 1400) // a full-size packet
	for i := range c {
		c[i] = byte(i)
	}
	got := splitDownstreamFrames(frame(a, b, c))
	if len(got) != 3 {
		t.Fatalf("got %d packets, want 3", len(got))
	}
	if string(got[0]) != "first" || len(got[1]) != 4 || len(got[2]) != 1400 {
		t.Fatalf("packets did not round-trip: %q %v len2=%d", got[0], got[1], len(got[2]))
	}
	if got[2][1399] != c[1399] {
		t.Errorf("last byte of large packet corrupted")
	}
}

func TestSplitDownstreamFrames_Single(t *testing.T) {
	// A single packet is the one-frame case; the wire format is uniform.
	p := []byte("solo")
	got := splitDownstreamFrames(frame(p))
	if len(got) != 1 || string(got[0]) != "solo" {
		t.Fatalf("single frame did not round-trip: %v", got)
	}
}

func TestSplitDownstreamFrames_Empty(t *testing.T) {
	if got := splitDownstreamFrames(nil); got != nil {
		t.Errorf("nil input: got %v, want nil", got)
	}
	if got := splitDownstreamFrames([]byte{0x00}); got != nil {
		t.Errorf("one stray byte (too short for a length) should yield no packets, got %v", got)
	}
}

func TestSplitDownstreamFrames_Truncated(t *testing.T) {
	// A length header that runs past the buffer ends the scan rather than
	// panicking or erroring: a truncated response yields the whole packets it did
	// carry, and drops the partial tail.
	good := []byte("ok")
	buf := frame(good)
	buf = append(buf, 0x00, 0xFF) // claims 255 bytes but none follow
	got := splitDownstreamFrames(buf)
	if len(got) != 1 || string(got[0]) != "ok" {
		t.Fatalf("truncated tail not handled: got %v", got)
	}
}

func TestSplitDownstreamFrames_ZeroLength(t *testing.T) {
	// A zero-length frame is malformed and must not loop forever.
	got := splitDownstreamFrames([]byte{0x00, 0x00, 0x00, 0x00})
	if got != nil {
		t.Errorf("zero-length frames should yield nothing, got %v", got)
	}
}

func TestNextResolver_RoundRobin(t *testing.T) {
	s := &dnsClientSession{dnsServers: []string{"a", "b", "c"}}
	want := []string{"a", "b", "c", "a", "b", "c"}
	for i, w := range want {
		if got := s.nextResolver(); got != w {
			t.Errorf("call %d: got %q, want %q", i, got, w)
		}
	}
}

func TestNextResolver_Single(t *testing.T) {
	s := &dnsClientSession{dnsServers: []string{"only"}}
	for i := 0; i < 3; i++ {
		if got := s.nextResolver(); got != "only" {
			t.Errorf("call %d: got %q, want only", i, got)
		}
	}
}

func TestCarrierResolvers(t *testing.T) {
	// List wins, trimmed, empties dropped.
	got := carrierResolvers(Config{DNSResolvers: []string{"1.1.1.1:53", " 8.8.8.8:53 ", ""}})
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Fatalf("list not parsed/trimmed: %v", got)
	}
	// Single resolver when no list.
	if got := carrierResolvers(Config{DNSResolver: "9.9.9.9"}); len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("single resolver: %v", got)
	}
	// Neither -> nil (caller falls back to the system resolver).
	if got := carrierResolvers(Config{}); got != nil {
		t.Fatalf("empty config: got %v, want nil", got)
	}
}

func TestDNSResolverStrategies_ExplicitIsSingle(t *testing.T) {
	got := dnsResolverStrategies(Config{DNSResolver: "1.2.3.4:53", ServerHost: "5.6.7.8"})
	if len(got) != 1 || got[0].name != "configured" || got[0].resolvers[0] != "1.2.3.4:53" {
		t.Fatalf("explicit config should collapse to one strategy: %+v", got)
	}
	if got[0].timeout != dnsHandshakeTimeout {
		t.Errorf("configured timeout = %v, want %v", got[0].timeout, dnsHandshakeTimeout)
	}
}

func TestDNSResolverStrategies_ServerDirectFirst(t *testing.T) {
	got := dnsResolverStrategies(Config{ServerHost: "5.6.7.8", DNSTunnelPort: 53})
	if len(got) == 0 || got[0].name != "server-direct" {
		t.Fatalf("server-direct should be first: %+v", got)
	}
	if got[0].resolvers[0] != "5.6.7.8:53" {
		t.Errorf("server-direct resolver = %q, want 5.6.7.8:53", got[0].resolvers[0])
	}
	if got[0].timeout != 2*time.Second {
		t.Errorf("server-direct timeout = %v, want a shorter 2s probe", got[0].timeout)
	}
}

func TestDNSResolverStrategies_DefaultPort(t *testing.T) {
	// DNSTunnelPort unset defaults to 53.
	got := dnsResolverStrategies(Config{ServerHost: "5.6.7.8"})
	if len(got) == 0 || got[0].resolvers[0] != "5.6.7.8:53" {
		t.Fatalf("default port should be 53: %+v", got)
	}
}
