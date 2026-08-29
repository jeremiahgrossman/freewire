package transport

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func tcbitQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0xBEEF)
	msg[2] = 0x01
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0, 0x00, 0x10, 0x00, 0x01) // root, TXT, IN
	return msg
}

func TestParseTCBitQuery(t *testing.T) {
	for _, tc := range []struct {
		label string
		size  int
		ok    bool
	}{
		{"abc123.s4000.tcbit", 4000, true},
		{"s512.tcbit", 512, true},
		{"ABC.S0.TCBIT", 0, true},
		{"abc.s99999999.tcbit", tcbitMaxSize, true}, // clamped, never trusted
		{"abc.tcbit", 0, false},                     // no size label
		{"tcbit", 0, false},                         // size label missing
		{"abc.sxyz.tcbit", 0, false},                // unparseable size
		{"abc.s100.other", 0, false},                // not the experiment
		{"h.1.abc", 0, false},                       // a real tunnel query
		{"t.abc.def", 0, false},
	} {
		got, ok := parseTCBitQuery(tc.label)
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.label, ok, tc.ok)
			continue
		}
		if ok && got.size != tc.size {
			t.Errorf("%q: size = %d, want %d", tc.label, got.size, tc.size)
		}
	}
}

// The property that makes this safe to leave running: the UDP reply must never
// EXCEED the query that provoked it, so a spoofed source cannot turn the
// experiment into an amplifier. The large answer exists only over TCP, where the
// handshake proves the source.
//
// Equal size is the floor, not a weakness. A valid DNS response has to echo the
// question section (a recursor may discard one that does not, which would break
// the very TCP fallback being measured), so header+question is the smallest
// well-formed truncated answer that exists. At a 1:1 ratio there is no
// amplification and no reflection worth having -- an attacker spends exactly
// what the victim receives, and could simply send to the victim directly.
// Contrast the probe responder, which is strictly smaller because it answers a
// padded 64-byte floor it defines itself.
func TestTCBitUDPReplyNeverAmplifies(t *testing.T) {
	for _, size := range []int{0, 512, 4096, 60000} {
		q := tcbitQuery(t, "nonce.s"+strconv.Itoa(size)+".tcbit.t.pinghop.net")
		reply := tcbitTruncatedReply(q)
		if len(reply) > len(q) {
			t.Errorf("size %d: reply %d bytes > query %d bytes — amplification risk",
				size, len(reply), len(q))
		}
		if reply[2]&0x02 == 0 {
			t.Errorf("size %d: TC bit not set — the recursor will not retry over TCP", size)
		}
		if binary.BigEndian.Uint16(reply[6:8]) != 0 {
			t.Errorf("size %d: truncated reply carries answer records", size)
		}
		if binary.BigEndian.Uint16(reply[0:2]) != 0xBEEF {
			t.Errorf("size %d: reply does not echo the query id", size)
		}
	}
}

func TestTCBitSizedReplyIsAboutTheRequestedSize(t *testing.T) {
	for _, size := range []int{100, 1000, 5000, 20000, 60000} {
		q := tcbitQuery(t, "nonce.s"+strconv.Itoa(size)+".tcbit.t.pinghop.net")
		reply := tcbitSizedReply(q, size)
		if reply == nil {
			t.Fatalf("size %d: nil reply", size)
		}
		// The payload is carried in TXT character-strings, so the message is the
		// requested size plus per-string and per-RR overhead. It must never be
		// smaller than asked, and the overhead must stay proportionate.
		if len(reply) < size {
			t.Errorf("size %d: reply is only %d bytes", size, len(reply))
		}
		if len(reply) > size+size/4+512 {
			t.Errorf("size %d: reply is %d bytes — overhead is out of proportion", size, len(reply))
		}
		if reply[2]&0x02 != 0 {
			t.Errorf("size %d: TC set on the TCP reply", size)
		}
		if binary.BigEndian.Uint16(reply[6:8]) == 0 {
			t.Errorf("size %d: no answer records", size)
		}
		if len(reply) > 65535 {
			t.Errorf("size %d: reply exceeds the DNS message maximum", size)
		}
	}
}

// A cached large answer would make the sweep measure a recursor's cache instead
// of its relay limit, and would leave big records in public caches.
func TestTCBitAnswersAreUncacheable(t *testing.T) {
	q := tcbitQuery(t, "nonce.s2000.tcbit.t.pinghop.net")
	reply := tcbitSizedReply(q, 2000)
	// Walk to the first answer RR: header + question, then name(2) type(2)
	// class(2) ttl(4).
	off := 12 + len(tcbitQuestion(q))
	ttl := binary.BigEndian.Uint32(reply[off+6 : off+10])
	if ttl != 0 {
		t.Errorf("answer TTL = %d, want 0 so no recursor caches it", ttl)
	}
}

func TestTCBitQuestionRejectsMalformed(t *testing.T) {
	if got := tcbitQuestion([]byte{1, 2, 3}); got != nil {
		t.Error("accepted a message shorter than a header")
	}
	// A compression pointer inside the question is malformed.
	bad := make([]byte, 12)
	bad = append(bad, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01)
	if got := tcbitQuestion(bad); got != nil {
		t.Error("accepted a compression pointer in the question section")
	}
}
