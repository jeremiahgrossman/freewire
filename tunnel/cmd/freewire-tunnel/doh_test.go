package main

import (
	"encoding/binary"
	"testing"
)

// query builds a minimal DNS query for "example.com A", optionally with an
// EDNS0 OPT record advertising a UDP budget.
func query(t *testing.T, ednsSize int) []byte {
	t.Helper()
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	for _, label := range []string{"example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)          // root
	msg = append(msg, 0, 1, 0, 1) // QTYPE=A, QCLASS=IN

	if ednsSize > 0 {
		binary.BigEndian.PutUint16(msg[10:12], 1) // ARCOUNT
		opt := []byte{0}                          // root name
		opt = append(opt, 0, 41)                  // TYPE=OPT
		opt = append(opt, byte(ednsSize>>8), byte(ednsSize))
		opt = append(opt, 0, 0, 0, 0) // TTL
		opt = append(opt, 0, 0)       // RDLENGTH
		msg = append(msg, opt...)
	}
	return msg
}

func TestUDPBudgetDefaultsTo512(t *testing.T) {
	if got := udpBudget(query(t, 0)); got != 512 {
		t.Errorf("budget = %d without EDNS0, want 512", got)
	}
}

func TestUDPBudgetReadsEDNS0(t *testing.T) {
	if got := udpBudget(query(t, 4096)); got != 4096 {
		t.Errorf("budget = %d, want the advertised 4096", got)
	}
}

// A resolver advertising less than the classic minimum does not shrink the
// floor; 512 is always safe to send.
func TestUDPBudgetIgnoresUndersizedAdvertisement(t *testing.T) {
	if got := udpBudget(query(t, 200)); got != 512 {
		t.Errorf("budget = %d for an undersized advertisement, want 512", got)
	}
}

// Truncation is the signal to retry over TCP. Getting the flags wrong means a
// stub resolver either accepts a gutted answer or hangs.
func TestTruncateSetsResponseAndTruncatedFlags(t *testing.T) {
	out := truncate(query(t, 0))
	if len(out) < 12 {
		t.Fatalf("truncated message is %d bytes", len(out))
	}
	if out[2]&0x80 == 0 {
		t.Error("QR not set: the stub would read this as a query")
	}
	if out[2]&0x02 == 0 {
		t.Error("TC not set: the stub would not retry over TCP")
	}
	for name, off := range map[string]int{"ANCOUNT": 6, "NSCOUNT": 8, "ARCOUNT": 10} {
		if binary.BigEndian.Uint16(out[off:off+2]) != 0 {
			t.Errorf("%s is non-zero but no records follow", name)
		}
	}
	if binary.BigEndian.Uint16(out[0:2]) != 0x1234 {
		t.Error("transaction id not preserved; the stub cannot match the reply")
	}
	if binary.BigEndian.Uint16(out[4:6]) != 1 {
		t.Error("question count not preserved")
	}
}

func TestServfailIsAFailureNotATruncation(t *testing.T) {
	out := servfail(query(t, 0))
	if len(out) < 12 {
		t.Fatal("servfail produced no message")
	}
	if out[2]&0x80 == 0 {
		t.Error("QR not set")
	}
	if out[2]&0x02 != 0 {
		t.Error("TC set on a SERVFAIL: the stub would retry over TCP instead of failing")
	}
	if out[3]&0x0F != 2 {
		t.Errorf("RCODE = %d, want 2 (SERVFAIL)", out[3]&0x0F)
	}
}

// Malformed input reaches this code from anything that can send a UDP packet to
// loopback, so it must not panic or run off the end.
func TestParsersSurviveMalformedInput(t *testing.T) {
	cases := [][]byte{
		{},
		{0x12},
		make([]byte, 11),
		make([]byte, 12),
		append(make([]byte, 12), 0xFF),       // length past the buffer
		append(make([]byte, 12), 0xC0, 0x0C), // compression pointer
	}
	full := query(t, 4096)
	for i := 1; i < len(full); i++ {
		cases = append(cases, full[:i])
	}
	for _, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on %d-byte input: %v", len(c), r)
				}
			}()
			udpBudget(c)
			truncate(c)
			servfail(c)
		}()
	}
}
