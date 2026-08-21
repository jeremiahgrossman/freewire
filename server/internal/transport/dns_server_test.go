package transport

import (
	"encoding/binary"
	"strings"
	"testing"
)

// parseTXTRDATA walks a TXT response built by buildDNSTXTResponse and returns
// the concatenated payload plus the length of each character-string.
func parseTXTRDATA(t *testing.T, resp []byte) (payload string, chunkLens []int) {
	t.Helper()
	// header(12) + NAME(1) + TYPE(2) + CLASS(2) + TTL(4) = 21, then RDLENGTH(2).
	const rdlenOff = 21
	if len(resp) < rdlenOff+2 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	rdlen := int(binary.BigEndian.Uint16(resp[rdlenOff : rdlenOff+2]))
	rdata := resp[rdlenOff+2:]
	if len(rdata) != rdlen {
		t.Fatalf("RDLENGTH says %d but %d bytes follow", rdlen, len(rdata))
	}

	var sb strings.Builder
	for i := 0; i < len(rdata); {
		n := int(rdata[i])
		i++
		if i+n > len(rdata) {
			t.Fatalf("character-string length %d overruns RDATA", n)
		}
		sb.Write(rdata[i : i+n])
		chunkLens = append(chunkLens, n)
		i += n
	}
	return sb.String(), chunkLens
}

func TestTXTResponseHeader(t *testing.T) {
	qid := []byte{0xAB, 0xCD}
	resp := buildDNSTXTResponse(qid, "hello")

	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Errorf("query ID = %02x%02x, want abcd", resp[0], resp[1])
	}
	if resp[2] != 0x84 || resp[3] != 0x00 {
		t.Errorf("flags = %02x%02x, want 8400 (QR=1 AA=1 RCODE=0)", resp[2], resp[3])
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", ancount)
	}
	if qtype := binary.BigEndian.Uint16(resp[13:15]); qtype != 16 {
		t.Errorf("TYPE = %d, want 16 (TXT)", qtype)
	}
}

func TestTXTShortPayloadIsSingleString(t *testing.T) {
	payload := "short-answer"
	got, lens := parseTXTRDATA(t, buildDNSTXTResponse([]byte{0, 1}, payload))
	if got != payload {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if len(lens) != 1 {
		t.Errorf("split into %d character-strings, want 1", len(lens))
	}
}

// Regression: payloads over 255 bytes were written with a truncated single
// length byte, producing a malformed record that resolvers dropped.
func TestTXTLongPayloadSplitsAt255(t *testing.T) {
	for _, size := range []int{255, 256, 300, 511, 512, 1000, 4096} {
		payload := strings.Repeat("x", size)
		got, lens := parseTXTRDATA(t, buildDNSTXTResponse([]byte{0, 1}, payload))

		if got != payload {
			t.Errorf("size %d: payload round trip lost data (%d bytes back)", size, len(got))
		}
		for i, n := range lens {
			if n > 255 {
				t.Errorf("size %d: character-string %d is %d bytes, exceeds 255", size, i, n)
			}
		}
		wantChunks := (size + 254) / 255
		if len(lens) != wantChunks {
			t.Errorf("size %d: split into %d strings, want %d", size, len(lens), wantChunks)
		}
	}
}

func TestTXTEmptyPayload(t *testing.T) {
	got, lens := parseTXTRDATA(t, buildDNSTXTResponse([]byte{0, 1}, ""))
	if got != "" {
		t.Errorf("payload = %q, want empty", got)
	}
	if len(lens) != 1 || lens[0] != 0 {
		t.Errorf("empty payload produced %v, want a single zero-length string", lens)
	}
}

func TestTXTBinarySafePayload(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 600; i++ {
		sb.WriteByte(byte(i % 256))
	}
	payload := sb.String()
	got, _ := parseTXTRDATA(t, buildDNSTXTResponse([]byte{0, 1}, payload))
	if got != payload {
		t.Error("binary payload did not survive the round trip")
	}
}

func TestNXDomainResponse(t *testing.T) {
	qid := []byte{0x12, 0x34}
	resp := buildDNSNXDomain(qid)

	if len(resp) != 12 {
		t.Fatalf("NXDOMAIN response is %d bytes, want 12", len(resp))
	}
	if resp[0] != 0x12 || resp[1] != 0x34 {
		t.Error("query ID not echoed")
	}
	if rcode := resp[3] & 0x0F; rcode != 3 {
		t.Errorf("RCODE = %d, want 3 (NXDOMAIN)", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 0 {
		t.Errorf("ANCOUNT = %d, want 0", ancount)
	}
}

func TestNonceLayout(t *testing.T) {
	var n [12]byte
	srvDNSNonceInto(0x01020304, &n)
	if got := binary.BigEndian.Uint32(n[:4]); got != 0x01020304 {
		t.Errorf("sequence = %08x, want 01020304", got)
	}
	for i, b := range n[4:] {
		if b != 0 {
			t.Errorf("nonce byte %d = %02x, want 00", i+4, b)
		}
	}
}

// The helper writes into a reused array, so it must clear any prior contents
// rather than only overwriting the first four bytes.
func TestNonceIntoClearsPriorContents(t *testing.T) {
	var n [12]byte
	for i := range n {
		n[i] = 0xFF
	}
	srvDNSNonceInto(7, &n)
	for i, b := range n[4:] {
		if b != 0 {
			t.Errorf("stale byte at %d: %02x, want 00", i+4, b)
		}
	}
}

func TestNoncesAreUniquePerSequence(t *testing.T) {
	seen := map[[12]byte]uint32{}
	for _, seq := range []uint32{0, 1, 2, 255, 256, 65535, 65536, 1 << 24, ^uint32(0)} {
		var n [12]byte
		srvDNSNonceInto(seq, &n)
		if prev, dup := seen[n]; dup {
			t.Errorf("sequences %d and %d produce the same nonce", prev, seq)
		}
		seen[n] = seq
	}
}
