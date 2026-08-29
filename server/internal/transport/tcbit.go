package transport

import (
	"encoding/binary"
	"strconv"
	"strings"
)

// TC-bit experiment scaffolding.
//
// THE QUESTION. On the recursor DNS path the documented cap is on QUERY RATE --
// a public resolver forwards roughly 14 unique names/s to one authoritative
// server -- not on response size. So if an authoritative answer sets TC=1, the
// recursor re-asks over TCP/53 and can return a much larger answer in that same
// one permitted query. Downstream capacity would rise with the query rate
// untouched, which is exactly the shape of the café failure (café #3 died at
// queue 256/256 with the carrier itself showing headroom).
//
// WHAT WAS ALREADY MEASURED without any server code (2026-08-28, public
// recursors): 1.1.1.1, 8.8.8.8 and 9.9.9.9 all follow TC=1 to TCP and relay
// 5209 bytes intact, and the same answer is truncated over UDP at an advertised
// buffer of 1232 AND 4096 -- so the gain is structurally TCP-only and cannot be
// had by advertising a bigger EDNS buffer. But 5209 is merely the largest PUBLIC
// RRset that exists to test against, not a recursor limit, and against our
// carrier's ~4096-wire budget that is only ~1.3x.
//
// WHAT THIS ANSWERS. Only an authoritative server we control can emit answers of
// arbitrary size, so this responder does exactly that and nothing else: a name
// carrying a requested byte count, truncated over UDP, served at that size over
// TCP. Sweeping the size finds the real ceiling, which decides whether a
// DNS-over-TCP carrier is worth building (1.3x is not; 10x+ is).
//
// SAFETY. This is inherently non-amplifying, which is why it can be on by
// default: the UDP answer is a small TC=1 header with no records, and the large
// answer exists only over TCP, where the handshake proves the source. A spoofed
// UDP query gets a reply smaller than itself. The size is bounded, the TTL is
// zero so no recursor caches a large answer, and the whole thing is gated behind
// a label under our own zone that nothing else queries.
//
// THIS IS SCAFFOLDING. Delete it once the ceiling is known and recorded; it
// serves no user.

const (
	// tcbitLabel gates the experiment. A query must be
	// <nonce>.s<N>.tcbit.<zone> -- the nonce defeats recursor caching (a
	// cached answer would measure the recursor's cache, not its relay limit)
	// and s<N> is the requested payload size in bytes.
	tcbitLabel = "TCBIT"

	// tcbitMaxSize bounds what we will build, below the 65535 DNS message
	// maximum with room for headers and the question section.
	tcbitMaxSize = 60000

	// tcbitTXTChunk is the maximum length of one TXT character-string
	// (RFC 1035 3.3.14), so a large payload is split across several.
	tcbitTXTChunk = 255
)

// tcbitRequest is a parsed experiment query: the requested payload size.
type tcbitRequest struct{ size int }

// parseTCBitQuery reports whether name (uppercased, no trailing dot, zone
// suffix already stripped) is an experiment query, and the size it asks for.
//
// Accepts <anything>.S<N>.TCBIT and S<N>.TCBIT, so a caller may prefix a
// cache-busting nonce or not.
func parseTCBitQuery(label string) (tcbitRequest, bool) {
	parts := strings.Split(strings.ToUpper(label), ".")
	// Find the TCBIT label; the size label must sit immediately before it.
	for i, p := range parts {
		if p != tcbitLabel {
			continue
		}
		if i == 0 {
			return tcbitRequest{}, false // no size label
		}
		sz := parts[i-1]
		if !strings.HasPrefix(sz, "S") {
			return tcbitRequest{}, false
		}
		n, err := strconv.Atoi(sz[1:])
		if err != nil || n < 0 {
			return tcbitRequest{}, false
		}
		if n > tcbitMaxSize {
			n = tcbitMaxSize
		}
		return tcbitRequest{size: n}, true
	}
	return tcbitRequest{}, false
}

// tcbitTruncatedReply is the UDP answer: header only, TC=1, no records.
//
// This is the whole trick. A recursor seeing TC re-asks over TCP, so the answer
// it ultimately relays is bounded by TCP, not by the UDP path's ~1232-to-4096
// ceiling. It is also why the experiment cannot amplify: this reply is smaller
// than the query that provoked it.
func tcbitTruncatedReply(query []byte) []byte {
	reply := tcbitHeader(query, 0)
	reply[2] |= 0x02 // TC
	return append(reply, tcbitQuestion(query)...)
}

// tcbitSizedReply is the TCP answer: TXT records totalling about size bytes.
func tcbitSizedReply(query []byte, size int) []byte {
	question := tcbitQuestion(query)
	if question == nil {
		return nil
	}

	// Build the payload as TXT RRs. Each RR carries up to ~255*N bytes as
	// character-strings; several RRs keep any single RDATA well inside the
	// 16-bit RDLENGTH field.
	const perRR = 4 * tcbitTXTChunk
	var answers []byte
	rrs := 0
	for remaining := size; remaining > 0; {
		n := remaining
		if n > perRR {
			n = perRR
		}
		answers = append(answers, tcbitTXTRecord(n)...)
		remaining -= n
		rrs++
	}

	reply := tcbitHeader(query, rrs)
	reply = append(reply, question...)
	return append(reply, answers...)
}

// tcbitTXTRecord builds one TXT RR of about n payload bytes, pointing its owner
// name at the question via compression (0xC00C).
//
// TTL is ZERO on purpose: a cached large answer would make the sweep measure a
// recursor's cache rather than its relay limit, and would leave big records
// sitting in public caches after the experiment.
func tcbitTXTRecord(n int) []byte {
	var rdata []byte
	for remaining := n; remaining > 0; {
		c := remaining
		if c > tcbitTXTChunk {
			c = tcbitTXTChunk
		}
		rdata = append(rdata, byte(c))
		for i := 0; i < c; i++ {
			rdata = append(rdata, 'x')
		}
		remaining -= c
	}

	rr := []byte{0xC0, 0x0C}    // owner: pointer to the question name
	rr = append(rr, 0x00, 0x10) // TYPE = TXT (16)
	rr = append(rr, 0x00, 0x01) // CLASS = IN
	rr = append(rr, 0, 0, 0, 0) // TTL = 0
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(rdata)))
	rr = append(rr, rdlen[:]...)
	return append(rr, rdata...)
}

// tcbitHeader builds a 12-byte response header echoing the query's ID.
func tcbitHeader(query []byte, ancount int) []byte {
	h := make([]byte, 12)
	copy(h[0:2], query[0:2])
	h[2] = 0x84 // QR=1, AA=1
	h[3] = 0x00 // RCODE=0; RA left clear (we are authoritative, not recursing)
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], uint16(ancount))
	return h
}

// tcbitQuestion returns the query's question section verbatim, or nil if it is
// malformed. A response must echo the question, not just the ID.
func tcbitQuestion(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	off := 12
	for off < len(query) {
		l := int(query[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 { // compression pointer in a question: malformed
			return nil
		}
		off += l + 1
	}
	off += 4 // QTYPE + QCLASS
	if off > len(query) {
		return nil
	}
	return query[12:off]
}
