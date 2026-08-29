package transport

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// The DNS-over-TCP carrier's handshake.
//
// WHY THIS CARRIER EXISTS. The UDP DNS carrier is what survives the hardest
// captive portals, and it is also where this project keeps losing: café #3 died
// at queue 256/256 under whole-machine load while the carrier itself still had
// headroom. Two of its three ceilings are properties of UDP DNS rather than of
// DNS:
//
//   - Per-query payload. UDP answers are capped by the advertised EDNS0 buffer
//     (~4096 for us, ~2400 of plaintext after base32's 8/5 inflation). Over TCP
//     a DNS message runs to 64KB, and the TC-bit sweep measured 60000 bytes
//     relayed end to end by Google and Quad9 -- ~15x.
//   - Backpressure. The UDP send path has none: excess is tail-dropped
//     indiscriminately, including the egress probe's own packets, which is how a
//     throttled café tears the tunnel down. TCP has flow control by
//     construction, so offered load is paced by the carrier instead of drowning
//     it. That is the deferred Stage-2 backpressure work, obtained structurally
//     rather than by a custom wireguard-go Bind.
//
// The third ceiling, a recursor's ~14 unique names/s, does not apply here at
// all: this carrier is server-direct, so no recursor is in the path.
//
// FRAMING. After the hello the connection carries [2-byte BE length][packet],
// which is RFC 7766's own DNS-over-TCP framing, so the stream stays well-framed
// for anything parsing port 53 -- the message CONTENTS are not DNS, which is an
// honest limit of the camouflage. Our field data says portals gate 53 by
// destination and port rather than inspecting message bodies; against a portal
// that does inspect them this fails like every content-evasion approach the
// research already ruled out.
//
// The hello itself is a real DNS query, so the first bytes on the wire are
// exactly what a resolver would send.

// dnsCarrierMagic opens the hello's TXT answer, so a client can tell OUR server
// from a portal's transparent DNS proxy answering on port 53. A proxy can return
// NXDOMAIN or a forged record; it cannot produce this plus the client's nonce.
var dnsCarrierMagic = []byte("FWDNSTCP1")

// dnsCarrierNonceLen is the hello nonce, echoed in the reply.
const dnsCarrierNonceLen = 16

// dnsCarrierLabel marks a hello: <hex nonce>.c.<zone>.
const dnsCarrierLabel = "C"

// parseDNSCarrierHello reports whether inner (uppercased, zone suffix already
// stripped) is a carrier hello, and returns the nonce it carries.
func parseDNSCarrierHello(inner string) ([]byte, bool) {
	parts := strings.Split(inner, ".")
	if len(parts) != 2 || parts[1] != dnsCarrierLabel {
		return nil, false
	}
	nonce, err := hex.DecodeString(strings.ToLower(parts[0]))
	if err != nil || len(nonce) != dnsCarrierNonceLen {
		return nil, false
	}
	return nonce, true
}

// dnsCarrierHelloReply builds the DNS response to a hello: one TXT record
// carrying the magic and the client's nonce.
func dnsCarrierHelloReply(query []byte, nonce []byte) []byte {
	question := tcbitQuestion(query)
	if question == nil {
		return nil
	}
	payload := append(append([]byte{}, dnsCarrierMagic...), nonce...)

	rdata := append([]byte{byte(len(payload))}, payload...)
	rr := []byte{0xC0, 0x0C}    // owner: pointer to the question name
	rr = append(rr, 0x00, 0x10) // TYPE = TXT
	rr = append(rr, 0x00, 0x01) // CLASS = IN
	rr = append(rr, 0, 0, 0, 0) // TTL = 0: never cached, never reused
	var rdlen [2]byte
	binary.BigEndian.PutUint16(rdlen[:], uint16(len(rdata)))
	rr = append(rr, rdlen[:]...)
	rr = append(rr, rdata...)

	reply := tcbitHeader(query, 1)
	reply = append(reply, question...)
	return append(reply, rr...)
}
