package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseDNSCarrierHello(t *testing.T) {
	good := strings.ToUpper(hex.EncodeToString(bytes.Repeat([]byte{0xAB}, dnsCarrierNonceLen))) + ".C"
	nonce, ok := parseDNSCarrierHello(good)
	if !ok {
		t.Fatalf("%q was not recognised as a carrier hello", good)
	}
	if !bytes.Equal(nonce, bytes.Repeat([]byte{0xAB}, dnsCarrierNonceLen)) {
		t.Errorf("nonce = %x, want the one in the label", nonce)
	}

	// Everything else must be refused, or TCP/53 starts answering things it
	// should not. A tunnel opcode reaching the carrier path would be worst.
	for _, bad := range []string{
		"ABCD.C", // nonce too short
		strings.Repeat("A", 2*dnsCarrierNonceLen) + ".D",    // wrong label
		"ZZZZ." + strings.Repeat("A", 2*dnsCarrierNonceLen), // reversed
		"NOTHEX" + strings.Repeat("0", 2*dnsCarrierNonceLen-6) + ".C",
		"H.1.ABC",   // a real tunnel handshake
		"T.ABC.DEF", // a real tunnel data query
		"ABC.S100.TCBIT",
		"C",
		"",
	} {
		if _, ok := parseDNSCarrierHello(bad); ok {
			t.Errorf("%q was accepted as a carrier hello", bad)
		}
	}
}

// The reply must carry the magic AND the client's nonce, because that pair is
// the only thing distinguishing our server from a portal's transparent DNS proxy
// answering on port 53 -- a connection that merely opens proves nothing there.
func TestDNSCarrierHelloReplyProvesTheServer(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5C}, dnsCarrierNonceLen)
	name := hex.EncodeToString(nonce) + ".c.t.pinghop.net"
	query := tcbitQuery(t, name)

	reply := dnsCarrierHelloReply(query, nonce)
	if reply == nil {
		t.Fatal("nil reply")
	}
	if binary.BigEndian.Uint16(reply[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
		t.Error("reply does not echo the query id")
	}
	if binary.BigEndian.Uint16(reply[6:8]) != 1 {
		t.Error("reply does not carry exactly one answer")
	}
	want := append(append([]byte{}, dnsCarrierMagic...), nonce...)
	if !bytes.Contains(reply, want) {
		t.Fatal("reply does not contain magic+nonce — a portal proxy would be indistinguishable")
	}
	// A DIFFERENT nonce must not satisfy the client's check.
	other := append(append([]byte{}, dnsCarrierMagic...), bytes.Repeat([]byte{0x00}, dnsCarrierNonceLen)...)
	if bytes.Contains(reply, other) {
		t.Error("reply matches a nonce it was not given")
	}
	// TTL 0: this answer must never be cached or reused.
	off := 12 + len(tcbitQuestion(query))
	if ttl := binary.BigEndian.Uint32(reply[off+6 : off+10]); ttl != 0 {
		t.Errorf("answer TTL = %d, want 0", ttl)
	}
}

// The client (tunnel/cmd/freewire-tunnel/dnstcp.go) hardcodes these. They are a
// cross-module wire contract: changing one side alone makes every carrier hello
// fail the magic check, which reads in the field as "the portal blocks TCP/53".
func TestDNSCarrierWireContractMatchesClient(t *testing.T) {
	if string(dnsCarrierMagic) != "FWDNSTCP1" {
		t.Errorf("dnsCarrierMagic = %q, want FWDNSTCP1", dnsCarrierMagic)
	}
	if dnsCarrierNonceLen != 16 {
		t.Errorf("dnsCarrierNonceLen = %d, want 16", dnsCarrierNonceLen)
	}
	if dnsCarrierLabel != "C" {
		t.Errorf("dnsCarrierLabel = %q, want C", dnsCarrierLabel)
	}
}

// The carrier hello and the probe must remain distinguishable on the shared
// TCP/53 listener: a DNS message opens with a small BE length, the probe with
// "FW" = 0x4657 = 17943, which is not a plausible DNS message length.
func TestProbeAndDNSFramingCannotBeConfused(t *testing.T) {
	probeHead := binary.BigEndian.Uint16(probeMagic[:2])
	if probeHead <= 4096 {
		t.Fatalf("probe magic reads as length %d, which is a plausible DNS message size — the TCP/53 dispatch is ambiguous", probeHead)
	}
}
