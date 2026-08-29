package main

import (
	"encoding/binary"
	"testing"
)

func TestDomainAllowed(t *testing.T) {
	domains := []string{"signal.org", "apple.com"}
	allow := []string{"signal.org", "chat.signal.org", "cdn.a.signal.org", "APPLE.COM", "push.apple.com", "signal.org."}
	deny := []string{"notsignal.org", "signal.org.evil.com", "example.com", "orgsignal.org", ""}
	for _, q := range allow {
		if !domainAllowed(q, domains) {
			t.Errorf("domainAllowed(%q) = false, want true", q)
		}
	}
	for _, q := range deny {
		if domainAllowed(q, domains) {
			t.Errorf("domainAllowed(%q) = true, want false", q)
		}
	}
}

func TestNormalizeEssentialsDomain(t *testing.T) {
	cases := map[string]string{
		"Signal.org":     "signal.org",
		"*.apple.com":    "apple.com",
		"chat.signal.org.": "chat.signal.org",
		"  mail.me.com ": "mail.me.com",
		"localhost":      "", // no dot
		"has space.com":  "", // invalid char
		"under_score.com": "", // underscore is not a hostname char
		"":               "",
	}
	for in, want := range cases {
		if got := normalizeEssentialsDomain(in); got != want {
			t.Errorf("normalizeEssentialsDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// Build a minimal DNS query for name (A record) and confirm essentialsQueryName
// decodes it, dotted and lowercased.
func TestEssentialsQueryName(t *testing.T) {
	q := buildQuery("Chat.Signal.ORG")
	name, ok := essentialsQueryName(q)
	if !ok || name != "chat.signal.org" {
		t.Fatalf("essentialsQueryName = %q, %v; want chat.signal.org, true", name, ok)
	}
	if _, ok := essentialsQueryName([]byte{0, 1, 2}); ok {
		t.Error("a too-short message should not parse")
	}
}

// Build a reply carrying one A (1.2.3.4) and one AAAA (2001:db8::1) and confirm
// both are extracted.
func TestExtractAnswerIPs(t *testing.T) {
	reply := buildReply("signal.org",
		[4]byte{1, 2, 3, 4},
		[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	ips := extractAnswerIPs(reply)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "2001:db8::1" {
		t.Fatalf("extractAnswerIPs = %v, want [1.2.3.4 2001:db8::1]", ips)
	}
	// An error reply (rcode != 0) yields nothing.
	bad := buildReply("x.org", [4]byte{9, 9, 9, 9}, [16]byte{})
	bad[3] |= 0x03 // NXDOMAIN
	if got := extractAnswerIPs(bad); got != nil {
		t.Errorf("error reply should extract no IPs, got %v", got)
	}
}

func TestRefuseReplies(t *testing.T) {
	q := buildQuery("blocked.example.com")
	for name, fn := range map[string]func([]byte) []byte{
		"nxdomain": nxdomainReply, "servfail": servfailReply, "refused": refusedReply,
	} {
		r := fn(q)
		if len(r) < 12 {
			t.Fatalf("%s reply too short", name)
		}
		if r[2]&0x80 == 0 {
			t.Errorf("%s: QR bit not set (not a response)", name)
		}
		if binary.BigEndian.Uint16(r[6:8]) != 0 {
			t.Errorf("%s: ANCOUNT should be 0", name)
		}
	}
	// The rcodes are the DNS-standard values.
	if nxdomainReply(q)[3]&0x0F != 3 {
		t.Error("nxdomain rcode should be 3")
	}
	if refusedReply(q)[3]&0x0F != 5 {
		t.Error("refused rcode should be 5")
	}
}

// The scoped resolver's upstream must never be a carrier resolver (which is
// pinned OUTSIDE the tunnel), or routing the same IP INTO the tunnel breaks the
// carrier.
func TestEssentialsUpstreamAvoidsCarrierResolver(t *testing.T) {
	if got := essentialsUpstream(nil); got != "1.1.1.1:53" {
		t.Errorf("no carrier resolvers -> %q, want 1.1.1.1:53", got)
	}
	if got := essentialsUpstream([]string{"1.1.1.1:53"}); got != "8.8.8.8:53" {
		t.Errorf("carrier=1.1.1.1 -> %q, want 8.8.8.8:53 (avoid collision)", got)
	}
	// Bare IPs (no port) are matched too.
	if got := essentialsUpstream([]string{"1.1.1.1", "8.8.8.8"}); got != "9.9.9.9:53" {
		t.Errorf("carrier=1.1.1.1,8.8.8.8 -> %q, want 9.9.9.9:53", got)
	}
}

// --- DNS wire-format builders for the tests ---

func encodeName(name string) []byte {
	var out []byte
	label := []byte{}
	flush := func() {
		out = append(out, byte(len(label)))
		out = append(out, label...)
		label = nil
	}
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			flush()
		} else {
			label = append(label, name[i])
		}
	}
	flush()
	out = append(out, 0) // root
	return out
}

func buildQuery(name string) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	msg = append(msg, encodeName(name)...)
	msg = append(msg, 0, 1, 0, 1) // type A, class IN
	return msg
}

func buildReply(name string, a4 [4]byte, a16 [16]byte) []byte {
	msg := buildQuery(name)
	msg[2] |= 0x80                            // QR
	binary.BigEndian.PutUint16(msg[6:8], 2)   // ANCOUNT = 2
	// Answer 1: A. Name via compression pointer to offset 12 (the question name).
	msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	msg = append(msg, a4[:]...)
	// Answer 2: AAAA.
	msg = append(msg, 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	msg = append(msg, a16[:]...)
	return msg
}
