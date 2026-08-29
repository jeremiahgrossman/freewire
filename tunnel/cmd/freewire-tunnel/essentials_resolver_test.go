package main

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		"Signal.org":       "signal.org",
		"*.apple.com":      "apple.com",
		"chat.signal.org.": "chat.signal.org",
		"  mail.me.com ":   "mail.me.com",
		"localhost":        "", // no dot
		"has space.com":    "", // invalid char
		"under_score.com":  "", // underscore is not a hostname char
		"":                 "",
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

// handle() is the resolver's core: allowlisted names are forwarded to the
// upstream and their IPs routed; everything else is NXDOMAIN with no forward and
// no route. Tested against a mock upstream, no listener/root/tunnel needed.
func TestResolverHandleAllowAndRefuse(t *testing.T) {
	// Mock upstream: answers every query with A 1.2.3.4 (+ an AAAA), and records
	// whether it was hit, so we can assert a refused name is never forwarded.
	up, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	var hits int32
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			atomic.AddInt32(&hits, 1)
			name, _ := essentialsQueryName(buf[:n])
			up.WriteTo(buildReply(name, [4]byte{1, 2, 3, 4},
				[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), from) //nolint:errcheck
		}
	}()

	var routed []string
	var rmu sync.Mutex
	r := &essentialsResolver{
		domains:  []string{"signal.org"},
		upstream: up.LocalAddr().String(),
		routed:   map[string]bool{},
		addRoute: func(ip string) { rmu.Lock(); routed = append(routed, ip); rmu.Unlock() },
	}

	// Allowlisted: forwarded, answered, and the A IP routed.
	reply := r.handle(buildQuery("chat.signal.org")) // a subdomain
	if reply[3]&0x0F != 0 {
		t.Fatalf("allowlisted query got rcode %d, want NOERROR", reply[3]&0x0F)
	}
	if got := extractAnswerIPs(reply); len(got) == 0 || got[0] != "1.2.3.4" {
		t.Fatalf("allowlisted answer = %v, want it to include 1.2.3.4", got)
	}
	rmu.Lock()
	sawA := false
	for _, ip := range routed {
		if ip == "1.2.3.4" {
			sawA = true
		}
	}
	rmu.Unlock()
	if !sawA {
		t.Errorf("allowlisted resolve did not route 1.2.3.4 into the tunnel; routed=%v", routed)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Error("allowlisted query was not forwarded to the upstream")
	}

	// Non-allowlisted: NXDOMAIN, and the upstream is NOT hit.
	before := atomic.LoadInt32(&hits)
	deny := r.handle(buildQuery("tracker.evil.com"))
	if deny[3]&0x0F != 3 {
		t.Errorf("non-allowlisted query rcode = %d, want NXDOMAIN(3)", deny[3]&0x0F)
	}
	if atomic.LoadInt32(&hits) != before {
		t.Error("a non-allowlisted query was forwarded to the upstream (should be refused locally)")
	}

	// routeOnce dedups: a second resolve of the same IP does not re-route.
	rmu.Lock()
	n1 := len(routed)
	rmu.Unlock()
	r.handle(buildQuery("signal.org"))
	rmu.Lock()
	n2 := len(routed)
	rmu.Unlock()
	if n2 != n1 {
		t.Errorf("re-resolving an already-routed IP added routes again (%d -> %d); dedup broken", n1, n2)
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
	msg[2] |= 0x80                          // QR
	binary.BigEndian.PutUint16(msg[6:8], 2) // ANCOUNT = 2
	// Answer 1: A. Name via compression pointer to offset 12 (the question name).
	msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	msg = append(msg, a4[:]...)
	// Answer 2: AAAA.
	msg = append(msg, 0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	msg = append(msg, a16[:]...)
	return msg
}

// flakyUpstream answers only after dropping the first `drop` queries, modelling
// the real failure: a still-settling tunnel swallowing the first datagram(s).
func flakyUpstream(t *testing.T, drop int32) (addr string, hits *int32, stop func()) {
	t.Helper()
	up, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n int32
	go func() {
		buf := make([]byte, 4096)
		for {
			c, from, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			if atomic.AddInt32(&n, 1) <= drop {
				continue // silently drop, exactly as a lost packet would
			}
			name, _ := essentialsQueryName(buf[:c])
			up.WriteTo(buildReply(name, [4]byte{5, 6, 7, 8},
				[16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), from) //nolint:errcheck
		}
	}()
	return up.LocalAddr().String(), &n, func() { up.Close() }
}

func newTestResolver(upstream string) *essentialsResolver {
	return &essentialsResolver{
		domains:  []string{"signal.org"},
		upstream: upstream,
		routed:   map[string]bool{},
		addRoute: func(string) {},
	}
}

// The regression this retry exists for. A single dropped first packet used to
// become SERVFAIL, which at a café is the user's first allowlisted lookup after
// tapping "Try messaging & email only". Reproduced on a routed desk run
// (2026-08-28) on the session's cold first connect.
func TestForwardRetriesPastADroppedFirstPacket(t *testing.T) {
	addr, hits, stop := flakyUpstream(t, 1)
	defer stop()
	r := newTestResolver(addr)

	reply := r.handle(buildQuery("chat.signal.org"))
	if rcode := reply[3] & 0x0F; rcode != 0 {
		t.Fatalf("rcode = %d, want NOERROR — one dropped packet still became a failure", rcode)
	}
	if got := extractAnswerIPs(reply); len(got) == 0 || got[0] != "5.6.7.8" {
		t.Fatalf("answer = %v, want the upstream's 5.6.7.8", got)
	}
	if n := atomic.LoadInt32(hits); n != 2 {
		t.Errorf("upstream saw %d queries, want 2 (one dropped, one answered)", n)
	}
}

// It must survive losing every attempt but the last, and no more than that.
//
// The policy is swapped for short timeouts so the suite does not pay two real
// budgets (13s) to assert control flow. The shipped values are pinned separately
// by TestForwardPolicyIsFieldPlausible, so shortening here cannot hide a bad one.
func TestForwardExhaustsBudgetThenServfails(t *testing.T) {
	restore := essentialsForwardTimeouts
	essentialsForwardTimeouts = []time.Duration{80 * time.Millisecond, 80 * time.Millisecond, 80 * time.Millisecond}
	defer func() { essentialsForwardTimeouts = restore }()
	attempts := len(essentialsForwardTimeouts)

	// Drops all but the final attempt: still answered.
	addr, hits, stop := flakyUpstream(t, int32(attempts-1))
	defer stop()
	reply := newTestResolver(addr).handle(buildQuery("signal.org"))
	if rcode := reply[3] & 0x0F; rcode != 0 {
		t.Fatalf("rcode = %d, want NOERROR on the last allowed attempt", rcode)
	}
	if n := atomic.LoadInt32(hits); int(n) != attempts {
		t.Errorf("upstream saw %d queries, want %d (the full budget)", n, attempts)
	}

	// Drops everything: SERVFAIL, and it must not retry forever.
	addr2, hits2, stop2 := flakyUpstream(t, 1000)
	defer stop2()
	reply2 := newTestResolver(addr2).handle(buildQuery("signal.org"))
	if rcode := reply2[3] & 0x0F; rcode != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL (2) once the budget is spent", rcode)
	}
	if n := atomic.LoadInt32(hits2); int(n) != attempts {
		t.Errorf("upstream saw %d queries, want exactly %d — the retry is unbounded", n, attempts)
	}
}

// A refused name must never be forwarded, retries or not: NXDOMAIN stays instant,
// which is what makes a DNS takeover tolerable on a slow carrier.
func TestRefusedNamesAreNeverRetried(t *testing.T) {
	addr, hits, stop := flakyUpstream(t, 0)
	defer stop()

	start := time.Now()
	reply := newTestResolver(addr).handle(buildQuery("example.com"))
	elapsed := time.Since(start)

	if rcode := reply[3] & 0x0F; rcode != 3 {
		t.Fatalf("rcode = %d, want NXDOMAIN (3)", rcode)
	}
	if n := atomic.LoadInt32(hits); n != 0 {
		t.Errorf("upstream saw %d queries for a refused name, want 0", n)
	}
	if elapsed > time.Second {
		t.Errorf("refusal took %s, want it instant — a refused name must not pay the retry budget", elapsed)
	}
}

// Pins the SHIPPED retry policy, which the test above deliberately overrides.
// These numbers are a field judgement, not an implementation detail: more than
// one attempt (the whole point), escalating deadlines so a warm path pays little,
// and a total budget in the range a stub resolver still waits for -- answering
// after the client gave up converts a visible failure into an invisible one.
func TestForwardPolicyIsFieldPlausible(t *testing.T) {
	if len(essentialsForwardTimeouts) < 2 {
		t.Fatalf("only %d attempt(s): a single lost packet becomes SERVFAIL again",
			len(essentialsForwardTimeouts))
	}
	for i := 1; i < len(essentialsForwardTimeouts); i++ {
		if essentialsForwardTimeouts[i] < essentialsForwardTimeouts[i-1] {
			t.Errorf("attempt %d (%s) is shorter than attempt %d (%s): deadlines must not shrink",
				i, essentialsForwardTimeouts[i], i-1, essentialsForwardTimeouts[i-1])
		}
	}
	if b := essentialsForwardBudget(); b < 4*time.Second || b > 10*time.Second {
		t.Errorf("budget %s is outside 4s..10s — too short for a throttled carrier, or past what a stub resolver waits", b)
	}
}

// The TCP listener's deadline has to outlast the forward budget, or a retrying
// query is cut off by its own listener before the last attempt finishes.
func TestTCPDeadlineOutlastsForwardBudget(t *testing.T) {
	if got := essentialsForwardBudget(); got < 4*time.Second {
		t.Errorf("forward budget %s is implausibly short for a throttled carrier", got)
	}
	// handleTCP uses budget+4s; assert the margin is real rather than negative.
	if essentialsForwardBudget()+4*time.Second <= essentialsForwardBudget() {
		t.Fatal("TCP deadline does not exceed the forward budget")
	}
}
