package tunnel

import (
	"net"
	"sync"
	"testing"
)

func testPool(t *testing.T, cidr, serverIP string) *ipPool {
	t.Helper()
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr %q: %v", cidr, err)
	}
	return newIPPool(network, serverIP)
}

func TestAllocateStartsAfterServerIP(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	ip, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	if ip != "10.0.0.2" {
		t.Errorf("first allocation = %q, want 10.0.0.2", ip)
	}
}

func TestAllocateSkipsServerIP(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	for i := 0; i < 10; i++ {
		ip, err := p.Allocate()
		if err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
		if ip == "10.0.0.1" {
			t.Fatal("allocated the server IP")
		}
	}
}

func TestAllocateNeverRepeats(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	seen := map[string]bool{}
	for {
		ip, err := p.Allocate()
		if err != nil {
			break
		}
		if seen[ip] {
			t.Fatalf("duplicate allocation: %s", ip)
		}
		seen[ip] = true
	}
	// /24 minus network(.0), server(.1), broadcast(.255) = 253
	if len(seen) != 253 {
		t.Errorf("allocated %d addresses, want 253", len(seen))
	}
}

func TestAllocateExcludesBroadcast(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	for {
		ip, err := p.Allocate()
		if err != nil {
			break
		}
		if ip == "10.0.0.255" {
			t.Fatal("allocated the broadcast address")
		}
	}
}

// Regression: an earlier implementation advanced a cursor and never revisited
// released addresses, so a pool with churn would exhaust while mostly free.
func TestReleasedIPIsReused(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	first, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	p.Release(first)

	again, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate after release: %v", err)
	}
	if again != first {
		t.Errorf("got %q after releasing %q, want the released address back", again, first)
	}
}

// A double release must not push the address onto the free list twice, or two
// peers would later be handed the same tunnel IP.
func TestDoubleReleaseIsIgnored(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	ip, err := p.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	p.Release(ip)
	p.Release(ip)

	seen := map[string]bool{}
	for {
		got, err := p.Allocate()
		if err != nil {
			break
		}
		if seen[got] {
			t.Fatalf("address %s handed out twice after a double release", got)
		}
		seen[got] = true
	}
}

func TestReleaseUnknownAddressIsIgnored(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	before := p.Size()
	p.Release("10.0.0.99") // never allocated
	p.Release("not-an-ip")
	p.Release("192.168.1.1") // outside the pool
	if got := p.Size(); got != before {
		t.Errorf("size changed from %d to %d after releasing unallocated addresses", before, got)
	}
}

func TestPoolSurvivesRepeatedChurn(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	for i := 0; i < 5000; i++ {
		ip, err := p.Allocate()
		if err != nil {
			t.Fatalf("exhausted after %d allocate/release cycles: %v", i, err)
		}
		p.Release(ip)
	}
}

func TestExhaustionReturnsError(t *testing.T) {
	p := testPool(t, "10.0.0.0/29", "10.0.0.1")
	// /29 = .0-.7; usable .2-.6 = 5 addresses
	for i := 0; i < 5; i++ {
		if _, err := p.Allocate(); err != nil {
			t.Fatalf("allocate %d: %v", i, err)
		}
	}
	if _, err := p.Allocate(); err == nil {
		t.Fatal("expected exhaustion error, got nil")
	}
}

func TestSizeTracksAllocations(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")
	if got := p.Size(); got != 1 {
		t.Errorf("initial size = %d, want 1 (server IP)", got)
	}
	ip, _ := p.Allocate()
	if got := p.Size(); got != 2 {
		t.Errorf("size after one allocation = %d, want 2", got)
	}
	p.Release(ip)
	if got := p.Size(); got != 1 {
		t.Errorf("size after release = %d, want 1", got)
	}
}

func TestConcurrentAllocateIsRaceFree(t *testing.T) {
	p := testPool(t, "10.0.0.0/24", "10.0.0.1")

	const workers = 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]bool{}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			ip, err := p.Allocate()
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if got[ip] {
				t.Errorf("two goroutines received the same address: %s", ip)
			}
			got[ip] = true
		}()
	}
	wg.Wait()

	if len(got) != workers {
		t.Errorf("allocated %d unique addresses across %d goroutines", len(got), workers)
	}
}

func TestUint32IPRoundTrip(t *testing.T) {
	for _, s := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "255.255.255.255", "0.0.0.0"} {
		n := ipToUint32(net.ParseIP(s).To4())
		if back := uint32ToIPStr(n); back != s {
			t.Errorf("round trip %q -> %d -> %q", s, n, back)
		}
	}
}

// newIPPool indexed the result of To4() without checking it, so an IPv6 or
// malformed tunnel_cidr crashed the server on startup with a runtime error
// instead of a message naming the field.
func TestNewIPPoolRejectsNonIPv4(t *testing.T) {
	for _, cidr := range []string{"fd00::/64", "2001:db8::/32", "::1/128"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		if p := newIPPool(network, "10.0.0.1"); p != nil {
			t.Errorf("%s: returned a pool for a non-IPv4 network", cidr)
		}
	}
}

func TestNewIPPoolRejectsNilNetwork(t *testing.T) {
	if p := newIPPool(nil, "10.0.0.1"); p != nil {
		t.Error("returned a pool for a nil network")
	}
}

func TestNewIPPoolAcceptsIPv4(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/24", "192.168.5.0/24", "172.16.0.0/16"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		if p := newIPPool(network, "10.0.0.1"); p == nil {
			t.Errorf("%s: rejected a usable IPv4 network", cidr)
		}
	}
}
