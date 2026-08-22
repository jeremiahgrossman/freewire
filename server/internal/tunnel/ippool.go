package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// ipPool hands out IPv4 addresses from a CIDR block. Thread-safe.
//
// Addresses are tracked as uint32 and handed out from a free list, so Allocate
// is O(1) and does no string work. An earlier linear scan formatted every
// candidate address to a string on each attempt, all while holding the lock.
type ipPool struct {
	mu        sync.Mutex
	network   *net.IPNet
	free      []uint32 // available addresses, taken from the tail
	allocated map[uint32]struct{}
	reserved  int // addresses excluded from the pool (network, server, broadcast)
}

// newIPPool builds a pool over network.
//
// Returns nil for anything that is not a usable IPv4 CIDR. To4() yields nil for
// an IPv6 or malformed network, and indexing that nil panicked the server on
// startup: a typo in the config file crashed the process with a runtime error
// rather than a message naming the field.
func newIPPool(network *net.IPNet, serverIP string) *ipPool {
	if network == nil || network.IP.To4() == nil || len(network.Mask) != net.IPv4len {
		return nil
	}
	base := ipToUint32(network.IP.To4())
	mask := binary.BigEndian.Uint32(net.IP(network.Mask).To4())
	broadcast := base | ^mask

	// Usable range is base+2 (skipping .0 network and .1 server) up to but not
	// including the broadcast address.
	var free []uint32
	for n := base + 2; n < broadcast; n++ {
		free = append(free, n)
	}
	// Reverse so the lowest address is at the tail and gets handed out first,
	// which keeps assignment order predictable for anyone reading logs.
	for i, j := 0, len(free)-1; i < j; i, j = i+1, j-1 {
		free[i], free[j] = free[j], free[i]
	}

	p := &ipPool{
		network:   network,
		free:      free,
		allocated: make(map[uint32]struct{}, len(free)),
	}

	// The server address is never handed out. It is counted in Size so callers
	// see the same occupancy the old string-keyed map reported.
	if ip := net.ParseIP(serverIP); ip != nil && ip.To4() != nil {
		p.allocated[ipToUint32(ip.To4())] = struct{}{}
		p.reserved = 1
	}
	return p
}

func (p *ipPool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.free) == 0 {
		return "", fmt.Errorf("ip pool exhausted")
	}
	n := p.free[len(p.free)-1]
	p.free = p.free[:len(p.free)-1]
	p.allocated[n] = struct{}{}
	return uint32ToIPStr(n), nil
}

func (p *ipPool) Release(ip string) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return
	}
	n := ipToUint32(parsed.To4())

	p.mu.Lock()
	defer p.mu.Unlock()

	// Releasing an address that is not allocated must not grow the free list, or
	// a double release would hand the same address to two peers.
	if _, ok := p.allocated[n]; !ok {
		return
	}
	delete(p.allocated, n)
	p.free = append(p.free, n)
}

func (p *ipPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.allocated)
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIPStr(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}
