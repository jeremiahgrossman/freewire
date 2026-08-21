package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// ipPool hands out IPv4 addresses from a CIDR block. Thread-safe.
type ipPool struct {
	mu        sync.Mutex
	network   *net.IPNet
	allocated map[string]bool
	base      uint32 // first usable address (.2)
	last      uint32 // exclusive upper bound (broadcast address)
}

func newIPPool(network *net.IPNet, serverIP string) *ipPool {
	base := ipToUint32(network.IP.To4())
	mask := binary.BigEndian.Uint32(net.IP(network.Mask).To4())
	broadcast := base | ^mask

	return &ipPool{
		network:   network,
		allocated: map[string]bool{serverIP: true},
		base:      base + 2, // .0 is network, .1 is server
		last:      broadcast, // broadcast excluded by < comparison in Allocate
	}
}

func (p *ipPool) Allocate() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for n := p.base; n < p.last; n++ {
		ip := uint32ToIPStr(n)
		if !p.allocated[ip] {
			p.allocated[ip] = true
			return ip, nil
		}
	}
	return "", fmt.Errorf("ip pool exhausted")
}

func (p *ipPool) Release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.allocated, ip)
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
