package tunnel

import (
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"go.uber.org/zap"
)

// persist() must serialize its own snapshot-then-write against concurrent
// calls. An earlier version guarded only the snapshot (a brief RLock), so two
// concurrent persist() calls -- e.g. one from an AddPeer, one from a
// RemovePeer racing it -- could take their snapshots in one order but land
// their disk WRITES in the other. The disk could then hold the staler of the
// two snapshots: a live peer silently missing (never restored on the next
// restart) or a just-revoked peer's key resurrected on one. Found by
// adversarial review 2026-08-30; this reproduces it directly against
// persist() rather than through AddPeer/RemovePeer, which need a real
// WireGuard device this package's tests don't have.
func TestPersistSerializesConcurrentWrites(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	m := &Manager{
		pool:      newIPPool(network, "10.0.0.1"),
		peers:     map[string]*Peer{},
		peersPath: filepath.Join(t.TempDir(), "peers.json"),
		log:       zap.NewNop(),
	}

	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("tok-%d", i)
			m.mu.Lock()
			m.peers[token] = &Peer{
				PublicKey: fmt.Sprintf("key-%d", i),
				TunnelIP:  fmt.Sprintf("10.0.0.%d", i+2),
			}
			m.mu.Unlock()
			m.persist()
		}(i)
	}
	wg.Wait()

	// The final on-disk file must reflect every peer added, not a partial
	// snapshot from a call that lost the write race against a staler one.
	onDisk := loadPeersFile(m.peersPath, zap.NewNop())
	if len(onDisk) != n {
		t.Fatalf("disk has %d peers after %d concurrent persist() calls, want %d -- "+
			"a stale snapshot's write landed after a fresher one", len(onDisk), n, n)
	}
}

// A persist() that runs after a peer is removed must not leave that peer on
// disk -- the mirror case of the test above, closer to the real
// AddPeer/RemovePeer race the review described.
func TestPersistReflectsLatestStateAfterRemoval(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	m := &Manager{
		pool:      newIPPool(network, "10.0.0.1"),
		peers:     map[string]*Peer{},
		peersPath: filepath.Join(t.TempDir(), "peers.json"),
		log:       zap.NewNop(),
	}

	m.mu.Lock()
	m.peers["stays"] = &Peer{PublicKey: "keyA", TunnelIP: "10.0.0.2"}
	m.peers["removed"] = &Peer{PublicKey: "keyB", TunnelIP: "10.0.0.3"}
	m.mu.Unlock()
	m.persist()

	m.mu.Lock()
	delete(m.peers, "removed")
	m.mu.Unlock()
	m.persist()

	onDisk := loadPeersFile(m.peersPath, zap.NewNop())
	if len(onDisk) != 1 || onDisk[0].PeerToken != "stays" {
		t.Fatalf("after removal, disk holds %+v, want exactly the surviving peer", onDisk)
	}
}
