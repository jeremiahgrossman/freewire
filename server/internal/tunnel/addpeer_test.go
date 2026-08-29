package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
)

func randKeyB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// rejectionManager builds a Manager with no WireGuard device.
//
// AddPeer needs a real device to complete, so only its rejection paths can be
// exercised here -- which is exactly what these tests cover. Every case below
// must return before the IPC call; if one ever stops doing so it will panic on
// the nil device rather than pass quietly.
func rejectionManager(t *testing.T, existing map[string]string) *Manager {
	t.Helper()
	_, network, err := net.ParseCIDR("10.0.0.0/24")
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	peers := map[string]*Peer{}
	pool := newIPPool(network, "10.0.0.1")
	for token, key := range existing {
		ip, err := pool.Allocate()
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		peers[token] = &Peer{PublicKey: key, TunnelIP: ip}
	}
	return &Manager{
		pool:  pool,
		peers: peers,
	}
}

// A client that dies without sending DELETE holds its slot until it expires. On
// a server with one slot that is forever, so re-presenting the key displaces
// the stale registration instead of being refused. The caller proved possession
// of the key by presenting it, which is what the original registration rested
// on too.
func TestAddPeerReplacesStaleRegistration(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"stale-token": key})
	staleIP := m.peers["stale-token"].TunnelIP

	peer, staleToken, releasedIP, err := m.reserveSlot("fresh-token", key, 10)
	if err != nil {
		t.Fatalf("re-registering an owned key was refused: %v", err)
	}
	if staleToken != "stale-token" {
		t.Errorf("displaced token = %q, want stale-token", staleToken)
	}
	if releasedIP != staleIP {
		t.Errorf("released ip = %q, want %q", releasedIP, staleIP)
	}
	if _, still := m.peers["stale-token"]; still {
		t.Error("the stale registration survived its replacement")
	}
	if m.peers["fresh-token"] != peer {
		t.Error("the new token was not registered")
	}
	if got := m.PeerCount(); got != 1 {
		t.Errorf("peer count = %d after a replacement, want 1", got)
	}
}

// Capacity binds only on registrations that add a peer. A replacement is
// net-neutral, and refusing it on a full server is exactly the lockout that
// displacement exists to prevent.
func TestReplacementIsAllowedAtCapacity(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"stale-token": key})

	if _, _, _, err := m.reserveSlot("fresh-token", key, 1); err != nil {
		t.Fatalf("a full server refused to replace its own stale peer: %v", err)
	}
}

// The same token re-presenting its own key is the ordinary reconnect case.
func TestAddPeerReregistrationBySameToken(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"tok": key})

	if _, staleToken, _, err := m.reserveSlot("tok", key, 10); err != nil {
		t.Fatalf("re-registering the same key under the same token failed: %v", err)
	} else if staleToken != "tok" {
		t.Errorf("displaced token = %q, want tok", staleToken)
	}
	if got := m.PeerCount(); got != 1 {
		t.Errorf("peer count = %d after a self-replacement, want 1", got)
	}
}

func TestAddPeerRejectsMalformedKeys(t *testing.T) {
	m := rejectionManager(t, nil)

	for name, key := range map[string]string{
		"not base64": "!!!!not-base64!!!!",
		"too short":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"empty":      "",
		"all zero":   base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		if _, err := m.AddPeer("tok-"+name, key, 10); err == nil {
			t.Errorf("%s: accepted an invalid public key", name)
		}
	}
}

// A rejection must not consume a capacity slot or a pool address.
func TestRejectedRegistrationLeavesNoResidue(t *testing.T) {
	m := rejectionManager(t, map[string]string{"victim-token": randKeyB64(t)})

	beforePeers := m.PeerCount()
	beforePool := m.pool.Size()

	for i := 0; i < 5; i++ {
		m.AddPeer("attacker", "!!!bad!!!", 10)  //nolint:errcheck
		m.AddPeer("attacker", "", 10)           //nolint:errcheck
		m.AddPeer("attacker", randKeyB64(t), 1) //nolint:errcheck  at capacity
	}

	if got := m.PeerCount(); got != beforePeers {
		t.Errorf("peer count moved from %d to %d on rejected registrations", beforePeers, got)
	}
	if got := m.pool.Size(); got != beforePool {
		t.Errorf("pool allocations moved from %d to %d on rejected registrations", beforePool, got)
	}
}

// Capacity is checked before the duplicate scan, so a full server rejects on
// capacity rather than leaking whether a key is registered.
func TestAddPeerRejectsAtCapacity(t *testing.T) {
	m := rejectionManager(t, map[string]string{"a": randKeyB64(t)})
	if _, err := m.AddPeer("b", randKeyB64(t), 1); err == nil {
		t.Error("registration succeeded on a server already at capacity")
	}
}

// restorePeer must reject the same malformed keys AddPeer does, and must do so
// before touching the (nil, in this test) WireGuard device -- restore runs at
// startup over a file nothing has validated since it was written.
func TestRestorePeerRejectsMalformedKeys(t *testing.T) {
	m := rejectionManager(t, nil)

	for name, key := range map[string]string{
		"not base64": "!!!!not-base64!!!!",
		"too short":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"empty":      "",
		"all zero":   base64.StdEncoding.EncodeToString(make([]byte, 32)),
	} {
		rp := persistedPeer{PeerToken: "tok-" + name, PublicKey: key, TunnelIP: "10.0.0.50"}
		if err := m.restorePeer(rp); err == nil {
			t.Errorf("%s: accepted an invalid public key", name)
		}
	}
	if got := m.PeerCount(); got != 0 {
		t.Errorf("a rejected restore left %d peers behind, want 0", got)
	}
}

// A peers-file entry claiming an address another restored peer (or a live
// registration) already holds must be skipped, not silently steal the
// address.
func TestRestorePeerRejectsAddressCollision(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"existing-token": key})
	takenIP := m.peers["existing-token"].TunnelIP

	rp := persistedPeer{PeerToken: "new-token", PublicKey: randKeyB64(t), TunnelIP: takenIP}
	if err := m.restorePeer(rp); err == nil {
		t.Error("restorePeer accepted an address already held by another peer")
	}
	if got := m.PeerCount(); got != 1 {
		t.Errorf("peer count = %d after a rejected restore, want 1 (unchanged)", got)
	}
}

// The pool reservation for a rejected restore must not leak: a run of bad
// entries must not exhaust addresses that legitimate registrations need.
func TestRestorePeerLeavesNoResidueOnRejection(t *testing.T) {
	m := rejectionManager(t, nil)
	before := m.pool.Size()

	for i := 0; i < 5; i++ {
		m.restorePeer(persistedPeer{PeerToken: "bad", PublicKey: "!!!not valid!!!", TunnelIP: "10.0.0.60"}) //nolint:errcheck
	}
	if got := m.pool.Size(); got != before {
		t.Errorf("pool allocations moved from %d to %d on rejected restores", before, got)
	}
}
