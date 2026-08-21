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
	for token, key := range existing {
		peers[token] = &Peer{PublicKey: key}
	}
	return &Manager{
		pool:  newIPPool(network, "10.0.0.1"),
		peers: peers,
	}
}

// Registration is unauthenticated and replace_allowed_ips makes the peer line
// authoritative, so re-registering a key already in use rewrote the original
// peer's allowed_ip to a new address -- silently cutting off their traffic and
// letting the caller then remove them. A public key is not secret: it crosses
// the API in the clear and is derivable from any captured handshake.
func TestAddPeerRejectsDuplicatePublicKey(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"victim-token": key})

	if _, err := m.AddPeer("attacker-token", key, 10); err == nil {
		t.Error("a second token was allowed to claim an already-registered key")
	}
}

func TestAddPeerRejectsReregistrationBySameToken(t *testing.T) {
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"tok": key})

	if _, err := m.AddPeer("tok", key, 10); err == nil {
		t.Error("re-registering the same key under the same token was allowed")
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
	key := randKeyB64(t)
	m := rejectionManager(t, map[string]string{"victim-token": key})

	beforePeers := m.PeerCount()
	beforePool := m.pool.Size()

	for i := 0; i < 5; i++ {
		m.AddPeer("attacker", key, 10)         //nolint:errcheck
		m.AddPeer("attacker", "!!!bad!!!", 10) //nolint:errcheck
		m.AddPeer("attacker", "", 10)          //nolint:errcheck
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
