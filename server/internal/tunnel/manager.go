package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/freewire/server/internal/config"
)

// Peer holds the in-memory state for a connected peer.
type Peer struct {
	PublicKey  string
	TunnelIP   string
	TunnelIPv6 string
}

// Manager owns the WireGuard device and peer lifecycle.
type Manager struct {
	dev   *device.Device
	log   *zap.Logger
	pool  *ipPool
	mu    sync.RWMutex
	peers map[string]*Peer // peer_token → Peer
}

func NewManager(cfg *config.Config, log *zap.Logger) (*Manager, error) {
	tdev, err := tun.CreateTUN("utun", device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}

	ifName, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return nil, fmt.Errorf("get tun name: %w", err)
	}

	wgLogger := device.NewLogger(device.LogLevelError, "")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), wgLogger)

	privateKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	ipcConf := fmt.Sprintf("private_key=%s\nlisten_port=%d\n",
		hex.EncodeToString(privateKeyBytes), cfg.ListenPort)
	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring up wireguard: %w", err)
	}

	if err := configureInterface(ifName, cfg.ServerTunnelIP, cfg.TunnelCIDR); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure interface: %w", err)
	}

	log.Info("wireguard ready",
		zap.String("interface", ifName),
		zap.String("tunnel_ip", cfg.ServerTunnelIP),
		zap.Int("wg_port", cfg.ListenPort),
	)

	_, network, err := net.ParseCIDR(cfg.TunnelCIDR)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("parse tunnel cidr: %w", err)
	}

	pool := newIPPool(network, cfg.ServerTunnelIP)
	if pool == nil {
		dev.Close()
		return nil, fmt.Errorf(
			"tunnel_cidr %q is not a usable IPv4 network; the tunnel pool is IPv4 only",
			cfg.TunnelCIDR)
	}

	return &Manager{
		dev:   dev,
		log:   log,
		pool:  pool,
		peers: make(map[string]*Peer),
	}, nil
}

func (m *Manager) AddPeer(peerToken, publicKeyBase64 string, capacity int) (*Peer, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	// A Curve25519 public key is exactly 32 bytes, and an all-zero key is not a
	// valid point. Neither was checked, so malformed input reached the device.
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes, got %d", len(publicKeyBytes))
	}
	var zero [32]byte
	if bytes.Equal(publicKeyBytes, zero[:]) {
		return nil, fmt.Errorf("public key is all zero")
	}

	// Claim the slot and publish the entry under one lock. Checking capacity and
	// inserting separately let concurrent registrations both observe room and
	// push the peer count past the configured limit. The entry starts empty and
	// is filled in once the WireGuard IPC succeeds.
	peer := &Peer{PublicKey: publicKeyBase64}

	m.mu.Lock()
	if len(m.peers) >= capacity {
		m.mu.Unlock()
		return nil, fmt.Errorf("server at capacity")
	}
	// Refuse a key that is already registered. Registration is unauthenticated
	// and replace_allowed_ips makes the peer line authoritative, so re-
	// registering someone else's key rewrote their allowed_ip to a fresh
	// address: their traffic stopped being routed to them, and the caller could
	// then remove them outright. A public key is not a secret -- it crosses the
	// API in the clear and is derivable from any captured handshake -- so it
	// cannot be treated as proof of anything, but it can at least be bound to
	// the first token that claimed it.
	for existingToken, p := range m.peers {
		if p.PublicKey == publicKeyBase64 {
			m.mu.Unlock()
			if existingToken == peerToken {
				return nil, fmt.Errorf("peer already registered")
			}
			return nil, fmt.Errorf("public key already registered to another peer")
		}
	}
	m.peers[peerToken] = peer
	m.mu.Unlock()

	// From here on, any failure must surrender the reserved slot.
	release := func() {
		m.mu.Lock()
		delete(m.peers, peerToken)
		m.mu.Unlock()
	}

	tunnelIP, err := m.pool.Allocate()
	if err != nil {
		release()
		return nil, err
	}

	ipcConf := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n\n",
		hex.EncodeToString(publicKeyBytes), tunnelIP)
	if err := m.dev.IpcSet(ipcConf); err != nil {
		m.pool.Release(tunnelIP)
		release()
		return nil, fmt.Errorf("add peer to wireguard: %w", err)
	}

	m.mu.Lock()
	peer.TunnelIP = tunnelIP
	peer.TunnelIPv6 = tunnelIPv6(tunnelIP)
	m.mu.Unlock()

	m.log.Info("peer added", zap.String("session", redactToken(peerToken)), zap.String("tunnel_ip", tunnelIP))
	return peer, nil
}

// RemovePeer removes the peer registered under peerToken.
//
// The bool reports whether a peer was actually removed, so the caller can
// distinguish an unknown token from a successful removal. Returning success for
// both told a client its peer was gone when nothing had been removed.
func (m *Manager) RemovePeer(peerToken string) (bool, error) {
	m.mu.Lock()
	peer, ok := m.peers[peerToken]
	if !ok {
		m.mu.Unlock()
		return false, nil
	}
	delete(m.peers, peerToken)
	m.mu.Unlock()

	publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return true, err
	}

	// The map entry is already gone, so the address must return to the pool even
	// if the WireGuard IPC fails. Leaving it allocated would drain the pool one
	// address per failed removal, with nothing left to retry the release.
	defer m.pool.Release(peer.TunnelIP)

	ipcConf := fmt.Sprintf("public_key=%s\nremove=true\n\n", hex.EncodeToString(publicKeyBytes))
	if err := m.dev.IpcSet(ipcConf); err != nil {
		return true, fmt.Errorf("remove peer from wireguard: %w", err)
	}

	m.log.Info("peer removed", zap.String("session", redactToken(peerToken)))
	return true, nil
}

func (m *Manager) PeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.peers)
}

func (m *Manager) Close() {
	m.dev.Close()
}

// configureInterface assigns the server tunnel IP and adds a route for the
// tunnel network. Requires root — the server runs with sudo.
func configureInterface(ifName, serverIP, tunnelCIDR string) error {
	_, network, err := net.ParseCIDR(tunnelCIDR)
	if err != nil {
		return fmt.Errorf("parse cidr: %w", err)
	}

	// Configure the WireGuard interface. Use `ip` (Linux) if available, fall back to ifconfig (macOS).
	if _, err := exec.LookPath("ip"); err == nil {
		// Linux: ip addr add <ip>/24 dev <iface> && ip link set <iface> up
		cidr := serverIP + "/" + network.String()[strings.LastIndex(network.String(), "/")+1:]
		if out, err := exec.Command("ip", "addr", "add", cidr, "dev", ifName).CombinedOutput(); err != nil {
			// Ignore "already exists" error on restart.
			if !strings.Contains(string(out), "exists") {
				return fmt.Errorf("ip addr add: %s: %w", bytes.TrimSpace(out), err)
			}
		}
		if out, err := exec.Command("ip", "link", "set", ifName, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ip link set up: %s: %w", bytes.TrimSpace(out), err)
		}
		// Add route for tunnel network.
		exec.Command("ip", "route", "add", network.String(), "dev", ifName).Run() //nolint:errcheck
	} else {
		// macOS: ifconfig <iface> <local> <remote> up
		out, err := exec.Command("ifconfig", ifName, serverIP, serverIP, "up").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ifconfig: %s: %w", bytes.TrimSpace(out), err)
		}
		exec.Command("route", "-q", "-n", "add", "-inet", network.String(), "-interface", ifName).Run() //nolint:errcheck
	}

	return nil
}

// tunnelIPv6 maps 10.0.0.x to fd00::x.
func tunnelIPv6(ipStr string) string {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("fd00::%x", ip[3])
}

// redactToken renders a peer token safe to log.
//
// The token is the only credential authorising a peer's removal, so a log line
// containing one is a credential sitting in a file that outlives the session
// and is read by more people than the peer. The prefix correlates entries
// without being enough to use.
func redactToken(token string) string {
	if len(token) <= 6 {
		return "redacted"
	}
	return token[:6] + "\u2026"
}
