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
	dev    *device.Device
	log    *zap.Logger
	pool   *ipPool
	mu     sync.RWMutex
	peers  map[string]*Peer // peer_token → Peer
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

	return &Manager{
		dev:   dev,
		log:   log,
		pool:  newIPPool(network, cfg.ServerTunnelIP),
		peers: make(map[string]*Peer),
	}, nil
}

func (m *Manager) AddPeer(peerToken, publicKeyBase64 string, capacity int) (*Peer, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	m.mu.Lock()
	if len(m.peers) >= capacity {
		m.mu.Unlock()
		return nil, fmt.Errorf("server at capacity")
	}
	m.mu.Unlock()

	tunnelIP, err := m.pool.Allocate()
	if err != nil {
		return nil, err
	}

	ipcConf := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n\n",
		hex.EncodeToString(publicKeyBytes), tunnelIP)
	if err := m.dev.IpcSet(ipcConf); err != nil {
		m.pool.Release(tunnelIP)
		return nil, fmt.Errorf("add peer to wireguard: %w", err)
	}

	peer := &Peer{
		PublicKey:  publicKeyBase64,
		TunnelIP:   tunnelIP,
		TunnelIPv6: tunnelIPv6(tunnelIP),
	}

	m.mu.Lock()
	m.peers[peerToken] = peer
	m.mu.Unlock()

	m.log.Info("peer added", zap.String("session", peerToken), zap.String("tunnel_ip", tunnelIP))
	return peer, nil
}

func (m *Manager) RemovePeer(peerToken string) error {
	m.mu.Lock()
	peer, ok := m.peers[peerToken]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	delete(m.peers, peerToken)
	m.mu.Unlock()

	publicKeyBytes, err := base64.StdEncoding.DecodeString(peer.PublicKey)
	if err != nil {
		return err
	}

	ipcConf := fmt.Sprintf("public_key=%s\nremove=true\n\n", hex.EncodeToString(publicKeyBytes))
	if err := m.dev.IpcSet(ipcConf); err != nil {
		return fmt.Errorf("remove peer from wireguard: %w", err)
	}

	m.pool.Release(peer.TunnelIP)
	m.log.Info("peer removed", zap.String("session", peerToken))
	return nil
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
