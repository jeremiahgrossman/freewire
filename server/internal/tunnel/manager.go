package tunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/freewire/server/internal/config"
	"github.com/freewire/server/internal/metrics"
)

// Peer holds the in-memory state for a connected peer.
type Peer struct {
	PublicKey  string
	TunnelIP   string
	TunnelIPv6 string
}

// Manager owns the WireGuard device and peer lifecycle.
type Manager struct {
	dev       *device.Device
	log       *zap.Logger
	pool      *ipPool
	mu        sync.RWMutex
	peers     map[string]*Peer // peer_token → Peer
	peersPath string           // where the peer table is persisted; "" disables it
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

	// Not device.NewLogger: its output names peers by public key. See wglogger.go.
	wgLogger := newWireGuardLogger(log)
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

	m := &Manager{
		dev:       dev,
		log:       log,
		pool:      pool,
		peers:     make(map[string]*Peer),
		peersPath: cfg.PeersStorePath(),
	}

	// Restore peers registered before whatever restarted this process (a
	// redeploy, a crash, an EC2 reboot). Without this, a client relying on a
	// cached registration -- the fallback that exists specifically for a
	// captive portal, where re-registering is impossible -- finds every
	// carrier connects at the transport layer and then silently fails the
	// WireGuard handshake, indistinguishable from the portal blocking
	// everything. Runs before the API is serving, so no lock contention.
	restored := 0
	for _, rp := range loadPeersFile(m.peersPath) {
		if err := m.restorePeer(rp); err != nil {
			log.Warn("skipping a peer from the peers file", zap.Error(err))
			continue
		}
		restored++
	}
	if restored > 0 {
		log.Info("restored peers from disk", zap.Int("count", restored))
	}

	return m, nil
}

// decodeAndValidatePublicKey applies the same checks AddPeer and restorePeer
// both need: a WireGuard public key is exactly 32 bytes, and an all-zero key
// is not a valid curve point.
func decodeAndValidatePublicKey(publicKeyBase64 string) ([]byte, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(publicKeyBytes) != 32 {
		return nil, fmt.Errorf("public key must be 32 bytes, got %d", len(publicKeyBytes))
	}
	var zero [32]byte
	if bytes.Equal(publicKeyBytes, zero[:]) {
		return nil, fmt.Errorf("public key is all zero")
	}
	return publicKeyBytes, nil
}

// wireguardAddPeerIPC builds the IpcSet payload that adds or replaces a peer.
func wireguardAddPeerIPC(publicKeyBytes []byte, tunnelIP string) string {
	return fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\npersistent_keepalive_interval=25\n\n",
		hex.EncodeToString(publicKeyBytes), tunnelIP)
}

// restorePeer re-establishes one peer read from disk into the running
// WireGuard device and the in-memory table. Called only from NewManager,
// before the API can receive any requests.
func (m *Manager) restorePeer(rp persistedPeer) error {
	publicKeyBytes, err := decodeAndValidatePublicKey(rp.PublicKey)
	if err != nil {
		return err
	}
	if !m.pool.reserveSpecific(rp.TunnelIP) {
		return fmt.Errorf("tunnel ip %s is no longer available", rp.TunnelIP)
	}

	if err := m.dev.IpcSet(wireguardAddPeerIPC(publicKeyBytes, rp.TunnelIP)); err != nil {
		m.pool.Release(rp.TunnelIP)
		return fmt.Errorf("add restored peer to wireguard: %w", err)
	}

	m.mu.Lock()
	m.peers[rp.PeerToken] = &Peer{
		PublicKey:  rp.PublicKey,
		TunnelIP:   rp.TunnelIP,
		TunnelIPv6: rp.TunnelIPv6,
	}
	m.mu.Unlock()
	return nil
}

// persist rewrites the peers file with the current table. Called after every
// successful AddPeer/RemovePeer so a restart never has stale-by-more-than-one
// state to lose. A write failure is logged, not fatal -- the in-memory table
// (and the live tunnel) stay correct either way; only durability across the
// *next* restart is at risk, and that next attempt gets another chance to
// persist.
func (m *Manager) persist() {
	m.mu.RLock()
	snapshot := make([]persistedPeer, 0, len(m.peers))
	for token, p := range m.peers {
		snapshot = append(snapshot, persistedPeer{
			PeerToken:  token,
			PublicKey:  p.PublicKey,
			TunnelIP:   p.TunnelIP,
			TunnelIPv6: p.TunnelIPv6,
		})
	}
	m.mu.RUnlock()

	if err := writePeersFile(m.peersPath, snapshot); err != nil {
		m.log.Warn("persist peers file failed", zap.Error(err))
	}
}

// reserveSlot claims the peer-token slot for publicKeyBase64 under one lock.
//
// Checking capacity and inserting separately let concurrent registrations both
// observe room and push the peer count past the configured limit, so both
// happen here. The returned Peer starts empty and is filled in once the
// WireGuard IPC succeeds.
//
// A key already registered under another token displaces that registration
// rather than being refused. Refusing it protected an existing peer from having
// its allowed_ip rewritten out from under it -- registration is unauthenticated
// and a public key is not a secret -- but it also meant a client that died
// without sending DELETE was locked out of its own server until the slot
// expired, which on a one-slot server is forever. The caller proved possession
// of the key by presenting it, which is the same evidence the original
// registration rested on.
//
// The displaced token and its tunnel address are returned so the caller can
// release the address once it is no longer holding the lock.
func (m *Manager) reserveSlot(peerToken, publicKeyBase64 string, capacity int) (peer *Peer, staleToken, staleIP string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for existingToken, p := range m.peers {
		if p.PublicKey == publicKeyBase64 {
			staleToken, staleIP = existingToken, p.TunnelIP
			break
		}
	}
	// Capacity binds only when the registration adds a peer. A replacement is
	// net-neutral on the count, and rejecting it would reintroduce the lockout
	// this displacement exists to prevent.
	if staleToken == "" && len(m.peers) >= capacity {
		return nil, "", "", fmt.Errorf("server at capacity")
	}
	if staleToken != "" {
		delete(m.peers, staleToken)
	}
	peer = &Peer{PublicKey: publicKeyBase64}
	m.peers[peerToken] = peer
	return peer, staleToken, staleIP, nil
}

func (m *Manager) AddPeer(peerToken, publicKeyBase64 string, capacity int) (*Peer, error) {
	publicKeyBytes, err := decodeAndValidatePublicKey(publicKeyBase64)
	if err != nil {
		return nil, err
	}

	peer, staleToken, staleIP, err := m.reserveSlot(peerToken, publicKeyBase64, capacity)
	if err != nil {
		return nil, err
	}
	// The displaced address is returned to the pool outside the lock, because
	// the pool takes its own.
	if staleToken != "" {
		if staleIP != "" {
			m.pool.Release(staleIP)
		}
		m.log.Info("replacing a stale registration for the same key",
			zap.String("session", redactToken(staleToken)))
	}

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

	if err := m.dev.IpcSet(wireguardAddPeerIPC(publicKeyBytes, tunnelIP)); err != nil {
		m.pool.Release(tunnelIP)
		release()
		return nil, fmt.Errorf("add peer to wireguard: %w", err)
	}

	m.mu.Lock()
	peer.TunnelIP = tunnelIP
	peer.TunnelIPv6 = tunnelIPv6(tunnelIP)
	m.mu.Unlock()

	// Counted, not logged. The line named no client IP, but a timestamped
	// record that a peer connected is what the privacy policy says is not
	// kept, and on a small server that timeline is close to a usage history.
	metrics.Global.PeersAdded.Add(1)
	m.persist()
	return peer, nil
}

// RemovePeer removes the peer registered under peerToken.
//
// The bool reports whether a peer was actually removed, so the caller can
// distinguish an unknown token from a successful removal. Returning success for
// both told a client its peer was gone when nothing had been removed.
func (m *Manager) RemovePeer(peerToken string) (bool, error) {
	// The fields are copied under the lock, not the pointer.
	//
	// Taking the pointer and reading through it after unlocking raced AddPeer,
	// which fills TunnelIP in under the same lock once the WireGuard IPC
	// succeeds. Removing a token while it was being registered could therefore
	// read a half-written entry -- and release an address that was either empty
	// or not yet the one in use.
	m.mu.Lock()
	peer, ok := m.peers[peerToken]
	if !ok {
		m.mu.Unlock()
		return false, nil
	}
	publicKey, tunnelIP := peer.PublicKey, peer.TunnelIP
	delete(m.peers, peerToken)
	m.mu.Unlock()
	// Persisted as soon as the in-memory map reflects the removal, whether or
	// not the WireGuard IPC below succeeds -- the map is already authoritative
	// at this point, matching the comment above.
	m.persist()

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return true, err
	}

	// The map entry is already gone, so the address must return to the pool even
	// if the WireGuard IPC fails. Leaving it allocated would drain the pool one
	// address per failed removal, with nothing left to retry the release.
	defer m.pool.Release(tunnelIP)

	ipcConf := fmt.Sprintf("public_key=%s\nremove=true\n\n", hex.EncodeToString(publicKeyBytes))
	if err := m.dev.IpcSet(ipcConf); err != nil {
		return true, fmt.Errorf("remove peer from wireguard: %w", err)
	}

	metrics.Global.PeersRemoved.Add(1)
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
	//
	// Absolute paths throughout. This runs as root, and resolving a bare name
	// through PATH means whatever PATH happens to hold at the time decides which
	// binary gets root -- a systemd unit file, a sudo invocation or a shell
	// profile is enough to change it. The client-side tunnel was given absolute
	// paths for the same reason.
	if ipBin := firstExisting("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"); ipBin != "" {
		// Linux: ip addr add <ip>/24 dev <iface> && ip link set <iface> up
		cidr := serverIP + "/" + network.String()[strings.LastIndex(network.String(), "/")+1:]
		if out, err := exec.Command(ipBin, "addr", "add", cidr, "dev", ifName).CombinedOutput(); err != nil {
			// Ignore "already exists" error on restart.
			if !strings.Contains(string(out), "exists") {
				return fmt.Errorf("ip addr add: %s: %w", bytes.TrimSpace(out), err)
			}
		}
		if out, err := exec.Command(ipBin, "link", "set", ifName, "up").CombinedOutput(); err != nil {
			return fmt.Errorf("ip link set up: %s: %w", bytes.TrimSpace(out), err)
		}
		// Add route for tunnel network.
		exec.Command(ipBin, "route", "add", network.String(), "dev", ifName).Run() //nolint:errcheck
		return nil
	}

	// macOS: ifconfig <iface> <local> <remote> up
	ifconfigBin := firstExisting("/sbin/ifconfig", "/usr/sbin/ifconfig")
	routeBin := firstExisting("/sbin/route", "/usr/sbin/route")
	if ifconfigBin == "" {
		return fmt.Errorf("neither ip nor ifconfig found in any expected location")
	}
	out, err := exec.Command(ifconfigBin, ifName, serverIP, serverIP, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig: %s: %w", bytes.TrimSpace(out), err)
	}
	if routeBin != "" {
		exec.Command(routeBin, "-q", "-n", "add", "-inet", network.String(), "-interface", ifName).Run() //nolint:errcheck
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

// firstExisting returns the first path that names an executable file.
//
// Used instead of exec.LookPath so that what runs as root is decided here
// rather than by the environment the process happened to inherit.
func firstExisting(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
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
