package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config is passed via stdin as JSON from the Swift app.
type Config struct {
	PrivateKey      string `json:"private_key"`       // base64
	ServerPublicKey string `json:"server_public_key"` // base64
	ServerEndpoint  string `json:"server_endpoint"`   // "host:51820" for direct WireGuard UDP
	ServerHost      string `json:"server_host"`       // "1.2.3.4" bare IP/hostname for TLS/DNS/ICMP
	TunnelIP        string `json:"tunnel_ip"`         // e.g. 10.0.0.2
	ServerTunnelIP  string `json:"server_tunnel_ip"`  // e.g. 10.0.0.1
	Keepalive       int    `json:"keepalive"`         // seconds, typically 25
	InsecureTLS     bool   `json:"insecure_tls"`      // dev only: skip cert verify
	TLSPort         int    `json:"tls_port"`          // default 443; server reports its own
	DNSTunnelPort   int    `json:"dns_tunnel_port"`   // default 53; server reports its own
	ICMPUDPPort     int    `json:"icmp_udp_port"`     // default 4500
}

func (c *Config) applyDefaults() {
	if c.TLSPort == 0 {
		c.TLSPort = 443
	}
	if c.DNSTunnelPort == 0 {
		c.DNSTunnelPort = 53
	}
	if c.ICMPUDPPort == 0 {
		c.ICMPUDPPort = 4500
	}
}

// oldGateway is set during setupRouting so cleanupRouting can restore it.
var oldGateway string

func main() {
	var cfg Config
	if err := json.NewDecoder(os.Stdin).Decode(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: config: %v\n", err)
		os.Exit(1)
	}
	cfg.applyDefaults()

	privKeyHex, err := b64ToHex(cfg.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: private_key: %v\n", err)
		os.Exit(1)
	}
	pubKeyHex, err := b64ToHex(cfg.ServerPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: server_public_key: %v\n", err)
		os.Exit(1)
	}

	// Create userspace TUN device.
	tunDev, err := tun.CreateTUN("utun", device.DefaultMTU)
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: create tun: %v\n", err)
		os.Exit(1)
	}
	tunName, err := tunDev.Name()
	if err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: tun name: %v\n", err)
		os.Exit(1)
	}

	// Configure interface IP before bringing WireGuard up.
	if err := configureInterface(tunName, cfg.TunnelIP, cfg.ServerTunnelIP); err != nil {
		tunDev.Close()
		fmt.Fprintf(os.Stderr, "freewire-tunnel: ifconfig: %v\n", err)
		os.Exit(1)
	}

	// Select transport: tries HTTP CONNECT → TLS/443 → DNS → ICMP → direct WireGuard.
	transportName, localProxy, transportConn, err := selectTransport(cfg)
	if err != nil {
		tunDev.Close()
		fmt.Fprintf(os.Stderr, "freewire-tunnel: transport: %v\n", err)
		os.Exit(1)
	}

	// Determine WireGuard endpoint.
	wgEndpoint := cfg.ServerEndpoint // direct UDP (wireguard transport)
	if transportName != "wireguard" && localProxy != nil {
		wgEndpoint = localProxy.LocalAddr().String()
	}

	logger := device.NewLogger(device.LogLevelError, "wg: ")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	keepalive := cfg.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	// replace_allowed_ips makes the allowed_ip lines below authoritative rather
	// than additive. Without it a second IpcSetOperation on the same device
	// accumulates entries instead of replacing them.
	ipcConf := "private_key=" + privKeyHex + "\n" +
		"public_key=" + pubKeyHex + "\n" +
		"endpoint=" + wgEndpoint + "\n" +
		"replace_allowed_ips=true\n" +
		"allowed_ip=0.0.0.0/0\n" +
		"allowed_ip=::/0\n" +
		fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive) +
		"\n"

	if err := wgDev.IpcSetOperation(strings.NewReader(ipcConf)); err != nil {
		wgDev.Close()
		fmt.Fprintf(os.Stderr, "freewire-tunnel: ipc set: %v\n", err)
		os.Exit(1)
	}

	if err := wgDev.Up(); err != nil {
		wgDev.Close()
		fmt.Fprintf(os.Stderr, "freewire-tunnel: device up: %v\n", err)
		os.Exit(1)
	}

	// Start local proxy bridge for non-wireguard transports.
	if transportName != "wireguard" && localProxy != nil && transportConn != nil {
		go runLocalProxy(localProxy, transportConn)
	}

	// Wait up to 5s for the WireGuard handshake to complete. This detects captive
	// portal networks where UDP (or the chosen transport) is blocked — if no handshake
	// occurs, all paths are effectively failed and Swift runs the captive portal probe.
	if !waitForHandshake(wgDev, 5*time.Second) {
		wgDev.Close()
		if transportConn != nil {
			transportConn.Close()
		}
		if localProxy != nil {
			localProxy.Close()
		}
		fmt.Println("all_paths_failed")
		os.Stdout.Sync() //nolint:errcheck
		os.Exit(2)
	}

	// Set up default route via tunnel. The bypass route for the server IP goes
	// through the old default gateway so WireGuard/TLS/DNS traffic is not looped.
	bypassHost := cfg.ServerHost
	if bypassHost == "" {
		// Extract host from endpoint.
		h, _, e := net.SplitHostPort(cfg.ServerEndpoint)
		if e == nil {
			bypassHost = h
		}
	}
	if err := setupRouting(tunName, bypassHost); err != nil {
		// Non-fatal: routing may partially work, log but continue.
		fmt.Fprintf(os.Stderr, "freewire-tunnel: routing: %v\n", err)
	}

	// Signal ready to the parent Swift process.
	fmt.Printf("ready %s %s %s\n", tunName, cfg.TunnelIP, transportName)
	os.Stdout.Sync() //nolint:errcheck

	// Block until signal.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	<-sigs

	wgDev.Close()
	if transportConn != nil {
		transportConn.Close()
	}
	if localProxy != nil {
		localProxy.Close()
	}
	cleanupRouting(tunName, bypassHost)
}

// setupRouting installs routes to send all traffic through the tunnel.
// 1. Saves the current default gateway.
// 2. Adds a specific route for bypassHost via the old gateway (so tunnel traffic isn't looped).
// 3. Replaces the default route to go via tunName.
func setupRouting(tunName, bypassHost string) error {
	gw, err := getDefaultGateway()
	if err != nil {
		return fmt.Errorf("get default gateway: %w", err)
	}
	oldGateway = gw

	// Resolve bypass host to IP if needed.
	bypassIP := bypassHost
	if net.ParseIP(bypassHost) == nil && bypassHost != "" {
		addrs, lookupErr := net.LookupHost(bypassHost)
		if lookupErr == nil && len(addrs) > 0 {
			bypassIP = addrs[0]
		}
	}

	// Add bypass route for server IP via old gateway.
	if bypassIP != "" {
		if out, err := exec.Command("route", "-q", "add", "-host", bypassIP, gw).CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "freewire-tunnel: bypass route (non-fatal): %v — %s\n",
				err, strings.TrimSpace(string(out)))
		}
	}

	// Delete current default route.
	exec.Command("route", "-q", "delete", "default").Run() //nolint:errcheck

	// Add new default route via tunnel interface.
	if out, err := exec.Command("route", "-q", "add", "default", "-interface", tunName).CombinedOutput(); err != nil {
		return fmt.Errorf("add default route: %w — %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// cleanupRouting restores the original default gateway.
func cleanupRouting(tunName, bypassHost string) {
	// Remove tunnel default route.
	exec.Command("route", "-q", "delete", "default").Run() //nolint:errcheck

	// Remove tunnel subnet route.
	exec.Command("route", "-q", "-n", "delete", "-inet", "10.0.0.0/24").Run() //nolint:errcheck

	// Remove bypass route.
	if bypassHost != "" {
		exec.Command("route", "-q", "delete", "-host", bypassHost).Run() //nolint:errcheck
	}

	// Restore original default gateway.
	if oldGateway != "" {
		exec.Command("route", "-q", "add", "default", oldGateway).Run() //nolint:errcheck
	}
}

// configureInterface sets the point-to-point tunnel address and MTU.
func configureInterface(tunName, tunnelIP, peerIP string) error {
	if net.ParseIP(tunnelIP) == nil {
		return fmt.Errorf("bad tunnel IP: %s", tunnelIP)
	}
	if out, err := exec.Command("ifconfig", tunName, tunnelIP, peerIP, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig addr: %w — %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ifconfig", tunName, "mtu", "1420").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig mtu: %w — %s", err, strings.TrimSpace(string(out)))
	}
	// Add tunnel subnet route (non-fatal if already exists).
	exec.Command("route", "-q", "-n", "add", "-inet", "10.0.0.0/24", "-interface", tunName).Run() //nolint:errcheck
	return nil
}

// waitForHandshake polls the WireGuard IPC interface until a handshake is confirmed
// (last_handshake_time_sec > 0) or the deadline passes.
func waitForHandshake(dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	// One buffer for the whole poll, reset per iteration.
	var buf bytes.Buffer
	for time.Now().Before(deadline) {
		buf.Reset()
		if err := dev.IpcGetOperation(&buf); err == nil {
			for _, line := range strings.Split(buf.String(), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "last_handshake_time_sec=") {
					val := strings.TrimPrefix(line, "last_handshake_time_sec=")
					if val != "0" && val != "" {
						return true
					}
				}
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
