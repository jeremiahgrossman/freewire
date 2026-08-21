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
	// PreferredTransport names a path to attempt before the normal chain.
	// Set when upgrading from a slower path: without it the relaunched tunnel
	// restarts the chain from the top and reselects whatever it had before,
	// so the upgrade tore the tunnel down and rebuilt the same thing.
	PreferredTransport string `json:"preferred_transport,omitempty"`
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

	logger := device.NewLogger(device.LogLevelError, "wg: ")
	wgDev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	keepalive := cfg.Keepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	// Walk the fallback chain, and judge each rung by whether WireGuard can
	// actually complete a handshake over it -- not merely by whether the
	// transport connected.
	//
	// Selection used to stop at the first transport that established, configure
	// WireGuard over it, and give up entirely if no handshake followed. A portal
	// that answers HTTP CONNECT with 200 and then discards the tunnelled bytes
	// is routine -- they whitelist the verb, not the destination -- and it made
	// the client report the network as blocking VPNs without ever having tried
	// TLS/443, DNS or ICMP. That is the exact situation this product exists for.
	transportName, localProxy, transportConn, err := establishTunnel(cfg, wgDev, privKeyHex, pubKeyHex, keepalive)
	if err != nil {
		wgDev.Close()
		tunDev.Close()
		fmt.Println("all_paths_failed")
		os.Stdout.Sync() //nolint:errcheck
		os.Exit(2)
	}

	// Route traffic into the tunnel, pinning the server and resolver outside it.
	bypassHost := cfg.ServerHost
	if bypassHost == "" {
		// Extract host from endpoint.
		h, _, e := net.SplitHostPort(cfg.ServerEndpoint)
		if e == nil {
			bypassHost = h
		}
	}
	if err := setupRouting(tunName, bypassHost); err != nil {
		// Fatal. A tunnel that carries nothing is worse than no tunnel: the
		// client reports "Protected" off the ready line, so a silent routing
		// failure means the user believes they are covered while every packet
		// leaves in the clear. Tear down and report instead.
		cleanupRouting(tunName, bypassHost)
		wgDev.Close()
		if transportConn != nil {
			transportConn.Close()
		}
		if localProxy != nil {
			localProxy.Close()
		}
		fmt.Fprintf(os.Stderr, "freewire-tunnel: routing: %v\n", err)
		os.Exit(1)
	}

	// Signal ready to the parent Swift process.
	fmt.Printf("ready %s %s %s\n", tunName, cfg.TunnelIP, transportName)
	os.Stdout.Sync() //nolint:errcheck

	// Block until a signal arrives, or until the routes stop carrying traffic.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	unhealthy := superviseRouting()

	select {
	case <-sigs:
	case <-unhealthy:
		// The tunnel owns the whole address space at this point, so a tunnel
		// that has stopped forwarding leaves the host with no working network
		// at all. Give the routes back rather than sitting on them.
		fmt.Fprintln(os.Stderr, "freewire-tunnel: tunnel stopped carrying traffic; releasing routes")
	}

	wgDev.Close()
	if transportConn != nil {
		transportConn.Close()
	}
	if localProxy != nil {
		localProxy.Close()
	}
	cleanupRouting(tunName, bypassHost)
}

// superviseRouting watches whether traffic still survives the tunnel routes and
// closes the returned channel when it stops.
//
// This covers the gap between the two failure modes that already heal
// themselves. A clean exit runs cleanupRouting; a crash or kill -9 takes the
// utun interface down, and the kernel drops routes bound to a vanished
// interface, so the untouched system default takes over. Neither helps when the
// process is alive and the routes are valid but the far end has stopped
// answering — the transport dropped, the server went away, the network changed
// underneath. Without this the host stays pointed into a tunnel that goes
// nowhere, indefinitely.
//
// Health is judged the same way the initial check judges it, so a tunnel that
// was good enough to start is measured against the same bar.
func superviseRouting() <-chan struct{} {
	const (
		checkEvery       = 10 * time.Second
		failuresToUnhook = 3 // ~30s of confirmed silence before acting
	)

	unhealthy := make(chan struct{})
	if skipEgressCheck() {
		// Nothing would keep the tunnel alive otherwise: the supervisor would
		// see the same failures the startup check was told to ignore.
		return unhealthy
	}
	go func() {
		defer close(unhealthy)
		tally := healthTally{limit: failuresToUnhook}
		for {
			time.Sleep(checkEvery)
			err := probeThroughTunnel()
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"freewire-tunnel: health check %d/%d failed: %v\n",
					tally.consecutive+1, failuresToUnhook, err)
			}
			if tally.record(err == nil) {
				return
			}
		}
	}()
	return unhealthy
}

// healthTally decides when a run of failed checks means the tunnel should give
// the routes back.
type healthTally struct {
	limit       int
	consecutive int
}

// record accounts for one check and reports whether to give up. Only an
// unbroken run counts: a single success clears the tally, so isolated packet
// loss never tears down a working tunnel.
func (h *healthTally) record(ok bool) bool {
	if ok {
		h.consecutive = 0
		return false
	}
	h.consecutive++
	return h.consecutive >= h.limit
}

// probeThroughTunnel performs one round trip over the current routes.
func probeThroughTunnel() error {
	c, err := net.DialTimeout("tcp", tunnelProbeAddr, 2*time.Second)
	if err != nil {
		return err
	}
	return c.Close()
}

// skipEgressCheckFlag disables both the startup egress check and the supervisor
// that releases the routes when traffic stops. Testing aid only.
//
// A flag rather than an environment variable because sudo clears the
// environment, and the helper always runs under sudo. It is passed on the
// command line by a person running the binary by hand; the app never passes
// it, so no server response or config field can reach it.
const skipEgressCheckFlag = "--skip-egress-check"

// skipEgressCheck reports whether the run was told to accept a tunnel whose
// egress cannot be verified.
func skipEgressCheck() bool {
	for _, a := range os.Args[1:] {
		if a == skipEgressCheckFlag {
			return true
		}
	}
	return false
}

// tunnelProbeAddr is dialed to decide whether traffic survives the tunnel
// routes. A TCP handshake against a well-known anycast resolver: DNS
// resolution is deliberately not used, since resolution itself may be what a
// broken tunnel has taken down.
const tunnelProbeAddr = "1.1.1.1:53"

// bypassRoutes records the host routes pinned outside the tunnel so cleanup can
// remove exactly what was added.
var bypassRoutes []string

// setupRouting sends all traffic through the tunnel.
//
// Two halves, in this order:
//
//  1. Pin the server (and the DNS resolver) to the path they already use, so
//     the transport's own packets are not routed into the tunnel they carry.
//  2. Cover the address space with 0.0.0.0/1 and 128.0.0.0/1 via the tunnel.
//
// The split-default pair is what WireGuard and OpenVPN use. Both halves are
// more specific than any default route, so they win without deleting one. The
// previous approach did `route delete default` followed by `route add default`,
// which breaks whenever more than one default route exists: the delete removes
// an arbitrary entry (a bridge's, say, not the physical link's) and the add then
// fails with "file exists" while the original default survives. Traffic kept
// flowing outside the tunnel while the client reported "Protected".
func setupRouting(tunName, bypassHost string) error {
	// Resolve bypass host to an IP if needed.
	bypassIP := bypassHost
	if bypassHost != "" && net.ParseIP(bypassHost) == nil {
		addrs, lookupErr := net.LookupHost(bypassHost)
		if lookupErr == nil && len(addrs) > 0 {
			bypassIP = addrs[0]
		}
	}
	if bypassIP == "" {
		return fmt.Errorf("no server address to pin outside the tunnel")
	}

	// The server must keep its current path. Routing it through the default
	// gateway is wrong whenever it is reachable some other way — on a bridge,
	// over another interface — and would black-hole the transport.
	if err := pinOutsideTunnel(bypassIP); err != nil {
		return fmt.Errorf("pin server route: %w", err)
	}

	// The DNS tunnel talks to the local resolver, which must stay reachable for
	// the same reason.
	if resolver, err := resolveLocalDNSServer(); err == nil && resolver != bypassIP {
		if err := pinOutsideTunnel(resolver); err != nil {
			// Not fatal: only the DNS transport depends on it.
			fmt.Fprintf(os.Stderr, "freewire-tunnel: pin resolver route: %v\n", err)
		}
	}

	// Cover everything with two halves rather than replacing the default route.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		// -ifscope keeps the entry tied to the tunnel; delete first so a stale
		// entry from an unclean exit cannot make the add fail.
		exec.Command("route", "-q", "-n", "delete", "-inet", half).Run() //nolint:errcheck
		if out, err := exec.Command("route", "-q", "-n", "add", "-inet", half,
			"-interface", tunName).CombinedOutput(); err != nil {
			return fmt.Errorf("add %s via %s: %w — %s", half, tunName, err,
				strings.TrimSpace(string(out)))
		}
	}

	// Verify rather than assume. A silent routing failure means the client
	// reports "Protected" while every packet leaves in the clear.
	if iface, err := interfaceForDest("8.8.8.8"); err != nil {
		return fmt.Errorf("verify tunnel route: %w", err)
	} else if iface != tunName {
		return fmt.Errorf("tunnel routes did not take effect: traffic to 8.8.8.8 still uses %s, not %s",
			iface, tunName)
	}

	// Installing the routes is not the same as traffic surviving them. If the
	// far end forwards without translating the source address, or forwards
	// nowhere at all, packets leave and nothing comes back: the host is
	// suddenly offline with a tunnel that looks healthy. Confirm something
	// answers through the tunnel before declaring it usable.
	//
	// The escape hatch exists for environments whose egress is known broken --
	// container runtimes on macOS drop forwarded traffic -- where the point of
	// the run is which transport gets chosen, not what the far end does with
	// the packets. It is deliberately an environment variable rather than a
	// config field: nothing the server sends can turn this off, and a release
	// build has no path to it unless someone sets it in the launching shell.
	if skipEgressCheck() {
		fmt.Fprintf(os.Stderr,
			"freewire-tunnel: %s — skipping the egress check; traffic may not be carried\n",
			skipEgressCheckFlag)
		return nil
	}

	if err := verifyTunnelCarriesTraffic(); err != nil {
		return fmt.Errorf("tunnel routes installed but carry no traffic: %w", err)
	}

	return nil
}

// verifyTunnelCarriesTraffic confirms a round trip survives the new routes.
//
// It runs after the split-default pair is in place, so it exercises the real
// post-routing path. Failing here is what turns a total loss of connectivity
// into a clean teardown and an error message.
func verifyTunnelCarriesTraffic() error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		c, err := net.DialTimeout("tcp", tunnelProbeAddr, 2*time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("no response from %s after 3 attempts: %w", tunnelProbeAddr, lastErr)
}

// pinOutsideTunnel adds a host route for ip along the path it currently uses,
// so it survives the tunnel taking over the rest of the address space.
func pinOutsideTunnel(ip string) error {
	gw, iface, err := routeTo(ip)
	if err != nil {
		return err
	}

	// A stale entry from an unclean exit would make the add fail.
	exec.Command("route", "-q", "-n", "delete", "-host", ip).Run() //nolint:errcheck

	// Prefer the gateway when there is one; otherwise the destination is on a
	// directly attached link and must be pinned to that interface.
	args := []string{"-q", "-n", "add", "-host", ip}
	switch {
	case gw != "" && net.ParseIP(gw) != nil:
		args = append(args, gw)
	case iface != "":
		args = append(args, "-interface", iface)
	default:
		return fmt.Errorf("no gateway or interface for %s", ip)
	}

	if out, err := exec.Command("route", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%w — %s", err, strings.TrimSpace(string(out)))
	}
	bypassRoutes = append(bypassRoutes, ip)
	return nil
}

// routeTo reports the gateway and interface the system currently uses for dest.
// The gateway is empty when dest sits on a directly attached link.
func routeTo(dest string) (gateway, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", dest).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("route get %s: %w", dest, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "gateway:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
			// A link-layer address here means the destination is on-link.
			if net.ParseIP(v) != nil {
				gateway = v
			}
		case strings.HasPrefix(line, "interface:"):
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if gateway == "" && iface == "" {
		return "", "", fmt.Errorf("route get %s: no gateway or interface in output", dest)
	}
	return gateway, iface, nil
}

// interfaceForDest reports which interface the system would use to reach dest.
func interfaceForDest(dest string) (string, error) {
	_, iface, err := routeTo(dest)
	if err != nil {
		return "", err
	}
	return iface, nil
}

// cleanupRouting restores the original default gateway.
// cleanupRouting removes exactly what setupRouting added.
//
// The system default route is never touched now, so there is nothing to
// restore: removing the two halves hands traffic back to it automatically.
func cleanupRouting(tunName, bypassHost string) {
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		exec.Command("route", "-q", "-n", "delete", "-inet", half).Run() //nolint:errcheck
	}

	// Remove the tunnel subnet route added by configureInterface.
	exec.Command("route", "-q", "-n", "delete", "-inet", "10.0.0.0/24").Run() //nolint:errcheck

	// Remove every host route pinned outside the tunnel, tracked so a resolver
	// route is not left behind when it differs from the server address.
	for _, ip := range bypassRoutes {
		exec.Command("route", "-q", "-n", "delete", "-host", ip).Run() //nolint:errcheck
	}
	bypassRoutes = nil
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
