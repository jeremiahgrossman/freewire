package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
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
	// ServerHostV6 is the server's global IPv6 address, advertised by the server.
	// The client stores it for the (not-yet-wired) wireguard6 carrier; see
	// IPV6-CARRIER-REMAINING.md. Populated from the config API today so a future
	// client build needs no server change.
	ServerHostV6 string `json:"server_host_v6,omitempty"`
	// CDNHost is a CDN hostname (e.g. a CloudFront distribution) that fronts the
	// server. When set, the cdn_wss carrier dials it instead of the server's IP,
	// so a portal that gates our ADDRESS -- not just the port -- still passes the
	// tunnel, because the CDN edge IP is one the portal already permits. Empty
	// disables that carrier. Reported by the server (cdn_host).
	CDNHost string `json:"cdn_host,omitempty"`
	// DNSTunnelDomain is the authoritative zone the DNS tunnel queries, reported
	// by the server so a rotation needs no client rebuild. Empty falls back to
	// defaultDNSTunnelDomain.
	DNSTunnelDomain string `json:"dns_tunnel_domain,omitempty"`
	// DoHEndpoints overrides the DoH resolvers used once connected, tried in
	// order as failover. Empty falls back to defaultDoHEndpoints. Each must be an
	// https:// URL; plaintext would defeat the point and is dropped. Diversifying
	// across operators here is what removes DNS as a single point of trust; the
	// default stays one operator until that choice is made deliberately.
	DoHEndpoints []string `json:"doh_endpoints,omitempty"`
	// DNSResolver overrides the resolver the DNS tunnel queries.
	//
	// Normally the tunnel uses the system resolver and relies on it forwarding
	// the tunnel zone to the authoritative server. That requires the zone to be
	// delegated, which is true in production and false anywhere else -- so
	// without this the DNS transport cannot be exercised against a development
	// server at all. Empty means use the system resolver.
	DNSResolver string `json:"dns_resolver,omitempty"`
	// DNSResolvers spreads the DNS carrier across several resolvers at once. A
	// public recursor rate-limits how fast it forwards UNIQUE (uncacheable) names
	// to our authoritative server, which caps routed throughput and drives loss;
	// fanning queries across N resolvers keeps each under its own per-auth-server
	// limit while the server (keyed by session token, not source) sees the sum.
	// Overrides DNSResolver when non-empty. Each entry is "host" or "host:port"
	// (port defaults to 53). Unreachable entries are dropped at startup.
	DNSResolvers []string `json:"dns_resolvers,omitempty"`
	// DNSTestCarrierCap simulates a portal that rate-limits DNS to the server at N
	// queries/sec, by dropping carrier queries above that rate (a "loss" the
	// adaptive limiter must discover and pace under). TEST ONLY -- it reproduces a
	// throttled café at the desk so the backpressure work can be verified without a
	// field trip. 0 = off. Set only by the test harness; a real server never sends
	// it.
	DNSTestCarrierCap int `json:"dns_test_carrier_cap,omitempty"`
	// HTTPProxy is an explicit "host:port" to attempt before probing the
	// gateway.
	//
	// Real portals mostly sit transparently on the gateway, which is what the
	// probe assumes. Some advertise a proxy elsewhere via WPAD or DHCP, and a
	// single-machine test setup cannot put a listener on the gateway address at
	// all -- so without this the HTTP CONNECT path is untestable without a
	// second machine acting as the router.
	HTTPProxy string `json:"http_proxy,omitempty"`
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

// pidFile lets `--stop` find a running tunnel.
//
// The alternative was `sudo pkill -x freewire-tunnel`, which needed a second
// passwordless sudo rule covering pkill itself. That rule let anything running
// as the user kill any process on the machine as root, security software
// included, to solve a problem that belongs to one binary. Teaching the tunnel
// to stop itself keeps the privileged surface at exactly one command, and
// signalling a recorded pid is also precise where pkill matches on a name
// anything can adopt.
const pidFile = "/var/run/freewire-tunnel.pid"

func main() {
	// --stop signals a running tunnel and waits for it to clean up.
	if len(os.Args) > 1 && os.Args[1] == "--stop" {
		os.Exit(stopRunningTunnel())
	}

	// --restore repairs a machine a previous run left misconfigured, without
	// connecting anything.
	//
	// This exists because the DNS takeover made an ungraceful exit far worse
	// than it used to be. The system resolver points at a forwarder on
	// loopback; if the process dies without running its cleanup, nothing is
	// listening there and name resolution stops entirely -- not "the wrong
	// resolver", but no DNS at all. That happened twice during development.
	if len(os.Args) > 1 && os.Args[1] == "--restore" {
		releaseStalePins()
		restoreStaleDNS()
		fmt.Fprintln(os.Stderr, "freewire-tunnel: restored routes and resolvers")
		os.Exit(0)
	}

	// --dns-probe runs only the DNS tunnel handshake against a resolver, to
	// prove the transport works end to end through a real delegation. It changes
	// no system state, so it exits here before the routing/resolver repair below.
	if len(os.Args) > 1 && os.Args[1] == "--dns-probe" {
		os.Exit(dnsProbe(os.Args[2:]))
	}

	// --dns-throughput measures the resolver/delegation query capacity and the
	// upstream ceiling it implies. Like --dns-probe it changes no system state.
	if len(os.Args) > 1 && os.Args[1] == "--dns-throughput" {
		os.Exit(dnsThroughput(os.Args[2:]))
	}

	// --icmp-probe runs only the ICMP/UDP tunnel handshake against the server.
	// No routing, no resolver, no system state.
	if len(os.Args) > 1 && os.Args[1] == "--icmp-probe" {
		os.Exit(icmpProbe(os.Args[2:]))
	}

	// --dns-datatest sends real single- and multi-fragment packets through a DNS
	// session to localize where the transport breaks. No routing.
	if len(os.Args) > 1 && os.Args[1] == "--dns-datatest" {
		os.Exit(dnsDataTest(os.Args[2:]))
	}

	// --wss-probe tests the WebSocket carrier's handshake, and alongside it the
	// raw TLS carrier on the same port, reporting both. It changes no system
	// state and needs no root, which is the point: it answers "does this network
	// pass web-443 while refusing raw 443?" from a café table, before committing
	// to a connection. See TRANSPORT-RESEARCH-2026-08-24.md.
	if len(os.Args) > 1 && os.Args[1] == "--wss-probe" {
		os.Exit(wssProbe(os.Args[2:]))
	}

	// --probe-battery runs the full reachability survey: every carrier we ship
	// plus the UDP/443, UDP/123 and IPv6 candidates we are deciding whether to
	// build, each probed against OUR server. No root, no routing. Run it at a
	// real portal to learn what that network passes before connecting.
	if len(os.Args) > 1 && os.Args[1] == "--probe-battery" {
		os.Exit(probeBattery(os.Args[2:]))
	}

	// --walled-garden surveys which well-known destinations a captive portal
	// permits pre-login, to learn what fronting could work where ours did not.
	// Rootless, non-routed.
	if len(os.Args) > 1 && os.Args[1] == "--walled-garden" {
		os.Exit(wgProbe(os.Args[2:]))
	}

	// Repair before doing anything else, on every run. setupRouting used to be
	// the only place this happened, so a machine left broken stayed broken
	// until a connection attempt got far enough to reach it -- and a connection
	// attempt needs DNS.
	releaseStalePins()
	restoreStaleDNS()

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

	// WireGuard logger, written to STDERR. device.NewLogger writes to os.Stdout,
	// which the app redirects to the ready-file and then deletes -- so its output
	// (including verbose handshake logs) was lost. Build the logger by hand so it
	// lands in the captured stderr log. Verbose in the skipRouting debug mode, so a
	// diagnostic run shows whether the WG handshake completes over the chosen
	// transport (the DNS carrier in particular); error-level otherwise.
	wgLogf := func(prefix string) func(string, ...any) {
		return log.New(os.Stderr, prefix+": wg: ", log.Ldate|log.Ltime).Printf
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: wgLogf("ERROR")}
	if skipEgressCheck() {
		logger.Verbosef = wgLogf("DEBUG")
	}
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
	// Route traffic into the tunnel, pinning the server and resolver outside it.
	bypassHost := cfg.ServerHost
	if bypassHost == "" {
		// Extract host from endpoint.
		h, _, e := net.SplitHostPort(cfg.ServerEndpoint)
		if e == nil {
			bypassHost = h
		}
	}

	// Walk the fallback chain judging each rung not by whether WireGuard
	// handshakes over it, but by whether the routed tunnel actually carries
	// traffic to the internet. A handshake proves the carrier reached the
	// server; it does not prove the path is usable. A portal that answers HTTP
	// CONNECT with 200 and discards the bytes, or throttles a DNS carrier below
	// what a TCP handshake can survive, will pass the handshake and then carry
	// nothing -- the exact situation this product exists for.
	//
	// So: establish over the fastest carrier that handshakes, route, and verify
	// egress. If the tunnel carries nothing, exclude that carrier and fall
	// through to the next-fastest one instead of giving up. "First to handshake"
	// becomes "fastest that actually carries traffic," and a network that leaves
	// only ICMP open is tried down to ICMP rather than abandoned at DNS.
	var (
		transportName string
		localProxy    net.PacketConn
		transportConn net.Conn
	)
	excluded := map[string]bool{}
	for {
		var err error
		transportName, localProxy, transportConn, err = establishTunnel(cfg, wgDev, privKeyHex, pubKeyHex, keepalive, excluded)
		if err != nil {
			// Every remaining carrier either failed to open or failed to carry
			// traffic. There is nothing left to fall through to.
			wgDev.Close()
			tunDev.Close()
			fmt.Println("all_paths_failed")
			os.Stdout.Sync() //nolint:errcheck
			os.Exit(2)
		}

		// Recorded once the chain has chosen. Both the probe budget and whether
		// DNS can be taken over depend on which transport is carrying traffic,
		// and both are consulted from code that does not otherwise know.
		activeTransport = transportName

		if selectOnly() {
			// The chain has chosen and WireGuard has handshaked over the winner.
			// Report it and stop before routing: this mode exists to learn the
			// selection safely, not to carry traffic. Egress is not verified here
			// (verifying would require routing), so this reports the fastest that
			// handshakes, not the fastest that carries traffic.
			fmt.Println(transportName)
			fmt.Fprintf(os.Stderr, "freewire-tunnel: --select-only chose %s; routing not installed\n", transportName)
			if transportConn != nil {
				transportConn.Close()
			}
			if localProxy != nil {
				localProxy.Close()
			}
			wgDev.Close()
			os.Exit(0)
		}

		if skipEgressCheck() {
			// Path selection has already been decided by this point: the
			// transport is chosen and WireGuard has handshaked over it. Routing
			// is the only step left, and it is the one that can strand the host,
			// so it is skipped rather than made unsafe. With routing skipped
			// there is no egress to verify, so this carrier is accepted as-is
			// (no fall-through).
			fmt.Fprintf(os.Stderr,
				"freewire-tunnel: %s — tunnel is up but routing is NOT installed; traffic still uses the normal path\n",
				skipEgressCheckFlag)
			break
		}

		if err := setupRouting(tunName, bypassHost, carrierPeerAddr(transportConn),
			carrierResolvers(cfg), cfg.DoHEndpoints); err == nil {
			// Routed and egress verified: this carrier actually carries traffic.
			break
		} else {
			// Handshaked but carried nothing once routed. Restore the machine,
			// exclude this carrier, and fall through to the next-fastest one.
			// Not fatal on its own -- fatal only when every carrier is exhausted
			// (the establishTunnel error above).
			cleanupRouting(tunName, bypassHost)
			if transportConn != nil {
				transportConn.Close()
			}
			if localProxy != nil {
				localProxy.Close()
			}
			fmt.Fprintf(os.Stderr,
				"freewire-tunnel: %s handshaked but carried no traffic once routed (%v); falling through to the next carrier\n",
				transportName, err)
			excluded[transportName] = true
		}
	}

	// Record the pid before announcing ready, so a caller that reacts to the
	// ready line by stopping the tunnel always finds it.
	writePIDFile()
	defer os.Remove(pidFile) //nolint:errcheck

	// Signal ready to the parent Swift process.
	fmt.Printf("ready %s %s %s\n", tunName, cfg.TunnelIP, transportName)
	os.Stdout.Sync() //nolint:errcheck

	// Block until a signal arrives, the routes stop carrying traffic, or the
	// controlling app lets go of our stdin.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	// The health watchdog releases routes when traffic stops surviving them. Under
	// --route-no-verify (diagnostic) that would tear the routes down within a
	// second or two of a slow tunnel, before egress can be measured -- the very
	// thing the flag exists to observe. Suspend it in that mode; a nil channel
	// never fires in the select below.
	var unhealthy <-chan struct{}
	if routeNoVerify() {
		fmt.Fprintln(os.Stderr, "freewire-tunnel: --route-no-verify — health watchdog suspended")
	} else {
		unhealthy = superviseRouting()
	}

	// The app keeps our stdin open for as long as it wants the tunnel up, and
	// closes it on disconnect. If the app crashes or quits, the OS closes it for
	// us. Either way the read below returns EOF -- so teardown never depends on
	// the app re-authenticating sudo to send `--stop` later, which failed
	// silently once the sudo timestamp expired and left the tunnel running with
	// its routes and DNS takeover still in place.
	stdinClosed := make(chan struct{})
	go func() {
		io.Copy(io.Discard, os.Stdin) //nolint:errcheck
		close(stdinClosed)
	}()

	select {
	case <-sigs:
	case <-stdinClosed:
		fmt.Fprintln(os.Stderr, "freewire-tunnel: controlling app released stdin; releasing routes")
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
		// No routes were installed, so there is nothing to release and nothing
		// to supervise.
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
// probeBudget is how long a probe through the tunnel may take.
//
// Set once the transport is known, because the transports differ by orders of
// magnitude: a TCP handshake over the DNS tunnel is several fragmented queries
// and a poll round trip, where the same handshake over TLS/443 is one RTT.
// handshakeBudgetFor already scales for exactly this reason.
//
// It was a flat 2s, which the DNS transport could not meet -- the tunnel came
// up, failed its own egress check and tore itself down. Raising it to a flat
// 12s fixed that and broke the other end: a genuinely dead tunnel then took
// three 12s attempts to notice, with the user unprotected throughout.
// activeTransport is the transport the chain selected, set once before routing.
var activeTransport string

func probeBudget() time.Duration { return probeBudgetFor(activeTransport) }

// probeBudgetFor is how long one probe may take on a given transport.
//
// Measured through the DNS tunnel, a TCP connect is bimodal: three samples gave
// 0.08s, 19.08s, 0.07s. It is usually one round trip and occasionally misses
// poll windows badly. A budget long enough to cover the tail would be 20s, and
// three of those exceed the client's 30s ready timeout -- the tunnel would lose
// to its own deadline.
//
// So the tail is not covered on purpose. A tunnel that needs 19 seconds to open
// a TCP connection cannot carry anything a user would wait for, and calling it
// dead is the right answer rather than a missed one.
func probeBudgetFor(transport string) time.Duration {
	switch transport {
	case "dns":
		return 6 * time.Second
	case "icmp_udp":
		return 5 * time.Second
	default:
		return 3 * time.Second
	}
}

// probeAttempts pairs with the budget: their product is what the client waits
// for, and it has to leave room for the fallback chain inside the same 30s.
func probeAttempts(transport string) int {
	switch transport {
	case "dns", "icmp_udp":
		return 2
	default:
		return 3
	}
}

func probeThroughTunnel() error {
	c, err := net.DialTimeout("tcp", probeAddr(), probeBudget())
	if err != nil {
		return err
	}
	return c.Close()
}

// skipEgressCheckFlag runs the tunnel without ever taking over routing.
//
// Testing aid, for environments where forwarded traffic is known not to
// survive and the point of the run is which transport gets chosen.
//
// It deliberately does NOT mean "install the routes and disable the checks".
// An earlier version did exactly that, and when a tunnel came up but carried
// nothing there was no longer anything to release the routes -- the machine was
// left with no working network and needed manual `route delete` surgery. A
// testing switch must reduce what is attempted, never remove a safety net.
//
// A flag rather than an environment variable because sudo clears the
// environment, and the helper always runs under sudo.
//
// The app DOES pass it, when the skipRouting preference is set. An earlier
// version of this comment claimed it did not, which is how a preference left
// enabled after a debugging session came to produce a tunnel that reported
// "Protected" while every packet left in the clear. It is still unreachable
// from any server response or config field -- only from a local preference the
// user set -- but "only a person can turn it on" is not the same as "the app
// never passes it", and the UI has to account for the difference. See DEBUG-1
// in error-states-spec.md.
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

// selectOnlyFlag runs the real fallback chain -- including the WireGuard
// handshake check that decides whether a transport actually carries traffic --
// prints the winning transport's name to stdout, and exits without ever
// installing routing. It is the safe way to answer "which transport does this
// network leave open", e.g. under a pf config that simulates a locked captive
// portal, with none of the machine-slowing hazard of routing over a slow path.
const selectOnlyFlag = "--select-only"

func selectOnly() bool {
	for _, a := range os.Args[1:] {
		if a == selectOnlyFlag {
			return true
		}
	}
	return false
}

// forceTransportFlag pins the chain to a single transport, skipping the others
// entirely (unlike PreferredTransport, which only reorders and still falls
// through). It exists for testing: forcing DNS from the command line reproduces
// a locked-portal connect without needing a pf config to block the server, and
// without the sudo/auto-revert flakiness that made that setup unreliable. Like
// the other test flags it is an argument, never a config field -- nothing the
// server sends can pin the client to a slow transport.
const forceTransportFlag = "--force-transport"

// routeNoVerifyFlag installs routing but skips the egress self-check and its
// route-release, so a slow-but-working transport stays up long enough to measure
// real egress. Diagnostic only; see the use site in setupRouting.
const routeNoVerifyFlag = "--route-no-verify"

func routeNoVerify() bool {
	for _, a := range os.Args[1:] {
		if a == routeNoVerifyFlag {
			return true
		}
	}
	return false
}

// forcedTransport returns the transport name after --force-transport, or "".
func forcedTransport() string {
	args := os.Args[1:]
	for i, a := range args {
		if a == forceTransportFlag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

// Absolute paths for every external binary.
//
// This process runs as root. Invoking "route" or "ifconfig" by bare name
// resolves through PATH, so anything earlier in PATH runs with root privileges.
const (
	routeBin        = "/sbin/route"
	ifconfigBin     = "/sbin/ifconfig"
	networksetupBin = "/usr/sbin/networksetup"
)

// probeCandidates are well-known anycast resolvers used to decide whether
// traffic survives the tunnel routes. A TCP handshake, not a DNS lookup:
// resolution itself may be what a broken tunnel has taken down.
//
// More than one, because the resolver in use gets pinned outside the tunnel so
// the DNS transport keeps working. Probing a pinned address proves only that
// the bypass route works, which is true whether or not the tunnel carries
// anything — the check would pass on a completely dead tunnel.
var probeCandidates = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}

// probeAddr returns the first candidate that is not pinned outside the tunnel.
func probeAddr() string {
	for _, cand := range probeCandidates {
		host, _, err := net.SplitHostPort(cand)
		if err != nil {
			continue
		}
		if !isPinned(host) {
			return cand
		}
	}
	// Every candidate is pinned, which should not happen; the caller is better
	// off probing something than skipping the check.
	return probeCandidates[0]
}

// isPinned reports whether ip was routed outside the tunnel.
func isPinned(ip string) bool {
	for _, p := range bypassRoutes {
		if p == ip {
			return true
		}
	}
	return false
}

// bypassRoutes records the host routes pinned outside the tunnel so cleanup can
// remove exactly what was added.
var bypassRoutes []string

// pinnedRoutesFile records pinned host routes so a run that dies without
// cleaning up can be repaired by the next one.
//
// The split-default routes heal themselves: they are bound to the utun
// interface, so the kernel drops them when it disappears. Pinned host routes do
// not -- they sit on a physical interface, they are static, and they outlive the
// process. A stale pin for a gateway or resolver breaks that network the next
// time the machine joins it, because a static route is not corrected by ARP or
// DHCP. That is not a hypothetical: a SIGKILL during testing left a pin on a
// home router and broke wifi.
const pinnedRoutesFile = "/var/run/freewire-pinned-routes"

func writePIDFile() {
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o644) //nolint:errcheck
}

// stopRunningTunnel signals the recorded tunnel and waits for it to exit.
//
// Waiting matters: the caller's next move is usually to start a new tunnel or
// to check that routing was restored, and both are wrong while the old process
// is still unwinding.
func stopRunningTunnel() int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		// Nothing recorded is a successful stop, not a failure: the caller
		// wanted no tunnel running and there is none.
		fmt.Fprintln(os.Stderr, "freewire-tunnel: no running tunnel recorded")
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		os.Remove(pidFile) //nolint:errcheck
		fmt.Fprintln(os.Stderr, "freewire-tunnel: pid file unreadable; nothing to stop")
		return 0
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidFile) //nolint:errcheck
		return 0
	}
	// SIGTERM, never SIGKILL. The process has routes, resolvers and an IPv6
	// setting to give back, and killing it outright leaves exactly the state
	// the stale-recovery paths exist to repair.
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		os.Remove(pidFile) //nolint:errcheck
		fmt.Fprintln(os.Stderr, "freewire-tunnel: no such process; nothing to stop")
		return 0
	}

	for i := 0; i < 100; i++ {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			return 0 // gone
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "freewire-tunnel: tunnel did not exit within 10s")
	return 1
}

// releaseStalePins removes host routes left behind by a previous run.
func releaseStalePins() {
	data, err := os.ReadFile(pinnedRoutesFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		ip := strings.TrimSpace(line)
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		exec.Command(routeBin, "-q", "-n", "delete", "-host", ip).Run() //nolint:errcheck
		fmt.Fprintf(os.Stderr, "freewire-tunnel: released a stale pinned route for %s\n", ip)
	}
	os.Remove(pinnedRoutesFile) //nolint:errcheck
}

// carrierPeerAddr reports the IP the established carrier is actually connected
// to, or "" when there is nothing to read.
//
// The DNS and ICMP carriers run their own bridge and hand back a nil transport
// connection; they pin their resolvers separately, so an empty result here is
// the correct answer for them rather than a missing one.
func carrierPeerAddr(transport net.Conn) string {
	if transport == nil {
		return ""
	}
	ra := transport.RemoteAddr()
	if ra == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(ra.String())
	if err != nil {
		return ""
	}
	return host
}

// recordPins persists the current pin list so a crash can be repaired later.
func recordPins() {
	if len(bypassRoutes) == 0 {
		os.Remove(pinnedRoutesFile) //nolint:errcheck
		return
	}
	os.WriteFile(pinnedRoutesFile, []byte(strings.Join(bypassRoutes, "\n")), 0644) //nolint:errcheck
}

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
func setupRouting(tunName, bypassHost, carrierPeer string, carrierResolvers []string, dohEndpoints []string) error {
	// Already repaired at process start; nothing to redo here.

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

	// Pin the address the carrier is ACTUALLY talking to, which is not always
	// the server's.
	//
	// bypassIP comes from configuration; carrierPeer comes from the established
	// connection. They are the same for every carrier that dials the server
	// directly, and they diverge the moment anything sits in front of it -- a
	// CDN-fronted carrier lands on an edge IP the config never names. Pinning
	// only the configured address then lets the split-default route below
	// capture the carrier's own packets and loop them into the tunnel, which
	// presents exactly as "connected but carries nothing" -- the failure this
	// project has already spent weeks on with routed DNS.
	//
	// Pinning the real peer is strictly more correct for every carrier, so it is
	// not conditional on which one is running. Non-fatal: on a direct carrier it
	// is the same address already pinned, and a failure here should not tear
	// down a tunnel that would otherwise work.
	if carrierPeer != "" && carrierPeer != bypassIP && net.ParseIP(carrierPeer) != nil {
		if err := pinOutsideTunnel(carrierPeer); err != nil {
			fmt.Fprintf(os.Stderr, "freewire-tunnel: pin carrier peer %s: %v\n", carrierPeer, err)
		} else {
			fmt.Fprintf(os.Stderr, "freewire-tunnel: pinned carrier peer %s outside the tunnel\n", carrierPeer)
		}
	}

	// The DNS carrier must keep talking to whatever resolver it actually queries,
	// or its own packets get captured by the split-default route below and loop
	// back into the tunnel -- which looks exactly like a slow carrier and stalls
	// the whole transport. Pin the carrier's resolver explicitly (it may not be
	// the system resolver: a config can point the DNS transport at a fast public
	// recursor), and also the system resolver so ordinary lookups survive.
	pinResolver := func(hostport string) {
		if hostport == "" {
			return
		}
		ip := hostport
		if h, _, e := net.SplitHostPort(hostport); e == nil {
			ip = h
		}
		if ip == "" || ip == bypassIP {
			return
		}
		if err := pinOutsideTunnel(ip); err != nil {
			// Not fatal: only the DNS transport depends on it.
			fmt.Fprintf(os.Stderr, "freewire-tunnel: pin resolver route %s: %v\n", ip, err)
		}
	}
	for _, r := range carrierResolvers {
		pinResolver(r)
	}
	if resolver, err := resolveLocalDNSServer(); err == nil {
		pinResolver(resolver)
	}

	// IPv6 must not survive the tunnel coming up.
	//
	// The routes below cover IPv4 only, and configureInterface assigns the utun
	// no v6 address, so the system's IPv6 default route stayed on the physical
	// interface: every v6-reachable destination was contacted in the clear
	// while the client reported "Protected". The WireGuard peer config sets
	// allowed_ip=::/0, which makes it look handled at the WireGuard layer even
	// though the kernel never sent a v6 packet to the interface, and the
	// existing route check only ever looked at a v4 destination.
	//
	// Carrying v6 inside the tunnel is the better answer and is not in scope
	// here. Until it is, v6 is switched off for the tunnel's lifetime and
	// restored on cleanup, so traffic that cannot be protected cannot leave.
	if err := setIPv6(false); err != nil {
		return fmt.Errorf("disable ipv6: %w", err)
	}

	// Cover everything with two halves rather than replacing the default route.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		// -ifscope keeps the entry tied to the tunnel; delete first so a stale
		// entry from an unclean exit cannot make the add fail.
		exec.Command(routeBin, "-q", "-n", "delete", "-inet", half).Run() //nolint:errcheck
		if out, err := exec.Command(routeBin, "-q", "-n", "add", "-inet", half,
			"-interface", tunName).CombinedOutput(); err != nil {
			return fmt.Errorf("add %s via %s: %w — %s", half, tunName, err,
				strings.TrimSpace(string(out)))
		}
	}

	// Diagnostic: confirm the carrier's own traffic actually bypasses the tunnel.
	// If the server (and, for the DNS transport, the resolver it queries) resolve
	// to the tun interface here, every carrier packet loops back into the tunnel
	// and times out -- which looks exactly like a slow carrier. This records the
	// truth in tunnel.err on every routed run, tun vs physical.
	if bypassIface, e := interfaceForDest(bypassIP); e == nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: route-check: server %s -> %s (want physical, NOT %s)\n",
			bypassIP, bypassIface, tunName)
	}
	checkResolvers := carrierResolvers
	if len(checkResolvers) == 0 {
		if r, e := resolveLocalDNSServer(); e == nil {
			checkResolvers = []string{r}
		}
	}
	for _, cr := range checkResolvers {
		ip := cr
		if h, _, e := net.SplitHostPort(cr); e == nil {
			ip = h
		}
		if ri, e := interfaceForDest(ip); e == nil {
			fmt.Fprintf(os.Stderr, "freewire-tunnel: route-check: carrier resolver %s -> %s (want physical, NOT %s)\n",
				ip, ri, tunName)
		}
	}

	// Verify rather than assume. A silent routing failure means the client
	// reports "Protected" while every packet leaves in the clear. This is only a
	// route lookup (does this destination resolve to the tun?), so use a fixed
	// TEST-NET-1 address (RFC 5737, never routed to a real host and never a
	// carrier resolver) rather than a live probe candidate: when the carrier
	// spreads across the public recursors, those are all pinned outside the
	// tunnel, and probing one of them would read the bypass route and wrongly
	// report that routing did not take effect.
	const routeCheckHost = "192.0.2.1"
	if iface, err := interfaceForDest(routeCheckHost); err != nil {
		return fmt.Errorf("verify tunnel route: %w", err)
	} else if iface != tunName {
		return fmt.Errorf("tunnel routes did not take effect: traffic to %s still uses %s, not %s",
			routeCheckHost, iface, tunName)
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
	if routeNoVerify() {
		// Diagnostic mode: install routing but do NOT gate on the egress self-
		// check, and do NOT release the routes if it would have failed. This
		// exists to answer "does this transport carry ANY real traffic, however
		// slowly" separately from "does it pass the strict probe deadline" -- the
		// probe releasing routes on a slow-but-working tunnel hid that difference.
		// Like the other test flags it is an argument, never a config field, so a
		// release build cannot leave the machine routed through a dead tunnel.
		fmt.Fprintln(os.Stderr,
			"freewire-tunnel: --route-no-verify — routes installed, egress self-check SKIPPED (diagnostic)")
	} else if err := verifyTunnelCarriesTraffic(); err != nil {
		return fmt.Errorf("tunnel routes installed but carry no traffic: %w", err)
	}

	// Encrypted DNS, on the transports that can carry it.
	//
	// DoH costs a full HTTPS round trip per uncached lookup, which the DNS and
	// ICMP transports deliver in 5-10 seconds. The takeover is system-wide, so
	// every application on the machine pays that, not just a browser -- which is
	// not a slow VPN but an unusable computer. See DNS-ON-SLOW-TRANSPORTS in
	// DECISIONS.md for the alternatives and what would reopen the choice.
	if !transportCanCarryDoH(activeTransport) {
		fmt.Fprintf(os.Stderr,
			"freewire-tunnel: %s is too slow for encrypted DNS; leaving the system resolver alone\n"+
				"freewire-tunnel: traffic is tunnelled, but this network can see which sites you visit (DNS-1)\n",
			activeTransport)
		return nil
	}

	// Start the DoH forwarder before pointing the system at it, so the resolver
	// it is sent to is already answering.
	fwd, dohErr := startDoHForwarder(dohEndpoints)
	dohNotice(dohErr)
	if dohErr == nil {
		dohActive = fwd
	}

	// Move DNS last, once traffic is known to survive the tunnel. Pointing the
	// system at a resolver that is only reachable through the tunnel before
	// knowing the tunnel works would take name resolution down with it.
	if dohErr != nil {
		// Without the forwarder there is nothing safe to point at: sending the
		// system to 1.1.1.1 directly is the cleartext path this replaced, and
		// leaving it alone keeps queries on the local network. The second is
		// the status quo and the one the user was already told about.
		return nil
	}
	if err := setupDNS(); err != nil {
		// Not fatal. A tunnel that carries traffic while DNS leaks is a real
		// privacy loss and has to be said out loud, but refusing to connect
		// over it leaves the user with neither protection nor a tunnel.
		fmt.Fprintf(os.Stderr,
			"freewire-tunnel: WARNING: could not take over DNS: %v\n"+
				"freewire-tunnel: lookups may still go to the local network in cleartext\n", err)
	}

	return nil
}

// verifyTunnelCarriesTraffic confirms a round trip survives the new routes.
//
// It runs after the split-default pair is in place, so it exercises the real
// post-routing path. Failing here is what turns a total loss of connectivity
// into a clean teardown and an error message.
// sustainedProbesRequired is how many egress probes, spaced across time, a
// transport must pass consecutively before its tunnel is called usable.
//
// Fast transports need one: if the carrier is up it stays up. The DNS and ICMP
// transports need more, because a throttling resolver or captive portal lets a
// brief burst through and then stalls. A single probe passed that burst and
// produced a "Protected" that carried no traffic on a real Starbucks portal
// (health checks then failed and every egress sample timed out). Requiring
// successes spaced seconds apart makes a burst-then-stall transport fail the
// check instead of lying about protection.
func sustainedProbesRequired(transport string) int {
	if transportCanCarryDoH(transport) {
		return 1
	}
	return 2
}

func verifyTunnelCarriesTraffic() error {
	need := sustainedProbesRequired(activeTransport)
	// After a success, wait before the next probe so successes must span time; a
	// transport that only bursts cannot answer probes seconds apart. A failure
	// breaks the streak, so `need` successes must be consecutive.
	const gap = 2 * time.Second
	maxAttempts := need + probeAttempts(activeTransport)

	got := 0
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if got > 0 {
			time.Sleep(gap)
		}
		if err := probeCarriesData(probeBudget()); err != nil {
			lastErr = err
			got = 0 // a miss breaks the sustained streak
			continue
		}
		got++
		if got >= need {
			return nil
		}
	}
	return fmt.Errorf("egress did not sustain: best streak %d/%d to %s: %w",
		got, need, probeAddr(), lastErr)
}

// probeCarriesData confirms the tunnel carries a real, multi-fragment exchange
// end to end -- not just a TCP handshake. It completes a TLS handshake to a
// well-known host on 443, which sends a multi-hundred-byte ClientHello and reads
// a multi-packet ServerHello + certificate back. A bare TCP dial (three tiny
// packets) passed on the DNS tunnel while every real HTTPS request failed,
// because the tunnel carried single-fragment packets but broke on multi-fragment
// ones -- a TCP SYN is one fragment, a TLS ClientHello is several. This probe
// exercises exactly that, so a tunnel that cannot move real data fails the check
// instead of reporting a false "Protected".
//
// InsecureSkipVerify is deliberate: this measures whether bytes flow both ways,
// not who the peer is. The user's actual traffic is authenticated end to end by
// WireGuard; this probe authenticates nothing and carries no user data.
func probeCarriesData(budget time.Duration) error {
	host, _, err := net.SplitHostPort(probeAddr())
	if err != nil {
		host = probeAddr()
	}
	dialer := net.Dialer{Timeout: budget}
	conn, err := tls.DialWithDialer(&dialer, "tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reachability probe, not authentication
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// pinOutsideTunnel adds a host route for ip along the path it currently uses,
// so it survives the tunnel taking over the rest of the address space.
func pinOutsideTunnel(ip string) error {
	gw, iface, err := routeTo(ip)
	if err != nil {
		return err
	}

	// A stale entry from an unclean exit would make the add fail.
	exec.Command(routeBin, "-q", "-n", "delete", "-host", ip).Run() //nolint:errcheck

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

	if out, err := exec.Command(routeBin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%w — %s", err, strings.TrimSpace(string(out)))
	}
	bypassRoutes = append(bypassRoutes, ip)
	recordPins()
	return nil
}

// routeTo reports the gateway and interface the system currently uses for dest.
// The gateway is empty when dest sits on a directly attached link.
func routeTo(dest string) (gateway, iface string, err error) {
	out, err := exec.Command(routeBin, "-n", "get", dest).CombinedOutput()
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
// dohActive is the running forwarder, stopped on teardown.
var dohActive *dohForwarder

// transportCanCarryDoH reports whether a transport can serve system-wide DNS
// over HTTPS without stalling the machine.
//
// Named for what it decides rather than listing "slow" transports, because the
// question is not how fast the tunnel feels: it is whether one HTTPS round trip
// per uncached lookup fits inside what an application will wait for.
func transportCanCarryDoH(transport string) bool {
	switch transport {
	case "dns", "icmp_udp":
		return false
	default:
		return true
	}
}

func cleanupRouting(tunName, bypassHost string) {
	// DNS first. The resolvers it points at are only reachable through the
	// tunnel, so restoring them after tearing the routes down would leave a
	// window with no working name resolution.
	cleanupDNS()
	// Then the forwarder, once nothing is pointed at it.
	if dohActive != nil {
		dohActive.Close()
		dohActive = nil
	}

	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		exec.Command(routeBin, "-q", "-n", "delete", "-inet", half).Run() //nolint:errcheck
	}

	// Give IPv6 back. Left off, a crashed tunnel would silently cost the user
	// v6 connectivity with nothing on screen to explain it.
	if err := setIPv6(true); err != nil {
		fmt.Fprintf(os.Stderr, "freewire-tunnel: restore ipv6: %v\n", err)
	}

	// Remove the tunnel subnet route added by configureInterface.
	exec.Command(routeBin, "-q", "-n", "delete", "-inet", "10.0.0.0/24").Run() //nolint:errcheck

	// Remove every host route pinned outside the tunnel, tracked so a resolver
	// route is not left behind when it differs from the server address.
	for _, ip := range bypassRoutes {
		exec.Command(routeBin, "-q", "-n", "delete", "-host", ip).Run() //nolint:errcheck
	}
	bypassRoutes = nil
	recordPins()
}

// ipv6Services lists the network services whose IPv6 configuration was changed,
// so cleanup restores exactly what was touched.
var ipv6Services []string

// Tunnel DNS.
//
// Routing all traffic through the tunnel does not move DNS with it. The system
// resolver is usually the local router, which sits on the link's own subnet, and
// that subnet route is more specific than 0.0.0.0/1 -- so every lookup keeps
// going to the local network in cleartext while the traffic it resolves is
// tunneled. Measured on a real connection: web traffic egressed from the VPN
// server while queries were answered by the ISP's resolver.
//
// That is the leak a VPN is most expected to close. On the captive-portal
// networks this product exists for, the operator would otherwise see every
// domain visited, which is most of the browsing history in practice.
//
// Cloudflare's resolvers are used because the tech stack already fixes on them,
// and they are reached through the tunnel like any other address.
// The system resolver points at the local DoH forwarder, not at Cloudflare
// directly. Pointing it straight at 1.1.1.1 stopped the leak to the local
// network but left queries as plain DNS on port 53: they crossed the tunnel in
// the clear and left the VPN server in the clear, so the one party the product
// promises cannot see your browsing could read every domain. See doh.go.
var tunnelResolvers = []string{"127.0.0.1"}

// savedDNSFile records each service's original resolvers.
//
// Same reasoning as pinnedRoutesFile, and more urgent than it since the DoH
// forwarder landed.
//
// This comment used to say the failure was gentle: a killed run left the system
// pointed at 1.1.1.1, the split-default routes died with the utun interface, and
// so name resolution kept working against the wrong resolver. That stopped being
// true the moment the resolver became a forwarder on loopback. A process that
// dies without running its cleanup now leaves the system pointed at a port
// nothing is listening on, and the machine has no DNS at all until something
// puts it back. It cost the user their network twice before the reasoning was
// re-checked against the change.
//
// So this file is read at the start of every run, and `--restore` exists to
// read it without connecting. A SIGKILL still leaves the machine broken until
// one of those happens; closing that properly needs a supervisor outside this
// process, which is what the privileged helper will be.
const savedDNSFile = "/var/run/freewire-saved-dns"

// dnsSaved maps a network service to the resolver list it had before.
// "Empty" is recorded literally, because that is what networksetup expects to
// restore a service to DHCP-provided resolvers.
var dnsSaved = map[string]string{}

// restoreStaleDNS puts back resolvers left redirected by a previous run.
func restoreStaleDNS() {
	data, err := os.ReadFile(savedDNSFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		service, servers, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok || service == "" {
			continue
		}
		args := append([]string{"-setdnsservers", service}, strings.Fields(servers)...)
		if len(args) == 2 {
			args = append(args, "Empty")
		}
		exec.Command(networksetupBin, args...).Run() //nolint:errcheck
		fmt.Fprintf(os.Stderr, "freewire-tunnel: restored stale DNS for %q\n", service)
	}
	os.Remove(savedDNSFile) //nolint:errcheck
}

func recordSavedDNS() {
	if len(dnsSaved) == 0 {
		os.Remove(savedDNSFile) //nolint:errcheck
		return
	}
	var b strings.Builder
	for service, servers := range dnsSaved {
		b.WriteString(service + "\t" + servers + "\n")
	}
	os.WriteFile(savedDNSFile, []byte(b.String()), 0o644) //nolint:errcheck
}

// setupDNS points every active network service at the tunnel's resolvers.
//
// Failure is reported but not fatal. A tunnel that carries traffic while DNS
// leaks is a real privacy loss and the user must be told, but it is still
// better than no tunnel -- whereas refusing to connect over it would leave them
// with neither.
func setupDNS() error {
	names, err := activeNetworkServices()
	if err != nil {
		return err
	}
	var failed []string
	for _, name := range names {
		out, err := exec.Command(networksetupBin, "-getdnsservers", name).Output()
		if err != nil {
			failed = append(failed, name)
			continue
		}
		// networksetup answers with a sentence when nothing is configured.
		current := strings.TrimSpace(string(out))
		if strings.Contains(current, "There aren't any") {
			current = ""
		} else {
			current = strings.Join(strings.Fields(current), " ")
		}

		args := append([]string{"-setdnsservers", name}, tunnelResolvers...)
		if err := exec.Command(networksetupBin, args...).Run(); err != nil {
			failed = append(failed, name)
			continue
		}
		dnsSaved[name] = current
	}
	recordSavedDNS()

	if len(dnsSaved) == 0 {
		return fmt.Errorf("no network service accepted -setdnsservers")
	}
	if len(failed) > 0 {
		return fmt.Errorf("DNS still leaks on: %s", strings.Join(failed, ", "))
	}
	return nil
}

// cleanupDNS restores exactly the services setupDNS changed.
func cleanupDNS() {
	for name, servers := range dnsSaved {
		args := append([]string{"-setdnsservers", name}, strings.Fields(servers)...)
		if len(args) == 2 {
			args = append(args, "Empty")
		}
		exec.Command(networksetupBin, args...).Run() //nolint:errcheck
	}
	dnsSaved = map[string]string{}
	recordSavedDNS()
}

// activeNetworkServices lists services that networksetup will accept commands
// for, skipping the header line and services marked disabled.
func activeNetworkServices() ([]string, error) {
	out, err := exec.Command(networksetupBin, "-listallnetworkservices").Output()
	if err != nil {
		return nil, fmt.Errorf("list network services: %w", err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "An asterisk") || strings.HasPrefix(name, "*") {
			continue
		}
		names = append(names, name)
	}
	return names, nil
}

// setIPv6 turns IPv6 on or off for every active network service.
//
// Disabling is a blunt instrument, and deliberate: the alternative is v6
// traffic leaving in the clear while the UI claims protection. Restoring uses
// "automatic", which is the macOS default.
func setIPv6(on bool) error {
	if !on {
		names, err := activeNetworkServices()
		if err != nil {
			return err
		}
		ipv6Services = nil
		for _, name := range names {
			if err := exec.Command(networksetupBin, "-setv6off", name).Run(); err == nil {
				ipv6Services = append(ipv6Services, name)
			}
		}
		if len(ipv6Services) == 0 {
			return fmt.Errorf("no network service accepted -setv6off")
		}
		return nil
	}

	for _, name := range ipv6Services {
		exec.Command(networksetupBin, "-setv6automatic", name).Run() //nolint:errcheck
	}
	ipv6Services = nil
	return nil
}

// configureInterface sets the point-to-point tunnel address and MTU.
func configureInterface(tunName, tunnelIP, peerIP string) error {
	if net.ParseIP(tunnelIP) == nil {
		return fmt.Errorf("bad tunnel IP: %s", tunnelIP)
	}
	if out, err := exec.Command(ifconfigBin, tunName, tunnelIP, peerIP, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig addr: %w — %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command(ifconfigBin, tunName, "mtu", "1420").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig mtu: %w — %s", err, strings.TrimSpace(string(out)))
	}
	// Add tunnel subnet route (non-fatal if already exists).
	exec.Command(routeBin, "-q", "-n", "add", "-inet", "10.0.0.0/24", "-interface", tunName).Run() //nolint:errcheck
	return nil
}

// waitForHandshake polls the WireGuard IPC interface until a handshake is confirmed
// (last_handshake_time_sec > 0) or the deadline passes.
func waitForHandshake(dev *device.Device, timeout time.Duration, baseline uint64) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hs := handshakeTime(dev); hs > baseline {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

// handshakeTime reports the peer's last handshake as a unix timestamp, 0 if none.
//
// Read as a baseline before each candidate, because the check used to be
// "is it non-zero". Once any candidate had handshaked, every candidate tried
// afterwards saw a non-zero value and reported success immediately -- so the
// transport the client believed it was using was whichever one happened to be
// in flight when some earlier candidate's handshake landed. Three runs with
// identical configuration selected three different transports.
//
// The consequence is worse than a wrong label. The chain stops at the first
// candidate that "succeeds", so it could settle on a transport carrying nothing
// while a working one further down was never tried.
func handshakeTime(dev *device.Device) uint64 {
	var buf bytes.Buffer
	if err := dev.IpcGetOperation(&buf); err != nil {
		return 0
	}
	var newest uint64
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		val, ok := strings.CutPrefix(line, "last_handshake_time_sec=")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(val, 10, 64); err == nil && n > newest {
			newest = n
		}
	}
	return newest
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
