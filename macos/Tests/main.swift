import Foundation

// Standalone assertions for KillSwitchRules.
//
// The project has one target and no test bundle, so these compile alongside the
// source rather than through XCTest. The logic under test is a pure function,
// which is the whole reason it was written that way: a kill switch that is
// wrong either leaks traffic the user believed was protected, or strands the
// machine with no way back.

var failures = 0

func check(_ condition: Bool, _ what: String) {
    if condition {
        print("  ok   \(what)")
    } else {
        print("  FAIL \(what)")
        failures += 1
    }
}

let server = KillSwitchRules.ServerEndpoint(
    host: "3.88.155.229",
    tcpPorts: [443, 8080],
    udpPorts: [51820, 53, 4500]
)

// MARK: - Default deny

let base = KillSwitchRules(serverEndpoints: [server]).render()

check(base.contains("block drop all"),
      "denies everything by default")
check(base.range(of: "block drop all")!.lowerBound < base.range(of: "pass out quick")!.lowerBound,
      "the deny comes before any pass, so passes are the exception")
check(base.contains("set skip on lo0"),
      "exempts loopback rather than breaking local IPC")

// MARK: - Reconnection must remain possible

check(base.contains("pass out quick proto tcp to 3.88.155.229 port { 443, 8080 }"),
      "permits the server's TCP ports")
check(base.contains("pass out quick proto udp to 3.88.155.229 port { 51820, 53, 4500 }"),
      "permits the server's UDP ports")
check(base.contains("port 68 to any port 67"),
      "permits DHCP renewal by default")

// A kill switch that blocks the path back to the server cannot be recovered
// from without the user finding pfctl themselves.
check(base.contains("3.88.155.229"),
      "the server is reachable while the switch is engaged")

// MARK: - Tunnel interface

let withTunnel = KillSwitchRules(
    serverEndpoints: [server],
    tunnelInterfaces: ["utun6"]
).render()
check(withTunnel.contains("pass quick on utun6 all"),
      "permits the tunnel interface when one exists")
check(!base.contains("pass quick on utun"),
      "permits no tunnel interface while reconnecting")

// MARK: - Local network is off unless asked for

check(!base.contains("192.168.0.0/16"),
      "does not permit the local network by default")
let withLAN = KillSwitchRules(
    serverEndpoints: [server], allowLocalNetwork: true
).render()
check(withLAN.contains("192.168.0.0/16") && withLAN.contains("10.0.0.0/8"),
      "permits the local network only when asked")

// MARK: - Injection

// These values come from server config, not a user, but they are interpolated
// into a file executed as root.
let hostile = KillSwitchRules(
    serverEndpoints: [KillSwitchRules.ServerEndpoint(
        host: "1.2.3.4\npass in all\n# ",
        tcpPorts: [443],
        udpPorts: []
    )],
    tunnelInterfaces: ["utun0\npass in all"]
).render()
check(!hostile.contains("pass in all"),
      "strips characters that would inject a rule")
check(hostile.contains("1.2.3.4passinall") || hostile.contains("1.2.3.4"),
      "keeps the usable part of the value")

let badPorts = KillSwitchRules(
    serverEndpoints: [KillSwitchRules.ServerEndpoint(
        host: "1.2.3.4", tcpPorts: [0, 70000, -1, 443], udpPorts: []
    )]
).render()
check(badPorts.contains("443") && !badPorts.contains("70000") && !badPorts.contains("-1"),
      "drops out-of-range ports rather than emitting an invalid ruleset")

// MARK: - No endpoints

// If the app somehow has no server, the ruleset must still deny by default
// rather than emit something that passes everything.
let noServer = KillSwitchRules(serverEndpoints: []).render()
check(noServer.contains("block drop all"),
      "still denies by default with no endpoints configured")
check(!noServer.contains("pass out quick proto tcp"),
      "emits no server rules when there are no endpoints")

// MARK: - TunnelTransport / Go carrier-chain parity
//
// The Swift enum's rawValues ARE the wire names passed to and parsed from the Go
// helper (preferred_transport in, "transport selected: <name>" out), and its
// priority order drives the upgrade manager. Both must match the Go chain in
// tunnel/cmd/freewire-tunnel/transport.go (defaultCandidates) and the probe
// battery that mirrors it. A drift here does not fail loudly at runtime -- it
// silently makes the app chase the wrong path or fail to parse a carrier name --
// so this is the tripwire. Keep this list identical to Go's TestCarrierChainOrderIsStable.
let goCarrierChain = [
    "wireguard", "udp443", "http_connect", "tls443",
    "wss443", "cdn_wss", "dns", "icmp_udp",
]

// Every carrier the app can select, in speed order.
let byPriority = TunnelTransport.allCases.sorted { $0.priority < $1.priority }
check(byPriority.map { $0.rawValue } == goCarrierChain,
      "transport rawValues match the Go chain order exactly")
check(TunnelTransport.allCases.count == goCarrierChain.count,
      "no carrier added on one side only (\(TunnelTransport.allCases.count) vs \(goCarrierChain.count))")

// Priorities must be exactly 1...8, dense and unique, so "lower = faster" is a
// total order with no ties the upgrade manager could resolve arbitrarily.
check(Set(TunnelTransport.allCases.map { $0.priority }) == Set(1...8),
      "priorities are exactly 1...8, unique and dense")

// udp443 must rank second: same speed as WireGuard-direct, one port portals pass
// more often. This is the exact rank the Go battery reorder corrected.
check(TunnelTransport.udp443.priority == 2,
      "udp443 ranks #2 (right after wireguard-direct)")
for tcp in [TunnelTransport.httpConnect, .tls443, .wss443, .cdnWSS] {
    check(tcp.priority > TunnelTransport.udp443.priority,
          "\(tcp.rawValue) ranks after udp443 (no TCP-over-TCP on udp443)")
}

// The reduced-speed / DNS-leak carriers are exactly the two tunnels, nothing else.
for t in TunnelTransport.allCases {
    let slow = (t == .dns || t == .icmpUDP)
    check(t.isReducedSpeed == slow, "isReducedSpeed correct for \(t.rawValue)")
    check(t.leaksDNSToNetwork == slow, "leaksDNSToNetwork correct for \(t.rawValue)")
}

// A round trip through rawValue (the Go boundary) must recover every case, so a
// "transport selected: <name>" line from the helper never silently falls back.
for t in TunnelTransport.allCases {
    check(TunnelTransport(rawValue: t.rawValue) == t,
          "rawValue round-trips for \(t.rawValue)")
}

// MARK: - PRIVACY-1 DoH status parsing (the Go helper <-> app boundary)

// Neither line: a transport that cannot carry DoH emits nothing here; that is
// DNS-1, warned separately, so the leak state stays unknown (nil), not "leaking".
check(DoHStatus.latestLeak(in: "ready utun6 10.0.0.2 tls443\n") == nil,
      "no doh line -> nil (DNS-1 handled separately, not a false PRIVACY-1)")

// Initial PRIVACY-1: the helper writes `doh down` during routing setup, before
// `ready`. Parser must report leaking even with the ready line present.
check(DoHStatus.latestLeak(in: "doh down\nready utun6 10.0.0.2 tls443\n") == true,
      "doh down before ready -> leaking (PRIVACY-1 shown)")

// Healthy path: `doh up` before `ready` -> not leaking.
check(DoHStatus.latestLeak(in: "doh up\nready utun6 10.0.0.2 tls443\n") == false,
      "doh up before ready -> not leaking")

// Auto-dismiss: the 60s retry appends `doh up` after the initial `doh down`.
// Newest wins, so the warning clears.
check(DoHStatus.latestLeak(in: "doh down\nready utun6 10.0.0.2 tls443\ndoh up\n") == false,
      "doh up after doh down -> not leaking (60s recovery dismisses the warning)")

// A later regression to down would re-show it (newest wins both ways).
check(DoHStatus.latestLeak(in: "doh up\ndoh down\n") == true,
      "newest line wins in both directions")

print("")
if failures == 0 {
    print("all KillSwitchRules + TunnelTransport + DoHStatus assertions passed")
    exit(0)
} else {
    print("\(failures) assertion(s) failed")
    exit(1)
}
