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

// MARK: - Path-upgrade candidate scope (probe .dns / .icmpUDP reasoning)

// The upgrade manager probes only paths FASTER than the current one. That makes
// DNS an upgrade target solely from ICMP, and ICMP a target from nobody -- which
// is exactly why probe(.dns) is implemented and probe(.icmpUDP) stays false.
// Pin it so a priority reorder cannot silently break that reasoning.
func fasterThan(_ t: TunnelTransport) -> [TunnelTransport] {
    TunnelTransport.allCases.filter { $0.priority < t.priority }
}
check(TunnelTransport.allCases.filter { fasterThan($0).contains(.dns) } == [.icmpUDP],
      "DNS is a faster-path upgrade candidate only from ICMP")
check(TunnelTransport.allCases.allSatisfy { !fasterThan($0).contains(.icmpUDP) },
      "ICMP is never a faster-path upgrade candidate (nothing is slower)")

// MARK: - MagicProbe wire codec (udp443 upgrade probe <-> server responder)

// The client's udp443 probe must speak the server's exact magic-UDP format
// (probe.go / udp443.go: FWPROBE1, 16-byte nonce, 64-byte floor). A drift makes
// the probe silently never pass, so udp443 upgrades would stop.
check(MagicProbe.magic == Array("FWPROBE1".utf8), "probe magic matches server probeMagic")
check(MagicProbe.nonceLen == 16, "nonce length matches server probeNonceLen")
check(MagicProbe.minRequest == 64, "request floor matches server probeMinRequest")

let n0 = [UInt8](repeating: 0xAB, count: MagicProbe.nonceLen)
let req = MagicProbe.request(nonce: n0)
check(req.count == MagicProbe.minRequest, "request is padded up to the 64-byte floor")
check(Array(req.prefix(8)) == MagicProbe.magic, "request opens with the magic")
check(Array(req[8 ..< 8 + MagicProbe.nonceLen]) == n0, "request carries the nonce after the magic")

// A well-formed reply (magic + our nonce) passes; a wrong nonce or a short
// datagram does not -- an unrelated packet on the port must not read as a pass.
check(MagicProbe.replyMatches(MagicProbe.magic + n0, nonce: n0), "reply echoing our nonce passes")
let n1 = [UInt8](repeating: 0xCD, count: MagicProbe.nonceLen)
check(!MagicProbe.replyMatches(MagicProbe.magic + n1, nonce: n0), "reply with a different nonce fails")
check(!MagicProbe.replyMatches(MagicProbe.magic, nonce: n0), "reply too short to carry a nonce fails")

print("")
if failures == 0 {
    print("all KillSwitchRules + TunnelTransport + DoHStatus + MagicProbe assertions passed")
    exit(0)
} else {
    print("\(failures) assertion(s) failed")
    exit(1)
}
