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

print("")
if failures == 0 {
    print("all KillSwitchRules assertions passed")
    exit(0)
} else {
    print("\(failures) assertion(s) failed")
    exit(1)
}
