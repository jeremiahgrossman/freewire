import Foundation

/// Generates the `pf` ruleset that blocks traffic while the tunnel is down.
///
/// Kept as a pure function of its inputs so it can be tested without root, a
/// helper, or a live tunnel. Getting this wrong has two failure modes and both
/// are bad: too permissive leaks the traffic the user believed was protected,
/// too strict strands the machine with no way to reconnect and no obvious
/// cause.
struct KillSwitchRules {

    /// Endpoints that must stay reachable for the tunnel to be re-established.
    struct ServerEndpoint {
        let host: String        // literal IPv4 address
        let tcpPorts: [Int]
        let udpPorts: [Int]
    }

    let serverEndpoints: [ServerEndpoint]
    /// Tunnel interfaces to exempt, e.g. "utun6". Empty while reconnecting.
    let tunnelInterfaces: [String]
    /// Permit DHCP so an interface can renew its lease.
    let allowDHCP: Bool
    /// Permit traffic to RFC 1918 destinations.
    ///
    /// Off by default. It makes printers and NAS reachable while the tunnel is
    /// down, but a captive portal lives on the local network too, so allowing
    /// it means the traffic the kill switch exists to stop can reach exactly
    /// the party most likely to be watching.
    let allowLocalNetwork: Bool

    init(
        serverEndpoints: [ServerEndpoint],
        tunnelInterfaces: [String] = [],
        allowDHCP: Bool = true,
        allowLocalNetwork: Bool = false
    ) {
        self.serverEndpoints = serverEndpoints
        self.tunnelInterfaces = tunnelInterfaces
        self.allowDHCP = allowDHCP
        self.allowLocalNetwork = allowLocalNetwork
    }

    /// Identifier for the ruleset.
    ///
    /// Named for an anchor because that was the intent, but nothing loads into
    /// one: an anchor only takes effect if /etc/pf.conf references it, and
    /// editing a system file to add that reference is a larger intrusion than
    /// replacing the ruleset and putting the previous one back. The controller
    /// saves what it displaces and restores it on release. Left here because
    /// the anchor approach is still the right end state if the app ever ships
    /// with an installer that can own /etc/pf.conf.
    static let anchorName = "com.freewire.killswitch"

    /// Renders the ruleset.
    func render() -> String {
        var out: [String] = []

        out.append("# Freewire kill switch. Generated — do not edit by hand.")
        out.append("#")
        out.append("# Blocks everything except what is needed to rebuild the tunnel.")
        out.append("# Replaces the main ruleset; the displaced one is restored on release.")
        out.append("")

        // Loopback is exempted wholesale: local IPC has nothing to do with the
        // tunnel, and blocking it breaks unrelated software in confusing ways.
        out.append("set block-policy drop")
        out.append("set skip on lo0")
        out.append("")

        out.append("# Default deny, both directions.")
        out.append("block drop all")
        out.append("")

        if !tunnelInterfaces.isEmpty {
            out.append("# The tunnel itself. Traffic here is already encrypted.")
            for iface in tunnelInterfaces {
                out.append("pass quick on \(sanitize(iface)) all")
            }
            out.append("")
        }

        if !serverEndpoints.isEmpty {
            out.append("# Reaching the server, so a dropped tunnel can be rebuilt.")
            out.append("# Without this the kill switch is a trap: it blocks the very")
            out.append("# traffic needed to restore the protection it is enforcing.")
            for ep in serverEndpoints {
                let host = sanitize(ep.host)
                if !ep.tcpPorts.isEmpty {
                    out.append("pass out quick proto tcp to \(host) port { \(portList(ep.tcpPorts)) }")
                }
                if !ep.udpPorts.isEmpty {
                    out.append("pass out quick proto udp to \(host) port { \(portList(ep.udpPorts)) }")
                }
            }
            out.append("")
        }

        if allowDHCP {
            out.append("# DHCP. Blocking renewal costs the machine its address on")
            out.append("# lease expiry, which looks like the kill switch breaking the")
            out.append("# network rather than protecting it.")
            out.append("pass out quick proto udp from any port 68 to any port 67")
            out.append("pass in quick proto udp from any port 67 to any port 68")
            out.append("")
        }

        if allowLocalNetwork {
            out.append("# Local network. Off by default: a captive portal is on the")
            out.append("# local network too.")
            out.append("pass quick from any to 10.0.0.0/8")
            out.append("pass quick from any to 172.16.0.0/12")
            out.append("pass quick from any to 192.168.0.0/16")
            out.append("")
        }

        return out.joined(separator: "\n") + "\n"
    }

    /// Rejects anything that could break out of the rule it appears in.
    ///
    /// These values arrive from server config and interface names rather than
    /// from a user, but they are interpolated into a file that runs with root
    /// privileges, so they are checked rather than trusted.
    private func sanitize(_ value: String) -> String {
        let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_")
        return String(value.filter { allowed.contains($0) })
    }

    private func portList(_ ports: [Int]) -> String {
        ports.filter { (1...65535).contains($0) }
             .map(String.init)
             .joined(separator: ", ")
    }
}
