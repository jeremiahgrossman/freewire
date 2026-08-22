import Foundation

// Command-line entry point for the privileged helper.
//
// The helper's eventual home is an SMAppService daemon talking XPC to the app,
// which needs a Developer ID this machine does not have. That blocked
// registration, and registration was treated as blocking the helper itself --
// so the pf logic sat unverified behind a certificate.
//
// It does not have to. SMAppService is only the installer; what it installs is
// an ordinary root process. Invoking that process directly under sudo exercises
// exactly the same code against exactly the same pf, and needs no certificate.
// The XPC wrapper can go on top later without touching what is below it.
//
//     freewire-killswitch engage --server <ip> --ports 443,53,4500 [--revert N]
//     freewire-killswitch release
//     freewire-killswitch status
//
// --revert is a dead-man switch: the rules come back out after N seconds unless
// released first. It exists because a kill switch that blocks everything is one
// mistake away from cutting the machine off the network, and this code has done
// that before through a rule scoped to an interface rather than to a host.

enum CLIError: Error, CustomStringConvertible {
    case usage(String)
    var description: String {
        switch self {
        case .usage(let m): return m
        }
    }
}

func arg(_ name: String) -> String? {
    guard let i = CommandLine.arguments.firstIndex(of: "--\(name)"),
          i + 1 < CommandLine.arguments.count else { return nil }
    return CommandLine.arguments[i + 1]
}

func requireRoot() {
    guard getuid() == 0 else {
        FileHandle.standardError.write(Data(
            "freewire-killswitch: must run as root (pf requires it)\n".utf8))
        exit(2)
    }
}

let controller = KillSwitchController()

do {
    guard CommandLine.arguments.count > 1 else {
        throw CLIError.usage("usage: freewire-killswitch engage|release|status")
    }

    switch CommandLine.arguments[1] {
    case "engage":
        requireRoot()
        guard let server = arg("server") else {
            throw CLIError.usage("engage requires --server <ip>")
        }
        // The transports the tunnel actually uses: TLS/443 and HTTP CONNECT
        // over TCP, the DNS tunnel and ICMP/UDP and WireGuard over UDP.
        let tcp = (arg("tcp") ?? "443,8080").split(separator: ",").compactMap { Int($0) }
        let udp = (arg("udp") ?? "53,4500,51820").split(separator: ",").compactMap { Int($0) }
        let tun = (arg("tunnel") ?? "").split(separator: ",").map(String.init)

        let rules = KillSwitchRules(
            serverEndpoints: [.init(host: server, tcpPorts: tcp, udpPorts: udp)],
            tunnelInterfaces: tun
        )
        try controller.engage(rules)
        print("engaged: everything blocked except \(server) tcp\(tcp) udp\(udp)")

        if let revert = arg("revert").flatMap(Int.init), revert > 0 {
            // Deliberately a child process rather than a timer in this one: the
            // point is to survive this process being killed, which is the case
            // that strands the machine.
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            let script = "sleep \(revert); /sbin/pfctl -f /etc/pf.conf >/dev/null 2>&1"
            p.arguments = ["-c", script]
            try? p.run()
            print("dead-man switch armed: rules revert in \(revert)s unless released")
        }

    case "release":
        requireRoot()
        try controller.release()
        print("released")

    case "status":
        print(controller.isEngaged() ? "engaged" : "not engaged")

    default:
        throw CLIError.usage("unknown command: \(CommandLine.arguments[1])")
    }
} catch {
    FileHandle.standardError.write(Data("freewire-killswitch: \(error)\n".utf8))
    exit(1)
}
