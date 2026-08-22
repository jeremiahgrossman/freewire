import Foundation

/// Applies and releases the kill switch `pf` ruleset.
///
/// Runs inside the privileged helper. Everything here needs root, which is the
/// only reason the helper exists.
///
/// **Fail closed.** If this process dies while the switch is engaged, the rules
/// stay loaded and traffic stays blocked. That is deliberate: the alternative
/// is that a crash silently unblocks traffic the user believes is protected,
/// and a VPN that quietly stops protecting is worse than one that visibly stops
/// working. The cost is accepted — a crash can leave the machine without
/// network until Freewire is relaunched, so `release` is reachable without the
/// app in `FreewireHelper.md`.
struct KillSwitchController {

    enum Failure: Error, CustomStringConvertible {
        case pfctlFailed(String)
        case rulesRejected(String)

        var description: String {
            switch self {
            case .pfctlFailed(let m):   return "pfctl failed: \(m)"
            case .rulesRejected(let m): return "ruleset rejected: \(m)"
            }
        }
    }

    private let anchor = KillSwitchRules.anchorName
    private let rulesPath = "/etc/freewire/killswitch.conf"

    /// Loads the ruleset and enables pf.
    func engage(_ rules: KillSwitchRules) throws {
        let text = rules.render()

        try? FileManager.default.createDirectory(
            atPath: "/etc/freewire", withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try text.write(toFile: rulesPath, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: rulesPath
        )

        // Validate before loading. A rejected ruleset would otherwise leave pf
        // enabled with whatever was loaded before, which may be nothing —
        // silently unprotected while the UI says otherwise.
        let check = run("/sbin/pfctl", ["-n", "-f", rulesPath])
        guard check.status == 0 else {
            throw Failure.rulesRejected(check.output)
        }

        let load = run("/sbin/pfctl", ["-f", rulesPath])
        guard load.status == 0 else {
            throw Failure.pfctlFailed(load.output)
        }

        // -E enables pf and takes a reference. Releasing uses -X with the token
        // so other software's pf usage is not disabled underneath it.
        let enable = run("/sbin/pfctl", ["-E"])
        guard enable.status == 0 else {
            throw Failure.pfctlFailed(enable.output)
        }
        if let token = parseEnableToken(enable.output) {
            try? token.write(toFile: "/etc/freewire/pf.token",
                             atomically: true, encoding: .utf8)
        }
    }

    /// Removes the rules and releases pf.
    ///
    /// Only ever called on an explicit user action — disconnecting, or quitting
    /// the app. Never on a timer, and never because reconnection failed.
    func release() throws {
        let flush = run("/sbin/pfctl", ["-F", "all"])
        guard flush.status == 0 else {
            throw Failure.pfctlFailed(flush.output)
        }

        if let token = try? String(contentsOfFile: "/etc/freewire/pf.token", encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty {
            _ = run("/sbin/pfctl", ["-X", token])
            try? FileManager.default.removeItem(atPath: "/etc/freewire/pf.token")
        }
        try? FileManager.default.removeItem(atPath: rulesPath)
    }

    /// Whether the kill switch is currently loaded.
    ///
    /// Read from pf rather than from any state this process holds, so a helper
    /// that restarted still reports the truth.
    func isEngaged() -> Bool {
        FileManager.default.fileExists(atPath: rulesPath)
            && run("/sbin/pfctl", ["-s", "info"]).output.contains("Status: Enabled")
    }

    // MARK: - Helpers

    private func parseEnableToken(_ output: String) -> String? {
        // "Token : 1234567890"
        for line in output.split(separator: "\n") where line.contains("Token") {
            return line.split(separator: ":").last?
                .trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    private func run(_ path: String, _ args: [String]) -> (status: Int32, output: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (1, "\(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
}
