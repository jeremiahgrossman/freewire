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

    /// Where the ruleset displaced by engage is kept, so release can restore it.
    static let savedRulesPath = "/etc/freewire/pf-previous.conf"
    /// Exposed so the dead-man switch in main.swift can clear it.
    static let stateFile = "/etc/freewire/killswitch.conf"

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

        // Capture whatever is loaded before replacing it, so release can put it
        // back. `pfctl -f` replaces the entire ruleset -- there is no way to add
        // rules without an anchor reference in /etc/pf.conf, and editing a
        // system file to get one is a larger intrusion than this. What must not
        // happen is the previous version's behaviour: replace the ruleset, then
        // release by flushing everything, leaving the machine with no pf rules
        // at all and every other consumer's rules silently gone.
        let existing = run("/sbin/pfctl", ["-s", "rules"])
        if existing.status == 0 {
            try? existing.output.write(toFile: Self.savedRulesPath,
                                       atomically: true, encoding: .utf8)
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
        // Restore, do not flush.
        //
        // This ran `pfctl -F all`, which erases every rule on the machine --
        // ours, macOS's own anchors, and anything any other application had
        // loaded. Releasing a kill switch is not a reason to disarm the
        // system's firewall, and the previous state is recoverable: either what
        // was captured at engage, or failing that the system default.
        let restore: (status: Int32, output: String)
        if FileManager.default.fileExists(atPath: Self.savedRulesPath) {
            restore = run("/sbin/pfctl", ["-f", Self.savedRulesPath])
        } else {
            restore = run("/sbin/pfctl", ["-f", "/etc/pf.conf"])
        }
        guard restore.status == 0 else {
            throw Failure.pfctlFailed(restore.output)
        }
        try? FileManager.default.removeItem(atPath: Self.savedRulesPath)

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
        // Ask pf what is loaded, not the filesystem what we once wrote.
        //
        // This tested for the existence of the rules file, which survives a
        // ruleset being replaced, flushed, or rejected. The file is written
        // before pf is touched, so a load that failed left the file present and
        // this reporting the kill switch active over a machine with no rules at
        // all -- the one lie a kill switch must never tell.
        let info = run("/sbin/pfctl", ["-s", "info"])
        guard info.status == 0, info.output.contains("Status: Enabled") else {
            return false
        }
        let rules = run("/sbin/pfctl", ["-s", "rules"])
        guard rules.status == 0 else { return false }
        // The marker is the default-deny our ruleset opens with. Its presence
        // means our rules are the ones loaded, not merely that pf is on.
        return rules.output.contains("block drop all")
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
