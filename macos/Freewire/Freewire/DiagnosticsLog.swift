import Foundation

/// Accumulates raw bytes from a stream (a stderr pipe) and extracts complete
/// lines as they arrive, holding any trailing partial line until either more
/// data completes it or `flushRemainder` is called at stream end.
///
/// A reference type with an internal lock rather than a captured `var`: the
/// pipe's `readabilityHandler` fires on Foundation's own background queue, and
/// the same buffer is flushed once more from the process-exit path, so two
/// different execution contexts touch it across the tunnel's lifetime.
final class LineBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var pending = Data()

    /// Appends `chunk`, returns every complete (newline-terminated) line found,
    /// each with its trailing newline stripped. Incomplete data at the end
    /// stays buffered for the next call.
    func appendAndExtractLines(_ chunk: Data) -> [String] {
        lock.lock()
        defer { lock.unlock() }
        pending.append(chunk)
        var lines: [String] = []
        while let newlineRange = pending.range(of: Data([0x0A])) {
            let lineData = pending[..<newlineRange.lowerBound]
            pending.removeSubrange(..<newlineRange.upperBound)
            if let line = String(data: lineData, encoding: .utf8), !line.isEmpty {
                lines.append(line)
            }
        }
        return lines
    }

    /// Returns and clears whatever partial line never saw a trailing newline,
    /// or nil if the buffer was already empty. Call once, at stream end.
    func flushRemainder() -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard !pending.isEmpty else { return nil }
        let line = String(data: pending, encoding: .utf8)
        pending.removeAll()
        return (line?.isEmpty ?? true) ? nil : line
    }
}

/// Persistent, timestamped local diagnostics log.
///
/// The tunnel helper already writes rich diagnostic output (carrier selection,
/// fallback reasons, DoH status, periodic per-second throughput/tail-drop
/// stats on the DNS carrier) to stderr -- this session leaned on exactly that
/// output throughout every field test. The gap was never richness, it was
/// that `/tmp/freewire-tunnel-stderr.log` is truncated on every connect and
/// lives in a directory the OS can clear at any time, so nothing survives
/// past the current session.
///
/// This does not invent a new logging system. It captures the SAME stream
/// (already reviewed and known to carry no client IPs -- see the non-negotiable
/// constraint in CLAUDE.md), timestamps each line, and appends it here instead
/// of letting it evaporate. Local only: nothing here is transmitted anywhere
/// automatically. Export is a deliberate, on-demand user action (see
/// `exportSnapshot`), not a background upload -- see DECISIONS.md's
/// NETWORK-INTELLIGENCE entry for why an automatic client->server telemetry
/// pipeline was declined, and why this project keeps that boundary.
enum DiagnosticsLog {
    /// Lines are trimmed once the file exceeds this size, keeping the most
    /// recent `trimTargetBytes` -- bounded local disk use without a full
    /// rotation scheme, which is more machinery than a single-file diagnostic
    /// log run by one operator needs.
    static let trimThresholdBytes = 20 * 1024 * 1024 // 20 MB
    static let trimTargetBytes = 10 * 1024 * 1024 // 10 MB

    private static var appDirectory: URL? {
        guard let dir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first else { return nil }
        let appDir = dir.appendingPathComponent("Freewire", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: appDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return appDir
    }

    static var fileURL: URL? {
        appDirectory?.appendingPathComponent("diagnostics.log")
    }

    /// Formats one raw diagnostic line with a leading RFC3339 timestamp.
    ///
    /// A pure function (no file I/O) so it's directly unit-testable. Strips a
    /// trailing newline from the input if present, since the caller always
    /// appends exactly one newline after formatting -- avoids double blank
    /// lines when the source already line-terminated.
    static func formatLine(_ raw: String, at date: Date = Date()) -> String {
        let iso = ISO8601DateFormatter()
        let trimmed = raw.hasSuffix("\n") ? String(raw.dropLast()) : raw
        return "\(iso.string(from: date)) \(trimmed)"
    }

    /// Given the log's current contents and its byte size, decides whether
    /// trimming is needed and returns the trimmed contents if so.
    ///
    /// Pure function, unit-tested directly: trims at a LINE boundary (never
    /// mid-line, which would leave a corrupt fragment at the top of the file)
    /// by dropping whole lines from the front until at or under the target
    /// size.
    static func trimIfNeeded(_ contents: String, thresholdBytes: Int = trimThresholdBytes, targetBytes: Int = trimTargetBytes) -> String? {
        guard contents.utf8.count > thresholdBytes else { return nil }
        var lines = contents.split(separator: "\n", omittingEmptySubsequences: false)
        // Drop from the front until under target, or one line remains (never
        // trim to nothing -- a single huge line is kept whole rather than
        // silently emptying the log).
        while lines.count > 1 {
            let candidate = lines.dropFirst().joined(separator: "\n")
            if candidate.utf8.count <= targetBytes { return candidate }
            lines = Array(lines.dropFirst())
        }
        return lines.joined(separator: "\n")
    }

    /// Appends one already-formatted (timestamped) line, then trims if the
    /// file has grown past the threshold. Best-effort: a write failure here
    /// must never interrupt the tunnel connection it is describing.
    static func appendLine(_ raw: String) {
        guard let url = fileURL else { return }
        let line = formatLine(raw) + "\n"

        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let handle = try? FileHandle(forWritingTo: url) else { return }
        defer { try? handle.close() }
        handle.seekToEndOfFile()
        handle.write(Data(line.utf8))

        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = attributes?[.size] as? Int ?? 0
        if size > trimThresholdBytes {
            if let contents = try? String(contentsOf: url, encoding: .utf8),
               let trimmed = trimIfNeeded(contents) {
                try? trimmed.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    /// Copies the current log to `destination`, for the user's own deliberate
    /// export -- e.g. via a Preferences action and NSSavePanel. Never called
    /// automatically; this is the only path data from this file ever takes.
    static func exportSnapshot(to destination: URL) throws {
        guard let url = fileURL, FileManager.default.fileExists(atPath: url.path) else {
            throw CocoaError(.fileNoSuchFile)
        }
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.copyItem(at: url, to: destination)
    }
}
