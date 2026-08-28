import Foundation

/// Parser for the helper's DoH status lines (PRIVACY-1).
///
/// The tunnel helper writes `doh down` / `doh up` on its stdout — the same
/// channel as the `ready …` line — so the app learns whether encrypted DNS is
/// in effect without scraping the stderr prose. `down` means the DoH forwarder
/// is not carrying lookups and they reach the network's resolver in cleartext;
/// `up` means encrypted DNS was (re)established.
///
/// Pulled out as a pure function with no AppKit dependency so it is testable at
/// the desk (`macos/Tests/run.sh`): it is the exact boundary the Go side's
/// `dohStatus` writes to, and a mismatch there is a silent privacy regression —
/// the warning would never show, or never clear.
enum DoHStatus {
    /// The newest DoH state in the helper's stdout so far:
    /// - `true`  — leaking (last line was `doh down`)
    /// - `false` — encrypted (last line was `doh up`)
    /// - `nil`   — the helper has written neither line (e.g. a transport that
    ///   cannot carry DoH at all, which is DNS-1 and warned separately)
    ///
    /// Newest wins: the file accumulates, so a later `doh up` after an initial
    /// `doh down` reports encrypted, which is how the 60s recovery dismisses the
    /// warning. Prefix-matched so a trailing newline or future suffix on the
    /// line does not defeat the match, while `ready`/other lines are ignored.
    static func latestLeak(in text: String) -> Bool? {
        var leak: Bool? = nil
        for line in text.components(separatedBy: "\n") {
            if line.hasPrefix("doh down") {
                leak = true
            } else if line.hasPrefix("doh up") {
                leak = false
            }
        }
        return leak
    }
}
