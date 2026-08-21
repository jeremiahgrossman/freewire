import Cocoa

// Top-level code in main.swift is nonisolated in Swift 6 even with
// SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor. MainActor.assumeIsolated
// establishes the @MainActor context so we can create the delegate and
// assign it. This is safe: the entry point always runs on the main thread.
MainActor.assumeIsolated {
    let delegate = AppDelegate()
    NSApplication.shared.delegate = delegate
    NSApplication.shared.run()
}
