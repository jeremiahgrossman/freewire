# SESSION-TEMPLATE.md

Copy and fill in this briefing at the start of every Claude Code session before describing your task. It takes 30 seconds and replaces exploratory context-setting that wastes tokens.

---

## Session Briefing

**Active phase:** [Phase number and name — e.g., "Phase 1 — Foundation"]

**Component I'm working on:** [Single file or module — be specific. e.g., "server/internal/tunnel/dns_server.go"]

**Task:** [One sentence. e.g., "Implement the DH handshake Step 1 handler in the DNS tunnel server."]

**Relevant spec:** [Filename and section. e.g., "dns-tunnel-protocol-spec.md §Handshake"]

**Acceptance criterion I'm targeting:** [Which phase gate criterion. e.g., "Phase 2 gate: all 4 fallback paths work against captive portal test configs 1–4"]

**Last thing completed:** [One sentence. e.g., "TLS/443 path with uTLS — all 3 fingerprint profiles working."]

**Constraints that apply to this task:** [Relevant non-negotiables from CLAUDE.md. e.g., "Session keys are ephemeral — never persist them. No client IPs in any log line."]

---

**My task:** [Now describe what you need help with in detail.]

---

## Why this works

- **Phase** tells Claude which spec files are in scope and which to ignore.
- **Component** prevents Claude from exploring the codebase unnecessarily.
- **Task** scopes the work so Claude doesn't over-build.
- **Relevant spec** tells Claude exactly what to read — not "go find the right doc."
- **Acceptance criterion** gives Claude a binary pass/fail to work toward.
- **Last completed** reconstructs continuity without reading git history.
- **Constraints** front-loads the rules most likely to be violated for this specific task.
