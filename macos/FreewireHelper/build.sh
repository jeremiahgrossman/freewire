#!/usr/bin/env bash
# Build the privileged helper without an Xcode target.
#
# The helper has no target in the project, and adding one would not help: what
# gates it is SMAppService registration, which needs a Developer ID. Compiling
# directly sidesteps the installer without sidestepping anything that matters --
# the same code runs against the same pf, just invoked under sudo rather than
# launched by launchd. See ../../DECISIONS.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/freewire-killswitch}"

swiftc -O \
  "$HERE/../Freewire/Freewire/KillSwitchRules.swift" \
  "$HERE/KillSwitchController.swift" \
  "$HERE/main.swift" \
  -o "$OUT"

echo "built $OUT"
