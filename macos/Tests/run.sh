#!/usr/bin/env bash
# Compile and run the standalone Swift assertions.
#
#   macos/Tests/run.sh
#
# The project has a single target and no test bundle, so these compile the
# source directly rather than going through XCTest.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/../Freewire/Freewire"
OUT="$(mktemp -d)/killswitch-tests"

swiftc -O \
  "$SRC/KillSwitchRules.swift" \
  "$SRC/PathUpgradeManager.swift" \
  "$HERE/main.swift" \
  -o "$OUT"

"$OUT"
