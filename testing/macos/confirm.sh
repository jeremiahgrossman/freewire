#!/usr/bin/env bash
# Cancel the auto-revert timer and keep the current rules until reset.sh.
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

mkdir -p "$STATE_DIR"
touch "$STATE_DIR/confirmed"

if [[ -f "$STATE_DIR/watchdog.pid" ]]; then
  kill "$(cat "$STATE_DIR/watchdog.pid")" 2>/dev/null || true
  rm -f "$STATE_DIR/watchdog.pid"
fi

echo "Auto-revert cancelled. Rules stay until you run reset.sh."
