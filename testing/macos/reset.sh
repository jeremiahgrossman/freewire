#!/usr/bin/env bash
# Restore the pf state saved before the first config was applied.
source "$(dirname "${BASH_SOURCE[0]}")/_lib.sh"
require_root

# Stop any pending auto-revert watchdog.
if [[ -f "$STATE_DIR/watchdog.pid" ]]; then
  kill "$(cat "$STATE_DIR/watchdog.pid")" 2>/dev/null || true
  rm -f "$STATE_DIR/watchdog.pid"
fi

if [[ -f "$BACKUP" ]]; then
  pfctl -f "$BACKUP" >/dev/null 2>&1 || true
  echo "Restored /etc/pf.conf ruleset."
else
  pfctl -f /etc/pf.conf >/dev/null 2>&1 || true
  echo "No backup found — reloaded /etc/pf.conf."
fi

if [[ -f "$STATE_DIR/pf.was" ]] && [[ "$(cat "$STATE_DIR/pf.was")" == "disabled" ]]; then
  pfctl -d >/dev/null 2>&1 || true
  echo "pf disabled (its state before testing)."
fi

rm -f "$STATE_DIR/confirmed" "$BACKUP" "$STATE_DIR/pf.was"
echo "Network restored to open."
