#!/usr/bin/env bash
# Shared helpers for the macOS (pf) captive portal test configs.
# Sourced by config*.sh — not run directly.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# shellcheck source=/dev/null
source "$ROOT/config.env"

ANCHOR="freewire.test"
ANCHOR_FILE="/tmp/freewire-pf-${ANCHOR}.conf"
STATE_DIR="/tmp/freewire-test-state"
BACKUP="$STATE_DIR/pf.conf.backup"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "This script applies firewall rules and must run as root:" >&2
    echo "  sudo $0" >&2
    exit 1
  fi
}

banner() {
  local n="$1" title="$2" path="$3" budget="$4"
  echo
  echo "=============================================================="
  echo " Config $n — $title"
  echo "=============================================================="
  echo " Expected path    : $path"
  echo " Timing budget    : $budget"
  echo " Interface        : $UPLINK_IF"
  echo " Server under test: $SERVER_IP"
  echo "--------------------------------------------------------------"
}

# Save the current pf state once per test session so reset.sh can restore it.
save_pf_state() {
  mkdir -p "$STATE_DIR"
  if [[ ! -f "$BACKUP" ]]; then
    if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
      echo "enabled" > "$STATE_DIR/pf.was"
    else
      echo "disabled" > "$STATE_DIR/pf.was"
    fi
    cp /etc/pf.conf "$BACKUP" 2>/dev/null || touch "$BACKUP"
    echo "Saved pf state (was: $(cat "$STATE_DIR/pf.was"))"
  fi
}

# Apply a pf ruleset passed on stdin, with an auto-revert safety timer.
apply_rules() {
  save_pf_state
  cat > "$ANCHOR_FILE"

  echo "Applying rules from $ANCHOR_FILE:"
  sed 's/^/    /' "$ANCHOR_FILE"
  echo

  if ! pfctl -n -f "$ANCHOR_FILE" 2>&1; then
    echo "Ruleset failed validation — nothing applied." >&2
    exit 1
  fi

  pfctl -E >/dev/null 2>&1 || true
  pfctl -f "$ANCHOR_FILE" >/dev/null 2>&1
  echo "Rules ACTIVE."

  if [[ "${AUTO_REVERT_SECONDS:-0}" -gt 0 ]]; then
    schedule_auto_revert
  fi
}

schedule_auto_revert() {
  local reset="$HERE/reset.sh"
  # Background watchdog: reverts unless the confirm flag appears.
  rm -f "$STATE_DIR/confirmed"
  (
    sleep "$AUTO_REVERT_SECONDS"
    if [[ ! -f "$STATE_DIR/confirmed" ]]; then
      "$reset" >/dev/null 2>&1 || true
      logger -t freewire-test "auto-reverted pf rules after ${AUTO_REVERT_SECONDS}s"
    fi
  ) &
  echo "$!" > "$STATE_DIR/watchdog.pid"

  echo
  echo "  SAFETY: rules auto-revert in ${AUTO_REVERT_SECONDS}s."
  echo "  To keep them longer:  sudo $HERE/confirm.sh"
  echo "  To revert now:        sudo $HERE/reset.sh"
}

footer() {
  echo
  echo "Next:"
  echo "  1. Connect Freewire on the test device."
  echo "  2. Verify the live path:  sudo $ROOT/which-path.sh"
  echo "  3. Record the result in  $ROOT/README.md"
  echo
}
