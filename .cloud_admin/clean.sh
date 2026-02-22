#!/usr/bin/env bash
# clean_rel_dir.sh — CMDS cleanup for migration/preflight artifacts
# Usage: ./clean_rel_dir.sh [TARGET_DIR]   (default = .)

set -euo pipefail

TARGET_DIR="${1:-.}"

# Require dialog
if ! command -v dialog >/dev/null 2>&1; then
  echo "This script needs 'dialog' installed." >&2
  exit 1
fi

# Collect files (non-recursive; just the target directory)
# NOTE: protect the "bible" manifest from deletion
mapfile -d '' FILES < <(find "$TARGET_DIR" -maxdepth 1 -type f \
  \( -name '*.csv' -o -name '*.env' -o -name '*.json' -o -name '*.flag' -o -name '*.ok' \) \
  ! -name 'cloud_models.json' \
  -print0)

# Also remove the meraki_claim.log symlink if present
if [[ -L "$TARGET_DIR/meraki_claim.log" ]]; then
  FILES+=("$TARGET_DIR/meraki_claim.log")
fi

TOTAL="${#FILES[@]}"
if (( TOTAL == 0 )); then
  dialog --no-shadow --title "Cleanup" --msgbox \
"Nothing to clean.

No .csv/.env/.json/.flag/.ok files or
Meraki claim log symlink were found in:
$(readlink -f "$TARGET_DIR")" 11 76
  clear
  exit 0
fi

dialog --no-shadow --title "Prepare for next migration" --yesno \
"This will clean up CMDS migration and preflight artifacts in:

$(readlink -f "$TARGET_DIR")

• Remove previous migration result/working files
• Remove Meraki claim log symlink (if present)
• Remove ALL .ok state files
• Free up space and reset state

Use this when you are finished with one batch of switches
and want to prepare the system for the NEXT migration.

After cleanup, please run the Setup Wizard again
before starting another migration.

Do you want to continue?" 20 74

resp=$?
clear
if (( resp != 0 )); then
  exit 1
fi

get_size() {
  local f="$1" s
  if s=$(stat -c %s "$f" 2>/dev/null); then
    echo "$s"
  elif s=$(wc -c <"$f" 2>/dev/null); then
    echo "$s"
  else
    echo 0
  fi
}

PROG_PIPE="$(mktemp -u)"
mkfifo "$PROG_PIPE"
exec {PROG_FD}<>"$PROG_PIPE"

cleanup_pipe() {
  exec {PROG_FD}>&- 2>/dev/null || true
  rm -f "$PROG_PIPE" 2>/dev/null || true
}
trap 'cleanup_pipe' EXIT

(dialog --no-shadow --title "Cleaning configuration artifacts…" \
        --gauge "Starting…" 8 70 0 < "$PROG_PIPE") & DPID=$!

deleted=0
freed=0

update_gauge () {
  local pct="$1" msg="$2"
  printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$msg" >&"$PROG_FD"
}

for ((i=0; i<TOTAL; i++)); do
  f="${FILES[$i]}"
  rel="${f#"$TARGET_DIR"/}"
  size=$(get_size "$f")
  pct=$(( (i*100) / TOTAL ))
  update_gauge "$pct" "Removing: ${rel}"
  rm -f -- "$f" || true
  deleted=$((deleted+1))
  freed=$((freed+size))
done

update_gauge 100 "Finalizing cleanup…"
sleep 0.3

exec {PROG_FD}>&- 2>/dev/null || true

for _ in 1 2 3 4 5; do
  if ! kill -0 "$DPID" 2>/dev/null; then
    break
  fi
  sleep 0.2
done

kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

hr() {
  local b=$1
  if (( b < 1024 )); then
    printf "%d B" "$b"
  elif (( b < 1048576 )); then
    printf "%.1f KB" "$(echo "$b / 1024" | bc -l)"
  elif (( b < 1073741824 )); then
    printf "%.1f MB" "$(echo "$b / 1048576" | bc -l)"
  else
    printf "%.2f GB" "$(echo "$b / 1073741824" | bc -l)"
  fi
}

dialog --no-shadow --title "Configuration cleanup complete" --msgbox \
"Cleanup finished successfully.

Stale migration/preflight artifacts removed: $deleted
Approximate space reclaimed: $(hr "$freed")

System is now ready for the NEXT set of switches.

IMPORTANT:
Please run the Setup Wizard again before starting
another migration batch." 16 74 || true

clear
exit 0