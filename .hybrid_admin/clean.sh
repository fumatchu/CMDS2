 #!/usr/bin/env bash
# clean_rel_dir.sh — simple cleanup for .csv .env .json + meraki_claim.log symlink
# Usage: ./clean_rel_dir.sh [TARGET_DIR]   (default = .)

set -euo pipefail

TARGET_DIR="${1:-.}"

# Require dialog
if ! command -v dialog >/dev/null 2>&1; then
  echo "This script needs 'dialog' installed." >&2
  exit 1
fi

abs_target="$(readlink -f "$TARGET_DIR")"
SYM_PATH="$TARGET_DIR/meraki_claim.log"
HAS_SYMLINK=0
[[ -L "$SYM_PATH" ]] && HAS_SYMLINK=1

# Collect files (non-recursive; just the target directory)
mapfile -d '' FILES < <(find "$TARGET_DIR" -maxdepth 1 -type f \( -name '*.csv' -o -name '*.env' -o -name '*.json' \) -print0)
TOTAL="${#FILES[@]}"

# If nothing to do, still show the final message so the flow is consistent
if (( TOTAL == 0 && HAS_SYMLINK == 0 )); then
  dialog --no-shadow --title "Cleanup" \
    --msgbox "Switch batch has been cleaned\nStart with the Setup Wizard again for the next set of switches" 9 72
  clear; exit 0
fi

# Small helper to get file size in bytes (portable) — retained but not shown to user
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

# Setup gauge
PROG_PIPE="$(mktemp -u)"
mkfifo "$PROG_PIPE"
# shellcheck disable=SC3020
exec {PROG_FD}<>"$PROG_PIPE"

trap 'exec {PROG_FD}>&- 2>/dev/null || true; rm -f "$PROG_PIPE" 2>/dev/null || true' EXIT

(dialog --no-shadow --title "Cleaning…" \
        --gauge "Starting…" 8 70 0 < "$PROG_PIPE") & DPID=$!

update_gauge () {
  local pct="$1" msg="$2"
  printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$msg" >&"$PROG_FD"
}

# Delete files
for ((i=0; i<TOTAL; i++)); do
  f="${FILES[$i]}"
  rel="${f#"$TARGET_DIR"/}"
  pct=$(( TOTAL > 0 ? (i*100)/TOTAL : 0 ))
  update_gauge "$pct" "Deleting: ${rel}"
  rm -f -- "$f" || true
done

# Remove the meraki_claim.log symlink (only the link, not the target)
if (( HAS_SYMLINK )); then
  update_gauge 95 "Removing symlink: meraki_claim.log"
  rm -f -- "$SYM_PATH" || true
fi

update_gauge 100 "Finalizing…"
sleep 0.2

# Close gauge cleanly
exec {PROG_FD}>&- 2>/dev/null || true
for _ in 1 2 3 4 5; do
  if ! kill -0 "$DPID" 2>/dev/null; then break; fi
  sleep 0.2
done
kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

# Single, simple final message
dialog --no-shadow --title "Cleanup complete" --ok-label "OK" \
  --msgbox "Switch batch has been cleaned and start with the Setup Wizard again for the Next set of Switches" 9 72

clear
exit 0
