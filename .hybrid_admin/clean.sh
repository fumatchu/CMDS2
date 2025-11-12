#!/usr/bin/env bash
# clean_rel_dir.sh — dialog-based cleanup for .csv .env .json files
# Usage: ./clean_rel_dir.sh [TARGET_DIR]   (default = .)

set -euo pipefail

TARGET_DIR="${1:-.}"

# Require dialog
if ! command -v dialog >/dev/null 2>&1; then
  echo "This script needs 'dialog' installed." >&2
  exit 1
fi

# Collect files (non-recursive; just the target directory)
mapfile -d '' FILES < <(find "$TARGET_DIR" -maxdepth 1 -type f \( -name '*.csv' -o -name '*.env' -o -name '*.json' \) -print0)

TOTAL="${#FILES[@]}"
if (( TOTAL == 0 )); then
  dialog --no-shadow --title "Cleanup" --msgbox "No .csv, .env, or .json files found in:\n$(readlink -f "$TARGET_DIR")" 8 70
  clear; exit 0
fi

# Optional preview (first few files)
preview=""
limit=$(( TOTAL < 10 ? TOTAL : 10 ))
for ((i=0; i<limit; i++)); do
  f="${FILES[$i]}"
  preview+=$'\n'$(basename -- "$f")
done
(( TOTAL > limit )) && preview+=$'\n'"... and $((TOTAL-limit)) more"

dialog --no-shadow --title "Confirm delete" --yesno \
"Delete $TOTAL file(s) in:\n$(readlink -f "$TARGET_DIR")\n\nExtensions: .csv .env .json\n\nPreview:$preview\n\nThis is PERMANENT. Continue?" 16 70
resp=$?
clear
if (( resp != 0 )); then exit 1; fi

# Small helper to get file size in bytes (portable)
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

# Work through files
deleted=0
freed=0

update_gauge () {
  local pct="$1" msg="$2"
  # dialog gauge protocol
  printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$msg" >&"$PROG_FD"
}

for ((i=0; i<TOTAL; i++)); do
  f="${FILES[$i]}"
  rel="${f#"$TARGET_DIR"/}"
  size=$(get_size "$f")
  pct=$(( (i*100) / TOTAL ))
  update_gauge "$pct" "Deleting: ${rel}"
  rm -f -- "$f" || true
  deleted=$((deleted+1))
  freed=$((freed+size))
done

update_gauge 100 "Done. Deleted $deleted file(s)."
sleep 0.3

# === CHANGED: close gauge cleanly and force-exit if needed ===
exec {PROG_FD}>&- 2>/dev/null || true
# give dialog up to ~1s to exit on its own
for _ in 1 2 3 4 5; do
  if ! kill -0 "$DPID" 2>/dev/null; then break; fi
  sleep 0.2
done
# if somehow still alive, terminate it and continue
kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

# Human readable freed size
hr() {
  local b=$1
  if (( b < 1024 )); then printf "%d B" "$b"
  elif (( b < 1048576 )); then printf "%.1f KB" "$(echo "$b / 1024" | bc -l)"
  elif (( b < 1073741824 )); then printf "%.1f MB" "$(echo "$b / 1048576" | bc -l)"
  else printf "%.2f GB" "$(echo "$b / 1073741824" | bc -l)"; fi
}

# === CHANGED: auto-dismiss summary, then exit cleanly ===
dialog --no-shadow --title "Cleanup complete" --timeout 2 \
  --msgbox "Deleted: $deleted file(s)\nFreed: $(hr "$freed")\nPath:  $(readlink -f "$TARGET_DIR")" 9 60 || true
clear
exit 0
