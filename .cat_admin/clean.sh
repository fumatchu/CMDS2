#!/usr/bin/env bash
# clean_rel_dir.sh — Quiet state reset for /root/.cat_admin
# Keeps runs/ logs. Removes state files only.

set -euo pipefail

TARGET="/root/.cat_admin"
REAL_TARGET="$(readlink -f "$TARGET")"

if ! command -v dialog >/dev/null 2>&1; then
  echo "dialog is required." >&2
  exit 1
fi

[[ -d "$REAL_TARGET" ]] || exit 1
[[ "$REAL_TARGET" == "/root/.cat_admin" ]] || exit 1

FILES=()

# Top-level only — never touch runs/
while IFS= read -r -d '' f; do
  FILES+=("$f")
done < <(
  find "$REAL_TARGET" -maxdepth 1 -type f \
    \( -name '*.json' \
       -o -name '*.csv' \
       -o -name '*.env' \
       -o -name '*.ENV' \
       -o -name 'ENV' \
       -o -name '.env' \
       -o -name '*.flag' \
       -o -name '*.ok' \
    \) \
    -print0 2>/dev/null
)

# Remove claim log symlink if present
[[ -L "$REAL_TARGET/meraki_claim.log" ]] && FILES+=("$REAL_TARGET/meraki_claim.log")

TOTAL="${#FILES[@]}"

if (( TOTAL == 0 )); then
  dialog --no-shadow --msgbox "Nothing to clean." 6 40
  clear
  exit 0
fi

dialog --no-shadow --yesno "Clean workspace?" 7 40
resp=$?
clear
(( resp == 0 )) || exit 1

PIPE="$(mktemp -u)"
mkfifo "$PIPE"
exec {FD}<>"$PIPE"

trap 'exec {FD}>&- 2>/dev/null || true; rm -f "$PIPE" 2>/dev/null || true' EXIT

(dialog --no-shadow --gauge "Cleaning…" 8 60 0 < "$PIPE") & DPID=$!

for ((i=0; i<TOTAL; i++)); do
  pct=$(( (i*100) / TOTAL ))
  printf 'XXX\n%s\nCleaning…\nXXX\n' "$pct" >&"$FD"
  rm -f -- "${FILES[$i]}" || true
done

printf 'XXX\n100\nDone.\nXXX\n' >&"$FD"
sleep 0.3

exec {FD}>&- 2>/dev/null || true
kill "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true

dialog --no-shadow --msgbox "Workspace reset." 6 40 || true
clear
exit 0