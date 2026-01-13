#!/usr/bin/env bash
# cmds_packager.sh
# Build an update tarball containing ONLY executable files from:
#   /root/.hybrid_admin
#   /root/.server_admin
#
# Excludes: runs/, *.env, *.csv, *.json, and anything non-executable.
#
# Output:
#   /root/cmds-<version>.tar.gz
#   /root/cmds-<version>.notes  (template)
#
# Requires: dialog, find, tar, gzip, awk, sed, sort, mktemp

set -Euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need find; need tar; need gzip; need awk; need sed; need sort; need mktemp

BACKTITLE="${BACKTITLE:-CMDS Packager}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

# dialog wrapper (never fails)
dlg() {
  local _t; _t="$(mktemp)"
  dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"
  DIALOG_RC=$?  # 0 OK, 1 Cancel, 255 ESC
  DOUT=""
  [[ -s "$_t" ]] && DOUT="$(cat "$_t")"
  rm -f "$_t"
  return 0
}

ROOT_BASE="/root"
SRC_DIRS=( ".hybrid_admin" ".server_admin" )

# Rules:
# - only executable regular files
# - exclude runs/
# - exclude data-ish extensions even if executable (belt + suspenders)
is_excluded_path() {
  local p="$1"
  [[ "$p" == */runs/* ]] && return 0
  case "$p" in
    *.env|*.csv|*.json|*.log|*.status) return 0 ;;
  esac
  return 1
}

gather_exec_files() {
  local tmp="$1"
  : >"$tmp"

  local d
  for d in "${SRC_DIRS[@]}"; do
    if [[ ! -d "$ROOT_BASE/$d" ]]; then
      # Not an error — you said .cloud_admin won't exist yet and that's fine.
      continue
    fi

    # We run find from /root so results are relative to /root (no leading /root)
    (
      cd "$ROOT_BASE"
      # -perm /111 = any execute bit set
      find "$d" \
        -type d -name runs -prune -o \
        -type f -perm /111 -print
    ) | while IFS= read -r rel; do
      [[ -z "$rel" ]] && continue
      if is_excluded_path "$rel"; then
        continue
      fi
      echo "$rel"
    done >>"$tmp"
  done

  sort -u -o "$tmp" "$tmp"
}

preview_listbox() {
  local filelist="$1"
  local count
  count="$(wc -l <"$filelist" 2>/dev/null || echo 0)"

  if (( count == 0 )); then
    dlg --title "Nothing to package" --msgbox \
"No executable files found under:
  /root/.hybrid_admin
  /root/.server_admin

Nothing to do." 10 70
    return 1
  fi

  local show_tmp; show_tmp="$(mktemp)"
  {
    echo "CMDS Packager will include ONLY executable files."
    echo
    echo "Count: $count"
    echo
    sed 's/^/  - /' "$filelist"
  } >"$show_tmp"

  dlg --title "Dry Run Preview" --textbox "$show_tmp" 0 0
  rm -f "$show_tmp"
  return 0
}

build_tarball() {
  local version="$1"
  local filelist="$2"

  local out_tar="/root/cmds-${version}.tar.gz"
  local out_notes="/root/cmds-${version}.notes"

  # Build tar.gz from /root so paths stay relative and extract cleanly into /root
  (
    cd "$ROOT_BASE"
    tar -czf "$out_tar" -T "$filelist"
  )

  # Notes template (if not already present)
  if [[ ! -f "$out_notes" ]]; then
    cat >"$out_notes" <<EOF
CMDS Update Notes - v${version}
Date: $(date)

Summary:
- 

Changes:
- 

Fixes:
- 

Notes / Known Issues:
- 
EOF
  fi

  dlg --title "Build complete" --msgbox \
"Created:

  $out_tar
  $out_notes

Next:
- Upload both into your repo under:
  updates/${version}/
  (e.g. cmds-${version}.tar.gz and ${version}.notes)

Tip:
- You can rename cmds-${version}.notes to ${version}.notes if you prefer.
" 14 80
}

main() {
  dlg --title "CMDS Packager" --inputbox \
"Enter version to package (example: 0.5)

This will build:
  /root/cmds-<version>.tar.gz
  /root/cmds-<version>.notes" 12 70 ""
  [[ $DIALOG_RC -ne 0 ]] && exit 0

  local ver
  ver="$(echo "$DOUT" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  if [[ -z "$ver" ]]; then
    dlg --title "Missing version" --msgbox "Version cannot be empty." 7 40
    exit 1
  fi

  local listtmp; listtmp="$(mktemp)"
  gather_exec_files "$listtmp"

  preview_listbox "$listtmp" || { rm -f "$listtmp"; exit 0; }

  dlg --title "Commit" --yesno \
"Ready to build update tarball for version: ${ver}

This will create:
  /root/cmds-${ver}.tar.gz
  /root/cmds-${ver}.notes

Proceed?" 12 70

  if (( DIALOG_RC != 0 )); then
    rm -f "$listtmp"
    exit 0
  fi

  build_tarball "$ver" "$listtmp"
  rm -f "$listtmp"
}

main