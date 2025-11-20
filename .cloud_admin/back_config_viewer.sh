#!/usr/bin/env bash
# backup_config_viewer.sh
# Dialog-based viewer for backup configs in /var/lib/tftpboot/hybrid
# - Lists *.cfg files with a compact menu (about 10 visible at a time)
# - For a selected file, lets you:
#     * View full config (scrollable)
#     * Search with grep -i -n and context lines

set -Eeuo pipefail

BACKTITLE="Backup config viewer"
DIR="${1:-/var/lib/tftpboot/hybrid}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

need dialog
need grep

# ---------- helpers ----------

list_cfg_files() {
  # Non-recursive, *.cfg only, sorted
  find "$DIR" -maxdepth 1 -type f -name '*.cfg' -printf '%f\n' 2>/dev/null | sort
}

view_config() {
  local path="$1" base
  base="$(basename -- "$path")"

  # Get terminal size (lines and columns)
  local rows cols
  rows=$(tput lines 2>/dev/null || echo 24)
  cols=$(tput cols 2>/dev/null || echo 80)

  # Leave a small margin so dialog borders fit
  local height width
  height=$((rows - 4))
  width=$((cols - 4))

  # Safety: enforce minimums so we don't pass tiny or zero values
  (( height < 10 )) && height=10
  (( width  < 40 )) && width=40

  dialog --no-shadow --backtitle "$BACKTITLE" \
         --title "Viewing $base" \
         --textbox "$path" "$height" "$width"
}

search_config() {
  local path="$1" base search_term ctx
  base="$(basename -- "$path")"
  ctx="${SEARCH_DEFAULT_CTX:-2}"   # default context lines

  while true; do
    local tmp_in
    tmp_in="$(mktemp)"

    # Both fields visible at once
    dialog --no-shadow --backtitle "$BACKTITLE" \
           --title "Search in $base" \
           --form "Search (case-insensitive; grep -i -n)\n\nSearch term is required.\nContext lines = lines above/below each match." \
           13 80 6 \
           "Search term:"   1 2 "${search_term:-}" 1 18 56 0 \
           "Context lines:" 3 2 "${ctx:-2}"        3 18 5  0 \
           2> "$tmp_in" || { rm -f "$tmp_in"; return 1; }

    mapfile -t fields < "$tmp_in" || true
    rm -f "$tmp_in"

    search_term="${fields[0]:-}"
    ctx="${fields[1]:-2}"

    # Require a search term
    if [[ -z "$search_term" ]]; then
      dialog --no-shadow --backtitle "$BACKTITLE" \
             --title "Search" \
             --msgbox "Search term is required." 6 50
      continue
    fi

    # Validate context lines (must be non-negative integer)
    if ! [[ "$ctx" =~ ^[0-9]+$ ]]; then
      ctx=0
    fi

    local tmp_out
    tmp_out="$(mktemp)"

    if (( ctx > 0 )); then
      # -C N = N lines of context above AND below each match
      if ! grep -i -n -C "$ctx" -- "$search_term" "$path" >"$tmp_out" 2>&1; then
        echo "No matches for \"$search_term\"." >"$tmp_out"
      fi
    else
      if ! grep -i -n -- "$search_term" "$path" >"$tmp_out" 2>&1; then
        echo "No matches for \"$search_term\"." >"$tmp_out"
      fi
    fi

    dialog --no-shadow --backtitle "$BACKTITLE" \
           --title "Matches in $base" \
           --textbox "$tmp_out" 25 90
    rm -f "$tmp_out"

    # Ask if they want to search again in the same file
    dialog --no-shadow --backtitle "$BACKTITLE" \
           --title "Search again?" \
           --yesno "Search again in $base?" 7 50
    local rc=$?

    case "$rc" in
      0)  # Yes -> loop and ask again
          continue
          ;;
      1)  # No -> go back to file list
          return 1
          ;;
      255) # ESC / Cancel -> also go back to file list
          return 1
          ;;
    esac
  done
}

file_action_menu() {
  local path="$1" base choice
  base="$(basename -- "$path")"

  while true; do
    choice=$(dialog --no-shadow --backtitle "$BACKTITLE" \
                    --title "Backup: $base" \
                    --menu "Choose an action:" \
                    12 60 4 \
                    1 "View full config" \
                    2 "Search within config" \
                    3 "Back to file list" \
                    2>&1 >/dev/tty) || return 0

    case "$choice" in
      1)
        view_config "$path"
        ;;
      2)
        # If search_config returns non-zero, jump back to file list
        if ! search_config "$path"; then
          return 0
        fi
        ;;
      3)
        return 0
        ;;
    esac
  done
}

# ---------- main loop ----------

main_menu() {
  while true; do
    mapfile -t FILES < <(list_cfg_files)

    if ((${#FILES[@]} == 0)); then
      dialog --no-shadow --backtitle "$BACKTITLE" \
             --title "No configs" \
             --msgbox "No *.cfg files found in:\n$DIR" 8 70
      clear
      return
    fi

    # Build dialog --menu items: show up to 10 at a time (menu-height = 10)
    local items=()
    local idx=1
    for f in "${FILES[@]}"; do
      items+=("$idx" "$f")
      ((idx++))
    done

    local sel_idx
    sel_idx=$(dialog --no-shadow --backtitle "$BACKTITLE" \
                     --title "Select backup config to view" \
                     --menu "Directory: $DIR\n\nUse UP/DOWN to choose a file, ENTER to select, or Cancel to exit." \
                     18 80 10 \
                     "${items[@]}" \
                     2>&1 >/dev/tty) || { clear; return; }

    # Map numeric choice back to filename
    local choice_file="${FILES[sel_idx-1]}"
    local full_path="$DIR/$choice_file"

    file_action_menu "$full_path"
    # After returning from file_action_menu, we loop and show the file list again
  done
}

trap 'clear' EXIT
main_menu