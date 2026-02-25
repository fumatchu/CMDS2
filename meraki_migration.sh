#!/usr/bin/env bash
# Main Dialog Menu for CMDS-Deployment Server
# Runs child menus from their own directories so relative paths resolve correctly.

set -Eeuo pipefail

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need curl
need sort
need grep
need sed
need cut
need tr

BACKTITLE="CMDS-Deployment Server"
TITLE="Main Menu"

HYBRID_MENU="/root/.hybrid_admin/menu.sh"
CLOUD_MENU="/root/.cloud_admin/menu.sh"
WLC_MENU="/root/.wlc_admin/menu.sh"
CAT_MENU="/root/.cat_admin/menu.sh"

# --- Update checker settings ---
REPO_OWNER="fumatchu"
REPO_NAME="CMDS2"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}"

INDEX_CANDIDATES=(
  "${RAW_BASE}/updates/INDEX.txt"
  "${RAW_BASE}/updates/index.txt"
  "${RAW_BASE}/updates/Index.txt"
)

SERVER_DIR="/root/.server_admin"
VERSION_FILE="${SERVER_DIR}/CMDS_VERSION"
UPDATER_BIN="${SERVER_DIR}/cmds_updater.sh"

ONLINE_REQUIRED="${ONLINE_REQUIRED:-1}"
ONLINE_BYPASS_ALLOWED="${ONLINE_BYPASS_ALLOWED:-0}"

HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"

cleanup(){ clear; }
trap cleanup EXIT

is_online_github() {
  curl -fsSI --connect-timeout 3 --max-time 5 \
    "https://raw.githubusercontent.com/" >/dev/null 2>&1
}

require_online_or_prompt() {
  [[ "${ONLINE_REQUIRED}" == "1" ]] || return 0
  is_online_github && return 0

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Offline Detected" --msgbox \
"CMDS requires internet access to operate.

Cannot reach raw.githubusercontent.com.

Fix connectivity and relaunch." 12 70
  return 1
}

read_installed_version() {
  local v=""
  [[ -r "$VERSION_FILE" ]] || { echo ""; return 0; }
  v="$(grep -m1 '^VERSION=' "$VERSION_FILE" | cut -d'=' -f2- | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]] || v=""
  printf "%s" "$v"
}

fetch_index_lines() {
  local tmp url ok=0
  tmp="$(mktemp)"
  : >"$tmp"

  for url in "${INDEX_CANDIDATES[@]}"; do
    if curl -fsSL --connect-timeout 6 --max-time 20 \
      -H "Cache-Control: no-cache" "$url" -o "$tmp" 2>/dev/null; then
      ok=1
      break
    fi
  done

  (( ok == 0 )) && { rm -f "$tmp"; return 1; }

  grep -Ev '^[[:space:]]*($|#)' "$tmp" | tr -d '\r'
  rm -f "$tmp"
  return 0
}

get_latest_version_from_index() {
  cut -d'|' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -E '^[0-9]+(\.[0-9]+)*$' |
    sort -V | tail -n 1
}

is_newer_version() {
  local a="$1" b="$2"
  [[ -n "$a" && -n "$b" && "$a" != "$b" ]] || return 1
  [[ "$(printf "%s\n%s\n" "$a" "$b" | sort -V | tail -n1)" == "$a" ]]
}

run_updater_and_show_log_on_failure() {
  # Run updater; if it fails, show the latest run log instead of silently returning.
  [[ -f "$UPDATER_BIN" ]] || {
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater missing" --msgbox \
"Missing updater binary:
$UPDATER_BIN" 8 70
    return 1
  }

  # Ensure executable (safe even if already executable)
  chmod +x "$UPDATER_BIN" 2>/dev/null || true

  clear
  bash "$UPDATER_BIN"
  local upd_rc=$?

  if (( upd_rc != 0 )); then
    local latest_run
    latest_run="$(ls -1dt /root/.server_admin/runs/cmds-update/run-* 2>/dev/null | head -n1)"

    dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater exited" --msgbox \
"Updater exited with code: ${upd_rc}

Showing the most recent updater log next." 10 70

    if [[ -n "${latest_run:-}" && -f "${latest_run}/cmds_updater.log" ]]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater log" --textbox \
"${latest_run}/cmds_updater.log" 0 0
    else
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater log" --msgbox \
"No updater log was found under:
/root/.server_admin/runs/cmds-update/" 9 70
    fi
  fi

  return 0
}

check_for_updates_and_prompt() {
  is_online_github || return 0

  dialog --no-shadow --backtitle "$BACKTITLE" \
    --infobox "Checking for CMDS updates..." 4 50
  sleep 0.2

  local installed latest index_lines
  installed="$(read_installed_version)"
  index_lines="$(fetch_index_lines)" || return 0
  latest="$(printf "%s\n" "$index_lines" | get_latest_version_from_index)"
  [[ -z "$latest" ]] && return 0

  if is_newer_version "$latest" "$installed"; then
    dialog --no-shadow --backtitle "$BACKTITLE" --yesno \
"An update is available.

Installed: $installed
Latest:    $latest

Update now?" 12 60

    if (( $? == 0 )); then
      run_updater_and_show_log_on_failure || true
    fi
  fi
}

run_child_menu() {
  local label="$1"
  local menu_path="$2"

  [[ -f "$menu_path" ]] || {
    dialog --backtitle "$BACKTITLE" --msgbox "Missing:\n$menu_path" 7 60
    return
  }

  clear
  local dir
  dir="$(cd -- "$(dirname "$menu_path")" && pwd -P)"

  set +e
  (
    cd "$dir" || exit 1
    exec bash "./$(basename "$menu_path")"
  )
  set -e
}

while true; do
  require_online_or_prompt || exit 0
  check_for_updates_and_prompt || true

  MENU_ITEMS=()

  [[ -f "$HYBRID_MENU" ]] && MENU_ITEMS+=(
    1 "Catalyst to Meraki (hybrid) (Device Local)"
    "${HELP_COLOR_PREFIX}Non-destructive migration of supported 9K switches to the Meraki Dashboard. IOS-XE preserved. Cloud CLI read/write enabled. IOS-XE feature set retained.${HELP_COLOR_RESET}"
  )

  [[ -f "$CLOUD_MENU" ]] && MENU_ITEMS+=(
    2 "Catalyst for Meraki (cloud)"
    "${HELP_COLOR_PREFIX}Destructive migration of supported 9K switches to the Meraki Dashboard. IOS-XE configuration migrated. Flash wiped. Full Dashboard control. Meraki feature set enabled.${HELP_COLOR_RESET}"
  )

  [[ -f "$WLC_MENU" ]] && MENU_ITEMS+=(
    3 "Catalyst to Meraki (wlc) (Device Local)"
    "${HELP_COLOR_PREFIX}Non-destructive migration of supported 9K WLC to the Meraki Dashboard. IOS-XE configuration preserved. IOS-XE feature set retained.${HELP_COLOR_RESET}"
  )

  [[ -f "$CAT_MENU" ]] && MENU_ITEMS+=(
    4 "Catalyst to Meraki (Legacy Hardware)"
    "${HELP_COLOR_PREFIX}Migration of legacy IOS-XE switch configs to an already provisioned Dashboard switch.${HELP_COLOR_RESET}"
  )

  # If nothing exists at all, exit cleanly
  (( ${#MENU_ITEMS[@]} == 0 )) && exit 0

  set +e
  CHOICE=$(
    dialog --no-shadow --colors --item-help \
      --backtitle "$BACKTITLE" \
      --title "$TITLE" \
      --menu "Select an option:" 20 110 10 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  )
  rc=$?
  set -e

  [[ $rc -ne 0 ]] && exit 0

  case "$CHOICE" in
    1) run_child_menu "Hybrid" "$HYBRID_MENU" ;;
    2) run_child_menu "Cloud"  "$CLOUD_MENU" ;;
    3) run_child_menu "WLC"    "$WLC_MENU" ;;
    4) run_child_menu "Legacy" "$CAT_MENU" ;;
  esac
done