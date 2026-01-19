#!/usr/bin/env bash
# Main Dialog Menu for CMDS-Deployment Server
# Runs the hybrid menu from its own directory so relative paths resolve to /root/.hybrid_admin

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

# --- Update checker settings (same repo model as cmds_updater.sh) ---
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

# ---- Online requirement (GitHub RAW reachability) ----
ONLINE_REQUIRED="${ONLINE_REQUIRED:-1}"          # 1=enforce (recommended), 0=warn/skip
ONLINE_BYPASS_ALLOWED="${ONLINE_BYPASS_ALLOWED:-0}"  # 1=allow "Continue anyway" when offline

# Colors for bottom status/help line (dialog --colors)
HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"  # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"

cleanup(){ clear; }
trap cleanup EXIT

is_online_github() {
  # Fast HEAD to the exact service needed (raw GitHub content)
  curl -fsSI --connect-timeout 3 --max-time 5 "https://raw.githubusercontent.com/" >/dev/null 2>&1
}

require_online_or_prompt() {
  # If not required, just return success (and later update check will silently fail if offline)
  [[ "${ONLINE_REQUIRED}" == "1" ]] || return 0

  # Quick single attempt
  if is_online_github; then
    return 0
  fi

  # Hard gate until online, or exit / bypass (if allowed)
  while true; do
    local msg
    msg="CMDS requires internet access to operate.

Connectivity check failed:
- Cannot reach raw.githubusercontent.com

Fix network/DNS and choose Retry."

    if [[ "${ONLINE_BYPASS_ALLOWED}" == "1" ]]; then
      local choice rc
      set +e
      choice="$(
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Offline Detected" \
          --menu "$msg" 15 78 6 \
            1 "Retry connectivity check" \
            2 "Continue anyway (NOT recommended)" \
            0 "Exit" \
          3>&1 1>&2 2>&3
      )"
      rc=$?
      set -e

      [[ $rc -ne 0 ]] && return 1
      case "$choice" in
        1)
          dialog --no-shadow --backtitle "$BACKTITLE" --title "Checking" \
            --infobox "Re-checking connectivity..." 5 60
          sleep 0.2
          is_online_github && return 0
          ;;
        2) return 0 ;;
        0) return 1 ;;
      esac
    else
      set +e
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Offline Detected" --yesno "$msg" 15 78
      local yn=$?
      set -e

      # YES=retry, NO=exit
      if (( yn == 0 )); then
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Checking" \
          --infobox "Re-checking connectivity..." 5 60
        sleep 0.2
        is_online_github && return 0
      else
        return 1
      fi
    fi
  done
}

read_installed_version() {
  # Expected file format: VERSION=1.0.0
  # If missing/invalid -> echo "" (unknown)
  local v=""
  [[ -r "$VERSION_FILE" ]] || { echo ""; return 0; }

  v="$(grep -m1 '^VERSION=' "$VERSION_FILE" 2>/dev/null | cut -d'=' -f2- | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]] || v=""
  printf "%s" "$v"
}

fetch_index_lines() {
  # Echoes raw index lines (filtered). Returns 0 if fetched, 1 if not.
  local tmp url ok=0
  tmp="$(mktemp)"
  : >"$tmp"

  for url in "${INDEX_CANDIDATES[@]}"; do
    # short + quiet; we don't want curl progress to bleed into dialog
    if curl -fsSL --connect-timeout 6 --max-time 20 -H "Cache-Control: no-cache" "$url" -o "$tmp" 2>/dev/null; then
      ok=1
      break
    fi
  done

  if (( ok == 0 )); then
    rm -f "$tmp" 2>/dev/null || true
    return 1
  fi

  # Remove comments/blank lines, strip CR
  grep -Ev '^[[:space:]]*($|#)' "$tmp" | tr -d '\r' || true
  rm -f "$tmp" 2>/dev/null || true
  return 0
}

get_latest_version_from_index() {
  # stdin: index lines
  # INDEX format: <version>|<tar>|<notes>|...
  cut -d'|' -f1 \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -E '^[0-9]+(\.[0-9]+)*$' \
    | sort -V \
    | tail -n 1
}

is_newer_version() {
  # returns 0 if $1 > $2
  local a="$1" b="$2"
  [[ -n "$a" && -n "$b" ]] || return 1
  [[ "$a" != "$b" ]] || return 1

  local last
  last="$(printf "%s\n%s\n" "$a" "$b" | sort -V | tail -n 1)"
  [[ "$last" == "$a" ]]
}

check_for_updates_and_prompt() {
  # If offline, skip update-check entirely (no dialogs) unless you forced ONLINE_REQUIRED=1
  # (Online requirement is enforced earlier; this is extra protection.)
  if ! is_online_github; then
    return 0
  fi

  # Show a fast infobox. Keep brief.
  dialog --no-shadow --backtitle "$BACKTITLE" --title "Updates" \
    --infobox "Checking for CMDS updates..." 5 60
  sleep 0.2

  local installed latest index_lines
  installed="$(read_installed_version)"

  # Fetch index
  if ! index_lines="$(fetch_index_lines)"; then
    # Repo unreachable -> fail silently (do NOT block app)
    return 0
  fi

  latest="$(printf "%s\n" "$index_lines" | get_latest_version_from_index)"
  [[ -n "${latest:-}" ]] || return 0

  # If local version is missing -> treat as "unknown install state"
  if [[ -z "${installed:-}" ]]; then
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Update Available" --yesno \
"This system does not have a local CMDS version recorded yet.

Latest available version: $latest

Patches are cumulative — updating will bring you fully current.

Update now?" 14 72
    if (( $? == 0 )); then
      if [[ -x "$UPDATER_BIN" ]]; then
        clear
        bash "$UPDATER_BIN" || true
      else
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater Missing" --msgbox \
"Update was requested, but the updater script is missing or not executable:

$UPDATER_BIN" 9 70
      fi
    fi
    return 0
  fi

  # Normal compare
  if is_newer_version "$latest" "$installed"; then
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Update Available" --yesno \
"An update is available.

Installed:  $installed
Latest:     $latest

Patches are cumulative — updating will bring you fully current.

Update now?" 14 70
    if (( $? == 0 )); then
      if [[ -x "$UPDATER_BIN" ]]; then
        clear
        bash "$UPDATER_BIN" || true
      else
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Updater Missing" --msgbox \
"Update was requested, but the updater script is missing or not executable:

$UPDATER_BIN" 9 70
      fi
    fi
  fi

  return 0
}

while true; do
  # Enforce online requirement (if enabled)
  if ! require_online_or_prompt; then
    clear
    exit 0
  fi

  # Check at each return to main menu (your preference)
  check_for_updates_and_prompt || true

  # dialog returns non-zero for Cancel/Esc; do NOT let set -e kill the script here
  set +e
  CHOICE=$(
    dialog --no-shadow --colors --item-help \
      --backtitle "$BACKTITLE" \
      --title "$TITLE" \
      --menu "Select an option:" 18 110 8 \
        1 "Catalyst to Meraki (hybrid) (Device Local)" \
          "${HELP_COLOR_PREFIX}Workflow for Configuration source: Device; Migrate Catalyst to Meraki while retaining IOS-XE; opens the hybrid tools menu.${HELP_COLOR_RESET}" \
        0 "Exit" \
          "${HELP_COLOR_PREFIX}Quit the deployment server menu.${HELP_COLOR_RESET}" \
      3>&1 1>&2 2>&3
  )
  rc=$?
  set -e

  # ESC or Cancel -> exit cleanly
  if [[ $rc -ne 0 ]]; then
    clear
    exit 0
  fi

  case "$CHOICE" in
    1)
      if [[ -f "$HYBRID_MENU" ]]; then
        clear
        HYBRID_DIR="$(cd -- "$(dirname "$HYBRID_MENU")" >/dev/null 2>&1 && pwd -P)"
        export HYBRID_HOME="$HYBRID_DIR"   # optional: available to child scripts

        # Run the menu FROM its directory so all relative paths write to /root/.hybrid_admin
        set +e
        (
          cd "$HYBRID_DIR" || exit 1
          exec bash "./$(basename "$HYBRID_MENU")"
        )
        hybrid_rc=$?
        set -e

        # Treat dialog-style exits as normal: 0=OK, 1=Cancel/No, 255=Esc
        case "$hybrid_rc" in
          0|1|255) : ;;  # normal return to main menu
          *)
            dialog --no-shadow --backtitle "$BACKTITLE" --title "Hybrid Menu" \
                   --msgbox "The script returned a non-zero status ($hybrid_rc).\n\nPath: $HYBRID_MENU" 9 70
            ;;
        esac
      else
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Not Found" \
               --msgbox "Cannot find:\n$HYBRID_MENU" 7 60
      fi
      ;;
    0)
      clear
      exit 0
      ;;
  esac
done