#!/usr/bin/env bash
# /root/.hybrid_admin/menu.sh
# Hybrid (Device Local) menu with dynamic help, completion checkmarks, and submenus.

set -Eeuo pipefail
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog

BACKTITLE="CMDS-Deployment Server"
TITLE="Catalyst to Meraki (hybrid) (Device Local)"

# Colors (dialog --colors)
HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"  # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"
MARK_CHECK="${MARK_CHECK:-\Z2\Zb[✓]\Zn}"          # bold green [✓]

# Map menu labels -> artifact file that indicates completion
declare -A DONE_FILE=(
  ["Setup Wizard"]="/root/.hybrid_admin/meraki_discovery.env"
  ["Switch Discovery"]="/root/.hybrid_admin/selected_upgrade.env"
  # (None yet for IOS-XE Upgrade / Deploy IOS-XE / Schedule Image Upgrade)
)

# Items: label -> script path
declare -A ITEMS=(
  ["Setup Wizard"]="/root/.hybrid_admin/setupwizard.sh"
  ["Switch Discovery"]="/root/.hybrid_admin/discoverswitches.sh"
  ["IOS-XE Upgrade"]=""  # handled by submenu
)

# Submenus: label -> function name
declare -A SUBMENU_FN=(
  ["IOS-XE Upgrade"]="submenu_iosxe"
)

# Per-item help (status line)
declare -A HELP_RAW=(
  ["Setup Wizard"]="Guided first-time setup: env, API keys, credentials, and paths."
  ["Switch Discovery"]="Discover live Catalyst switches, probe via SSH, and build the selection for upgrades."
  ["IOS-XE Upgrade"]="Run IOS-XE install/activate/commit workflows and tools."
  ["Deploy IOS-XE"]="Copy image to flash, then install/activate/commit on selected switches."
  ["Schedule Image Upgrade"]="Schedule a future image upgrade (snapshots envs, uses 'at')."
)

# Display order (main menu)
ORDER=("Setup Wizard" "Switch Discovery" "IOS-XE Upgrade")

cleanup(){ clear; }
trap cleanup EXIT

is_done(){  # $1=label -> returns 0 if artifact exists and non-empty
  local lbl="$1" f="${DONE_FILE[$lbl]:-}"
  [[ -n "$f" && -s "$f" ]]
}

colorize_help(){  # $1=label
  local lbl="$1" extra=""
  if is_done "$lbl"; then
    extra="  \Z2\Zb(Completed)\Zn"
  fi
  printf '%b%s%b%b' "$HELP_COLOR_PREFIX" "${HELP_RAW[$lbl]:-Run $lbl}" "$HELP_COLOR_RESET" "$extra"
}

display_label(){  # $1=label -> returns label with green check if complete
  local lbl="$1"
  if is_done "$lbl"; then
    printf "%s  %s" "$lbl" "$MARK_CHECK"
  else
    printf "%s" "$lbl"
  fi
}

run_target(){
  local script="$1" label="$2"
  # If this label maps to a submenu, open it
  if [[ -n "${SUBMENU_FN[$label]:-}" ]]; then
    "${SUBMENU_FN[$label]}"
    return
  fi

  clear
  if [[ -n "$script" && -f "$script" ]]; then
    bash "$script"
    local rc=$?
    if (( rc != 0 )); then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "$label" \
             --msgbox "Script exited with status $rc.\n\n$script" 8 72
    fi
  else
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Not Found" \
           --msgbox "Cannot find:\n${script:-<none>}" 7 60
  fi
}

# ---------- IOS-XE Upgrade submenu ----------
submenu_iosxe(){
  local SUB_TITLE="IOS-XE Upgrade"
  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    # Deploy now
    local lbl1="Deploy IOS-XE"
    local path1="/root/.hybrid_admin/image_upgrade.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(colorize_help "$lbl1")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    # NEW: Schedule Image Upgrade
    local lbl2="Schedule Image Upgrade"
    local path2="/root/.hybrid_admin/scheduler.sh"
    MENU_ITEMS+=("$i" "$lbl2" "$(colorize_help "$lbl2")")
    PATH_BY_TAG["$i"]="$path2"
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    MENU_ITEMS+=("0" "Back" "$(printf '%bReturn to main menu%b' "$HELP_COLOR_PREFIX" "$HELP_COLOR_RESET")")

    local CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --menu "Select an option:" 18 78 10 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0
    run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
  done
}

# ---------- Main menu loop ----------
while true; do
  MENU_ITEMS=()
  declare -A PATH_BY_TAG=()
  declare -A LABEL_BY_TAG=()

  i=1
  for label in "${ORDER[@]}"; do
    shown="$(display_label "$label")"
    MENU_ITEMS+=("$i" "$shown" "$(colorize_help "$label")")
    PATH_BY_TAG["$i"]="${ITEMS[$label]}"
    LABEL_BY_TAG["$i"]="$label"
    ((i++))
  done
  MENU_ITEMS+=("0" "Back" "$(printf '%bReturn to previous menu%b' "$HELP_COLOR_PREFIX" "$HELP_COLOR_RESET")")

  CHOICE=$(
    dialog --no-shadow --colors --item-help \
      --backtitle "$BACKTITLE" \
      --title "$TITLE" \
      --menu "Select an option:" 18 78 10 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  ) || exit 0

  [[ "$CHOICE" == "0" ]] && exit 0
  run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
done
