#!/usr/bin/env bash
# /root/.cloud_admin/menu.sh
# Cloud (Device Local) menu with dynamic help, completion checkmarks, and submenus.

set -Eeuo pipefail
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog

BACKTITLE="CMDS-Deployment Server"
TITLE="Catalyst to Meraki (cloud) (Device Local)"

# ---- Cloud support matrix viewer script (set to your actual file) ----
CLOUD_MATRIX_SCRIPT="/root/.cloud_admin/cloud_support_matrix.sh"

# Colors (dialog --colors)
HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"  # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"
MARK_CHECK="${MARK_CHECK:-\Z2\Zb[✓]\Zn}"          # bold green [✓]

# Map menu labels -> artifact file that indicates completion
declare -A DONE_FILE=(
  ["Cloud Support Matrix (Models ↔ IOS-XE)"]="/root/.cloud_admin/cloud_firmware_report.env"
  ["Setup Wizard"]="/root/.cloud_admin/meraki_discovery.env"
  ["Switch Discovery"]="/root/.cloud_admin/selected_upgrade.env"
  ["Validate IOS-XE configuration"]="/root/.cloud_admin/preflight.ok"
  # For migration, we use a symlink to the latest claim log
  ["Migrate Switches"]="/root/.cloud_admin/meraki_claim.log"
)

# Items: label -> script path
# NOTE: Section headers are kept as empty paths and ignored by run_target().
declare -A ITEMS=(
  # Section headers (non-clickable)
  ["Firmware & Compatibility"]=""
  ["Deployment Workflow"]=""

  # Firmware & Compatibility
  ["Cloud Support Matrix (Models ↔ IOS-XE)"]="$CLOUD_MATRIX_SCRIPT"

  # Deployment workflow
  ["Setup Wizard"]="/root/.cloud_admin/setupwizard.sh"
  ["Switch Discovery"]="/root/.cloud_admin/discoverswitches.sh"
  ["Validate IOS-XE configuration"]="/root/.cloud_admin/meraki_preflight.sh"
  ["IOS-XE Upgrade"]=""  # handled by submenu
  ["Migrate Switches"]="/root/.cloud_admin/migration.sh"
  ["Logging"]="/root/.cloud_admin/show_logs.sh"
  ["Clean Configuration (New Batch Deployment)"]="/root/.cloud_admin/clean.sh"
  ["Utilities"]=""  # handled by submenu

  # Server / docs
  ["Server Management"]=""  # header / separator, not an actual script
  ["Server Service Control"]=""  # handled by submenu
  ["README"]="/root/.cloud_admin/readme.sh"
)

# Submenus: label -> function name
declare -A SUBMENU_FN=(
  ["IOS-XE Upgrade"]="submenu_iosxe"
  ["Utilities"]="submenu_utilities"
  ["Server Service Control"]="submenu_server_services"
)

# Per-item help (status line)
declare -A HELP_RAW=(
  ["Firmware & Compatibility"]="Reference tools for firmware ↔ model support and requirements."
  ["Cloud Support Matrix (Models ↔ IOS-XE)"]="Searchable database for model + minimum IOS-XE requirements (informational)."
  ["Deployment Workflow"]="Operational workflows for discovery, validation, upgrade, and cloud conversion."
  ["Setup Wizard"]="Guided Setup: Always run between batches (API keys, credentials)"
  ["Switch Discovery"]="Discover live Catalyst switches, probe via SSH, and build the selection for upgrades."
  ["Validate IOS-XE configuration"]="Run preflight validation for selected switches and configuration before upgrade."
  ["IOS-XE Upgrade"]="Run IOS-XE install/activate/commit workflows and tools."
  ["Deploy IOS-XE"]="Copy image to flash, then install/activate/commit on selected switches."
  ["Schedule Image Upgrade"]="Schedule a future image upgrade (snapshots envs, uses 'at')."
  ["Migrate Switches"]="Run the Catalyst-to-Meraki cloud migration workflow and claim devices into Dashboard."
  ["Logging"]="View CMDS deployment and migration log files."
  ["Clean Configuration (New Batch Deployment)"]="Clear previous selections and files to prepare a new batch deployment."
  ["Utilities"]="Utility tools for monitoring and quick checks."
  ["Switch UP/Down Status"]="Monitor switch reachability (UP/DOWN) using continuous ping."
  ["IOS-XE Image Management"]="Manage IOS-XE image files (list, inspect, and clean up)."
  ["CLI Updater"]="Run ad-hoc CLI command packs on selected switches."
  ["Backup Config Viewer"]="Browse and search saved switch backup configs."
  ["Server Management"]="Server management tools and utilities."
  ["Server Service Control"]="Manage CMDS services or reboot the server."
  ["README"]="View CMDS cloud README / usage guide."
)

# Display order (main menu)
ORDER=(
  "Firmware & Compatibility"
  "Cloud Support Matrix (Models ↔ IOS-XE)"

  "Deployment Workflow"
  "Setup Wizard"
  "Switch Discovery"
  "IOS-XE Upgrade"
  "Validate IOS-XE configuration"
  "Migrate Switches"
  "Clean Configuration (New Batch Deployment)"
  "Logging"
  "Utilities"

  "Server Management"
  "Server Service Control"
  "README"
)

cleanup(){ clear; }
trap cleanup EXIT

is_done(){  # $1=label -> returns 0 if artifact indicates completion
  local lbl="$1" f="${DONE_FILE[$lbl]:-}"

  [[ -n "$f" ]] || return 1

  if [[ "$lbl" == "Migrate Switches" ]]; then
    # Presence of symlink marks completion; optionally fail if underlying log has "FAILED"
    if [[ -L "$f" ]]; then
      local tgt; tgt="$(readlink -f -- "$f" 2>/dev/null || true)"
      if [[ -n "$tgt" && -e "$tgt" ]]; then
        if grep -q "FAILED" "$tgt" 2>/dev/null; then
          return 1
        else
          return 0
        fi
      fi
      return 1
    fi
    return 1
  fi

  # Default: must be a non-empty file
  [[ -s "$f" ]]
}

colorize_help(){  # $1=label
  local lbl="$1" extra=""
  if is_done "$lbl"; then
    extra="  \Z2\Zb(Completed)\Zn"
  fi
  printf '%b%s%b%b' "$HELP_COLOR_PREFIX" "${HELP_RAW[$lbl]:-Run $lbl}" "$HELP_COLOR_RESET" "$extra"
}

display_label(){  # $1=label -> returns label with green check and submenu marker if applicable
  local lbl="$1" text

  # Section header formatting
  case "$lbl" in
    "Firmware & Compatibility")
      printf "%s" "--------- Firmware & Compatibility ---------"
      return
      ;;
    "Deployment Workflow")
      printf "%s" "------------ Deployment Workflow ------------"
      return
      ;;
    "Server Management")
      printf "%s" "---------------- Server Management ----------------"
      return
      ;;
  esac

  # Base label with optional green check
  if is_done "$lbl"; then
    text="$lbl  $MARK_CHECK"
  else
    text="$lbl"
  fi

  # Submenu marker
  if [[ -n "${SUBMENU_FN[$lbl]:-}" ]]; then
    text="$text  >"
  fi

  printf "%s" "$text"
}

run_target(){
  local script="$1" label="$2"

  # Section header? do nothing.
  if [[ "$label" == "Server Management" \
     || "$label" == "Firmware & Compatibility" \
     || "$label" == "Deployment Workflow" ]]; then
    return
  fi

  # Submenu?
  if [[ -n "${SUBMENU_FN[$label]:-}" ]]; then
    "${SUBMENU_FN[$label]}"
    return
  fi

  clear
  if [[ -n "$script" && -f "$script" ]]; then
    # Run child and capture status without letting -e kill us
    set +e
    bash "$script"
    local rc=$?
    set -e

    case "$rc" in
      0) : ;;                            # success
      1|255|130|143) return 0 ;;         # dialog Cancel/Esc/Ctrl-C → not an error
      *)  dialog --no-shadow --backtitle "$BACKTITLE" --title "$label" \
                --msgbox "Script exited with status $rc.\n\n$script" 8 72 ;;
    esac
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

    local lbl1="Deploy IOS-XE"
    local path1="/root/.cloud_admin/image_upgrade.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(colorize_help "$lbl1")"); PATH_BY_TAG["$i"]="$path1"; LABEL_BY_TAG["$i"]="$lbl1"; ((i++))

    local lbl2="Schedule Image Upgrade"
    local path2="/root/.cloud_admin/scheduler.sh"
    MENU_ITEMS+=("$i" "$lbl2" "$(colorize_help "$lbl2")"); PATH_BY_TAG["$i"]="$path2"; LABEL_BY_TAG["$i"]="$lbl2"; ((i++))

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

# ---------- Utilities submenu ----------
submenu_utilities(){
  local SUB_TITLE="Utilities"
  color_help(){ printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"; }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    local lbl1="Switch UP/Down Status"
    local path1="/root/.cloud_admin/ping.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Continuous ping monitor for selected switches (UP/DOWN).")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    local lbl2="IOS-XE Image Management"
    local path2="/root/.cloud_admin/image_management.sh"
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "Manage IOS-XE image files (list, inspect, and clean up).")")
    PATH_BY_TAG["$i"]="$path2"
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    local lbl3="CLI Updater"
    local path3="/root/.cloud_admin/cli_updater.sh"
    MENU_ITEMS+=("$i" "$lbl3" "$(color_help "Run ad-hoc CLI command packs on selected switches.")")
    PATH_BY_TAG["$i"]="$path3"
    LABEL_BY_TAG["$i"]="$lbl3"
    ((i++))

    local lbl4="Backup Config Viewer"
    local path4="/root/.cloud_admin/back_config_viewer.sh"
    MENU_ITEMS+=("$i" "$lbl4" "$(color_help "Browse and search saved switch backup configs.")")
    PATH_BY_TAG["$i"]="$path4"
    LABEL_BY_TAG["$i"]="$lbl4"
    ((i++))

    MENU_ITEMS+=("0" "Back" "$(color_help "Return to main menu")")

    local CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --menu "Select a utility:" 16 78 10 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0
    run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
  done
}

# ---------- Server Service Control submenu ----------
submenu_server_services(){
  local SUB_TITLE="Server Service Control"
  color_help(){ printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"; }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    local lbl1="Manage CMDS Services"
    local path1="/root/.server_admin/service_control.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Start/stop/restart CMDS services via dialog.")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    if [[ -f /etc/kea/kea-dhcp4.conf ]]; then
      local lbl_dhcp="DHCP Administration"
      local path_dhcp="/root/.server_admin/dhcp_admin.sh"
      MENU_ITEMS+=("$i" "$lbl_dhcp" "$(color_help "Administer Kea DHCP configuration and leases.")")
      PATH_BY_TAG["$i"]="$path_dhcp"
      LABEL_BY_TAG["$i"]="$lbl_dhcp"
      ((i++))
    fi

    local lbl2="Reboot Server"
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "Safely reboot this server (confirmation required).")")
    PATH_BY_TAG["$i"]=""
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    MENU_ITEMS+=("0" "Back" "$(color_help "Return to main menu")")

    local CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --menu "Select an option:" 14 78 8 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0

    local label="${LABEL_BY_TAG[$CHOICE]}"

    if [[ "$label" == "Reboot Server" ]]; then
      if [[ $EUID -ne 0 ]]; then
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Permission required" \
               --msgbox "Reboot requires root privileges." 7 60
        continue
      fi
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Confirm Reboot" --yesno \
"Are you sure you want to reboot this server now?

Active tasks or SSH sessions may be interrupted." 10 70
      if (( $? == 0 )); then
        dialog --no-shadow --title "Rebooting…" --infobox "Rebooting in 3 seconds…" 5 40; sleep 1
        dialog --no-shadow --title "Rebooting…" --infobox "Rebooting in 2 seconds…" 5 40; sleep 1
        dialog --no-shadow --title "Rebooting…" --infobox "Rebooting in 1 second…" 5 40; sleep 1
        clear
        systemctl reboot || reboot || shutdown -r now
        exit 0
      fi
    else
      run_target "${PATH_BY_TAG[$CHOICE]}" "$label"
    fi
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
      --menu "Select an option:" 22 78 10 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  ) || exit 0

  [[ "$CHOICE" == "0" ]] && exit 0
  run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
done