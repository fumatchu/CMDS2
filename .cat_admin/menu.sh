#!/usr/bin/env bash
# /root/.cat_admin/menu.sh
# CAT admin menu with dynamic help, completion checkmarks, and submenus.

set -Eeuo pipefail

# Always start in the CAT admin directory
cd /root/.cat_admin || {
  echo "Cannot change directory to /root/.cat_admin" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing: $1" >&2
    exit 1
  }
}
need dialog

BACKTITLE="CMDS-Deployment Server"
TITLE="Legacy Catalyst to Meraki Migration (Non-9K to Dashboard)"

# Colors (dialog --colors)
HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"  # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"
MARK_CHECK="${MARK_CHECK:-\Z2\Zb[✓]\Zn}"          # bold green [✓]

# Completion marker files
SWITCH_MAPPING_OK_FILE="/root/.cat_admin/switch_mapping.ok"
UPLINK_VALIDATION_OK_FILE="/root/.cat_admin/uplink_validation.ok"
PORT_MIGRATION_OK_FILE="/root/.cat_admin/port_migration.ok"
IP_MGMT_MIGRATION_OK_FILE="/root/.cat_admin/ip_management_migration.ok"

# Map menu labels -> artifact file that indicates completion
declare -A DONE_FILE=(
  ["Setup Wizard"]="/root/.cat_admin/meraki_discovery.env"
  ["Switch Discovery"]="/root/.cat_admin/selected_upgrade.env"
  ["Catalyst/Meraki Switch Mapping"]="$SWITCH_MAPPING_OK_FILE"
  ["Uplink Port Validation (Optional but Recommended)"]="$UPLINK_VALIDATION_OK_FILE"
  ["Port Migration"]="$PORT_MIGRATION_OK_FILE"
  ["IP Management Migration"]="$IP_MGMT_MIGRATION_OK_FILE"
)

# Items: label -> script path
# Section headers use empty paths and are ignored by run_target().
declare -A ITEMS=(
  ["Deployment Workflow"]=""
  ["Setup Wizard"]="/root/.cat_admin/setupwizard.sh"
  ["Switch Discovery"]="/root/.cat_admin/discoverswitches.sh"
  ["Catalyst/Meraki Switch Mapping"]="/root/.cat_admin/map_selected_to_meraki.sh"
  ["Uplink Port Validation (Optional but Recommended)"]="/root/.cat_admin/uplink_dialog_wrapper.sh"
  ["IOS-XE Config Migration"]=""
  ["Clean Configuration (New Batch Deployment)"]="/root/.cat_admin/clean.sh"
  ["Logging"]="/root/.cat_admin/show_logs.sh"
  ["Utilities"]=""
  ["Server Management"]=""
  ["Server Service Control"]=""
  ["README"]="/root/.cat_admin/readme.sh"
)

# Submenus: label -> function name
declare -A SUBMENU_FN=(
  ["IOS-XE Config Migration"]="submenu_ios_xe_config_migration"
  ["Utilities"]="submenu_utilities"
  ["Server Service Control"]="submenu_server_services"
)

# Per-item help text
declare -A HELP_RAW=(
  ["Deployment Workflow"]="Operational workflows for discovery, mapping, uplink validation, and IOS-XE config migration."
  ["Setup Wizard"]="Guided setup for API keys, credentials, and deployment inputs."
  ["Switch Discovery"]="Discover live Catalyst switches, probe via SSH, and build the selected switch set."
  ["Catalyst/Meraki Switch Mapping"]="Map selected Catalyst switches to the correct Meraki targets before validation and migration."
  ["Uplink Port Validation (Optional but Recommended)"]="Validate uplink-to-uplink mappings and review or correct remaps before migration."
  ["IOS-XE Config Migration"]="Migration tools for Catalyst IOS-XE configuration elements such as ports and management IP settings."
  ["Port Migration"]="Run the Catalyst-to-Meraki port migration workflow."
  ["IP Management Migration"]="Migrate management IP settings from IOS-XE configs to Meraki management interfaces."
  ["Clean Configuration (New Batch Deployment)"]="Clear prior selections and files to prepare a new deployment batch."
  ["Logging"]="View CMDS deployment and migration log files."
  ["Utilities"]="Utility tools for config review, ad-hoc command execution, and backup browsing."
  ["Config Review"]="Browse and review generated or discovered configuration content in a carousel-style viewer."
  ["CLI Updater"]="Run ad-hoc CLI command packs on selected switches."
  ["Backup Config Viewer"]="Browse and search saved switch backup configs."
  ["Server Management"]="Server management tools and utilities."
  ["Server Service Control"]="Manage CMDS services or reboot the server."
  ["README"]="View the CAT admin README and usage guide."
)

# Display order
ORDER=(
  "Deployment Workflow"
  "Setup Wizard"
  "Switch Discovery"
  "Catalyst/Meraki Switch Mapping"
  "Uplink Port Validation (Optional but Recommended)"
  "IOS-XE Config Migration"
  "Clean Configuration (New Batch Deployment)"
  "Logging"
  "Utilities"
  "Server Management"
  "Server Service Control"
  "README"
)

cleanup() { clear; }
trap cleanup EXIT

is_done() {  # $1=label -> returns 0 if artifact indicates completion
  local lbl="$1"
  local f="${DONE_FILE[$lbl]:-}"
  [[ -n "$f" ]] || return 1
  [[ -s "$f" || -f "$f" ]]
}

colorize_help() {  # $1=label
  local lbl="$1"
  local extra=""
  if is_done "$lbl"; then
    extra="  \Z2\Zb(Completed)\Zn"
  fi
  printf '%b%s%b%b' \
    "$HELP_COLOR_PREFIX" \
    "${HELP_RAW[$lbl]:-Run $lbl}" \
    "$HELP_COLOR_RESET" \
    "$extra"
}

display_label() {  # $1=label
  local lbl="$1"
  local text

  case "$lbl" in
    "Deployment Workflow")
      printf "%s" "------------ Deployment Workflow ------------"
      return
      ;;
    "Server Management")
      printf "%s" "---------------- Server Management ----------------"
      return
      ;;
  esac

  if is_done "$lbl"; then
    text="$lbl  $MARK_CHECK"
  else
    text="$lbl"
  fi

  if [[ -n "${SUBMENU_FN[$lbl]:-}" ]]; then
    text="$text  >"
  fi

  printf "%s" "$text"
}

run_target() {
  local script="$1"
  local label="$2"

  # Section headers are non-clickable
  if [[ "$label" == "Deployment Workflow" || "$label" == "Server Management" ]]; then
    return
  fi

  # Submenu handler
  if [[ -n "${SUBMENU_FN[$label]:-}" ]]; then
    "${SUBMENU_FN[$label]}"
    return
  fi

  clear

  if [[ -n "$script" && -f "$script" ]]; then
    # Mark Port Migration immediately when launched from menu
    if [[ "$label" == "Port Migration" ]]; then
      : > "$PORT_MIGRATION_OK_FILE" 2>/dev/null || touch "$PORT_MIGRATION_OK_FILE"
    fi

    set +e
    bash "$script"
    local rc=$?
    set -e

    # Stamp completion marker files on success
    if [[ "$label" == "Catalyst/Meraki Switch Mapping" ]]; then
      if [[ $rc -eq 0 ]]; then
        : > "$SWITCH_MAPPING_OK_FILE" 2>/dev/null || touch "$SWITCH_MAPPING_OK_FILE"
      else
        rm -f -- "$SWITCH_MAPPING_OK_FILE" 2>/dev/null || true
      fi
    fi

    if [[ "$label" == "Uplink Port Validation (Optional but Recommended)" ]]; then
      if [[ $rc -eq 0 ]]; then
        : > "$UPLINK_VALIDATION_OK_FILE" 2>/dev/null || touch "$UPLINK_VALIDATION_OK_FILE"
      else
        rm -f -- "$UPLINK_VALIDATION_OK_FILE" 2>/dev/null || true
      fi
    fi

    if [[ "$label" == "IP Management Migration" ]]; then
      if [[ $rc -eq 0 ]]; then
        : > "$IP_MGMT_MIGRATION_OK_FILE" 2>/dev/null || touch "$IP_MGMT_MIGRATION_OK_FILE"
      else
        rm -f -- "$IP_MGMT_MIGRATION_OK_FILE" 2>/dev/null || true
      fi
    fi

    case "$rc" in
      0) : ;;
      1|255|130|143) return 0 ;;  # cancel/back/ctrl-c: not an error
      *)
        dialog --no-shadow \
          --backtitle "$BACKTITLE" \
          --title "$label" \
          --msgbox "Script exited with status $rc.\n\n$script" 8 72
        ;;
    esac
  else
    dialog --no-shadow \
      --backtitle "$BACKTITLE" \
      --title "Not Found" \
      --msgbox "Cannot find:\n${script:-<none>}" 7 60
  fi
}

# ---------- IOS-XE Config Migration submenu ----------
submenu_ios_xe_config_migration() {
  local SUB_TITLE="IOS-XE Config Migration"

  color_help() {
    printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"
  }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    local lbl1="Port Migration"
    local path1="/root/.cat_admin/port_migration.sh"
    local desc1="Run the Catalyst-to-Meraki port migration workflow."
    if is_done "$lbl1"; then
      lbl1="$lbl1  $MARK_CHECK"
      desc1="${desc1}  \Z2\Zb(Completed)\Zn"
    fi
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "$desc1")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="Port Migration"
    ((i++))

    local lbl2="IP Management Migration"
    local path2="/root/.cat_admin/per_switch_ip_migration.sh"
    local desc2="Migrate management IP settings from IOS-XE configs to Meraki management interfaces."
    if is_done "IP Management Migration"; then
      lbl2="$lbl2  $MARK_CHECK"
      desc2="${desc2}  \Z2\Zb(Completed)\Zn"
    fi
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "$desc2")")
    PATH_BY_TAG["$i"]="$path2"
    LABEL_BY_TAG["$i"]="IP Management Migration"
    ((i++))

    MENU_ITEMS+=("0" "Back" "$(color_help "Return to main menu")")

    local CHOICE
    CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --ok-label "OK" \
        --cancel-label "Back" \
        --menu "Select a migration workflow:" 15 88 8 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0
    run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
  done
}

# ---------- Utilities submenu ----------
submenu_utilities() {
  local SUB_TITLE="Utilities"

  color_help() {
    printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"
  }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    local lbl1="Config Review"
    local path1="/root/.cat_admin/config_carousel.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Browse and review generated or discovered configuration content in a carousel-style viewer.")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    local lbl2="CLI Updater"
    local path2="/root/.cat_admin/cli_updater.sh"
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "Run ad-hoc CLI command packs on selected switches.")")
    PATH_BY_TAG["$i"]="$path2"
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    local lbl3="Backup Config Viewer"
    local path3="/root/.cat_admin/back_config_viewer.sh"
    MENU_ITEMS+=("$i" "$lbl3" "$(color_help "Browse and search saved switch backup configs.")")
    PATH_BY_TAG["$i"]="$path3"
    LABEL_BY_TAG["$i"]="$lbl3"
    ((i++))

    MENU_ITEMS+=("0" "Back" "$(color_help "Return to main menu")")

    local CHOICE
    CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --ok-label "OK" \
        --cancel-label "Back" \
        --menu "Select a utility:" 16 78 10 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0
    run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
  done
}

# ---------- Server Service Control submenu ----------
submenu_server_services() {
  local SUB_TITLE="Server Service Control"

  color_help() {
    printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"
  }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    local lbl1="Manage CMDS Services"
    local path1="/root/.server_admin/service_control.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Start, stop, or restart CMDS services via dialog.")")
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

    local CHOICE
    CHOICE=$(
      dialog --no-shadow --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "$SUB_TITLE" \
        --ok-label "OK" \
        --cancel-label "Back" \
        --menu "Select an option:" 14 78 8 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || return 0

    [[ "$CHOICE" == "0" ]] && return 0

    local label="${LABEL_BY_TAG[$CHOICE]}"

    if [[ "$label" == "Reboot Server" ]]; then
      if [[ $EUID -ne 0 ]]; then
        dialog --no-shadow \
          --backtitle "$BACKTITLE" \
          --title "Permission required" \
          --msgbox "Reboot requires root privileges." 7 60
        continue
      fi

      dialog --no-shadow \
        --backtitle "$BACKTITLE" \
        --title "Confirm Reboot" \
        --yesno "Are you sure you want to reboot this server now?

Active tasks or SSH sessions may be interrupted." 10 70

      if (( $? == 0 )); then
        dialog --no-shadow --title "Rebooting..." --infobox "Rebooting in 3 seconds..." 5 40
        sleep 1
        dialog --no-shadow --title "Rebooting..." --infobox "Rebooting in 2 seconds..." 5 40
        sleep 1
        dialog --no-shadow --title "Rebooting..." --infobox "Rebooting in 1 second..." 5 40
        sleep 1
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
      --ok-label "OK" \
      --cancel-label "Back" \
      --menu "Select an option:" 20 95 10 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  ) || exit 0

  [[ "$CHOICE" == "0" ]] && exit 0
  run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
done
