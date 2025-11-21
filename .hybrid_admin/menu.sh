#!/usr/bin/env bash
# ServiceMan – systemd service manager (dialog UI) — sturdy unit detection
set -euo pipefail

# ─── Stable environment for systemctl ─────────────────────────────────────────
export LC_ALL=C
export LANG=C
export SYSTEMD_PAGER=
export SYSTEMD_LESS=
export SYSTEMD_COLORS=0

# ─── Requirements ─────────────────────────────────────────────────────────────
if ! command -v dialog >/dev/null 2>&1; then
  echo "Error: dialog is required. Install it and retry." >&2
  exit 1
fi

# Consistent backtitle + enable color tags everywhere we call dialog
shopt -s expand_aliases
alias dialog='dialog --backtitle "Service Manager" --colors'

# ─── Admin tool mappings (optional helpers per unit) ──────────────────────────
declare -A SERVICE_ADMIN_TOOLS=(
  [samba.service]="/root/.servman/SambaMan"
  [dhcpd.service]="/root/.servman/dhcp_admin.sh"
  [kea-dhcp4.service]="/root/.server_admin/dhcp_admin.sh"
  [chronyd.service]="/root/.servman/NTPMan/ntp_admin.sh"
  [fail2ban.service]="/root/.servman/jail-admin.sh"
)

# ─── Candidate units to list (only those present will be shown) ───────────────
CANDIDATE_UNITS=(
  chronyd.service
  httpd.service
  tftp-server.socket
  dhcpd.service
  fail2ban.service
  kea-dhcp4.service
  named.service
  sshd.service
  cockpit.socket
  # openvpn-server@*.service  # example of templated units if you need them
)

# ─── Helpers ──────────────────────────────────────────────────────────────────
service_state() {
  # Return exactly one token: active|inactive|failed|activating|deactivating|reloading|dead|unknown
  local s
  s=$(systemctl is-active "$1" 2>/dev/null) || true
  echo "${s:-unknown}"
}

pretty_state() {
  case "$1" in
    active)                  echo "running" ;;
    inactive|dead|unknown)   echo "stopped" ;;
    failed)                  echo "failed/stopped" ;;
    activating|deactivating) echo "transitioning" ;;
    *)                       echo "$1" ;;
  esac
}

style_state() {
  case "$1" in
    running) echo $'\Z2running\Zn' ;;
    stopped) echo $'\Z1stopped\Zn' ;;
    *)       echo $'\Z3'"$1"$'\Zn' ;;
  esac
}

# Robust: a unit is "installed/present" if systemd knows about it (rc 0 or 3)
_present_unit() {
  # 0 = active, 3 = inactive (loaded), both mean “known”
  if systemctl status "$1" >/dev/null 2>&1; then
    return 0
  else
    local rc=$?
    [[ $rc -eq 3 ]] && return 0
    return 1
  fi
}

get_installed_units() {
  local installed=() u
  for u in "${CANDIDATE_UNITS[@]}"; do
    # Handle templated patterns here if you add them later
    if [[ "$u" == *'@*.service' ]]; then
      # example expansion block (kept off by default)
      # mapfile -t _tmpl < <(systemctl list-units --all --no-legend --no-pager | awk '{print $1}' | grep -E "^${u/\*/.+}$" || true)
      # installed+=("${_tmpl[@]}")
      :
    else
      if _present_unit "$u"; then
        installed+=("$u")
      fi
    fi
  done
  printf '%s\n' "${installed[@]}"
}

# ─── Unit Control Submenu ─────────────────────────────────────────────────────
control_unit_menu() {
  local unit="$1"
  local admin_script="" has_admin_script=false

  if [[ -n "${SERVICE_ADMIN_TOOLS[$unit]+_}" && -x "${SERVICE_ADMIN_TOOLS[$unit]}" ]]; then
    admin_script="${SERVICE_ADMIN_TOOLS[$unit]}"
    has_admin_script=true
  fi

  while true; do
    local a f label styled header choice rc
    a=$(systemctl is-active "$unit" 2>/dev/null) || a=""
    f=$(systemctl is-failed "$unit" 2>/dev/null) || f=""

    if [[ "$f" == "failed" ]]; then
      label="failed/stopped";         styled=$'\Z1failed/stopped\Zn'
    elif [[ "$a" == "active" ]]; then
      label="running";                styled=$'\Z2running\Zn'
    elif [[ "$a" == "inactive" || "$a" == "dead" ]]; then
      label="stopped";                styled=$'\Z1stopped\Zn'
    elif [[ "$a" == "unknown" || "$f" == "unknown" || -z "$a" ]]; then
      label="unknown/stopped";        styled=$'\Z1unknown/stopped\Zn'
    elif [[ "$a" == "activating" || "$a" == "deactivating" || "$a" == "reloading" ]]; then
      label="transitioning";          styled=$'\Z3transitioning\Zn'
    else
      label="unknown/stopped";        styled=$'\Z1unknown/stopped\Zn'
    fi

    header=$'Status: '"$styled"$'\n\nAction:'

    exec 3>&1; set +e
    local options=(
      1 "Start"
      2 "Stop"
      3 "Restart"
      4 "View Logs"
    )
    if [[ "$has_admin_script" == true ]]; then
      options+=(5 "Launch Admin Tool" 6 "Back")
    else
      options+=(5 "Back")
    fi
    choice=$(dialog --clear --title "Manage Unit: $unit" \
                    --menu "$header" 20 70 10 "${options[@]}" \
                    2>&1 1>&3)
    rc=$?; set -e; exec 3>&-
    [[ $rc -ne 0 ]] && break

    case "$choice" in
      1) systemctl start   "$unit" && dialog --msgbox "$unit started."   6 50 ;;
      2) systemctl stop    "$unit" && dialog --msgbox "$unit stopped."   6 50 ;;
      3) systemctl restart "$unit" && dialog --msgbox "$unit restarted." 6 50 ;;
      4)
         journalctl -u "$unit" -n 200 --no-pager > "/tmp/${unit//\//_}_logs.txt"
         dialog --title "$unit Logs (arrows/PageUp/PageDown)" \
                --tailbox "/tmp/${unit//\//_}_logs.txt" 30 160
         ;;
      5)
         if [[ "$has_admin_script" == true ]]; then
           "$admin_script"
         else
           break
         fi
         ;;
      6) break ;;
    esac
  done
}

# ─── Manage Installed Units ───────────────────────────────────────────────────
manage_units_menu() {
  while true; do
    mapfile -t UNITS < <( get_installed_units )
    if (( ${#UNITS[@]} == 0 )); then
      dialog --msgbox "No candidate units present." 6 60
      break
    fi

    local menu_args=() u s s_disp selected rc
    for u in "${UNITS[@]}"; do
      s=$(service_state "$u")
      case "$s" in
        active)            s_disp=$'\Z2active\Zn' ;;
        inactive|dead)     s_disp=$'\Z1inactive\Zn' ;;
        failed)            s_disp=$'\Z1failed\Zn' ;;
        unknown|'')        s_disp=$'\Z1unknown/stopped\Zn' ;;
        *)                 s_disp=$'\Z3'"$s"$'\Zn' ;;
      esac
      menu_args+=( "$u" "$s_disp" )
    done

    exec 3>&1; set +e
    selected=$(
      dialog --clear \
             --title "Systemd Unit Manager" \
             --menu "Select a unit to manage (Cancel -> back):" \
             20 90 "${#UNITS[@]}" \
             "${menu_args[@]}" \
        2>&1 1>&3
    )
    rc=$?; set -e; exec 3>&-
    [[ $rc -ne 0 ]] && break

    control_unit_menu "$selected"
  done
}

# ─── Enable/Disable Services Submenu ──────────────────────────────────────────
enable_disable_menu() {
  set +e
  dialog --clear \
         --title "Enable/Disable Services" \
         --msgbox "Launching ntsysv...\n\nUse space to toggle services, then OK to apply." \
         8 60
  ntsysv
  set -e
}

# ─── Top-Level Main Menu ──────────────────────────────────────────────────────
main_menu() {
  while true; do
    local choice rc
    exec 3>&1; set +e
    choice=$(
      dialog --clear --title "Service Manager" \
             --menu "Choose an option (Cancel -> exit):" \
             15 60 3 \
               1 "View/Manage Services" \
               2 "Enable/Disable Services (ntsysv)" \
               3 "Exit" \
        2>&1 1>&3
    )
    rc=$?; set -e; exec 3>&-
    [[ $rc -ne 0 ]] && break

    case "$choice" in
      1) manage_units_menu   ;;
      2) enable_disable_menu ;;
      3) clear; exit 0       ;;
    esac
  done
  clear
}

# ─── Direct jump support (e.g. `ServiceMan samba.service`) ────────────────────
if [[ $# -ge 1 ]]; then
  want="$1"
  [[ "$want" != *.service && "$want" != *.socket ]] && want="${want}.service"
  if _present_unit "$want"; then
    control_unit_menu "$want"
    clear
    exit 0
  fi
fi

# ─── Start UI ─────────────────────────────────────────────────────────────────
main_menu
[root@cmds .hybrid_admin]#  more menu.sh
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
  ["Validate IOS-XE configuration"]="/root/.hybrid_admin/preflight_validated.flag"
  # For migration, we use a symlink to the latest claim log
  ["Migrate Switches"]="/root/.hybrid_admin/meraki_claim.log"
)

# Items: label -> script path
declare -A ITEMS=(
  ["Setup Wizard"]="/root/.hybrid_admin/setupwizard.sh"
  ["Switch Discovery"]="/root/.hybrid_admin/discoverswitches.sh"
  ["Validate IOS-XE configuration"]="/root/.hybrid_admin/meraki_preflight.sh"
  ["IOS-XE Upgrade"]=""  # handled by submenu
  ["Migrate Switches"]="/root/.hybrid_admin/migration.sh"
  ["Logging"]="/root/.hybrid_admin/show_logs.sh"
  ["Clean Configuration (New Batch Deployment)"]="/root/.hybrid_admin/clean.sh"
  ["Utilities"]=""  # handled by submenu
  ["Server Management"]=""  # header / separator, not an actual script
  ["Server Service Control"]=""  # handled by submenu
)

# Submenus: label -> function name
declare -A SUBMENU_FN=(
  ["IOS-XE Upgrade"]="submenu_iosxe"
  ["Utilities"]="submenu_utilities"
  ["Server Service Control"]="submenu_server_services"
)

# Per-item help (status line)
declare -A HELP_RAW=(
  ["Setup Wizard"]="Guided Setup: Always run between batches (API keys, credentials)"
  ["Switch Discovery"]="Discover live Catalyst switches, probe via SSH, and build the selection for upgrades."
  ["Validate IOS-XE configuration"]="Run preflight validation for selected switches and configuration before upgrade."
  ["IOS-XE Upgrade"]="Run IOS-XE install/activate/commit workflows and tools."
  ["Deploy IOS-XE"]="Copy image to flash, then install/activate/commit on selected switches."
  ["Schedule Image Upgrade"]="Schedule a future image upgrade (snapshots envs, uses 'at')."
  ["Migrate Switches"]="Run the Catalyst-to-Meraki switch migration workflow and claim devices into Dashboard."
  ["Logging"]="View CMDS deployment and migration log files."
  ["Clean Configuration (New Batch Deployment)"]="Clear previous selections and files to prepare a new batch deployment."
  ["Utilities"]="Utility tools for monitoring and quick checks."
  ["Switch UP/Down Status"]="Monitor switch reachability (UP/DOWN) using continuous ping."
  ["IOS-XE Image Management"]="Manage IOS-XE image files (list, inspect, and clean up)."
  ["CLI Updater"]="Run ad-hoc CLI command packs on selected switches."
  ["Backup Config Viewer"]="Browse and search saved switch backup configs."
  ["Server Management"]="Server management tools and utilities."
  ["Server Service Control"]="Manage CMDS services or reboot the server."
)

# Display order (main menu)
ORDER=(
  "Setup Wizard"
  "Switch Discovery"
  "IOS-XE Upgrade"
  "Validate IOS-XE configuration"
  "Migrate Switches"
  "Logging"
  "Clean Configuration (New Batch Deployment)"
  "Utilities"
  "Server Management"
  "Server Service Control"
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
  if [[ "$lbl" == "Server Management" ]]; then
    printf "%s" "---------------- Server Management ----------------"
    return
  fi

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
  if [[ "$label" == "Server Management" ]]; then
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
    local path1="/root/.hybrid_admin/image_upgrade.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(colorize_help "$lbl1")"); PATH_BY_TAG["$i"]="$path1"; LABEL_BY_TAG["$i"]="$lbl1"; ((i++))

    local lbl2="Schedule Image Upgrade"
    local path2="/root/.hybrid_admin/scheduler.sh"
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

    # 1) Switch UP/Down Status (ping monitor)
    local lbl1="Switch UP/Down Status"
    local path1="/root/.hybrid_admin/ping.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Continuous ping monitor for selected switches (UP/DOWN).")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    # 2) IOS-XE Image Management
    local lbl2="IOS-XE Image Management"
    local path2="/root/.hybrid_admin/image_management.sh"
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "Manage IOS-XE image files (list, inspect, and clean up).")")
    PATH_BY_TAG["$i"]="$path2"
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    # 3) CLI Updater
    local lbl3="CLI Updater"
    local path3="/root/.hybrid_admin/cli_updater.sh"
    MENU_ITEMS+=("$i" "$lbl3" "$(color_help "Run ad-hoc CLI command packs on selected switches.")")
    PATH_BY_TAG["$i"]="$path3"
    LABEL_BY_TAG["$i"]="$lbl3"
    ((i++))

    # 4) Backup Config Viewer
    local lbl4="Backup Config Viewer"
    local path4="/root/.hybrid_admin/back_config_viewer.sh"
    MENU_ITEMS+=("$i" "$lbl4" "$(color_help "Browse and search saved switch backup configs.")")
    PATH_BY_TAG["$i"]="$path4"
    LABEL_BY_TAG["$i"]="$lbl4"
    ((i++))

    # Back
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
# ---------- Server Service Control submenu ----------
submenu_server_services(){
  local SUB_TITLE="Server Service Control"

  color_help(){ printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"; }

  while true; do
    local MENU_ITEMS=()
    local -A PATH_BY_TAG=()
    local -A LABEL_BY_TAG=()
    local i=1

    # Option 1: manage services
    local lbl1="Manage CMDS Services"
    local path1="/root/.server_admin/service_control.sh"
    MENU_ITEMS+=("$i" "$lbl1" "$(color_help "Start/stop/restart CMDS services via dialog.")")
    PATH_BY_TAG["$i"]="$path1"
    LABEL_BY_TAG["$i"]="$lbl1"
    ((i++))

    # OPTIONAL: DHCP Administration (only if Kea config exists)
    if [[ -f /etc/kea/kea-dhcp4.conf ]]; then
      local lbl_dhcp="DHCP Administration"
      local path_dhcp="/root/.server_admin/dhcp_admin.sh"
      MENU_ITEMS+=("$i" "$lbl_dhcp" "$(color_help "Administer Kea DHCP configuration and leases.")")
      PATH_BY_TAG["$i"]="$path_dhcp"
      LABEL_BY_TAG["$i"]="$lbl_dhcp"
      ((i++))
    fi

    # Reboot server
    local lbl2="Reboot Server"
    MENU_ITEMS+=("$i" "$lbl2" "$(color_help "Safely reboot this server (confirmation required).")")
    PATH_BY_TAG["$i"]=""          # handled specially below
    LABEL_BY_TAG["$i"]="$lbl2"
    ((i++))

    # Back
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

    # Special handling for reboot; everything else goes through run_target
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
      --menu "Select an option:" 18 78 10 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  ) || exit 0

  [[ "$CHOICE" == "0" ]] && exit 0
  run_target "${PATH_BY_TAG[$CHOICE]}" "${LABEL_BY_TAG[$CHOICE]}"
done