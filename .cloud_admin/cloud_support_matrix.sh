#!/usr/bin/env bash
# firmware_network_report.sh — One-file Firmware Network Report (Prompts + Collection)
# - Dialog prompts (scan CIDR or manual IPs, SSH creds, enable password)
# - Writes a separate report env (does NOT touch setupwizard env)
# - Runs split-screen collection UI (scan -> ssh/22 -> probe -> PID match vs manifest JSON)
# - Outputs report JSON/CSV + summary + devlogs
#
# Wire this into your "Firmware Check" menu.

set -Euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

###############################################################################
# CONFIG (adjust here)
###############################################################################
CLOUD_ROOT="${CLOUD_ROOT:-/root/.cloud_admin}"
BACKTITLE="${BACKTITLE:-CMDS-Deployment Server}"
TITLE="${TITLE:-Firmware Network Report}"
ENV_FILE="${ENV_FILE:-$CLOUD_ROOT/cloud_firmware_report.env}"
MANIFEST_JSON="${MANIFEST_JSON:-$CLOUD_ROOT/cloud_models.json}"
REPORT_ROOT="${REPORT_ROOT:-$CLOUD_ROOT/runs/firmware_reports}"

# Defaults
DISCOVERY_MODE_DEFAULT="${DISCOVERY_MODE_DEFAULT:-scan}"  # scan|list
DEFAULT_CIDR_EXAMPLE="${DEFAULT_CIDR_EXAMPLE:-10.0.0.0/24}"
MAX_SSH_FANOUT_DEFAULT="${MAX_SSH_FANOUT_DEFAULT:-10}"
SSH_TIMEOUT_DEFAULT="${SSH_TIMEOUT_DEFAULT:-30}"

###############################################################################
# REQUIREMENTS
###############################################################################
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need nmap
need jq
need awk
need sed
need ssh
need timeout || true
need python3
command -v sshpass >/dev/null 2>&1 || true

[[ -r "$MANIFEST_JSON" ]] || { echo "Manifest JSON not found/readable: $MANIFEST_JSON" >&2; exit 1; }

###############################################################################
# Small helpers
###############################################################################
trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
is_valid_ip()   { python3 -c 'import sys,ipaddress; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
is_valid_cidr() { python3 -c 'import sys,ipaddress; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }
split_list() { tr ',;' ' ' | xargs -n1 | awk 'NF'; }
dlg() {
  local _tmp; _tmp="$(mktemp)"
  dialog "$@" 2>"$_tmp"
  local _rc=$?
  DOUT=""
  [[ -s "$_tmp" ]] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $_rc
}

mask_last4() {
  local s="$1" n
  n="$(printf '%s' "$s" | wc -c | awk '{print $1}')"
  if [[ "$n" -le 4 ]]; then
    printf '****'
  else
    printf "%0.s*" $(seq 1 $((n-4)))
    printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}

clean_field() {
  local s
  s="$(printf '%s' "$1" | tr -d '\r\n')"
  s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//; s/[#]$//')"
  printf '%s' "$s"
}

sanitize_ver(){
  local v="${1:-}"
  v="${v//[^0-9.]/}"
  sed -E 's/\.+/./g; s/^\.//; s/\.$//' <<<"$v"
}

vercmp(){  # -1 (a<b), 0 (==), 1 (a>b)
  local a b i len ai bi
  a="$(sanitize_ver "$1")"; b="$(sanitize_ver "$2")"
  IFS='.' read -r -a A <<<"${a:-0}"; IFS='.' read -r -a B <<<"${b:-0}"
  (( len = ${#A[@]} > ${#B[@]} ? ${#A[@]} : ${#B[@]} ))
  for ((i=0;i<len;i++)); do
    ai="${A[i]:-0}"; bi="${B[i]:-0}"
    ((10#$ai < 10#$bi)) && { echo -1; return; }
    ((10#$ai > 10#$bi)) && { echo 1; return; }
  done
  echo 0
}

# Decide which Cisco image "type" you need (UNIVERSAL vs LITE)
# (Nice-to-humans labels included as well)
# Returns: "TYPE|TRAIN"
# - UNIVERSAL -> cat9k_iosxe
# - LITE      -> cat9k_lite_iosxe
infer_image_meta() {
  local pid="${1:-}"
  local fam="${2:-}"

  local s="${pid}${fam}"
  s="$(printf '%s' "$s" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')"

  if [[ "$s" == *C9200* || "$s" == *C9200L* || "$s" == *C9200CX* ]]; then
    echo "LITE|cat9k_lite_iosxe"
  else
    echo "UNIVERSAL|cat9k_iosxe"
  fi
}

# Bigger dialog sizing for "review" windows
dlg_big_dims() {
  local lines cols h w
  if ! read -r lines cols < <(stty size 2>/dev/null); then
    lines=24; cols=80
  fi
  # Big, but leave a little margin
  h=$((lines - 4)); w=$((cols - 6))
  (( h < 22 )) && h=22
  (( w < 90 )) && w=90
  echo "$h $w"
}

# Post-run viewer menu (summary + JSON/CSV + logs)
post_run_menu() {
  local h w choice
  read -r h w < <(dlg_big_dims)

  while :; do
    choice="$(
      dialog --no-shadow --backtitle "Firmware Requirement Report" \
        --title "Report Complete — $RUN_TAG" \
        --menu "Choose what to view:" 12 60 6 \
          1 "View Summary" \
          2 "View JSON results" \
          3 "View CSV results" \
          4 "View per-host logs (devlogs/)" \
          0 "Exit" \
        2>&1 >/dev/tty
    )" || break

    case "$choice" in
      1) dialog --no-shadow --backtitle "Firmware Requirement Report" --title "Summary — $RUN_TAG" \
            --textbox "$SUMMARY_TXT" "$h" "$w" ;;
      2) dialog --no-shadow --backtitle "Firmware Requirement Report" --title "JSON — $RUN_TAG" \
            --textbox "$REPORT_JSON" "$h" "$w" ;;
      3) dialog --no-shadow --backtitle "Firmware Requirement Report" --title "CSV — $RUN_TAG" \
            --textbox "$REPORT_CSV" "$h" "$w" ;;
      4)
         local tmp pick
         tmp="$(mktemp)"
         (cd "$DEVLOG_DIR" && ls -1 2>/dev/null | sed 's/$/ -/') >"$tmp"
         if [[ ! -s "$tmp" ]]; then
           dialog --no-shadow --backtitle "Firmware Requirement Report" --title "Devlogs" \
             --msgbox "No devlogs found in:\n$DEVLOG_DIR" 8 70
           rm -f "$tmp"
           continue
         fi
         rm -f "$tmp"

         # shellcheck disable=SC2086
         pick="$(
           dialog --no-shadow --backtitle "Firmware Requirement Report" \
             --title "Per-host logs" \
             --menu "Select a log file to view:" "$h" "$w" 12 \
             $(cd "$DEVLOG_DIR" && ls -1 | awk '{print $0" -"}') \
             2>&1 >/dev/tty
         )" || continue

         if [[ -n "$pick" && -r "$DEVLOG_DIR/$pick" ]]; then
           dialog --no-shadow --backtitle "Firmware Requirement Report" \
             --title "Log: $pick" --textbox "$DEVLOG_DIR/$pick" "$h" "$w"
         fi
         ;;
      0) break ;;
    esac
  done
}

###############################################################################
# Setupwizard-style prompt flow (dialog) for Network Report
###############################################################################
REPORT_TITLE="CMDS Network Report — Setup"
REPORT_BACKTITLE="Meraki Migration Toolkit — Network Report"
REPORT_ENV_FILE="$ENV_FILE"

trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

dlg() {
  local _tmp; _tmp="$(mktemp)"
  dialog "$@" 2>"$_tmp"
  local _rc=$?
  DOUT=""
  [[ -s "$_tmp" ]] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $_rc
}

is_valid_ip()   { python3 -c 'import sys,ipaddress; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
is_valid_cidr() { python3 -c 'import sys,ipaddress; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }

ssh_login_ok() {
  sshpass -p "$3" ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 -tt "$2@$1" "exit" >/dev/null 2>&1
}

get_default_priv_level() {
  local host="$1" user="$2" pass="$3"
  local out pl pc
  out="$(
    { printf 'terminal length 0\n'; printf 'show privilege\n'; printf 'exit\n'; } |
    sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o PreferredAuthentications=password,keyboard-interactive \
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 -tt "$user@$host" 2>/dev/null
  )"
  out="$(printf '%s' "$out" | tr -d '\r')"
  pl="$(printf '%s\n' "$out" | awk 'BEGIN{IGNORECASE=1} /Current privilege level is/ {print $NF; exit}')"
  pl="$(trim "$pl")"
  if [[ -z "$pl" ]]; then
    pc="$(printf '%s\n' "$out" | awk '/[>#][[:space:]]*$/{p=$0} END{print p}' | sed -nE 's/.*([>#])[[:space:]]*$/\1/p')"
    case "$pc" in
      \#) pl="15" ;;
      \>) pl="1" ;;
      *)  pl="" ;;
    esac
  fi
  printf '%s' "$pl"
}

ssh_enable_ok() {
  local host="$1" user="$2" pass="$3" enpass="$4"
  [[ -n "$host" && -n "$user" && -n "$pass" && -n "$enpass" ]] || return 7
  HOST="$host" USER="$user" PASS="$pass" ENPASS="$enpass" \
  expect -f - <<'EXP'
    log_user 0
    set host $env(HOST); set user $env(USER); set pass $env(PASS); set enpass $env(ENPASS)
    set t_login 15
    set t_enable 2
    set t_verify 4
    set prompt_re {[\r\n][^\r\n]*[>#] ?$}

    spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
              -o ConnectTimeout=10 -o PreferredAuthentications=password,keyboard-interactive \
              -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
              -o NumberOfPasswordPrompts=1 -tt $user@$host

    set timeout $t_login
    while 1 {
      expect -nocase -re {username:} { send -- "$user\r" } \
             -nocase -re {password:} { send -- "$pass\r" } \
             -re $prompt_re          { break } \
             -re {denied|authentication failed|login invalid} { exit 3 } \
             timeout                 { exit 3 } eof { exit 3 }
    }

    send -- "\r"; expect -re $prompt_re
    send -- "terminal length 0\r"; expect -re $prompt_re
    send -- "disable\r"; expect -re $prompt_re

    proc try_enable {t_enable prompt_re} {
      send -- "enable\r"
      set sawpw 0
      set timeout $t_enable
      while 1 {
        expect -nocase -re {password:} { set sawpw 1; send -- "$::enpass\r"; exp_continue } \
               -re $prompt_re          { return [list 1 $sawpw] } \
               timeout                 { return [list 0 $sawpw] } \
               eof                     { return [list -1 $sawpw] }
      }
    }

    lassign [try_enable $t_enable $prompt_re] ok1 sawpw1
    if {$ok1 == 0 && $sawpw1 == 0} {
      lassign [try_enable $t_enable $prompt_re] ok2 sawpw2
      if {$ok2 == 0 && $sawpw2 == 0} { exit 5 }
    } elseif {$ok1 < 0} { exit 4 }

    set timeout $t_verify
    send -- "show privilege\r"
    expect {
      -re {Current privilege level is[[:space:]]*15} { exit 0 }
      -re {Current privilege level is[[:space:]]*[0-9]+} { exit 6 }
      timeout { exit 4 }
      eof     { exit 4 }
    }
EXP
  return $?
}

_prompt_targets_like_setupwizard() {
  local MODE rc
  local W_MODE=68 W_DEF=68 W_EDIT=68

  dlg --clear --backtitle "$REPORT_BACKTITLE" --title "$REPORT_TITLE" \
      --menu "How do you want to provide targets?" 12 "$W_MODE" 2 \
      scan "Discover live hosts by scanning CIDR networks" \
      list "Use a manual list of IPs (one per line)"
  rc=$?; MODE="$(trim "${DOUT:-}")"
  [[ $rc -eq 0 ]] || return 1

  DISCOVERY_MODE="$MODE"
  DISCOVERY_NETWORKS=""
  DISCOVERY_IPS=""

  if [[ "$MODE" == "scan" ]]; then
    local NETS_PREV tmpnets NETS_RAW invalid_line line
    NETS_PREV="# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored.
10.0.0.0/24"
    while :; do
      tmpnets="$(mktemp)"; printf '%s\n' "$NETS_PREV" >"$tmpnets"
      dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Networks to Scan (one per line)" --editbox "$tmpnets" 14 "$W_EDIT"
      rc=$?; NETS_RAW="${DOUT:-}"; rm -f "$tmpnets"; [[ $rc -eq 0 ]] || return 1
      NETS_PREV="$NETS_RAW"

      DISCOVERY_NETWORKS=""
      invalid_line=""
      while IFS= read -r raw; do
        line="$(trim "$raw")"
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue
        if ! is_valid_cidr "$line"; then invalid_line="$line"; break; fi
        [[ -z "$DISCOVERY_NETWORKS" ]] && DISCOVERY_NETWORKS="$line" || DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS,$line"
      done <<<"$NETS_RAW"

      [[ -z "$invalid_line" ]] || { dlg --title "Invalid Network" --msgbox "Invalid: '$invalid_line'\nUse CIDR like 10.0.0.0/24." 8 "$W_DEF"; continue; }
      [[ -n "$DISCOVERY_NETWORKS" ]] || { dlg --title "No Networks" --msgbox "Provide at least one valid CIDR." 7 "$W_DEF"; continue; }
      break
    done
  else
    local IPS_PREV tmpips IPS_RAW invalid_ip ip
    IPS_PREV="# Paste or type one IP per line.
# Lines starting with '#' and blank lines are ignored.
192.168.1.10
192.168.1.11"
    while :; do
      tmpips="$(mktemp)"; printf '%s\n' "$IPS_PREV" >"$tmpips"
      dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Manual IP List (one per line)" --editbox "$tmpips" 16 "$W_EDIT"
      rc=$?; IPS_RAW="${DOUT:-}"; rm -f "$tmpips"; [[ $rc -eq 0 ]] || return 1
      IPS_PREV="$IPS_RAW"

      DISCOVERY_IPS=""
      invalid_ip=""
      declare -A _seen=()
      while IFS= read -r raw; do
        ip="$(trim "$raw")"
        [[ -z "$ip" ]] && continue
        [[ "$ip" == \#* ]] && continue
        if ! is_valid_ip "$ip"; then invalid_ip="$ip"; break; fi
        if [[ -z "${_seen[$ip]:-}" ]]; then
          _seen["$ip"]=1
          [[ -z "$DISCOVERY_IPS" ]] && DISCOVERY_IPS="$ip" || DISCOVERY_IPS="$DISCOVERY_IPS $ip"
        fi
      done <<<"$IPS_RAW"

      [[ -z "$invalid_ip" ]] || { dlg --title "Invalid IP" --msgbox "Invalid IP: '$invalid_ip'." 7 "$W_DEF"; continue; }
      [[ -n "$DISCOVERY_IPS" ]] || { dlg --title "No IPs" --msgbox "Provide at least one valid IP." 7 "$W_DEF"; continue; }
      break
    done
  fi

  return 0
}

_prompt_creds_test_like_setupwizard() {
  local W_DEF=68 rc
  while :; do
    dlg --clear --backtitle "$REPORT_BACKTITLE" --title "SSH Username" --inputbox "Enter SSH switch username:" 8 "$W_DEF" "${SSH_USERNAME:-}"
    rc=$?; [[ $rc -eq 0 ]] || return 1
    SSH_USERNAME="$(trim "${DOUT:-}")"
    [[ -n "$SSH_USERNAME" ]] && break
    dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
  done

  while :; do
    dlg --clear --backtitle "$REPORT_BACKTITLE" --title "SSH Password" --insecure --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF"
    rc=$?; [[ $rc -eq 0 ]] || return 1
    SSH_PASSWORD="$(trim "${DOUT:-}")"
    [[ -n "$SSH_PASSWORD" ]] && break
    dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
  done

  SSH_TEST_IP=""
  if [[ -n "${DISCOVERY_IPS:-}" ]]; then
    local MENU_ARGS=""
    for ip in $DISCOVERY_IPS; do MENU_ARGS="$MENU_ARGS $ip -"; done
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Test Device" \
        --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
    rc=$?; [[ $rc -eq 0 ]] || return 1
    SSH_TEST_IP="$(trim "${DOUT:-}")"
  else
    while :; do
      dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Test Device IP" \
          --inputbox "Enter a switch IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
      rc=$?; [[ $rc -eq 0 ]] || return 1
      local val; val="$(trim "${DOUT:-}")"
      [[ -n "$val" ]] && is_valid_ip "$val" && SSH_TEST_IP="$val" && break
      dlg --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
    done
  fi

  while :; do
    dlg --backtitle "$REPORT_BACKTITLE" --title "Testing SSH" \
        --infobox "Testing SSH login to ${SSH_TEST_IP} as ${SSH_USERNAME}…" 6 "$W_DEF"
    sleep 1
    if ssh_login_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD"; then
      dlg --backtitle "$REPORT_BACKTITLE" --title "SSH Test" --infobox "Login OK to ${SSH_TEST_IP}." 5 "$W_DEF"
      sleep 1
      break
    fi
    dlg --backtitle "$REPORT_BACKTITLE" --title "Login Failed" --yesno "Could not log in. Re-enter username and password?" 8 "$W_DEF"
    rc=$?; [[ $rc -eq 0 ]] || return 1
    while :; do
      dlg --clear --backtitle "$REPORT_BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 "$W_DEF" "$SSH_USERNAME"
      rc=$?; [[ $rc -eq 0 ]] || return 1
      SSH_USERNAME="$(trim "${DOUT:-}")"
      [[ -n "$SSH_USERNAME" ]] && break
      dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
    done
    while :; do
      dlg --clear --backtitle "$REPORT_BACKTITLE" --title "SSH Password" --insecure --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF"
      rc=$?; [[ $rc -eq 0 ]] || return 1
      SSH_PASSWORD="$(trim "${DOUT:-}")"
      [[ -n "$SSH_PASSWORD" ]] && break
      dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
    done
  done

  DEFAULT_LOGIN_PRIV="$(get_default_priv_level "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD")"
  DEFAULT_LOGIN_PRIV="$(trim "$DEFAULT_LOGIN_PRIV")"
  local PL_NUM; PL_NUM="$(printf '%s' "$DEFAULT_LOGIN_PRIV" | tr -cd '0-9')"
  DEFAULT_PRIV15_OK="0"
  if [[ "$PL_NUM" == "15" ]]; then
    DEFAULT_PRIV15_OK="1"
  else
    dialog --no-shadow --backtitle "$REPORT_BACKTITLE" --title "Privilege Level Too Low" --msgbox \
"Your account does not land in privileged EXEC by default.

Device: ${SSH_TEST_IP}
Detected default privilege level: ${DEFAULT_LOGIN_PRIV:-unknown}

This report tool requires a user that logs in at privilege 15 (#) without entering 'enable'.

Please use an account with privilege 15 and re-run." 16 "$W_DEF"
    return 1
  fi

  ENABLE_PASSWORD=""; ENABLE_TEST_OK="0"
  while :; do
    dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Enable Password (required)" \
        --insecure --passwordbox \
"Enter the device's ENABLE password.
We'll verify it now before scanning the network." 10 "$W_DEF"
    rc=$?; [[ $rc -eq 0 ]] || return 1

    ENABLE_PASSWORD="$(trim "${DOUT:-}")"
    if [[ -z "$ENABLE_PASSWORD" ]]; then
      dlg --no-shadow --backtitle "$REPORT_BACKTITLE" --title "Missing Enable Password" \
          --msgbox "The ENABLE password is required.\n\nPlease enter a non-empty password." 8 "$W_DEF"
      continue
    fi

    dlg --backtitle "$REPORT_BACKTITLE" --title "Testing Enable" \
        --infobox "Verifying enable password on ${SSH_TEST_IP}…" 6 "$W_DEF"

    ssh_enable_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD" "$ENABLE_PASSWORD"
    rc=$?

    if [[ $rc -eq 0 || $rc -eq 5 ]]; then
      ENABLE_TEST_OK="1"
      dlg --backtitle "$REPORT_BACKTITLE" --title "Enable Test" \
          --msgbox "Enable password verified and stored for this report run." 7 "$W_DEF"
      break
    fi

    local reason="Enable password failed."
    [[ $rc -eq 6 ]] && reason="Enable password was rejected by the device."

    dialog --no-shadow --backtitle "$REPORT_BACKTITLE" --title "Enable Test Failed" --yesno \
"${reason}

Do you want to try entering the ENABLE password again?" 10 "$W_DEF"
    rc=$?; [[ $rc -eq 0 ]] || return 1
  done

  return 0
}

write_report_env() {
  umask 077
  {
    echo "# Generated $(date -u '+%F %T') UTC"
    printf 'export DISCOVERY_MODE=%q\n' "${DISCOVERY_MODE:-}"
    printf 'export DISCOVERY_NETWORKS=%q\n' "${DISCOVERY_NETWORKS:-}"
    printf 'export DISCOVERY_IPS=%q\n' "${DISCOVERY_IPS:-}"
    printf 'export SSH_USERNAME=%q\n' "${SSH_USERNAME:-}"
    printf 'export SSH_PASSWORD=%q\n' "${SSH_PASSWORD:-}"
    printf 'export SSH_TEST_IP=%q\n' "${SSH_TEST_IP:-}"
    printf 'export DEFAULT_PRIV15_OK=%q\n' "${DEFAULT_PRIV15_OK:-}"
    printf 'export DEFAULT_LOGIN_PRIV=%q\n' "${DEFAULT_LOGIN_PRIV:-}"
    printf 'export ENABLE_PASSWORD=%q\n' "${ENABLE_PASSWORD:-}"
    printf 'export ENABLE_TEST_OK=%q\n' "${ENABLE_TEST_OK:-}"
  } > "$REPORT_ENV_FILE"
}

prompt_report_setupwizard_flow() {
  need dialog; need python3; need ssh; need sshpass; need expect

  dlg --clear --backtitle "$REPORT_BACKTITLE" --title "Welcome — Network Report" --msgbox \
"This will generate a Network Report by:
  1) Choosing targets (scan CIDR or manual list)
  2) Entering SSH credentials and verifying login
  3) Verifying ENABLE password on one sample switch
  4) Running discovery + collection with live progress UI

This does NOT overwrite meraki_discovery.env.
It writes: ${REPORT_ENV_FILE}" 14 80 || return 1

  _prompt_targets_like_setupwizard || return 1
  _prompt_creds_test_like_setupwizard || return 1

  write_report_env
  return 0
}

###############################################################################
# 2) COLLECTION (split-screen dialog UI + report outputs)
###############################################################################
load_env() {
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  DISCOVERY_MODE="${DISCOVERY_MODE:-list}"
  DISCOVERY_IPS="${DISCOVERY_IPS:-}"
  DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
  SSH_USERNAME="$(printf '%s' "${SSH_USERNAME:-}" | tr -d '\r')"
  SSH_PASSWORD="$(printf '%s' "${SSH_PASSWORD:-}" | tr -d '\r')"
  ENABLE_PASSWORD="$(printf '%s' "${ENABLE_PASSWORD:-}" | tr -d '\r')"
  MAX_SSH_FANOUT="${MAX_SSH_FANOUT:-10}"
  SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
  UI_MODE="${UI_MODE:-dialog}"
  MANIFEST_JSON="${MANIFEST_JSON:-$MANIFEST_JSON}"
  REPORT_ROOT="${REPORT_ROOT:-$REPORT_ROOT}"
}

DIALOG_AVAILABLE=0
STATUS_FILE=""
PROG_PIPE=""
PROG_FD=""
DIALOG_PID=""
TAIL_H=; TAIL_W=; GAUGE_H=; GAUGE_W=; GAUGE_ROW=; GAUGE_COL=
DEV_LOG=""
RUN_TAG=""
RUN_DIR=""
DEVLOG_DIR=""
REPORT_JSON=""
REPORT_CSV=""
SUMMARY_TXT=""
MANIFEST_INDEX=""

log_msg(){ printf '%s [%s] %s\n' "$(date '+%F %T')" "$RUN_TAG" "$*" >>"$DEV_LOG"; }

_ui_calc_layout() {
  local lines cols
  if ! read -r lines cols < <(stty size 2>/dev/null); then lines=24 cols=80; fi
  if (( lines < 18 || cols < 70 )); then DIALOG_AVAILABLE=0; return; fi
  TAIL_H=$((lines - 10)); (( TAIL_H < 10 )) && TAIL_H=10
  TAIL_W=$((cols - 4));   (( TAIL_W < 68 )) && TAIL_W=68
  GAUGE_H=7
  GAUGE_W=$TAIL_W
  GAUGE_ROW=$((TAIL_H + 3))
  GAUGE_COL=2
}

_ui_fd_open() {
  [[ -n "${PROG_FD:-}" ]] || return 1
  [[ -e "/proc/$$/fd/$PROG_FD" ]] && return 0
  { : >&"$PROG_FD"; } 2>/dev/null || return 1
  return 0
}

ui_start() {
  _ui_calc_layout
  log_msg "UI: start (DIALOG_AVAILABLE=$DIALOG_AVAILABLE)"
  if (( DIALOG_AVAILABLE )); then
    mkfifo "$PROG_PIPE"
    exec {PROG_FD}<>"$PROG_PIPE"
    (
      dialog --no-shadow \
             --backtitle "Firmware Requirement Report" \
             --begin 2 2 --title "Activity" --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
             --and-widget \
             --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Overall Progress" \
             --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$PROG_PIPE"
    ) & DIALOG_PID=$!
    sleep 0.15
  else
    echo "[info] UI plain mode."
  fi
}

ui_status() {
  local msg="$1"
  log_msg "STATUS: $msg"
  printf '%(%H:%M:%S)T %s\n' -1 "$msg" >> "$STATUS_FILE"
  (( DIALOG_AVAILABLE )) || echo "$msg"
}

ui_gauge() {
  local p="$1"; shift || true; local m="${*:-Working…}"
  log_msg "GAUGE: ${p}%% - $m"
  if (( DIALOG_AVAILABLE )) && _ui_fd_open; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$PROG_FD"; } 2>/dev/null || true
  else
    echo "[progress] $p%% - $m"
  fi
}

ui_stop() {
  log_msg "UI: stop"
  if (( DIALOG_AVAILABLE )); then
    if _ui_fd_open; then
      { printf 'XXX\n100\nDone.\nXXX\n' >&"$PROG_FD"; } 2>/dev/null || true
    fi
    if [[ -n "${PROG_FD:-}" ]]; then
      exec {PROG_FD}>&- 2>/dev/null || true
      PROG_FD=""
    fi
    rm -f "$PROG_PIPE" 2>/dev/null || true
    if [[ -n "${DIALOG_PID:-}" ]]; then
      kill "$DIALOG_PID" 2>/dev/null || true
      DIALOG_PID=""
    fi
  fi
}

TARGETS=()
TARGET_MODE=""
USE_IFACE=0

resolve_targets() {
  TARGETS=()
  local mode="${DISCOVERY_MODE,,}"

  if [[ "$mode" == "scan" ]]; then
    [[ -n "${DISCOVERY_NETWORKS:-}" ]] || return 1
    mapfile -t TARGETS < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list)
    TARGET_MODE="scan"
  else
    mapfile -t TARGETS < <(printf '%s\n' "$DISCOVERY_IPS" | tr ',;' ' ' | xargs -n1 | awk 'NF')
    TARGET_MODE="list"
  fi

  [[ ${#TARGETS[@]} -gt 0 ]] || return 1
  ui_status "Mode: $TARGET_MODE"
  ui_status "Targets: ${TARGETS[*]}"
  log_msg "resolve_targets: mode=$TARGET_MODE count=${#TARGETS[@]}"
}

nmap_cmd_base() {
  local opts=(-n)
  [[ $(id -u) -ne 0 ]] && opts+=(--privileged)
  (( USE_IFACE )) && opts+=(-e "$DISCOVERY_INTERFACE")
  printf '%s ' "${opts[@]}"
}

run_nmap_with_heartbeat() {
  local label="$1"; shift
  local -a args=("$@")
  local -a cmd=(nmap $(nmap_cmd_base) -sn "${args[@]}" "${TARGETS[@]}")
  local tmp; tmp="$(mktemp)"
  {
    "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' >"$tmp"
  } &
  local scan_pid=$!
  local elapsed=0
  while kill -0 "$scan_pid" 2>/dev/null; do
    ui_status "${label}… (elapsed ${elapsed}s)"
    sleep 5
    ((elapsed+=5))
  done
  wait "$scan_pid" 2>/dev/null || true
  cat "$tmp"
  rm -f "$tmp"
}

discover_targets() {
  ui_status "Discovering live hosts…"; ui_gauge 5 "Scanning networks…"
  local live=()
  mapfile -t live < <(run_nmap_with_heartbeat "Discovering live hosts" -PE -PS22,80,443,830 -PA22,443)
  printf '%s\n' "${live[@]}" | awk 'NF' | sort -u
}

filter_ssh_open() {
  local ips=("$@")
  ui_status "Checking TCP/22 on ${#ips[@]} host(s)…"; ui_gauge 15 "Checking SSH ports…"
  local cmd=(nmap $(nmap_cmd_base) -Pn --open -p22 --max-retries 2 "${ips[@]}")
  "${cmd[@]}" -oG - 2>/dev/null | awk '/Ports: 22\/open/{print $2}' || true
}

build_manifest_index() {
  ui_status "Indexing manifest JSON…"
  jq -c '
    def norm: tostring | gsub("[[:space:]]+";"") ;

    .families // []
    | map(select(type=="object"))
    | [
        .[] as $f
        | ($f.models // []) | .[]? as $m
        | { ( ($m|norm) ): { family: ($f.family//""), min_iosxe: ($f.min_iosxe//"") } }
      ]
    | add
    | { map: . }
  ' "$MANIFEST_JSON" >"$MANIFEST_INDEX"
}

lookup_required_meta() {
  local model_raw="$1"
  local model="$(printf '%s' "$model_raw" | tr -d '[:space:]')"
  [[ -n "$model" ]] || { echo "|"; return 0; }

  local fam req
  fam="$(jq -r --arg m "$model" '.map[$m].family // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
  req="$(jq -r --arg m "$model" '.map[$m].min_iosxe // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
  if [[ -n "$fam$req" ]]; then
    echo "${fam}|${req}"
    return 0
  fi

  if [[ "$model" == *-M ]]; then
    local alt="${model%-M}"
    fam="$(jq -r --arg m "$alt" '.map[$m].family // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
    req="$(jq -r --arg m "$alt" '.map[$m].min_iosxe // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
    [[ -n "$fam$req" ]] && { echo "${fam}|${req}"; return 0; }
  else
    local alt="${model}-M"
    fam="$(jq -r --arg m "$alt" '.map[$m].family // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
    req="$(jq -r --arg m "$alt" '.map[$m].min_iosxe // empty' "$MANIFEST_INDEX" 2>/dev/null || true)"
    [[ -n "$fam$req" ]] && { echo "${fam}|${req}"; return 0; }
  fi

  echo "|"
}

probe_host() {
  local ip="$1"
  local log="$DEVLOG_DIR/$ip.log"
  : > "$log"

  ui_status "[${ip}] SSH: connecting…"
  log_msg "probe_host: start ip=$ip"

  local -a SSH_CMD
  if [[ -n "${SSH_KEY_PATH:-}" && -r "${SSH_KEY_PATH:-}" ]]; then
    SSH_CMD=(ssh
      -o LogLevel=ERROR
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=1
      -o PreferredAuthentications=publickey,password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=yes
      -o NumberOfPasswordPrompts=1
      -i "$SSH_KEY_PATH" -tt "$SSH_USERNAME@$ip"
    )
  else
    if ! command -v sshpass >/dev/null 2>&1; then
      ui_status "[${ip}] sshpass missing; cannot password-auth."
      jq -n --arg ip "$ip" '{ip:$ip, login:false, status:"SSHPASS_MISSING"}'
      return 0
    fi
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" ssh
      -o LogLevel=ERROR
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=1
      -o PreferredAuthentications=password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1
      -tt "$SSH_USERNAME@$ip"
    )
  fi

  _run_ssh_script() {
    local timeout_secs="$1"
    if command -v timeout >/dev/null 2>&1; then
      timeout -k 5s "${timeout_secs}s" "${SSH_CMD[@]}"
    else
      "${SSH_CMD[@]}"
    fi
  }

  local tmpout; tmpout="$(mktemp)"
  {
    printf '\r\n\r\n'
    printf 'terminal length 0\r\n'
    printf 'terminal width 511\r\n'
    printf 'show privilege\r\n'
    printf 'exit\r\n'
  } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$tmpout" 2>&1

  tr -d '\r' < "$tmpout" | tee -a "$log" > "$tmpout.clean"
  rm -f "$tmpout"

  local at15=0
  grep -Eq 'Current privilege level is[[:space:]]*15' "$tmpout.clean" && at15=1

  local facts; facts="$(mktemp)"
  if (( at15 == 1 )); then
    ui_status "[${ip}] Priv 15 ok; collecting version/inventory…"
    {
      printf '\r\n\r\n'
      printf 'terminal length 0\r\n'
      printf 'terminal width 511\r\n'
      printf 'show version\r\n'
      printf 'show running-config | include ^hostname\r\n'
      printf 'show inventory\r\n'
      printf 'exit\r\n'
    } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1
  else
    ui_status "[${ip}] Not privileged; attempting enable…"
    {
      printf '\r\n\r\n'
      printf 'terminal length 0\r\n'
      printf 'terminal width 511\r\n'
      printf 'enable\r\n'
      printf '%s\r\n' "$ENABLE_PASSWORD"
      printf 'show privilege\r\n'
      printf 'show version\r\n'
      printf 'show running-config | include ^hostname\r\n'
      printf 'show inventory\r\n'
      printf 'exit\r\n'
    } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1
  fi

  tr -d '\r' < "$facts" | tee -a "$log" > "$facts.clean"
  rm -f "$facts"

  local login_ok=0
  grep -Eq 'Cisco IOS|IOS XE| uptime is |Current privilege level is' "$facts.clean" && login_ok=1

  local hostname version pid sn
  hostname="$(awk '/^hostname[[:space:]]+/{print $2}' "$facts.clean" | tail -n1)"
  [[ -z "$hostname" ]] && hostname="$(grep -m1 -E ' uptime is ' "$facts.clean" | awk '{print $1}')"
  hostname="$(clean_field "${hostname:-}")"

  version="$(grep -m1 -E 'Cisco IOS XE Software, Version[[:space:]]+' "$facts.clean" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  [[ -z "$version" ]] && version="$(grep -m1 -E 'Cisco IOS Software|Version[[:space:]]+[0-9]' "$facts.clean" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  version="$(clean_field "${version:-}")"

  pid="$(grep -m1 -E 'PID:[[:space:]]*[^,]+' "$facts.clean" | sed -E 's/.*PID:[[:space:]]*([^,]+).*/\1/')"
  sn="$(grep -m1 -E 'SN:[[:space:]]*[A-Za-z0-9]+' "$facts.clean" | sed -E 's/.*SN:[[:space:]]*([^,[:space:]]+).*/\1/')"
  pid="$(clean_field "${pid:-}")"
  sn="$(clean_field "${sn:-}")"

  rm -f "$facts.clean" "$tmpout.clean" 2>/dev/null || true

  if (( login_ok )); then
    ui_status "[${ip}] Collected: PID='${pid:-?}' IOS='${version:-?}' Host='${hostname:-?}'"
  else
    ui_status "[${ip}] SSH login failed or no usable output."
  fi

  local req_ios="" req_family="" req_image_type="" req_image_train="" status="UNKNOWN"
  if (( login_ok )) && [[ -n "${pid:-}" ]]; then
    IFS='|' read -r req_family req_ios <<<"$(lookup_required_meta "$pid")"
    req_family="$(clean_field "${req_family:-}")"
    req_ios="$(clean_field "${req_ios:-}")"

    IFS='|' read -r req_image_type req_image_train <<<"$(infer_image_meta "$pid" "$req_family")"
    req_image_type="$(clean_field "${req_image_type:-}")"
    req_image_train="$(clean_field "${req_image_train:-}")"

    if [[ -n "$req_ios" ]]; then
      if [[ -n "$version" ]]; then
        case "$(vercmp "$version" "$req_ios")" in
          -1) status="BELOW_REQUIRED" ;;
           0) status="MEETS_REQUIRED" ;;
           1) status="MEETS_REQUIRED" ;;
        esac
      else
        status="REQUIRED_KNOWN_CURRENT_UNKNOWN"
      fi
    else
      status="MODEL_NOT_IN_MANIFEST"
    fi
  elif (( login_ok )); then
    status="LOGIN_OK_BUT_MISSING_PID"
  else
    status="LOGIN_FAILED"
  fi

  jq -n \
    --arg ip "$ip" \
    --arg host "${hostname:-}" \
    --arg cur "${version:-}" \
    --arg pid "$pid" \
    --arg sn  "$sn" \
    --arg fam "${req_family:-}" \
    --arg it  "${req_image_type:-}" \
    --arg trn "${req_image_train:-}" \
    --arg req "${req_ios:-}" \
    --arg st  "$status" \
    --arg log "$log" \
    '{
      ip: $ip,
      login: ( $st != "LOGIN_FAILED" ),
      hostname: $host,
      current_iosxe: $cur,
      pid: $pid,
      serial: $sn,
      required_family: $fam,
      required_image_type: $it,
      required_image_train: $trn,
      required_min_iosxe: $req,
      status: $st,
      per_host_log: $log
    }'
}

HAS_WAIT_N=0
if help wait >/dev/null 2>&1 && help wait 2>&1 | grep -q -- '-n'; then HAS_WAIT_N=1; fi

run_probe_pool() {
  local hosts=("$@") max="${MAX_SSH_FANOUT}" total="${#hosts[@]}"
  (( total == 0 )) && return 0
  (( max < 1 )) && max=1
  (( max > total )) && max=$total

  ui_status "Probing ${total} device(s) (fanout=${max})…"
  log_msg "run_probe_pool: fanout=$max total=$total"

  local TMPJSON="$RUN_DIR/tmp.results.jsonl"
  : > "$TMPJSON"

  local running=0 done=0
  local -a pids=()

  for ip in "${hosts[@]}"; do
    { probe_host "$ip"; } >> "$TMPJSON" &
    pids+=("$!"); ((running++))
    if (( running >= max )); then
      if (( HAS_WAIT_N )); then
        wait -n || true
      else
        wait "${pids[0]}" || true
        pids=("${pids[@]:1}")
      fi
      ((done++))
      local pct=$(( 20 + 75 * done / total ))
      ui_gauge "$pct" "Collecting facts… ($done / $total)"
      ((running--))
    fi
  done

  while (( running > 0 )); do
    if (( HAS_WAIT_N )); then
      wait -n || true
    else
      wait "${pids[0]}" || true
      pids=("${pids[@]:1}")
    fi
    ((done++))
    local pct=$(( 20 + 75 * done / total ))
    ui_gauge "$pct" "Collecting facts… ($done / $total)"
    ((running--))
  done

  jq -s '.' "$TMPJSON" > "$REPORT_JSON"
  rm -f "$TMPJSON"
}

write_csv_and_summary() {
  {
    echo "ip,hostname,pid,serial,current_iosxe,required_family,required_image_type,required_image_train,required_min_iosxe,status,per_host_log"
    jq -r '.[] | [
      .ip,
      (.hostname//""),
      (.pid//""),
      (.serial//""),
      (.current_iosxe//""),
      (.required_family//""),
      (.required_image_type//""),
      (.required_image_train//""),
      (.required_min_iosxe//""),
      (.status//""),
      (.per_host_log//"")
    ] | @csv' "$REPORT_JSON"
  } >"$REPORT_CSV"

  local total ok below missing loginfail
  total="$(jq 'length' "$REPORT_JSON" 2>/dev/null || echo 0)"
  ok="$(jq '[.[] | select(.status=="MEETS_REQUIRED")] | length' "$REPORT_JSON" 2>/dev/null || echo 0)"
  below="$(jq '[.[] | select(.status=="BELOW_REQUIRED")] | length' "$REPORT_JSON" 2>/dev/null || echo 0)"
  missing="$(jq '[.[] | select(.status=="MODEL_NOT_IN_MANIFEST")] | length' "$REPORT_JSON" 2>/dev/null || echo 0)"
  loginfail="$(jq '[.[] | select(.status=="LOGIN_FAILED")] | length' "$REPORT_JSON" 2>/dev/null || echo 0)"

  local byver_txt downloads_txt
  byver_txt="$(jq -r '
    [ .[]
      | select((.required_min_iosxe//"") != ""
               and (.required_image_type//"") != ""
               and (.required_image_train//"") != ""
               and (.status != "MODEL_NOT_IN_MANIFEST")
               and (.status != "LOGIN_FAILED"))
      | {k:(.required_image_type + "|" + .required_image_train + "|" + .required_min_iosxe), c:1}
    ]
    | group_by(.k)
    | map({key: .[0].k, count: (map(.c)|add)})
    | map(.key as $k | ($k|split("|")) as $p | {img:$p[0], train:$p[1], ver:$p[2], count:.count})
    | sort_by(.img, .ver)
    | map("  " + .img + " (" + .train + ") IOS-XE " + .ver + " : " + (.count|tostring) + " switch(es)")
    | .[]
  ' "$REPORT_JSON" 2>/dev/null || true)"

  downloads_txt="$(jq -r '
    [ .[]
      | select((.required_min_iosxe//"") != ""
               and (.required_image_type//"") != ""
               and (.required_image_train//"") != ""
               and (.status != "MODEL_NOT_IN_MANIFEST")
               and (.status != "LOGIN_FAILED"))
      | {k:(.required_image_type + "|" + .required_image_train + "|" + .required_min_iosxe)}
    ]
    | group_by(.k)
    | map(.[0].k)
    | map(split("|"))
    | map("  - Download " + (.[0]) + " (" + (.[1]) + ") IOS-XE " + (.[2]))
    | .[]
  ' "$REPORT_JSON" 2>/dev/null || true)"

  [[ -z "$byver_txt" ]] && byver_txt="  (none)"
  [[ -z "$downloads_txt" ]] && downloads_txt="  (none)"

  {
    echo "Firmware Requirement Report — $RUN_TAG"
    echo
    echo "Inputs ENV: $ENV_FILE"
    echo "Manifest:   $MANIFEST_JSON"
    echo "Run Dir:    $RUN_DIR"
    echo
    echo "Totals:"
    echo "  Devices scanned:           $total"
    echo "  Meets required min IOS-XE: $ok"
    echo "  Below required min IOS-XE: $below"
    echo "  Model not in manifest:     $missing"
    echo "  Login failed:              $loginfail"
    echo
    echo "IOS-XE downloads required (count by image type + version):"
    echo "$byver_txt"
    echo
    echo "Firmware downloads needed (unique by image type + version):"
    echo "$downloads_txt"
    echo
    echo "Outputs:"
    echo "  JSON: $REPORT_JSON"
    echo "  CSV : $REPORT_CSV"
    echo
    echo "Notes:"
    echo "  - required_* fields come from your local manifest JSON “bible” (cloud_models.json)."
    echo "  - Image mapping heuristic used:"
    echo "      * LITE (cat9k_lite_iosxe) for C9200/C9200L/C9200CX"
    echo "      * UNIVERSAL (cat9k_iosxe) for others (e.g., C9300/C9300L/C9300X)"
    echo "  - This report does not download firmware; it tells you what to fetch from Cisco."
  } >"$SUMMARY_TXT"
}

run_collection() {
  load_env

  mkdir -p "$REPORT_ROOT"
  RUN_TAG="report-$(date -u '+%Y%m%d%H%M%S')"
  RUN_DIR="$REPORT_ROOT/$RUN_TAG"
  mkdir -p "$RUN_DIR"

  # NEW: maintain "latest" symlink like your other run directories
  ln -sfn "$RUN_DIR" "$REPORT_ROOT/latest" 2>/dev/null || true

  DEVLOG_DIR="$RUN_DIR/devlogs"
  mkdir -p "$DEVLOG_DIR"

  DEV_LOG="$RUN_DIR/ui.status"
  STATUS_FILE="$(mktemp)"; : >"$STATUS_FILE"
  PROG_PIPE="$(mktemp -u)"
  PROG_FD=""
  DIALOG_PID=""

  REPORT_JSON="$RUN_DIR/firmware_report.json"
  REPORT_CSV="$RUN_DIR/firmware_report.csv"
  SUMMARY_TXT="$RUN_DIR/firmware_report_summary.txt"
  MANIFEST_INDEX="$RUN_DIR/manifest_index.json"

  DIALOG_AVAILABLE=0
  if [[ "${UI_MODE:-dialog}" == "dialog" ]] && command -v dialog >/dev/null 2>&1; then
    DIALOG_AVAILABLE=1
  fi

  trap 'ui_stop; rm -f "$STATUS_FILE" 2>/dev/null || true' EXIT

  log_msg "=== firmware report start ==="
  log_msg "ENV_FILE=$ENV_FILE"
  log_msg "MANIFEST_JSON=$MANIFEST_JSON"
  log_msg "DISCOVERY_MODE=$DISCOVERY_MODE DISCOVERY_IPS='${DISCOVERY_IPS:-}' DISCOVERY_NETWORKS='${DISCOVERY_NETWORKS:-}'"
  log_msg "SSH_USERNAME=$SSH_USERNAME MAX_SSH_FANOUT=$MAX_SSH_FANOUT SSH_TIMEOUT=$SSH_TIMEOUT UI_MODE=$UI_MODE"

  ui_start
  ui_gauge 1 "Initializing…"

  build_manifest_index
  ui_gauge 10 "Manifest indexed."

  resolve_targets || {
    ui_status "No targets found in env. Aborting."
    ui_gauge 100 "No targets."
    return 1
  }

  local live=()
  if [[ "${TARGET_MODE:-}" == "scan" ]]; then
    mapfile -t live < <(discover_targets)
    if [[ ${#live[@]} -eq 0 ]]; then
      ui_status "No live hosts found during scan."
      jq -n '[]' >"$REPORT_JSON"
      write_csv_and_summary
      ui_gauge 100 "Done (no live hosts)."
      return 0
    fi
  else
    live=("${TARGETS[@]}")
  fi

  ui_status "Hosts to check: ${#live[@]}"
  ui_gauge 12 "Checking SSH port 22…"

  local ssh_hosts=()
  mapfile -t ssh_hosts < <(filter_ssh_open "${live[@]}")
  ui_status "SSH open: ${#ssh_hosts[@]} host(s)."

  if [[ ${#ssh_hosts[@]} -eq 0 ]]; then
    ui_status "No hosts with SSH open."
    jq -n '[]' >"$REPORT_JSON"
    write_csv_and_summary
    ui_gauge 100 "Done (no SSH)."
    return 0
  fi

  ui_gauge 20 "Probing switches…"
  run_probe_pool "${ssh_hosts[@]}"

  ui_gauge 96 "Writing report files…"
  write_csv_and_summary
  ui_gauge 100 "Report complete."

  if (( DIALOG_AVAILABLE )); then
    ui_stop
    post_run_menu
  else
    cat "$SUMMARY_TXT"
    echo
    echo "JSON: $REPORT_JSON"
    echo "CSV : $REPORT_CSV"
  fi

  log_msg "=== firmware report complete ==="
  return 0
}

###############################################################################
# MAIN
###############################################################################
main() {
  prompt_report_setupwizard_flow || exit 1
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  run_collection
}

main "$@"