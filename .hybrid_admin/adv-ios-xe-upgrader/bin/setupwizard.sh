#!/bin/sh
# discovery_prompt.sh — IOS-XE Upgrade-only wizard
# POSIX /bin/sh; dialog UI; writes PROJECT_ROOT/meraki_discovery.env by default
#
# CHANGE REQUEST IMPLEMENTED:
#  - If an existing env file is found, DO NOT say “we found X file”.
#  - Instead: “Pre-existing data was found.”
#  - Display the actual data:
#      • scan range(s) OR ip list
#      • SSH username
#      • SSH password (masked)
#      • ENABLE password (masked)
#  - If user says YES: import ALL fields and continue walking through wizard (as before).
#
# NOTE:
#  - Passwords are displayed masked (never plaintext).
#  - We still pre-fill dialog password boxes when possible; if dialog won’t prefill,
#    user can press OK with blank to KEEP the imported password.

TITLE="CMDS Switch Upgrade — Setup"
BACKTITLE="Meraki Migration Toolkit — IOS-XE Upgrade"

###############################################################################
# Pathing: script lives in bin/, so defaults should land in project root (..)
###############################################################################
SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)}"

ENV_FILE="${ENV_FILE:-$PROJECT_ROOT/meraki_discovery.env}"

FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}"

DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

RUNS_ROOT="${RUNS_ROOT:-$PROJECT_ROOT/runs}"
DISC_SCAN_ROOT="${DISC_SCAN_ROOT:-$RUNS_ROOT/discoveryscans}"
mkdir -p "$DISC_SCAN_ROOT"

log()  { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }
trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need python3; need find; need ssh; need sshpass; need timeout; need expect

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

# ---------- Privilege helpers ----------
get_default_priv_level() {
  host="$1"; user="$2"; pass="$3"
  [ -n "$host" ] && [ -n "$user" ] && [ -n "$pass" ] || { echo ""; return 1; }
  OUT="$(
    { printf 'terminal length 0\n'; printf 'show privilege\n'; printf 'exit\n'; } |
    sshpass -p "$pass" ssh \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o PreferredAuthentications=password,keyboard-interactive \
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 -tt "$user@$host" 2>/dev/null
  )"
  [ "${DEBUG:-0}" = "1" ] && { printf '[PRIVDBG] raw after login:\n%s\n' "$OUT" >>"$DEBUG_LOG"; }
  OUT_CLEAN="$(printf '%s' "$OUT" | tr -d '\r')"
  PL="$(printf '%s\n' "$OUT_CLEAN" | awk 'BEGIN{IGNORECASE=1} /Current privilege level is/ {print $NF; exit}')"
  PL="$(trim "$PL")"
  if [ -z "$PL" ]; then
    PC="$(printf '%s\n' "$OUT_CLEAN" | awk '/[>#][[:space:]]*$/{p=$0} END{print p}' | sed -nE 's/.*([>#])[[:space:]]*$/\1/p')"
    case "$PC" in \#) PL="15";; \>) PL="1";; *) PL="";; esac
  fi
  printf '%s' "$PL"
}

ssh_enable_ok() {
  host="$1"; user="$2"; pass="$3"; enable_pass="$4"
  [ -n "$host" ] && [ -n "$user" ] && [ -n "$pass" ] && [ -n "$enable_pass" ] || return 7
  HOST="$host" USER="$user" PASS="$pass" ENPASS="$enable_pass" \
  DEBUG_FLAG="${DEBUG:-0}" DEBUG_LOG_FILE="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}" \
  ENABLE_PROMPT_TIMEOUT="${ENABLE_PROMPT_TIMEOUT:-2}" ENABLE_VERIFY_TIMEOUT="${ENABLE_VERIFY_TIMEOUT:-4}" \
  expect -f - <<'EXP'
    log_user 0
    if {$env(DEBUG_FLAG) == "1"} { catch {log_file -a $env(DEBUG_LOG_FILE)} }
    set host   $env(HOST); set user $env(USER); set pass $env(PASS); set enpass $env(ENPASS)
    set t_enable [expr {int($env(ENABLE_PROMPT_TIMEOUT))}]; set t_verify [expr {int($env(ENABLE_VERIFY_TIMEOUT))}]
    set t_login 15; set prompt_re {[\r\n][^\r\n]*[>#] ?$}
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
      send -- "enable\r"; set sawpw 0; set timeout $t_enable
      while 1 {
        expect -nocase -re {password:} { set sawpw 1; send -- "$::enpass\r"; exp_continue } \
               -re $prompt_re          { return [list 1 $sawpw] } \
               timeout                 { return [list 0 $sawpw] } eof { return [list -1 $sawpw] }
      }
    }
    lassign [try_enable $t_enable $prompt_re] ok1 sawpw1
    if {$ok1 == 0 && $sawpw1 == 0} {
      lassign [try_enable $t_enable $prompt_re] ok2 sawpw2
      if {$ok2 == 0 && $sawpw2 == 0} { exit 5 }
    } elseif {$ok1 < 0} { exit 4 }
    set timeout $t_verify; send -- "show privilege\r"
    expect { -re {Current privilege level is[[:space:]]*15} { exit 0 }
             -re {Current privilege level is[[:space:]]*[0-9]+} { exit 6 }
             timeout { exit 4 } eof { exit 4 } }
EXP
  rc=$?; [ "${DEBUG:-0}" = "1" ] && printf '[ENABLEDBG] expect rc=%s\n' "$rc" >>"$DEBUG_LOG"
  return $rc
}

# ---------- Utilities ----------
hbytes() { awk 'function hb(b){if(b<1024)printf "%d B",b;else if(b<1048576)printf "%.1f KB",b/1024;else if(b<1073741824)printf "%.1f MB",b/1048576;else printf "%.2f GB",b/1073741824}{hb($1)}' <<EOF
${1:-0}
EOF
}

version_from_name() {
  b="$(basename -- "$1" 2>/dev/null || printf '%s' "$1")"
  v="$(printf '%s\n' "$b" | sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' | head -n1)"
  [ -n "$v" ] || v="$(printf '%s\n' "$b" | sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,3}).*/\1/p' | head -n1)"
  printf '%s\n' "${v:-0}"
}

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

dlg() {
  _tmp="$(mktemp)"
  dialog "$@" 2>"$_tmp"
  _rc=$?
  DOUT=""
  [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $_rc
}

osc8_link() {
  url="$1"
  txt="${2:-$1}"
  printf '\033]8;;%s\033\\%s\033]8;;\033\\\n' "$url" "$txt"
}

print_cockpit_link_and_wait() {
  HOST_SHOW="${HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
  ENC_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$COCKPIT_UPLOAD_DIR")"
  URL_B="https://${HOST_SHOW}:9090/=${HOST_SHOW}/files#/?path=${ENC_PATH}"

  clear
  echo "=== Upload firmware via Cockpit ==="
  echo
  echo "  $URL_B"
  echo
  echo "Clickable:"
  osc8_link "$URL_B" "Open Cockpit Files at /root/IOS-XE_images"
  echo
  echo "Upload to: $COCKPIT_UPLOAD_DIR"
  [ -L "$COCKPIT_UPLOAD_DIR" ] && echo "(symlink to: $FIRMWARE_DIR)"
  echo
  printf "Press Enter when you are done uploading firmware... "
  IFS= read -r _junk
  stty sane 2>/dev/null || true
}

# -------- Box widths --------
TERM_LINES="$(tput lines 2>/dev/null)"; [ -z "$TERM_LINES" ] && TERM_LINES=40
TERM_COLS="$(tput cols 2>/dev/null)";  [ -z "$TERM_COLS" ] && TERM_COLS=140

BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200
W_WIDE="$BOX_W"

W_MODE="${W_MODE:-68}"; [ "$W_MODE" -lt 60 ] && W_MODE=60; [ "$W_MODE" -gt 90 ] && W_MODE=90
W_DEF="$W_MODE"; W_EDIT="$W_MODE"

WELCOME_W="${WELCOME_W:-100}"
[ "$WELCOME_W" -lt 60 ] && WELCOME_W=60
[ "$WELCOME_W" -gt "$BOX_W" ] && WELCOME_W="$BOX_W"

WELCOME_H="${WELCOME_H:-24}"
MAX_WELCOME_H=$((TERM_LINES - 4))
[ "$WELCOME_H" -gt "$MAX_WELCOME_H" ] && WELCOME_H="$MAX_WELCOME_H"
[ "$WELCOME_H" -lt 10 ] && WELCOME_H=10

###############################################################################
# Import support (prefill defaults)
###############################################################################
IMPORT_ENV="/root/.hybrid_admin/meraki_discovery.env"
IMPORTED="0"

# Defaults that may be prefilled
MODE_DEFAULT=""
NETS_PREV_DEFAULT=""
IPS_PREV_DEFAULT=""
SSH_USERNAME_DEFAULT=""
SSH_PASSWORD_DEFAULT=""
SSH_TEST_IP_DEFAULT=""
ENABLE_PASSWORD_DEFAULT=""
HTTP_CLIENT_VLAN_ID_DEFAULT=""
FW_CAT9K_FILE_DEFAULT=""
FW_CAT9K_LITE_FILE_DEFAULT=""

env_to_lines_networks() {
  # input: comma-separated CIDRs
  printf '%s' "$1" | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}
env_to_lines_ips() {
  # input: space-separated IPs
  printf '%s' "$1" | tr ' ' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

safe_source_env() {
  f="$1"
  [ -f "$f" ] || return 1
  [ -r "$f" ] || return 1
  # basic hardening: refuse world-writable files
  if command -v stat >/dev/null 2>&1; then
    perm="$(stat -c %a "$f" 2>/dev/null || echo "")"
    case "$perm" in
      ???) ow="${perm#??}";;
      *) ow="";;
    esac
    # If last digit is 2/3/6/7 => world-writable
    case "$ow" in 2|3|6|7) return 1;; esac
  fi
  # shellcheck disable=SC1090
  . "$f" >/dev/null 2>&1 || return 1
  return 0
}

mask() {
  # show length without leaking; also handles empty
  s="$1"
  n="$(printf '%s' "$s" | wc -c | awk '{print $1}')"
  [ "$n" -gt 0 ] && { i=1; out=""; while [ "$i" -le "$n" ]; do out="${out}*"; i=$((i+1)); done; printf '%s' "$out"; } || printf "(empty)"
}

###############################################################################
# 0) WELCOME — Upgrade-only
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "Welcome — IOS-XE Upgrade Setup" --msgbox \
"Welcome to the CMDS IOS-XE Upgrade wizard.

This will guide you through:
  1) Choose how to provide targets (scan CIDR or manual list)
  2) Provide targets (networks/IPs)
  3) Enter SSH credentials and verify login
  4) Verify your account lands in privileged EXEC (#) by default (required)
  5) Capture and verify the device ENABLE password
  6) Provide VLAN SVI for 'ip http client source-interface Vlan<N>'
  7) Select IOS XE firmware image(s) (or upload via Cockpit)

Have these ready:
  • Target networks/IPs
  • SSH username and password (must land at privilege 15 — prompt '#')
  • ENABLE password (required)
  • VLAN ID (1–4094) for HTTP client source-interface
  • (Optional) Firmware file(s) in ${FIRMWARE_DIR} or upload to ${COCKPIT_UPLOAD_DIR}" \
  "$WELCOME_H" "$WELCOME_W" || { clear; exit 1; }

###############################################################################
# 0a) Import pre-existing config (AFTER welcome)
#     UX:
#       - Do NOT mention path
#       - Say "Pre-existing data was found."
#       - Display actual data one-per-line, INCLUDING passwords (plaintext)
###############################################################################
if [ -f "$IMPORT_ENV" ]; then
  # Gather display-only values without modifying wizard defaults yet
  PRE_MODE=""; PRE_NETS=""; PRE_IPS=""; PRE_USER=""; PRE_PASS=""; PRE_ENPASS=""

  if safe_source_env "$IMPORT_ENV"; then
    PRE_MODE="$(trim "${DISCOVERY_MODE:-}")"
    [ -n "$PRE_MODE" ] || PRE_MODE="$(trim "${MODE:-}")"
    PRE_NETS="$(trim "${DISCOVERY_NETWORKS:-}")"
    PRE_IPS="$(trim "${DISCOVERY_IPS:-}")"
    PRE_USER="$(trim "${SSH_USERNAME:-}")"
    PRE_PASS="${SSH_PASSWORD:-}"
    PRE_ENPASS="${ENABLE_PASSWORD:-}"
  else
    PRE_MODE=""
  fi

  # Build targets text, one per line
  PRE_TARGETS_BLOCK=""
  if [ "$PRE_MODE" = "scan" ] && [ -n "$PRE_NETS" ]; then
    PRE_TARGETS_BLOCK="Scan ranges (CIDR), one per line:
$(env_to_lines_networks "$PRE_NETS")"
  elif [ "$PRE_MODE" = "list" ] && [ -n "$PRE_IPS" ]; then
    PRE_TARGETS_BLOCK="IP list, one per line:
$(env_to_lines_ips "$PRE_IPS")"
  else
    if [ -n "$PRE_NETS" ]; then
      PRE_TARGETS_BLOCK="Scan ranges (CIDR), one per line:
$(env_to_lines_networks "$PRE_NETS")"
    elif [ -n "$PRE_IPS" ]; then
      PRE_TARGETS_BLOCK="IP list, one per line:
$(env_to_lines_ips "$PRE_IPS")"
    else
      PRE_TARGETS_BLOCK="Targets:
(none)"
    fi
  fi

  # One-per-line credential display (PASSWORDS SHOWN PLAINTEXT per request)
  PRE_USER_SHOW="${PRE_USER:-}"
  PRE_PASS_SHOW="${PRE_PASS:-}"
  PRE_ENPASS_SHOW="${PRE_ENPASS:-}"

  [ -n "$PRE_USER_SHOW" ]  || PRE_USER_SHOW="(empty)"
  [ -n "$PRE_PASS_SHOW" ]  || PRE_PASS_SHOW="(empty)"
  [ -n "$PRE_ENPASS_SHOW" ] || PRE_ENPASS_SHOW="(empty)"

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Import existing data?" --yesno \
"Pre-existing data was found.

${PRE_TARGETS_BLOCK}

Switch SSH username (one line):
${PRE_USER_SHOW}

Switch SSH password (PLAINTEXT):
${PRE_PASS_SHOW}

Enable password (PLAINTEXT):
${PRE_ENPASS_SHOW}

Do you want to import this data and continue the wizard?" \
  26 96

  if [ $? -eq 0 ]; then
    # Import for real (and prefill ALL fields)
    if safe_source_env "$IMPORT_ENV"; then
      MODE_DEFAULT="$(trim "${DISCOVERY_MODE:-}")"
      [ -n "$MODE_DEFAULT" ] || MODE_DEFAULT="$(trim "${MODE:-}")"

      SSH_USERNAME_DEFAULT="$(trim "${SSH_USERNAME:-}")"
      SSH_PASSWORD_DEFAULT="${SSH_PASSWORD:-}"
      SSH_TEST_IP_DEFAULT="$(trim "${SSH_TEST_IP:-}")"
      ENABLE_PASSWORD_DEFAULT="${ENABLE_PASSWORD:-}"

      HTTP_CLIENT_VLAN_ID_DEFAULT="$(trim "${HTTP_CLIENT_VLAN_ID:-}")"

      # Targets
      if [ "$MODE_DEFAULT" = "scan" ]; then
        nets="${DISCOVERY_NETWORKS:-}"
        NETS_PREV_DEFAULT="# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored."
        if [ -n "$nets" ]; then
          NETS_PREV_DEFAULT="${NETS_PREV_DEFAULT}
$(env_to_lines_networks "$nets")"
        else
          NETS_PREV_DEFAULT="${NETS_PREV_DEFAULT}
10.0.0.0/24"
        fi
      elif [ "$MODE_DEFAULT" = "list" ]; then
        ips="${DISCOVERY_IPS:-}"
        IPS_PREV_DEFAULT="# Paste or type one IP per line.
# Lines starting with '#' and blank lines are ignored."
        if [ -n "$ips" ]; then
          IPS_PREV_DEFAULT="${IPS_PREV_DEFAULT}
$(env_to_lines_ips "$ips")"
        else
          IPS_PREV_DEFAULT="${IPS_PREV_DEFAULT}
192.168.1.10
192.168.1.11"
        fi
      fi

      # Firmware picks (only used as defaults if still present in FIRMWARE_DIR)
      FW_CAT9K_FILE_DEFAULT="$(trim "${FW_CAT9K_FILE:-}")"
      FW_CAT9K_LITE_FILE_DEFAULT="$(trim "${FW_CAT9K_LITE_FILE:-}")"

      IMPORTED="1"
      log "Imported settings (plaintext display was shown in import UI)"
    else
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Import failed" --msgbox \
"Pre-existing data could not be imported safely.

We will continue without importing." 10 70
    fi
  fi
fi

###############################################################################
# 1) MODE (Provide targets)
###############################################################################
log "Prompt: mode"
DEFAULT_ITEM="${MODE_DEFAULT:-scan}"
dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
    --default-item "$DEFAULT_ITEM" \
    --menu "How do you want to provide targets?" 12 "$W_MODE" 2 \
    scan "Discover live hosts by scanning CIDR networks" \
    list "Use a manual list of IPs (one per line)"
rc=$?; MODE="$(trim "${DOUT:-}")"; log "Mode rc=$rc val='$MODE'"
[ $rc -eq 0 ] || { clear; exit 1; }

###############################################################################
# 2) TARGETS
###############################################################################
DISCOVERY_NETWORKS=""; DISCOVERY_IPS=""
if [ "$MODE" = "scan" ]; then
  NETS_PREV="${NETS_PREV_DEFAULT:-# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored.
10.0.0.0/24}"
  while :; do
    tmpnets="$(mktemp)"; printf '%s\n' "$NETS_PREV" >"$tmpnets"
    dlg --clear --backtitle "$BACKTITLE" --title "Networks to Scan (one per line)" --editbox "$tmpnets" 14 "$W_EDIT"
    rc=$?; NETS_RAW="${DOUT:-}"; rm -f "$tmpnets"; [ $rc -eq 0 ] || { clear; exit 1; }
    NETS_PREV="$NETS_RAW"
    tmpin_nets="$(mktemp)"; printf '%s\n' "$NETS_RAW" >"$tmpin_nets"
    DISCOVERY_NETWORKS=""; invalid_line=""
    while IFS= read -r raw; do
      line="$(trim "$raw")"; [ -z "$line" ] && continue
      case "$line" in \#*) continue;; esac
      if ! is_valid_cidr "$line"; then invalid_line="$line"; break; fi
      [ -z "$DISCOVERY_NETWORKS" ] && DISCOVERY_NETWORKS="$line" || DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS,$line"
    done <"$tmpin_nets"
    rm -f "$tmpin_nets"
    [ -z "$invalid_line" ] || { dlg --title "Invalid Network" --msgbox "Invalid: '$invalid_line'\nUse CIDR like 10.0.0.0/24." 8 "$W_DEF"; continue; }
    [ -n "$DISCOVERY_NETWORKS" ] || { dlg --title "No Networks" --msgbox "Provide at least one valid CIDR." 7 "$W_DEF"; continue; }
    break
  done
else
  IPS_PREV="${IPS_PREV_DEFAULT:-# Paste or type one IP per line.
# Lines starting with '#' and blank lines are ignored.
192.168.1.10
192.168.1.11}"
  while :; do
    tmpips="$(mktemp)"; printf '%s\n' "$IPS_PREV" >"$tmpips"
    dlg --clear --backtitle "$BACKTITLE" --title "Manual IP List (one per line)" --editbox "$tmpips" 16 "$W_EDIT"
    rc=$?; IPS_RAW="${DOUT:-}"; rm -f "$tmpips"; [ $rc -eq 0 ] || { clear; exit 1; }
    IPS_PREV="$IPS_RAW"
    ips_file="$(mktemp)"; printf '%s\n' "$IPS_RAW" >"$ips_file"
    DISCOVERY_IPS=""; invalid_ip=""; SEEN_TMP="$(mktemp)"; : >"$SEEN_TMP"
    while IFS= read -r raw; do
      ip="$(trim "$raw")"; [ -z "$ip" ] && continue
      case "$ip" in \#*) continue;; esac
      if ! is_valid_ip "$ip"; then invalid_ip="$ip"; break; fi
      if ! grep -qx -- "$ip" "$SEEN_TMP" 2>/dev/null; then
        printf '%s\n' "$ip" >>"$SEEN_TMP"
        [ -z "$DISCOVERY_IPS" ] && DISCOVERY_IPS="$ip" || DISCOVERY_IPS="$DISCOVERY_IPS $ip"
      fi
    done <"$ips_file"
    rm -f "$ips_file"
    [ -z "$invalid_ip" ] || { rm -f "$SEEN_TMP"; dlg --title "Invalid IP" --msgbox "Invalid IP: '$invalid_ip'." 7 "$W_DEF"; continue; }
    [ -n "$DISCOVERY_IPS" ] || { rm -f "$SEEN_TMP"; dlg --title "No IPs" --msgbox "Provide at least one valid IP." 7 "$W_DEF"; continue; }
    rm -f "$SEEN_TMP"; break
  done
fi

###############################################################################
# 3) SSH CREDS (require non-empty) + TEST
###############################################################################
SSH_USERNAME="${SSH_USERNAME_DEFAULT:-}"
SSH_PASSWORD="${SSH_PASSWORD_DEFAULT:-}"

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" \
      --inputbox "Enter SSH switch username:" 8 "$W_DEF" "$SSH_USERNAME"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
done

# NOTE: some dialog builds accept an init value for --passwordbox, some don't.
# We pass the init value AND also allow blank to mean "keep imported".
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" --insecure \
      --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
  [ $? -eq 0 ] || { clear; exit 1; }
  entered="$(trim "${DOUT:-}")"
  if [ -n "$entered" ]; then
    SSH_PASSWORD="$entered"
  fi
  [ -n "$SSH_PASSWORD" ] && break
  dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
done

SSH_TEST_IP="${SSH_TEST_IP_DEFAULT:-}"

if [ -n "$DISCOVERY_IPS" ]; then
  MENU_ARGS=""; for ip in $DISCOVERY_IPS; do MENU_ARGS="$MENU_ARGS $ip -"; done
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Test Device" \
      --default-item "${SSH_TEST_IP:-}" \
      --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_TEST_IP="$(trim "${DOUT:-}")"
else
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "Test Device IP" \
        --inputbox "Enter a switch IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
    rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
    val="$(trim "${DOUT:-}")"
    [ -n "$val" ] && is_valid_ip "$val" && SSH_TEST_IP="$val" && break
    dlg --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
  done
fi

while :; do
  dlg --backtitle "$BACKTITLE" --title "Testing SSH" --infobox "Testing SSH login to ${SSH_TEST_IP} as ${SSH_USERNAME}…" 6 "$W_DEF"
  sleep 1
  if ssh_login_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD"; then
    dlg --backtitle "$BACKTITLE" --title "SSH Test" --infobox "Login OK to ${SSH_TEST_IP}." 5 "$W_DEF"; sleep 1; break
  fi
  dlg --backtitle "$BACKTITLE" --title "Login Failed" --yesno "Could not log in. Re-enter username and password?" 8 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }

  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 "$W_DEF" "$SSH_USERNAME"
    [ $? -eq 0 ] || { clear; exit 1; }
    SSH_USERNAME="$(trim "${DOUT:-}")"
    [ -n "$SSH_USERNAME" ] && break
    dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
  done

  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
    [ $? -eq 0 ] || { clear; exit 1; }
    entered="$(trim "${DOUT:-}")"
    if [ -n "$entered" ]; then SSH_PASSWORD="$entered"; fi
    [ -n "$SSH_PASSWORD" ] && break
    dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
  done
done

# Enforce default login privilege 15
DEFAULT_LOGIN_PRIV="$(get_default_priv_level "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD")"
DEFAULT_LOGIN_PRIV="$(trim "$DEFAULT_LOGIN_PRIV")"; PL_NUM="$(printf '%s' "$DEFAULT_LOGIN_PRIV" | tr -cd '0-9')"
DEFAULT_PRIV15_OK="0"
if [ "$PL_NUM" = "15" ]; then
  DEFAULT_PRIV15_OK="1"
else
  dialog --no-shadow --backtitle "$BACKTITLE" --title "Privilege Level Too Low" --msgbox \
"Your account does not land in privileged EXEC by default.

Device: ${SSH_TEST_IP}
Detected default privilege level: ${DEFAULT_LOGIN_PRIV:-unknown}

Upgrade automation requires a user that logs in at privilege 15 (prompt ends with #)
without entering 'enable' first.

Please use an account with privilege 15 and re-run the setup." 16 "$W_DEF"
  clear; exit 1
fi

###############################################################################
# 3a) ENABLE PASSWORD (required) + verify
###############################################################################
ENABLE_PASSWORD="${ENABLE_PASSWORD_DEFAULT:-}"
ENABLE_TEST_OK="0"
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Enable Password (required)" \
      --insecure --passwordbox \
"Enter the device's ENABLE password.
We'll verify it now.

(If imported, you can press OK to keep it.)" \
      12 "$W_DEF" "$ENABLE_PASSWORD"
  rc=$?; [ $rc -ne 0 ] && { clear; exit 1; }

  entered="$(trim "${DOUT:-}")"
  if [ -n "$entered" ]; then ENABLE_PASSWORD="$entered"; fi

  if [ -z "$ENABLE_PASSWORD" ]; then
    dlg --no-shadow --backtitle "$BACKTITLE" --title "Missing Enable Password" \
        --msgbox "The ENABLE password is required.\n\nPlease enter a non-empty password." 8 "$W_DEF"
    continue
  fi

  dlg --backtitle "$BACKTITLE" --title "Testing Enable" \
      --infobox "Verifying enable password on ${SSH_TEST_IP}…" 6 "$W_DEF"

  ssh_enable_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD" "$ENABLE_PASSWORD"
  rc=$?

  if [ $rc -eq 0 ] || [ $rc -eq 5 ]; then
    ENABLE_TEST_OK="1"
    dlg --backtitle "$BACKTITLE" --title "Enable Test" \
        --msgbox "Enable password verified and stored." 7 "$W_DEF"
    break
  fi

  reason="Enable password failed."
  [ $rc -eq 6 ] && reason="Enable password was rejected by the device."

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Enable Test Failed" --yesno \
"${reason}

Do you want to try entering the ENABLE password again?" 10 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }
done

###############################################################################
# 3b) VLAN SVI — MANDATORY
###############################################################################
HTTP_CLIENT_VLAN_ID="${HTTP_CLIENT_VLAN_ID_DEFAULT:-}"
HTTP_CLIENT_SOURCE_IFACE=""
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "HTTP Client Source SVI (required)" \
      --inputbox "Enter the VLAN SVI number to use with:

  ip http client source-interface Vlan<N>

Examples: 10, 20, 4094" 11 "$W_DEF" "$HTTP_CLIENT_VLAN_ID"
  rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
  val="$(trim "${DOUT:-}")"
  python3 - "$val" <<'PY'
import sys
s=sys.argv[1]; ok = s.isdigit() and 1 <= int(s) <= 4094
sys.exit(0 if ok else 1)
PY
  if [ $? -eq 0 ]; then
    HTTP_CLIENT_VLAN_ID="$val"
    HTTP_CLIENT_SOURCE_IFACE="Vlan${HTTP_CLIENT_VLAN_ID}"
    break
  fi
  dlg --msgbox "Invalid VLAN ID: '${val:-<empty>}'\nEnter a number 1–4094." 9 "$W_DEF"
done

###############################################################################
# 4) FIRMWARE PICK
###############################################################################
mkdir -p "$FIRMWARE_DIR"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%T@|%s|%f\n' 2>/dev/null
}

build_sorted_menu_file() {
  fam="$1"; infile="$2"; tmp="$(mktemp)"; : >"$tmp"
  while IFS='|' read -r _mt _sz nm; do
    [ -n "$nm" ] || continue
    lower="$(printf '%s' "$nm" | tr '[:upper:]' '[:lower:]')"
    case "$fam" in
      universal) echo "$lower" | grep -Eq '^cat9k_iosxe.*\.bin$'      || continue ;;
      lite)      echo "$lower" | grep -Eq '^cat9k_lite_iosxe.*\.bin$' || continue ;;
    esac
    ver="$(version_from_name "$nm")"
    printf '%s|%s\n' "$ver" "$nm" >>"$tmp"
  done <"$infile"
  sort -t'|' -k1,1V -k2,2 "$tmp" | awk -F'|' '{print $2"\n-"}'
  rm -f "$tmp"
}

resolve_meta() {
  name="$1"; infile="$2"
  while IFS='|' read -r _mt _sz _nm; do
    [ "$_nm" = "$name" ] && { printf '%s|%s\n' "$_sz" "$FIRMWARE_DIR/$_nm"; return; }
  done <"$infile"
  printf '|\n'
}

FW_CAT9K_FILE=""; FW_CAT9K_LITE_FILE=""
FW_CAT9K_PATH=""; FW_CAT9K_SIZE_BYTES=""; FW_CAT9K_SIZE_H=""; FW_CAT9K_VERSION=""
FW_CAT9K_LITE_PATH=""; FW_CAT9K_LITE_SIZE_BYTES=""; FW_CAT9K_LITE_SIZE_H=""; FW_CAT9K_LITE_VERSION=""

# If imported defaults exist but files are missing now, drop the default
[ -n "$FW_CAT9K_FILE_DEFAULT" ] && [ ! -f "$FIRMWARE_DIR/$FW_CAT9K_FILE_DEFAULT" ] && FW_CAT9K_FILE_DEFAULT=""
[ -n "$FW_CAT9K_LITE_FILE_DEFAULT" ] && [ ! -f "$FIRMWARE_DIR/$FW_CAT9K_LITE_FILE_DEFAULT" ] && FW_CAT9K_LITE_FILE_DEFAULT=""

while :; do
  tmp_lines="$(mktemp)"
  list_files | sort -nr >"$tmp_lines"

  U_FILE="$(mktemp)"; build_sorted_menu_file universal "$tmp_lines" >"$U_FILE"
  L_FILE="$(mktemp)"; build_sorted_menu_file lite      "$tmp_lines" >"$L_FILE"
  U_ARGS="$(tr '\n' ' ' <"$U_FILE")"
  L_ARGS="$(tr '\n' ' ' <"$L_FILE")"

  if [ ! -s "$tmp_lines" ]; then
    CH=$(dialog --clear --backtitle "$BACKTITLE" --title "Firmware Upload Needed" \
        --menu "No firmware images found in:\n  $FIRMWARE_DIR\n\nUpload in Cockpit, then Rescan." 14 "$W_DEF" 6 \
        1 "Show clickable Cockpit link (opens /root/IOS-XE_images)" \
        2 "Rescan directory" \
        0 "Exit setup" 3>&1 1>&2 2>&3) || { clear; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; exit 1; }
    case "$CH" in
      1) print_cockpit_link_and_wait; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; continue ;;
      2) rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; continue ;;
      0) clear; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; exit 1 ;;
    esac
  fi

  if [ -s "$U_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
        --default-item "${FW_CAT9K_FILE_DEFAULT:-}" \
        --menu "Choose a Cat9k image (sorted by version asc):" 12 "$((W_DEF + 10))" 6 $U_ARGS
    [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
  fi

  if [ -s "$L_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
        --default-item "${FW_CAT9K_LITE_FILE_DEFAULT:-}" \
        --menu "Choose a Cat9k-Lite image (sorted by version asc):" 12 "$((W_DEF + 10))" 6 $L_ARGS
    [ $? -eq 0 ] && FW_CAT9K_LITE_FILE="${DOUT:-}"
  fi

  if [ -n "$FW_CAT9K_FILE" ]; then
    out="$(resolve_meta "$FW_CAT9K_FILE" "$tmp_lines")"
    FW_CAT9K_SIZE_BYTES="$(printf '%s' "$out" | cut -d'|' -f1)"
    FW_CAT9K_PATH="$(printf '%s' "$out" | cut -d'|' -f2)"
    FW_CAT9K_SIZE_H="$(hbytes "${FW_CAT9K_SIZE_BYTES:-0}")"
    FW_CAT9K_VERSION="$(version_from_name "$FW_CAT9K_FILE")"
  fi

  if [ -n "$FW_CAT9K_LITE_FILE" ]; then
    out="$(resolve_meta "$FW_CAT9K_LITE_FILE" "$tmp_lines")"
    FW_CAT9K_LITE_SIZE_BYTES="$(printf '%s' "$out" | cut -d'|' -f1)"
    FW_CAT9K_LITE_PATH="$(printf '%s' "$out" | cut -d'|' -f2)"
    FW_CAT9K_LITE_SIZE_H="$(hbytes "${FW_CAT9K_LITE_SIZE_BYTES:-0}")"
    FW_CAT9K_LITE_VERSION="$(version_from_name "$FW_CAT9K_LITE_FILE")"
  fi

  rm -f "$tmp_lines" "$U_FILE" "$L_FILE"
  break
done

###############################################################################
# 5) RUN DIR
###############################################################################
DISCOVERY_RUN_ID="${DISCOVERY_RUN_ID:-scan-$(date -u +%Y%m%d%H%M%S)}"
DISCOVERY_RUN_DIR="${DISCOVERY_RUN_DIR:-$DISC_SCAN_ROOT/$DISCOVERY_RUN_ID}"
mkdir -p "$DISCOVERY_RUN_DIR" "$DISCOVERY_RUN_DIR/devlogs"
ln -sfn "$DISCOVERY_RUN_DIR" "$DISC_SCAN_ROOT/latest"

###############################################################################
# 6) EXPORT + PERSIST
###############################################################################
export PROJECT_ROOT RUNS_ROOT
export DISCOVERY_MODE="$MODE" DISCOVERY_NETWORKS DISCOVERY_IPS
export SSH_USERNAME SSH_PASSWORD SSH_TEST_IP
export DEFAULT_PRIV15_OK DEFAULT_LOGIN_PRIV
export ENABLE_PASSWORD ENABLE_TEST_OK
export HTTP_CLIENT_VLAN_ID HTTP_CLIENT_SOURCE_IFACE
export FW_CAT9K_FILE FW_CAT9K_PATH FW_CAT9K_SIZE_BYTES FW_CAT9K_SIZE_H FW_CAT9K_VERSION
export FW_CAT9K_LITE_FILE FW_CAT9K_LITE_PATH FW_CAT9K_LITE_SIZE_BYTES FW_CAT9K_LITE_SIZE_H FW_CAT9K_LITE_VERSION
export DISC_SCAN_ROOT DISCOVERY_RUN_ID DISCOVERY_RUN_DIR

{
  echo "# Generated $(date -u '+%F %T') UTC"
  printf 'export PROJECT_ROOT=%q\n' "$PROJECT_ROOT"
  printf 'export RUNS_ROOT=%q\n' "$RUNS_ROOT"
  printf 'export DISCOVERY_MODE=%q\n' "$DISCOVERY_MODE"
  printf 'export DISCOVERY_NETWORKS=%q\n' "$DISCOVERY_NETWORKS"
  printf 'export DISCOVERY_IPS=%q\n' "$DISCOVERY_IPS"
  printf 'export SSH_USERNAME=%q\n' "$SSH_USERNAME"
  printf 'export SSH_PASSWORD=%q\n' "$SSH_PASSWORD"
  printf 'export SSH_TEST_IP=%q\n' "$SSH_TEST_IP"
  printf 'export DEFAULT_PRIV15_OK=%q\n' "$DEFAULT_PRIV15_OK"
  printf 'export DEFAULT_LOGIN_PRIV=%q\n' "$DEFAULT_LOGIN_PRIV"
  printf 'export ENABLE_PASSWORD=%q\n' "$ENABLE_PASSWORD"
  printf 'export ENABLE_TEST_OK=%q\n' "$ENABLE_TEST_OK"
  printf 'export HTTP_CLIENT_VLAN_ID=%q\n' "$HTTP_CLIENT_VLAN_ID"
  printf 'export HTTP_CLIENT_SOURCE_IFACE=%q\n' "$HTTP_CLIENT_SOURCE_IFACE"
  printf 'export DISC_SCAN_ROOT=%q\n' "$DISC_SCAN_ROOT"
  printf 'export DISCOVERY_RUN_ID=%q\n' "$DISCOVERY_RUN_ID"
  printf 'export DISCOVERY_RUN_DIR=%q\n' "$DISCOVERY_RUN_DIR"
  [ -n "$FW_CAT9K_FILE" ] && {
    printf 'export FW_CAT9K_FILE=%q\n' "$FW_CAT9K_FILE"
    printf 'export FW_CAT9K_PATH=%q\n' "$FW_CAT9K_PATH"
    printf 'export FW_CAT9K_SIZE_BYTES=%q\n' "$FW_CAT9K_SIZE_BYTES"
    printf 'export FW_CAT9K_SIZE_H=%q\n' "$FW_CAT9K_SIZE_H"
    printf 'export FW_CAT9K_VERSION=%q\n' "$FW_CAT9K_VERSION"
  }
  [ -n "$FW_CAT9K_LITE_FILE" ] && {
    printf 'export FW_CAT9K_LITE_FILE=%q\n' "$FW_CAT9K_LITE_FILE"
    printf 'export FW_CAT9K_LITE_PATH=%q\n' "$FW_CAT9K_LITE_PATH"
    printf 'export FW_CAT9K_LITE_SIZE_BYTES=%q\n' "$FW_CAT9K_LITE_SIZE_BYTES"
    printf 'export FW_CAT9K_LITE_SIZE_H=%q\n' "$FW_CAT9K_LITE_SIZE_H"
    printf 'export FW_CAT9K_LITE_VERSION=%q\n' "$FW_CAT9K_LITE_VERSION"
  }
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

###############################################################################
# 7) SUMMARY
###############################################################################
PW_MASK="$(mask "$SSH_PASSWORD")"
SVI_SUMMARY="$(printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID")"
DEFPRIV_SUMMARY="$( [ "$DEFAULT_PRIV15_OK" = "1" ] && echo "# (priv 15)" || echo "> (user exec)" )"

summary="Wizard Results:

Project root:
  ${PROJECT_ROOT}

Env file:
  ${ENV_FILE}

Runs:
  ${DISCOVERY_RUN_DIR}

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Test Device IP: ${SSH_TEST_IP}
Default Login Privilege: ${DEFAULT_LOGIN_PRIV} (${DEFPRIV_SUMMARY})
Enable Password: provided (verified)

HTTP client source-interface (required):
  ${SVI_SUMMARY}
"

if [ -n "$FW_CAT9K_FILE" ]; then
  summary="${summary}
Cat9k (universal):
  ${FW_CAT9K_FILE}  [$(hbytes "${FW_CAT9K_SIZE_BYTES:-0}")${FW_CAT9K_VERSION:+, v${FW_CAT9K_VERSION}}]
  ${FW_CAT9K_PATH}
"
fi
if [ -n "$FW_CAT9K_LITE_FILE" ]; then
  summary="${summary}
Cat9k-Lite (9200):
  ${FW_CAT9K_LITE_FILE}  [$(hbytes "${FW_CAT9K_LITE_SIZE_BYTES:-0}")${FW_CAT9K_LITE_VERSION:+, v${FW_CAT9K_LITE_VERSION}}]
  ${FW_CAT9K_LITE_PATH}
"
fi

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 27 90
clear