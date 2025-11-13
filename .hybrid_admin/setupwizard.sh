#!/bin/sh
# discovery_prompt.sh — targets + SSH creds (+ login test) + Meraki API key
# + DNS (required; fallbacks) + NTP (at least one) fallbacks + mandatory HTTP client SVI + firmware selection
# + Enable password (required) + on-box verification to privilege 15
# POSIX /bin/sh; dialog UI; writes ./meraki_discovery.env

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"
ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"        # scanner reads here
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}" # Cockpit opens here (symlink to FIRMWARE_DIR)
DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

# Base paths for discovery scan run logging (runs/discoveryscans)
SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
RUNS_ROOT="${RUNS_ROOT:-$SCRIPT_DIR/runs}"
DISC_SCAN_ROOT="${DISC_SCAN_ROOT:-$RUNS_ROOT/discoveryscans}"

# Ensure discovery runs root exists so menus / scanners can rely on it
mkdir -p "$DISC_SCAN_ROOT"

log()      { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }
_dnslog()  { [ "${DEBUG:-0}" = "1" ] && printf '[DNSDBG] %s\n' "$*" >>"$DEBUG_LOG"; }
trim()     { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

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

# Compare two IOS XE version strings, ignoring any trailing letter suffix.
# Returns 0 (true) if first arg < second arg, 1 otherwise.
version_is_older() {
  python3 - "$1" "$2" <<'PY'
import sys, re

def norm(v):
    v = v.strip()
    v = re.sub(r'[^0-9.]', '', v)
    if not v:
        v = "0"
    parts = [int(p) for p in v.split('.') if p != ""]
    while len(parts) < 3:
        parts.append(0)
    return parts[:3]

have = norm(sys.argv[1])
req  = norm(sys.argv[2])

sys.exit(0 if have < req else 1)
PY
}

HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

# dialog wrapper + link helper
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

# ---------- DNS helpers (defined BEFORE use) ----------
dns_server_works() {
  srv="$1"; [ -n "$srv" ] || return 1
  ans="$(dig +time=3 +tries=1 +short google.com @"$srv" 2>/dev/null | awk 'NF{print; exit}')"
  [ -n "$ans" ]
}

validate_dns_servers() {
  command -v dig >/dev/null 2>&1 || { dialog --msgbox "Missing: dig (bind-utils). Install it and re-run." 7 70; return 1; }
  DNS_PRIMARY="${DNS_PRIMARY:-}"; DNS_SECONDARY="${DNS_SECONDARY:-}"

  _prompt_ip() {
    while :; do
      dlg --clear --backtitle "$BACKTITLE" --title "$1" --inputbox "Enter a valid DNS server IP address:" 8 "$W_DEF" "$2"
      rc=$?; _dnslog "inputbox rc=$rc title='$1'"
      [ $rc -eq 0 ] || { clear; return 1; }
      val="$(trim "${DOUT:-}")"
      if [ -n "$val" ] && is_valid_ip "$val"; then OUT_IP="$val"; return 0; fi
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
    done
  }

  _check_one_dns() {
    srv="$1"
    out="$(dig +time=3 +tries=1 +noall +answer google.com @"$srv" 2>&1)"
    echo "$out" | awk '/^[^;].*[[:space:]](A|AAAA)[[:space:]][0-9a-fA-F:.]+$/ {print $NF; ok=1; exit} END{exit ok?0:1}'
  }

  while :; do
    OUT_IP=""; _prompt_ip "DNS — Primary (required)"   "$DNS_PRIMARY"   || { _dnslog "primary prompt: cancel"; return 1; }
    DNS_PRIMARY="$OUT_IP"
    OUT_IP=""; _prompt_ip "DNS — Secondary (required)" "$DNS_SECONDARY" || { _dnslog "secondary prompt: cancel"; return 1; }
    DNS_SECONDARY="$OUT_IP"

    dlg --backtitle "$BACKTITLE" --title "Testing DNS" --infobox "Resolving google.com via:\n  Primary  : $DNS_PRIMARY\n  Secondary: $DNS_SECONDARY" 7 "$W_DEF"
    sleep 0.6

    P_ANS="$(_check_one_dns "$DNS_PRIMARY")"; P_OK=$?
    S_ANS="$(_check_one_dns "$DNS_SECONDARY")"; S_OK=$?
    _dnslog "dig primary ok=$P_OK ans='${P_ANS:-}' secondary ok=$S_OK ans='${S_ANS:-}'"

    if [ $P_OK -eq 0 ] && [ $S_OK -eq 0 ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Validation" --msgbox \
"google.com resolved successfully:

  Primary   ($DNS_PRIMARY): ${P_ANS}
  Secondary ($DNS_SECONDARY): ${S_ANS}

Note: These are *fallback* resolvers. If switch does not have any" 13 "$W_DEF"
      export DNS_PRIMARY DNS_SECONDARY
      return 0
    fi

    RESULT_MSG=$(cat <<EOF
DNS test results for google.com:

  Primary   ($DNS_PRIMARY): ${P_ANS:-FAILED}
  Secondary ($DNS_SECONDARY): ${S_ANS:-FAILED}

Re-enter the DNS servers?
  • Yes  = re-enter both and test again
  • No   = keep these values and continue (still used as fallbacks)
  • Esc  = abort
EOF
)
    dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Check Failed" --yesno "$RESULT_MSG" 16 "$W_DEF"
    YN_RC=$?; _dnslog "yesno rc=$YN_RC (0=yes, 1=no, 255=esc)"
    case "$YN_RC" in
      0)  continue ;;
      1)  export DNS_PRIMARY DNS_SECONDARY; return 0 ;;
      255) clear; return 1 ;;
      *)  continue ;;
    esac
  done
}

# -------- Box widths --------
TERM_LINES="$(tput lines 2>/dev/null)"; [ -z "$TERM_LINES" ] && TERM_LINES=40
TERM_COLS="$(tput cols 2>/dev/null)";  [ -z "$TERM_COLS" ] && TERM_COLS=140

BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200
W_WIDE="$BOX_W"

W_MODE="${W_MODE:-68}"; [ "$W_MODE" -lt 60 ] && W_MODE=60; [ "$W_MODE" -gt 90 ] && W_MODE=90
W_DEF="$W_MODE"; W_EDIT="$W_MODE"

# Dedicated size for the big welcome screen (taller, not as wide)
WELCOME_W="${WELCOME_W:-100}"          # manual override width
[ "$WELCOME_W" -lt 60 ] && WELCOME_W=60
[ "$WELCOME_W" -gt "$BOX_W" ] && WELCOME_W="$BOX_W"

WELCOME_H="${WELCOME_H:-30}"           # manual override height
MAX_WELCOME_H=$((TERM_LINES - 4))
[ "$WELCOME_H" -gt "$MAX_WELCOME_H" ] && WELCOME_H="$MAX_WELCOME_H"
[ "$WELCOME_H" -lt 10 ] && WELCOME_H=10

###############################################################################
# 0) WELCOME — overview + what you’ll need
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "Welcome — Discovery & Preflight" --msgbox \
"Welcome to the CMDS Discovery & Preflight wizard.

This will guide you through:
  1) Choose how to provide targets (scan CIDR or manual list)
  2) Provide targets (networks/IPs)
  3) Enter SSH credentials and verify login
  4) Verify your account lands in privileged EXEC (#) by default (required)
  5) Capture and verify the device ENABLE password
  6) Paste your Meraki Dashboard API key
  7) Enter DNS fallback resolvers (2) and validate reachability
  8) Enter NTP fallback servers (>=1) and validate reachability
  9) Provide VLAN SVI for 'ip http client source-interface Vlan<N>'
 10) Select IOS XE firmware image(s) (or upload via Cockpit)
 11) Set the minimum IOS XE version required for hybrid onboarding
 12) Save all choices to ${ENV_FILE} and show a summary

Have these ready:
  • Target networks/IPs
  • SSH username and password (must land at privilege 15 — prompt '#')
  • ENABLE password (required; used later for Meraki claim)
  • Meraki Dashboard API key
  • Two DNS server IPs (fallbacks)
  • At least one NTP server (hostname or IP)
  • VLAN ID (1–4094) for HTTP client source-interface (for IOS-XE image downloading)
  • (Optional) Firmware file(s) in ${FIRMWARE_DIR} or upload to ${COCKPIT_UPLOAD_DIR}" \
  "$WELCOME_H" "$WELCOME_W"

###############################################################################
# 1) MODE (Provide targets)
###############################################################################
log "Prompt: mode"
dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
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
  NETS_PREV="# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored.
10.0.0.0/24"
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
  IPS_PREV="# Paste or type one IP per line.
# Lines starting with '#' and blank lines are ignored.
192.168.1.10
192.168.1.11"
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
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH switch username:" 8 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
done
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" --insecure --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_PASSWORD="$(trim "${DOUT:-}")"
  [ -n "$SSH_PASSWORD" ] && break
  dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
done

SSH_TEST_IP=""
if [ -n "$DISCOVERY_IPS" ]; then
  MENU_ARGS=""; for ip in $DISCOVERY_IPS; do MENU_ARGS="$MENU_ARGS $ip -"; done
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Test Device" --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_TEST_IP="$(trim "${DOUT:-}")"
else
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "Test Device IP" --inputbox "Enter a switch IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
    rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
    val="$(trim "${DOUT:-}")"
    [ -n "$val" ] && is_valid_ip "$val" && SSH_TEST_IP="$val" && break
    dlg --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
  done
fi

# Basic SSH reachability
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
    dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF"
    [ $? -eq 0 ] || { clear; exit 1; }
    SSH_PASSWORD="$(trim "${DOUT:-}")"
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

Hybrid onboarding requires a user that logs in at privilege 15 (prompt ends with #)
without entering 'enable' first.

Please use an account with privilege 15 and re-run the setup." 16 "$W_DEF"
  clear; exit 1
fi

###############################################################################
# 3a) ENABLE PASSWORD (required) + verify
###############################################################################
ENABLE_PASSWORD=""; ENABLE_TEST_OK="0"
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Enable Password (required)" \
      --insecure --passwordbox \
"Enter the device's ENABLE password.
We'll verify it now so it can be sent during claim process." \
      10 "$W_DEF"
  rc=$?; [ $rc -ne 0 ] && { clear; exit 1; }

  ENABLE_PASSWORD="$(trim "${DOUT:-}")"

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
        --msgbox "Enable password verified and stored for later claim." 7 "$W_DEF"
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
# 3b) MERAKI API KEY
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" \
      --title "Meraki API Key" \
      --insecure --passwordbox \
"Paste your Meraki Dashboard API key:" \
      8 "$W_DEF"
  rc=$?; [ $rc -eq 1 ] && { clear; exit 1; }
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 "$W_DEF"; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 "$W_DEF"; [ $? -eq 0 ] && break
done
###############################################################################
# 3c) DNS — REQUIRED (validated with dig; fallbacks)
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "DNS Servers" --msgbox \
"Enter two DNS server IP addresses.

We won't overwrite working DNS on switches.

These DNS servers are used only as fallbacks:
  • When a switch has no DNS configured
  • For our own lookups during setup." 12 "$W_DEF"

if ! validate_dns_servers; then clear; exit 1; fi

###############################################################################
# 3c.1) NTP — validate (Primary required; Secondary optional)
###############################################################################
probe_ntp_host() {
  local host="${1:-}"; [ -n "$host" ] || return 1
  if command -v ntpdate >/dev/null 2>&1; then timeout 8s ntpdate -u -q -t 4 "$host" >/dev/null 2>&1; return $?; fi
  if command -v chronyd >/dev/null 2>&1; then
    local kind="server"; case "$host" in pool.*|*.pool.ntp.*|*.pool.ntp.org) kind="pool";; esac
    timeout 10s chronyd -Q -t 4 "$kind $host iburst maxsamples 1" >/dev/null 2>&1; return $?
  fi
  if command -v sntp >/dev/null 2>&1; then timeout 8s sntp -r "$host" >/dev/null 2>&1; return $?; fi
  return 1
}

dlg --clear --backtitle "$BACKTITLE" --title "NTP Servers" --msgbox \
"Enter at least one NTP server (hostname or IP).

We won't overwrite working NTP on switches.

These NTP servers are used only as fallbacks:
  • When a switch has no NTP configured
  • For our own time checks during setup." 12 "$W_DEF"

NTP_PRIMARY=""; NTP_SECONDARY=""
while :; do
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "NTP — Primary (required)" --inputbox "Primary NTP server (hostname or IP):" 8 "$W_DEF" "$NTP_PRIMARY"
    rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
    val="$(trim "${DOUT:-}")"; [ -n "$val" ] && NTP_PRIMARY="$val" && break
    dlg --msgbox "Primary NTP cannot be empty." 7 "$W_DEF"
  done
  dlg --clear --backtitle "$BACKTITLE" --title "NTP — Secondary (optional)" --inputbox "Secondary NTP server (hostname or IP, optional):" 8 "$W_DEF" "$NTP_SECONDARY"
  rc=$?; [ $rc -ne 0 ] && NTP_SECONDARY="" || NTP_SECONDARY="$(trim "${DOUT:-}")"
  dlg --backtitle "$BACKTITLE" --title "NTP Validation" --infobox "Checking:\n  Primary  : ${NTP_PRIMARY}\n  Secondary: ${NTP_SECONDARY:-<none>}" 7 "$W_DEF"
  sleep 0.5
  P_OK=0; S_OK=2
  if probe_ntp_host "$NTP_PRIMARY"; then P_OK=1; fi
  if [ -n "$NTP_SECONDARY" ]; then S_OK=0; if probe_ntp_host "$NTP_SECONDARY"; then S_OK=1; fi; fi
  if [ $P_OK -eq 1 ] && { [ $S_OK -eq 1 ] || [ $S_OK -eq 2 ]; }; then
    dlg --clear --backtitle "$BACKTITLE" --title "NTP Validation" --msgbox \
"Validated NTP server(s):
  Primary  (${NTP_PRIMARY}): OK
  Secondary(${NTP_SECONDARY:-<none>}): $( [ $S_OK -eq 1 ] && echo OK || echo skipped )" 11 "$W_DEF"
    break
  fi
  msg="NTP check results:
  Primary  (${NTP_PRIMARY}): $( [ $P_OK -eq 1 ] && echo OK || echo FAILED )
  Secondary(${NTP_SECONDARY:-<none>}): "
  if   [ $S_OK -eq 1 ]; then msg="${msg}OK"
  elif [ $S_OK -eq 0 ]; then msg="${msg}FAILED"
  else                     msg="${msg}(skipped)"; fi
  if [ $P_OK -eq 0 ] && { [ $S_OK -eq 0 ] || [ $S_OK -eq 2 ]; }; then
    dlg --backtitle "$BACKTITLE" --title "NTP Validation" --msgbox "Neither NTP server responded. Please re-enter at least one working server." 9 "$W_DEF"
    continue
  fi
  CH=$(dialog --no-shadow --backtitle "$BACKTITLE" --title "NTP Validation" \
    --menu "${msg}\n\nDo you want to re-enter the NTP servers or proceed with the current values?" \
    13 "$W_DEF" 6 \
    1 "Re-enter NTP servers" \
    2 "Proceed with these values" \
    3>&1 1>&2 2>&3) || CH=1

  [ "$CH" = "2" ] && break
done

###############################################################################
# 3d) VLAN SVI — MANDATORY
###############################################################################
HTTP_CLIENT_VLAN_ID=""; HTTP_CLIENT_SOURCE_IFACE=""
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "HTTP Client Source SVI (required)" \
      --inputbox "Enter the VLAN SVI number to use with:

For downloading IOS-XE images (your MGMT interface):
  ip http client source-interface Vlan<N>

Examples: 10, 20, 4094" 12 "$W_DEF" "$HTTP_CLIENT_VLAN_ID"
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
# 4) FIRMWARE PICK (WIDE) — numerically sorted by version (ascending)
###############################################################################
mkdir -p "$FIRMWARE_DIR"; command -v restorecon >/dev/null 2>&0 && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

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
  # Version sort ascending
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

# Selected firmware + metadata
FW_CAT9K_FILE=""; FW_CAT9K_LITE_FILE=""
FW_CAT9K_PATH=""; FW_CAT9K_SIZE_BYTES=""; FW_CAT9K_SIZE_H=""; FW_CAT9K_VERSION=""
FW_CAT9K_LITE_PATH=""; FW_CAT9K_LITE_SIZE_BYTES=""; FW_CAT9K_LITE_SIZE_H=""; FW_CAT9K_LITE_VERSION=""

# Loop here so Cockpit upload / rescan stays in the firmware step
while :; do
  tmp_lines="$(mktemp)"
  list_files | sort -nr >"$tmp_lines"

  U_FILE="$(mktemp)"; build_sorted_menu_file universal "$tmp_lines" >"$U_FILE"
  L_FILE="$(mktemp)"; build_sorted_menu_file lite      "$tmp_lines" >"$L_FILE"
  U_ARGS="$(tr '\n' ' ' <"$U_FILE")"
  L_ARGS="$(tr '\n' ' ' <"$L_FILE")"

  if [ ! -s "$tmp_lines" ]; then
    CH=$(dialog --clear --backtitle "$BACKTITLE" --title "Firmware Upload Needed" \
        --menu "No firmware images were found in:\n  $FIRMWARE_DIR\n\nUpload in Cockpit, then choose Rescan." 14 "$W_DEF" 6 \
        1 "Show clickable Cockpit link (opens /root/IOS-XE_images)" \
        2 "Rescan directory" \
        0 "Exit setup" 3>&1 1>&2 2>&3) || { clear; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; exit 1; }
    case "$CH" in
      1) print_cockpit_link_and_wait; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; continue ;;
      2) rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; continue ;;
      0) clear; rm -f "$tmp_lines" "$U_FILE" "$L_FILE"; exit 1 ;;
    esac
  fi

    # Cat9k (universal) menu
  if [ -s "$U_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
        --menu "Choose a Cat9k (9300/9400/9500/9600) image (sorted by version asc):" \
        12 "$((W_DEF + 10))" 4 $U_ARGS
    [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
  fi

  # Cat9k-Lite (9200) menu
  if [ -s "$L_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
        --menu "Choose a Cat9k-Lite (9200) image (sorted by version asc):" \
        12 "$((W_DEF + 10))" 4 $L_ARGS
    [ $? -eq 0 ] && FW_CAT9K_LITE_FILE="${DOUT:-}"
  fi

  # Generic picker (optional, unchanged ordering)
  if [ -z "$FW_CAT9K_FILE$FW_CAT9K_LITE_FILE" ]; then
    G_TMP="$(mktemp)"
    while IFS='|' read -r _mt _sz nm; do
      [ -z "$nm" ] || printf '%s\n%s\n' "$nm" "-" >>"$G_TMP"
    done <"$tmp_lines"
    if [ -s "$G_TMP" ]; then
      # shellcheck disable=SC2086
      dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Generic" \
          --menu "Pick an image to proceed:" 22 "$W_WIDE" 16 $(tr '\n' ' ' <"$G_TMP")
      [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
    fi
    rm -f "$G_TMP"
  fi

  # ---- Compute metadata *before* deleting tmp_lines ----
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
  # ------------------------------------------------------

  rm -f "$tmp_lines" "$U_FILE" "$L_FILE"
  break
done
###############################################################################
# 4a) Hybrid minimum IOS XE requirement
###############################################################################
MIN_IOSXE_REQUIRED="${MIN_IOSXE_REQUIRED:-17.15.03}"

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Hybrid minimum IOS XE version" \
      --inputbox "We detected that you are staging IOS XE images for Meraki hybrid onboarding.

Meraki's hybrid onboarding and preflight checks require that all Catalyst switches
are running *at least* a specific IOS XE version before they will pass firmware
validation.

Current documented minimum (baseline): 17.15.03

Important:
  • If you upload an image *older* than this (for example 17.12.x),
    discovery can still run, but the Meraki preflight will flag those
    switches as NOT meeting the firmware requirement until they are
    upgraded again to 17.15.03 or later.
  • In almost all cases you should leave this set to 17.15.03.
  • Only change this if Cisco/Meraki documentation for your environment
    explicitly calls for a different minimum version.

Enter the minimum IOS XE version that devices must meet or exceed
to be considered compliant for hybrid onboarding:" 0 "$W_WIDE" "$MIN_IOSXE_REQUIRED"
  rc=$?

  if [ $rc -ne 0 ]; then
    break
  fi

  val="$(trim "${DOUT:-}")"
  [ -z "$val" ] && break

  python3 - "$val" <<'PY'
import sys, re
v = sys.argv[1].strip()
ok = bool(re.match(r'^[0-9]+\.([0-9]+)(\.[0-9]+)?[A-Za-z0-9]*$', v))
sys.exit(0 if ok else 1)
PY

  if [ $? -eq 0 ]; then
    MIN_IOSXE_REQUIRED="$val"
    break
  fi

  dlg --no-shadow --backtitle "$BACKTITLE" --title "Invalid Version" \
      --msgbox "Version '${val:-<empty>}' does not look like a valid IOS XE version.

Examples of valid formats:
  • 17.15
  • 17.15.03
  • 17.15.03a
  • 16.12.5b" 12 "$W_DEF"
done

###############################################################################
# 4b) Warn if selected firmware is below the hybrid minimum (pretty format)
###############################################################################
FW_WARN_MSG=""

append_fw_warn() {
  line="$1"
  if [ -z "$FW_WARN_MSG" ]; then
    FW_WARN_MSG="$line"
  else
    FW_WARN_MSG="${FW_WARN_MSG}
$line"
  fi
}

if [ -n "$FW_CAT9K_FILE" ] && [ -n "$FW_CAT9K_VERSION" ]; then
  if version_is_older "$FW_CAT9K_VERSION" "$MIN_IOSXE_REQUIRED"; then
    append_fw_warn "- Cat9k (universal): ${FW_CAT9K_FILE} (v${FW_CAT9K_VERSION})"
  fi
fi

if [ -n "$FW_CAT9K_LITE_FILE" ] && [ -n "$FW_CAT9K_LITE_VERSION" ]; then
  if version_is_older "$FW_CAT9K_LITE_VERSION" "$MIN_IOSXE_REQUIRED"; then
    append_fw_warn "- Cat9k-Lite (9200): ${FW_CAT9K_LITE_FILE} (v${FW_CAT9K_LITE_VERSION})"
  fi
fi

if [ -n "$FW_WARN_MSG" ]; then
  TMP_WARN="$(mktemp)"
  cat <<EOF >"$TMP_WARN"
We detected that at least one of the IOS-XE firmware images you selected is
*earlier* than your configured hybrid minimum (${MIN_IOSXE_REQUIRED}).

───────────────────────────────────────────────────────────────
What this means:
  • Discovery and configuration collection can still run using these images.
  • However, any switches actually running these versions will *FAIL*
    Meraki hybrid preflight until they are upgraded to
    ${MIN_IOSXE_REQUIRED} or later.
───────────────────────────────────────────────────────────────

Affected image(s):
${FW_WARN_MSG}
In almost all cases, you should plan to have **all switches** at
${MIN_IOSXE_REQUIRED} or a later IOS-XE release before attempting
Meraki hybrid onboarding.
EOF

  dialog --clear --backtitle "$BACKTITLE" \
    --title "Firmware below hybrid minimum" \
    --textbox "$TMP_WARN" 22 "$W_WIDE"
  rm -f "$TMP_WARN"
fi

###############################################################################
# 5) DISCOVERY SCAN RUN DIR (runs/discoveryscans)
###############################################################################
DISCOVERY_RUN_ID="${DISCOVERY_RUN_ID:-scan-$(date -u +%Y%m%d%H%M%S)}"
DISCOVERY_RUN_DIR="${DISCOVERY_RUN_DIR:-$DISC_SCAN_ROOT/$DISCOVERY_RUN_ID}"

mkdir -p "$DISCOVERY_RUN_DIR" "$DISCOVERY_RUN_DIR/devlogs"
ln -sfn "$DISCOVERY_RUN_DIR" "$DISC_SCAN_ROOT/latest"

###############################################################################
# 6) EXPORT + PERSIST
###############################################################################
export DISCOVERY_MODE="$MODE" DISCOVERY_NETWORKS DISCOVERY_IPS
export SSH_USERNAME SSH_PASSWORD SSH_TEST_IP
export DEFAULT_PRIV15_OK DEFAULT_LOGIN_PRIV
export ENABLE_PASSWORD ENABLE_TEST_OK
export MERAKI_API_KEY
export DNS_PRIMARY DNS_SECONDARY
export NTP_PRIMARY NTP_SECONDARY
export HTTP_CLIENT_VLAN_ID HTTP_CLIENT_SOURCE_IFACE
export FW_CAT9K_FILE FW_CAT9K_PATH FW_CAT9K_SIZE_BYTES FW_CAT9K_SIZE_H FW_CAT9K_VERSION
export FW_CAT9K_LITE_FILE FW_CAT9K_LITE_PATH FW_CAT9K_LITE_SIZE_BYTES FW_CAT9K_LITE_SIZE_H FW_CAT9K_LITE_VERSION
export MIN_IOSXE_REQUIRED
export DISC_SCAN_ROOT DISCOVERY_RUN_ID DISCOVERY_RUN_DIR

{
  echo "# Generated $(date -u '+%F %T') UTC"
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
  printf 'export MERAKI_API_KEY=%q\n' "$MERAKI_API_KEY"
  printf 'export DNS_PRIMARY=%q\n' "$DNS_PRIMARY"
  printf 'export DNS_SECONDARY=%q\n' "$DNS_SECONDARY"
  printf 'export NTP_PRIMARY=%q\n' "$NTP_PRIMARY"
  printf 'export NTP_SECONDARY=%q\n' "$NTP_SECONDARY"
  printf 'export HTTP_CLIENT_VLAN_ID=%q\n' "$HTTP_CLIENT_VLAN_ID"
  printf 'export HTTP_CLIENT_SOURCE_IFACE=%q\n' "$HTTP_CLIENT_SOURCE_IFACE"
  printf 'export MIN_IOSXE_REQUIRED=%q\n' "$MIN_IOSXE_REQUIRED"
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
# 7) SUMMARY (WIDE)
###############################################################################
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() { s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}'); if [ "$n" -le 4 ]; then printf '****'; else printf "%0.s*" $(seq 1 $((n-4))); printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"; fi; }

PW_MASK="$(mask "$SSH_PASSWORD")"; API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
SVI_SUMMARY="$( printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID" )"
ENABLE_SUMMARY="provided (verified)"
DEFPRIV_SUMMARY="$( [ "$DEFAULT_PRIV15_OK" = "1" ] && echo "# (priv 15)" || echo "> (user exec)" )"

summary="Wizard Results:

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Default Login Privilege: ${DEFAULT_LOGIN_PRIV} (${DEFPRIV_SUMMARY})
Enable Password: ${ENABLE_SUMMARY}
Meraki API Key: ${API_MASK}

DNS (fallbacks):
  Primary  : ${DNS_PRIMARY}
  Secondary: ${DNS_SECONDARY}

NTP (fallbacks):
  Primary  : ${NTP_PRIMARY}
  Secondary: ${NTP_SECONDARY:-<none>}

HTTP client source-interface (required):
  ${SVI_SUMMARY}

Hybrid minimum IOS XE required:
  ${MIN_IOSXE_REQUIRED}
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

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
    --msgbox "$summary" 40 85
clear