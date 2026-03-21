#!/usr/bin/env bash
# setupwizard.sh — CMDS Switch Discovery — Setup
# - Prompts: targets, SSH creds (+ test), default privilege 15 check, enable password verify
# - Meraki API key
# - Writes ./meraki_discovery.env
#
# Legacy SSH handling:
# - Creates custom RSA-OPENSSH-1024 crypto policy module if missing
# - Switches system policy to LEGACY:RSA-OPENSSH-1024 for the duration of the wizard
# - Uses legacy-compatible SSH options that work for old Catalyst gear
# - Always restores the host crypto policy to DEFAULT on exit

set -u

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"

ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"

DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

# Script/run paths
SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
RUNS_ROOT="${RUNS_ROOT:-$SCRIPT_DIR/runs}"
DISC_SCAN_ROOT="${DISC_SCAN_ROOT:-$RUNS_ROOT/discoveryscans}"
mkdir -p "$DISC_SCAN_ROOT"

# ---- deps ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need python3; need ssh; need sshpass; need timeout; need expect; need update-crypto-policies

# ---- helpers ----
log() { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }
trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

dlg() {
  _tmp="$(mktemp)"
  dialog "$@" 2>"$_tmp"
  _rc=$?
  DOUT=""
  [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $_rc
}

is_valid_ip()   { python3 -c 'import sys,ipaddress; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
is_valid_cidr() { python3 -c 'import sys,ipaddress; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }

first_token() { set -- $1; printf '%s' "${1:-}"; }

###############################################################################
# Legacy crypto policy handling
###############################################################################
DEFAULT_CRYPTO_POLICY="DEFAULT"
CRYPTO_MODULE_DIR="/etc/crypto-policies/policies/modules"
CRYPTO_MODULE_FILE="$CRYPTO_MODULE_DIR/RSA-OPENSSH-1024.pmod"
LEGACY_CRYPTO_POLICY="LEGACY:RSA-OPENSSH-1024"

restore_crypto_policy() {
  update-crypto-policies --set "$DEFAULT_CRYPTO_POLICY" >/dev/null 2>&1 || true
}

cleanup_and_exit() {
  restore_crypto_policy
  clear
  exit "${1:-0}"
}

trap 'restore_crypto_policy' EXIT

ensure_legacy_crypto_policy() {
  mkdir -p "$CRYPTO_MODULE_DIR" || return 1

  if [ ! -f "$CRYPTO_MODULE_FILE" ]; then
    cat >"$CRYPTO_MODULE_FILE" <<'EOF'
min_rsa_size@openssh = 1024
EOF
    chmod 644 "$CRYPTO_MODULE_FILE" || true
  fi

  update-crypto-policies --set "$LEGACY_CRYPTO_POLICY" >/dev/null 2>&1 || return 1
  return 0
}

###############################################################################
# Legacy SSH option profile
###############################################################################
ssh_login_ok() {
  sshpass -p "$3" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=1 \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o KbdInteractiveAuthentication=yes \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    -o KexAlgorithms=+diffie-hellman-group14-sha1 \
    -o HostKeyAlgorithms=+ssh-rsa \
    -o PubkeyAcceptedAlgorithms=+ssh-rsa \
    -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc \
    -o MACs=+hmac-sha1,hmac-sha1-96 \
    -tt "$2@$1" "exit" >/dev/null 2>&1
}

get_default_priv_level() {
  host="$1"; user="$2"; pass="$3"
  [ -n "$host" ] && [ -n "$user" ] && [ -n "$pass" ] || { echo ""; return 1; }

  HOST="$host" USER="$user" PASS="$pass" \
  DEBUG_FLAG="${DEBUG:-0}" DEBUG_LOG_FILE="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}" \
  expect -f - <<'EXP'
    log_user 0
    if {$env(DEBUG_FLAG) == "1"} { catch {log_file -a $env(DEBUG_LOG_FILE)} }

    set host   $env(HOST)
    set user   $env(USER)
    set pass   $env(PASS)
    set t_login 15
    set t_cmd   8
    set prompt_re {[\r\n][^\r\n]*([>#]) ?$}

    spawn ssh \
      -o LogLevel=ERROR \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o PreferredAuthentications=password,keyboard-interactive \
      -o KbdInteractiveAuthentication=yes \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o KexAlgorithms=+diffie-hellman-group14-sha1 \
      -o HostKeyAlgorithms=+ssh-rsa \
      -o PubkeyAcceptedAlgorithms=+ssh-rsa \
      -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc \
      -o MACs=+hmac-sha1,hmac-sha1-96 \
      -tt $user@$host

    set timeout $t_login
    while 1 {
      expect \
        -nocase -re {username:} { send -- "$user\r" } \
        -nocase -re {password:} { send -- "$pass\r" } \
        -re $prompt_re {
          if {[regexp {([>#]) ?$} $expect_out(0,string) -> prompt_char]} {
            if {$prompt_char eq "#"} {
              puts "15"
              exit 0
            } elseif {$prompt_char eq ">"} {
              puts "1"
              exit 0
            }
          }
        } \
        -re {denied|authentication failed|login invalid} { exit 3 } \
        timeout { exit 3 } \
        eof { exit 3 }
    }

    send -- "\r"
    expect -re $prompt_re

    send -- "terminal length 0\r"
    set timeout $t_cmd
    expect -re $prompt_re

    send -- "show privilege\r"
    expect {
      -re {Current privilege level is[[:space:]]*([0-9]+)} {
        puts $expect_out(1,string)
        exit 0
      }
      -re $prompt_re {
        if {[regexp {([>#]) ?$} $expect_out(0,string) -> prompt_char]} {
          if {$prompt_char eq "#"} {
            puts "15"
            exit 0
          } elseif {$prompt_char eq ">"} {
            puts "1"
            exit 0
          }
        }
        puts ""
        exit 1
      }
      timeout {
        puts ""
        exit 1
      }
      eof {
        puts ""
        exit 1
      }
    }
EXP
}

ssh_enable_ok() {
  host="$1"; user="$2"; pass="$3"; enable_pass="$4"
  [ -n "$host" ] && [ -n "$user" ] && [ -n "$pass" ] && [ -n "$enable_pass" ] || return 7

  HOST="$host" USER="$user" PASS="$pass" ENPASS="$enable_pass" \
  DEBUG_FLAG="${DEBUG:-0}" DEBUG_LOG_FILE="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}" \
  ENABLE_VERIFY_TIMEOUT="${ENABLE_VERIFY_TIMEOUT:-6}" \
  expect -f - <<'EXP'
    log_user 0
    if {$env(DEBUG_FLAG) == "1"} { catch {log_file -a $env(DEBUG_LOG_FILE)} }

    set host   $env(HOST)
    set user   $env(USER)
    set pass   $env(PASS)
    set enpass $env(ENPASS)
    set t_login 15
    set t_verify [expr {int($env(ENABLE_VERIFY_TIMEOUT))}]
    set prompt_re {[\r\n][^\r\n]*[>#] ?$}

    spawn ssh \
      -o LogLevel=ERROR \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o ConnectTimeout=10 \
      -o PreferredAuthentications=password,keyboard-interactive \
      -o KbdInteractiveAuthentication=yes \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o KexAlgorithms=+diffie-hellman-group14-sha1 \
      -o HostKeyAlgorithms=+ssh-rsa \
      -o PubkeyAcceptedAlgorithms=+ssh-rsa \
      -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc \
      -o MACs=+hmac-sha1,hmac-sha1-96 \
      -tt $user@$host

    set timeout $t_login
    while 1 {
      expect \
        -nocase -re {username:} { send -- "$user\r" } \
        -nocase -re {password:} { send -- "$pass\r" } \
        -re $prompt_re { break } \
        -re {denied|authentication failed|login invalid} { exit 3 } \
        timeout { exit 3 } \
        eof { exit 3 }
    }

    send -- "\r"
    expect -re $prompt_re

    send -- "terminal length 0\r"
    expect -re $prompt_re

    send -- "show privilege\r"
    set timeout $t_verify
    expect {
      -re {Current privilege level is[[:space:]]*15} {}
      -re {Current privilege level is[[:space:]]*[0-9]+} { exit 6 }
      timeout { exit 4 }
      eof { exit 4 }
    }

    send -- "show running-config | include ^hostname\r"
    expect {
      -re {hostname[[:space:]]+.+} { exit 0 }
      -re {% ?Authorization failed} { exit 9 }
      -re {% ?Invalid input} { exit 8 }
      -re $prompt_re { exit 0 }
      timeout { exit 4 }
      eof { exit 4 }
    }
EXP
  return $?
}

# ---- UI sizing ----
TERM_LINES="$(tput lines 2>/dev/null)"; [ -z "$TERM_LINES" ] && TERM_LINES=40
TERM_COLS="$(tput cols 2>/dev/null)";  [ -z "$TERM_COLS" ] && TERM_COLS=140

BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200
W_WIDE="$BOX_W"

W_MODE="${W_MODE:-68}"; [ "$W_MODE" -lt 60 ] && W_MODE=60; [ "$W_MODE" -gt 90 ] && W_MODE=90
W_DEF="$W_MODE"; W_EDIT="$W_MODE"

WELCOME_W="${WELCOME_W:-100}"
[ "$WELCOME_W" -lt 60 ] && WELCOME_W=60
[ "$WELCOME_W" -gt "$BOX_W" ] && WELCOME_W="$BOX_W"

WELCOME_H="${WELCOME_H:-30}"
MAX_WELCOME_H=$((TERM_LINES - 4))
[ "$WELCOME_H" -gt "$MAX_WELCOME_H" ] && WELCOME_H="$MAX_WELCOME_H"
[ "$WELCOME_H" -lt 10 ] && WELCOME_H=10

###############################################################################
# Switch crypto policy now, before any SSH work
###############################################################################
if ! ensure_legacy_crypto_policy; then
  dlg --clear --backtitle "$BACKTITLE" --title "Crypto Policy Error" --msgbox \
"Failed to enable temporary legacy crypto compatibility mode.

The wizard needs to temporarily switch this host to:
  ${LEGACY_CRYPTO_POLICY}

Please verify this script is running as root and that update-crypto-policies is available." \
  12 "$W_DEF"
  cleanup_and_exit 1
fi

###############################################################################
# Pre-populate wizard defaults from existing ENV_FILE (if present)
###############################################################################
# shellcheck disable=SC1090
[ -r "$ENV_FILE" ] && . "$ENV_FILE" 2>/dev/null || true

REPORT_DISCOVERY_MODE="${DISCOVERY_MODE:-}"
REPORT_DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
REPORT_DISCOVERY_IPS="${DISCOVERY_IPS:-}"
REPORT_SSH_USERNAME="${SSH_USERNAME:-}"
REPORT_SSH_PASSWORD="${SSH_PASSWORD:-}"
REPORT_SSH_TEST_IP="${SSH_TEST_IP:-}"
REPORT_ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"

[ -n "$REPORT_DISCOVERY_MODE" ] || REPORT_DISCOVERY_MODE="scan"
REPORT_NETS_LINES="$(printf '%s' "${REPORT_DISCOVERY_NETWORKS:-}" | tr ',' '\n')"
REPORT_IPS_LINES="$(printf '%s' "${REPORT_DISCOVERY_IPS:-}" | tr ' ' '\n')"

###############################################################################
# 0) WELCOME
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "Welcome — Discovery Setup" --msgbox \
"Welcome to the CMDS Discovery setup wizard.

For compatibility with older Catalyst SSH stacks, this wizard temporarily
switches the host crypto policy to:
  ${LEGACY_CRYPTO_POLICY}

The host crypto policy will be restored to:
  ${DEFAULT_CRYPTO_POLICY}

This will guide you through:
  1) Choose how to provide targets (scan CIDR or manual list)
  2) Provide targets (networks/IPs)
  3) Enter SSH credentials and verify login
  4) Verify your account lands in privileged EXEC (#) by default (required)
  5) Capture and verify the device ENABLE password
  6) Paste your Meraki Dashboard API key
  7) Save all choices to ${ENV_FILE} and show a summary

Have these ready:
  • Target networks/IPs
  • SSH username and password (must land at privilege 15 — prompt '#')
  • ENABLE password (required)
  • Meraki Dashboard API key" \
  "$WELCOME_H" "$WELCOME_W"

###############################################################################
# 1) MODE
###############################################################################
log "Prompt: mode"
if [ "$REPORT_DISCOVERY_MODE" = "list" ]; then
  dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
      --menu "How do you want to provide targets?" 12 "$W_MODE" 2 \
      list "Use a manual list of IPs (one per line)" \
      scan "Discover live hosts by scanning CIDR networks"
else
  dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
      --menu "How do you want to provide targets?" 12 "$W_MODE" 2 \
      scan "Discover live hosts by scanning CIDR networks" \
      list "Use a manual list of IPs (one per line)"
fi
rc=$?; MODE="$(trim "${DOUT:-}")"; log "Mode rc=$rc val='$MODE'"
[ $rc -eq 0 ] || cleanup_and_exit 1

###############################################################################
# 2) TARGETS
###############################################################################
DISCOVERY_NETWORKS=""; DISCOVERY_IPS=""

if [ "$MODE" = "scan" ]; then
  NETS_PREV="# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored.
"
  if [ -n "$(trim "$REPORT_NETS_LINES")" ]; then
    NETS_PREV="${NETS_PREV}$(printf '%s\n' "$REPORT_NETS_LINES")"
  else
    NETS_PREV="${NETS_PREV}10.0.0.0/24"
  fi

  while :; do
    tmpnets="$(mktemp)"; printf '%s\n' "$NETS_PREV" >"$tmpnets"
    dlg --clear --backtitle "$BACKTITLE" --title "Networks to Scan (one per line)" --editbox "$tmpnets" 14 "$W_EDIT"
    rc=$?; NETS_RAW="${DOUT:-}"; rm -f "$tmpnets"; [ $rc -eq 0 ] || cleanup_and_exit 1
    NETS_PREV="$NETS_RAW"

    tmpin_nets="$(mktemp)"; printf '%s\n' "$NETS_RAW" >"$tmpin_nets"
    DISCOVERY_NETWORKS=""; invalid_line=""
    while IFS= read -r raw; do
      line="$(trim "$raw")"; [ -z "$line" ] && continue
      case "$line" in \#*) continue ;; esac
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
"
  if [ -n "$(trim "$REPORT_IPS_LINES")" ]; then
    IPS_PREV="${IPS_PREV}$(printf '%s\n' "$REPORT_IPS_LINES")"
  else
    IPS_PREV="${IPS_PREV}192.168.1.10
192.168.1.11"
  fi

  while :; do
    tmpips="$(mktemp)"; printf '%s\n' "$IPS_PREV" >"$tmpips"
    dlg --clear --backtitle "$BACKTITLE" --title "Manual IP List (one per line)" --editbox "$tmpips" 16 "$W_EDIT"
    rc=$?; IPS_RAW="${DOUT:-}"; rm -f "$tmpips"; [ $rc -eq 0 ] || cleanup_and_exit 1
    IPS_PREV="$IPS_RAW"

    ips_file="$(mktemp)"; printf '%s\n' "$IPS_RAW" >"$ips_file"
    DISCOVERY_IPS=""; invalid_ip=""; SEEN_TMP="$(mktemp)"; : >"$SEEN_TMP"
    while IFS= read -r raw; do
      ip="$(trim "$raw")"; [ -z "$ip" ] && continue
      case "$ip" in \#*) continue ;; esac
      if ! is_valid_ip "$ip"; then invalid_ip="$ip"; break; fi
      if ! grep -qx -- "$ip" "$SEEN_TMP" 2>/dev/null; then
        printf '%s\n' "$ip" >>"$SEEN_TMP"
        [ -z "$DISCOVERY_IPS" ] && DISCOVERY_IPS="$ip" || DISCOVERY_IPS="$DISCOVERY_IPS $ip"
      fi
    done <"$ips_file"
    rm -f "$ips_file"

    [ -z "$invalid_ip" ] || { rm -f "$SEEN_TMP"; dlg --title "Invalid IP" --msgbox "Invalid IP: '$invalid_ip'." 7 "$W_DEF"; continue; }
    [ -n "$DISCOVERY_IPS" ] || { rm -f "$SEEN_TMP"; dlg --title "No IPs" --msgbox "Provide at least one valid IP." 7 "$W_DEF"; continue; }
    rm -f "$SEEN_TMP"
    break
  done
fi

###############################################################################
# 3) SSH CREDS + TEST
###############################################################################
SSH_USERNAME="${REPORT_SSH_USERNAME:-}"
SSH_PASSWORD="${REPORT_SSH_PASSWORD:-}"
SSH_TEST_IP="${REPORT_SSH_TEST_IP:-}"

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" \
      --inputbox "Enter SSH switch username:" 8 "$W_DEF" "$SSH_USERNAME"
  [ $? -eq 0 ] || cleanup_and_exit 1
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
done

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
  [ $? -eq 0 ] || cleanup_and_exit 1
  SSH_PASSWORD="$(trim "${DOUT:-}")"
  [ -n "$SSH_PASSWORD" ] && break
  dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
done

if [ -n "$DISCOVERY_IPS" ]; then
  MENU_ARGS=""
  if [ -n "$SSH_TEST_IP" ] && ! printf '%s\n' "$DISCOVERY_IPS" | tr ' ' '\n' | grep -qx -- "$SSH_TEST_IP" 2>/dev/null; then
    MENU_ARGS="$MENU_ARGS $SSH_TEST_IP (report)"
  fi
  for ip in $DISCOVERY_IPS; do
    MENU_ARGS="$MENU_ARGS $ip -"
  done
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Test Device" \
      --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
  [ $? -eq 0 ] || cleanup_and_exit 1
  SSH_TEST_IP="$(trim "${DOUT:-}")"
else
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "Test Device IP" \
        --inputbox "Enter a switch IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
    rc=$?; [ $rc -eq 0 ] || cleanup_and_exit 1
    val="$(trim "${DOUT:-}")"
    [ -n "$val" ] && is_valid_ip "$val" && SSH_TEST_IP="$val" && break
    dlg --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
  done
fi

while :; do
  dlg --backtitle "$BACKTITLE" --title "Testing SSH" \
      --infobox "Testing SSH login to ${SSH_TEST_IP} as ${SSH_USERNAME}…" 6 "$W_DEF"
  sleep 1
  if ssh_login_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD"; then
    dlg --backtitle "$BACKTITLE" --title "SSH Test" --infobox "Login OK to ${SSH_TEST_IP}." 5 "$W_DEF"
    sleep 1
    break
  fi

  dlg --backtitle "$BACKTITLE" --title "Login Failed" --yesno "Could not log in. Re-enter username and password?" 8 "$W_DEF"
  [ $? -eq 0 ] || cleanup_and_exit 1

  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" \
      --inputbox "Enter SSH username:" 8 "$W_DEF" "$SSH_USERNAME"
  [ $? -eq 0 ] || cleanup_and_exit 1
  SSH_USERNAME="$(trim "${DOUT:-}")"

  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
  [ $? -eq 0 ] || cleanup_and_exit 1
  SSH_PASSWORD="$(trim "${DOUT:-}")"
done

DEFAULT_LOGIN_PRIV="$(trim "$(get_default_priv_level "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD")")"
PL_NUM="$(printf '%s' "$DEFAULT_LOGIN_PRIV" | tr -cd '0-9')"
DEFAULT_PRIV15_OK="0"
if [ "$PL_NUM" = "15" ]; then
  DEFAULT_PRIV15_OK="1"
else
  dialog --no-shadow --backtitle "$BACKTITLE" --title "Privilege Level Too Low" --msgbox \
"Your account does not land in privileged EXEC by default.

Device: ${SSH_TEST_IP}
Detected default privilege level: ${DEFAULT_LOGIN_PRIV:-unknown}

This workflow requires a user that logs in at privilege 15 (prompt ends with #)
without entering 'enable' first.

Please use an account with privilege 15 and re-run the setup." 16 "$W_DEF"
  cleanup_and_exit 1
fi

###############################################################################
# 3a) ENABLE PASSWORD (required) + verify
###############################################################################
ENABLE_PASSWORD="${REPORT_ENABLE_PASSWORD:-}"
ENABLE_TEST_OK="0"

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Enable Password (required)" \
      --insecure --passwordbox \
"Enter the device's ENABLE password.
We'll verify that this session has privileged EXEC access (# / privilege 15) and can read running-config." \
      11 "$W_DEF" "$ENABLE_PASSWORD"
  rc=$?; [ $rc -ne 0 ] && cleanup_and_exit 1

  ENABLE_PASSWORD="$(trim "${DOUT:-}")"
  if [ -z "$ENABLE_PASSWORD" ]; then
    dlg --no-shadow --backtitle "$BACKTITLE" --title "Missing Enable Password" \
        --msgbox "The ENABLE password is required.\n\nPlease enter a non-empty password." 8 "$W_DEF"
    continue
  fi

  dlg --backtitle "$BACKTITLE" --title "Testing Enable" \
      --infobox "Verifying privileged EXEC access on ${SSH_TEST_IP}…" 6 "$W_DEF"

  ssh_enable_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD" "$ENABLE_PASSWORD"
  rc=$?

  if [ $rc -eq 0 ]; then
    ENABLE_TEST_OK="1"
    dlg --backtitle "$BACKTITLE" --title "Enable Test" \
        --msgbox "Privileged EXEC access verified." 7 "$W_DEF"
    break
  fi

  reason="Privilege verification failed."
  [ $rc -eq 6 ] && reason="Login succeeded, but the session did not land at privilege level 15."
  [ $rc -eq 8 ] && reason="The privileged command check did not complete successfully."
  [ $rc -eq 9 ] && reason="The session appears to be blocked by command authorization."

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Enable Test Failed" --yesno \
"${reason}

Do you want to try entering the ENABLE password again?" 10 "$W_DEF"
  [ $? -eq 0 ] || cleanup_and_exit 1
done

###############################################################################
# 3b) MERAKI API KEY
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Meraki API Key" --insecure --passwordbox \
"Paste your Meraki Dashboard API key:" 8 "$W_DEF"
  rc=$?; [ $rc -eq 1 ] && cleanup_and_exit 1
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 "$W_DEF"; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 "$W_DEF"; [ $? -eq 0 ] && break
done

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
export DISC_SCAN_ROOT DISCOVERY_RUN_ID DISCOVERY_RUN_DIR
export DEFAULT_CRYPTO_POLICY LEGACY_CRYPTO_POLICY

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
  printf 'export DISC_SCAN_ROOT=%q\n' "$DISC_SCAN_ROOT"
  printf 'export DISCOVERY_RUN_ID=%q\n' "$DISCOVERY_RUN_ID"
  printf 'export DISCOVERY_RUN_DIR=%q\n' "$DISCOVERY_RUN_DIR"
  printf 'export DEFAULT_CRYPTO_POLICY=%q\n' "$DEFAULT_CRYPTO_POLICY"
  printf 'export LEGACY_CRYPTO_POLICY=%q\n' "$LEGACY_CRYPTO_POLICY"
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

###############################################################################
# 7) SUMMARY
###############################################################################
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() {
  s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}')
  if [ "$n" -le 4 ]; then
    printf '****'
  else
    printf "%0.s*" $(seq 1 $((n-4)))
    printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}

PW_MASK="$(mask "$SSH_PASSWORD")"
API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
ENABLE_SUMMARY="provided (verified)"
DEFPRIV_SUMMARY="$( [ "$DEFAULT_PRIV15_OK" = "1" ] && echo "# (priv 15)" || echo "> (user exec)" )"

summary="Wizard Results:

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Default Login Privilege: ${DEFAULT_LOGIN_PRIV} (${DEFPRIV_SUMMARY})
Enable Password: ${ENABLE_SUMMARY}
Meraki API Key: ${API_MASK}

Temporary Crypto Policy Used: ${LEGACY_CRYPTO_POLICY}
Crypto Policy Restored To: ${DEFAULT_CRYPTO_POLICY}
"

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 20 95
cleanup_and_exit 0