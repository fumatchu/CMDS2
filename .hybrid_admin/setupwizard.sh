#!/bin/sh
# discovery_prompt.sh — targets + SSH creds (+ login test) + Meraki API key
# + DNS (required) + NTP (at least one) fallbacks + mandatory HTTP client SVI + firmware selection
# + Enable password (optional) + on-box verification to privilege 15
# POSIX /bin/sh; dialog UI; writes ./meraki_discovery.env

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"
ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"       # scanner reads here
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}" # Cockpit opens here (symlink to FIRMWARE_DIR)
DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

log() { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }
_dnslog(){ [ "${DEBUG:-0}" = "1" ] && printf '[DNSDBG] %s\n' "$*" >>"$DEBUG_LOG"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need python3
need find
need ssh
need sshpass
need timeout

# ---------- Helpers ----------
trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
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

# Test 'enable' password by forcing a re-auth attempt even if we already have priv 15.
# Sequence:
#  terminal length 0
#  show privilege
#  disable            (ignored if not in priv 15)
#  enable
#  <enable-password>
#  show privilege     (must report "Current privilege level is 15")
ssh_enable_ok() {
  host="$1"; user="$2"; pass="$3"; enable_pass="$4"
  [ -n "$host" ] && [ -n "$user" ] && [ -n "$pass" ] && [ -n "$enable_pass" ] || return 1

  OUT="$(
    {
      printf 'terminal length 0\n'
      printf 'show privilege\n'
      printf 'disable\n'
      printf 'enable\n'
      printf '%s\n' "$enable_pass"
      printf 'show privilege\n'
      printf 'exit\n'
    } | sshpass -p "$pass" ssh \
          -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=8 -o PreferredAuthentications=password,keyboard-interactive \
          -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
          -o NumberOfPasswordPrompts=1 -tt "$user@$host" 2>/dev/null
  )"
  [ "${DEBUG:-0}" = "1" ] && printf '[ENABLEDBG] raw:\n%s\n' "$OUT" >>"$DEBUG_LOG"
  printf '%s' "$OUT" | LC_ALL=C grep -Eiq 'Current privilege level is[[:space:]]+15'
}

# Returns 0 if the NTP server replies. Accepts hostname or IP.
ntp_server_works() {
  srv="$1"
  [ -n "$srv" ] || return 1
  out="$(timeout 6s chronyc -n ntpdate "$srv" 2>&1)"; rc=$?
  [ "${DEBUG:-0}" = "1" ] && printf '[NTPDBG] srv=%s rc=%s out=%s\n' "$srv" "$rc" "$out" >>"$DEBUG_LOG"
  [ $rc -eq 0 ]
}

# human bytes
hbytes() {
  awk 'function hb(b){if(b<1024)printf "%d B",b;else if(b<1048576)printf "%.1f KB",b/1024;else if(b<1073741824)printf "%.1f MB",b/1048576;else printf "%.2f GB",b/1073741824}
       {hb($1)}' <<EOF
${1:-0}
EOF
}
# Extract IOS XE version from filename safely (e.g., cat9k_iosxe.17.15.03.SPA.bin -> 17.15.03)
version_from_name() {
  b="$(basename -- "$1" 2>/dev/null || printf '%s' "$1")"
  v="$(printf '%s\n' "$b" | sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' | head -n1)"
  [ -n "$v" ] || v="$(printf '%s\n' "$b" | sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,3}).*/\1/p' | head -n1)"
  printf '%s\n' "$v"
}
HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

# Ensure Cockpit upload path exists (and points to the scanner dir if missing)
ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

# dialog wrapper
dlg() { _tmp="$(mktemp)"; dialog "$@" 2>"$_tmp"; _rc=$?; DOUT=""; [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"; rm -f "$_tmp"; return $_rc; }

# Returns 0 if DNS server answers for google.com, else non-zero
dns_server_works() {
  srv="$1"
  [ -n "$srv" ] || return 1
  ans="$(dig +time=3 +tries=1 +short google.com @"$srv" 2>/dev/null | awk 'NF{print; exit}')"
  [ -n "$ans" ]
}

#===========VALIDATE DNS SERVERS AND EXPORT (robust)=============
# Requires: dialog, dig; helpers: trim, is_valid_ip, dlg; vars: BACKTITLE, W_DEF
validate_dns_servers() {
  command -v dig >/dev/null 2>&1 || {
    dialog --msgbox "Missing: dig (bind-utils). Install it and re-run." 7 70
    return 1
  }

  DNS_PRIMARY="${DNS_PRIMARY:-}"; DNS_SECONDARY="${DNS_SECONDARY:-}"

  _prompt_ip() {
    while :; do
      dlg --clear --backtitle "$BACKTITLE" --title "$1" \
          --inputbox "Enter a valid DNS server IP:" 8 "$W_DEF" "$2"
      rc=$?; _dnslog "inputbox rc=$rc title='$1'"
      [ $rc -eq 0 ] || { clear; return 1; }
      val="$(trim "${DOUT:-}")"
      if [ -n "$val" ] && is_valid_ip "$val"; then OUT_IP="$val"; return 0; fi
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Invalid IP" \
             --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
    done
  }

  _check_one_dns() {
    srv="$1"
    out="$(dig +time=3 +tries=1 +noall +answer google.com @"$srv" 2>&1)"
    echo "$out" | awk '
      /^[^;].*[[:space:]](A|AAAA)[[:space:]][0-9a-fA-F:.]+$/ {print $NF; ok=1; exit}
      END{exit ok?0:1}
    '
  }

  while :; do
    OUT_IP=""; _prompt_ip "DNS — Primary (required)"   "$DNS_PRIMARY"   || { _dnslog "primary prompt: cancel"; return 1; }
    DNS_PRIMARY="$OUT_IP"
    OUT_IP=""; _prompt_ip "DNS — Secondary (required)" "$DNS_SECONDARY" || { _dnslog "secondary prompt: cancel"; return 1; }
    DNS_SECONDARY="$OUT_IP"

    dlg --backtitle "$BACKTITLE" --title "Testing DNS" \
        --infobox "Resolving google.com via:\n  Primary  : $DNS_PRIMARY\n  Secondary: $DNS_SECONDARY" 7 "$W_DEF"
    sleep 0.6

    P_ANS="$(_check_one_dns "$DNS_PRIMARY")"; P_OK=$?
    S_ANS="$(_check_one_dns "$DNS_SECONDARY")"; S_OK=$?
    _dnslog "dig primary ok=$P_OK ans='${P_ANS:-}' secondary ok=$S_OK ans='${S_ANS:-}'"

    if [ $P_OK -eq 0 ] && [ $S_OK -eq 0 ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Validation" --msgbox \
"google.com resolved successfully:

  Primary   ($DNS_PRIMARY): ${P_ANS}
  Secondary ($DNS_SECONDARY): ${S_ANS}" 11 "$W_DEF"
      export DNS_PRIMARY DNS_SECONDARY
      _dnslog "both OK → proceed"
      return 0
    fi

    RESULT_MSG=$(cat <<EOF
DNS test results for google.com:

  Primary   ($DNS_PRIMARY): ${P_ANS:-FAILED}
  Secondary ($DNS_SECONDARY): ${S_ANS:-FAILED}

Re-enter the DNS servers?
  • Yes  = re-enter both and test again
  • No   = keep these values and continue
  • Esc  = abort
EOF
)
    dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Check Failed" \
           --yesno "$RESULT_MSG" 16 "$W_DEF"
    YN_RC=$?; _dnslog "yesno rc=$YN_RC (0=yes, 1=no, 255=esc)"

    case "$YN_RC" in
      0)  continue ;;
      1)  export DNS_PRIMARY DNS_SECONDARY; return 0 ;;
      255) clear; return 1 ;;
      *)  continue ;;
    esac
  done
}

# Clickable link helper (OSC-8)
osc8_link() { url="$1"; txt="${2:-$1}"; printf '\033]8;;%s\033\\%s\033]8;;\033\\\n' "$url" "$txt"; }

print_cockpit_link_and_wait() {
  HOST_SHOW="${HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
  ENC_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$COCKPIT_UPLOAD_DIR")"
  URL_A="https://${HOST_SHOW}:9090/files#/?path=${ENC_PATH}"
  URL_B="https://${HOST_SHOW}:9090/=${HOST_SHOW}/files#/?path=${ENC_PATH}"
  clear
  echo "=== Upload firmware via Cockpit ==="
  echo "  $URL_A"
  echo "  $URL_B"
  echo "Clickable:"
  osc8_link "$URL_A" "Open Cockpit Files at /root/IOS-XE_images"; osc8_link "$URL_B"
  echo "Upload to: $COCKPIT_UPLOAD_DIR"; [ -L "$COCKPIT_UPLOAD_DIR" ] && echo "(symlink to: $FIRMWARE_DIR)"
  printf "Press Enter when done… "; IFS= read -r _junk; stty sane 2>/dev/null || true
}

# -------- Box widths --------
TERM_COLS="$(tput cols 2>/dev/null)"; [ -z "$TERM_COLS" ] && TERM_COLS=140
BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200
W_WIDE="$BOX_W"
W_MODE="${W_MODE:-68}"; [ "$W_MODE" -lt 60 ] && W_MODE=60; [ "$W_MODE" -gt 90 ] && W_MODE=90
W_DEF="$W_MODE"
W_EDIT="$W_MODE"

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
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 "$W_DEF"
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

SSH_TEST_IP=""
if [ -n "$DISCOVERY_IPS" ]; then
  MENU_ARGS=""; for ip in $DISCOVERY_IPS; do MENU_ARGS="$MENU_ARGS $ip -"; done
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Test Device" --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_TEST_IP="$(trim "${DOUT:-}")"
else
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "Test Device IP" --inputbox "Enter an IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
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
  # Re-enter loops
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

###############################################################################
# 3a) ENABLE PASSWORD (optional) + verify escalation to priv 15
###############################################################################
ENABLE_PASSWORD=""
ENABLE_TEST_OK="0"
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Enable Password (optional)" \
      --insecure --passwordbox "If your device uses an enable password, enter it to verify we can reach privilege 15.\n\n(Leave blank and press OK to skip.)" 12 "$W_DEF"
  rc=$?; [ $rc -ne 0 ] && { clear; exit 1; }   # treat Esc as cancel whole flow
  ENABLE_PASSWORD="$(trim "${DOUT:-}")"

  # Skip if empty
  if [ -z "$ENABLE_PASSWORD" ]; then
    ENABLE_TEST_OK="0"
    break
  fi

  dlg --backtitle "$BACKTITLE" --title "Testing Enable" \
      --infobox "Verifying enable password on ${SSH_TEST_IP}…" 6 "$W_DEF"
  if ssh_enable_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD" "$ENABLE_PASSWORD"; then
    ENABLE_TEST_OK="1"
    dlg --backtitle "$BACKTITLE" --title "Enable Test" --msgbox "Enable password verified (privilege 15 confirmed)." 7 "$W_DEF"
    break
  fi

  CH=$(
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Enable Test Failed" --menu \
"Could not escalate to privilege 15 using the provided enable password on ${SSH_TEST_IP}.

Choose:" 12 "$W_DEF" 6 \
      1 "Re-enter enable password" \
      2 "Proceed without enable password" \
      3>&1 1>&2 2>&3
  ) || CH=1
  case "$CH" in
    1) continue ;;
    2) ENABLE_PASSWORD=""; ENABLE_TEST_OK="0"; break ;;
    *) continue ;;
  esac
done

###############################################################################
# 3b) MERAKI API KEY (keep WIDE)
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Meraki API Key" --insecure --passwordbox "Paste your Meraki Dashboard API key:\n(Asterisks shown while typing; last 4 shown in summary.)" 10 "$W_WIDE"
  rc=$?; [ $rc -eq 1 ] && { clear; exit 1; }
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 "$W_DEF"; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 "$W_DEF"
  [ $? -eq 0 ] && break
done

###############################################################################
# 3c) DNS — REQUIRED (validated with dig)
###############################################################################
if ! validate_dns_servers; then
  clear
  exit 1   # user hit Esc/cancel
fi
# DNS_PRIMARY and DNS_SECONDARY are exported by the function

###############################################################################
# 3c.1) NTP — validate (Primary required; Secondary optional)
# Accepts IP or hostname; tries ntpdate/chronyd/sntp
###############################################################################
probe_ntp_host() {
  local host="${1:-}"; [ -n "$host" ] || return 1

  if command -v ntpdate >/dev/null 2>&1; then
    timeout 8s ntpdate -u -q -t 4 "$host" >/dev/null 2>&1
    return $?
  fi
  if command -v chronyd >/dev/null 2>&1; then
    local kind="server"
    case "$host" in
      pool.*|*.pool.ntp.*|*.pool.ntp.org) kind="pool" ;;
    esac
    timeout 10s chronyd -Q -t 4 "$kind $host iburst maxsamples 1" >/dev/null 2>&1
    return $?
  fi
  if command -v sntp >/dev/null 2>&1; then
    timeout 8s sntp -r "$host" >/dev/null 2>&1
    return $?
  fi
  return 1
}

dlg --clear --backtitle "$BACKTITLE" --title "NTP Servers" --msgbox \
"Enter at least one NTP server (hostname or IP).\nWe won't overwrite working NTP on switches; these are fallbacks." 10 "$W_DEF"

NTP_PRIMARY=""; NTP_SECONDARY=""
while :; do
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "NTP — Primary (required)" \
        --inputbox "Primary NTP server (hostname or IP):" 8 "$W_DEF" "$NTP_PRIMARY"
    rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
    val="$(trim "${DOUT:-}")"
    [ -n "$val" ] && NTP_PRIMARY="$val" && break
    dlg --msgbox "Primary NTP cannot be empty." 7 "$W_DEF"
  done

  dlg --clear --backtitle "$BACKTITLE" --title "NTP — Secondary (optional)" \
      --inputbox "Secondary NTP server (hostname or IP, optional):" 8 "$W_DEF" "$NTP_SECONDARY"
  rc=$?; [ $rc -ne 0 ] && NTP_SECONDARY="" || NTP_SECONDARY="$(trim "${DOUT:-}")"

  dlg --backtitle "$BACKTITLE" --title "NTP Validation" \
      --infobox "Checking:\n  Primary  : ${NTP_PRIMARY}\n  Secondary: ${NTP_SECONDARY:-<none>}" 7 "$W_DEF"
  sleep 0.5

  P_OK=0; S_OK=2
  if probe_ntp_host "$NTP_PRIMARY"; then P_OK=1; fi
  if [ -n "$NTP_SECONDARY" ]; then
    S_OK=0
    if probe_ntp_host "$NTP_SECONDARY"; then S_OK=1; fi
  fi

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
    dlg --backtitle "$BACKTITLE" --title "NTP Validation" --msgbox \
"Neither NTP server responded:

  Primary  (${NTP_PRIMARY}): $( [ $P_OK -eq 1 ] && echo OK || echo FAILED )
  Secondary(${NTP_SECONDARY:-<none>}): $( [ $S_OK -eq 1 ] && echo OK || ([ $S_OK -eq 0 ] && echo FAILED || echo skipped) )

Please re-enter at least one working server." 14 "$W_DEF"
    continue
  fi

  CH=$(
    dialog --no-shadow --backtitle "$BACKTITLE" --title "NTP Validation" --menu \
"${msg}

Do you want to re-enter the NTP servers or proceed with the current values?" 13 "$W_DEF" 6 \
      1 "Re-enter NTP servers" \
      2 "Proceed with these values" \
      3>&1 1>&2 2>&3
  ) || CH=1
  [ "$CH" = "2" ] && break
done

###############################################################################
# 3d) VLAN SVI — MANDATORY
###############################################################################
HTTP_CLIENT_VLAN_ID=""; HTTP_CLIENT_SOURCE_IFACE=""
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "HTTP Client Source SVI (required)" \
      --inputbox "Enter the VLAN SVI number to use with:\n  ip http client source-interface Vlan<N>\n\nExamples: 10, 20, 4094" 12 "$W_DEF" "$HTTP_CLIENT_VLAN_ID"
  rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
  val="$(trim "${DOUT:-}")"
  python3 - "$val" <<'PY'
import sys
s=sys.argv[1]
ok = s.isdigit() and 1 <= int(s) <= 4094
sys.exit(0 if ok else 1)
PY
  if [ $? -eq 0 ]; then
    HTTP_CLIENT_VLAN_ID="$val"; HTTP_CLIENT_SOURCE_IFACE="Vlan${HTTP_CLIENT_VLAN_ID}"; break
  fi
  dlg --msgbox "Invalid VLAN ID: '${val:-<empty>}'\nEnter a number 1–4094." 9 "$W_DEF"
done

###############################################################################
# 4) FIRMWARE PICK (WIDE)
###############################################################################
mkdir -p "$FIRMWARE_DIR"
command -v restorecon >/dev/null 2>/dev/null && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%T@|%s|%f\n' 2>/dev/null | sort -nr
}

while :; do
  tmp_lines="$(mktemp)"; list_files >"$tmp_lines"
  if [ ! -s "$tmp_lines" ]; then
    CH=$(
      dialog --clear --backtitle "$BACKTITLE" --title "Firmware Upload Needed" \
        --menu "No firmware images were found in:\n  $FIRMWARE_DIR\n\nUpload in Cockpit, then choose Rescan." 14 "$W_DEF" 6 \
          1 "Show clickable Cockpit link (opens /root/IOS-XE_images)" \
          2 "Rescan directory" \
          0 "Exit setup" \
        3>&1 1>&2 2>&3
    ) || { clear; rm -f "$tmp_lines"; exit 1; }
    case "$CH" in
      1) print_cockpit_link_and_wait; rm -f "$tmp_lines"; continue ;;
      2) rm -f "$tmp_lines"; continue ;;
      0) clear; rm -f "$tmp_lines"; exit 1 ;;
    esac
  fi
  break
done

build_menu_file() {
  fam="$1"; infile="$2"
  while IFS='|' read -r _mt _sz nm; do
    [ -z "$nm" ] && continue
    lower="$(printf '%s' "$nm" | tr '[:upper:]' '[:lower:]')"
    case "$fam" in
      universal) echo "$lower" | grep -Eq '^cat9k_iosxe.*\.bin$' || continue ;;
      lite)      echo "$lower" | grep -Eq '^cat9k_lite_iosxe.*\.bin$' || continue ;;
    esac
    printf '%s\n' "$nm"; printf '%s\n' "-"
  done <"$infile"
}

U_FILE="$(mktemp)"; build_menu_file universal "$tmp_lines" >"$U_FILE"
L_FILE="$(mktemp)"; build_menu_file lite "$tmp_lines" >"$L_FILE"
U_ARGS="$(tr '\n' ' ' <"$U_FILE")"; L_ARGS="$(tr '\n' ' ' <"$L_FILE")"
FW_CAT9K_FILE=""; FW_CAT9K_LITE_FILE=""

if [ -s "$U_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
      --menu "Choose a Cat9k (9300/9400/9500/9600) image:" 22 "$W_WIDE" 16 $U_ARGS
  [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
fi
if [ -s "$L_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
      --menu "Choose a Cat9k-Lite (9200) image:" 22 "$W_WIDE" 16 $L_ARGS
  [ $? -eq 0 ] && FW_CAT9K_LITE_FILE="${DOUT:-}"
fi

if [ -z "$FW_CAT9K_FILE$FW_CAT9K_LITE_FILE" ]; then
  G_TMP="$(mktemp)"; while IFS='|' read -r _mt _sz nm; do [ -z "$nm" ] || printf '%s\n%s\n' "$nm" "-" >>"$G_TMP"; done <"$tmp_lines"
  if [ -s "$G_TMP" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Generic" \
        --menu "Pick an image to proceed:" 22 "$W_WIDE" 16 $(tr '\n' ' ' <"$G_TMP")
    [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
  fi
  rm -f "$G_TMP"
fi

resolve_meta() {
  name="$1"; infile="$2"
  while IFS='|' read -r mt sz nm; do [ "$nm" = "$name" ] && { printf '%s|%s\n' "$sz" "$FIRMWARE_DIR/$nm"; return; }; done <"$infile"
  printf '|\n'
}

FW_CAT9K_PATH=""; FW_CAT9K_SIZE_BYTES=""; FW_CAT9K_SIZE_H=""; FW_CAT9K_VERSION=""
FW_CAT9K_LITE_PATH=""; FW_CAT9K_LITE_SIZE_BYTES=""; FW_CAT9K_LITE_SIZE_H=""; FW_CAT9K_LITE_VERSION=""
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

rm -f "$tmp_lines" "$U_FILE" "$L_FILE" 2>/dev/null

###############################################################################
# 5) EXPORT + PERSIST
###############################################################################
export DISCOVERY_MODE="$MODE"
export DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS"
export DISCOVERY_IPS="$DISCOVERY_IPS"
export SSH_USERNAME SSH_PASSWORD SSH_TEST_IP
export ENABLE_PASSWORD ENABLE_TEST_OK
export MERAKI_API_KEY
export DNS_PRIMARY DNS_SECONDARY
export NTP_PRIMARY NTP_SECONDARY
export HTTP_CLIENT_VLAN_ID HTTP_CLIENT_SOURCE_IFACE
export FW_CAT9K_FILE FW_CAT9K_PATH FW_CAT9K_SIZE_BYTES FW_CAT9K_SIZE_H FW_CAT9K_VERSION
export FW_CAT9K_LITE_FILE FW_CAT9K_LITE_PATH FW_CAT9K_LITE_SIZE_BYTES FW_CAT9K_LITE_SIZE_H FW_CAT9K_LITE_VERSION

{
  echo "# Generated $(date -u '+%F %T') UTC"
  printf 'export DISCOVERY_MODE=%q\n' "$DISCOVERY_MODE"
  printf 'export DISCOVERY_NETWORKS=%q\n' "$DISCOVERY_NETWORKS"
  printf 'export DISCOVERY_IPS=%q\n' "$DISCOVERY_IPS"
  printf 'export SSH_USERNAME=%q\n' "$SSH_USERNAME"
  printf 'export SSH_PASSWORD=%q\n' "$SSH_PASSWORD"
  printf 'export SSH_TEST_IP=%q\n' "$SSH_TEST_IP"
  printf 'export ENABLE_PASSWORD=%q\n' "$ENABLE_PASSWORD"
  printf 'export ENABLE_TEST_OK=%q\n' "$ENABLE_TEST_OK"
  printf 'export MERAKI_API_KEY=%q\n' "$MERAKI_API_KEY"
  printf 'export DNS_PRIMARY=%q\n' "$DNS_PRIMARY"
  printf 'export DNS_SECONDARY=%q\n' "$DNS_SECONDARY"
  printf 'export NTP_PRIMARY=%q\n' "$NTP_PRIMARY"
  printf 'export NTP_SECONDARY=%q\n' "$NTP_SECONDARY"
  printf 'export HTTP_CLIENT_VLAN_ID=%q\n' "$HTTP_CLIENT_VLAN_ID"
  printf 'export HTTP_CLIENT_SOURCE_IFACE=%q\n' "$HTTP_CLIENT_SOURCE_IFACE"
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
# 6) SUMMARY (WIDE)
###############################################################################
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() {
  s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}')
  if [ "$n" -le 4 ]; then printf '****'; else
    printf "%0.s*" $(seq 1 $((n-4))); printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}
PW_MASK="$(mask "$SSH_PASSWORD")"; API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
SVI_SUMMARY="$( printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID" )"
ENABLE_SUMMARY="$( [ "$ENABLE_TEST_OK" = "1" ] && echo 'provided (tested OK)' || ([ -n "$ENABLE_PASSWORD" ] && echo 'provided (test FAILED)') )"
[ -z "$ENABLE_SUMMARY" ] && ENABLE_SUMMARY="not provided"

summary="Saved: ${ENV_FILE}

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Enable Password: ${ENABLE_SUMMARY}
Meraki API Key: ${API_MASK}

DNS (required; used as fallback if needed):
  Primary  : ${DNS_PRIMARY}
  Secondary: ${DNS_SECONDARY}

NTP (at least one; used as fallback if needed):
  Primary  : ${NTP_PRIMARY}
  Secondary: ${NTP_SECONDARY:-<none>}

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

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 24 "$W_WIDE"
clear
