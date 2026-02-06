#!/bin/sh
# setupwizard.sh — CMDS Switch Discovery — Setup (POSIX /bin/sh)
# - Requires firmware discovery scan output: cloud_firmware_report.env (or runs firmware_scan.sh)
# - Prompts: targets, SSH creds (+ test), default privilege 15 check, enable password verify
# - Meraki API key, DNS fallbacks validation, mandatory HTTP client SVI
# - Firmware selection (MULTI) + post-selection checks:
#     1) selected files exist + non-empty
#     2) train requirement (LITE/UNIVERSAL) based on BELOW_REQUIRED inventory
#     3) version coverage vs required minimum per train
# - Writes ./meraki_discovery.env

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"

ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"

FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"        # scanner reads here
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}" # Cockpit opens here (symlink to FIRMWARE_DIR)

DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

# Script/run paths
SCRIPT_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"
RUNS_ROOT="${RUNS_ROOT:-$SCRIPT_DIR/runs}"
DISC_SCAN_ROOT="${DISC_SCAN_ROOT:-$RUNS_ROOT/discoveryscans}"
mkdir -p "$DISC_SCAN_ROOT"

# Firmware scan artifacts
FIRMWARE_REPORT_ENV="${FIRMWARE_REPORT_ENV:-$SCRIPT_DIR/cloud_firmware_report.env}"
FIRMWARE_SCAN_SCRIPT="${FIRMWARE_SCAN_SCRIPT:-$SCRIPT_DIR/firmware_scan.sh}"
FIRMWARE_REPORT_DIR="${FIRMWARE_REPORT_DIR:-/root/.cloud_admin/runs/firmware_reports/latest}"
FIRMWARE_REPORT_JSON="${FIRMWARE_REPORT_JSON:-$FIRMWARE_REPORT_DIR/firmware_report.json}"
FIRMWARE_REPORT_SUMMARY_TXT="${FIRMWARE_REPORT_SUMMARY_TXT:-$FIRMWARE_REPORT_DIR/firmware_report_summary.txt}"

# Bible (source of truth for min IOS-XE + train/type by PID)
BIBLE_JSON="${BIBLE_JSON:-/root/.cloud_admin/cloud_models.json}"

# ---- deps ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need python3; need find; need ssh; need sshpass; need timeout; need expect; need jq

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

hbytes() {
  awk 'function hb(b){
    if(b<1024)printf "%d B",b;
    else if(b<1048576)printf "%.1f KB",b/1024;
    else if(b<1073741824)printf "%.1f MB",b/1048576;
    else printf "%.2f GB",b/1073741824
  }{hb($1)}' <<EOF
${1:-0}
EOF
}

version_from_name() {
  b="$(basename -- "$1" 2>/dev/null || printf '%s' "$1")"
  v="$(printf '%s\n' "$b" | sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' | head -n1)"
  [ -n "$v" ] || v="$(printf '%s\n' "$b" | sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,3}).*/\1/p' | head -n1)"
  printf '%s\n' "${v:-0}"
}

version_is_older() {
  python3 - "$1" "$2" <<'PY'
import sys, re
def norm(v):
    v = (v or "").strip()
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

first_token() { set -- $1; printf '%s' "${1:-}"; }

ssh_login_ok() {
  sshpass -p "$3" ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 -tt "$2@$1" "exit" >/dev/null 2>&1
}

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
  return $?
}

# ---- Cockpit link helpers ----
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

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

# ---- DNS helpers ----
validate_dns_servers() {
  command -v dig >/dev/null 2>&1 || {
    dialog --no-shadow --backtitle "$BACKTITLE" --title "Missing dependency" \
      --msgbox "Missing: dig (bind-utils). Install it and re-run." 7 70
    return 1
  }

  DNS_PRIMARY="${DNS_PRIMARY:-$REPORT_DNS_PRIMARY}"
  DNS_SECONDARY="${DNS_SECONDARY:-$REPORT_DNS_SECONDARY}"

  _prompt_ip() {
    title="$1"; def="$2"
    while :; do
      dlg --clear --backtitle "$BACKTITLE" --title "$title" \
          --inputbox "Enter a valid DNS server IP address:" 8 "$W_DEF" "$def"
      rc=$?
      [ $rc -eq 0 ] || { clear; return 1; }
      val="$(trim "${DOUT:-}")"
      if [ -n "$val" ] && is_valid_ip "$val"; then
        OUT_IP="$val"
        return 0
      fi
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Invalid IP" \
        --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
    done
  }

  _check_one_dns() {
    srv="$1"
    out="$(dig +time=3 +tries=1 +noall +answer google.com @"$srv" 2>&1)"
    echo "$out" | awk '/^[^;].*[[:space:]](A|AAAA)[[:space:]][0-9a-fA-F:.]+$/ {print $NF; ok=1; exit} END{exit ok?0:1}'
  }

  while :; do
    OUT_IP=""; _prompt_ip "DNS — Primary (required)"   "$DNS_PRIMARY"   || return 1
    DNS_PRIMARY="$OUT_IP"

    OUT_IP=""; _prompt_ip "DNS — Secondary (required)" "$DNS_SECONDARY" || return 1
    DNS_SECONDARY="$OUT_IP"

    dlg --backtitle "$BACKTITLE" --title "Testing DNS" --infobox \
"Resolving google.com via:
  Primary  : $DNS_PRIMARY
  Secondary: $DNS_SECONDARY" 7 "$W_DEF"
    sleep 0.6

    P_ANS="$(_check_one_dns "$DNS_PRIMARY")"; P_OK=$?
    S_ANS="$(_check_one_dns "$DNS_SECONDARY")"; S_OK=$?

    if [ $P_OK -eq 0 ] && [ $S_OK -eq 0 ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Validation" --msgbox \
"google.com resolved successfully:

  Primary   ($DNS_PRIMARY): ${P_ANS}
  Secondary ($DNS_SECONDARY): ${S_ANS}

These are *fallback* resolvers only." 12 "$W_DEF"
      export DNS_PRIMARY DNS_SECONDARY
      return 0
    fi

    dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS Check Failed" --yesno \
"DNS test results for google.com:

  Primary   ($DNS_PRIMARY): ${P_ANS:-FAILED}
  Secondary ($DNS_SECONDARY): ${S_ANS:-FAILED}

Re-enter the DNS servers?
  • Yes = re-enter both
  • No  = keep these values and continue" 16 "$W_DEF"
    case $? in
      0) continue ;;
      1) export DNS_PRIMARY DNS_SECONDARY; return 0 ;;
      *) return 1 ;;
    esac
  done
}

# ---- Firmware Recovery Helper ----
firmware_recovery_menu() {
  _title="$1"
  _msg="$2"

  while :; do
    CH="$(dialog --clear --no-shadow --backtitle "$BACKTITLE" --title "$_title" \
      --menu "$_msg

Choose an action:" 18 "$W_WIDE" 8 \
      1 "Upload firmware now (open Cockpit link)" \
      2 "Rescan firmware directory" \
      3 "Re-open firmware selection" \
      0 "Exit setup" \
      3>&1 1>&2 2>&3)"
    rc=$?
    clear
    [ $rc -eq 0 ] || return 3

    case "$CH" in
      1) print_cockpit_link_and_wait; return 1 ;;
      2) return 1 ;;
      3) return 2 ;;
      0) return 3 ;;
    esac
  done
}

# ---- Bible/Model helpers ----
bible_lookup_pid() {
  pid="$1"
  [ -r "$BIBLE_JSON" ] || return 1
  jq -r --arg pid "$pid" '
    .families[]
    | select(.models[]? == $pid)
    | "\(.family)|\(.min_iosxe)|\(.image_type)|\(.image_train)"
  ' "$BIBLE_JSON" 2>/dev/null | head -n1
}

bible_train_meta() {
  itype="$1"
  [ -r "$BIBLE_JSON" ] || return 1
  jq -r --arg t "$itype" '
    .image_trains[$t] // empty
    | "\(.train)|\(.filename_regex)"
  ' "$BIBLE_JSON" 2>/dev/null | head -n1
}

show_required_trains_from_latest_report() {
  [ -r "$FIRMWARE_REPORT_JSON" ] || return 0

  tmp="$(mktemp)"
  jq -r '
    map(select(.status=="BELOW_REQUIRED"))
    | .[]
    | "\(.ip)|\(.hostname)|\(.pid)|\(.current_iosxe)|\(.required_min_iosxe)"
  ' "$FIRMWARE_REPORT_JSON" >"$tmp" 2>/dev/null || { rm -f "$tmp"; return 0; }

  [ -s "$tmp" ] || { rm -f "$tmp"; return 0; }

  need_lite=0
  need_universal=0
  details=""

  while IFS='|' read -r ip host pid cur reqmin; do
    meta="$(bible_lookup_pid "$pid")"
    if [ -z "$meta" ]; then
      details="${details}\n- ${ip} (${host}) PID=${pid} current=${cur} needs>=${reqmin}  => UNKNOWN (PID not in bible)"
      continue
    fi

    fam="$(printf '%s' "$meta" | cut -d'|' -f1)"
    bmin="$(printf '%s' "$meta" | cut -d'|' -f2)"
    itype="$(printf '%s' "$meta" | cut -d'|' -f3)"
    itrain="$(printf '%s' "$meta" | cut -d'|' -f4)"

    details="${details}\n- ${ip} (${host}) PID=${pid} fam='${fam}' current=${cur} needs>=${reqmin}  => ${itype}/${itrain} (bible min ${bmin})"

    case "$itype" in
      LITE) need_lite=1 ;;
      UNIVERSAL) need_universal=1 ;;
    esac
  done <"$tmp"
  rm -f "$tmp"

  msg="Firmware requirements (actionable)

We detected device(s) that are BELOW_REQUIRED in:
  $FIRMWARE_REPORT_DIR

Download the following IOS-XE image train(s) before continuing:

"

  if [ $need_universal -eq 1 ]; then
    tm="$(bible_train_meta "UNIVERSAL")"
    trn="$(printf '%s' "$tm" | cut -d'|' -f1)"
    msg="${msg}• UNIVERSAL: ${trn}  (examples: Cat9300/C9500/C9600 families)\n"
  fi

  if [ $need_lite -eq 1 ]; then
    tm="$(bible_train_meta "LITE")"
    trn="$(printf '%s' "$tm" | cut -d'|' -f1)"
    msg="${msg}• LITE: ${trn}  (examples: C9200/C9200L/C9200CX)\n"
  fi

  msg="${msg}

Details:${details}

Reminder:
- Always verify Cisco's current recommended release for your platform.
- This wizard enforces your local bible + scan results."

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Firmware Needed (from latest scan)" \
    --msgbox "$(printf '%b' "$msg")" 26 "$W_WIDE"
}

# ---- Post-selection checks ----
verify_selected_firmware_files_exist() {
  missing=""

  for f in $FW_CAT9K_FILES $FW_CAT9K_LITE_FILES; do
    [ -n "$f" ] || continue
    if [ ! -s "$FIRMWARE_DIR/$f" ]; then
      missing="${missing}\n  - $FIRMWARE_DIR/$f"
    fi
  done

  [ -z "$missing" ] && return 0

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Selected firmware missing or empty" --yesno \
"One or more selected firmware files is missing (or zero bytes):${missing}

Go back and re-select / upload again?
  • Yes = go back
  • No  = continue anyway" 16 "$W_WIDE"
  [ $? -eq 0 ] && return 1 || return 0
}

warn_if_missing_required_train_selection() {
  [ -r "$FIRMWARE_REPORT_JSON" ] || return 0

  need_lite=0
  need_universal=0

  tmp="$(mktemp)"
  jq -r 'map(select(.status=="BELOW_REQUIRED")) | .[] | "\(.pid)"' "$FIRMWARE_REPORT_JSON" >"$tmp" 2>/dev/null || {
    rm -f "$tmp"; return 0;
  }

  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    meta="$(bible_lookup_pid "$pid")"
    [ -n "$meta" ] || continue
    itype="$(printf '%s' "$meta" | cut -d'|' -f3)"
    case "$itype" in
      LITE) need_lite=1 ;;
      UNIVERSAL) need_universal=1 ;;
    esac
  done <"$tmp"
  rm -f "$tmp"

  miss=""
  [ $need_universal -eq 1 ] && [ -z "$FW_CAT9K_FILES" ]      && miss="${miss}\n  - UNIVERSAL (cat9k_iosxe)"
  [ $need_lite      -eq 1 ] && [ -z "$FW_CAT9K_LITE_FILES" ] && miss="${miss}\n  - LITE (cat9k_lite_iosxe)"

  [ -z "$miss" ] && return 0

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Firmware selection doesn't match this deployment" --yesno \
"Based on BELOW_REQUIRED devices in the latest scan, your selections look incomplete.

You did NOT select:${miss}

Select/upload the missing train(s) now?
  • Yes = return to firmware selection
  • No  = continue anyway (not recommended)" 18 "$W_WIDE"

  [ $? -eq 0 ] && return 1 || return 0
}

check_selected_firmware_covers_report() {
  [ -s "$FIRMWARE_REPORT_JSON" ] || return 0

  tmp="$(mktemp)"
  python3 - "$FIRMWARE_REPORT_JSON" "$FW_CAT9K_FILES" "$FW_CAT9K_LITE_FILES" >"$tmp" <<'PY'
import json, sys, re

report_path=sys.argv[1]
sel_univ=(sys.argv[2] or "").split()
sel_lite=(sys.argv[3] or "").split()

def norm(v):
    v = (v or "").strip()
    v = re.sub(r'[^0-9.]', '', v)
    if not v: v="0"
    parts=[int(p) for p in v.split('.') if p]
    while len(parts)<3: parts.append(0)
    return parts[:3]

def version_from_name(name):
    b=name.lower()
    m=re.search(r'iosxe\.([0-9]+(\.[0-9]+){1,4})', b)
    if m: return m.group(1)
    m=re.search(r'[^0-9]([0-9]{1,2}(\.[0-9]+){1,3})', b)
    return m.group(1) if m else "0"

sel_best={"cat9k_iosxe":"0","cat9k_lite_iosxe":"0"}
for f in sel_univ:
    v=version_from_name(f)
    if norm(v) > norm(sel_best["cat9k_iosxe"]): sel_best["cat9k_iosxe"]=v
for f in sel_lite:
    v=version_from_name(f)
    if norm(v) > norm(sel_best["cat9k_lite_iosxe"]): sel_best["cat9k_lite_iosxe"]=v

data=json.load(open(report_path))

req_min={}
by_train_hosts={}
for r in data:
    train=r.get("required_image_train") or "unknown"
    need=str(r.get("required_min_iosxe") or "0")
    req_min[train]=max(req_min.get(train,"0"), need, key=lambda x:norm(x))
    by_train_hosts.setdefault(train, []).append(r)

warn_lines=[]
for train, need in sorted(req_min.items()):
    picked=sel_best.get(train,"0")
    if norm(picked) < norm(need):
        warn_lines.append((train, need, picked))

if not warn_lines:
    print("OK")
    sys.exit(0)

print("WARN")
print("Your selected firmware does NOT cover the required minimum for at least one train:")
for train,need,picked in warn_lines:
    print(f"  - {train}: required >= {need} ; best selected = {picked}")
print("")
print("Affected devices (from firmware report):")
for train,need,picked in warn_lines:
    for r in by_train_hosts.get(train, []):
        ip=r.get("ip","?")
        hn=r.get("hostname","?")
        pid=r.get("pid","?")
        cur=r.get("current_iosxe","?")
        st=r.get("status","?")
        req=str(r.get("required_min_iosxe") or "?")
        print(f"  - {ip:15}  {hn:18}  {pid:14}  current {cur:8}  need >= {req}  status={st}")
PY

  status="$(head -n1 "$tmp" 2>/dev/null || true)"
  if [ "$status" = "OK" ]; then
    rm -f "$tmp"
    return 0
  fi

  dialog --clear --backtitle "$BACKTITLE" --title "Firmware selection mismatch" \
    --textbox "$tmp" 22 "$W_WIDE"

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Go back and re-select?" --yesno \
"At least one train requires a higher IOS-XE minimum than what you selected.

Go back and re-select firmware files now?
  • Yes = return to firmware selection
  • No  = continue anyway (not recommended)" 14 "$W_WIDE"

  rc=$?
  rm -f "$tmp"
  [ $rc -eq 0 ] && return 1
  return 0
}

# ---- UI sizing (must be defined before dialogs that use W_DEF/W_WIDE) ----
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
# REQUIRED: Firmware discovery scan must exist first (cloud_firmware_report.env)
# - If missing, we POP A WINDOW explaining why, then run firmware_scan.sh.
###############################################################################
ensure_firmware_discovery_scan() {
  # Must have env file; JSON is strongly expected too.
  while :; do
    [ -s "$FIRMWARE_REPORT_ENV" ] && break

    dialog --no-shadow --backtitle "$BACKTITLE" --title "Firmware discovery scan required" --yesno \
"This Setup Wizard requires a firmware discovery scan BEFORE you can continue.

The scan creates:
  • $FIRMWARE_REPORT_ENV
  • $FIRMWARE_REPORT_JSON
  • $FIRMWARE_REPORT_SUMMARY_TXT

Missing:
  $FIRMWARE_REPORT_ENV

Run the discovery scan now (firmware_scan.sh)?" 18 "$W_WIDE"

    rc=$?
    clear
    [ $rc -eq 0 ] || return 1

    if [ ! -f "$FIRMWARE_SCAN_SCRIPT" ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Not Found" --msgbox \
"Cannot find the discovery scan script:
  $FIRMWARE_SCAN_SCRIPT

Fix this path and re-run setupwizard." 10 "$W_WIDE"
      clear
      return 1
    fi

    dialog --no-shadow --backtitle "$BACKTITLE" --title "Running discovery scan" --infobox \
"Starting firmware_scan.sh…

This collects inventory and writes the firmware report used by this wizard." 8 "$W_WIDE"
    sleep 0.8

    clear
    sh "$FIRMWARE_SCAN_SCRIPT"
    scan_rc=$?

    # Accept common "non-fatal" codes your scan may use.
    case "$scan_rc" in
      0|1|130|143|255) : ;;
      *)
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Discovery scan error" --msgbox \
"firmware_scan.sh exited with status: $scan_rc

We will check if the report file was still created.
If not, you can re-run the scan from the prompt." 12 "$W_WIDE"
        ;;
    esac

    # If it still didn't produce the env, loop and ask again.
    if [ ! -s "$FIRMWARE_REPORT_ENV" ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Scan did not produce report" --yesno \
"The scan did not create (or left empty):
  $FIRMWARE_REPORT_ENV

Troubleshooting:
  • Run: sh $FIRMWARE_SCAN_SCRIPT
  • Confirm it writes to: $FIRMWARE_REPORT_DIR
  • Check permissions under /root/.cloud_admin

Try running the scan again now?" 16 "$W_WIDE"
      rc=$?
      clear
      [ $rc -eq 0 ] || return 1
      continue
    fi

    # Optional: if summary exists, show it once (nice UX).
    if [ -s "$FIRMWARE_REPORT_SUMMARY_TXT" ]; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "Discovery scan summary" \
        --textbox "$FIRMWARE_REPORT_SUMMARY_TXT" 22 "$W_WIDE"
    fi

    break
  done

  return 0
}

ensure_firmware_discovery_scan || exit 1

###############################################################################
# Pre-populate wizard defaults from cloud_firmware_report.env
###############################################################################
# shellcheck disable=SC1090
. "$FIRMWARE_REPORT_ENV" 2>/dev/null || true

REPORT_DISCOVERY_MODE="${DISCOVERY_MODE:-}"
REPORT_DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
REPORT_DISCOVERY_IPS="${DISCOVERY_IPS:-}"
REPORT_SSH_USERNAME="${SSH_USERNAME:-}"
REPORT_SSH_PASSWORD="${SSH_PASSWORD:-}"
REPORT_SSH_TEST_IP="${SSH_TEST_IP:-}"
REPORT_ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"
REPORT_DNS_PRIMARY="${DNS_PRIMARY:-}"
REPORT_DNS_SECONDARY="${DNS_SECONDARY:-}"

[ -n "$REPORT_DISCOVERY_MODE" ] || REPORT_DISCOVERY_MODE="scan"
REPORT_NETS_LINES="$(printf '%s' "${REPORT_DISCOVERY_NETWORKS:-}" | tr ',' '\n')"
REPORT_IPS_LINES="$(printf '%s' "${REPORT_DISCOVERY_IPS:-}" | tr ' ' '\n')"

###############################################################################
# 0) WELCOME
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
  8) Provide VLAN SVI for 'ip http client source-interface Vlan<N>'
  9) Select IOS XE firmware image(s) (MULTI-select supported)
 10) Set the minimum IOS XE version required for hybrid onboarding
 11) Save all choices to ${ENV_FILE} and show a summary

Have these ready:
  • Target networks/IPs
  • SSH username and password (must land at privilege 15 — prompt '#')
  • ENABLE password (required; used later for Meraki claim)
  • Meraki Dashboard API key
  • Two DNS server IPs (fallbacks)
  • VLAN ID (1–4094) for HTTP client source-interface
  • Firmware file(s) in ${FIRMWARE_DIR} or upload to ${COCKPIT_UPLOAD_DIR}" \
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
[ $rc -eq 0 ] || { clear; exit 1; }

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
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
done

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH switch password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
  [ $? -eq 0 ] || { clear; exit 1; }
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
  dlg --backtitle "$BACKTITLE" --title "Testing SSH" \
      --infobox "Testing SSH login to ${SSH_TEST_IP} as ${SSH_USERNAME}…" 6 "$W_DEF"
  sleep 1
  if ssh_login_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD"; then
    dlg --backtitle "$BACKTITLE" --title "SSH Test" --infobox "Login OK to ${SSH_TEST_IP}." 5 "$W_DEF"
    sleep 1
    break
  fi

  dlg --backtitle "$BACKTITLE" --title "Login Failed" --yesno "Could not log in. Re-enter username and password?" 8 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }

  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" \
      --inputbox "Enter SSH username:" 8 "$W_DEF" "$SSH_USERNAME"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"

  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF" "$SSH_PASSWORD"
  [ $? -eq 0 ] || { clear; exit 1; }
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

Hybrid onboarding requires a user that logs in at privilege 15 (prompt ends with #)
without entering 'enable' first.

Please use an account with privilege 15 and re-run the setup." 16 "$W_DEF"
  clear
  exit 1
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
We'll verify it now so it can be sent during claim process." \
      10 "$W_DEF" "$ENABLE_PASSWORD"
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
  dlg --clear --backtitle "$BACKTITLE" --title "Meraki API Key" --insecure --passwordbox \
"Paste your Meraki Dashboard API key:" 8 "$W_DEF"
  rc=$?; [ $rc -eq 1 ] && { clear; exit 1; }
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 "$W_DEF"; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 "$W_DEF"; [ $? -eq 0 ] && break
done

###############################################################################
# 3c) DNS — REQUIRED
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "DNS Servers" --msgbox \
"Enter two DNS server IP addresses.

We won't overwrite working DNS on switches.

These DNS servers are used only as fallbacks:
  • When a switch has no DNS configured
  • For our own lookups during setup." 12 "$W_DEF"

if ! validate_dns_servers; then
  dialog --no-shadow --backtitle "$BACKTITLE" --title "DNS step failed" \
    --msgbox "DNS validation was cancelled or failed. Exiting setup." 7 70
  clear
  exit 1
fi

###############################################################################
# 3d) VLAN SVI — MANDATORY
###############################################################################
HTTP_CLIENT_VLAN_ID=""
HTTP_CLIENT_SOURCE_IFACE=""
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
# 3e) Firmware report reminder (what to download)
###############################################################################
show_required_trains_from_latest_report

###############################################################################
# 4) FIRMWARE PICK (MULTI) — sorted by version (ascending)
###############################################################################
mkdir -p "$FIRMWARE_DIR"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%T@|%s|%f\n' 2>/dev/null
}

build_sorted_checklist_args() {
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

  sort -t'|' -k1,1V -k2,2 "$tmp" | awk -F'|' '{ printf "%s\n-\noff\n", $2 }'
  rm -f "$tmp"
}

resolve_meta() {
  name="$1"; infile="$2"
  while IFS='|' read -r _mt _sz _nm; do
    [ "$_nm" = "$name" ] && { printf '%s|%s\n' "$_sz" "$FIRMWARE_DIR/$_nm"; return; }
  done <"$infile"
  printf '|\n'
}

FW_CAT9K_FILES=""
FW_CAT9K_LITE_FILES=""
FW_CAT9K_FILE=""
FW_CAT9K_LITE_FILE=""

FW_CAT9K_PATH=""; FW_CAT9K_SIZE_BYTES=""; FW_CAT9K_SIZE_H=""; FW_CAT9K_VERSION=""
FW_CAT9K_LITE_PATH=""; FW_CAT9K_LITE_SIZE_BYTES=""; FW_CAT9K_LITE_SIZE_H=""; FW_CAT9K_LITE_VERSION=""

while :; do
  tmp_lines="$(mktemp)"
  list_files | sort -nr >"$tmp_lines"

  if [ ! -s "$tmp_lines" ]; then
    CH=$(dialog --clear --backtitle "$BACKTITLE" --title "Firmware Upload Needed" \
        --menu "No firmware images were found in:\n  $FIRMWARE_DIR\n\nUpload in Cockpit, then choose Rescan." 14 "$W_DEF" 6 \
        1 "Show clickable Cockpit link (opens /root/IOS-XE_images)" \
        2 "Rescan directory" \
        0 "Exit setup" 3>&1 1>&2 2>&3) || { clear; rm -f "$tmp_lines"; exit 1; }
    case "$CH" in
      1) print_cockpit_link_and_wait; rm -f "$tmp_lines"; continue ;;
      2) rm -f "$tmp_lines"; continue ;;
      0) clear; rm -f "$tmp_lines"; exit 1 ;;
    esac
  fi

  U_FILE="$(mktemp)"; build_sorted_checklist_args universal "$tmp_lines" >"$U_FILE"
  L_FILE="$(mktemp)"; build_sorted_checklist_args lite      "$tmp_lines" >"$L_FILE"

  if [ -s "$U_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
      --checklist "Select one or more Cat9k (9300/9400/9500/9600) images.\nUse SPACE to toggle, ENTER to accept." \
      18 "$W_WIDE" 10 $(tr '\n' ' ' <"$U_FILE")
    if [ $? -eq 0 ]; then
      FW_CAT9K_FILES="$(printf '%s' "${DOUT:-}" | sed 's/"//g' | awk '{$1=$1}1')"
    fi
  fi

  if [ -s "$L_FILE" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
      --checklist "Select one or more Cat9k-Lite (9200/9200CX/etc) images.\nUse SPACE to toggle, ENTER to accept." \
      18 "$W_WIDE" 10 $(tr '\n' ' ' <"$L_FILE")
    if [ $? -eq 0 ]; then
      FW_CAT9K_LITE_FILES="$(printf '%s' "${DOUT:-}" | sed 's/"//g' | awk '{$1=$1}1')"
    fi
  fi

  rm -f "$U_FILE" "$L_FILE"

  if [ -z "$FW_CAT9K_FILES$FW_CAT9K_LITE_FILES" ]; then
    G_TMP="$(mktemp)"
    while IFS='|' read -r _mt _sz nm; do
      [ -z "$nm" ] || printf '%s\n%s\n' "$nm" "-" >>"$G_TMP"
    done <"$tmp_lines"
    if [ -s "$G_TMP" ]; then
      # shellcheck disable=SC2086
      dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Generic" \
          --menu "Pick an image to proceed:" 22 "$W_WIDE" 16 $(tr '\n' ' ' <"$G_TMP")
      [ $? -eq 0 ] && FW_CAT9K_FILES="$(trim "${DOUT:-}")"
    fi
    rm -f "$G_TMP"
  fi

  [ -n "$FW_CAT9K_FILES" ]      && FW_CAT9K_FILE="$(first_token "$FW_CAT9K_FILES")"
  [ -n "$FW_CAT9K_LITE_FILES" ] && FW_CAT9K_LITE_FILE="$(first_token "$FW_CAT9K_LITE_FILES")"

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

  rm -f "$tmp_lines"

  # 1) Integrity
  if ! verify_selected_firmware_files_exist; then
    firmware_recovery_menu "Firmware selection problem" \
"One or more selected files are missing or empty.

If you need to upload an image first, choose:
  Upload firmware now (Cockpit link)."
    case $? in
      1|2) continue ;;
      *) clear; exit 1 ;;
    esac
  fi

  # 2) Train requirement vs BELOW_REQUIRED
  if ! warn_if_missing_required_train_selection; then
    firmware_recovery_menu "Missing required firmware train" \
"Your selection does not include all required trains for this deployment.

If the required image is not present yet, upload it now."
    case $? in
      1|2) continue ;;
      *) clear; exit 1 ;;
    esac
  fi

  # 3) Version coverage vs required mins
  if ! check_selected_firmware_covers_report; then
    firmware_recovery_menu "Firmware minimum not met" \
"The selected firmware does not meet the required minimum for at least one train.

You may need to upload a newer image, then rescan."
    case $? in
      1|2) continue ;;
      *) clear; exit 1 ;;
    esac
  fi

  break
done

###############################################################################
# 4a) Minimum IOS-XE requirements (DERIVED from BIBLE via firmware_report.json)
###############################################################################
derive_required_mins_from_report() {
  REQ_MIN_UNIVERSAL=""
  REQ_MIN_LITE=""

  [ -s "$FIRMWARE_REPORT_JSON" ] || return 0

  out="$(python3 - "$FIRMWARE_REPORT_JSON" <<'PY'
import json, re, sys
def norm(v):
    v=(v or "").strip()
    v=re.sub(r'[^0-9.]','',v)
    if not v: v="0"
    parts=[int(p) for p in v.split('.') if p]
    while len(parts)<3: parts.append(0)
    return parts[:3]
data=json.load(open(sys.argv[1]))
best={"UNIVERSAL":"0","LITE":"0"}
for r in data:
    it=str(r.get("required_image_type") or "").strip().upper()
    v=str(r.get("required_min_iosxe") or "").strip()
    if it in best and v and norm(v) > norm(best[it]):
        best[it]=v
print("UNIVERSAL=" + ("" if best["UNIVERSAL"]=="0" else best["UNIVERSAL"]))
print("LITE=" + ("" if best["LITE"]=="0" else best["LITE"]))
PY
  )"

  REQ_MIN_UNIVERSAL="$(printf '%s\n' "$out" | awk -F= '$1=="UNIVERSAL"{print $2}')"
  REQ_MIN_LITE="$(printf '%s\n' "$out" | awk -F= '$1=="LITE"{print $2}')"
}

maybe_show_derived_mins_screen() {
  [ -s "$FIRMWARE_REPORT_JSON" ] || return 0
  [ -n "$REQ_MIN_UNIVERSAL$REQ_MIN_LITE" ] || return 0

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Minimum IOS-XE requirements" --yesno \
"These minimums are derived from your BIBLE + latest firmware scan (no manual input).

View them now?" 10 "$W_DEF" || return 0

  msg="Minimum IOS-XE required (derived):\n\n"
  [ -n "$REQ_MIN_UNIVERSAL" ] && msg="${msg}  • UNIVERSAL (cat9k_iosxe)      >= ${REQ_MIN_UNIVERSAL}\n"
  [ -n "$REQ_MIN_LITE" ]      && msg="${msg}  • LITE      (cat9k_lite_iosxe) >= ${REQ_MIN_LITE}\n"

  dialog --no-shadow --backtitle "$BACKTITLE" --title "Derived minimums" \
    --msgbox "$(printf '%b' "$msg")" 14 "$W_WIDE"
}

derive_required_mins_from_report
maybe_show_derived_mins_screen

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
export HTTP_CLIENT_VLAN_ID HTTP_CLIENT_SOURCE_IFACE
export FW_CAT9K_FILES FW_CAT9K_FILE FW_CAT9K_PATH FW_CAT9K_SIZE_BYTES FW_CAT9K_SIZE_H FW_CAT9K_VERSION
export FW_CAT9K_LITE_FILES FW_CAT9K_LITE_FILE FW_CAT9K_LITE_PATH FW_CAT9K_LITE_SIZE_BYTES FW_CAT9K_LITE_SIZE_H FW_CAT9K_LITE_VERSION
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
  printf 'export HTTP_CLIENT_VLAN_ID=%q\n' "$HTTP_CLIENT_VLAN_ID"
  printf 'export HTTP_CLIENT_SOURCE_IFACE=%q\n' "$HTTP_CLIENT_SOURCE_IFACE"
  printf 'export MIN_IOSXE_REQUIRED=%q\n' "$MIN_IOSXE_REQUIRED"
  printf 'export DISC_SCAN_ROOT=%q\n' "$DISC_SCAN_ROOT"
  printf 'export DISCOVERY_RUN_ID=%q\n' "$DISCOVERY_RUN_ID"
  printf 'export DISCOVERY_RUN_DIR=%q\n' "$DISCOVERY_RUN_DIR"

  [ -n "$FW_CAT9K_FILES" ] && printf 'export FW_CAT9K_FILES=%q\n' "$FW_CAT9K_FILES"
  [ -n "$FW_CAT9K_LITE_FILES" ] && printf 'export FW_CAT9K_LITE_FILES=%q\n' "$FW_CAT9K_LITE_FILES"

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
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() {
  s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}')
  if [ "$n" -le 4 ]; then printf '****'
  else printf "%0.s*" $(seq 1 $((n-4))); printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}

PW_MASK="$(mask "$SSH_PASSWORD")"
API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
SVI_SUMMARY="$(printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID")"
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

HTTP client source-interface (required):
  ${SVI_SUMMARY}
"

[ -n "$FW_CAT9K_FILES" ] && summary="${summary}
Cat9k (universal) selected:
  ${FW_CAT9K_FILES}
"
[ -n "$FW_CAT9K_LITE_FILES" ] && summary="${summary}
Cat9k-Lite (9200) selected:
  ${FW_CAT9K_LITE_FILES}
"

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 40 90
clear
exit 0