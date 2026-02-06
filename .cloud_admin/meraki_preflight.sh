#!/usr/bin/env bash
# meraki_cloud_preflight.sh — Preflight + Auto-Fix for IOS-XE -> Meraki Cloud Management conversion
#
# What we do:
#   - Precheck inventory: login, hostname, model, ios, install mode
#   - Enforce minimum IOS-XE per model via cloud_models.json
#   - Run "show meraki compatibility" and parse COMPAT status (stack-aware)
#   - AUTO-FIX what we safely can:
#       * DNS (ip name-server) from meraki_discovery.env
#       * ip domain lookup (enable if disabled)
#       * ip http client source-interface <iface>  (from meraki_discovery.env)
#   - Connectivity tests:
#       * ping dashboard.meraki.com
#       * ping google.com
#
# Outputs:
#   runs/preflight/latest.csv  (and latest.env/latest symlinks)
#   devlogs/<ip>.session.log (facts + fixes + verification)
#
# Usage:
#   ./meraki_cloud_preflight.sh              # preflight (includes auto-fix)
#   ./meraki_cloud_preflight.sh preflight    # same as default
#   ./meraki_cloud_preflight.sh fix-dns      # apply DNS/domain lookup fixes using latest.csv
#   ./meraki_cloud_preflight.sh fix-http     # apply HTTP client source-interface fixes using latest.csv
#
# Notes:
#   - Only devices eligible per discovery gates (ssh=true, login=true, blacklisted!=true) are selectable.
#   - Auto-fix only runs if the needed env values exist (DNS_PRIMARY/SECONDARY, HTTP_CLIENT_SOURCE_IFACE).

set -o pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need jq; need awk; need sed; need grep; need ssh; need timeout; need flock
command -v sshpass >/dev/null 2>&1 || true
command -v dialog  >/dev/null 2>&1 || true

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit}"
DOPTS=(--no-shadow --backtitle "$BACKTITLE")
DOUT=""
dlg(){ local t; t="$(mktemp)"; dialog "${DOPTS[@]}" "$@" 2>"$t"; local rc=$?; DOUT=""; [[ -s "$t" ]] && DOUT="$(<"$t")"; rm -f "$t"; return $rc; }

__deq(){ local s="${1-}"; s="${s//\\!/!}"; s="${s//\\;/;}"; s="${s//\\ / }"; s="${s//\\\\/\\}"; printf '%s' "$s"; }
trim(){ sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }
now(){ date +%H:%M:%S; }

append_csv(){
  local csv="$1"; shift
  local line="$*"
  { flock -x 9
    printf '%s\n' "$line" >&9
  } 9>>"$csv"
}

DISC_ENV="$SCRIPT_DIR/meraki_discovery.env"
DISC_JSON="$SCRIPT_DIR/discovery_results.json"
SEL_ENV="$SCRIPT_DIR/selected_upgrade.env"
SEL_JSON="$SCRIPT_DIR/selected_upgrade.json"

CLOUD_MODELS_JSON_DEFAULT="$SCRIPT_DIR/cloud_models.json"
CLOUD_MODELS_JSON="${CLOUD_MODELS_JSON:-$CLOUD_MODELS_JSON_DEFAULT}"

# Flag file used by subsequent scripts to know if preflight is clean
PREFLIGHT_OK_FLAG="$SCRIPT_DIR/preflight.ok"

# ---------- UI (tailbox + gauge) ----------
DIALOG=0; command -v dialog >/dev/null 2>&1 && DIALOG=1
STATUS_FILE=""; GAUGE_PIPE=""; GAUGE_FD=""; DPID=""; MAIN=$$
UI_TITLE="Preflight"

ui_calc(){
  local L=24 C=80
  read -r L C < <(stty size 2>/dev/null || echo "24 80")
  ((L<20)) && L=20
  ((C<80)) && C=80
  local TOP_PAD=2 BOT_PAD=2 SIDE_PAD=2 SPACE=1
  GAUGE_H=6
  TAIL_W=$(( C - SIDE_PAD*2 ))
  GAUGE_W=$TAIL_W
  TAIL_H=$(( L - TOP_PAD - BOT_PAD - GAUGE_H - SPACE - 2 ))
  (( TAIL_H < 8 )) && TAIL_H=8
  TAIL_ROW=$TOP_PAD
  GAUGE_ROW=$(( TOP_PAD + TAIL_H + SPACE ))
  GAUGE_COL=$SIDE_PAD
}

log(){
  printf '%s %s\n' "$(now)" "$1" | tee -a "$STATUS_FILE" >/dev/null
}

gauge(){
  local p="${1:-0}" m="${2:-Working…}"
  if ((DIALOG)) && [[ -n "${GAUGE_FD:-}" ]] && [[ -e "/proc/$MAIN/fd/$GAUGE_FD" ]]; then
    printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$GAUGE_FD" 2>/dev/null || true
  else
    echo "[progress] $p%% - $m"
  fi
}

ui_start(){
  STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"
  if (( !DIALOG )); then return; fi
  ui_calc
  GAUGE_PIPE="$(mktemp -u)"; mkfifo "$GAUGE_PIPE"; exec {GAUGE_FD}<>"$GAUGE_PIPE"
  (
    dialog --no-shadow --backtitle "$BACKTITLE" \
      --begin "$TAIL_ROW" "$GAUGE_COL" \
      --title "$UI_TITLE (run: $RUN_ID)" \
      --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
      --and-widget \
      --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Progress" \
      --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$GAUGE_PIPE"
  ) & DPID=$!
  sleep 0.15
  printf 'XXX\n1\nStarting…\nXXX\n' >&"$GAUGE_FD" 2>/dev/null || true
}

ui_stop(){
  [[ $$ -ne $MAIN ]] && return
  if ((DIALOG)); then
    printf 'XXX\n100\nDone.\nXXX\n' >&"$GAUGE_FD" 2>/dev/null || true
    exec {GAUGE_FD}>&- 2>/dev/null || true
    rm -f "$GAUGE_PIPE" 2>/dev/null || true
    kill "$DPID" 2>/dev/null || true
  fi
}

# ---------- SSH helpers ----------
build_ssh_arr(){
  local ip="$1"
  SSH_CMD=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=40 \
            -o ServerAliveInterval=10 -o ServerAliveCountMax=6 \
            -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group14-sha1 \
            -tt "${SSH_USERNAME}@${ip}")
  if [[ -n "${SSH_KEY_PATH-}" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD+=(-i "$SSH_KEY_PATH" -o BatchMode=yes)
  else
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" "${SSH_CMD[@]}" -o PreferredAuthentications=password,keyboard-interactive \
             -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)
  fi
}

is_priv15_for_ip(){
  local ip="$1" raw out ok=1
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  # Log that we're checking privilege
  log "[${ip}] checking privilege level…"

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    printf 'show privilege\r\n'; printf 'exit\r\n'
  } | timeout -k 5s 25s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"
  if grep -Eiq 'Current privilege level is[[:space:]]*15' "$out"; then
    ok=0
    log "[${ip}] privilege level 15 confirmed."
  else
    ok=1
    log "[${ip}] not at privilege 15 – will use enable."
  fi

  rm -f "$raw" "$out"
  return $ok
}

emit_enable(){
  printf 'enable\r\n'; sleep 0.2
  if [[ -n "${ENABLE_PASSWORD-}" ]]; then printf '%s\r\n' "$ENABLE_PASSWORD"; else printf '\r\n'; fi
  printf 'show privilege\r\n'; sleep 0.2
}

# ---------- Model + firmware rules helpers ----------
_extract_model_from_showver() {
  awk '
    BEGIN{IGNORECASE=1}
    $0 ~ /^[[:space:]]*Model[[:space:]]*number[[:space:]]*:[[:space:]]*/ {print $NF; exit}
    $0 ~ /^[[:space:]]*Model[[:space:]]*Name[[:space:]]*:[[:space:]]*/   {print $NF; exit}
    $0 ~ /^[[:space:]]*cisco[[:space:]]+C[0-9]+/                        {for(i=1;i<=NF;i++) if($i ~ /^C[0-9]+/) {print $i; exit}}
  ' | sed -E 's/[^A-Za-z0-9-].*$//'
}

shortver_from_string(){ awk 'match($0,/[0-9]+\.[0-9]+\.[0-9]+/){print substr($0,RSTART,RLENGTH)}'; }

ver_ge(){ # a >= b
  awk -v A="$1" -v B="$2" '
    function n(x){return (x==""?0:x)+0}
    BEGIN{
      split(A,a,"."); split(B,b,".");
      for(i=1;i<=4;i++){
        ai=n(a[i]); bi=n(b[i]);
        if(ai>bi){exit 0}
        if(ai<bi){exit 1}
      }
      exit 0
    }'
}

rules_for_model(){
  local model="$1"
  jq -r --arg m "$model" '
    .families[]
    | select(.models[]? == $m)
    | [.image_type, .min_iosxe, (.image_train // ""), (.family // "")]
    | @tsv
  ' "$CLOUD_MODELS_JSON" | head -n1
}

# ---------- Meraki compatibility parser (stack-aware) ----------
parse_meraki_compat(){
  local txt; txt="$(cat)"

  if [[ -z "$(trim "$txt")" ]]; then
    echo "unknown|no_output;"
    return 0
  fi

  if grep -Eiq '(Not[[:space:]]+Compatible|Incompatible|Unsupported)' <<<"$txt"; then
    echo "no|incompatible_marker_found;"
    return 0
  fi

  local ok="unknown"
  local notes=""

  if grep -Eiq 'Boot[[:space:]]+Mode' <<<"$txt"; then
    if grep -Eiq 'Boot[[:space:]]+Mode.*Compatible' <<<"$txt"; then
      ok="yes"
    else
      ok="no"; notes+="boot_mode_not_compatible;"
    fi
  else
    ok="unknown"; notes+="boot_mode_missing;"
  fi

  if ! awk 'BEGIN{IGNORECASE=1; rows=0}
          /^[[:space:]]*[0-9]+[[:space:]]+C[0-9]+/ {rows++}
          END{exit (rows>0)?0:1}' <<<"$txt"
  then
    notes+="no_switch_rows_detected;"
  fi

  [[ -z "$notes" ]] && notes="ok;"
  echo "${ok}|${notes}"
}

extract_meraki_compat_block(){
  local f="$1"
  awk '
    BEGIN{IGNORECASE=1; inblk=0}
    /(Meraki Cloud Management|Meraki Cloud Monitoring|Compatibility Check)[[:space:]]*:/ {inblk=1}
    inblk && match($0,/^[[:alnum:]_.:-]+[>#][[:space:]]*$/) {exit}
    inblk {print}
  ' "$f"
}

# ---------- Fix helpers (idempotent) ----------
apply_fixes_one(){
  local ip="$1" need_en="$2" dns_missing="$3" dl_disabled="$4" http_need="$5"
  local did_dns="no" did_dl="no" did_http="no" notes=""

  local have_dns_env=0; [[ -n "${DNS_PRIMARY:-}" || -n "${DNS_SECONDARY:-}" ]] && have_dns_env=1
  local have_http_env=0; [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]] && have_http_env=1

  if [[ "$dns_missing" != "yes" && "$dl_disabled" != "yes" && "$http_need" != "yes" ]]; then
    echo "no,no,no,"
    return 0
  fi

  local cfg=""
  if [[ "$dns_missing" == "yes" ]]; then
    if (( have_dns_env )); then
      [[ -n "${DNS_PRIMARY:-}"   ]] && cfg+="ip name-server ${DNS_PRIMARY}\n"
      [[ -n "${DNS_SECONDARY:-}" ]] && cfg+="ip name-server ${DNS_SECONDARY}\n"
      did_dns="yes"
    else
      notes+="dns_env_missing;"
    fi
  fi
  if [[ "$dl_disabled" == "yes" ]]; then
    cfg+="ip domain lookup\n"
    did_dl="yes"
  fi
  if [[ "$http_need" == "yes" ]]; then
    if (( have_http_env )); then
      cfg+="ip http client source-interface ${HTTP_CLIENT_SOURCE_IFACE}\n"
      did_http="yes"
    else
      notes+="http_client_env_missing;"
    fi
  fi

  if [[ -z "$cfg" ]]; then
    echo "${did_dns},${did_dl},${did_http},${notes}"
    return 0
  fi

  log "[${ip}] AUTO-FIX: applying config (dns:${did_dns} dl:${did_dl} http:${did_http})"
  local raw; raw="$(mktemp)"

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'configure terminal\r\n'
    while IFS= read -r line; do
      [[ -n "$line" ]] && printf '%s\r\n' "$line"
    done < <(printf "%b" "$cfg")
    printf 'end\r\n'
    printf 'write memory\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 180s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$raw"

  echo "${did_dns},${did_dl},${did_http},${notes}"
}

# =====================================================================
# PRE-FLIGHT (with auto-fix)
# =====================================================================
probe_one(){
  set +e
  local ip="$1" need_en=0 raw out

  local host model ios install_mode
  local req_type="" req_min="" req_train="" fam=""
  local meets_min="unknown"

  local meraki_ok="unknown" meraki_notes=""
  local dns_ok="no" domlkp="enabled"
  local http_client_ok="unknown" http_client_cur=""

  local ping_meraki="unknown" ping_google="unknown"
  local ready="no" notes=""

  local changed_dns="no" enabled_dl="no" changed_http="no" fix_notes=""

  # New: mgmt vs SVI routing flags
  local has_ip_routing="no" has_default_gw="no" has_svi_ip="no" has_mgmt_ip="no" mgmt_only_l3="no"

  log "[${ip}] CONNECT…"
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  # privilege check (logs its own progress)
  is_priv15_for_ip "$ip" || need_en=1

  # Log that we're about to collect facts
  log "[${ip}] collecting facts (show version, install, DNS, HTTP, Meraki compat, running-config)…"

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show version\r\n'
    printf 'show install summary\r\n'
    printf 'show running-config | include ^ip name-server\r\n'
    printf 'show running-config | include ^no ip domain lookup\r\n'
    printf 'show running-config | include ^ip domain lookup\r\n'
    printf 'show running-config | include ^ip http client source-interface\r\n'
    # Full running-config (for mgmt/SVI/default-gw analysis)
    printf 'show running-config\r\n'
    printf 'show meraki compatibility\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 210s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"
  mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$raw"

  host="$(awk 'match($0,/^([[:alnum:]_.:-]+)[>#][[:space:]]*$/,m){print m[1]; exit}' "$out")"
  [[ -z "$host" ]] && host="$(awk '/^hostname[[:space:]]+/{print $2; exit}' "$out")"
  [[ -z "$host" ]] && host="$ip"

  ios="$(awk '
    match($0,/Cisco IOS XE Software, Version[[:space:]]+([^ ,]+)/,m){print m[1]; exit}
    match($0,/Version[[:space:]]+([0-9]+\.[0-9]+(\.[0-9A-Za-z]+)?)/,m){print m[1]; exit}
  ' "$out")"
  ios="$(printf '%s\n' "$ios" | shortver_from_string)"

  install_mode="$(awk -F: 'BEGIN{IGNORECASE=1}/Running[[:space:]]+mode/ {gsub(/^[ \t]+/,"",$2); print toupper($2); exit}' "$out")"
  [[ -z "$install_mode" ]] && install_mode="$(grep -Eio '(INSTALL|BUNDLE)' "$out" | head -n1 | tr '[:lower:]' '[:upper:]')"

  model="$(_extract_model_from_showver < "$out")"

  if [[ -n "$model" && -f "$CLOUD_MODELS_JSON" ]]; then
    local r; r="$(rules_for_model "$model")"
    if [[ -n "$r" ]]; then
      req_type="$(cut -f1 <<<"$r")"
      req_min="$(cut -f2 <<<"$r")"
      req_train="$(cut -f3 <<<"$r")"
      fam="$(cut -f4 <<<"$r")"
      if [[ -n "$ios" && -n "$req_min" ]]; then
        if ver_ge "$ios" "$req_min"; then
          meets_min="yes"
        else
          meets_min="no"
          notes+="min_ios_fail(${req_min});"
        fi
      fi
    else
      notes+="model_not_in_rules(${model});"
    fi
  else
    notes+="no_model_or_rules;"
  fi

  # Basic DNS/domain/http parsing (from includes)
  grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$out" && dns_ok="yes" || dns_ok="no"
  grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$out" && domlkp="disabled" || domlkp="enabled"

  [[ "$dns_ok" == "yes" ]] || notes+="dns_missing;"
  [[ "$domlkp" == "enabled" ]] || notes+="domain_lookup_disabled;"

  http_client_cur="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*ip[[:space:]]+http[[:space:]]+client[[:space:]]+source-interface/ {print $NF; exit}' "$out")"
  if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
    if [[ -n "$http_client_cur" && "$http_client_cur" == "$HTTP_CLIENT_SOURCE_IFACE" ]]; then
      http_client_ok="yes"
    else
      http_client_ok="no"
      notes+="http_client_src_if_missing_or_wrong(${HTTP_CLIENT_SOURCE_IFACE});"
    fi
  else
    http_client_ok="unknown"
    notes+="http_client_src_if_env_missing;"
  fi

  # Meraki compatibility
  local compat_block
  compat_block="$(extract_meraki_compat_block "$out")"
  IFS='|' read -r meraki_ok meraki_notes <<<"$(printf '%s\n' "$compat_block" | parse_meraki_compat)"
  [[ "$meraki_ok" == "yes" ]] || notes+="compat_fail;"

  # -------- mgmt vs SVI routing analysis (from full running-config) --------
  # We treat output as including "show running-config" – section-aware parse.
  local _rip _rdg _rsvi _rmgmt
    read -r _rip _rdg _rsvi _rmgmt < <(awk '
    BEGIN{
      IGNORECASE=1
      has_ip_routing=0; has_default_gw=0; has_svi_ip=0; has_mgmt_ip=0;
      iface=""
    }

    # Global L3 bits
    /^[[:space:]]*ip[[:space:]]+routing([[:space:]]|$)/ {
      has_ip_routing=1
    }
    /^[[:space:]]*ip[[:space:]]+default-gateway[[:space:]]+([0-9]+\.){3}[0-9]+/ {
      has_default_gw=1
    }

    # Track which interface block we are in
    /^[[:space:]]*interface[[:space:]]+([A-Za-z0-9\/.]+)[[:space:]]*$/ {
      iface=$2
    }

    # Any "ip address ..." under an interface counts, including DHCP/negotiated
    /^[[:space:]]+ip[[:space:]]+address/ {
      if (iface ~ /^Vlan[0-9]+$/) {
        has_svi_ip=1
      }
      # Treat 0/x mgmt-style ports as OOB management
      else if (iface ~ /^(GigabitEthernet0\/|FastEthernet0\/|TenGigabitEthernet0\/|MgmtEthernet)/) {
        has_mgmt_ip=1
      }
    }

    END{
      printf "%d %d %d %d\n", has_ip_routing, has_default_gw, has_svi_ip, has_mgmt_ip
    }
  ' "$out")

  [[ "$_rip"  == "1" ]] && has_ip_routing="yes"
  [[ "$_rdg"  == "1" ]] && has_default_gw="yes"
  [[ "$_rsvi" == "1" ]] && has_svi_ip="yes"
  [[ "$_rmgmt" == "1" ]] && has_mgmt_ip="yes"
  # Log basic L3 posture for debugging
  log "[${ip}] routing view: ip_routing=${has_ip_routing} default_gw=${has_default_gw} svi_ip=${has_svi_ip} mgmt_ip=${has_mgmt_ip}"

  # Quick facts log so user sees movement
  log "[${ip}] facts: HOST=${host} MODEL=${model:-?} IOS=${ios:-?} MODE=${install_mode:-?} COMPAT=${meraki_ok} DNS=${dns_ok} DOMLKP=${domlkp} HTTP=${http_client_ok}"

  # -------- AUTO-FIX (best-effort) --------
  local need_dns_fix="no" need_dl_fix="no" need_http_fix="no"
  [[ "$dns_ok" != "yes" ]] && need_dns_fix="yes"
  [[ "$domlkp" == "disabled" ]] && need_dl_fix="yes"
  [[ "$http_client_ok" == "no" ]] && need_http_fix="yes"

  log "[${ip}] pre-fix status: need_dns_fix=${need_dns_fix} need_dl_fix=${need_dl_fix} need_http_fix=${need_http_fix}"

  if [[ "$need_dns_fix" == "yes" || "$need_dl_fix" == "yes" || "$need_http_fix" == "yes" ]]; then
    IFS=',' read -r changed_dns enabled_dl changed_http fix_notes <<<"$(apply_fixes_one "$ip" "$need_en" "$need_dns_fix" "$need_dl_fix" "$need_http_fix")"
    [[ "$changed_dns" == "yes" ]] && notes+="fixed_dns;"
    [[ "$enabled_dl"  == "yes" ]] && notes+="fixed_domain_lookup;"
    [[ "$changed_http" == "yes" ]] && notes+="fixed_http_client_src_if;"
    [[ -n "$fix_notes" ]] && notes+="${fix_notes}"
  fi

    # -------- RE-VERIFY + PINGS (with progress heartbeats) --------
  log "[${ip}] re-verifying config and running pings…"

  raw="$(mktemp)"; : > "$raw"

  # Run the verification + ping sequence in the background so we can
  # emit progress messages while the device is busy (DNS lookup / ping).
  (
    {
      printf '\r\nterminal length 0\r\nterminal width 511\r\n'
      (( need_en )) && emit_enable

      printf 'show running-config | include ^ip name-server\r\n'
      printf 'show running-config | include ^no ip domain lookup\r\n'
      printf 'show running-config | include ^ip domain lookup\r\n'
      printf 'show running-config | include ^ip http client source-interface\r\n'

      printf 'ping dashboard.meraki.com repeat 2 timeout 2\r\n'
      sleep 6
      printf '\r\n'

      printf 'ping google.com repeat 2 timeout 2\r\n'
      sleep 6
      printf '\r\n'

      printf 'exit\r\n'
    } | timeout -k 10s 260s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  ) &
  local ssh_ping_pid=$!

  # Heartbeat: if this takes more than a few seconds, keep telling the user
  # that we’re still waiting on network connectivity tests for this device.
  local elapsed=0
  # Normal ping sequence (2x pings + sleeps) is ~12s, so don’t warn
  # until we’re clearly slower than that.
  local first_notice=25     # first “this is slow” message after 15s
  local notice_interval=20    # then every 15s after that

  while kill -0 "$ssh_ping_pid" 2>/dev/null; do
    sleep 3
    elapsed=$((elapsed + 3))

    if (( elapsed >= first_notice )); then
      log "[${ip}] Network connectivity tests (dashboard.meraki.com / google.com) are taking longer than expected – still working, please wait…"
      first_notice=$((first_notice + notice_interval))
    fi
  done

  wait "$ssh_ping_pid" || true

  tr -d '\r' < "$raw" > "$out"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$raw"

  # refresh state after fix (from include-filtered running-config)
  grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$out" && dns_ok="yes" || dns_ok="no"
  grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$out" && domlkp="disabled" || domlkp="enabled"
  http_client_cur="$(awk 'BEGIN{IGNORECASE=1} /^[[:space:]]*ip[[:space:]]+http[[:space:]]+client[[:space:]]+source-interface/ {print $NF; exit}' "$out")"
  if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
    [[ -n "$http_client_cur" && "$http_client_cur" == "$HTTP_CLIENT_SOURCE_IFACE" ]] && http_client_ok="yes" || http_client_ok="no"
  fi

  # ----- ping evaluation (using "Success rate is 100 percent" blocks) -----
  ping_meraki="no"
  ping_google="no"

  # Meraki dashboard ping: look for a "Success rate is 100 percent" AFTER
  # "ping dashboard.meraki.com", but before "ping google.com".
  if awk '
    /ping dashboard\.meraki\.com/ {seen=1}
    seen && /Success rate is 100 percent/ {ok=1}
    seen && /ping google\.com/ && !ok {fail=1}
    END{
      if (ok) exit 0;
      else    exit 1;
    }
  ' "$out"; then
    ping_meraki="yes"
  else
    notes+="ping_meraki_failed;"
  fi

  # Google ping: look for a "Success rate is 100 percent" after
  # "ping google.com" but before next device prompt.
  if awk '
    /ping google\.com/ {seen=1}
    seen && /Success rate is 100 percent/ {ok=1}
    # Device prompt line (e.g. C9200#) — if we hit this before success, treat as fail
    seen && /^[[:alnum:]_.:-]+[>#][[:space:]]*$/ && !ok {fail=1}
    END{
      if (ok) exit 0;
      else    exit 1;
    }
  ' "$out"; then
    ping_google="yes"
  else
    notes+="ping_google_failed;"
  fi

  # mgmt-only L3 detection:
  # Pattern:
  #   - ping to dashboard.meraki.com failed
  #   - no 'ip routing' (classic L2 mode)
  #   - dedicated mgmt port has an IP
  #   - ip default-gateway is configured
  #
  # This strongly suggests the box is using the OOB Management interface
  # for Internet/L3 reachability, which Meraki Cloud Management does NOT
  # support. The Meraki mgmt IP must live on an in-band SVI with routing.
  if [[ "$ping_meraki" != "yes" && \
        "$has_ip_routing" == "no" && \
        "$has_mgmt_ip" == "yes" && \
        "$has_default_gw" == "yes" ]]; then
    mgmt_only_l3="yes"
    local msg="Using dedicated Management interface for Internet connectivity. Meraki Cloud Management requires an in-band SVI with IP routing; move the mgmt IP off the OOB port."
    notes+="oob_mgmt_l3_not_supported(${msg});"
    log "[${ip}] WARNING: ${msg}"
  fi

  # Log ping outcomes
  log "[${ip}] ping results: meraki=${ping_meraki} google=${ping_google}"

  # Ready gating
  ready="yes"
  [[ "$install_mode" == "INSTALL" ]] || { ready="no"; notes+="mode_${install_mode:-?};"; }
  [[ "$meets_min" == "yes" ]] || { ready="no"; [[ "$meets_min" == "no" ]] && : || notes+="min_ios_unknown;"; }
  [[ "$meraki_ok" == "yes" ]] || { ready="no"; [[ "$meraki_ok" == "unknown" ]] && notes+="meraki_compat_unknown;" ; }
  [[ "$dns_ok" == "yes" ]] || ready="no"
  [[ "$domlkp" == "enabled" ]] || ready="no"
  if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
    [[ "$http_client_ok" == "yes" ]] || ready="no"
  fi
  [[ "$ping_meraki" == "yes" ]] || ready="no"

  log "[${ip}] HOST=${host} MODEL=${model:-?} IOS=${ios:-?} MODE=${install_mode:-?} MIN=${req_min:-?} COMPAT=${meraki_ok} DNS=${dns_ok} DOMLKP=${domlkp} HTTPCLIENT=${http_client_ok} PING_MERAKI=${ping_meraki} READY=${ready}"

  append_csv "$SUMMARY_CSV" \
"${ip},${host},${model:-},${ios:-},${install_mode:-},${req_type:-},${req_min:-},${req_train:-},${meraki_ok},${dns_ok},${domlkp},${http_client_ok},${ping_meraki},${ping_google},${changed_dns},${enabled_dl},${changed_http},${ready},${notes}"

  rm -f "$out"
}

# ---------- Fix-only helpers that return what changed ----------
fix_dns_one(){
  local ip="$1" need_en=0
  build_ssh_arr "$ip"
  is_priv15_for_ip "$ip" || need_en=1
  # dns_missing=yes, dl_disabled=yes, http_need=no
  apply_fixes_one "$ip" "$need_en" "yes" "yes" "no"
}

fix_http_one(){
  local ip="$1" need_en=0
  build_ssh_arr "$ip"
  is_priv15_for_ip "$ip" || need_en=1
  # dns_missing=no, dl_disabled=no, http_need=yes
  apply_fixes_one "$ip" "$need_en" "no" "no" "yes"
}

# =====================================================================
# MAIN preflight flow
# =====================================================================
meraki_preflight(){
  trap 'ui_stop' EXIT

  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  DNS_PRIMARY="$(__deq "${DNS_PRIMARY-}")"
  DNS_SECONDARY="$(__deq "${DNS_SECONDARY-}")"
  HTTP_CLIENT_SOURCE_IFACE="$(__deq "${HTTP_CLIENT_SOURCE_IFACE-}")"

  [[ -n "$SSH_USERNAME" ]] || { dlg --title "Missing" --msgbox "SSH_USERNAME is empty in meraki_discovery.env" 7 60; clear; trap - EXIT; return 1; }
  if [[ -z "${SSH_KEY_PATH-}" && -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
    dlg --title "Missing requirement" --msgbox "sshpass is required when SSH_PASSWORD is used.\n\nInstall it or set SSH_KEY_PATH to a readable private key." 11 70
    clear; trap - EXIT; return 1
  fi
  [[ -f "$CLOUD_MODELS_JSON" ]] || { dlg --title "Missing" --msgbox "cloud_models.json not found:\n$CLOUD_MODELS_JSON" 9 70; clear; trap - EXIT; return 1; }

  local SRC=""
  local have_disc="" have_sel_json="" have_sel_ips=""

  [[ -s "$SEL_JSON" && "$(jq 'length' "$SEL_JSON" 2>/dev/null || echo 0)" -gt 0 ]] && have_sel_json=1
  if [[ -f "$SEL_ENV" ]]; then
    source "$SEL_ENV"
    UPGRADE_SELECTED_IPS="$(__deq "${UPGRADE_SELECTED_IPS-}")"
    [[ -n "$UPGRADE_SELECTED_IPS" ]] && have_sel_ips=1
  fi
  [[ -s "$DISC_JSON" ]] && have_disc=1

  if [[ -n "$have_sel_json" ]]; then SRC="seljson"
  elif [[ -n "$have_sel_ips" ]]; then SRC="selips"
  elif [[ -n "$have_disc" ]]; then SRC="disc"
  else
    dlg --title "Nothing to pick" --msgbox "No selected_upgrade.json, selected_upgrade.env, or discovery_results.json found." 10 75
    clear; trap - EXIT; return 1
  fi

  declare -A DISC_SSH DISC_LOGIN DISC_BL
  if [[ -s "$DISC_JSON" ]]; then
    while IFS=$'\t' read -r ip ssh login bl; do
      DISC_SSH["$ip"]="$ssh"
      DISC_LOGIN["$ip"]="$login"
      DISC_BL["$ip"]="$bl"
    done < <(jq -r '.[] | [ .ip, (.ssh//false), (.login//false), (.blacklisted//false) ] | @tsv' "$DISC_JSON")
  fi

  declare -a IPS HOSTS
  if [[ "$SRC" == "disc" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$DISC_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$DISC_JSON" 2>/dev/null)
  elif [[ "$SRC" == "seljson" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$SEL_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$SEL_JSON" 2>/dev/null)
  else
    read -r -a IPS <<<"${UPGRADE_SELECTED_IPS:-}"
    HOSTS=(); for ip in "${IPS[@]}"; do HOSTS+=(""); done
  fi

  (( ${#IPS[@]} > 0 )) || {
    if (( DIALOG )); then
      dlg --title "No devices" --msgbox "The chosen source has zero devices." 7 60
      clear
    else
      echo "No devices found in selected source."
    fi
    trap - EXIT
    return 1
  }

  # Build TARGETS automatically from eligible devices – no user checklist.
  local TARGETS=()
  for i in "${!IPS[@]}"; do
    local ip="${IPS[$i]}"

    # If we have discovery metadata, enforce ssh/login/blacklist gates
    if [[ -n "${DISC_SSH[$ip]+x}" ]]; then
      if [[ "${DISC_SSH[$ip]}" != "true" || "${DISC_LOGIN[$ip]}" != "true" || "${DISC_BL[$ip]}" == "true" ]]; then
        continue
      fi
    fi

    TARGETS+=( "$ip" )
  done

  (( ${#TARGETS[@]} > 0 )) || {
    if (( DIALOG )); then
      dlg --title "No eligible devices" --msgbox "None eligible (ssh/login failed or blacklisted)." 9 70
      clear
    else
      echo "No eligible devices (ssh/login failed or blacklisted)."
    fi
    trap - EXIT
    return 1
  }

  RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/preflight"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"

  printf 'export PRE_FLIGHT_RUN_ID=%q\nexport PRE_FLIGHT_RUN_DIR=%q\n' "$RUN_ID" "$RUN_DIR" > "$RUN_ROOT/latest.env"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  SUMMARY_CSV="$RUN_DIR/summary.csv"
  echo "ip,hostname,model,ios_ver,install_mode,req_image_type,min_iosxe,train,meraki_compat_ok,dns_ok,domain_lookup,http_client_ok,ping_meraki,ping_google,changed_dns,enabled_domain_lookup,changed_http_client,ready,notes" > "$SUMMARY_CSV"
  printf 'export PRE_FLIGHT_SUMMARY=%q\n' "$SUMMARY_CSV" >> "$RUN_ROOT/latest.env"
  ln -sfn "$SUMMARY_CSV" "$RUN_ROOT/latest.csv"

  UI_TITLE="Preflight"
  ui_start
  log "Preflight Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Rules: $CLOUD_MODELS_JSON"
  log "Targets: ${TARGETS[*]}"
  log "DNS env: ${DNS_PRIMARY:-<none>} ${DNS_SECONDARY:-<none>}"
  log "HTTP client src-if env: ${HTTP_CLIENT_SOURCE_IFACE:-<none>}"
  gauge 1 "Starting…"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}
  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( probe_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      wait -n || true
      ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Processed $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done
  while (( DONE < TOTAL )); do
    wait -n || true
    ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Processed $DONE / $TOTAL"
  done

    gauge 100 "Done"
  log "Summary: $SUMMARY_CSV"
  ui_stop
  clear

  local scanned ready_count dns_changed dl_changed http_changed
  local meraki_ping_fail mgmt_only_count overall_ok

  scanned="$(awk -F, 'NR>1{c++} END{print c+0}' "$SUMMARY_CSV")"
  ready_count="$(awk -F, 'NR>1{if($18=="yes") c++} END{print c+0}' "$SUMMARY_CSV")"
  dns_changed="$(awk -F, 'NR>1{if($15=="yes") c++} END{print c+0}' "$SUMMARY_CSV")"
  dl_changed="$(awk -F, 'NR>1{if($16=="yes") c++} END{print c+0}' "$SUMMARY_CSV")"
  http_changed="$(awk -F, 'NR>1{if($17=="yes") c++} END{print c+0}' "$SUMMARY_CSV")"
  meraki_ping_fail="$(awk -F, 'NR>1{if($13!="yes") c++} END{print c+0}' "$SUMMARY_CSV")"
  mgmt_only_count="$(awk -F, 'NR>1{if($19 ~ /oob_mgmt_l3_not_supported/) c++} END{print c+0}' "$SUMMARY_CSV")"

  # Overall OK = every scanned device is READY=yes
  # (which already includes ping, DNS, HTTP client, compat, etc.)
  if (( scanned > 0 && ready_count == scanned )); then
    overall_ok=1
  else
    overall_ok=0
  fi

  # Manage the OK flag for downstream scripts
  if (( overall_ok )); then
    echo "OK $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$PREFLIGHT_OK_FLAG"
    log "Preflight OK flag written: $PREFLIGHT_OK_FLAG"
  else
    rm -f "$PREFLIGHT_OK_FLAG"
    log "Preflight NOT clean – OK flag removed (if present): $PREFLIGHT_OK_FLAG"
  fi

    # Mirror any auto-fixes into dnsfix/httpfix trees so unified_logs.sh
  # can display them alongside manual fix runs.
  if (( dns_changed > 0 )); then
    local dns_root="$SCRIPT_DIR/runs/dnsfix"
    local dns_base="${RUN_ID/run-/dns-}"        # run-YYYYmmddHHMMSS -> dns-YYYYmmddHHMMSS
    local dns_dir="$dns_root/$dns_base"
    mkdir -p "$dns_dir"

    # Symlink preflight artifacts so the DNS Fix Logs viewer can see them
    ln -sfn "../../preflight/$RUN_ID/ui.status"    "$dns_dir/ui.status"
    ln -sfn "../../preflight/$RUN_ID/summary.csv" "$dns_dir/dnsfix.csv"
    ln -sfn "../../preflight/$RUN_ID/devlogs"     "$dns_dir/devlogs"
  fi

  if (( http_changed > 0 )); then
    local http_root="$SCRIPT_DIR/runs/httpfix"
    local http_base="${RUN_ID/run-/http-}"       # run-YYYYmmddHHMMSS -> http-YYYYmmddHHMMSS
    local http_dir="$http_root/$http_base"
    mkdir -p "$http_dir"

    # Symlink preflight artifacts so the HTTP Client Fix Logs viewer can see them
    ln -sfn "../../preflight/$RUN_ID/ui.status"    "$http_dir/ui.status"
    ln -sfn "../../preflight/$RUN_ID/summary.csv" "$http_dir/httpfix.csv"
    ln -sfn "../../preflight/$RUN_ID/devlogs"     "$http_dir/devlogs"
  fi



  if (( DIALOG )); then
    # Main summary dialog (unchanged except for mgmt-only line)
    dlg --title "Preflight complete" --msgbox \
"Scanned: ${scanned}
Ready:   ${ready_count}

Auto-fixes applied:
  DNS added/updated:          ${dns_changed}
  Domain lookup enabled:      ${dl_changed}
  HTTP client source-if set:  ${http_changed}

Meraki reachability failures (ping dashboard.meraki.com): ${meraki_ping_fail}
Devices using dedicated Management interface for Internet (i.e gi0/0 – NOT supported): ${mgmt_only_count}

Outputs:
  ${RUN_DIR}
  ${RUN_ROOT}/latest.csv" 20 88

    # Second dialog: pass/fail statement for the user
    if (( overall_ok )); then
      dlg --title "Preflight status" --msgbox \
"All ${scanned} selected switches passed preflight checks.

A preflight OK flag has been written in:
  ${PREFLIGHT_OK_FLAG}

You may proceed to the Meraki onboarding step." 12 78
    else
      dlg --title "Preflight status" --msgbox \
"Preflight completed, but NOT all switches are ready.

Summary:
  Ready switches:   ${ready_count} / ${scanned}
  Ping failures:    ${meraki_ping_fail}
  OOB mgmt in use:  ${mgmt_only_count}

The preflight OK flag has NOT been set.
Review the run logs and summary CSV, correct any issues,
and re-run preflight before proceeding to onboarding." 15 80
    fi

    clear
  else
    echo "Preflight complete: scanned=${scanned} ready=${ready_count} dns_fix=${dns_changed} dl_fix=${dl_changed} http_fix=${http_changed} meraki_ping_fail=${meraki_ping_fail} mgmt_only=${mgmt_only_count}"
    echo "Outputs: $RUN_DIR ; latest: $RUN_ROOT/latest.csv"

    if (( overall_ok )); then
      echo "Preflight status: ALL DEVICES READY. Flag written: $PREFLIGHT_OK_FLAG"
    else
      echo "Preflight status: NOT CLEAN. No OK flag. Fix issues before onboarding."
    fi
  fi

  trap - EXIT
  return 0
}

meraki_fix_dns(){
  trap 'ui_stop' EXIT

  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  DNS_PRIMARY="$(__deq "${DNS_PRIMARY-}")"
  DNS_SECONDARY="$(__deq "${DNS_SECONDARY-}")"

  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""
  [[ -f "$LATEST_ENV" ]] && source "$LATEST_ENV" && SUM="${PRE_FLIGHT_SUMMARY:-}"
  [[ -z "${SUM:-}" || ! -f "$SUM" ]] && {
    dlg --title "No Preflight Summary" --msgbox \
"Could not find runs/preflight/latest.csv.
Run preflight first." 9 70
    clear; trap - EXIT; return 1
  }

  # Devices needing DNS / domain lookup fix:
  #   dns_ok != yes   OR   domain_lookup == disabled
  mapfile -t TARGETS < <(awk -F, 'NR>1 { if ($10!="yes" || $11=="disabled") print $1 }' "$SUM")
  (( ${#TARGETS[@]} )) || {
    dlg --title "Nothing to do" --msgbox \
"All switches already have DNS and domain lookup enabled." 7 70
    clear; trap - EXIT; return 0
  }

  # Create dnsfix run folder + summary CSV
  RUN_ID="dns-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/dnsfix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"
  UI_TITLE="DNS Fix"
  ui_start
  log "DNS Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets: ${TARGETS[*]}"
  log "DNS servers: ${DNS_PRIMARY:-<none>} ${DNS_SECONDARY:-<none>}"
  gauge 1 "Starting…"

  local DNS_SUMMARY="$RUN_DIR/dnsfix.csv"
  echo "ip,changed_dns,enabled_domain_lookup,notes" > "$DNS_SUMMARY"

  local total=${#TARGETS[@]} idx=0
  for ip in "${TARGETS[@]}"; do
    idx=$((idx+1))
    gauge $(( 100 * (idx-1) / total )) "Fixing DNS on $ip ($idx / $total)…"

    # apply_fixes_one returns: did_dns,did_dl,did_http,notes
    local result did_dns did_dl did_http notes
    result="$(fix_dns_one "$ip")"
    IFS=',' read -r did_dns did_dl did_http notes <<<"$result"

    append_csv "$DNS_SUMMARY" "${ip},${did_dns},${did_dl},${notes}"
  done

  gauge 100 "Done"
  ui_stop
  clear
  trap - EXIT
  return 0
}

meraki_fix_http(){
  trap 'ui_stop' EXIT

  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  HTTP_CLIENT_SOURCE_IFACE="$(__deq "${HTTP_CLIENT_SOURCE_IFACE-}")"

  [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]] || {
    dlg --title "Missing" --msgbox \
"HTTP_CLIENT_SOURCE_IFACE is not set in meraki_discovery.env" 8 70
    clear; trap - EXIT; return 1
  }

  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""
  [[ -f "$LATEST_ENV" ]] && source "$LATEST_ENV" && SUM="${PRE_FLIGHT_SUMMARY:-}"
  [[ -z "${SUM:-}" || ! -f "$SUM" ]] && {
    dlg --title "No Preflight Summary" --msgbox \
"Could not find runs/preflight/latest.csv.
Run preflight first." 9 70
    clear; trap - EXIT; return 1
  }

  # Devices needing HTTP client fix (http_client_ok != yes ; col 12)
  mapfile -t TARGETS < <(awk -F, 'NR>1 { if ($12!="yes") print $1 }' "$SUM")
  (( ${#TARGETS[@]} )) || {
    dlg --title "Nothing to do" --msgbox \
"All switches already have HTTP client source-interface set correctly." 7 76
    clear; trap - EXIT; return 0
  }

  # Create httpfix run folder + summary CSV
  RUN_ID="http-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/httpfix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"
  UI_TITLE="HTTP Fix"
  ui_start
  log "HTTP Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets: ${TARGETS[*]}"
  log "HTTP client src-if: ${HTTP_CLIENT_SOURCE_IFACE}"
  gauge 1 "Starting…"

  local HTTP_SUMMARY="$RUN_DIR/httpfix.csv"
  echo "ip,changed_http_client,notes" > "$HTTP_SUMMARY"

  local total=${#TARGETS[@]} idx=0
  for ip in "${TARGETS[@]}"; do
    idx=$((idx+1))
    gauge $(( 100 * (idx-1) / total )) "Fixing HTTP client on $ip ($idx / $total)…"

    # apply_fixes_one returns: did_dns,did_dl,did_http,notes
    local result did_dns did_dl did_http notes
    result="$(fix_http_one "$ip")"
    IFS=',' read -r did_dns did_dl did_http notes <<<"$result"

    append_csv "$HTTP_SUMMARY" "${ip},${did_http},${notes}"
  done

  gauge 100 "Done"
  ui_stop
  clear
  trap - EXIT
  return 0
}
case "${1:-preflight}" in
  preflight|"") meraki_preflight ;;
  fix-dns)      meraki_fix_dns ;;
  fix-http)     meraki_fix_http ;;
  *)
    echo "Usage: $0 {preflight|fix-dns|fix-http}"
    exit 1
    ;;
esac