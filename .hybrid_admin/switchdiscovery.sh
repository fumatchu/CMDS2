#!/usr/bin/env bash
# Catalyst/Meraki discovery + plan with split-screen dialog UI + selection
# - nmap discover -> SSH probe -> parse hostname/version/PID/SN
# - Builds upgrade plan (JSON/CSV)
# - Dialog checklist to pick switches to upgrade; writes selected_upgrade.{json,csv,env}
# - Eligible = Catalyst 9200/9300/9400/9500/9600
# - Ineligible devices (wrong model, SSH closed, or login failure) are shown and cannot be selected.

set -Euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# ===== ENV autodetect =====
if [[ -n "${1:-}" ]]; then
  ENV_FILE="$1"
else
  CANDIDATES=("$SCRIPT_DIR/ENV" "$SCRIPT_DIR/.env" "$SCRIPT_DIR/meraki_discovery.env" "$SCRIPT_DIR/meraki.env")
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR"/*.env 2>/dev/null || true)
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR"/*ENV 2>/dev/null || true)
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR"/*.ENV 2>/dev/null || true)
  ENV_FILE=""
  for f in "${CANDIDATES[@]}"; do
    [[ -f "$f" && -r "$f" ]] || continue
    if grep -Eq '(^|\s)(export\s+)?(MERAKI_API_KEY|SSH_USERNAME)=' "$f"; then ENV_FILE="$f"; break; fi
  done
fi
[[ -n "${ENV_FILE:-}" ]] || { echo "No ENV found in $SCRIPT_DIR; pass path explicitly."; exit 1; }
echo "Using ENV file: $ENV_FILE" >&2
set +H
# shellcheck disable=SC1090
source "$ENV_FILE"

# ===== Config / defaults =====
DISCOVERY_MODE="${DISCOVERY_MODE:-}"           # list|networks|scan|cidr|subnets|(auto)
DISCOVERY_IPS="${DISCOVERY_IPS:-}"
DISCOVERY_IPS_FILE="${DISCOVERY_IPS_FILE:-}"
DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
DISCOVERY_INTERFACE="${DISCOVERY_INTERFACE:-}"
SSH_USERNAME="${SSH_USERNAME:-admin}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"
MAX_SSH_FANOUT="${MAX_SSH_FANOUT:-1}"
SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
DEBUG="${DISCOVERY_DEBUG:-0}"
UI_MODE="${UI_MODE:-dialog}"                    # dialog|plain

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need nmap; need jq; need awk; need sed
command -v sshpass >/dev/null 2>&1 || echo "NOTE: sshpass not found; password auth disabled unless SSH_KEY_PATH is set."

OUT_DIR="$(dirname "$ENV_FILE")"
JSON_OUT="$OUT_DIR/discovery_results.json"
CSV_OUT="$OUT_DIR/discovery_results.csv"
UP_JSON_OUT="$OUT_DIR/upgrade_plan.json"
UP_CSV_OUT="$OUT_DIR/upgrade_plan.csv"
SEL_JSON_OUT="$OUT_DIR/selected_upgrade.json"
SEL_CSV_OUT="$OUT_DIR/selected_upgrade.csv"
SEL_ENV_OUT="$OUT_DIR/selected_upgrade.env"
LOG_DIR="$OUT_DIR/logs"; mkdir -p "$LOG_DIR"

# Normalize CRLF in creds
SSH_USERNAME="$(printf '%s' "${SSH_USERNAME:-}" | tr -d '\r')"
SSH_PASSWORD="$(printf '%s' "${SSH_PASSWORD:-}" | tr -d '\r')"

dbg() { [[ "$DEBUG" == "1" ]] && echo "[debug] $*" >&2 || true; }
split_list() { tr ',;' ' ' | xargs -n1 | awk 'NF'; }

# Allow DISCOVERY_IPS to be a file path or @file
read_ip_list() {
  local src="${DISCOVERY_IPS:-}"
  local file_var="${DISCOVERY_IPS_FILE:-}"
  local file_path=""
  if [[ -n "$src" && -f "$src" ]]; then file_path="$src"; fi
  if [[ -z "$file_path" && -n "$src" && "$src" == @* && -f "${src#@}" ]]; then file_path="${src#@}"; fi
  if [[ -z "$file_path" && -n "$file_var" && -f "$file_var" ]]; then file_path="$file_var"; fi
  if [[ -n "$file_path" ]]; then
    awk 'NF && $1 !~ /^#/ {print $1}' "$file_path"
  else
    printf '%s\n' "$src" | tr ',;' ' ' | xargs -n1 | awk 'NF'
  fi
}

# ===== UI (dialog; non-blocking FIFO; idempotent stop) =====
DIALOG_AVAILABLE=0
if [[ "$UI_MODE" == "dialog" ]] && command -v dialog >/dev/null 2>&1; then DIALOG_AVAILABLE=1; fi

STATUS_FILE="$(mktemp)"; : > "$STATUS_FILE"
PROG_PIPE="$(mktemp -u)"
PROG_FD=""
DIALOG_PID=""

TAIL_H=; TAIL_W=; GAUGE_H=; GAUGE_W=; GAUGE_ROW=; GAUGE_COL=

_ui_calc_layout() {
  local lines cols
  if ! read -r lines cols < <(stty size 2>/dev/null); then lines=24 cols=80; fi
  if (( lines < 18 || cols < 70 )); then DIALOG_AVAILABLE=0; return; fi
  TAIL_H=$((lines - 10)); (( TAIL_H < 10 )) && TAIL_H=10
  TAIL_W=$((cols - 4));   (( TAIL_W < 68 )) && TAIL_W=68
  GAUGE_H=7; GAUGE_W=$TAIL_W; GAUGE_ROW=$((TAIL_H + 2)); GAUGE_COL=2
}
_ui_fd_open() {
  [[ -n "${PROG_FD:-}" ]] || return 1
  if [[ -e "/proc/$$/fd/$PROG_FD" ]]; then return 0; fi
  { : >&"$PROG_FD"; } 2>/dev/null || return 1
  return 0
}
ui_start() {
  _ui_calc_layout
  if (( DIALOG_AVAILABLE )); then
    mkfifo "$PROG_PIPE"
    exec {PROG_FD}<>"$PROG_PIPE"
    (
      dialog --no-shadow \
             --begin 1 2 --title "Activity" --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
             --and-widget \
             --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Overall Progress" \
             --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$PROG_PIPE"
    ) & DIALOG_PID=$!
    sleep 0.15
  else
    echo "[info] UI plain mode (set UI_MODE=dialog and install 'dialog')."
  fi
}
ui_status() { local msg="$1"; printf '%(%H:%M:%S)T %s\n' -1 "$msg" >> "$STATUS_FILE"; (( DIALOG_AVAILABLE )) || echo "$msg"; }
ui_gauge()  {
  local p="$1"; shift || true; local m="${*:-Working…}"
  if (( DIALOG_AVAILABLE )) && _ui_fd_open; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$PROG_FD"; } 2>/dev/null || true
  else
    echo "[progress] $p%% - $m"
  fi
}
ui_stop() {
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
  rm -f "$STATUS_FILE" 2>/dev/null || true
}
trap 'ui_stop' EXIT

# ===== helpers =====
clean_field() { local s; s="$(printf '%s' "$1" | tr -d '\r\n')"; s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//; s/[#]$//')"; printf '%s' "$s"; }

# --- Human-readable reason strings for the checklist ---
pretty_reason() {
  local r="${1:-unknown}"
  case "${r,,}" in
    login_failed:auth_failed|auth_failed)       echo "AUTH FAILED" ;;
    login_failed:timeout|timeout)               echo "SSH TIMEOUT" ;;
    login_failed:connect_failed|connect_failed) echo "SSH CONNECT FAILED" ;;
    ssh_closed)                                 echo "SSH CLOSED" ;;
    unsupported_pid)                            echo "UNSUPPORTED MODEL" ;;
    missing_pid)                                echo "NO MODEL INFO" ;;
    ok)                                         echo "OK" ;;
    *)                                          echo "${r^^}" ;;
  esac
}

# ----- Platform eligibility (only Cat 9200/9300/9400/9500/9600 allowed) -----
ALLOWED_SERIES_REGEX='^(WS-)?(C9200(L|CX)?|C9300([A-Z])?|C94[0-9]{2}R?|C9500([A-Z0-9-]*)?|C96[0-9]{2}R?)(-|$)'
pid_is_eligible() {
  local pid="${1:-}"
  [[ -z "$pid" ]] && return 1
  pid="${pid^^}"
  [[ "$pid" =~ $ALLOWED_SERIES_REGEX ]]
}

# ===== SSH probe (with hard timeout) =====
probe_host() {
  local ip="$1" log="$LOG_DIR/scan-$ip.log"
  : > "$log"; ui_status "[${ip}] Probing via SSH…"; ui_status "[${ip}] SSH: connecting…"

  local -a SSH_OPTS=(
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=1
    -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa
    -o KexAlgorithms=+diffie-hellman-group14-sha1
  )
  local -a SSH_CMD
  if [[ -n "$SSH_KEY_PATH" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD=(ssh "${SSH_OPTS[@]}" -i "$SSH_KEY_PATH" -o BatchMode=yes "$SSH_USERNAME@$ip")
  elif [[ -n "$SSH_PASSWORD" ]] && command -v sshpass >/dev/null 2>&1; then
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" ssh "${SSH_OPTS[@]}"
      -o PreferredAuthentications=password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1 -o BatchMode=no "$SSH_USERNAME@$ip")
  else
    SSH_CMD=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes -o NumberOfPasswordPrompts=0 "$SSH_USERNAME@$ip")
  fi
  { printf '[cmd] '; printf '%q ' "${SSH_CMD[@]}" | sed 's/sshpass -p [^ ]\+/sshpass -p ****/g'; echo; } >> "$log"

  local cmdf out outn; cmdf="$(mktemp)"; out="$(mktemp)"; outn="$(mktemp)"
  {
    printf '\r\n\r\n'; sleep 0.40
    printf 'terminal length 0\r\n';              sleep 0.35
    printf 'terminal width 511\r\n';             sleep 0.35
    printf 'show clock\r\n';                     sleep 0.45
    printf 'show version\r\n';                   sleep 0.55
    printf 'show running-config | include ^hostname\r\n'; sleep 0.45
    printf 'show inventory\r\n';                 sleep 0.70
    sleep 0.60
    printf 'exit\r\n'
  } > "$cmdf"

  local ssh_rc=0 _pf_state
  _pf_state="$(set -o | awk '/pipefail/{print $2}')"; set +o pipefail
  if command -v timeout >/dev/null 2>&1; then
    cat "$cmdf" | timeout -k 5s "${SSH_TIMEOUT}s" "${SSH_CMD[@]}" -tt >"$out" 2>&1 || ssh_rc=$?
    (( ssh_rc != 0 )) && echo "[${ip}] SSH timeout or error after ${SSH_TIMEOUT}s (rc=$ssh_rc)" >> "$log"
  else
    cat "$cmdf" | "${SSH_CMD[@]}" -tt >"$out" 2>&1 || ssh_rc=$?
  fi
  [[ "$_pf_state" == "on" ]] && set -o pipefail
  rm -f "$cmdf"

  tr -d '\r' < "$out" | tee -a "$log" > "$outn"

  local login_ok=0
  if grep -Eq 'Cisco IOS|IOS XE| uptime is |^[A-Za-z0-9_.:/-]+[>#] *$|[0-9]{2}:[0-9]{2}:[0-9]{2}' "$outn"; then login_ok=1; fi
  (( login_ok )) && ui_status "[${ip}] SSH: logged in and collected output."

  local login_err=""
  if (( ! login_ok )); then
    if grep -qiE 'Permission denied|Authentication failed|Access denied|Login incorrect' "$outn"; then
      login_err="auth_failed"; ui_status "[${ip}] SSH: AUTH FAILED"
    elif (( ssh_rc == 124 || ssh_rc == 137 )); then
      login_err="timeout"; ui_status "[${ip}] SSH: TIMEOUT"
    elif grep -qiE 'Connection refused|No route to host|Connection timed out|Connection reset|Connection closed' "$outn"; then
      login_err="connect_failed"; ui_status "[${ip}] SSH: CONNECT FAILED"
    else
      login_err="unknown"; ui_status "[${ip}] SSH: UNKNOWN ERROR"
    fi
  fi

  local hostname version pid sn
  hostname="$(awk '/^hostname[[:space:]]+/{print $2}' "$outn" | tail -n1)"
  [[ -z "$hostname" ]] && hostname="$(grep -E '^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$' "$outn" | tail -n1 | sed -E 's/[>#].*$//')"
  [[ -z "$hostname" ]] && hostname="$(grep -m1 -E ' uptime is ' "$outn" | awk '{print $1}')"
  hostname="$(clean_field "$hostname")"

  version="$(grep -m1 -E 'Cisco IOS XE Software, Version[[:space:]]+' "$outn" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  [[ -z "$version" ]] && version="$(grep -m1 -E 'Cisco IOS Software|Version[[:space:]]+[0-9]' "$outn" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  version="$(clean_field "$version")"

  pid="$(grep -m1 -E 'PID:[[:space:]]*[^,]+' "$outn" | sed -E 's/.*PID:[[:space:]]*([^,]+).*/\1/')"
  sn="$(grep -m1 -E 'SN:[[:space:]]*[A-Za-z0-9]+' "$outn" | sed -E 's/.*SN:[[:space:]]*([^,[:space:]]+).*/\1/')"

  if [[ -z "$pid" ]]; then
    pid="$(awk -F':' '/^[[:space:]]*Model (N|n)umber/{gsub(/^[ \t]+/,"",$2); gsub(/[ \t]+$/,"",$2); print $2; exit}' "$outn")"
  fi
  if [[ -z "$pid" ]]; then
    pid="$(awk '/^cisco C[0-9]/{for(i=1;i<=NF;i++) if($i ~ /^C[0-9]/){print $i; exit}}' "$outn")"
  fi

  pid="$(clean_field "$pid")"; sn="$(clean_field "$sn")"
  rm -f "$out" "$outn"

  if (( login_ok )); then
    jq -n --arg ip "$ip" --arg host "${hostname:-}" --arg ver "${version:-}" --arg pid "${pid:-}" --arg sn "${sn:-}" \
          --arg login_error "" \
          '{ip:$ip, ssh:true, login:true, hostname:$host, version:$ver, pid:$pid, serial:$sn, login_error:$login_error}'
  else
    jq -n --arg ip "$ip" --arg le "$login_err" '{ip:$ip, ssh:true, login:false, login_error:$le}'
  fi
}

# ===== Discovery =====
resolve_targets() {
  local mode="${DISCOVERY_MODE,,}" targets=()
  case "$mode" in
    list|iplist|hosts) mapfile -t targets < <(read_ip_list) ;;
    networks|scan|cidr|subnets) [[ -n "$DISCOVERY_NETWORKS" ]] && mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list) ;;
    *) if [[ -n "$DISCOVERY_IPS" || -n "$DISCOVERY_IPS_FILE" ]]; then mapfile -t targets < <(read_ip_list); mode="list"
       elif [[ -n "$DISCOVERY_NETWORKS" ]]; then mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list); mode="networks"
       fi ;;
  esac
  [[ ${#targets[@]} -gt 0 ]] || { echo "No targets: set DISCOVERY_MODE=list & DISCOVERY_IPS, or DISCOVERY_MODE=scan|networks & DISCOVERY_NETWORKS" >&2; return 1; }
  if [[ -n "$DISCOVERY_INTERFACE" ]]; then ui_status "Using interface override: $DISCOVERY_INTERFACE"; USE_IFACE=1; else ui_status "Interface: kernel default (no -e override)"; USE_IFACE=0; fi
  TARGET_MODE="$mode"; TARGETS=("${targets[@]}"); ui_status "Mode: $TARGET_MODE"; ui_status "Targets: ${TARGETS[*]}"
}

nmap_cmd_base() {
  local opts=(-n)
  (( USE_IFACE )) && opts+=(-e "$DISCOVERY_INTERFACE")
  printf '%s ' "${opts[@]}"
}
pass_a() { local probes=(-PE -PS22,80,443,830 -PA22,443); (( USE_IFACE )) && probes+=(-PR); local cmd=(nmap $(nmap_cmd_base) -sn "${probes[@]}" --max-retries 2 "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' || true; }
pass_b() { local cmd=(nmap $(nmap_cmd_base) -sn -PE "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' || true; }
pass_c() { local cmd=(nmap $(nmap_cmd_base) -sn -Pn -PS22,80,443 "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Status: Up/{print $2}' || true; }
pass_fping() { command -v fping >/dev/null 2>&1 || return 0; local out=(); for t in "${TARGETS[@]}"; do if [[ "$t" =~ / ]]; then mapfile -t out < <(fping -a -q -g "$t" 2>/dev/null || true); else mapfile -t out < <(printf '%s\n' "$t" | fping -a -q 2>/dev/null || true); fi; done; pr
intf '%s\n' "${out[@]}" | awk 'NF'; }

discover_targets() {
  ui_status "Discovering live hosts (pass 1/3)…"; ui_gauge 5 "Scanning (hybrid)…"
  local live=(); mapfile -t live < <(pass_a)
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying ICMP only…"; ui_gauge 10 "Scanning (ICMP)…"; mapfile -t live < <(pass_b); fi
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying TCP-only ping…"; ui_gauge 15 "Scanning (TCP)…"; mapfile -t live < <(pass_c); fi
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying fping fallback…"; mapfile -t live < <(pass_fping); fi
  printf '%s\n' "${live[@]}" | awk -F. '!(NF==4 && ($4==0 || $4==255))' | sort -u
}

# --- SAFE SSH port check (chunked, non-fatal) ---
filter_ssh_open() {
  local ips=("$@")
  if [[ ${#ips[@]} -eq 0 ]]; then
    ui_status "No hosts to check for SSH."
    return 0
  fi
  ui_status "Checking TCP/22 on ${#ips[@]} host(s)…"; ui_gauge 25 "Checking SSH ports…"

  local tmp; tmp="$(mktemp)"
  local -a chunk=()
  local i=0

  _scan_chunk() {
    local chunk=( "$@" )
    local cmd=(nmap $(nmap_cmd_base) -Pn --open -p22 --max-retries 2 --host-timeout 6s "${chunk[@]}")
    if ! "${cmd[@]}" -oG - 2>>"$LOG_DIR/nmap.err" | awk '/22\/open/{print $2}'; then
      ui_status "[warn] nmap returned non-zero scanning ${#chunk[@]} host(s); continuing."
      return 0
    fi
  }

  for ip in "${ips[@]}"; do
    chunk+=("$ip")
    (( ++i % 100 == 0 )) && { _scan_chunk "${chunk[@]}" >>"$tmp" || true; chunk=(); }
  done
  (( ${#chunk[@]} )) && _scan_chunk "${chunk[@]}" >>"$tmp" || true

  awk 'NF' "$tmp" || true
  rm -f "$tmp" 2>/dev/null || true
  return 0
}

emit_extra_json() {
  local hosts=("$@")
  for ip in "${hosts[@]}"; do
    if [[ -n "${TCP22[$ip]:-}" ]]; then
      printf '{"ip":"%s","ssh":true,"login":false,"login_error":"unknown"}\n' "$ip"
    else
      printf '{"ip":"%s","ssh":false,"login":false,"login_error":"ssh_closed"}\n' "$ip"
    fi
  done | jq -s '.'
}

# Worker pool
HAS_WAIT_N=0; if help wait >/dev/null 2>&1 && help wait 2>&1 | grep -q -- '-n'; then HAS_WAIT_N=1; fi
run_probe_pool() {
  local hosts=("$@") max=${MAX_SSH_FANOUT} total=${#hosts[@]}
  local running=0 done=0 pids=()
  for ip in "${hosts[@]}"; do
    { probe_host "$ip"; } >> "$TMPJSON" & pids+=("$!"); ((running++))
    if (( running >= max )); then
      if (( HAS_WAIT_N )); then wait -n || true; else wait "${pids[0]}" || true; pids=("${pids[@]:1}"); fi
      ((done++)); local pct=$(( 25 + 60 * done / total )); ui_gauge "$pct" "Probing devices… ($done / $total)"; ((running--))
    fi
  done
  while (( running > 0 )); do
    if (( HAS_WAIT_N )); then wait -n || true; else wait "${pids[0]}" || true; pids=("${pids[@]:1}"); fi
    ((done++)); local pct=$(( 25 + 60 * done / total )); ui_gauge "$pct" "Probing devices… ($done / $total)"; ((running--))
  done
}

# ===== Upgrade planning =====
choose_image() {
  local pid="$1"
  if ! pid_is_eligible "$pid"; then
    printf '||||\n'
    return
  fi
  if [[ "$pid" =~ (^|-)C9200 ]] || [[ "$pid" =~ (^|-)C9200CX ]] || [[ "$pid" =~ (^|-)C9200L ]]; then
    printf '%s|%s|%s|%s\n' "${FW_CAT9K_LITE_FILE:-}" "${FW_CAT9K_LITE_PATH:-}" "${FW_CAT9K_LITE_VERSION:-}" "${FW_CAT9K_LITE_SIZE_BYTES:-}"
  else
    printf '%s|%s|%s|%s\n' "${FW_CAT9K_FILE:-}" "${FW_CAT9K_PATH:-}" "${FW_CAT9K_VERSION:-}" "${FW_CAT9K_SIZE_BYTES:-}"
  fi
}
normalize_ver() { local v="${1:-0.0.0}"; awk -F. '{printf("%d.%d.%d\n",$1+0,$2+0,$3+0)}' <<<"$v" 2>/dev/null || printf '0.0.0\n'; }

make_upgrade_plan() {
  local json="$JSON_OUT"; [[ -s "$json" ]] || { ui_status "No discovery JSON to build an upgrade plan."; return 0; }
  ui_gauge 90 "Building upgrade plan…"

  jq -r '.[] | [.ip, .pid, .version, .hostname, (.ssh|tostring), (.login|tostring), (.login_error//"")] | @tsv' "$json" | \
  while IFS=$'\t' read -r ip pid cur_ver host ssh login login_err; do
    elig="false"; reason="unsupported_pid"
    if [[ -z "${pid:-}" ]]; then
      elig="false"; reason="missing_pid"
    elif pid_is_eligible "$pid"; then
      elig="true"; reason="ok"
    fi

    IFS='|' read -r tgt_file tgt_path tgt_ver tgt_size <<<"$(choose_image "$pid")"

    needs="false"
    if [[ "$elig" == "true" && -n "${tgt_ver:-}" ]]; then
      nv_cur="$(normalize_ver "${cur_ver:-0.0.0}")"
      nv_tgt="$(normalize_ver "${tgt_ver:-0.0.0}")"
      [[ "$nv_cur" != "$nv_tgt" ]] && needs="true"
    fi

    ready="false"; ready_reason=""
    if [[ "$elig" != "true" ]]; then
      ready="false"; ready_reason="$reason"
    elif [[ "$ssh" != "true" ]]; then
      ready="false"; ready_reason="ssh_closed"
    elif [[ "$login" != "true" ]]; then
      ready="false"; ready_reason="login_failed${login_err:+:$login_err}"
    else
      ready="true"; ready_reason="ok"
    fi

    jq -n --arg ip "$ip" --arg hostname "${host:-}" --arg pid "${pid:-}" \
          --arg current_version "${cur_ver:-}" --arg target_version "${tgt_ver:-}" \
          --arg target_file "${tgt_file:-}" --arg target_path "${tgt_path:-}" \
          --arg target_size "${tgt_size:-}" --arg needs_upgrade "$needs" \
          --arg eligible "$elig" --arg reason "$reason" \
          --arg ssh "$ssh" --arg login "$login" --arg login_error "${login_err:-}" \
          --arg ready "$ready" --arg ready_reason "$ready_reason" \
          '{ip:$ip, hostname:$hostname, pid:$pid,
            current_version:$current_version, target_version:$target_version,
            target_file:$target_file, target_path:$target_path,
            target_size_bytes: ($target_size|tonumber?),
            needs_upgrade: ($needs_upgrade=="true"),
            eligible: ($eligible=="true"), eligibility_reason: $reason,
            ssh: ($ssh=="true"), login: ($login=="true"), login_error:$login_error,
            ready: ($ready=="true"), ready_reason:$ready_reason }'
  done | jq -s '.' > "$UP_JSON_OUT"

  { echo "ip,hostname,pid,current_version,target_version,target_file,target_path,target_size_bytes,needs_upgrade,eligible,eligibility_reason,ssh,login,login_error,ready,ready_reason"
    jq -r '.[] | [.ip, (.hostname//""), (.pid//""), (.current_version//""), (.target_version//""),
                   (.target_file//""), (.target_path//""), (.target_size_bytes//""), (.needs_upgrade//false),
                   (.eligible//false), (.eligibility_reason//""), (.ssh//false), (.login//false),
                   (.login_error//""), (.ready//false), (.ready_reason//"")] | @csv' "$UP_JSON_OUT"
  } > "$UP_CSV_OUT"

  SKIPPED_CSV_OUT="$OUT_DIR/ineligible_devices.csv"
  { echo "ip,hostname,pid,ready,ready_reason"
    jq -r '.[] | select((.ready//false)==false) | [.ip, (.hostname//""), (.pid//""), (.ready//false), (.ready_reason//"")] | @csv' "$UP_JSON_OUT"
  } > "$SKIPPED_CSV_OUT"

  ui_status "Upgrade plan written: $UP_CSV_OUT"
  ui_status "Ineligible / not-ready devices (if any): $SKIPPED_CSV_OUT"
  ui_gauge 100 "Done."
}

# ===== Selection (dialog checklist) =====
do_selection_dialog() {
  ui_stop  # close split UI so the checklist fully takes over

  local -a items=()

  # ---------- A) Build items from upgrade plan (ready + not-ready) ----------
  while IFS=$'\t' read -r ip host pid cur tgt need ready ready_reason; do
    host="${host:--}"; pid="${pid:--}"; cur="${cur:-?}"; tgt="${tgt:-?}"
    if [[ "$ready" == "true" ]]; then
      local text="${host} (${ip})  ${pid}  ${cur} -> ${tgt}"
      local def="off"; [[ "$need" == "true" ]] && def="on"
      items+=("$ip" "$text" "$def")
    else
      local why; why="$(pretty_reason "$ready_reason")"
      local text="${host} (${ip})  ${pid}  ${cur} -> -  [INELIGIBLE: ${why}]"
      items+=("$ip" "$text" "off")
    fi
  done < <(jq -r '.[] | [.ip, (.hostname//"-"), (.pid//"-"), (.current_version//"?"), (.target_version//"?"),
                        (.needs_upgrade//false), ((.ready//false)|tostring), (.ready_reason//"unsupported")] | @tsv' "$UP_JSON_OUT")

  # ---------- B) Add any discovered hosts that didn't make it into the plan ----------
  declare -A PLAN_IPS
  while read -r pip; do PLAN_IPS["$pip"]=1; done < <(jq -r '.[].ip' "$UP_JSON_OUT")

  while IFS=$'\t' read -r ip host pid ver ssh login login_err; do
    [[ -n "${PLAN_IPS[$ip]:-}" ]] && continue
    host="${host:--}"; pid="${pid:--}"; ver="${ver:-?}"
    local reason=""
    if [[ "$ssh" != "true" ]]; then
      reason="ssh_closed"
    elif [[ "$login" != "true" ]]; then
      reason="login_failed${login_err:+:$login_err}"
    else
      reason="unknown"
    fi
    local why; why="$(pretty_reason "$reason")"
    local text="${host} (${ip})  ${pid}  ${ver} -> -  [INELIGIBLE: ${why}]"
    items+=("$ip" "$text" "off")
  done < <(jq -r '.[] | [.ip, (.hostname//"-"), (.pid//"-"), (.version//"?"), ((.ssh//false)|tostring), ((.login//false)|tostring), (.login_error//"")] | @tsv' "$JSON_OUT")

  if (( ${#items[@]} == 0 )); then
    dialog --no-shadow --infobox "No devices available for selection." 7 60
    sleep 2
    return 1
  fi

  local tmp_sel; tmp_sel="$(mktemp)"
  dialog --no-shadow --colors \
         --title "Select switches to upgrade" \
         --backtitle "Upgrade Selection" \
         --checklist "Use <SPACE> to toggle.\nItems tagged \Z1INELIGIBLE\Zn will be IGNORED." \
         22 110 15 \
         "${items[@]}" 2> "$tmp_sel"
  local rc=$?
  if (( rc != 0 )); then
    rm -f "$tmp_sel"
    dialog --no-shadow --infobox "Selection cancelled." 5 40
    sleep 2
    return 2
  fi

  mapfile -t SEL_ARR < <(tr -d '"' < "$tmp_sel")
  rm -f "$tmp_sel"

  if (( ${#SEL_ARR[@]} == 0 )); then
    dialog --no-shadow --infobox "No switches selected. Nothing to do." 6 50
    sleep 2
    return 3
  fi

  # Only allow devices with ready=true (from the plan)
  declare -A READY_MAP REASON_MAP
  while IFS=$'\t' read -r ip ready reason; do
    if [[ "$ready" == "true" ]]; then READY_MAP["$ip"]=1; fi
    REASON_MAP["$ip"]="$reason"
  done < <(jq -r '.[] | [.ip, ((.ready//false)|tostring), (.ready_reason//"unsupported")] | @tsv' "$UP_JSON_OUT")

  SELECTED_OK=()
  IGNORED=()
  for ip in "${SEL_ARR[@]}"; do
    if [[ -n "${READY_MAP[$ip]:-}" ]]; then
      SELECTED_OK+=("$ip")
    else
      IGNORED+=("$ip [$(pretty_reason "${REASON_MAP[$ip]:-unknown}")]")
    fi
  done

  if (( ${#SELECTED_OK[@]} == 0 )); then
    dialog --no-shadow --msgbox "All selected items were \Z1INELIGIBLE\Zn.\nNothing to do." 8 60
    return 4
  fi

  local ips_json
  ips_json="$(printf '%s\n' "${SELECTED_OK[@]}" | jq -R -s 'split("\n")|map(select(length>0))')"
  jq --argjson ips "$ips_json" '[ .[] | select( (.ip|tostring) as $x | $ips | index($x) ) ]' "$UP_JSON_OUT" > "$SEL_JSON_OUT"

  { echo "ip,hostname,pid,current_version,target_version,target_file,target_path,target_size_bytes,needs_upgrade"
    jq -r '.[] | [.ip, (.hostname//""), (.pid//""), (.current_version//""), (.target_version//""),
                   (.target_file//""), (.target_path//""), (.target_size_bytes//""), (.needs_upgrade//false)] | @csv' "$SEL_JSON_OUT"
  } > "$SEL_CSV_OUT"

  {
    echo "# Generated $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf "export UPGRADE_BASE_ENV=%q\n" "$ENV_FILE"
    printf "export UPGRADE_SELECTED_IPS=%q\n" "${SELECTED_OK[*]}"
    printf "export UPGRADE_SELECTED_JSON=%q\n" "$SEL_JSON_OUT"
    printf "export UPGRADE_SELECTED_CSV=%q\n" "$SEL_CSV_OUT"
  } > "$SEL_ENV_OUT"

  if (( ${#IGNORED[@]} > 0 )); then
    {
      echo "Selection saved."
      echo
      echo "Env:  $SEL_ENV_OUT"
      echo
      echo "Eligible selections:"
      echo "  ${SELECTED_OK[*]}"
      echo
      echo "Ignored (INELIGIBLE):"
      for x in "${IGNORED[@]}"; do echo "  $x"; done
      echo
      echo "(Only ready & eligible Catalyst 9200/9300/9400/9500/9600 can be upgraded.)"
    } | dialog --no-shadow --msgbox "$(cat -)" 20 100
  else
    dialog --no-shadow --infobox \
"Selection saved.

Env:  $SEL_ENV_OUT

Selected IPs:
  ${SELECTED_OK[*]}

(Only ready & eligible Catalyst 9200/9300/9400/9500/9600 can be upgraded.)" 13 90
    sleep 3
  fi

  return 0
}

# ===== Main =====
main() {
  ui_start; ui_gauge 1 "Initializing…"

  resolve_targets || {
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    ui_status "No targets."
    return 0
  }

  mapfile -t live < <(discover_targets)
  if [[ ${#live[@]} -eq 0 ]]; then
    ui_status "No live hosts found."
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    ui_gauge 100 "Done (no live hosts)."
    return 0
  fi
  ui_status "Live hosts: ${live[*]}"; ui_gauge 20 "Live hosts discovered."

  SSH_TMP="$(mktemp)"
  (
    set +e
    set +o pipefail 2>/dev/null || true
    ui_status "Starting SSH port scan…"
    filter_ssh_open "${live[@]}" >"$SSH_TMP" 2>>"$LOG_DIR/nmap.err"
    rc=$?
    echo "[diag] filter_ssh_open rc=$rc ($(date -u))" >> "$LOG_DIR/run.diag"
    exit 0
  ) || true

  if [[ ! -s "$SSH_TMP" ]]; then
    ui_status "[warn] SSH port scan returned no results; treating as 0 hosts."
  fi

  ssh_hosts=()
  if [[ -s "$SSH_TMP" ]]; then mapfile -t ssh_hosts < "$SSH_TMP" 2>/dev/null || true; fi
  rm -f "$SSH_TMP"
  ui_status "SSH port check: found ${#ssh_hosts[@]} host(s) with TCP/22 open."

  declare -A TCP22; for ip in "${ssh_hosts[@]}"; do TCP22["$ip"]=1; done

  if [[ ${#ssh_hosts[@]} -eq 0 ]]; then
    ui_status "No hosts with SSH open."
    emit_extra_json "${live[@]}" > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    jq -r '.[] | [.ip, .ssh, .login, (.hostname//""), (.version//""), (.pid//""), (.serial//"")] | @csv' "$JSON_OUT" >> "$CSV_OUT"
    make_upgrade_plan
    do_selection_dialog || true
    return 0
  fi

  ui_status "SSH hosts: ${ssh_hosts[*]}"
  TOTAL_SSH_HOSTS=${#ssh_hosts[@]}

  ui_status "Probing ${TOTAL_SSH_HOSTS} host(s) via SSH as ${SSH_USERNAME}…"; ui_gauge 30 "Probing devices…"
  TMPJSON="$(mktemp)"; : > "$TMPJSON"
  run_probe_pool "${ssh_hosts[@]}"

  mapfile -t probed_ips < <(jq -r '.[].ip' <(jq -s '.' "$TMPJSON")); declare -A seen; for ip in "${probed_ips[@]}"; do seen["$ip"]=1; done
  extra=(); for ip in "${live[@]}"; do [[ -n "${seen[$ip]:-}" ]] || extra+=("$ip"); done
  if [[ ${#extra[@]} -gt 0 ]]; then
    EXTRA_JSON="$(emit_extra_json "${extra[@]}")"
    jq -s '.[0] + .[1]' <(jq -s '.' "$TMPJSON") <(printf '%s' "$EXTRA_JSON") > "$JSON_OUT"
  else
    jq -s '.' "$TMPJSON" > "$JSON_OUT"
  fi
  rm -f "$TMPJSON"

  printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
  jq -r '.[] | [.ip, .ssh, .login, (.hostname//""), (.version//""), (.pid//""), (.serial//"")] | @csv' "$JSON_OUT" >> "$CSV_OUT"
  ui_status "Discovery results: $CSV_OUT"

  make_upgrade_plan
  do_selection_dialog || true
}

main "$@"
