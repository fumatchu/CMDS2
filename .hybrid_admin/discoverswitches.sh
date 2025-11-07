#!/usr/bin/env bash
# Catalyst/Meraki discovery + plan with split-screen dialog UI + selection
# - nmap discover -> SSH probe -> parse hostname/version/PID/SN
# - Builds upgrade plan (JSON/CSV)
# - Dialog checklist to pick switches to upgrade; writes selected_upgrade.{json,csv,env}
# - The final screen is the selection summary (no upgrade-plan display)

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

# --- De-escape %q artifacts from the setup script ---
__deq() {
  local s="${1//$'\r'/}"
  s="${s//\\!/!}"   # \! -> !
  s="${s//\\;/;}"   # \; -> ;
  s="${s//\\ / }"   # '\ ' -> ' '
  s="${s//\\\\/\\}" # \\ -> \
  printf '%s' "$s"
}

SSH_USERNAME="$(__deq "${SSH_USERNAME:-}")"
SSH_PASSWORD="$(__deq "${SSH_PASSWORD:-}")"
ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD:-}")"
MERAKI_API_KEY="$(__deq "${MERAKI_API_KEY:-}")"
DISCOVERY_IPS="$(__deq "${DISCOVERY_IPS:-}")"
DISCOVERY_NETWORKS="$(__deq "${DISCOVERY_NETWORKS:-}")"

# ===== Config / defaults =====
DISCOVERY_MODE="${DISCOVERY_MODE:-}"           # list|networks|scan|cidr|subnets|(auto)
DISCOVERY_IPS="${DISCOVERY_IPS:-}"
DISCOVERY_IPS_FILE="${DISCOVERY_IPS_FILE:-}"
DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
DISCOVERY_INTERFACE="${DISCOVERY_INTERFACE:-}"
SSH_USERNAME="${SSH_USERNAME:-admin}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"
ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"
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

# ===== runs/ + devlogs wiring =====
RUNS_ROOT="$OUT_DIR/runs/discoveryscans"
mkdir -p "$RUNS_ROOT"

# Run tag (still UTC for uniqueness of folder names)
RUN_TS="$(date -u '+%Y%m%d%H%M%S')"
RUN_TAG="scan-$RUN_TS"
RUN_DIR="$RUNS_ROOT/$RUN_TAG"
mkdir -p "$RUN_DIR"

DEVLOG_DIR="$RUN_DIR/devlogs"
mkdir -p "$DEVLOG_DIR"

# Main discovery run log (match other tools: ui.status)
DEV_LOG="$RUN_DIR/ui.status"

# Per-host probe logs live here
PROBE_LOG_DIR="$DEVLOG_DIR"

# Keep a "latest" pointer
ln -sfn "$RUN_DIR" "$RUNS_ROOT/latest"

# Symlinks to the main JSON/CSV/plan files for this run
ln -sfn "$JSON_OUT"    "$RUN_DIR/discovery_results.json"
ln -sfn "$CSV_OUT"     "$RUN_DIR/discovery_results.csv"
ln -sfn "$UP_JSON_OUT" "$RUN_DIR/upgrade_plan.json"
ln -sfn "$UP_CSV_OUT"  "$RUN_DIR/upgrade_plan.csv"

log_msg() {
  # Local time in the log, to match other ui.status logs
  printf '%s [%s] %s\n' "$(date '+%F %T')" "$RUN_TAG" "$*" >>"$DEV_LOG"
}

# Normalize CRLF in creds
SSH_USERNAME="$(printf '%s' "${SSH_USERNAME:-}" | tr -d '\r')"
SSH_PASSWORD="$(printf '%s' "${SSH_PASSWORD:-}" | tr -d '\r')"

dbg() {
  if [[ "$DEBUG" == "1" ]]; then
    echo "[debug] $*" >&2
    log_msg "[debug] $*"
  fi
}

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
  log_msg "UI: start (DIALOG_AVAILABLE=$DIALOG_AVAILABLE)"
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
ui_status() {
  local msg="$1"
  log_msg "STATUS: $msg"
  printf '%(%H:%M:%S)T %s\n' -1 "$msg" >> "$STATUS_FILE"
  (( DIALOG_AVAILABLE )) || echo "$msg"
}
ui_gauge()  {
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
  rm -f "$STATUS_FILE" 2>/dev/null || true
}
trap 'ui_stop' EXIT

# ===== helpers =====
clean_field() { local s; s="$(printf '%s' "$1" | tr -d '\r\n')"; s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//; s/[#]$//')"; printf '%s' "$s"; }

# --- version helpers (for UPGRADE/DOWNGRADE/SAME labels) ---
extract_iosxe_ver_from_file() {  # from: cat9k_lite_iosxe.17.15.03.SPA.bin
  local f="$1" b="${1##*/}" v
  v="$(sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' <<<"$b")"
  [[ -n "$v" ]] || v="$(sed -nE 's/.*([0-9]+(\.[0-9]+){1,4}).*/\1/p' <<<"$b")"
  printf '%s\n' "$v"
}
sanitize_ver(){ local v="${1:-}"; v="${v//[^0-9.]/}"; sed -E 's/\.+/./g; s/^\.//; s/\.$//' <<<"$v"; }
vercmp(){  # -1 (a<b), 0 (==), 1 (a>b)
  local a b i len ai bi
  a="$(sanitize_ver "$1")"; b="$(sanitize_ver "$2")"
  IFS='.' read -r -a A <<<"${a:-0}"; IFS='.' read -r -a B <<<"${b:-0}"
  (( len = ${#A[@]} > ${#B[@]} ? ${#A[@]} : ${#B[@]} ))
  for ((i=0;i<len;i++)); do
    ai="${A[i]:-0}"; bi="${B[i]:-0}"
    ((10#$ai < 10#$bi)) && { echo -1; return; }
    ((10#$ai > 10#$bi)) && { echo 1; return; }
  done; echo 0
}
plan_action_label(){  # UPGRADE/DOWNGRADE/SAME/UNKNOWN
  local cur="$(sanitize_ver "$1")" tgt="$(sanitize_ver "$2")"
  [[ -z "$cur" || -z "$tgt" ]] && { echo "UNKNOWN"; return; }
  case "$(vercmp "$cur" "$tgt")" in -1) echo "UPGRADE";; 1) echo "DOWNGRADE";; 0) echo "SAME";; esac
}

# ===== SSH probe (pure Bash; no expect) =====
probe_host() {
  local ip="$1" log="$PROBE_LOG_DIR/$ip.log"
  : > "$log"
  log_msg "probe_host: start ip=$ip"
  ui_status "[${ip}] Probing via SSH…"
  ui_status "[${ip}] SSH: connecting…"

  local -a SSH_CMD
  if [[ -n "$SSH_KEY_PATH" && -r "$SSH_KEY_PATH" ]]; then
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
    local timeout_secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
      timeout -k 5s "${timeout_secs}s" "${SSH_CMD[@]}"
    else
      "${SSH_CMD[@]}"
    fi
  }

  local out_priv facts outn
  out_priv="$(mktemp)"
  facts="$(mktemp)"
  outn="$(mktemp)"

  {
    printf '\r\n\r\n'
    printf 'terminal length 0\r\n'
    printf 'terminal width 511\r\n'
    printf 'show privilege\r\n'
    printf 'exit\r\n'
  } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$out_priv" 2>&1

  tr -d '\r' < "$out_priv" | tee -a "$log" > "$outn"

  local at15=0
  if grep -Eq 'Current privilege level is[[:space:]]*15' "$outn"; then
    at15=1
  fi
  log_msg "probe_host: ip=$ip after pass1 at15=$at15"

  : > "$outn"
  if (( at15 == 1 )); then
    ui_status "[${ip}] Privilege 15 detected; collecting facts…"
    {
      printf '\r\n\r\n'
      printf 'terminal length 0\r\n'
      printf 'terminal width 511\r\n'
      printf 'show clock\r\n'
      printf 'show version\r\n'
      printf 'show running-config | include ^hostname\r\n'
      printf 'show inventory\r\n'
      printf 'exit\r\n'
    } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1
  else
    if [[ -n "${ENABLE_PASSWORD:-}" ]]; then
      ui_status "[${ip}] Not privileged; attempting enable…"
      {
        printf '\r\n\r\n'
        printf 'terminal length 0\r\n'
        printf 'terminal width 511\r\n'
        printf 'enable\r\n'
        printf '%s\r\n' "$ENABLE_PASSWORD"
        printf 'show privilege\r\n'
        printf 'show clock\r\n'
        printf 'show version\r\n'
        printf 'show running-config | include ^hostname\r\n'
        printf 'show inventory\r\n'
        printf 'exit\r\n'
      } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1
    else
      ui_status "[${ip}] No enable secret; collecting what we can…"
      {
        printf '\r\n\r\n'
        printf 'terminal length 0\r\n'
        printf 'terminal width 511\r\n'
        printf 'show clock\r\n'
        printf 'show version\r\n'
        printf 'show running-config | include ^hostname\r\n'
        printf 'show inventory\r\n'
        printf 'exit\r\n'
      } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1
    fi
  fi

  tr -d '\r' < "$facts" | tee -a "$log" > "$outn"

  local login_ok=0
  if grep -Eq 'Cisco IOS|IOS XE| uptime is |^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$|Current privilege level is' "$outn"; then
    login_ok=1
  fi
  (( login_ok )) && ui_status "[${ip}] SSH: logged in and collected output."

  local hostname version pid sn
  hostname="$(awk '/^hostname[[:space:]]+/{print $2}' "$outn" | tail -n1)"
  [[ -z "$hostname" ]] && hostname="$(grep -E '^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$' "$outn" | tail -n1 | sed -E 's/[>#].*$//')"
  [[ -z "$hostname" ]] && hostname="$(grep -m1 -E ' uptime is ' "$outn" | awk '{print $1}')"
  hostname="$(clean_field "${hostname:-}")"

  version="$(grep -m1 -E 'Cisco IOS XE Software, Version[[:space:]]+' "$outn" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  [[ -z "$version" ]] && version="$(grep -m1 -E 'Cisco IOS Software|Version[[:space:]]+[0-9]' "$outn" | sed -E 's/.*Version[[:space:]]+([^, ]+).*/\1/')"
  version="$(clean_field "${version:-}")"

  pid="$(grep -m1 -E 'PID:[[:space:]]*[^,]+' "$outn" | sed -E 's/.*PID:[[:space:]]*([^,]+).*/\1/')"
  sn="$(grep -m1 -E 'SN:[[:space:]]*[A-Za-z0-9]+' "$outn" | sed -E 's/.*SN:[[:space:]]*([^,[:space:]]+).*/\1/')"
  pid="$(clean_field "${pid:-}")"; sn="$(clean_field "${sn:-}")"

  rm -f "$out_priv" "$facts" "$outn"

  if (( login_ok )); then
    log_msg "probe_host: ip=$ip login=ok hostname='${hostname:-}' version='${version:-}' pid='${pid:-}' sn='${sn:-}'"
    jq -n --arg ip "$ip" --arg host "${hostname:-}" --arg ver "${version:-}" --arg pid "${pid:-}" --arg sn "${sn:-}" \
          '{ip:$ip, ssh:true, login:true, hostname:$host, version:$ver, pid:$pid, serial:$sn}'
  else
    log_msg "probe_host: ip=$ip login=failed"
    jq -n --arg ip "$ip" '{ip:$ip, ssh:true, login:false}'
  fi
}

# ===== Discovery =====
resolve_targets() {
  local mode="${DISCOVERY_MODE,,}" targets=()
  case "$mode" in
    list|iplist|hosts)
      mapfile -t targets < <(read_ip_list)
      ;;
    networks|scan|cidr|subnets)
      [[ -n "$DISCOVERY_NETWORKS" ]] && mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list)
      ;;
    *)
      if [[ -n "$DISCOVERY_IPS" || -n "$DISCOVERY_IPS_FILE" ]]; then
        mapfile -t targets < <(read_ip_list); mode="list"
      elif [[ -n "$DISCOVERY_NETWORKS" ]]; then
        mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list); mode="networks"
      fi
      ;;
  esac
  [[ ${#targets[@]} -gt 0 ]] || { echo "No targets: set DISCOVERY_MODE=list & DISCOVERY_IPS, or DISCOVERY_MODE=scan|networks & DISCOVERY_NETWORKS" >&2; return 1; }
  if [[ -n "$DISCOVERY_INTERFACE" ]]; then
    ui_status "Using interface override: $DISCOVERY_INTERFACE"
    USE_IFACE=1
  else
    ui_status "Interface: kernel default (no -e override)"
    USE_IFACE=0
  fi
  TARGET_MODE="$mode"; TARGETS=("${targets[@]}")
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
pass_a() { local probes=(-PE -PS22,80,443,830 -PA22,443); (( USE_IFACE )) && probes+=(-PR); local cmd=(nmap $(nmap_cmd_base) -sn "${probes[@]}" --max-retries 2 "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' || true; }
pass_b() { local cmd=(nmap $(nmap_cmd_base) -sn -PE "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' || true; }
pass_c() { local cmd=(nmap $(nmap_cmd_base) -sn -Pn -PS22,80,443 "${TARGETS[@]}"); "${cmd[@]}" -oG - 2>/dev/null | awk '/Status: Up/{print $2}' || true; }
pass_fping() {
  command -v fping >/dev/null 2>&1 || return 0
  local out=()
  for t in "${TARGETS[@]}"; do
    if [[ "$t" =~ / ]]; then
      mapfile -t out < <(fping -a -q -g "$t" 2>/dev/null || true)
    else
      mapfile -t out < <(printf '%s\n' "$t" | fping -a -q 2>/dev/null || true)
    fi
  done
  printf '%s\n' "${out[@]}" | awk 'NF'
}

discover_targets() {
  ui_status "Discovering live hosts (pass 1/3)…"; ui_gauge 5 "Scanning (hybrid)…"
  local live=(); mapfile -t live < <(pass_a)
  if [[ ${#live[@]} -eq 0 ]]; then
    ui_status "Trying ICMP only…"; ui_gauge 10 "Scanning (ICMP)…"; mapfile -t live < <(pass_b)
  fi
  if [[ ${#live[@]} -eq 0 ]]; then
    ui_status "Trying TCP-only ping…"; ui_gauge 15 "Scanning (TCP)…"; mapfile -t live < <(pass_c)
  fi
  if [[ ${#live[@]} -eq 0 ]]; then
    ui_status "Trying fping fallback…"; mapfile -t live < <(pass_fping)
  fi
  log_msg "discover_targets: live_count=${#live[@]} live='${live[*]:-}'"
  printf '%s\n' "${live[@]}" | awk -F. '!(NF==4 && ($4==0 || $4==255))' | sort -u
}

filter_ssh_open() {
  local ips=("$@")
  if [[ ${#ips[@]} -eq 0 ]]; then
    ui_status "No hosts to check for SSH."
    return 0
  fi
  ui_status "Checking TCP/22 on ${#ips[@]} host(s)…"; ui_gauge 25 "Checking SSH ports…"
  local cmd=(nmap $(nmap_cmd_base) -Pn --open -p22 --max-retries 2 "${ips[@]}")
  "${cmd[@]}" -oG - 2>/dev/null | awk '/Ports: 22\/open/{print $2}' || true
  return 0
}

emit_extra_json() {
  local hosts=("$@")
  for ip in "${hosts[@]}"; do
    if [[ -n "${TCP22[$ip]:-}" ]]; then
      printf '{"ip":"%s","ssh":true,"login":false}\n' "$ip"
    else
      printf '{"ip":"%s","ssh":false,"login":false}\n' "$ip"
    fi
  done | jq -s '.'
}

HAS_WAIT_N=0
if help wait >/dev/null 2>&1 && help wait 2>&1 | grep -q -- '-n'; then HAS_WAIT_N=1; fi

run_probe_pool() {
  local hosts=("$@") max=${MAX_SSH_FANOUT} total=${#hosts[@]}
  local running=0 done=0 pids=()
  log_msg "run_probe_pool: fanout=$max total=$total"
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
      local pct=$(( 25 + 60 * done / total ))
      ui_gauge "$pct" "Probing devices… ($done / $total)"
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
    local pct=$(( 25 + 60 * done / total ))
    ui_gauge "$pct" "Probing devices… ($done / $total)"
    ((running--))
  done
  log_msg "run_probe_pool: finished probed=$done"
}

# ===== Upgrade planning =====
choose_image() {
  local pid="$1"
  local file path ver size
  if [[ "$pid" =~ (^|-)C9200 ]] || [[ "$pid" =~ (^|-)C9200CX ]] || [[ "$pid" =~ (^|-)C9200L ]]; then
    file="${FW_CAT9K_LITE_FILE:-}"; path="${FW_CAT9K_LITE_PATH:-}"
    ver="${FW_CAT9K_LITE_VERSION:-}"; size="${FW_CAT9K_LITE_SIZE_BYTES:-}"
  else
    file="${FW_CAT9K_FILE:-}"; path="${FW_CAT9K_PATH:-}"
    ver="${FW_CAT9K_VERSION:-}"; size="${FW_CAT9K_SIZE_BYTES:-}"
  fi
  [[ -z "$ver" && -n "$file" ]] && ver="$(extract_iosxe_ver_from_file "$file")"
  [[ -z "$ver" && -n "$path" ]] && ver="$(extract_iosxe_ver_from_file "$path")"
  [[ -z "$size" && -n "$path" && -f "$path" ]] && size="$(stat -c %s "$path" 2>/dev/null || echo "")"
  printf '%s|%s|%s|%s\n' "${file:-}" "${path:-}" "${ver:-}" "${size:-}"
}

make_upgrade_plan() {
  local json="$JSON_OUT"
  if [[ ! -s "$json" ]]; then
    ui_status "No discovery JSON to build an upgrade plan (file empty)."
    log_msg "make_upgrade_plan: $json is empty or missing"
    echo "[]" > "$UP_JSON_OUT"
    { echo "ip,hostname,pid,current_version,target_version,plan_action,target_file,target_path,target_size_bytes,needs_upgrade"; } > "$UP_CSV_OUT"
    return 0
  fi

  local disc_count
  disc_count="$(jq 'length' "$json" 2>/dev/null || echo 0)"
  log_msg "make_upgrade_plan: discovery entries=$disc_count"
  ui_gauge 90 "Building upgrade plan for $disc_count device(s)…"

  jq -r '.[] | [.ip, .pid, .version, .hostname] | @tsv' "$json" |
    while IFS=$'\t' read -r ip pid cur_ver host; do
      IFS='|' read -r tgt_file tgt_path tgt_ver tgt_size <<<"$(choose_image "$pid")"

      local action need
      if [[ -n "$tgt_ver" && -n "$cur_ver" ]]; then
        action="$(plan_action_label "$cur_ver" "$tgt_ver")"
      else
        action="UNKNOWN"
      fi
      case "$action" in
        UPGRADE|DOWNGRADE) need="true" ;;
        SAME|UNKNOWN|"")   need="false" ;;
      esac

      jq -n --arg ip "$ip" --arg hostname "${host:-}" --arg pid "$pid" \
            --arg current_version "${cur_ver:-}" --arg target_version "${tgt_ver:-}" \
            --arg target_file "${tgt_file:-}" --arg target_path "${tgt_path:-}" \
            --arg target_size "${tgt_size:-}" --arg action "$action" --arg needs "$need" \
            '{ip:$ip, hostname:$hostname, pid:$pid,
              current_version:$current_version, target_version:$target_version,
              target_file:$target_file, target_path:$target_path,
              target_size_bytes: ($target_size|tonumber?),
              plan_action:$action, needs_upgrade: ($needs=="true") }'
    done | jq -s '.' > "$UP_JSON_OUT"

  local up_count
  up_count="$(jq 'length' "$UP_JSON_OUT" 2>/dev/null || echo 0)"
  log_msg "make_upgrade_plan: initial plan entries=$up_count"

  if (( disc_count > 0 && up_count == 0 )); then
    log_msg "make_upgrade_plan: WARNING plan entries=0 while discovery entries=$disc_count; building passthrough plan."
    jq '[ .[] | {
            ip,
            hostname,
            pid,
            current_version: (.version//""),
            target_version: "",
            target_file: "",
            target_path: "",
            target_size_bytes: null,
            plan_action: "UNKNOWN",
            needs_upgrade: false
          } ]' "$json" > "$UP_JSON_OUT"
    up_count="$(jq 'length' "$UP_JSON_OUT" 2>/dev/null || echo 0)"
    log_msg "make_upgrade_plan: passthrough plan entries=$up_count"
  fi

  {
    echo "ip,hostname,pid,current_version,target_version,plan_action,target_file,target_path,target_size_bytes,needs_upgrade"
    jq -r '.[] | [.ip, (.hostname//""), (.pid//""), (.current_version//""), (.target_version//""), (.plan_action//""), (.target_file//""), (.target_path//""), (.target_size_bytes//""), (.needs_upgrade//false)] | @csv' "$UP_JSON_OUT"
  } > "$UP_CSV_OUT"

  ui_status "Upgrade plan written: $UP_CSV_OUT (entries: $up_count)"
  ui_gauge 100 "Done."
}

# ===== Selection (dialog checklist) =====
do_selection_dialog() {
  local -a items=()
  while IFS=$'\t' read -r ip host pid cur tgt action need; do
    host="${host:--}"; pid="${pid:--}"; cur="${cur:-?}"; tgt="${tgt:-?}"; action="${action:-UNKNOWN}"
    local text="${host} (${ip})  ${pid}  ${cur} -> ${tgt} (${action})"
    local def="off"; [[ "$need" == "true" ]] && def="on"
    items+=("$ip" "$text" "$def")
  done < <(jq -r '.[] | [.ip, (.hostname//"-"), (.pid//"-"), (.current_version//"?"), (.target_version//"?"), (.plan_action//"UNKNOWN"), (.needs_upgrade//false)] | @tsv' "$UP_JSON_OUT")

  if (( ${#items[@]} == 0 )); then
    dialog --no-shadow --infobox "No devices available for selection.\n(Upgrade plan had zero items.)" 7 60
    sleep 3
    return 1
  fi

  ui_stop
  local tmp_sel; tmp_sel="$(mktemp)"
  dialog --no-shadow --title "Select switches to upgrade" \
         --backtitle "Upgrade Selection" \
         --checklist "Use <SPACE> to toggle. Pre-selected = needs upgrade." \
         22 100 15 \
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

  local ips_json
  ips_json="$(printf '%s\n' "${SEL_ARR[@]}" | jq -R -s 'split("\n")|map(select(length>0))')"
  jq --argjson ips "$ips_json" '[ .[] | select( (.ip|tostring) as $x | $ips | index($x) ) ]' "$UP_JSON_OUT" > "$SEL_JSON_OUT"

  {
    echo "ip,hostname,pid,current_version,target_version,plan_action,target_file,target_path,target_size_bytes,needs_upgrade"
    jq -r '.[] | [.ip, (.hostname//""), (.pid//""), (.current_version//""), (.target_version//""), (.plan_action//""), (.target_file//""), (.target_path//""), (.target_size_bytes//""), (.needs_upgrade//false)] | @csv' "$SEL_JSON_OUT"
  } > "$SEL_CSV_OUT"

  {
    echo "# Generated $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf "export UPGRADE_BASE_ENV=%q\n" "$ENV_FILE"
    printf "export UPGRADE_SELECTED_IPS=%q\n" "${SEL_ARR[*]}"
    printf "export UPGRADE_SELECTED_JSON=%q\n" "$SEL_JSON_OUT"
    printf "export UPGRADE_SELECTED_CSV=%q\n" "$SEL_CSV_OUT"
  } > "$SEL_ENV_OUT"

  dialog --no-shadow --infobox \
"Selection saved.

Env:  $SEL_ENV_OUT

Selected IPs:
  ${SEL_ARR[*]}

Use this env in your upgrade step." 12 80
  sleep 3
  return 0
}

# ===== Main =====
main() {
  log_msg "=== scan run start ==="
  log_msg "ENV_FILE=$ENV_FILE"
  log_msg "DISCOVERY_MODE=${DISCOVERY_MODE:-} DISCOVERY_IPS=${DISCOVERY_IPS:-} DISCOVERY_NETWORKS=${DISCOVERY_NETWORKS:-}"
  log_msg "SSH_USERNAME=${SSH_USERNAME:-} MAX_SSH_FANOUT=${MAX_SSH_FANOUT:-1} UI_MODE=${UI_MODE:-dialog}"

  ui_start; ui_gauge 1 "Initializing…"

  resolve_targets || {
    ui_status "No targets; writing empty discovery outputs."
    log_msg "main: resolve_targets returned non-zero; no targets."
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    return 0
  }

  mapfile -t live < <(discover_targets)
  if [[ ${#live[@]} -eq 0 ]]; then
    ui_status "No live hosts found."
    log_msg "main: no live hosts."
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    ui_gauge 100 "Done (no live hosts)."
    return 0
  fi
  ui_status "Live hosts: ${live[*]}"; ui_gauge 20 "Live hosts discovered."
  log_msg "main: live_count=${#live[@]} live='${live[*]}'"

  SSH_TMP="$(mktemp)"
  filter_ssh_open "${live[@]}" >"$SSH_TMP" 2>/dev/null || true
  ssh_hosts=()
  if [[ -s "$SSH_TMP" ]]; then mapfile -t ssh_hosts < "$SSH_TMP" 2>/dev/null || true; fi
  rm -f "$SSH_TMP"
  ui_status "SSH port check: found ${#ssh_hosts[@]} host(s) with TCP/22 open."
  log_msg "main: ssh_open_count=${#ssh_hosts[@]} ssh_hosts='${ssh_hosts[*]:-}'"

  declare -A TCP22; for ip in "${ssh_hosts[@]}"; do TCP22["$ip"]=1; done

  if [[ ${#ssh_hosts[@]} -eq 0 ]]; then
    ui_status "No hosts with SSH open."
    log_msg "main: no ssh-open hosts; emitting minimal JSON for live hosts."
    emit_extra_json "${live[@]}" > "$JSON_OUT"
    printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
    jq -r '.[] | [.ip, .ssh, .login, (.hostname//""), (.version//""), (.pid//""), (.serial//"")] | @csv' "$JSON_OUT" >> "$CSV_OUT"
    local disc_count
    disc_count="$(jq 'length' "$JSON_OUT" 2>/dev/null || echo 0)"
    log_msg "main: discovery JSON entries (no-SSH case)=$disc_count"
    make_upgrade_plan
    if (( DIALOG_AVAILABLE )); then
      do_selection_dialog || true
    else
      echo "Selection UI skipped (dialog not available)."
    fi
    return 0
  fi

  ui_status "SSH hosts: ${ssh_hosts[*]}"
  TOTAL_SSH_HOSTS=${#ssh_hosts[@]}
  log_msg "main: total ssh_hosts=${TOTAL_SSH_HOSTS}"

  ui_status "Probing ${TOTAL_SSH_HOSTS} host(s) via SSH as ${SSH_USERNAME}…"; ui_gauge 30 "Probing devices…"
  TMPJSON="$(mktemp)"; : > "$TMPJSON"
  run_probe_pool "${ssh_hosts[@]}"

  mapfile -t probed_ips < <(jq -r '.[].ip' <(jq -s '.' "$TMPJSON")) || probed_ips=()
  declare -A seen; for ip in "${probed_ips[@]}"; do seen["$ip"]=1; done
  extra=(); for ip in "${live[@]}"; do [[ -n "${seen[$ip]:-}" ]] || extra+=("$ip"); done

  if [[ ${#extra[@]} -gt 0 ]]; then
    log_msg "main: extra (live-but-unprobed) hosts=${#extra[@]} extra='${extra[*]}'"
    EXTRA_JSON="$(emit_extra_json "${extra[@]}")"
    jq -s '.[0] + .[1]' <(jq -s '.' "$TMPJSON") <(printf '%s' "$EXTRA_JSON") > "$JSON_OUT"
  else
    jq -s '.' "$TMPJSON" > "$JSON_OUT"
  fi
  rm -f "$TMPJSON"

  local disc_count
  disc_count="$(jq 'length' "$JSON_OUT" 2>/dev/null || echo 0)"
  log_msg "main: discovery JSON entries=$disc_count"

  printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
  jq -r '.[] | [.ip, .ssh, .login, (.hostname//""), (.version//""), (.pid//""), (.serial//"")] | @csv' "$JSON_OUT" >> "$CSV_OUT"
  ui_status "Discovery results: $CSV_OUT"

  make_upgrade_plan

  if (( DIALOG_AVAILABLE )); then
    do_selection_dialog || true
  else
    echo "Selection UI skipped (dialog not available)."
  fi

  log_msg "=== scan run complete ==="
}

main "$@"
