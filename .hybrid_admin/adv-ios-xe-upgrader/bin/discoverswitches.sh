#!/usr/bin/env bash
# Catalyst/Meraki discovery + plan + selection (show ALL devices; blacklist ONLY if not manageable)
# - Uses ONLY: /root/.hybrid_admin/adv-ios-xe-upgrader/meraki_discovery.env
# - Always shows every device (manual list => all listed; scan => all discovered "Up")
# - Blacklist only for: SSH closed OR login/auth failure (cannot be manipulated)
# - Writes outputs to same directory as meraki_discovery.env
# - Selection UI sorts non-blocked first, blocked last

set -Euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# ===== ENV: fixed path ONLY =====
ENV_FILE="/root/.hybrid_admin/adv-ios-xe-upgrader/meraki_discovery.env"
[[ -f "$ENV_FILE" && -r "$ENV_FILE" ]] || { echo "Missing ENV: $ENV_FILE" >&2; exit 1; }
echo "Using ENV file: $ENV_FILE" >&2

set +H
# shellcheck disable=SC1090
source "$ENV_FILE"

# --- De-escape %q artifacts from setup script ---
__deq() {
  local s="${1//$'\r'/}"
  s="${s//\\!/!}"
  s="${s//\\;/;}"
  s="${s//\\ / }"
  s="${s//\\\\/\\}"
  printf '%s' "$s"
}

SSH_USERNAME="$(__deq "${SSH_USERNAME:-}")"
SSH_PASSWORD="$(__deq "${SSH_PASSWORD:-}")"
ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD:-}")"
DISCOVERY_IPS="$(__deq "${DISCOVERY_IPS:-}")"
DISCOVERY_NETWORKS="$(__deq "${DISCOVERY_NETWORKS:-}")"
DISCOVERY_MODE="$(__deq "${DISCOVERY_MODE:-}")"
DISCOVERY_INTERFACE="$(__deq "${DISCOVERY_INTERFACE:-}")"
DISCOVERY_IPS_FILE="$(__deq "${DISCOVERY_IPS_FILE:-}")"
SSH_KEY_PATH="$(__deq "${SSH_KEY_PATH:-}")"

# ===== Config / defaults =====
MAX_SSH_FANOUT="${MAX_SSH_FANOUT:-10}"
SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
DEBUG="${DISCOVERY_DEBUG:-0}"
UI_MODE="${UI_MODE:-dialog}"   # dialog|plain

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need nmap; need jq; need awk; need sed
command -v sshpass >/dev/null 2>/dev/null || echo "NOTE: sshpass not found; password auth disabled unless SSH_KEY_PATH is set."

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
RUN_TS="$(date -u '+%Y%m%d%H%M%S')"
RUN_TAG="scan-$RUN_TS"
RUN_DIR="$RUNS_ROOT/$RUN_TAG"
mkdir -p "$RUN_DIR"
DEVLOG_DIR="$RUN_DIR/devlogs"
mkdir -p "$DEVLOG_DIR"
DEV_LOG="$RUN_DIR/ui.status"
PROBE_LOG_DIR="$DEVLOG_DIR"
ln -sfn "$RUN_DIR" "$RUNS_ROOT/latest"

ln -sfn "$JSON_OUT"    "$RUN_DIR/discovery_results.json"
ln -sfn "$CSV_OUT"     "$RUN_DIR/discovery_results.csv"
ln -sfn "$UP_JSON_OUT" "$RUN_DIR/upgrade_plan.json"
ln -sfn "$UP_CSV_OUT"  "$RUN_DIR/upgrade_plan.csv"

log_msg() { printf '%s [%s] %s\n' "$(date '+%F %T')" "$RUN_TAG" "$*" >>"$DEV_LOG"; }

dbg() {
  if [[ "$DEBUG" == "1" ]]; then
    echo "[debug] $*" >&2
    log_msg "[debug] $*"
  fi
}

split_list() { tr ',;' ' ' | xargs -n1 | awk 'NF'; }

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
  GAUGE_H=7
  GAUGE_W=$TAIL_W
  GAUGE_ROW=$((TAIL_H + 3))
  GAUGE_COL=2
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
             --backtitle "Discovering Switches" \
             --begin 2 2 --title "Activity" --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
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
plan_action_label(){  # UPGRADE/DOWNGRADE/SAME/UNKNOWN
  local cur="$(sanitize_ver "$1")" tgt="$(sanitize_ver "$2")"
  [[ -z "$cur" || -z "$tgt" ]] && { echo "UNKNOWN"; return; }
  case "$(vercmp "$cur" "$tgt")" in
    -1) echo "UPGRADE" ;;
     1) echo "DOWNGRADE" ;;
     0) echo "SAME" ;;
  esac
}

extract_iosxe_ver_from_file() {
  local b="${1##*/}" v
  v="$(sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' <<<"$b")"
  [[ -n "$v" ]] || v="$(sed -nE 's/.*([0-9]+(\.[0-9]+){1,4}).*/\1/p' <<<"$b")"
  printf '%s\n' "$v"
}

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

# ===== Discovery =====
resolve_targets() {
  local mode="${DISCOVERY_MODE,,}" targets=()

  case "$mode" in
    list|iplist|hosts) mapfile -t targets < <(read_ip_list) ;;
    networks|scan|cidr|subnets)
      [[ -n "$DISCOVERY_NETWORKS" ]] && mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list)
      ;;
    *)
      if [[ -n "${DISCOVERY_IPS:-}" || -n "${DISCOVERY_IPS_FILE:-}" ]]; then
        mapfile -t targets < <(read_ip_list); mode="list"
      elif [[ -n "${DISCOVERY_NETWORKS:-}" ]]; then
        mapfile -t targets < <(printf '%s\n' "$DISCOVERY_NETWORKS" | split_list); mode="networks"
      fi
      ;;
  esac

  [[ ${#targets[@]} -gt 0 ]] || { echo "No targets configured." >&2; return 1; }

  if [[ -n "$DISCOVERY_INTERFACE" ]]; then
    ui_status "Using interface override: $DISCOVERY_INTERFACE"
    USE_IFACE=1
  else
    ui_status "Interface: kernel default (no -e override)"
    USE_IFACE=0
  fi

  TARGET_MODE="$mode"
  TARGETS=("${targets[@]}")

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

  { "${cmd[@]}" -oG - 2>/dev/null | awk '/Up$/{print $2}' >"$tmp"; } &
  local scan_pid=$!

  local elapsed=0
  while kill -0 "$scan_pid" 2>/dev/null; do
    ui_status "${label}… (elapsed ${elapsed}s)"
    sleep 5
    ((elapsed+=5))
  done
  wait "$scan_pid" 2>/dev/null || true

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    ui_status "Discovered live host: $ip"
    printf '%s\n' "$ip"
  done < "$tmp"
  rm -f "$tmp"
}

pass_a() { run_nmap_with_heartbeat "Discovering live hosts (pass 1/3)" -PE -PS22,80,443,830 -PA22,443; }
pass_b() { run_nmap_with_heartbeat "Discovering live hosts (ICMP-only)" -PE; }
pass_c() { run_nmap_with_heartbeat "Discovering live hosts (TCP ping)" -Pn -PS22,80,443; }

discover_targets() {
  ui_status "Discovering live hosts (pass 1/3)…"; ui_gauge 5 "Scanning…"
  local live=(); mapfile -t live < <(pass_a)
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying ICMP only…"; ui_gauge 10 "Scanning…"; mapfile -t live < <(pass_b); fi
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying TCP-only ping…"; ui_gauge 15 "Scanning…"; mapfile -t live < <(pass_c); fi
  log_msg "discover_targets: live_count=${#live[@]}"
  printf '%s\n' "${live[@]}" | sort -u
}

filter_ssh_open_grepable() {
  local ips=("$@")
  (( ${#ips[@]} == 0 )) && return 0
  ui_status "Scanning TCP/22 on ${#ips[@]} host(s)…"; ui_gauge 25 "Checking SSH ports…"
  local cmd=(nmap $(nmap_cmd_base) -Pn -p22 --max-retries 2 "${ips[@]}")
  "${cmd[@]}" -oG - 2>/dev/null || true
}

_reason_from_ssh_output() {
  local out="$1"
  if grep -qiE 'Permission denied|Authentication failed' <<<"$out"; then
    echo "AUTH FAILED"
  elif grep -qiE 'Connection timed out|Operation timed out|timed out' <<<"$out"; then
    echo "SSH TIMEOUT"
  elif grep -qiE 'Connection refused' <<<"$out"; then
    echo "SSH REFUSED"
  elif grep -qiE 'No route to host|Network is unreachable' <<<"$out"; then
    echo "NO ROUTE"
  elif grep -qiE 'Could not resolve hostname|Name or service not known' <<<"$out"; then
    echo "DNS/RESOLUTION FAILED"
  elif grep -qiE 'Host key verification failed' <<<"$out"; then
    echo "HOSTKEY FAILED"
  elif grep -qiE 'REMOTE HOST IDENTIFICATION HAS CHANGED' <<<"$out"; then
    echo "HOSTKEY CHANGED"
  elif grep -qiE 'Connection closed by remote host|closed by remote host' <<<"$out"; then
    echo "CONNECTION CLOSED"
  else
    echo "LOGIN FAILED"
  fi
}

probe_host() {
  local ip="$1" log="$PROBE_LOG_DIR/$ip.log"
  : > "$log"
  log_msg "probe_host: start ip=$ip"
  ui_status "[${ip}] Probing via SSH…"

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
    SSH_CMD=(sshpass -p "${SSH_PASSWORD:-}" ssh
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
  } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$out_priv" 2>&1 || true

  tr -d '\r' < "$out_priv" | tee -a "$log" > "$outn"

  local at15=0
  grep -Eq 'Current privilege level is[[:space:]]*15' "$outn" && at15=1

  : > "$outn"
  if (( at15 == 1 )); then
    {
      printf '\r\n\r\n'
      printf 'terminal length 0\r\n'
      printf 'terminal width 511\r\n'
      printf 'show clock\r\n'
      printf 'show version\r\n'
      printf 'show running-config | include ^hostname\r\n'
      printf 'show inventory\r\n'
      printf 'exit\r\n'
    } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1 || true
  else
    if [[ -n "${ENABLE_PASSWORD:-}" ]]; then
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
      } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1 || true
    else
      {
        printf '\r\n\r\n'
        printf 'terminal length 0\r\n'
        printf 'terminal width 511\r\n'
        printf 'show clock\r\n'
        printf 'show version\r\n'
        printf 'show running-config | include ^hostname\r\n'
        printf 'show inventory\r\n'
        printf 'exit\r\n'
      } | _run_ssh_script "${SSH_TIMEOUT:-30}" >"$facts" 2>&1 || true
    fi
  fi

  tr -d '\r' < "$facts" | tee -a "$log" > "$outn"

  local login_ok=0
  if grep -Eq 'Cisco IOS|IOS XE| uptime is |^hostname[[:space:]]+|^NAME:|^PID:' "$outn"; then
    login_ok=1
  fi

  local login_reason=""
  if (( login_ok == 0 )); then
    local combo
    combo="$(tr -d '\r' < "$out_priv"; echo; tr -d '\r' < "$facts")"
    login_reason="$(_reason_from_ssh_output "$combo")"
  fi

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
  pid="$(clean_field "${pid:-}")"
  sn="$(clean_field "${sn:-}")"

  rm -f "$out_priv" "$facts" "$outn"

  if (( login_ok )); then
    jq -n \
      --arg ip "$ip" \
      --arg host "${hostname:-}" \
      --arg ver "${version:-}" \
      --arg pid "${pid:-}" \
      --arg sn "${sn:-}" \
      --arg lr "" \
      '{
         ip: $ip,
         ssh: true,
         login: true,
         login_reason: $lr,
         hostname: $host,
         version: $ver,
         pid: $pid,
         serial: $sn
       }'
  else
    jq -n \
      --arg ip "$ip" \
      --arg lr "${login_reason:-LOGIN FAILED}" \
      '{ip:$ip, ssh:true, login:false, login_reason:$lr, hostname:"", version:"", pid:"", serial:""}'
  fi
}

HAS_WAIT_N=0
if help wait >/dev/null 2>&1 && help wait 2>&1 | grep -q -- '-n'; then HAS_WAIT_N=1; fi

run_probe_pool() {
  local hosts=("$@") max=${MAX_SSH_FANOUT} total=${#hosts[@]}
  (( total == 0 )) && return 0
  (( max < 1 )) && max=1
  (( max > total )) && max=$total

  local running=0 done=0 pids=()
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
      ui_gauge "$((30 + 50 * done / total))" "Probing devices… ($done / $total)"
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
    ui_gauge "$((30 + 50 * done / total))" "Probing devices… ($done / $total)"
    ((running--))
  done
}

make_upgrade_plan() {
  local json="$JSON_OUT"
  local disc_count
  disc_count="$(jq 'length' "$json" 2>/dev/null || echo 0)"
  ui_gauge 90 "Building upgrade plan for $disc_count device(s)…"

  jq -r '.[] |
         [
           .ip,
           (.pid//""),
           (.version//""),
           (.hostname//""),
           (.ssh//false),
           (.login//false),
           (.ssh_reason//""),
           (.login_reason//"")
         ] | @tsv' "$json" |
  while IFS=$'\t' read -r ip pid cur_ver host ssh login sshr lrr; do
    IFS='|' read -r tgt_file tgt_path tgt_ver tgt_size <<<"$(choose_image "$pid")"

    local action need
    if [[ "$ssh" != "true" || "$login" != "true" ]]; then
      action="BLOCKED"
      need="false"
    else
      if [[ -n "$tgt_ver" && -n "$cur_ver" ]]; then
        action="$(plan_action_label "$cur_ver" "$tgt_ver")"
      else
        action="UNKNOWN"
      fi
      case "$action" in
        UPGRADE|DOWNGRADE) need="true" ;;
        SAME|UNKNOWN|"")   need="false" ;;
      esac
    fi

    local bl="false" blr=""
    if [[ "$ssh" != "true" ]]; then
      bl="true"; blr="${sshr:-SSH CLOSED}"
    elif [[ "$login" != "true" ]]; then
      bl="true"; blr="${lrr:-BAD LOGIN}"
    fi

    jq -n \
      --arg ip "$ip" \
      --arg hostname "${host:-}" \
      --arg pid "${pid:-}" \
      --arg current_version "${cur_ver:-}" \
      --arg target_version "${tgt_ver:-}" \
      --arg target_file "${tgt_file:-}" \
      --arg target_path "${tgt_path:-}" \
      --arg target_size "${tgt_size:-}" \
      --arg action "$action" \
      --arg needs "$need" \
      --arg ssh "$ssh" \
      --arg login "$login" \
      --arg sshr "${sshr:-}" \
      --arg lrr "${lrr:-}" \
      --arg bl "$bl" \
      --arg blr "$blr" \
      '{
         ip: $ip,
         hostname: $hostname,
         pid: $pid,
         current_version: $current_version,
         target_version: $target_version,
         target_file: $target_file,
         target_path: $target_path,
         target_size_bytes: ($target_size|tonumber?),
         plan_action: $action,
         needs_upgrade: ($needs=="true"),
         ssh: ($ssh=="true"),
         login: ($login=="true"),
         ssh_reason: $sshr,
         login_reason: $lrr,
         blacklisted: ($bl=="true"),
         blacklist_reason: $blr
       }'
  done | jq -s '.' > "$UP_JSON_OUT"

  {
    echo "ip,hostname,pid,current_version,target_version,plan_action,target_file,target_path,target_size_bytes,needs_upgrade,blacklisted,blacklist_reason,ssh,login,ssh_reason,login_reason"
    jq -r '.[] | [
        .ip,
        (.hostname//""),
        (.pid//""),
        (.current_version//""),
        (.target_version//""),
        (.plan_action//""),
        (.target_file//""),
        (.target_path//""),
        (.target_size_bytes//""),
        (.needs_upgrade//false),
        (.blacklisted//false),
        (.blacklist_reason//""),
        (.ssh//false),
        (.login//false),
        (.ssh_reason//""),
        (.login_reason//"")
      ] | @csv' "$UP_JSON_OUT"
  } > "$UP_CSV_OUT"
}

do_selection_dialog() {
  declare -A BLKMAP=()
  local -a items_ok=()
  local -a items_blocked=()

  while IFS=$'\t' read -r ip host pid cur tgt action need blacklisted bl_reason; do
    host="${host:--}"
    pid="${pid:--}"
    cur="${cur:-?}"
    tgt="${tgt:-?}"
    action="${action:-UNKNOWN}"
    need="${need:-false}"
    blacklisted="${blacklisted:-false}"
    bl_reason="${bl_reason:-}"

    local text="${host} (${ip})  ${pid}  ${cur} -> ${tgt} (${action})"
    local def="off"

    if [[ "$blacklisted" == "true" ]]; then
      text="$text  [BLOCKED: ${bl_reason}]"
      def="off"
      BLKMAP["$ip"]="$bl_reason"
      items_blocked+=("$ip" "$text" "$def")
    else
      [[ "$need" == "true" ]] && def="on"
      items_ok+=("$ip" "$text" "$def")
    fi
  done < <(jq -r '.[] |
           [
             .ip,
             (.hostname//"-"),
             (.pid//"-"),
             (.current_version//"?"),
             (.target_version//"?"),
             (.plan_action//"UNKNOWN"),
             (.needs_upgrade//false),
             (.blacklisted//false),
             (.blacklist_reason//"")
           ] | @tsv' "$UP_JSON_OUT")

  local -a items=("${items_ok[@]}" "${items_blocked[@]}")
  (( ${#items[@]} > 0 )) || return 1

  ui_stop
  local tmp_sel; tmp_sel="$(mktemp)"
  dialog --no-shadow --title "Select switches to upgrade" \
         --backtitle "Upgrade Selection" \
         --checklist "Use <SPACE> to toggle. BLOCKED entries are shown but will be ignored.\n\nNon-blocked devices are listed first; BLOCKED devices are grouped at the bottom." \
         22 140 15 \
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

  local -a FILTERED_SEL=()
  local ip
  for ip in "${SEL_ARR[@]}"; do
    [[ -z "$ip" ]] && continue
    [[ -n "${BLKMAP[$ip]:-}" ]] && continue
    FILTERED_SEL+=("$ip")
  done

  if (( ${#FILTERED_SEL[@]} == 0 )); then
    dialog --no-shadow --infobox \
"All selected devices are BLOCKED.
Fix connectivity/credentials and re-run discovery." 8 70
    sleep 3
    return 3
  fi

  local ips_json
  ips_json="$(printf '%s\n' "${FILTERED_SEL[@]}" | jq -R -s 'split("\n")|map(select(length>0))')"
  jq --argjson ips "$ips_json" '[ .[] | select( (.ip|tostring) as $x | $ips | index($x) ) ]' "$UP_JSON_OUT" > "$SEL_JSON_OUT"

  {
    echo "ip,hostname,pid,current_version,target_version,plan_action,target_file,target_path,target_size_bytes,needs_upgrade"
    jq -r '.[] | [
        .ip,
        (.hostname//""),
        (.pid//""),
        (.current_version//""),
        (.target_version//""),
        (.plan_action//""),
        (.target_file//""),
        (.target_path//""),
        (.target_size_bytes//""),
        (.needs_upgrade//false)
      ] | @csv' "$SEL_JSON_OUT"
  } > "$SEL_CSV_OUT"

  {
    echo "# Generated $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf "export UPGRADE_BASE_ENV=%q\n" "$ENV_FILE"
    printf "export UPGRADE_SELECTED_IPS=%q\n" "${FILTERED_SEL[*]}"
    printf "export UPGRADE_SELECTED_JSON=%q\n" "$SEL_JSON_OUT"
    printf "export UPGRADE_SELECTED_CSV=%q\n" "$SEL_CSV_OUT"
  } > "$SEL_ENV_OUT"

  dialog --no-shadow --infobox "Selection saved. BLOCKED entries ignored." 6 70
  sleep 2
  return 0
}

main() {
  log_msg "=== scan run start ==="

  ui_start; ui_gauge 1 "Initializing…"

  resolve_targets || {
    ui_status "No targets; writing empty outputs."
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,ssh_reason,login_reason,hostname,version,pid,serial\n" > "$CSV_OUT"
    return 0
  }

  mapfile -t base_list < <(printf '%s\n' "${TARGETS[@]}" | awk 'NF' | sort -u)

  live=()
  if [[ "${TARGET_MODE:-}" == "list" ]]; then
    ui_status "Manual/list mode: using ALL provided IPs (no ICMP required)."
    live=("${base_list[@]}")
  else
    mapfile -t live < <(discover_targets)
  fi

  if (( ${#live[@]} == 0 )); then
    ui_status "No devices found."
    jq -n '[]' > "$JSON_OUT"
    printf "ip,ssh,login,ssh_reason,login_reason,hostname,version,pid,serial\n" > "$CSV_OUT"
    ui_gauge 100 "Done (no devices)."
    return 0
  fi

  ui_status "Devices in scope: ${#live[@]}"; ui_gauge 15 "Targets gathered."

  # SSH open detection (deterministic; no subshell array issues)
  SSH_GREP="$(mktemp)"
  filter_ssh_open_grepable "${live[@]}" >"$SSH_GREP" 2>/dev/null || true

  declare -A SSHOPEN=()
  declare -A SSHREASON=()

  # Default: closed
  for ip in "${live[@]}"; do
    SSHOPEN["$ip"]=0
    SSHREASON["$ip"]="SSH CLOSED"
  done

  # Mark open (use mapfile, no pipe subshell)
  mapfile -t OPEN_IPS < <(awk '/Ports: 22\/open/{print $2}' "$SSH_GREP" | awk 'NF' | sort -u)
  for ip in "${OPEN_IPS[@]}"; do
    SSHOPEN["$ip"]=1
    SSHREASON["$ip"]=""
  done

  rm -f "$SSH_GREP"

  ssh_hosts=()
  for ip in "${live[@]}"; do
    if [[ "${SSHOPEN[$ip]:-0}" == "1" ]]; then
      ssh_hosts+=("$ip")
    fi
  done

  ui_status "SSH open: ${#ssh_hosts[@]} / ${#live[@]}"; ui_gauge 25 "SSH port scan complete."
  log_msg "main: ssh_open_count=${#ssh_hosts[@]}"

  TMPJSON="$(mktemp)"; : > "$TMPJSON"
  if (( ${#ssh_hosts[@]} > 0 )); then
    ui_status "Probing SSH-open devices via SSH as ${SSH_USERNAME}…"
    run_probe_pool "${ssh_hosts[@]}"
  fi

  declare -A SEENPROBE=()
  PROBED_JSON="$(mktemp)"
  if [[ -s "$TMPJSON" ]]; then
    jq -s '.' "$TMPJSON" > "$PROBED_JSON"
    while read -r ip; do
      [[ -z "$ip" ]] && continue
      SEENPROBE["$ip"]=1
    done < <(jq -r '.[].ip' "$PROBED_JSON" 2>/dev/null || true)
  else
    echo "[]" > "$PROBED_JSON"
  fi

  ALL_JSON_LINES="$(mktemp)"
  : > "$ALL_JSON_LINES"

  for ip in "${live[@]}"; do
    if [[ "${SSHOPEN[$ip]:-0}" != "1" ]]; then
      jq -n \
        --arg ip "$ip" \
        --arg sr "${SSHREASON[$ip]:-SSH CLOSED}" \
        '{ip:$ip, ssh:false, login:false, ssh_reason:$sr, login_reason:"", hostname:"", version:"", pid:"", serial:""}' >> "$ALL_JSON_LINES"
    else
      if [[ -n "${SEENPROBE[$ip]:-}" ]]; then
        jq -c --arg ip "$ip" '
          .[] | select(.ip==$ip) |
          . + {ssh_reason:""}
        ' "$PROBED_JSON" >> "$ALL_JSON_LINES"
      else
        jq -n \
          --arg ip "$ip" \
          '{ip:$ip, ssh:true, login:false, ssh_reason:"", login_reason:"LOGIN FAILED", hostname:"", version:"", pid:"", serial:""}' >> "$ALL_JSON_LINES"
      fi
    fi
  done

  jq -s '.' "$ALL_JSON_LINES" > "$JSON_OUT"
  rm -f "$TMPJSON" "$PROBED_JSON" "$ALL_JSON_LINES"

  {
    echo "ip,ssh,login,ssh_reason,login_reason,hostname,version,pid,serial"
    jq -r '.[] | [
      .ip,
      (.ssh//false),
      (.login//false),
      (.ssh_reason//""),
      (.login_reason//""),
      (.hostname//""),
      (.version//""),
      (.pid//""),
      (.serial//"")
    ] | @csv' "$JSON_OUT"
  } > "$CSV_OUT"

  ui_status "Discovery results: $CSV_OUT"
  ui_gauge 85 "Discovery complete."

  make_upgrade_plan

  if (( DIALOG_AVAILABLE )); then
    do_selection_dialog || true
  else
    echo "Selection UI skipped (dialog not available)."
  fi

  log_msg "=== scan run complete ==="
}

main "$@"