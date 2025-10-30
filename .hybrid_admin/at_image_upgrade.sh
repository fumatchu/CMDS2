#!/usr/bin/env bash
# at_image_upgrade.sh — headless, scheduler-friendly, parallel IOS-XE upgrader
# Pipeline: PRECHECK → TFTP backup → install remove inactive → HTTP copy → INSTALL
# Concurrency: MAX_CONCURRENCY (default 5)
# Logging: runs/at/<run-id> with per-IP devlogs + CSV summaries
# Notes:
#   - Headless: NO dialog usage
#   - Supports both '>' (user exec) and '#' (privileged) prompts via auto-enable
#   - Compatible with meraki_discovery.env + selected_upgrade.env used by Scheduler.sh

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need awk; need jq; need ssh; need timeout
command -v sshpass >/dev/null 2>&1 || true

BASE_ENV="$SCRIPT_DIR/meraki_discovery.env"
SEL_ENV="${1:-$SCRIPT_DIR/selected_upgrade.env}"

[[ -f "$BASE_ENV" ]] || { echo "ERROR: meraki_discovery.env not found. Run the Setup Wizard first." >&2; exit 1; }
[[ -f "$SEL_ENV"  ]]  || { echo "ERROR: selected_upgrade.env not found. Run Discovery & Selection first." >&2; exit 1; }

# Avoid history expansion on !
set +H
# shellcheck disable=SC1090
source "$BASE_ENV"
# shellcheck disable=SC1090
source "$SEL_ENV"

# De-escape a few chars we quoted in env files
__deq(){ local s="$1"; s="${s//\\!/!}"; s="${s//\\;/;}"; s="${s//\\ / }"; s="${s//\\\\/\\}"; printf '%s' "$s"; }

SSH_USERNAME="$(__deq "${SSH_USERNAME:-}")"
SSH_PASSWORD="$(__deq "${SSH_PASSWORD:-}")"
ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD:-}")"
UPGRADE_SELECTED_IPS="$(__deq "${UPGRADE_SELECTED_IPS:-}")"
UPGRADE_SELECTED_JSON="${UPGRADE_SELECTED_JSON:-}"
HTTP_FORCE_COPY="${HTTP_FORCE_COPY:-0}"

[[ -n "$SSH_USERNAME" ]] || { echo "ERROR: SSH_USERNAME is empty in meraki_discovery.env" >&2; exit 1; }
if [[ -z "${SSH_KEY_PATH:-}" && -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
  echo "ERROR: sshpass is not installed but a password is set. Install sshpass or set SSH_KEY_PATH." >&2
  exit 1
fi

# Targets
TARGETS=()
if [[ -n "$UPGRADE_SELECTED_IPS" ]]; then
  # split on whitespace/newlines
  read -r -a TARGETS <<< "$UPGRADE_SELECTED_IPS"
elif [[ -n "$UPGRADE_SELECTED_JSON" && -f "$UPGRADE_SELECTED_JSON" ]]; then
  mapfile -t TARGETS < <(jq -r '.[].ip' "$UPGRADE_SELECTED_JSON" | awk 'NF')
fi
TOTAL=${#TARGETS[@]}
(( TOTAL > 0 )) || { echo "ERROR: No targets to run." >&2; exit 1; }

# Basic network helpers
detect_server_ip(){
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i!="127.0.0.1"){print $i; exit}}')"
  echo "$ip"
}
SERVER_IP="$(detect_server_ip)"
[[ -n "$SERVER_IP" ]] || { echo "ERROR: Could not determine local server IP." >&2; exit 1; }
TFTP_BASE="tftp://${SERVER_IP}/hybrid"
FIRMWARE_HTTP_BASE="${FIRMWARE_HTTP_BASE:-http://${SERVER_IP}/images}"

# ----- Run layout (scheduled logs go under runs/at/) -----
RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
RUN_ROOT="$SCRIPT_DIR/runs/at"; mkdir -p "$RUN_ROOT"
RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs" "$RUN_DIR/cmds"
RUN_ERR="$RUN_DIR/run.err"; : > "$RUN_ERR"
STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"

# Capture full console output (and still print to screen)
exec > >(tee -a "$RUN_DIR/console.log") 2> >(tee -a "$RUN_DIR/console.err" >&2)

SUMMARY_CSV="$RUN_DIR/summary.csv"; echo "ip,hostname,mode,confreg,precheck,result" > "$SUMMARY_CSV"
ACTIONS_CSV="$RUN_DIR/actions.csv"; echo "ip,hostname,action,result,detail" > "$ACTIONS_CSV"
printf '%s\n' "${TARGETS[@]}" > "$RUN_DIR/targets.list"

# ----- Safe CSV append with file locks -----
add_action(){ { flock -x 200; echo "$1" >> "$ACTIONS_CSV"; } 200>"$ACTIONS_CSV.lock"; }
add_summary(){ { flock -x 201; echo "$1" >> "$SUMMARY_CSV"; } 201>"$SUMMARY_CSV.lock"; }

# ----- Headless UI helpers (log + simple gauge text) -----
log(){ printf '%(%H:%M:%S)T %s\n' -1 "$1" | tee -a "$STATUS_FILE"; }
gauge(){ local p="${1:-0}" m="${2:-Working…}"; echo "[progress] $p% - $m" | tee -a "$STATUS_FILE"; }

MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
SPLAY_MS="${SPLAY_MS:-150}"          # light stagger when spawning jobs
HTTP_PROGRESS_POLL_SEC="${HTTP_PROGRESS_POLL_SEC:-10}"

# ===== SSH builder (fixed ordering; options BEFORE host) =====
build_ssh_arr(){
  local ip="$1"
  local dest="${SSH_USERNAME}@${ip}"
  local base_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
                   -o ConnectTimeout=60 -o ServerAliveInterval=10 -o ServerAliveCountMax=6
                   -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa
                   -o KexAlgorithms=+diffie-hellman-group14-sha1 -tt)
  if [[ -n "${SSH_KEY_PATH:-}" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD=(ssh "${base_opts[@]}" -i "$SSH_KEY_PATH" -o BatchMode=yes "$dest")
  else
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" ssh "${base_opts[@]}"
             -o PreferredAuthentications=password,keyboard-interactive
             -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no
             -o NumberOfPasswordPrompts=1 "$dest")
  fi
}

# ---- Check privilege level (15 means we're already enabled) ----
is_priv15_for_ip() {
  local ip="$1" raw out ok=1
  build_ssh_arr "$ip"
  raw="$(mktemp)"; out="$(mktemp)"
  {
    printf '\r\n'
    printf 'terminal length 0\r\n'
    printf 'terminal width 511\r\n'
    printf 'show privilege\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 25s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"
  grep -Eiq 'Current privilege level is[[:space:]]*15' "$out" && ok=0
  rm -f "$raw" "$out"
  return $ok
}

# ---- Elevate only when needed ----
emit_enable(){
  printf 'enable\r\n'
  sleep 0.2
  if [[ -n "${ENABLE_PASSWORD:-}" ]]; then
    printf '%s\r\n' "$ENABLE_PASSWORD"
  else
    printf '\r\n'
  fi
  printf 'show privilege\r\n'
  sleep 0.2
}

# ===== helpers =====
get_plan_field(){ local ip="$1" key="$2"; [[ -n "$UPGRADE_SELECTED_JSON" && -s "$UPGRADE_SELECTED_JSON" ]] || return 1; jq -r --arg ip "$ip" --arg k "$key" '.[] | select(.ip==$ip) | .[$k] // empty' "$UPGRADE_SELECTED_JSON"; }
resolve_image_for_ip(){
  local ip="$1" file="" size=""
  if [[ -s "${UPGRADE_SELECTED_JSON:-}" ]]; then
    file="$(get_plan_field "$ip" "target_file")"
    size="$(get_plan_field "$ip" "target_size_bytes")"
  fi
  if [[ -z "$file" ]]; then
    [[ -n "${FW_CAT9K_LITE_FILE:-}" ]] && { file="$FW_CAT9K_LITE_FILE"; size="${FW_CAT9K_LITE_SIZE_BYTES:-}"; }
    [[ -z "$file" && -n "${FW_CAT9K_FILE:-}" ]] && { file="$FW_CAT9K_FILE"; size="${FW_CAT9K_SIZE_BYTES:-}"; }
  fi
  echo "${file}|${size}"
}
fmt_bytes(){ awk -v b="${1:-0}" 'BEGIN{ if(b<1024)printf("%d B",b); else if(b<1048576)printf("%.1f KB",b/1024); else if(b<1073741824)printf("%.1f MB",b/1048576); else printf("%.2f GB",b/1073741824);}'; }
flash_bytes_from_capture(){ local outfile="$1" base="$2"; awk -v f="$base" 'BEGIN{mx=-1;seen=0} index($0,f){seen=1;for(i=1;i<=NF;i++) if($i~/^[0-9]+$/){n=$i+0;if(n>mx)mx=n}} END{if(seen&&mx>=0)print mx}' "$outfile"; }
flash_size_from(){ flash_bytes_from_capture "$@"; }
shortver_from_string(){ awk 'match($0,/[0-9]+\.[0-9]+\.[0-9]+/){print substr($0,RSTART,RLENGTH)}'; }

installed_short_version_for_ip(){
  local ip="$1" raw norm v="" need_en=0
  build_ssh_arr "$ip"; raw="$(mktemp)"; norm="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show install summary\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$norm"; cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+C[[:space:]]+/{print $NF; exit}' "$norm")"
  [[ -z "$v" ]] && v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+U[[:space:]]+/{print $NF; exit}' "$norm")"
  v="$(printf '%s\n' "$v" | shortver_from_string)"; rm -f "$raw" "$norm"; printf '%s' "$v"
}

skip_if_same_version_for_ip(){
  local ip="$1" file size base target_short inst_short host
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  [[ -z "$file" ]] && { log "[${ip}] VERSION: no target image defined — cannot compare"; return 1; }
  base="$(basename -- "$file")"; target_short="$(printf '%s\n' "$base" | shortver_from_string)"
  [[ -z "$target_short" ]] && { log "[${ip}] VERSION: unable to parse target version from '$base'"; return 1; }
  inst_short="$(installed_short_version_for_ip "$ip")"
  if [[ -n "$inst_short" && "$inst_short" == "$target_short" ]]; then
    log "[${ip}] VERSION: ${inst_short} already committed/active — SKIP copy/install"
    add_action "$ip,${host},version_check,skip,same(${inst_short})"
    return 0
  fi
  log "[${ip}] VERSION: target ${target_short}; installed ${inst_short:-unknown} — proceed"; return 1
}

# ===== PRECHECK =====
precheck_for_ip(){
  local ip="$1" raw out rc=0 need_en=0
  log "[${ip}] CONNECT…"; build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show version\r\n';         sleep 0.3
    printf 'show install summary\r\n'; sleep 0.3
    printf 'exit\r\n'
  } | timeout -k 5s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?
  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.session.log"

  local hostname mode confreg
  hostname="$(awk '/^hostname[[:space:]]+/{print $2}' "$out" | tail -n1)"
  [[ -z "$hostname" ]] && hostname="$(grep -E '^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$' "$out" | tail -n1 | sed -E 's/[>#].*$//')"
  [[ -z "$hostname" ]] && hostname="$(awk '/ uptime is /{print $1; exit}' "$out")"
  mode="$(awk -F: 'BEGIN{IGNORECASE=1}/Running[[:space:]]+mode/{gsub(/^[ \t]+/,"",$2);print toupper($2);exit}' "$out")"
  [[ -z "$mode" ]] && mode="$(awk 'BEGIN{hdr=0}
    /^[[:space:]]*Switch[[:space:]]+Ports[[:space:]]+Model[[:space:]]+SW[[:space:]]+Version[[:space:]]+SW[[:space:]]+Image[[:space:]]+Mode/{hdr=1;next}
    hdr==1 && /^[[:space:]]*([*]|[0-9])/{m=toupper($NF);print m;exit}' "$out")"
  [[ -z "$mode" ]] && mode="$(grep -Eo '(INSTALL|BUNDLE)' "$out" | head -n1 | tr '[:lower:]' '[:upper:]')"
  confreg="$(grep -i 'Configuration register is' "$out" | tail -n1 | awk '{print $NF}' | tr 'A-Z' 'a-z' | tr -d '.,;')"

  local precheck="ok"; [[ "$mode" == "INSTALL" ]] || precheck="fail:mode"
  [[ "$confreg" == "0x102" ]] || precheck="${precheck}${precheck:++}confreg"
  [[ "$precheck" == "ok" ]] && log "[${ip}] PRECHECK OK (mode=${mode:-?}, confreg=${confreg:-?})" \
                             || log "[${ip}] PRECHECK FAIL (mode=${mode:-?}, confreg=${confreg:-?}) => ${precheck}"
  echo "$hostname" > "$RUN_DIR/host.$ip"; echo "$mode" > "$RUN_DIR/mode.$ip"; echo "$confreg" > "$RUN_DIR/confreg.$ip"; echo "$precheck" > "$RUN_DIR/precheck.$ip"
  rm -f "$raw" "$out"; [[ "$precheck" == "ok" ]]
}

# ===== TFTP backup =====
backup_for_ip(){
  local ip="$1" hn ts url raw rc=0 need_en=0
  hn="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"; [[ -n "$hn" ]] || hn="sw-${ip//./-}"
  ts="$(date -u +%Y%m%d-%H%M)"; url="${TFTP_BASE}/${hn}-${ts}.cfg"
  log "[${ip}] BACKUP -> ${url}"
  build_ssh_arr "$ip"; raw="$(mktemp)"; is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'copy %s %s\r\n' "running-config" "$url"
    printf '\r\n'; sleep 0.2; printf '\r\n'
    printf 'exit\r\n'
  } | timeout -k 8s 180s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?
  tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.session.log"
  if grep -qiE 'bytes copied|Copy complete|[Ss]uccess' "$raw"; then
    log "[${ip}] BACKUP OK"; add_action "$ip,$hn,backup,ok,"; rm -f "$raw"; return 0
  fi
  log "[${ip}] BACKUP FAILED"; add_action "$ip,$hn,backup,failed,"; mv -f "$raw" "$RUN_DIR/${ip}.backup.out"; return 1
}

# ===== Clean inactive =====
clean_inactive_for_ip(){
  local ip="$1" host need_en=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  log "[${ip}] CLEAN: install remove inactive"
  build_ssh_arr "$ip"; is_priv15_for_ip "$ip" || need_en=1

  local raw norm state fifo FEED_PID="" WATCH_PID="" RESP_PID="" SSH_PID="" rc=0
  raw="$(mktemp)"; norm="$(mktemp)"; state="$(mktemp)"
  fifo="$(mktemp -u)"; mkfifo "$fifo"

  timeout -k 15s "${INSTALL_REMOVE_TIMEOUT_SEC:-1200}" \
    "${SSH_CMD[@]}" <"$fifo" >"$raw" 2>&1 & SSH_PID=$!

  (
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'install remove inactive\r\n'
    while [[ ! -s "$state" ]] && kill -0 "$SSH_PID" 2>/dev/null; do
      sleep 2
      printf '\r\n'
    done
    printf 'exit\r\n'
  ) >"$fifo" & FEED_PID=$!

  (
    tail -n +1 -f "$raw" | stdbuf -o0 tr -d '\r' | awk 'BEGIN{IGNORECASE=1}
      /Do you want to remove the above files\?[[:space:]]*\[y\/n\]/ {print "Y"; fflush();}
      /Remove[[:space:]].*\?[[:space:]]*\[y\/n\]/                   {print "Y"; fflush();}
      /Proceed[[:space:]]*with[[:space:]]*removal\?[[:space:]]*\(y\/n\)/ {print "Y"; fflush();}
    ' | while read -r _; do printf 'y\r\n' >"$fifo"; done
  ) & RESP_PID=$!

  (
    tail -n +1 -f "$raw" | stdbuf -o0 tr -d '\r' | awk 'BEGIN{IGNORECASE=1}
      /SUCCESS:[[:space:]]*install_remove/           {print "OK";   fflush(); exit}
      /Finished[[:space:]]+Post_Remove_Cleanup/      {print "OK";   fflush(); exit}
      /No extra package|Nothing to clean/            {print "OK";   fflush(); exit}
      /cannot start new install operation/           {print "BUSY"; fflush(); exit}
      /(%%?Error|Permission denied|timed out|FAILED)/{print "FAIL"; fflush(); exit}'
  ) >"$state" & WATCH_PID=$!

  wait "$SSH_PID" 2>/dev/null || rc=$?
  kill "$FEED_PID" "$WATCH_PID" "$RESP_PID" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true
  wait "$WATCH_PID" 2>/dev/null || true
  wait "$RESP_PID" 2>/dev/null || true

  tr -d '\r' < "$raw" > "$norm"; cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"; rm -f "$raw"
  local verdict=""; [[ -s "$state" ]] && verdict="$(cat "$state" 2>/dev/null)"; rm -f "$state"

  case "$verdict" in
    OK)   log "[${ip}] CLEAN: OK";   add_action "$ip,${host},clean_inactive,ok,";      rm -f "$norm"; return 0 ;;
    BUSY) log "[${ip}] CLEAN: busy (another install op) — proceeding"; add_action "$ip,${host},clean_inactive,ok,busy"; rm -f "$norm"; return 0 ;;
    *)    log "[${ip}] CLEAN: FAILED (see devlog)"; add_action "$ip,${host},clean_inactive,failed,"; mv -f "$norm" "$RUN_DIR/${ip}.clean.fail.out"; return 1 ;;
  esac
}

# ===== HTTP fetch =====
http_fetch_image_for_ip(){
  local ip="$1" host file size url base
  local pre_raw pre_norm existing_bytes="" rc=0 need_en=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  if [[ -z "$file" ]]; then log "[${ip}] HTTP: no target image defined."; add_action "$ip,${host},http_copy,skipped,no_image"; return 1; fi
  base="$(basename -- "$file")"; url="${FIRMWARE_HTTP_BASE%/}/${base}"

  build_ssh_arr "$ip"; pre_raw="$(mktemp)"; pre_norm="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'dir flash: | include %s\r\n' "$base"
    printf 'exit\r\n'
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$pre_raw" 2>&1 || true
  tr -d '\r' < "$pre_raw" > "$pre_norm"
  existing_bytes="$(flash_size_from "$pre_norm" "$base")"; rm -f "$pre_raw" "$pre_norm"
  if [[ -n "$size" && -n "$existing_bytes" && "$existing_bytes" == "$size" && "${HTTP_FORCE_COPY:-0}" != "1" ]]; then
    log "[${ip}] HTTP: file exists — SKIP (bytes=${existing_bytes})"; add_action "$ip,${host},http_copy,ok,already_present(${existing_bytes})"; return 0
  fi

  log "[${ip}] HTTP: copying ${url} -> flash:${base}"
  build_ssh_arr "$ip"; local COPY_SSH=( "${SSH_CMD[@]}" )
  local copy_raw copy_norm COPY_PID HB_PID; copy_raw="$(mktemp)"; copy_norm="$(mktemp)"
  (
    {
      printf '\r\nterminal length 0\r\nterminal width 511\r\n'
      (( need_en )) && emit_enable
      if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
        printf 'configure terminal\r\nip http client source-interface %s\r\nend\r\n' "$HTTP_CLIENT_SOURCE_IFACE"
      fi
      printf 'copy %s flash:%s\r\n' "$url" "$base"
      printf '\r\n'; sleep 0.5; printf '\r\n'
    } | timeout -k 30s 7200s "${COPY_SSH[@]}"
  ) >"$copy_raw" 2>&1 & COPY_PID=$!

  build_ssh_arr "$ip"; local POLL_SSH=( "${SSH_CMD[@]}" )
  (
    local last="" cur="" total="${size:-}" pct poll="$HTTP_PROGRESS_POLL_SEC"
    while kill -0 "$COPY_PID" 2>/dev/null; do
      local p_raw p_norm; p_raw="$(mktemp)"; p_norm="$(mktemp)"
      {
        printf '\r\nterminal length 0\r\nterminal width 511\r\n'
        (( need_en )) && emit_enable
        printf 'dir flash: | include %s\r\nexit\r\n' "$base"
      } | timeout -k 5s 30s "${POLL_SSH[@]}" >"$p_raw" 2>&1 || true
      tr -d '\r' < "$p_raw" > "$p_norm"; cur="$(flash_size_from "$p_norm" "$base")"; rm -f "$p_raw" "$p_norm"
      if [[ -n "$cur" && "$cur" != "$last" ]]; then
        if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then pct=$((100*cur/total)); ((pct>99 && cur<total))&&pct=99; log "[${ip}] HTTP: progress $(fmt_bytes "$cur") / $(fmt_bytes "$total") (${pct}%)"
        else log "[${ip}] HTTP: progress $(fmt_bytes "$cur")"; fi
        last="$cur"
      else
        log "[${ip}] HTTP: copying… (checking again in ${poll}s)"
      fi
      sleep "$poll"
    done
  ) & HB_PID=$!

  wait "$COPY_PID" || rc=$?; kill "$HB_PID" 2>/dev/null || true; wait "$HB_PID" 2>/dev/null || true
  tr -d '\r' < "$copy_raw" > "$copy_norm"; cat "$copy_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  # Final verify
  local post_raw post_norm post_bytes=""; build_ssh_arr "$ip"; need_en=0; post_raw="$(mktemp)"; post_norm="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'dir flash: | include %s\r\nexit\r\n' "$base"
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$post_raw" 2>&1 || true
  tr -d '\r' < "$post_raw" > "$post_norm"; post_bytes="$(flash_size_from "$post_norm" "$base")"; rm -f "$post_raw" "$post_norm"

  if grep -qiE '(bytes copied|copied in [0-9.]+ sec|Copy complete|copied successfully|\[OK -[[:space:]]*[0-9]+[[:space:]]*bytes\])' "$copy_norm" || [[ -n "$post_bytes" ]]; then
    [[ -n "$post_bytes" ]] && { log "[${ip}] HTTP: OK (bytes=${post_bytes})"; add_action "$ip,${host},http_copy,ok,bytes=${post_bytes}"; } \
                            || { log "[${ip}] HTTP: OK"; add_action "$ip,${host},http_copy,ok,"; }
    rm -f "$copy_raw" "$copy_norm"; return 0
  fi
  log "[${ip}] HTTP: FAILED"; add_action "$ip,${host},http_copy,failed,"; mv -f "$copy_norm" "$RUN_DIR/${ip}.http_copy.out"; rm -f "$copy_raw"; return 1
}

# ===== write memory =====
write_memory_for_ip(){
  local ip="$1" raw norm need_en=0
  build_ssh_arr "$ip"; is_priv15_for_ip "$ip" || need_en=1
  log "[${ip}] WR: write memory…"; raw="$(mktemp)"; norm="$(mktemp)"
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'write memory\r\n'
    printf 'exit\r\n'
  } | timeout -k 8s 120s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$norm"; cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  if grep -qiE '(\[OK\]|Copy complete|bytes copied|copied successfully)' "$norm"; then log "[${ip}] WR: OK"; rm -f "$raw" "$norm"; return 0; fi
  log "[${ip}] WR: ambiguous — proceeding"; mv -f "$norm" "$RUN_DIR/${ip}.write_memory.out"; rm -f "$raw"; return 1
}

# ===== INSTALL =====
install_activate_image_for_ip(){
  local ip="$1" host file size base need_en=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  if [[ -z "$file" ]]; then log "[${ip}] INSTALL: no image defined — SKIP"; add_action "$ip,${host},install,skipped,no_image"; return 2; fi
  base="$(basename -- "$file")"

  build_ssh_arr "$ip"; local chk_raw chk_norm have=""; chk_raw="$(mktemp)"; chk_norm="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'dir flash: | include %s\r\nexit\r\n' "$base"
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$chk_raw" 2>&1 || true
  tr -d '\r' < "$chk_raw" > "$chk_norm"; have="$(flash_size_from "$chk_norm" "$base")"; rm -f "$chk_raw" "$chk_norm"
  if [[ -z "$have" ]]; then log "[${ip}] INSTALL: image not found on flash — SKIP"; add_action "$ip,${host},install,skipped,missing_image"; return 2; fi
  if [[ -n "$size" && "$size" != "$have" ]]; then log "[${ip}] INSTALL: image size mismatch (have=${have}, want=${size}) — SKIP"; add_action "$ip,${host},install,skipped,size_mismatch"; return 2; fi

  write_memory_for_ip "$ip" || true
  is_priv15_for_ip "$ip" || need_en=1

  local cmd="install add file flash:${base} activate commit prompt-level none"
  log "[${ip}] INSTALL: add+activate+commit (flash:${base})"; printf '%s\n' "$cmd" > "$RUN_DIR/cmds/${ip}.install.cmd"

  local inst_raw inst_norm state_file fifo FEED_PID="" STREAM_PID="" rc=0
  inst_raw="$(mktemp)"; inst_norm="$(mktemp)"; state_file="$(mktemp)"
  fifo="$(mktemp -u)"; mkfifo "$fifo"; build_ssh_arr "$ip"; local INST_SSH=( "${SSH_CMD[@]}" )

  timeout -k 10s "${INSTALL_STREAM_MAX_SECS:-14400}" "${INST_SSH[@]}" <"$fifo" >"$inst_raw" 2>&1 & local INST_PID=$!

  (
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf '%s\r\n' "$cmd"
    while [[ ! -s "$state_file" ]] && kill -0 "$INST_PID" 2>/dev/null; do
      sleep "${INSTALL_KEEPALIVE_GAP_SEC:-5}"
      printf '\r\n'
    done
  ) >"$fifo" & local FEED_PID2=$!

  (
    tail -n +1 -f "$inst_raw" 2>/dev/null | stdbuf -o0 tr -d '\r' | {
      seen_act=0; seen_commit=0
      while IFS= read -r line; do lc="${line,,}"
        case "$lc" in
          *"install_add_activate_commit: start"*) log "[${ip}] INSTALL: workflow START" ;;
          *"install_add: start"*)                log "[${ip}] INSTALL: ADD start" ;;
          *"finished initial file syncing"*)     log "[${ip}] INSTALL: file sync done" ;;
          *"image added. version:"*)             log "[${ip}] INSTALL: ADD finished" ;;
          *"install_activate: start"*)           log "[${ip}] INSTALL: ACTIVATE start" ;;
          *"finished activate"*)                 (( !seen_act )) && { log "[${ip}] INSTALL: ACTIVATE finished"; seen_act=1; } ;;
          *"finished commit"*)                   (( !seen_commit )) && { log "[${ip}] INSTALL: COMMIT finished (verifying…)"; seen_commit=1; } ;;
          *"success: install_add_activate_commit"*) log "[${ip}] INSTALL: SUCCESS"; echo success > "$state_file"; break ;;
          *"failed:"*)                           log "[${ip}] INSTALL: FAILED — ${line#*FAILED: }"; echo failed > "$state_file"; break ;;
          *"cannot start new install operation, some operation is already running"*) log "[${ip}] INSTALL: BUSY"; echo busy > "$state_file"; break ;;
        esac
      done
    }
  ) & STREAM_PID=$!

  wait "$INST_PID" 2>/dev/null || rc=$?
  kill "$FEED_PID2" 2>/dev/null || true
  kill "$STREAM_PID" 2>/dev/null || true
  rm -f "$fifo" 2>/dev/null || true
  wait "$FEED_PID2" 2>/dev/null || true
  wait "$STREAM_PID" 2>/dev/null || true

  tr -d '\r' < "$inst_raw" > "$inst_norm"; cat "$inst_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"; rm -f "$inst_raw"

  local state=""; [[ -s "$state_file" ]] && state="$(cat "$state_file" 2>/dev/null || true)"; rm -f "$state_file"
  if [[ "$state" == "success" ]]; then
    log "[${ip}] INSTALL: complete"; add_action "$ip,${host},install,ok,success"; rm -f "$inst_norm"; return 0
  fi
  if [[ "$state" == "failed" ]];  then
    log "[${ip}] INSTALL: failed (see devlogs)"; add_action "$ip,${host},install,failed,"; mv -f "$inst_norm" "$RUN_DIR/${ip}.install.fail.out"; return 1
  fi
  if [[ "$state" == "busy" ]];    then
    log "[${ip}] INSTALL: busy/in-progress — recommend manual reboot, then re-run."
    add_action "$ip,${host},install,skipped,busy"; mv -f "$inst_norm" "$RUN_DIR/${ip}.install.busy.out"; return 3
  fi

  # fallback verify
  local sum_raw sum_norm; build_ssh_arr "$ip"; need_en=0; sum_raw="$(mktemp)"; sum_norm="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show install summary\r\nexit\r\n'
  } | timeout -k 5s 120s "${SSH_CMD[@]}" >"$sum_raw" 2>&1 || true
  tr -d '\r' < "$sum_raw" > "$sum_norm"; cat "$sum_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"; rm -f "$sum_raw"
  if grep -qiE 'Commit:[[:space:]]+Passed|Status:[[:space:]]+Committed|SUCCESS:[[:space:]]*install_add_activate_commit' "$sum_norm"; then
    log "[${ip}] INSTALL: verified SUCCESS via summary"; add_action "$ip,${host},install,ok,verified"; rm -f "$sum_norm" "$inst_norm"; return 0
  fi
  if grep -qiE 'Operation in progress|in[- ]progress' "$sum_norm"; then
    log "[${ip}] INSTALL: still in progress (device busy)"; add_action "$ip,${host},install,ok,in_progress"; rm -f "$sum_norm" "$inst_norm"; return 0
  fi
  log "[${ip}] INSTALL: uncertain/failed (no success markers)"; add_action "$ip,${host},install,failed,uncertain"
  mv -f "$inst_norm" "$RUN_DIR/${ip}.install.uncertain.out"; rm -f "$sum_norm"; return 1
}

# ===== per-IP pipeline (headless, parallel) =====
process_ip(){
  local ip="$1"
  # Pre-create a devlog so you always see something for each IP
  : > "$RUN_DIR/devlogs/${ip}.session.log"

  local result="skipped"
  if precheck_for_ip "$ip"; then
    if backup_for_ip "$ip"; then
      clean_inactive_for_ip "$ip" || true
      if skip_if_same_version_for_ip "$ip"; then
        result="skipped(same_version)"
      else
        if http_fetch_image_for_ip "$ip"; then
          local rc_install=0; install_activate_image_for_ip "$ip" || rc_install=$?
          case "$rc_install" in
            0) result="ok" ;;
            2) result="skipped(install)" ;;
            3) result="busy(reboot_suggested)" ;;
            *) result="fail(install)" ;;
          esac
        else
          result="fail(http_copy)"
        fi
      fi
    else
      result="fail(backup)"
    fi
  else
    result="skipped"
  fi

  local hn mode confreg precheck
  hn="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  mode="$(cat "$RUN_DIR/mode.$ip" 2>/dev/null || true)"
  confreg="$(cat "$RUN_DIR/confreg.$ip" 2>/dev/null || true)"
  precheck="$(cat "$RUN_DIR/precheck.$ip" 2>/dev/null || true)"
  add_summary "$ip,${hn},${mode},${confreg},${precheck},${result}"
}

# ===== main (parallel orchestration) =====
log "Run ID: $RUN_ID (scheduled/headless)"; log "Run dir: $RUN_DIR"
log "User: ${SSH_USERNAME}"; log "Server TFTP: ${SERVER_IP}/hybrid"
log "Targets: ${TARGETS[*]}"
gauge 1 "Starting… (up to ${MAX_CONCURRENCY} in parallel)"

ACTIVE=0
DONE=0
rand_ms(){ awk -v m="${SPLAY_MS}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}' ;}

for ip in "${TARGETS[@]}"; do
  ( process_ip "$ip" ) &
  ((ACTIVE++))
  sleep "$(rand_ms)"
  if (( ACTIVE >= MAX_CONCURRENCY )); then
    wait -n || true
    ((DONE++))
    pct=$(( 100 * DONE / TOTAL ))
    gauge "$pct" "Completed $DONE / $TOTAL"
    ((ACTIVE--))
  fi
done

while (( DONE < TOTAL )); do
  wait -n || true
  ((DONE++))
  pct=$(( 100 * DONE / TOTAL ))
  gauge "$pct" "Completed $DONE / $TOTAL"
done

log "Summary CSV: $SUMMARY_CSV"
log "Actions CSV: $ACTIONS_CSV"
log "All device transcripts: $RUN_DIR/devlogs"
echo
echo "=== at_image_upgrade.sh completed ==="
echo "Run directory: $RUN_DIR"
