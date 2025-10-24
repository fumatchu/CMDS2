#!/usr/bin/env bash
# upgrade_iosxe_safe.sh — serial, dialog-safe.
# Steps: PRECHECK → TFTP backup → install remove inactive → HTTP image fetch to flash.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need awk; need jq; need ssh; need timeout
command -v sshpass >/dev/null 2>&1 || true

BASE_ENV="$SCRIPT_DIR/meraki_discovery.env"
SEL_ENV="${1:-$SCRIPT_DIR/selected_upgrade.env}"

err_box(){
  if command -v dialog >/dev/null 2>&1; then
    dialog --no-shadow --title "Error" --msgbox "$1" 8 80
    clear
  else
    echo "ERROR: $1" >&2
  fi
}

[[ -f "$BASE_ENV" ]] || { err_box "meraki_discovery.env not found. Run the Setup Wizard first."; exit 1; }
[[ -f "$SEL_ENV"  ]]  || { err_box "selected_upgrade.env not found. Run Discovery & Selection first."; exit 1; }

set +H
# shellcheck disable=SC1090
source "$BASE_ENV"
# shellcheck disable=SC1090
source "$SEL_ENV"

SSH_USERNAME="${SSH_USERNAME:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
UPGRADE_SELECTED_IPS="${UPGRADE_SELECTED_IPS:-}"
UPGRADE_SELECTED_JSON="${UPGRADE_SELECTED_JSON:-}"
HTTP_FORCE_COPY="${HTTP_FORCE_COPY:-0}"   # 1 = always copy even if file exists

[[ -n "$SSH_USERNAME" ]] || { err_box "SSH_USERNAME is empty in meraki_discovery.env"; exit 1; }
if [[ -z "${SSH_KEY_PATH:-}" && -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
  err_box "sshpass is not installed but a password is set. Install sshpass or set SSH_KEY_PATH."
  exit 1
fi

TARGETS=()
if [[ -n "$UPGRADE_SELECTED_IPS" ]]; then
  read -r -a TARGETS <<< "$UPGRADE_SELECTED_IPS"
elif [[ -n "$UPGRADE_SELECTED_JSON" && -f "$UPGRADE_SELECTED_JSON" ]]; then
  mapfile -t TARGETS < <(jq -r '.[].ip' "$UPGRADE_SELECTED_JSON" | awk 'NF')
fi
TOTAL=${#TARGETS[@]}
(( TOTAL > 0 )) || { err_box "No targets to run."; exit 1; }

detect_server_ip(){
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i!="127.0.0.1"){print $i; exit}}')"
  echo "$ip"
}
SERVER_IP="$(detect_server_ip)"
[[ -n "$SERVER_IP" ]] || { err_box "Could not determine local server IP."; exit 1; }
TFTP_BASE="tftp://${SERVER_IP}/hybrid"
FIRMWARE_HTTP_BASE="${FIRMWARE_HTTP_BASE:-http://${SERVER_IP}/images}"

RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
RUN_ROOT="$SCRIPT_DIR/runs"; mkdir -p "$RUN_ROOT"
RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs" "$RUN_DIR/cmds"
RUN_ERR="$RUN_DIR/run.err"; : > "$RUN_ERR"
STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"

SUMMARY_CSV="$RUN_DIR/summary.csv"; echo "ip,hostname,mode,confreg,precheck,result" > "$SUMMARY_CSV"
ACTIONS_CSV="$RUN_DIR/actions.csv"; echo "ip,hostname,action,result,detail" > "$ACTIONS_CSV"

DIALOG=0; command -v dialog >/dev/null 2>&1 && DIALOG=1
PROG_PIPE=""; PROG_FD=""; DIALOG_PID=""
# Keep the dialog split view open this many seconds at the end (0 = no hold).
UI_EXIT_HOLD_SEC="${UI_EXIT_HOLD_SEC:-4}"


ui_hold_end() {
  if (( DIALOG )); then
    local s="${UI_EXIT_HOLD_SEC:-0}"
    if (( s > 0 )); then
      gauge 100 "Done. Closing in ${s}s…"
      sleep "$s"
    fi
  fi
}
ui_flush(){ (( DIALOG )) && sleep 0.25; }

ui_calc(){
  local L=24 C=80
  if read -r L C < <(stty size 2>/dev/null); then :; fi
  (( L<18 )) && L=18; (( C<80 )) && C=80
  TAIL_H=$((L-8)); (( TAIL_H<10 )) && TAIL_H=10
  TAIL_W=$((C-4)); (( TAIL_W<70 )) && TAIL_W=70
  GAUGE_H=6; GAUGE_W=$TAIL_W
  GAUGE_ROW=$((TAIL_H+2)); GAUGE_COL=2
}
log(){ printf '%(%H:%M:%S)T %s\n' -1 "$1" >> "$STATUS_FILE"; (( DIALOG )) || echo "$1"; }
gauge(){
  local p="${1:-0}" m="${2:-Working…}"
  if (( DIALOG )) && [[ -n "$PROG_FD" ]] && [[ -e "/proc/$$/fd/$PROG_FD" ]]; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$PROG_FD"; } 2>>"$RUN_ERR" || true
  else
    echo "[progress] $p%% - $m"
  fi
}
ui_start(){
  if (( ! DIALOG )); then echo "[info] Plain UI."; return; fi
  ui_calc
  PROG_PIPE="$(mktemp -u)"
  mkfifo "$PROG_PIPE"
  # shellcheck disable=SC3020
  exec {PROG_FD}<>"$PROG_PIPE"
  (
    dialog --no-shadow \
           --begin 1 2 --title "Activity (Run: $RUN_ID)" --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
           --and-widget \
           --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Overall Progress" \
           --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$PROG_PIPE"
  ) & DIALOG_PID=$!
  sleep 0.15
  if ! { printf 'XXX\n1\nStarting…\nXXX\n' >&"$PROG_FD"; } 2>>"$RUN_ERR"; then
    exec {PROG_FD}>&- 2>/dev/null || true
    rm -f "$PROG_PIPE" 2>/dev/null || true
    kill "$DIALOG_PID" 2>/dev/null || true
    DIALOG=0
  fi
}
ui_stop(){
  if (( DIALOG )); then
    { printf 'XXX\n100\nDone.\nXXX\n' >&"$PROG_FD"; } 2>/dev/null || true
    exec {PROG_FD}>&- 2>/dev/null || true
    rm -f "$PROG_PIPE" 2>/dev/null || true
    kill "$DIALOG_PID" 2>/dev/null || true
  fi
}
trap 'ui_stop' EXIT

# ===== SSH builder =====
build_ssh_arr(){
  local ip="$1"
  SSH_CMD=(ssh
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=60 -o ServerAliveInterval=10 -o ServerAliveCountMax=6
    -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa
    -o KexAlgorithms=+diffie-hellman-group14-sha1
    -tt "${SSH_USERNAME}@${ip}"
  )
  if [[ -n "${SSH_KEY_PATH:-}" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD+=(-i "$SSH_KEY_PATH" -o BatchMode=yes)
  else
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" "${SSH_CMD[@]}"
      -o PreferredAuthentications=password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1)
  fi
}

# ===== Helpers: resolving image from plan/env =====
get_plan_field(){ local ip="$1" key="$2"
  [[ -n "$UPGRADE_SELECTED_JSON" && -s "$UPGRADE_SELECTED_JSON" ]] || return 1
  jq -r --arg ip "$ip" --arg k "$key" '.[] | select(.ip==$ip) | .[$k] // empty' "$UPGRADE_SELECTED_JSON"
}
resolve_image_for_ip(){ # -> "file|size_bytes"
  local ip="$1" file="" size=""
  if [[ -s "${UPGRADE_SELECTED_JSON:-}" ]]; then
    file="$(get_plan_field "$ip" "target_file")"
    size="$(get_plan_field "$ip" "target_size_bytes")"
  fi
  if [[ -z "$file" ]]; then
    if [[ -n "${FW_CAT9K_LITE_FILE:-}" ]]; then file="$FW_CAT9K_LITE_FILE"; size="${FW_CAT9K_LITE_SIZE_BYTES:-}"; fi
    if [[ -z "$file" && -n "${FW_CAT9K_FILE:-}" ]]; then file="$FW_CAT9K_FILE"; size="${FW_CAT9K_SIZE_BYTES:-}"; fi
  fi
  echo "${file}|${size}"
}

# Pretty-print bytes (B/KB/MB/GB) for logs
fmt_bytes(){ awk -v b="${1:-0}" 'BEGIN{
  if (b<1024)            printf("%d B", b);
  else if (b<1048576)    printf("%.1f KB", b/1024);
  else if (b<1073741824) printf("%.1f MB", b/1048576);
  else                   printf("%.2f GB", b/1073741824);
}'; }

# ===== Parse bytes from a captured "dir" output: choose the LARGEST integer on the line with filename =====
flash_bytes_from_capture(){
  # usage: flash_bytes_from_capture <capture_file> <basename>; prints bytes or nothing
  local outfile="$1" base="$2"
  awk -v f="$base" '
    BEGIN{mx=-1; seen=0}
    index($0,f){
      seen=1
      for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/){n=$i+0; if(n>mx) mx=n}
    }
    END{ if(seen && mx>=0) print mx }' "$outfile"
}

# Back-compat alias: parse bytes from captured 'dir' output
flash_size_from(){ flash_bytes_from_capture "$@"; }

# Poll flash for the file size and log progress while $4 (copy PID) is alive
http_progress_poller() {
  local ip="$1" base="$2" total="$3" copy_pid="$4"
  local poll="${HTTP_PROGRESS_POLL_SEC:-10}" last_bytes="" cur="" laps=0

  build_ssh_arr "$ip"; local POLL_SSH=( "${SSH_CMD[@]}" )
  while kill -0 "$copy_pid" 2>/dev/null; do
    local p_raw p_norm
    p_raw="$(mktemp)"; p_norm="$(mktemp)"
    {
      printf '\r\n'; printf 'terminal length 0\r\n'
      printf 'dir flash: | include %s\r\n' "$base"
      printf 'exit\r\n'
    } | timeout -k 5s 30s "${POLL_SSH[@]}" >"$p_raw" 2>&1 || true
    tr -d '\r' < "$p_raw" > "$p_norm"
    cur="$(flash_size_from "$p_norm" "$base")"
    rm -f "$p_raw" "$p_norm"

    if [[ -n "$cur" && "$cur" =~ ^[0-9]+$ && "$cur" != "$last_bytes" ]]; then
      if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
        local pct=$(( 100 * cur / total ))
        (( pct > 99 && cur < total )) && pct=99
        log "[${ip}] HTTP: progress $(fmt_bytes "$cur") / $(fmt_bytes "$total") (${pct}%)"
      else
        log "[${ip}] HTTP: progress $(fmt_bytes "$cur")"
      fi
      last_bytes="$cur"
    else
      laps=$((laps + poll))
      log "[${ip}] HTTP: copying… (no byte counter yet, +${poll}s; elapsed ${laps}s)"
    fi
    sleep "$poll"
  done
}
##Declare Skipping Version is Needed
# ---- extract x.y.z from any string (e.g., filename or "17.15.03.0.5635")
shortver_from_string(){ awk 'match($0,/[0-9]+\.[0-9]+\.[0-9]+/){print substr($0,RSTART,RLENGTH)}'; }

# ---- return the installed short version (pref C, then U); prints "17.15.03" or empty
installed_short_version_for_ip(){
  local ip="$1" raw norm v=""
  build_ssh_arr "$ip"
  raw="$(mktemp)"; norm="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'show install summary\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$norm"
  cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  # Prefer committed (C), then fall back to activated (U)
  v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+C[[:space:]]+/{print $NF; exit}' "$norm")"
  [[ -z "$v" ]] && v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+U[[:space:]]+/{print $NF; exit}' "$norm")"

  v="$(printf '%s\n' "$v" | shortver_from_string)"
  rm -f "$raw" "$norm"
  printf '%s' "$v"
}

# ---- decide skip: if target short ver == installed short ver → return 0 (skip)
skip_if_same_version_for_ip(){
  local ip="$1" file size base target_short inst_short host
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"

  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  [[ -z "$file" ]] && { log "[${ip}] VERSION: no target image defined — cannot compare"; return 1; }

  base="$(basename -- "$file")"
  target_short="$(printf '%s\n' "$base" | shortver_from_string)"
  [[ -z "$target_short" ]] && { log "[${ip}] VERSION: unable to parse target version from '$base'"; return 1; }

  inst_short="$(installed_short_version_for_ip "$ip")"

  if [[ -n "$inst_short" && "$inst_short" == "$target_short" ]]; then
    log "[${ip}] VERSION: ${inst_short} already committed/active — SKIP copy/install"
    echo "$ip,${host},version_check,skip,same(${inst_short})" >> "$ACTIONS_CSV"
    return 0   # signal: skip
  fi

  log "[${ip}] VERSION: target ${target_short}; installed ${inst_short:-unknown} — proceed"
  return 1
}
# ===== Pre-checks =====
precheck_for_ip(){
  local ip="$1" raw out rc=0
  log "[${ip}] CONNECT…"
  build_ssh_arr "$ip"
  raw="$(mktemp)"; out="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf 'show version\r\n';         sleep 1
    printf 'show install summary\r\n'; sleep 1
    printf 'exit\r\n'
  } | timeout -k 5s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?

  tr -d '\r' < "$raw" > "$out"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.session.log"

  local hostname; hostname="$(awk '/^hostname[[:space:]]+/{print $2}' "$out" | tail -n1)"
  [[ -z "$hostname" ]] && hostname="$(grep -E '^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$' "$out" | tail -n1 | sed -E 's/[>#].*$//')"
  [[ -z "$hostname" ]] && hostname="$(awk '/ uptime is /{print $1; exit}' "$out")"

  local mode=""
  mode="$(awk -F: 'BEGIN{IGNORECASE=1} /Running[[:space:]]+mode/{gsub(/^[ \t]+/,"",$2); print toupper($2); exit}' "$out")"
  if [[ -z "$mode" ]]; then
    mode="$(awk 'BEGIN{hdr=0}
      /^[[:space:]]*Switch[[:space:]]+Ports[[:space:]]+Model[[:space:]]+SW[[:space:]]+Version[[:space:]]+SW[[:space:]]+Image[[:space:]]+Mode/ {hdr=1; next}
      hdr==1 && /^[[:space:]]*([*]|[0-9])/ {m=toupper($NF); print m; exit}' "$out")"
  fi
  [[ -z "$mode" ]] && mode="$(grep -Eo '(INSTALL|BUNDLE)' "$out" | head -n1 | tr '[:lower:]' '[:upper:]')"

  local confreg; confreg="$(grep -i 'Configuration register is' "$out" | tail -n1 | awk '{print $NF}' | tr 'A-Z' 'a-z' | tr -d '.,;')"

  local precheck="ok"; [[ "$mode" == "INSTALL" ]] || precheck="fail:mode"
  [[ "$confreg" == "0x102" ]] || precheck="${precheck}${precheck:++}confreg"

  [[ "$precheck" == "ok" ]] && log "[${ip}] PRECHECK OK (mode=${mode:-?}, confreg=${confreg:-?})" \
                            || log "[${ip}] PRECHECK FAIL (mode=${mode:-?}, confreg=${confreg:-?}) => ${precheck}"

  echo "$hostname" > "$RUN_DIR/host.$ip"
  echo "$mode"     > "$RUN_DIR/mode.$ip"
  echo "$confreg"  > "$RUN_DIR/confreg.$ip"
  echo "$precheck" > "$RUN_DIR/precheck.$ip"

  rm -f "$raw" "$out"
  [[ "$precheck" == "ok" ]]
}

# ===== TFTP backup =====
backup_for_ip(){
  local ip="$1" hn ts url raw rc=0
  hn="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"; [[ -n "$hn" ]] || hn="sw-${ip//./-}"
  ts="$(date -u +%Y%m%d-%H%M)"; url="${TFTP_BASE}/${hn}-${ts}.cfg"
  log "[${ip}] BACKUP -> ${url}"
  build_ssh_arr "$ip"
  raw="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf 'copy running-config %s\r\n' "$url"
    printf '\r\n'; sleep 0.3; printf 'y\r\n'; sleep 0.3; printf 'exit\r\n'
  } | timeout -k 8s 180s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?

  tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.session.log"
  if grep -qiE 'bytes copied|Copy complete|[Ss]uccess' "$raw"; then
    log "[${ip}] BACKUP OK"; echo "$ip,$hn,backup,ok," >> "$ACTIONS_CSV"; rm -f "$raw"; return 0
  else
    log "[${ip}] BACKUP FAILED"; echo "$ip,$hn,backup,failed," >> "$ACTIONS_CSV"; mv -f "$raw" "$RUN_DIR/${ip}.backup.out"; return 1
  fi
}

# ===== Clean inactive =====
clean_inactive_for_ip(){
  local ip="$1" host raw norm rc=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  log "[${ip}] CLEAN: install remove inactive"

  # ---- tunables (override with env if needed) ----
  local FIRST_Y_DELAY="${INSTALL_Y_FIRST_DELAY_SEC:-5}"     # wait before first 'y'
  local Y_DRIP_COUNT="${INSTALL_Y_DRIP_COUNT:-8}"            # extra 'y' presses
  local Y_DRIP_GAP="${INSTALL_Y_DRIP_GAP_SEC:-1}"            # gap between 'y'
  local BUSY_WAIT_LOOPS="${INSTALL_BUSY_WAIT_LOOPS:-10}"     # polls if "already running"
  local BUSY_WAIT_GAP="${INSTALL_BUSY_WAIT_GAP_SEC:-6}"      # seconds between polls

  build_ssh_arr "$ip"
  raw="$(mktemp)"; norm="$(mktemp)"

  # Optional: pre-clear any stale install op (no-op if none)
  if [[ "${INSTALL_ABORT_BEFORE_CLEAN:-0}" == "1" ]]; then
    { printf '\r\n'; printf 'terminal length 0\r\n'
      printf 'install abort\r\n'
      printf '\r\n'; printf 'exit\r\n'
    } | timeout -k 5s 30s "${SSH_CMD[@]}" >/dev/null 2>&1 || true
  fi

  # Send command, then drip confirmations so we don't "early-y" the prompt
  {
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf 'install remove inactive\r\n'
    sleep "$FIRST_Y_DELAY"
    for _i in $(seq 1 "$Y_DRIP_COUNT"); do
      printf 'y\r\n'
      sleep "$Y_DRIP_GAP"
    done
    printf '\r\n'      # harmless extra CR
    printf 'exit\r\n'
  } | timeout -k 15s 900s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?

  tr -d '\r' < "$raw" > "$norm"
  cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  # Hard errors (avoid treating the heading word "FAILED" as fatal)
  if grep -qiE '(^|[^A-Z])(%?Error|Permission denied|Unknown host|timed out)' "$norm"; then
    log "[${ip}] CLEAN: FAILED"
    echo "$ip,${host},clean_inactive,failed," >> "$ACTIONS_CSV"
    mv -f "$norm" "$RUN_DIR/${ip}.clean.fail.out"; rm -f "$raw"
    return 1
  fi

  # If install manager is already busy, poll until it clears, then treat as OK(no changes)
  if grep -qi 'cannot start new install operation, some operation is already running' "$norm"; then
    log "[${ip}] CLEAN: busy — waiting for current install op to clear…"
    local cleared=0 p_raw p_norm
    for _try in $(seq 1 "$BUSY_WAIT_LOOPS"); do
      p_raw="$(mktemp)"; p_norm="$(mktemp)"
      { printf '\r\n'; printf 'terminal length 0\r\n'
        printf 'show install summary\r\n'
        printf 'exit\r\n'
      } | timeout -k 5s 60s "${SSH_CMD[@]}" >"$p_raw" 2>&1 || true
      tr -d '\r' < "$p_raw" > "$p_norm"
      cat "$p_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
      if grep -qiE 'No[[:space:]]+pending[[:space:]]+install|No[[:space:]]+install[[:space:]]+operation|No[[:space:]]+in-?progress[[:space:]]+install' "$p_norm"; then
        cleared=1; rm -f "$p_raw" "$p_norm"; break
      fi
      rm -f "$p_raw" "$p_norm"
      sleep "$BUSY_WAIT_GAP"
    done
    if (( cleared )); then
      log "[${ip}] CLEAN: OK (busy cleared, no changes)"
      echo "$ip,${host},clean_inactive,ok,busy_cleared" >> "$ACTIONS_CSV"
    else
      log "[${ip}] CLEAN: OK (busy, timed out waiting — proceeding)"
      echo "$ip,${host},clean_inactive,ok,busy_timedout" >> "$ACTIONS_CSV"
    fi
    rm -f "$raw" "$norm"
    return 0
  fi

  # Clear success signals
  if grep -qiE '(SUCCESS:[[:space:]]*install_remove|SUCCESS:[[:space:]]*Files deleted|SUCCESS:[[:space:]]*No extra package|Nothing to clean|Finished Post_Remove_Cleanup)' "$norm"; then
    log "[${ip}] CLEAN: OK"
    echo "$ip,${host},clean_inactive,ok," >> "$ACTIONS_CSV"
    rm -f "$raw" "$norm"; return 0
  fi

  # Workflow banners but no deletes → OK(no changes)
  if grep -qiE '(install_remove:|Cleaning[[:space:]]*/flash)' "$norm"; then
    log "[${ip}] CLEAN: OK (no changes)"
    echo "$ip,${host},clean_inactive,ok,no_changes" >> "$ACTIONS_CSV"
    rm -f "$raw" "$norm"; return 0
  fi

  # Super quiet → still OK to avoid false negatives
  log "[${ip}] CLEAN: OK (quiet)"
  echo "$ip,${host},clean_inactive,ok,quiet" >> "$ACTIONS_CSV"
  rm -f "$raw" "$norm"; return 0
}
http_fetch_image_for_ip(){
  local ip="$1" host file size url base
  local pre_raw pre_norm existing_bytes="" rc=0
  local POLL="${HTTP_PROGRESS_POLL_SEC:-10}"

  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  if [[ -z "$file" ]]; then
    log "[${ip}] HTTP: no target image defined."
    echo "$ip,${host},http_copy,skipped,no_image" >> "$ACTIONS_CSV"
    return 1
  fi

  base="$(basename -- "$file")"
  url="${FIRMWARE_HTTP_BASE%/}/${base}"

  # ---- pre-check: skip if exact bytes already present (and not forcing) ----
  log "[${ip}] HTTP: checking flash for '${base}'…"
  build_ssh_arr "$ip"
  pre_raw="$(mktemp)"; pre_norm="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'dir flash: | include %s\r\n' "$base"
    printf 'exit\r\n'
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$pre_raw" 2>&1 || true
  tr -d '\r' < "$pre_raw" > "$pre_norm"
  existing_bytes="$(flash_size_from "$pre_norm" "$base")"
  rm -f "$pre_raw" "$pre_norm"

  if [[ -n "$size" && -n "$existing_bytes" && "$existing_bytes" == "$size" && "${HTTP_FORCE_COPY:-0}" != "1" ]]; then
    log "[${ip}] HTTP: file exists — SKIP (bytes=${existing_bytes})"
    echo "$ip,${host},http_copy,ok,already_present(${existing_bytes})" >> "$ACTIONS_CSV"
    return 0
  fi

  log "[${ip}] HTTP: copying ${url} -> flash:${base}"

  # ---- launch the copy in background, capture ALL output to a file ----
  build_ssh_arr "$ip"; local COPY_SSH=( "${SSH_CMD[@]}" )
  local copy_raw copy_norm COPY_PID HB_PID
  copy_raw="$(mktemp)"; copy_norm="$(mktemp)"
  (
    { printf '\r\n'; printf 'terminal length 0\r\n'
      if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
        printf 'configure terminal\r\n'
        printf 'ip http client source-interface %s\r\n' "$HTTP_CLIENT_SOURCE_IFACE"
        printf 'end\r\n'
      fi
      # Prefer /overwrite; device will NACK it if unsupported
      printf 'copy /overwrite %s flash:%s\r\n' "$url" "$base"
      # Keep this session dedicated to the copy (no extra commands).
    } | timeout -k 30s 7200s "${COPY_SSH[@]}"
  ) >"$copy_raw" 2>&1 & COPY_PID=$!

  # ---- progress poller: query flash size periodically during the copy ----
  build_ssh_arr "$ip"; local POLL_SSH=( "${SSH_CMD[@]}" )
  (
    local last_bytes="" cur="" total="${size:-}" pct
    while kill -0 "$COPY_PID" 2>/dev/null; do
      local p_raw p_norm
      p_raw="$(mktemp)"; p_norm="$(mktemp)"
      {
        printf '\r\n'; printf 'terminal length 0\r\n'
        printf 'dir flash: | include %s\r\n' "$base"
        printf 'exit\r\n'
      } | timeout -k 5s 30s "${POLL_SSH[@]}" >"$p_raw" 2>&1 || true
      tr -d '\r' < "$p_raw" > "$p_norm"
      cur="$(flash_size_from "$p_norm" "$base")"
      rm -f "$p_raw" "$p_norm"

      if [[ -n "$cur" && "$cur" != "$last_bytes" ]]; then
        if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
          pct=$(( 100 * cur / total )); (( pct > 99 && cur < total )) && pct=99
          log "[${ip}] HTTP: progress $(fmt_bytes "$cur") / $(fmt_bytes "$total") (${pct}%)"
        else
          log "[${ip}] HTTP: progress $(fmt_bytes "$cur")"
        fi
        last_bytes="$cur"
      else
        log "[${ip}] HTTP: copying… (checking again in ${POLL}s)"
      fi
      sleep "$POLL"
    done
  ) & HB_PID=$!

  # ---- wait for copy to finish, stop poller, normalize output ----
  wait "$COPY_PID" || rc=$?
  kill "$HB_PID" 2>/dev/null || true
  wait "$HB_PID" 2>/dev/null || true
  tr -d '\r' < "$copy_raw" > "$copy_norm"
  cat "$copy_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  # ---- fallback: classic copy if /overwrite unsupported (with progress poller) ----
  if grep -qiE '(Invalid input detected|Unrecognized command)' "$copy_norm"; then
    log "[${ip}] HTTP: /overwrite unsupported — retrying without it"
    : > "$copy_raw"; : > "$copy_norm"

    (
      { printf '\r\n'; printf 'terminal length 0\r\n'
        printf 'copy %s flash:%s\r\n' "$url" "$base"
        printf '\r\n'; sleep 0.5       # accept default filename
        printf 'y\r\n';  sleep 0.5     # overwrite if prompted
        printf '\r\n';  sleep 0.5
      } | timeout -k 30s 7200s "${COPY_SSH[@]}"
    ) >"$copy_raw" 2>&1 & COPY_PID=$!

    # same poller for fallback
    build_ssh_arr "$ip"; POLL_SSH=( "${SSH_CMD[@]}" )
    (
      local last_bytes="" cur="" total="${size:-}" pct
      while kill -0 "$COPY_PID" 2>/dev/null; do
        local p_raw p_norm
        p_raw="$(mktemp)"; p_norm="$(mktemp)"
        {
          printf '\r\n'; printf 'terminal length 0\r\n'
          printf 'dir flash: | include %s\r\n' "$base"
          printf 'exit\r\n'
        } | timeout -k 5s 30s "${POLL_SSH[@]}" >"$p_raw" 2>&1 || true
        tr -d '\r' < "$p_raw" > "$p_norm"
        cur="$(flash_size_from "$p_norm" "$base")"
        rm -f "$p_raw" "$p_norm"

        if [[ -n "$cur" && "$cur" != "$last_bytes" ]]; then
          if [[ -n "$total" && "$total" =~ ^[0-9]+$ && "$total" -gt 0 ]]; then
            pct=$(( 100 * cur / total )); (( pct > 99 && cur < total )) && pct=99
            log "[${ip}] HTTP: progress $(fmt_bytes "$cur") / $(fmt_bytes "$total") (${pct}%)"
          else
            log "[${ip}] HTTP: progress $(fmt_bytes "$cur")"
          fi
          last_bytes="$cur"
        else
          log "[${ip}] HTTP: copying… (checking again in ${POLL}s)"
        fi
        sleep "$POLL"
      done
    ) & HB_PID=$!

    wait "$COPY_PID" || rc=$?
    kill "$HB_PID" 2>/dev/null || true
    wait "$HB_PID" 2>/dev/null || true

    tr -d '\r' < "$copy_raw" > "$copy_norm"
    cat "$copy_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  fi

  # ---- final size check from flash ----
  local post_raw post_norm post_bytes=""
  build_ssh_arr "$ip"
  post_raw="$(mktemp)"; post_norm="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'dir flash: | include %s\r\n' "$base"
    printf 'exit\r\n'
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$post_raw" 2>&1 || true
  tr -d '\r' < "$post_raw" > "$post_norm"
  post_bytes="$(flash_size_from "$post_norm" "$base")"
  rm -f "$post_raw" "$post_norm"

  if grep -qiE '(bytes copied|copied in [0-9.]+ sec|Copy complete|copied successfully|\[OK -[[:space:]]*[0-9]+[[:space:]]*bytes\])' "$copy_norm" \
     || [[ -n "$post_bytes" ]]; then
    if [[ -n "$post_bytes" ]]; then
      log "[${ip}] HTTP: OK (bytes=${post_bytes})"
      echo "$ip,${host},http_copy,ok,bytes=${post_bytes}" >> "$ACTIONS_CSV"
    else
      log "[${ip}] HTTP: OK"
      echo "$ip,${host},http_copy,ok," >> "$ACTIONS_CSV"
    fi
    rm -f "$copy_raw" "$copy_norm"
    return 0
  fi

  log "[${ip}] HTTP: FAILED"
  echo "$ip,${host},http_copy,failed," >> "$ACTIONS_CSV"
  mv -f "$copy_norm" "$RUN_DIR/${ip}.http_copy.out"; rm -f "$copy_raw"
  return 1
}

# ===== Save running-config (write memory) with explicit UI logs =====
write_memory_for_ip() {
  local ip="$1" host raw norm rc=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"

  log "[${ip}] WR: write memory…"
  build_ssh_arr "$ip"
  raw="$(mktemp)"; norm="$(mktemp)"

  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'write memory\r\n'
    printf 'exit\r\n'
  } | timeout -k 8s 120s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?

  tr -d '\r' < "$raw" > "$norm"
  cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  # Success signals commonly seen on IOS-XE
  if grep -qiE '(\[OK\]|Copy complete|bytes copied|copied successfully)' "$norm"; then
    log "[${ip}] WR: OK"
    rm -f "$raw" "$norm"
    return 0
  fi

  # Not fatal, but warn loudly
  log "[${ip}] WR: ambiguous — proceeding (check devlog)"
  mv -f "$norm" "$RUN_DIR/${ip}.write_memory.out"
  rm -f "$raw"
  return 1
}

##INSTALL
install_activate_image_for_ip(){
  local ip="$1" host file size base
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"

  # caps/timeouts + keepalive drip
  local MAX_RUN_SEC="${INSTALL_STREAM_MAX_SECS:-14400}"
  local DRIP_GAP="${INSTALL_KEEPALIVE_GAP_SEC:-5}"

  # Resolve target image from plan/env
  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  if [[ -z "$file" ]]; then
    log "[${ip}] INSTALL: no image defined — SKIP"
    echo "$ip,${host},install,skipped,no_image" >> "$ACTIONS_CSV"
    return 2
  fi
  base="$(basename -- "$file")"

  # Make sure it’s on flash (and matches bytes if known)
  build_ssh_arr "$ip"
  local chk_raw chk_norm have_bytes=""
  chk_raw="$(mktemp)"; chk_norm="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'dir flash: | include %s\r\n' "$base"
    printf 'exit\r\n'
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$chk_raw" 2>&1 || true
  tr -d '\r' < "$chk_raw" > "$chk_norm"
  have_bytes="$(flash_size_from "$chk_norm" "$base")"
  rm -f "$chk_raw" "$chk_norm"

  if [[ -z "$have_bytes" ]]; then
    log "[${ip}] INSTALL: image not found on flash — SKIP"
    echo "$ip,${host},install,skipped,missing_image" >> "$ACTIONS_CSV"
    return 2
  fi
  if [[ -n "$size" && "$size" != "$have_bytes" ]]; then
    log "[${ip}] INSTALL: image size mismatch (have=${have_bytes}, want=${size}) — SKIP"
    echo "$ip,${host},install,skipped,size_mismatch" >> "$ACTIONS_CSV"
    return 2
  fi

  # Save config first (avoids “System configuration has been modified” failure)
  if ! write_memory_for_ip "$ip"; then
    log "[${ip}] INSTALL: warning — write memory didn’t confirm; continuing"
  fi

  local cmd="install add file bootflash:${base} activate commit prompt-level none"
  log "[${ip}] INSTALL: add+activate+commit (bootflash:${base})"
  # also persist the exact command we’ll feed
  printf '%s\n' "$cmd" > "$RUN_DIR/cmds/${ip}.install.cmd"

  # Build SSH and files for streaming
  build_ssh_arr "$ip"; local INST_SSH=( "${SSH_CMD[@]}" )
  local inst_raw inst_norm state_file fifo FEED_PID="" STREAM_PID="" rc=0
  inst_raw="$(mktemp)"; inst_norm="$(mktemp)"; state_file="$(mktemp)"
  fifo="$(mktemp -u)"; mkfifo "$fifo"

  # 1) Start SSH reading from our FIFO and writing to inst_raw
  timeout -k 10s "$MAX_RUN_SEC" "${INST_SSH[@]}" <"$fifo" >"$inst_raw" 2>&1 & local INST_PID=$!

  # 2) Feed commands to FIFO AND keep stdin open with a CR drip until we set state
  (
    # initial setup + the install command
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf '%s\r\n' "$cmd"
    # keep the session open so the device can stream progress
    while [[ ! -s "$state_file" ]] && kill -0 "$INST_PID" 2>/dev/null; do
      sleep "$DRIP_GAP"
      printf '\r\n'
    done
  ) >"$fifo" 2>/dev/null & FEED_PID=$!

    # 3) Milestone streamer (case-insensitive), sets state_file on success/fail/busy
  (
    tail -n +1 -f "$inst_raw" 2>/dev/null \
      | stdbuf -o0 tr -d '\r' \
      | {
          # de-dup flags (persist within this subshell)
          seen_activate_finished=0
          seen_commit_finished=0

          while IFS= read -r line; do
            lc="${line,,}"
            case "$lc" in
              *"install_add_activate_commit: start"*) log "[${ip}] INSTALL: workflow START" ;;
              *"install_add: start"*)                log "[${ip}] INSTALL: ADD start" ;;
              *"finished initial file syncing"*)     log "[${ip}] INSTALL: file sync done" ;;
              *"image added. version:"*)             log "[${ip}] INSTALL: ADD finished (${line#*Version: })" ;;
              *"install_activate: start"*)           log "[${ip}] INSTALL: ACTIVATE start" ;;
              *"activating img"*)                    log "[${ip}] INSTALL: Activating IMG" ;;
              *"finished activate"*)
                                                      if (( ! seen_activate_finished )); then
                                                        log "[${ip}] INSTALL: ACTIVATE finished"
                                                        seen_activate_finished=1
                                                      fi ;;
              *"finished commit"*)
                                                      if (( ! seen_commit_finished )); then
                                                        log "[${ip}] INSTALL: COMMIT finished (verifying…)"
                                                        seen_commit_finished=1
                                                      fi ;;
              *"success: install_add_activate_commit"*)
                                                      log "[${ip}] INSTALL: SUCCESS (add/activate/commit)"
                                                      echo success > "$state_file"; break ;;
              *"failed:"*)                            log "[${ip}] INSTALL: FAILED — ${line#*FAILED: }"
                                                      echo failed > "$state_file"; break ;;
              *"cannot start new install operation, some operation is already running"*)
                                                      log "[${ip}] INSTALL: BUSY — another install op is running (suggest reboot)"
                                                      echo busy > "$state_file"; break ;;
            esac
          done
        }
  ) & STREAM_PID=$!

  # 4) Wait for SSH to finish; then stop helpers
  wait "$INST_PID" 2>/dev/null || rc=$?
  kill "$FEED_PID" 2>/dev/null || true
  kill "$STREAM_PID" 2>/dev/null || true
  rm -f "$fifo" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true
  wait "$STREAM_PID" 2>/dev/null || true

  # Normalize + archive all device output
  tr -d '\r' < "$inst_raw" > "$inst_norm"
  cat "$inst_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$inst_raw"

  # Decide from explicit markers
  local state=""
  [[ -s "$state_file" ]] && state="$(cat "$state_file" 2>/dev/null || true)"
  rm -f "$state_file"

  if [[ "$state" == "success" ]]; then
    log "[${ip}] INSTALL: complete"
    echo "$ip,${host},install,ok,success" >> "$ACTIONS_CSV"
    rm -f "$inst_norm"
    return 0
  fi
  if [[ "$state" == "failed" ]]; then
    log "[${ip}] INSTALL: failed (see devlogs)"
    echo "$ip,${host},install,failed," >> "$ACTIONS_CSV"
    mv -f "$inst_norm" "$RUN_DIR/${ip}.install.fail.out"
    return 1
  fi
  if [[ "$state" == "busy" ]]; then
    log "[${ip}] INSTALL: busy/in-progress — recommend manual reboot, then re-run."
    echo "$ip,${host},install,skipped,busy" >> "$ACTIONS_CSV"
    mv -f "$inst_norm" "$RUN_DIR/${ip}.install.busy.out"
    return 3
  fi

  # Fallback: we didn’t see SUCCESS/FAILED — try to verify outcome
  build_ssh_arr "$ip"
  local sum_raw sum_norm
  sum_raw="$(mktemp)"; sum_norm="$(mktemp)"
  {
    printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'show install summary\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 120s "${SSH_CMD[@]}" >"$sum_raw" 2>&1 || true
  tr -d '\r' < "$sum_raw" > "$sum_norm"
  cat "$sum_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$sum_raw"

  if grep -qiE 'Commit:[[:space:]]+Passed|Status:[[:space:]]+Committed|SUCCESS:[[:space:]]*install_add_activate_commit' "$sum_norm"; then
    log "[${ip}] INSTALL: verified SUCCESS via summary"
    echo "$ip,${host},install,ok,verified" >> "$ACTIONS_CSV"
    rm -f "$sum_norm" "$inst_norm"
    return 0
  fi
  if grep -qiE 'Operation in progress|in[- ]progress' "$sum_norm"; then
    log "[${ip}] INSTALL: still in progress (device busy)"
    echo "$ip,${host},install,ok,in_progress" >> "$ACTIONS_CSV"
    rm -f "$sum_norm" "$inst_norm"
    return 0
  fi

  log "[${ip}] INSTALL: uncertain/failed (no success markers)"
  echo "$ip,${host},install,failed,uncertain" >> "$ACTIONS_CSV"
  mv -f "$inst_norm" "$RUN_DIR/${ip}.install.uncertain.out"
  rm -f "$sum_norm"
  return 1
}
# ===== main =====
ui_start
log "Run ID: $RUN_ID"; log "Run dir: $RUN_DIR"
log "User: ${SSH_USERNAME} (from env)"; log "Server TFTP: ${SERVER_IP}/hybrid"
log "Targets: ${TARGETS[*]}"; gauge 1 "Starting…"

WORK_DONE=0
for ip in "${TARGETS[@]}"; do
  result="skipped"

  if precheck_for_ip "$ip"; then
    if backup_for_ip "$ip"; then
      clean_inactive_for_ip "$ip" || true

      # ---- NEW: skip if already on the target version
      if skip_if_same_version_for_ip "$ip"; then
        result="skipped(same_version)"
      else
        # continue with copy/install as usual
        if http_fetch_image_for_ip "$ip"; then
          rc_install=0
          install_activate_image_for_ip "$ip" || rc_install=$?

          case "$rc_install" in
            0) result="ok" ;;                          # success (or verified)
            2) result="skipped(install)" ;;            # image missing/size mismatch
            3) result="busy(reboot_suggested)" ;;      # install mgr already running
            *) result="fail(install)" ;;               # explicit fail/uncertain
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

  hn="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  mode="$(cat "$RUN_DIR/mode.$ip" 2>/dev/null || true)"
  confreg="$(cat "$RUN_DIR/confreg.$ip" 2>/dev/null || true)"
  precheck="$(cat "$RUN_DIR/precheck.$ip" 2>/dev/null || true)"
  echo "$ip,${hn},${mode},${confreg},${precheck},${result}" >> "$SUMMARY_CSV"

  WORK_DONE=$((WORK_DONE + 1))
  pct=$(( 100 * WORK_DONE / TOTAL ))
  gauge "$pct" "Processed $WORK_DONE / $TOTAL"
done

log "Summary: $SUMMARY_CSV"

if (( DIALOG )) && [[ "${SHOW_RUN_SUMMARY:-0}" == "1" ]]; then
  ui_flush
  dialog --no-shadow --title "Run complete" \
         --msgbox "Summary CSV:\n$SUMMARY_CSV\n\nRun dir:\n$RUN_DIR\n\nPress Enter to close." 11 72
  ui_flush
fi

ui_hold_end
ui_stop
