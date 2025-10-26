#!/usr/bin/env bash
# at_image_upgrade.sh — headless (no dialog). Safe to run under `at`.
# Uses meraki_discovery.env + selected_upgrade.env to perform the same flow as upgrade_iosxe_safe.sh:
# PRECHECK → TFTP backup → install remove inactive → HTTP image fetch → install activate commit.

set -Eeuo pipefail

# ---------- basics ----------
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need awk; need jq; need ssh; need timeout
command -v sshpass >/dev/null 2>&1 || true

# Minimal environment in case we’re invoked by `at`
export TERM="${TERM:-dumb}"
export PATH="${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}"
export LC_ALL="${LC_ALL:-C}"

# ---------- inputs ----------
BASE_ENV="${BASE_ENV:-$SCRIPT_DIR/meraki_discovery.env}"
SEL_ENV="${1:-$SCRIPT_DIR/selected_upgrade.env}"

[[ -f "$BASE_ENV" ]] || { echo "ERROR: $BASE_ENV not found." >&2; exit 1; }
[[ -f "$SEL_ENV"  ]] || { echo "ERROR: $SEL_ENV not found."  >&2; exit 1; }

# avoid history expansion (!) in passwords
set +H
# shellcheck disable=SC1090
source "$BASE_ENV"
# shellcheck disable=SC1090
source "$SEL_ENV"

SSH_USERNAME="${SSH_USERNAME:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
UPGRADE_SELECTED_IPS="${UPGRADE_SELECTED_IPS:-}"
UPGRADE_SELECTED_JSON="${UPGRADE_SELECTED_JSON:-}"
HTTP_FORCE_COPY="${HTTP_FORCE_COPY:-0}"   # 1 = force re-copy even if bytes match

[[ -n "$SSH_USERNAME" ]] || { echo "ERROR: SSH_USERNAME is empty in $BASE_ENV" >&2; exit 1; }
if [[ -z "${SSH_KEY_PATH:-}" && -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
  echo "ERROR: sshpass not installed but a password is set. Install sshpass or set SSH_KEY_PATH." >&2
  exit 1
fi

# ---------- target list ----------
TARGETS=()
if [[ -n "$UPGRADE_SELECTED_IPS" ]]; then
  read -r -a TARGETS <<< "$UPGRADE_SELECTED_IPS"
elif [[ -n "$UPGRADE_SELECTED_JSON" && -f "$UPGRADE_SELECTED_JSON" ]]; then
  mapfile -t TARGETS < <(jq -r '.[].ip' "$UPGRADE_SELECTED_JSON" | awk 'NF')
fi
TOTAL=${#TARGETS[@]}
(( TOTAL > 0 )) || { echo "ERROR: No targets to run." >&2; exit 1; }

# ---------- server IP + endpoints ----------
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

# ---------- run folders ----------
RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
RUN_ROOT="${RUN_ROOT:-$SCRIPT_DIR/runs}"
mkdir -p "$RUN_ROOT"
RUN_DIR="$RUN_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs" "$RUN_DIR/cmds"
RUN_ERR="$RUN_DIR/run.err"; : > "$RUN_ERR"

SUMMARY_CSV="$RUN_DIR/summary.csv"; echo "ip,hostname,mode,confreg,precheck,result" > "$SUMMARY_CSV"
ACTIONS_CSV="$RUN_DIR/actions.csv"; echo "ip,hostname,action,result,detail" > "$ACTIONS_CSV"

log(){ printf '%(%H:%M:%S)T %s\n' -1 "$1" | tee -a "$RUN_DIR/ui.status"; }

# ---------- SSH builder ----------
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

# ---------- image helpers ----------
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

fmt_bytes(){ awk -v b="${1:-0}" 'BEGIN{
  if (b<1024)            printf("%d B", b);
  else if (b<1048576)    printf("%.1f KB", b/1024);
  else if (b<1073741824) printf("%.1f MB", b/1048576);
  else                   printf("%.2f GB", b/1073741824);
}'; }

flash_bytes_from_capture(){
  local outfile="$1" base="$2"
  awk -v f="$base" '
    BEGIN{mx=-1; seen=0}
    index($0,f){ seen=1; for(i=1;i<=NF;i++) if($i ~ /^[0-9]+$/){n=$i+0; if(n>mx) mx=n} }
    END{ if(seen && mx>=0) print mx }' "$outfile"
}
flash_size_from(){ flash_bytes_from_capture "$@"; }
shortver_from_string(){ awk 'match($0,/[0-9]+\.[0-9]+\.[0-9]+/){print substr($0,RSTART,RLENGTH)}'; }

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
  v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+C[[:space:]]+/{print $NF; exit}' "$norm")"
  [[ -z "$v" ]] && v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+U[[:space:]]+/{print $NF; exit}' "$norm")"
  v="$(printf '%s\n' "$v" | shortver_from_string)"
  rm -f "$raw" "$norm"
  printf '%s' "$v"
}

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
    return 0
  fi
  log "[${ip}] VERSION: target ${target_short}; installed ${inst_short:-unknown} — proceed"
  return 1
}

# ---------- steps ----------
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

clean_inactive_for_ip(){
  local ip="$1" host raw norm rc=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  log "[${ip}] CLEAN: install remove inactive"
  local FIRST_Y_DELAY="${INSTALL_Y_FIRST_DELAY_SEC:-5}"
  local Y_DRIP_COUNT="${INSTALL_Y_DRIP_COUNT:-8}"
  local Y_DRIP_GAP="${INSTALL_Y_DRIP_GAP_SEC:-1}"
  local BUSY_WAIT_LOOPS="${INSTALL_BUSY_WAIT_LOOPS:-10}"
  local BUSY_WAIT_GAP="${INSTALL_BUSY_WAIT_GAP_SEC:-6}"

  build_ssh_arr "$ip"
  raw="$(mktemp)"; norm="$(mktemp)"

  if [[ "${INSTALL_ABORT_BEFORE_CLEAN:-0}" == "1" ]]; then
    { printf '\r\n'; printf 'terminal length 0\r\n'
      printf 'install abort\r\n'
      printf '\r\n'; printf 'exit\r\n'
    } | timeout -k 5s 30s "${SSH_CMD[@]}" >/dev/null 2>&1 || true
  fi

  {
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf 'install remove inactive\r\n'
    sleep "$FIRST_Y_DELAY"
    for _i in $(seq 1 "$Y_DRIP_COUNT"); do printf 'y\r\n'; sleep "$Y_DRIP_GAP"; done
    printf '\r\n'; printf 'exit\r\n'
  } | timeout -k 15s 900s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?

  tr -d '\r' < "$raw" > "$norm"
  cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  if grep -qiE '(^|[^A-Z])(%?Error|Permission denied|Unknown host|timed out)' "$norm"; then
    log "[${ip}] CLEAN: FAILED"
    echo "$ip,${host},clean_inactive,failed," >> "$ACTIONS_CSV"
    mv -f "$norm" "$RUN_DIR/${ip}.clean.fail.out"; rm -f "$raw"; return 1
  fi

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
      rm -f "$p_raw" "$p_norm"; sleep "$BUSY_WAIT_GAP"
    done
    if (( cleared )); then
      log "[${ip}] CLEAN: OK (busy cleared, no changes)"
      echo "$ip,${host},clean_inactive,ok,busy_cleared" >> "$ACTIONS_CSV"
    else
      log "[${ip}] CLEAN: OK (busy, timed out waiting — proceeding)"
      echo "$ip,${host},clean_inactive,ok,busy_timedout" >> "$ACTIONS_CSV"
    fi
    rm -f "$raw" "$norm"; return 0
  fi

  if grep -qiE '(SUCCESS:[[:space:]]*install_remove|SUCCESS:[[:space:]]*Files deleted|SUCCESS:[[:space:]]*No extra package|Nothing to clean|Finished Post_Remove_Cleanup)' "$norm"; then
    log "[${ip}] CLEAN: OK"
    echo "$ip,${host},clean_inactive,ok," >> "$ACTIONS_CSV"
    rm -f "$raw" "$norm"; return 0
  fi

  if grep -qiE '(install_remove:|Cleaning[[:space:]]*/flash)' "$norm"; then
    log "[${ip}] CLEAN: OK (no changes)"
    echo "$ip,${host},clean_inactive,ok,no_changes" >> "$ACTIONS_CSV"
    rm -f "$raw" "$norm"; return 0
  fi

  log "[${ip}] CLEAN: OK (quiet)"
  echo "$ip,${host},clean_inactive,ok,quiet" >> "$ACTIONS_CSV"
  rm -f "$raw" "$norm"; return 0
}

http_fetch_image_for_ip(){
  local ip="$1" host file size url base pre_raw pre_norm existing_bytes="" rc=0
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
      printf 'copy /overwrite %s flash:%s\r\n' "$url" "$base"
    } | timeout -k 30s 7200s "${COPY_SSH[@]}"
  ) >"$copy_raw" 2>&1 & COPY_PID=$!

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

  wait "$COPY_PID" || rc=$?
  kill "$HB_PID" 2>/dev/null || true
  wait "$HB_PID" 2>/dev/null || true
  tr -d '\r' < "$copy_raw" > "$copy_norm"
  cat "$copy_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"

  if grep -qiE '(Invalid input detected|Unrecognized command)' "$copy_norm"; then
    log "[${ip}] HTTP: /overwrite unsupported — retrying without it"
    : > "$copy_raw"; : > "$copy_norm"
    (
      { printf '\r\n'; printf 'terminal length 0\r\n'
        printf 'copy %s flash:%s\r\n' "$url" "$base"
        printf '\r\n'; sleep 0.5; printf 'y\r\n'; sleep 0.5; printf '\r\n'; sleep 0.5
      } | timeout -k 30s 7200s "${COPY_SSH[@]}"
    ) >"$copy_raw" 2>&1 & COPY_PID=$!

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

write_memory_for_ip(){
  local ip="$1" host raw norm rc=0
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  log "[${ip}] WR: write memory…"
  build_ssh_arr "$ip"
  raw="$(mktemp)"; norm="$(mktemp)"
  { printf '\r\n'; printf 'terminal length 0\r\n'
    printf 'write memory\r\n'
    printf 'exit\r\n'
  } | timeout -k 8s 120s "${SSH_CMD[@]}" >"$raw" 2>&1 || rc=$?
  tr -d '\r' < "$raw" > "$norm"
  cat "$norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  if grep -qiE '(\[OK\]|Copy complete|bytes copied|copied successfully)' "$norm"; then
    log "[${ip}] WR: OK"; rm -f "$raw" "$norm"; return 0
  fi
  log "[${ip}] WR: ambiguous — proceeding (check devlog)"
  mv -f "$norm" "$RUN_DIR/${ip}.write_memory.out"; rm -f "$raw"; return 1
}

install_activate_image_for_ip(){
  local ip="$1" host file size base
  host="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  local MAX_RUN_SEC="${INSTALL_STREAM_MAX_SECS:-14400}"
  local DRIP_GAP="${INSTALL_KEEPALIVE_GAP_SEC:-5}"

  IFS='|' read -r file size <<<"$(resolve_image_for_ip "$ip")"
  if [[ -z "$file" ]]; then
    log "[${ip}] INSTALL: no image defined — SKIP"
    echo "$ip,${host},install,skipped,no_image" >> "$ACTIONS_CSV"
    return 2
  fi
  base="$(basename -- "$file")"

  build_ssh_arr "$ip"
  local chk_raw chk_norm have_bytes=""
  chk_raw="$(mktemp)"; chk_norm="$(mktemp)"
  { printf '\r\n'; printf 'terminal length 0\r\n'
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

  if ! write_memory_for_ip "$ip"; then
    log "[${ip}] INSTALL: warning — write memory didn’t confirm; continuing"
  fi

  local cmd="install add file bootflash:${base} activate commit prompt-level none"
  log "[${ip}] INSTALL: add+activate+commit (bootflash:${base})"
  printf '%s\n' "$cmd" > "$RUN_DIR/cmds/${ip}.install.cmd"

  build_ssh_arr "$ip"; local INST_SSH=( "${SSH_CMD[@]}" )
  local inst_raw inst_norm state_file fifo FEED_PID="" STREAM_PID="" rc=0
  inst_raw="$(mktemp)"; inst_norm="$(mktemp)"; state_file="$(mktemp)"
  fifo="$(mktemp -u)"; mkfifo "$fifo"

  timeout -k 10s "$MAX_RUN_SEC" "${INST_SSH[@]}" <"$fifo" >"$inst_raw" 2>&1 & local INST_PID=$!

  (
    printf '\r\n'; printf 'terminal length 0\r\n'; printf 'terminal width 511\r\n'
    printf '%s\r\n' "$cmd"
    while [[ ! -s "$state_file" ]] && kill -0 "$INST_PID" 2>/dev/null; do sleep "$DRIP_GAP"; printf '\r\n'; done
  ) >"$fifo" 2>/dev/null & FEED_PID=$!

  (
    tail -n +1 -f "$inst_raw" 2>/dev/null \
      | stdbuf -o0 tr -d '\r' \
      | {
          seen_activate_finished=0; seen_commit_finished=0
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
                if (( ! seen_activate_finished )); then log "[${ip}] INSTALL: ACTIVATE finished"; seen_activate_finished=1; fi ;;
              *"finished commit"*)
                if (( ! seen_commit_finished )); then log "[${ip}] INSTALL: COMMIT finished (verifying…)"; seen_commit_finished=1; fi ;;
              *"success: install_add_activate_commit"*)
                log "[${ip}] INSTALL: SUCCESS (add/activate/commit)"; echo success > "$state_file"; break ;;
              *"failed:"*) log "[${ip}] INSTALL: FAILED — ${line#*FAILED: }"; echo failed > "$state_file"; break ;;
              *"cannot start new install operation, some operation is already running"*)
                log "[${ip}] INSTALL: BUSY — another install op is running (suggest reboot)"; echo busy > "$state_file"; break ;;
            esac
          done
        }
  ) & STREAM_PID=$!

  wait "$INST_PID" 2>/dev/null || rc=$?
  kill "$FEED_PID" 2>/dev/null || true
  kill "$STREAM_PID" 2>/dev/null || true
  rm -f "$fifo" 2>/dev/null || true
  wait "$FEED_PID" 2>/dev/null || true
  wait "$STREAM_PID" 2>/dev/null || true

  tr -d '\r' < "$inst_raw" > "$inst_norm"
  cat "$inst_norm" >> "$RUN_DIR/devlogs/${ip}.session.log"
  rm -f "$inst_raw"

  local state=""
  [[ -s "$state_file" ]] && state="$(cat "$state_file" 2>/dev/null || true)"
  rm -f "$state_file"

  if [[ "$state" == "success" ]]; then
    log "[${ip}] INSTALL: complete"; echo "$ip,${host},install,ok,success" >> "$ACTIONS_CSV"; rm -f "$inst_norm"; return 0
  fi
  if [[ "$state" == "failed" ]]; then
    log "[${ip}] INSTALL: failed (see devlogs)"; echo "$ip,${host},install,failed," >> "$ACTIONS_CSV"; mv -f "$inst_norm" "$RUN_DIR/${ip}.install.fail.out"; return 1
  fi
  if [[ "$state" == "busy" ]]; then
    log "[${ip}] INSTALL: busy/in-progress — recommend manual reboot, then re-run."
    echo "$ip,${host},install,skipped,busy" >> "$ACTIONS_CSV"
    mv -f "$inst_norm" "$RUN_DIR/${ip}.install.busy.out"; return 3
  fi

  build_ssh_arr "$ip"
  local sum_raw sum_norm
  sum_raw="$(mktemp)"; sum_norm="$(mktemp)"
  { printf '\r\n'; printf 'terminal length 0\r\n'; printf 'show install summary\r\n'; printf 'exit\r\n'
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

# ---------- main ----------
log "Run ID: $RUN_ID"
log "Run dir: $RUN_DIR"
log "User: ${SSH_USERNAME} (from env)"
log "Server TFTP: ${SERVER_IP}/hybrid"
log "Targets: ${TARGETS[*]}"

WORK_DONE=0
for ip in "${TARGETS[@]}"; do
  result="skipped"

  if precheck_for_ip "$ip"; then
    if backup_for_ip "$ip"; then
      clean_inactive_for_ip "$ip" || true

      if skip_if_same_version_for_ip "$ip"; then
        result="skipped(same_version)"
      else
        if http_fetch_image_for_ip "$ip"; then
          rc_install=0
          install_activate_image_for_ip "$ip" || rc_install=$?
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

  hn="$(cat "$RUN_DIR/host.$ip" 2>/dev/null || true)"
  mode="$(cat "$RUN_DIR/mode.$ip" 2>/dev/null || true)"
  confreg="$(cat "$RUN_DIR/confreg.$ip" 2>/dev/null || true)"
  precheck="$(cat "$RUN_DIR/precheck.$ip" 2>/dev/null || true)"
  echo "$ip,${hn},${mode},${confreg},${precheck},${result}" >> "$SUMMARY_CSV"

  WORK_DONE=$((WORK_DONE + 1))
  log "Progress: $WORK_DONE / $TOTAL"
done

log "Summary CSV: $SUMMARY_CSV"
exit 0
