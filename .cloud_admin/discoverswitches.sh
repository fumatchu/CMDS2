#!/usr/bin/env bash
# switch_discovery.sh
# Catalyst/Meraki discovery + processing plan with split-screen dialog UI + selection

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
    if grep -Eq '(^|\s)(export\s+)?(MERAKI_API_KEY|SSH_USERNAME)=' "$f"; then
      ENV_FILE="$f"
      break
    fi
  done
fi

[[ -n "${ENV_FILE:-}" ]] || { echo "No ENV found in $SCRIPT_DIR; pass path explicitly." >&2; exit 1; }
echo "Using ENV file: $ENV_FILE" >&2

set +H
# shellcheck disable=SC1090
source "$ENV_FILE"

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
MERAKI_API_KEY="$(__deq "${MERAKI_API_KEY:-}")"
DISCOVERY_IPS="$(__deq "${DISCOVERY_IPS:-}")"
DISCOVERY_NETWORKS="$(__deq "${DISCOVERY_NETWORKS:-}")"

# ===== Config / defaults =====
DISCOVERY_MODE="${DISCOVERY_MODE:-}"
DISCOVERY_IPS="${DISCOVERY_IPS:-}"
DISCOVERY_IPS_FILE="${DISCOVERY_IPS_FILE:-}"
DISCOVERY_NETWORKS="${DISCOVERY_NETWORKS:-}"
DISCOVERY_INTERFACE="${DISCOVERY_INTERFACE:-}"

SSH_USERNAME="${SSH_USERNAME:-admin}"
SSH_PASSWORD="${SSH_PASSWORD:-}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"
ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"

FW_CAT9K_FILES="${FW_CAT9K_FILES:-}"
FW_CAT9K_LITE_FILES="${FW_CAT9K_LITE_FILES:-}"
FW_CAT9K_FILE="${FW_CAT9K_FILE:-}"
FW_CAT9K_LITE_FILE="${FW_CAT9K_LITE_FILE:-}"

FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"
FIRMWARE_REPORT_JSON="${FIRMWARE_REPORT_JSON:-/root/.cloud_admin/runs/firmware_reports/latest/firmware_report.json}"

MAX_SSH_FANOUT="${MAX_SSH_FANOUT:-10}"
SSH_TIMEOUT="${SSH_TIMEOUT:-30}"
DEBUG="${DISCOVERY_DEBUG:-0}"
UI_MODE="${UI_MODE:-dialog}"

TFTP_BASE="${TFTP_BASE:-}"

# ===== backup config settings =====
BACKUP_DIR="${BACKUP_DIR:-/var/lib/tftpboot/mig}"
BACKUP_CONFIG_ON_DISCOVERY="${BACKUP_CONFIG_ON_DISCOVERY:-1}"  # 1 = take backup during discovery, 0 = disable

detect_server_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i!="127.0.0.1"){print $i; exit}}')"
  echo "$ip"
}

if [[ -z "$TFTP_BASE" ]]; then
  SERVER_IP="$(detect_server_ip)"
  if [[ -n "${SERVER_IP:-}" ]]; then
    TFTP_BASE="tftp://${SERVER_IP}/mig"
  fi
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need nmap; need jq; need awk; need sed
command -v sshpass >/dev/null 2>/dev/null || echo "NOTE: sshpass not found; password auth disabled unless SSH_KEY_PATH is set." >&2

OUT_DIR="$(dirname "$ENV_FILE")"
JSON_OUT="$OUT_DIR/discovery_results.json"
CSV_OUT="$OUT_DIR/discovery_results.csv"

UP_JSON_OUT="$OUT_DIR/upgrade_plan.json"
UP_CSV_OUT="$OUT_DIR/upgrade_plan.csv"

SEL_JSON_OUT="$OUT_DIR/selected_upgrade.json"
SEL_CSV_OUT="$OUT_DIR/selected_upgrade.csv"
SEL_ENV_OUT="$OUT_DIR/selected_upgrade.env"

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

log_msg() {
  printf '%s [%s] %s\n' "$(date '+%F %T')" "$RUN_TAG" "$*" >>"$DEV_LOG"
}

SSH_USERNAME="$(printf '%s' "${SSH_USERNAME:-}" | tr -d '\r')"
SSH_PASSWORD="$(printf '%s' "${SSH_PASSWORD:-}" | tr -d '\r')"
ENABLE_PASSWORD="$(printf '%s' "${ENABLE_PASSWORD:-}" | tr -d '\r')"

dbg() {
  [[ "$DEBUG" == "1" ]] || return 0
  echo "[debug] $*" >&2
  log_msg "[debug] $*"
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

# ===== helpers =====
clean_field() {
  local s
  s="$(printf '%s' "$1" | tr -d '\r\n')"
  s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//; s/[#]$//')"
  printf '%s' "$s"
}

extract_iosxe_ver_from_file() {
  local b="${1##*/}" v
  v="$(sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' <<<"$b" | head -n1)"
  [[ -n "$v" ]] || v="$(sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,4}).*/\1/p' <<<"$b" | head -n1)"
  printf '%s\n' "$v"
}

sanitize_ver() {
  local v="${1:-}"
  v="${v//[^0-9.]/}"
  sed -E 's/\.+/./g; s/^\.//; s/\.$//' <<<"$v"
}

vercmp() {
  local a b i len ai bi
  a="$(sanitize_ver "$1")"; b="$(sanitize_ver "$2")"
  IFS='.' read -r -a A <<<"${a:-0}"
  IFS='.' read -r -a B <<<"${b:-0}"
  (( len = ${#A[@]} > ${#B[@]} ? ${#A[@]} : ${#B[@]} ))
  for ((i=0;i<len;i++)); do
    ai="${A[i]:-0}"; bi="${B[i]:-0}"
    ((10#$ai < 10#$bi)) && { echo -1; return; }
    ((10#$ai > 10#$bi)) && { echo 1; return; }
  done
  echo 0
}

plan_action_label() {
  local cur="$(sanitize_ver "$1")" tgt="$(sanitize_ver "$2")"
  [[ -z "$cur" || -z "$tgt" ]] && { echo "UNKNOWN"; return; }
  case "$(vercmp "$cur" "$tgt")" in
    -1) echo "UPGRADE" ;;
     1) echo "DOWNGRADE" ;;
     0) echo "SAME" ;;
  esac
}

firmware_report_ok() { [[ -s "$FIRMWARE_REPORT_JSON" ]] && command -v jq >/dev/null 2>&1; }

report_req_for_ip() {
  local ip="$1"
  if ! firmware_report_ok; then
    printf '\t\t\t\tUNKNOWN\n'
    return 0
  fi
  jq -r --arg ip "$ip" '
    map(select(.ip==$ip)) | .[0] // {} |
    [
      (.required_image_train//""),
      (.required_min_iosxe//""),
      (.required_image_type//""),
      (.required_family//""),
      (.status//"UNKNOWN")
    ] | @tsv
  ' "$FIRMWARE_REPORT_JSON" 2>/dev/null | head -n1
}

_pick_best_meeting_min() {
  local min="$1"; shift
  local best_file="" best_ver="" f v
  for f in "$@"; do
    [[ -n "$f" ]] || continue
    v="$(extract_iosxe_ver_from_file "$f")"
    [[ -n "$v" ]] || continue
    if [[ "$(vercmp "$v" "$min")" -ge 0 ]]; then
      if [[ -z "$best_ver" || "$(vercmp "$v" "$best_ver")" -lt 0 ]]; then
        best_ver="$v"; best_file="$f"
      fi
    fi
  done
  printf '%s|%s\n' "$best_file" "$best_ver"
}

pick_target_for_ip() {
  local ip="$1"
  local train min type fam status
  IFS=$'\t' read -r train min type fam status <<<"$(report_req_for_ip "$ip")"
  train="${train:-}"; min="${min:-}"; status="${status:-UNKNOWN}"

  [[ -z "${FW_CAT9K_FILES:-}" ]] && [[ -n "${FW_CAT9K_FILE:-}" ]] && FW_CAT9K_FILES="$FW_CAT9K_FILE"
  [[ -z "${FW_CAT9K_LITE_FILES:-}" ]] && [[ -n "${FW_CAT9K_LITE_FILE:-}" ]] && FW_CAT9K_LITE_FILES="$FW_CAT9K_LITE_FILE"

  local best_file="" best_ver=""
  case "$train" in
    cat9k_iosxe)
      read -r -a arr <<<"${FW_CAT9K_FILES:-}"
      IFS='|' read -r best_file best_ver <<<"$(_pick_best_meeting_min "$min" "${arr[@]}")"
      ;;
    cat9k_lite_iosxe)
      read -r -a arr <<<"${FW_CAT9K_LITE_FILES:-}"
      IFS='|' read -r best_file best_ver <<<"$(_pick_best_meeting_min "$min" "${arr[@]}")"
      ;;
    *)
      best_file=""; best_ver=""
      ;;
  esac
  printf '%s|%s|%s|%s|%s\n' "$train" "$min" "$status" "$best_file" "$best_ver"
}

# ===== UI =====
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
  [[ -e "/proc/$$/fd/$PROG_FD" ]] && return 0
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

ui_gauge() {
  local p="$1"; shift || true; local m="${*:-Working…}"
  log_msg "GAUGE: ${p}%% - $m"
  if (( DIALOG_AVAILABLE )); then
    if _ui_fd_open; then
      { printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$PROG_FD"; } 2>/dev/null || true
    fi
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

# ===== Stack parsing (show switch) =====
parse_stack_info() {
  local file="$1"

  local base_mac="" is_stack="false" stack_members=1
  declare -A READY=()
  local line sw state state_upper

  base_mac="$(grep -m1 -E 'Switch/Stack Mac Address[[:space:]]*:' "$file" \
              | sed -E 's/.*Address[[:space:]]*:[[:space:]]*([0-9a-fA-F.]+).*/\1/')" || true
  base_mac="$(clean_field "${base_mac:-}")"

  local in_table=0
  while IFS= read -r line; do
    if (( ! in_table )); then
      [[ "$line" =~ ^Switch# ]] && { in_table=1; continue; }
      continue
    fi
    [[ -z "$line" ]] && break
    [[ "$line" =~ ^-+$ ]] && continue

    if [[ "$line" =~ ^[\*\ ]*([0-9]+)[[:space:]]+([A-Za-z]+)[[:space:]]+([0-9a-fA-F\.]+)[[:space:]]+([0-9]+)[[:space:]]+([A-Za-z0-9]+)[[:space:]]+([A-Za-z]+) ]]; then
      sw="${BASH_REMATCH[1]}"
      state="${BASH_REMATCH[6]}"
      state_upper="${state^^}"
      if [[ "$state_upper" == "READY" ]]; then
        READY["$sw"]=1
      fi
    fi
  done < "$file"

  if ((${#READY[@]} > 1)); then
    stack_members=${#READY[@]}
    is_stack="true"
  else
    stack_members=1
    is_stack="false"
  fi

  printf '%s\t%s\t%s\n' "${base_mac:-}" "$is_stack" "$stack_members"
}

# per-member MACs from "show switch" READY rows, ordered by switch# (1,2,3,…)
parse_stack_member_macs() {
  local file="$1"
  local line sw mac state state_upper
  local in_table=0
  declare -A MACS=()

  while IFS= read -r line; do
    if (( ! in_table )); then
      [[ "$line" =~ ^Switch# ]] && { in_table=1; continue; }
      continue
    fi
    [[ -z "$line" ]] && break
    [[ "$line" =~ ^-+$ ]] && continue

    if [[ "$line" =~ ^[\*\ ]*([0-9]+)[[:space:]]+([A-Za-z]+)[[:space:]]+([0-9a-fA-F\.]+)[[:space:]]+([0-9]+)[[:space:]]+([A-Za-z0-9]+)[[:space:]]+([A-Za-z]+) ]]; then
      sw="${BASH_REMATCH[1]}"
      mac="${BASH_REMATCH[3]}"
      state="${BASH_REMATCH[6]}"
      state_upper="${state^^}"
      if [[ "$state_upper" == "READY" ]]; then
        MACS["$sw"]="$(clean_field "$mac")"
      fi
    fi
  done < "$file"

  local k
  for k in $(printf '%s\n' "${!MACS[@]}" | sort -n); do
    [[ -n "${MACS[$k]}" ]] && printf '%s\n' "${MACS[$k]}"
  done
}

# ===== Motherboard serial parsing (show hardware) =====
parse_mb_serials() {
  local file="$1" line sn
  local -a mb=()
  while IFS= read -r line; do
    if [[ "$line" =~ Motherboard[[:space:]]+Serial[[:space:]]+Number[[:space:]]*:[[:space:]]*([^[:space:]]+) ]]; then
      sn="${BASH_REMATCH[1]}"
      mb+=("$sn")
    fi
  done < "$file"

  if ((${#mb[@]} > 0)); then
    printf '%s\n' "${mb[@]}" | awk '!seen[$0]++'
  fi
}

# ===== NEW: stack_detail.members[] from "show switch" =====
parse_stack_detail_members_json() {
  local file="$1"
  local line
  local in_table=0

  while IFS= read -r line; do
    if (( ! in_table )); then
      [[ "$line" =~ ^Switch# ]] && { in_table=1; continue; }
      continue
    fi
    [[ -z "$line" ]] && break
    [[ "$line" =~ ^-+$ ]] && continue

    if [[ "$line" =~ ^[\*\ ]*([0-9]+)[[:space:]]+([A-Za-z]+)[[:space:]]+([0-9a-fA-F\.]+)[[:space:]]+([0-9]+)[[:space:]]+([A-Za-z0-9]+)[[:space:]]+([A-Za-z]+) ]]; then
      local sw="${BASH_REMATCH[1]}"
      local role="${BASH_REMATCH[2]}"
      local mac="${BASH_REMATCH[3]}"
      local state="${BASH_REMATCH[6]}"
      local state_upper="${state^^}"

      [[ "$state_upper" == "READY" ]] || continue

      printf '%s|%s|%s|%s\n' \
        "$sw" "$(clean_field "$role")" "$(clean_field "$mac")" "$(clean_field "$state")"
    fi
  done < "$file" \
  | sort -t'|' -k1,1n \
  | jq -R -s '
      split("\n")
      | map(select(length>0))
      | map(split("|"))
      | map({
          member_index: (.[0] | tonumber),
          role: .[1],
          state: .[3],
          mac: .[2]
        })
    '
}

# ===== NEW: hw_detail.members{} from "show inventory" =====
parse_inventory_hw_detail_json() {
  local file="$1"

  awk '
    function ltrim(s){ sub(/^[ \t\r\n]+/, "", s); return s }
    function rtrim(s){ sub(/[ \t\r\n]+$/, "", s); return s }
    function trim(s){ return rtrim(ltrim(s)) }

    BEGIN{
      inblk=0; sw=0; name=""; pid=""; sn="";
    }

    /^NAME:[ \t]*"/{
      inblk=1;
      name=$0;
      sub(/^NAME:[ \t]*"/, "", name);
      sub(/".*$/, "", name);
      name=trim(name);
      pid=""; sn="";

      sw=0;
      if (match(name, /Switch[ \t]+([0-9]+)/, m)) sw=m[1]+0;
      next
    }

    inblk && /PID:[ \t]*/{
      pid=$0; sub(/.*PID:[ \t]*/, "", pid); sub(/,[ \t]*VID:.*$/, "", pid);
      pid=trim(pid);
      next
    }

    inblk && /SN:[ \t]*/{
      sn=$0; sub(/.*SN:[ \t]*/, "", sn);
      sn=trim(sn);
      next
    }

    inblk && /^$/{
      if (sw>0 && (pid!="" || sn!="")) {
        printf "%d|%s|%s|%s\n", sw, name, pid, sn;
      }
      inblk=0; sw=0; name=""; pid=""; sn="";
      next
    }

    END{
      if (inblk && sw>0 && (pid!="" || sn!="")) {
        printf "%d|%s|%s|%s\n", sw, name, pid, sn;
      }
    }
  ' "$file" \
  | jq -R -s '
      def is_nm($n):
        ($n|ascii_downcase) | (test("uplink") or test("network module") or test("nm") or test("module"));

      def is_chassis($n):
        ($n|ascii_downcase)
        | (test("chassis") or test("^switch[ ]+[0-9]+$"))
        and (test("power")|not) and (test("fan")|not) and (test("supply")|not);

      split("\n")
      | map(select(length>0))
      | map(split("|"))
      | map({
          sw: (.[0]|tonumber),
          name: .[1],
          pid: (.[2]//""),
          sn: (.[3]//"")
        })
      | reduce .[] as $r ({};
          .[$r.sw|tostring] |= (
            . // { chassis_pid:"", chassis_sn:"", nm_modules:[] }
            | if (is_chassis($r.name) and ($r.pid != "" or $r.sn != "")) then
                .chassis_pid = (if $r.pid != "" then $r.pid else .chassis_pid end)
              | .chassis_sn  = (if $r.sn  != "" then $r.sn  else .chassis_sn  end)
              else .
              end
            | if (is_nm($r.name) and ($r.pid != "" or $r.sn != "")) then
                .nm_modules += [{ name: $r.name, pid: $r.pid, sn: $r.sn }]
              else .
              end
          )
        )
    '
}

# ===== Discovery fallback records =====
emit_extra_json() {
  local hosts=("$@")
  for ip in "${hosts[@]}"; do
    if [[ -n "${TCP22[$ip]:-}" ]]; then
      printf '{"ip":"%s","ssh":true,"login":false,"hostname":"UNKNOWN","version":"UNKNOWN","pid":"UNKNOWN","serial":"","base_mac":"","is_stack":false,"stack_members":0,"stack_serials":[],"stack_macs":[],"backup_enabled":false,"backup_status":"SKIPPED","backup_url":"","backup_filename":"","backup_timestamp_utc":"","blacklisted":true,"blacklist_reason":"login failed","stack_detail":{"source":"","members":[]},"hw_detail":{"source":"","members":{}}}\n' "$ip"
    else
      printf '{"ip":"%s","ssh":false,"login":false,"hostname":"UNKNOWN","version":"UNKNOWN","pid":"UNKNOWN","serial":"","base_mac":"","is_stack":false,"stack_members":0,"stack_serials":[],"stack_macs":[],"backup_enabled":false,"backup_status":"SKIPPED","backup_url":"","backup_filename":"","backup_timestamp_utc":"","blacklisted":true,"blacklist_reason":"ssh closed or unreachable","stack_detail":{"source":"","members":[]},"hw_detail":{"source":"","members":{}}}\n' "$ip"
    fi
  done | jq -s '.'
}

# ===== SSH probe =====
probe_host() {
  local ip="$1" log="$PROBE_LOG_DIR/$ip.log"
  : > "$log"
  ui_status "[${ip}] Probing via SSH…"

  local backup_enabled="false" backup_status="SKIPPED" backup_url="" backup_filename="" backup_timestamp_utc=""
  local base_mac="" is_stack="false" stack_members=1 stack_serials_json="[]" stack_macs_json="[]"

  # Always present (schema-consistent)
  local stack_detail_json hw_detail_json
  stack_detail_json='{"source":"","members":[]}'
  hw_detail_json='{"source":"","members":{}}'

  local -a SSH_CMD
  if [[ -n "$SSH_KEY_PATH" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD=(ssh -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=1
      -o PreferredAuthentications=publickey,password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=yes
      -o NumberOfPasswordPrompts=1 -i "$SSH_KEY_PATH" -tt "$SSH_USERNAME@$ip")
  else
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" ssh -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=1
      -o PreferredAuthentications=password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1 -tt "$SSH_USERNAME@$ip")
  fi

  _run_ssh() {
    local timeout_secs="$1"; shift || true
    if command -v timeout >/dev/null 2>&1; then
      timeout -k 5s "${timeout_secs}s" "${SSH_CMD[@]}"
    else
      "${SSH_CMD[@]}"
    fi
  }

  local facts outn
  facts="$(mktemp)"; outn="$(mktemp)"

  {
    printf '\r\n\r\n'
    printf 'terminal length 0\r\n'
    printf 'terminal width 511\r\n'
    printf 'show clock\r\n'
    printf 'show version\r\n'
    printf 'show running-config | include ^hostname\r\n'
    printf 'show running-config | include ^username\r\n'
    printf 'show inventory\r\n'
    printf 'show switch\r\n'
    printf 'show hardware\r\n'
    printf 'exit\r\n'
  } | _run_ssh "${SSH_TIMEOUT:-30}" >"$facts" 2>&1

  tr -d '\r' < "$facts" | tee -a "$log" > "$outn"

  local login_ok=0
  if grep -Eq 'Cisco IOS|IOS XE| uptime is |^[A-Za-z0-9_.:/-]+[>#][[:space:]]*$|Current privilege level is' "$outn"; then
    login_ok=1
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
  sn="$(grep -m1 -E 'System Serial Number[[:space:]]*:[[:space:]]*([^[:space:]]+)' "$outn" | sed -E 's/.*System Serial Number[[:space:]]*:[[:space:]]*([^[:space:]]+).*/\1/')" || true
  pid="$(clean_field "${pid:-}")"
  sn="$(clean_field "${sn:-}")"

  # Stack + base-mac from show switch (source of truth)
  local is_stack_flag="false" stack_members_val="1"
  IFS=$'\t' read -r base_mac is_stack_flag stack_members_val < <(parse_stack_info "$outn")
  [[ -z "$base_mac" ]] && base_mac=""

  # Motherboard serials from show hardware
  local -a mb_arr=()
  while IFS= read -r line; do
    mb_arr+=("$line")
  done < <(parse_mb_serials "$outn" || true)

  # Per-member MACs from show switch
  local -a mac_arr=()
  while IFS= read -r line; do
    mac_arr+=("$line")
  done < <(parse_stack_member_macs "$outn" || true)

  # Decide stack vs single based on show switch ONLY
  if [[ "$is_stack_flag" == "true" && "$stack_members_val" -gt 1 ]]; then
    is_stack="true"
    stack_members="$stack_members_val"

    if ((${#mb_arr[@]} > 0)); then
      local -a uniq=()
      local s
      declare -A seen_serial=()
      for s in "${mb_arr[@]}"; do
        [[ -z "$s" ]] && continue
        [[ -n "${seen_serial[$s]:-}" ]] && continue
        seen_serial["$s"]=1
        uniq+=("$s")
      done
      local -a limited=()
      local i
      for ((i=0; i<stack_members && i<${#uniq[@]}; i++)); do
        limited+=("${uniq[i]}")
      done
      if ((${#limited[@]} > 0)); then
        stack_serials_json="$(printf '%s\n' "${limited[@]}" | jq -R . | jq -s '.')"
      else
        stack_serials_json='[]'
      fi
    else
      stack_serials_json='[]'
    fi

    if ((${#mac_arr[@]} > 0)); then
      local -a mac_limited=()
      local i
      for ((i=0; i<stack_members && i<${#mac_arr[@]}; i++)); do
        [[ -n "${mac_arr[i]}" ]] && mac_limited+=("${mac_arr[i]}")
      done
      if ((${#mac_limited[@]} > 0)); then
        stack_macs_json="$(printf '%s\n' "${mac_limited[@]}" | jq -R . | jq -s '.')"
      else
        stack_macs_json='[]'
      fi
    else
      stack_macs_json='[]'
    fi
  else
    is_stack="false"
    stack_members=1

    local first_serial=""
    if ((${#mb_arr[@]} > 0)); then
      first_serial="${mb_arr[0]}"
    else
      first_serial="$sn"
    fi
    if [[ -n "$first_serial" ]]; then
      stack_serials_json="$(printf '%s\n' "$first_serial" | jq -R . | jq -s '.')"
    else
      stack_serials_json='[]'
    fi

    local first_mac=""
    if ((${#mac_arr[@]} > 0)); then
      first_mac="${mac_arr[0]}"
    else
      first_mac="$base_mac"
    fi
    if [[ -n "$first_mac" ]]; then
      stack_macs_json="$(printf '%s\n' "$first_mac" | jq -R . | jq -s '.')"
    else
      stack_macs_json='[]'
    fi
  fi

  # Only build detail objects when login succeeded
  if (( login_ok )); then
    local stack_members_detail='[]' inv_hw_members='{}'
    stack_members_detail="$(parse_stack_detail_members_json "$outn" 2>/dev/null || echo '[]')"
    inv_hw_members="$(parse_inventory_hw_detail_json "$outn" 2>/dev/null || echo '{}')"

    stack_detail_json="$(jq -n --arg src "show switch" --argjson members "$stack_members_detail" '{source:$src, members:$members}')"
    hw_detail_json="$(jq -n --arg src "show inventory" --argjson members "$inv_hw_members" '{source:$src, members:$members}')"
  fi

  local bl_flag="false" bl_reason=""
  if grep -Eq '^username[[:space:]]+meraki-user\b' "$outn"; then
    bl_flag="true"; bl_reason="meraki-user exists"
  fi

  # Backup running-config to TFTP
  if (( login_ok )) && [[ "$BACKUP_CONFIG_ON_DISCOVERY" == "1" ]] && [[ -n "$TFTP_BASE" ]]; then
    mkdir -p "$BACKUP_DIR"

    local ts h_safe
    ts="$(date -u +%Y%m%d-%H%M)"
    h_safe="${hostname:-$ip}"
    h_safe="$(echo "$h_safe" | tr '[:space:]' '_' | tr -cd 'A-Za-z0-9_.-')"

    backup_filename="${h_safe}-${ts}.cfg"
    backup_timestamp_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    {
      printf '\r\n'
      printf 'copy running-config %s/%s\r\n' "$TFTP_BASE" "$backup_filename"
      printf '\r\n'
      printf '\r\n'
      printf 'exit\r\n'
    } | _run_ssh "${SSH_TIMEOUT:-60}" >>"$log" 2>&1 || true

    if [[ -f "$BACKUP_DIR/$backup_filename" ]]; then
      backup_enabled="true"
      backup_status="OK"
      backup_url="${TFTP_BASE}/${backup_filename}"
      ui_status "[${ip}] Backup OK → ${backup_filename}"
    else
      backup_enabled="true"
      backup_status="FAILED"
      backup_url="${TFTP_BASE}/${backup_filename}"
      ui_status "[${ip}] Backup FAILED → ${backup_filename} (file not found in $BACKUP_DIR)"
    fi
  fi

  rm -f "$facts" "$outn"

  if (( login_ok )); then
    if [[ -n "${pid:-}" ]]; then
      case "$pid" in
        C9200*|C9300*|C9400*|C9500*|C9600*) : ;;
        *) bl_flag="true"; bl_reason="unsupported PID (${pid})" ;;
      esac
    else
      bl_flag="true"; bl_reason="unknown PID (parse failed)"
    fi

    jq -n \
      --arg ip "$ip" \
      --arg host "${hostname:-}" \
      --arg ver "${version:-}" \
      --arg pid "${pid:-}" \
      --arg sn "${sn:-}" \
      --arg base_mac "${base_mac:-}" \
      --arg backup_enabled "${backup_enabled:-false}" \
      --arg backup_status "${backup_status:-SKIPPED}" \
      --arg backup_url "${backup_url:-}" \
      --arg backup_filename "${backup_filename:-}" \
      --arg backup_ts "${backup_timestamp_utc:-}" \
      --arg bl "$bl_flag" \
      --arg blr "$bl_reason" \
      --arg is_stack "${is_stack:-false}" \
      --arg stack_members_str "${stack_members:-1}" \
      --argjson stack_serials "$stack_serials_json" \
      --argjson stack_macs "$stack_macs_json" \
      --argjson stack_detail "$stack_detail_json" \
      --argjson hw_detail "$hw_detail_json" \
      '{
         ip: $ip,
         ssh: true,
         login: true,
         hostname: $host,
         version: $ver,
         pid: $pid,
         serial: $sn,
         base_mac: $base_mac,
         is_stack: ($is_stack=="true"),
         stack_members: ($stack_members_str|tonumber? // 1),
         stack_serials: $stack_serials,
         stack_macs: $stack_macs,
         stack_detail: $stack_detail,
         hw_detail: $hw_detail,
         backup_enabled: ($backup_enabled=="true"),
         backup_status: $backup_status,
         backup_url: $backup_url,
         backup_filename: $backup_filename,
         backup_timestamp_utc: $backup_ts,
         blacklisted: ($bl=="true"),
         blacklist_reason: $blr
       }'
  else
    jq -n \
      --arg ip "$ip" \
      '{
         ip: $ip,
         ssh: true,
         login: false,
         hostname: "UNKNOWN",
         version: "UNKNOWN",
         pid: "UNKNOWN",
         serial: "",
         base_mac: "",
         is_stack: false,
         stack_members: 0,
         stack_serials: [],
         stack_macs: [],
         stack_detail: { source: "", members: [] },
         hw_detail: { source: "", members: {} },
         backup_enabled: false,
         backup_status: "SKIPPED",
         backup_url: "",
         backup_filename: "",
         backup_timestamp_utc: "",
         blacklisted: true,
         blacklist_reason: "login failed"
       }'
  fi
}

# ===== Target resolution + discovery =====
resolve_targets() {
  local mode="${DISCOVERY_MODE,,}" targets=()
  case "$mode" in
    list|iplist|hosts) mapfile -t targets < <(read_ip_list) ;;
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
    sleep 5; ((elapsed+=5))
  done
  wait "$scan_pid" 2>/dev/null || true

  while read -r ip; do
    [[ -z "$ip" ]] && continue
    ui_status "Discovered live host: $ip"
    printf '%s\n' "$ip"
  done < "$tmp"
  rm -f "$tmp"
}

pass_a() { local probes=(-PE -PS22,80,443,830 -PA22,443); (( USE_IFACE )) && probes+=(-PR); run_nmap_with_heartbeat "Discovering live hosts (pass 1/3)" "${probes[@]}"; }
pass_b() { run_nmap_with_heartbeat "Discovering live hosts (ICMP-only)" -PE; }
pass_c() { run_nmap_with_heartbeat "Discovering live hosts (TCP ping)" -Pn -PS22,80,443; }

pass_fping() {
  command -v fping >/dev/null 2>/dev/null || return 0
  local out=()
  for t in "${TARGETS[@]}"; do
    if [[ "$t" =~ / ]]; then
      mapfile -t out < <(fping -a -q -g "$t" 2>/dev/null || true)
    else
      mapfile -t out < <(printf '%s\n' "$t" | fping -a -q 2>/dev/null || true)
    fi
  done
  printf '%s\n' "${out[@]}" | awk 'NF' | while read -r ip; do
    [[ -z "$ip" ]] && continue
    ui_status "Discovered live host (fping): $ip"
    printf '%s\n' "$ip"
  done || true
}

discover_targets() {
  ui_status "Discovering live hosts (pass 1/3)…"; ui_gauge 5 "Scanning (hybrid)…"
  local live=(); mapfile -t live < <(pass_a)
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying ICMP only…"; ui_gauge 10 "Scanning (ICMP)…"; mapfile -t live < <(pass_b); fi
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying TCP-only ping…"; ui_gauge 15 "Scanning (TCP)…"; mapfile -t live < <(pass_c); fi
  if [[ ${#live[@]} -eq 0 ]]; then ui_status "Trying fping fallback…"; mapfile -t live < <(pass_fping); fi
  printf '%s\n' "${live[@]}" | awk -F. '!(NF==4 && ($4==0 || $4==255))' | sort -u
}

filter_ssh_open() {
  local ips=("$@")
  [[ ${#ips[@]} -eq 0 ]] && return 0
  ui_status "Checking TCP/22 on ${#ips[@]} host(s)…"; ui_gauge 25 "Checking SSH ports…"
  local cmd=(nmap $(nmap_cmd_base) -Pn --open -p22 --max-retries 2 "${ips[@]}")
  "${cmd[@]}" -oG - 2>/dev/null | awk '/Ports: 22\/open/{print $2}' || true
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
      ((done++)); ui_gauge $(( 25 + 60 * done / total )) "Probing devices… ($done / $total)"
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
    ((done++)); ui_gauge $(( 25 + 60 * done / total )) "Probing devices… ($done / $total)"
    ((running--))
  done
}

# ===== Processing plan =====
make_upgrade_plan() {
  local json="$JSON_OUT"
  if [[ ! -s "$json" ]]; then
    echo "[]" > "$UP_JSON_OUT"
    return 0
  fi

  local US=$'\x1f'

  while IFS=$US read -r ip pid cur_ver host blacklisted bl_reason ssh login; do
    ip="${ip:-}"; pid="${pid:-}"; cur_ver="${cur_ver:-}"; host="${host:-}"
    blacklisted="${blacklisted:-false}"; bl_reason="${bl_reason:-}"
    ssh="${ssh:-false}"; login="${login:-false}"

    local req_train req_min rep_status tgt_file tgt_ver
    IFS='|' read -r req_train req_min rep_status tgt_file tgt_ver <<<"$(pick_target_for_ip "$ip")"

    local tgt_path tgt_size
    tgt_path=""; tgt_size=""
    if [[ -n "$tgt_file" ]]; then
      tgt_path="${FIRMWARE_DIR%/}/${tgt_file}"
      [[ -f "$tgt_path" ]] && tgt_size="$(stat -c %s "$tgt_path" 2>/dev/null || true)"
    fi

    local action="UNKNOWN"
    if [[ -n "$tgt_ver" && -n "$cur_ver" ]]; then
      action="$(plan_action_label "$cur_ver" "$tgt_ver")"
    fi

    local need="false"
    if [[ -n "$req_min" && -n "$cur_ver" ]]; then
      [[ "$(vercmp "$(sanitize_ver "$cur_ver")" "$(sanitize_ver "$req_min")")" -lt 0 ]] && need="true"
    fi

    jq -n \
      --arg ip "$ip" \
      --arg hostname "${host:-}" \
      --arg pid "$pid" \
      --arg current_version "${cur_ver:-}" \
      --arg req_train "${req_train:-}" \
      --arg req_min "${req_min:-}" \
      --arg rep_status "${rep_status:-UNKNOWN}" \
      --arg target_version "${tgt_ver:-}" \
      --arg target_file "${tgt_file:-}" \
      --arg target_path "${tgt_path:-}" \
      --arg target_size "${tgt_size:-}" \
      --arg action "$action" \
      --arg needs "$need" \
      --arg bl "$blacklisted" \
      --arg blr "$bl_reason" \
      --arg ssh "$ssh" \
      --arg login "$login" \
      '{
         ip: $ip,
         hostname: $hostname,
         pid: $pid,
         current_version: $current_version,
         required_image_train: $req_train,
         required_min_iosxe: $req_min,
         firmware_report_status: $rep_status,
         target_version: $target_version,
         target_file: $target_file,
         target_path: $target_path,
         target_size_bytes: ($target_size|tonumber?),
         plan_action: $action,
         needs_upgrade: ($needs=="true"),
         blacklisted: ($bl=="true"),
         blacklist_reason: $blr,
         ssh: ($ssh=="true"),
         login: ($login=="true")
       }'
  done < <(
    jq -r --arg us "$US" '
      .[] |
      [
        (.ip|tostring),
        (.pid//""),
        (.version//""),
        (.hostname//""),
        ((.blacklisted//false)|tostring),
        (.blacklist_reason//""),
        ((.ssh//false)|tostring),
        ((.login//false)|tostring)
      ] | join($us)
    ' "$json"
  ) | jq -s '.' > "$UP_JSON_OUT"
}

# ===== Selection =====
do_selection_dialog() {
  local disc="$JSON_OUT"
  [[ -s "$disc" ]] || { dialog --no-shadow --infobox "No discovery results to select from." 6 60; sleep 2; return 1; }

  local plan="$UP_JSON_OUT"
  [[ -s "$plan" ]] || echo "[]" > "$plan"

  local US=$'\x1f'

  local -a items=()
  declare -A BLKMAP=()

  while IFS=$US read -r ip host pid cur tgt action req_train req_min rep_status blacklisted bl_reason ssh login; do
    ip="${ip:-}"; [[ -n "$ip" ]] || continue

    host="${host:-UNKNOWN}"
    pid="${pid:-UNKNOWN}"
    cur="${cur:-UNKNOWN}"
    tgt="${tgt:-UNKNOWN}"
    action="${action:-UNKNOWN}"
    rep_status="${rep_status:-UNKNOWN}"
    blacklisted="${blacklisted:-false}"
    bl_reason="${bl_reason:-}"

    local req_bits=""
    [[ -n "$req_train" || -n "$req_min" ]] && req_bits=" req:${req_train:-?}>=${req_min:-?} (${rep_status})"

    local text="${host} (${ip})  ${pid}  ${cur} -> ${tgt} (${action})${req_bits}"

    local def="on"
    if [[ "$blacklisted" == "true" ]]; then
      def="off"
      [[ -z "$bl_reason" ]] && bl_reason="blacklisted"
      text="$text  [BLACKLISTED: ${bl_reason}]"
      BLKMAP["$ip"]="$bl_reason"
    fi

    items+=("$ip" "$text" "$def")
  done < <(
    jq -r --arg us "$US" --slurpfile plan "$plan" '
      def idx_by_ip(a):
        reduce a[] as $x ({}; .[$x.ip] = $x);

      ($plan[0] // []) as $p
      | idx_by_ip($p) as $M
      | .[] as $d
      | ($M[$d.ip] // {}) as $u
      | [
          ($d.ip|tostring),
          ($d.hostname // "UNKNOWN"),
          ($d.pid // "UNKNOWN"),
          ($d.version // "UNKNOWN"),
          ($u.target_version // "UNKNOWN"),
          ($u.plan_action // "UNKNOWN"),
          ($u.required_image_train // ""),
          ($u.required_min_iosxe // ""),
          ($u.firmware_report_status // "UNKNOWN"),
          ((($d.blacklisted // false) or ($u.blacklisted // false)) | tostring),
          (
            if ($d.blacklist_reason // "") != "" then $d.blacklist_reason
            elif ($u.blacklist_reason // "") != "" then $u.blacklist_reason
            else "" end
          ),
          (($d.ssh // false) | tostring),
          (($d.login // false) | tostring)
        ] | join($us)
    ' "$disc"
  )

  if (( ${#items[@]} == 0 )); then
    dialog --no-shadow --infobox "No devices available for selection." 6 60
    sleep 2
    return 1
  fi

  ui_stop
  local tmp_sel; tmp_sel="$(mktemp)"
  dialog --no-shadow --title "Select switches to process" \
         --backtitle "Discovery Selection" \
         --checklist "Use <SPACE> to toggle. BLACKLISTED entries are shown for visibility but cannot be selected (ignored even if checked)." \
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
  for ip in "${SEL_ARR[@]}"; do
    [[ -z "$ip" ]] && continue
    [[ -n "${BLKMAP[$ip]:-}" ]] && continue
    FILTERED_SEL+=("$ip")
  done

  if (( ${#FILTERED_SEL[@]} == 0 )); then
    dialog --no-shadow --infobox \
"All selected devices are BLACKLISTED.
(meraki-user exists, login failed, ssh closed/unreachable, unsupported PID, etc.)" 9 90
    sleep 3
    return 3
  fi

  local ips_json
  ips_json="$(printf '%s\n' "${FILTERED_SEL[@]}" | jq -R -s 'split("\n")|map(select(length>0))')"
  jq --argjson ips "$ips_json" '[ .[] | select( (.ip|tostring) as $x | $ips | index($x) ) ]' "$UP_JSON_OUT" > "$SEL_JSON_OUT"

  {
    echo "# Generated $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    printf "export UPGRADE_BASE_ENV=%q\n" "$ENV_FILE"
    printf "export UPGRADE_SELECTED_IPS=%q\n" "${FILTERED_SEL[*]}"
    printf "export UPGRADE_SELECTED_JSON=%q\n" "$SEL_JSON_OUT"
  } > "$SEL_ENV_OUT"

  dialog --no-shadow --infobox \
"Selection saved.

BLACKLISTED entries were ignored." 7 70
  sleep 2
  return 0
}

# ===== Main =====
main() {
  ui_start; ui_gauge 1 "Initializing…"

  resolve_targets || { jq -n '[]' > "$JSON_OUT"; return 0; }

  mapfile -t live < <(discover_targets)
  [[ ${#live[@]} -gt 0 ]] || { jq -n '[]' > "$JSON_OUT"; return 0; }

  SSH_TMP="$(mktemp)"
  filter_ssh_open "${live[@]}" >"$SSH_TMP" 2>/dev/null || true
  ssh_hosts=()
  [[ -s "$SSH_TMP" ]] && mapfile -t ssh_hosts < "$SSH_TMP" 2>/dev/null || true
  rm -f "$SSH_TMP"

  declare -A TCP22
  for ip in "${ssh_hosts[@]}"; do TCP22["$ip"]=1; done

  if [[ ${#ssh_hosts[@]} -eq 0 ]]; then
    emit_extra_json "${live[@]}" > "$JSON_OUT"
  else
    TMPJSON="$(mktemp)"; : > "$TMPJSON"
    run_probe_pool "${ssh_hosts[@]}"

    mapfile -t probed_ips < <(jq -r '.[].ip' <(jq -s '.' "$TMPJSON")) || probed_ips=()
    declare -A seen; for ip in "${probed_ips[@]}"; do seen["$ip"]=1; done
    extra=(); for ip in "${live[@]}"; do [[ -n "${seen[$ip]:-}" ]] || extra+=("$ip"); done

    if [[ ${#extra[@]} -gt 0 ]]; then
      EXTRA_JSON="$(emit_extra_json "${extra[@]}")"
      jq -s '.[0] + .[1]' <(jq -s '.' "$TMPJSON") <(printf '%s' "$EXTRA_JSON") > "$JSON_OUT"
    else
      jq -s '.' "$TMPJSON" > "$JSON_OUT"
    fi
    rm -f "$TMPJSON"
  fi

  printf "ip,ssh,login,hostname,version,pid,serial\n" > "$CSV_OUT"
  jq -r '.[] | [.ip, .ssh, .login, (.hostname//""), (.version//""), (.pid//""), (.serial//"")] | @csv' "$JSON_OUT" >> "$CSV_OUT"

  make_upgrade_plan

  if (( DIALOG_AVAILABLE )); then
    do_selection_dialog || true
  else
    echo "Selection UI skipped (dialog not available)."
  fi

  local failed_list
  failed_list="$(jq -r '.[] | select(.backup_enabled==true and .backup_status=="FAILED") | "\(.hostname // "UNKNOWN") (\(.ip)) -> \(.backup_filename // "N/A")"' "$JSON_OUT")"

  if [[ -n "$failed_list" ]]; then
    if (( DIALOG_AVAILABLE )); then
      local msg
      msg=$'The following devices had backup failures:\n\n'"$failed_list"$'\n\nCheck logs in:\n'"$DEVLOG_DIR"
      dialog --no-shadow --title "Backup failures" --msgbox "$msg" 20 100
    else
      echo "Backup failures detected:"
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        echo "[backup-failed] $line"
      done <<< "$failed_list"
      echo "Check logs in: $DEVLOG_DIR"
    fi
  fi

  ui_gauge 100 "Done."
}

main "$@"