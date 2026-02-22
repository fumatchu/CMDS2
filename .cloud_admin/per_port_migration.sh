#!/usr/bin/env bash
# ============================================================
# Cloud Migration – IOS Port Intent → Meraki Switch Ports
# Single-file, corrected + cleaned
#
# Key change in this revision (YOUR REQUEST):
#   - Cisco serials are NOT used at all.
#   - We ONLY use cloud_id everywhere.
#   - Wherever Meraki API requires "serial", we supply cloud_id.
#
# Notes:
#   - We identify Meraki switches ONLY by cloud_id (Q5TD-xxxx-xxxx).
#   - Meraki API paths still call it {serial}, but we always supply cloud_id.
# ============================================================

set -Euo pipefail
exec 2> >(tee -a "/tmp/cloud_admin_port_mig.stderr.log" >&2)

: "${DIALOG:=dialog}"

# ------------------------------------------------------------
# dialog helpers
# ------------------------------------------------------------
DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi

dlg() {
  local common=(--clear --ok-label "Continue" --cancel-label "Back")

  if [[ $DIALOG_HAS_STDOUT -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --stdout "$@"
  else
    local out
    out="$(mktemp)"
    if "$DIALOG" "${common[@]}" "$@" 2>"$out"; then
      cat "$out"
      rm -f "$out"
      return 0
    else
      rm -f "$out"
      return 1
    fi
  fi
}

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; return 1; }; }

# ============================================================
# Paths / globals
# ============================================================

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

CLOUD_ADMIN_BASE="${CLOUD_ADMIN_BASE:-/root/.cloud_admin}"
MERAKI_MEMORY_DIR="${MERAKI_MEMORY_DIR:-${CLOUD_ADMIN_BASE}/meraki_memory}"

DISCOVERY_RESULTS_FILE="${DISCOVERY_RESULTS_FILE:-${CLOUD_ADMIN_BASE}/discovery_results.json}"
BACKUP_LOCAL_BASE_DIR="${BACKUP_LOCAL_BASE_DIR:-/var/lib/tftpboot/mig}"

BACKTITLE_PORTS="Cloud Migration – IOS port profiles → Meraki"

MERAKI_ENV_FILE="${MERAKI_ENV_FILE:-${CLOUD_ADMIN_BASE}/meraki_discovery.env}"

# Uplink type memory created by discovery (per-switch JSON)
UPLINK_TYPES_DIR="${UPLINK_TYPES_DIR:-${CLOUD_ADMIN_BASE}/uplink_types}"
mkdir -p "$UPLINK_TYPES_DIR" 2>/dev/null || true

# ============================================================
# UI: stack diff viewer (member menu + all-members view)
# ============================================================

: "${STACK_MAX_MEMBERS:=8}"

dlg_textbox() {
  local title="$1" file="$2"
  "$DIALOG" --backtitle "$BACKTITLE_PORTS" \
            --title "$title" \
            --scrollbar \
            --textbox "$file" 0 0
}

build_all_members_view() {
  local ip="$1" base="$2" outdir="$3"
  local tmp; tmp="$(mktemp)"

  local n
  for n in $(seq 1 "$STACK_MAX_MEMBERS"); do
    local f="${outdir}/${ip}_${base}_m${n}_ports_diff.txt"
    [[ -f "$f" ]] || continue
    {
      echo "================================================================================"
      echo "STACK MEMBER ${n}"
      echo "FILE: ${f}"
      echo "================================================================================"
      cat "$f"
      echo
      echo
    } >>"$tmp"
  done

  echo "$tmp"
}

search_in_file_dialog() {
  local file="$1"
  local term
  term="$(dlg --backtitle "$BACKTITLE_PORTS" \
             --title "Search" \
             --inputbox "Search term (case-insensitive):" 8 70)" || return 0
  term="$(trim "$term")"
  [[ -n "$term" ]] || return 0

  local tmp; tmp="$(mktemp)"
  grep -ni -C 2 -- "$term" "$file" >"$tmp" 2>/dev/null || echo "No matches for: $term" >"$tmp"
  dlg_textbox "Search results: $term" "$tmp"
  rm -f "$tmp"
}

show_stack_diffs_menu() {
  local ip="$1" base="$2" outdir="$3"

  local -a items=()
  local n found_any=0

  for n in $(seq 1 "$STACK_MAX_MEMBERS"); do
    local f="${outdir}/${ip}_${base}_m${n}_ports_diff.txt"
    if [[ -f "$f" ]]; then
      found_any=1
      items+=("$n" "Member $n")
    fi
  done

  if [[ $found_any -eq 0 ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No stack diffs found" \
        --msgbox "No member diff files found for:\n\n  ${ip}_${base}\n\nin:\n  $outdir" 12 80
    return 0
  fi

  items+=("A" "All members (combined)")
  items+=("S" "Search (combined view)")
  items+=("X" "Exit")

  while true; do
    local choice
    choice="$(
      dlg --backtitle "$BACKTITLE_PORTS" \
          --title "Stack diffs built" \
          --menu "Select what to view for $ip:" 16 80 10 \
          "${items[@]}"
    )" || return 0

    case "$choice" in
      A)
        local allfile
        allfile="$(build_all_members_view "$ip" "$base" "$outdir")"
        dlg_textbox "All members: $ip" "$allfile"
        rm -f "$allfile"
        ;;
      S)
        local allfile
        allfile="$(build_all_members_view "$ip" "$base" "$outdir")"
        search_in_file_dialog "$allfile"
        rm -f "$allfile"
        ;;
      X) return 0 ;;
      *)
        local f="${outdir}/${ip}_${base}_m${choice}_ports_diff.txt"
        dlg_textbox "Member ${choice}: $ip" "$f"
        ;;
    esac
  done
}

get_discovery_hostname_for_ip() {
  local ip="$1"
  need jq || return 1
  [[ -f "$DISCOVERY_RESULTS_FILE" ]] || return 1

  jq -r --arg ip "$ip" '
    (if type=="array" then .
     elif has("results") then .results
     else [.]
     end)
    | map(select(.ip == $ip)) | .[0]
    | (.hostname // empty)
  ' "$DISCOVERY_RESULTS_FILE" 2>/dev/null | awk 'NF {print; exit}'
}

# ------------------------------------------------------------
# Stack naming helpers
# ------------------------------------------------------------
sanitize_stack_name() {
  # Meraki allows pretty normal names, but keep it clean/safe.
  # - remove weird chars
  # - collapse spaces
  # - trim
  local s="${1-}"
  s="$(sed -e 's/[^A-Za-z0-9._ -]/-/g' -e 's/[[:space:]]\+/ /g' -e 's/^ *//' -e 's/ *$//' <<<"$s")"
  # avoid empty
  [[ -n "$s" ]] || s="AutoStack"
  printf '%s' "$s"
}

build_stack_name_for_ip() {
  local ip="$1"
  local host=""
  host="$(get_discovery_hostname_for_ip "$ip" 2>/dev/null || true)"
  host="$(trim "$host")"

  if [[ -n "$host" ]]; then
    host="$(sanitize_stack_name "$host")"
    # If hostname already ends with "-Stack" (case-insensitive), don't double-append
    if [[ "$host" =~ -[Ss][Tt][Aa][Cc][Kk]$ ]]; then
      printf '%s\n' "$host"
    else
      printf '%s\n' "${host}-Stack"
    fi
  else
    printf '%s\n' "AutoStack-${ip}"
  fi
}

# ============================================================
# UI helpers: SINGLE dialog gauge (no concurrent tailboxbg)
# ============================================================

UI_ACTIVE=0
UI_LOG=""
UI_LAST_MSG=""
UI_LAST_PCT=0
UI_GAUGE_PID=""
UI_FIFO=""
UI_STTY=""

UI_GAUGE_W=120
UI_GAUGE_H=14
UI_IDENT_LINE=""

_ui_term_size() {
  local r c
  if read -r r c < <(stty size </dev/tty 2>/dev/null); then
    :
  else
    r="$(tput lines 2>/dev/null || true)"
    c="$(tput cols  2>/dev/null || true)"
  fi

  [[ "$r" =~ ^[0-9]+$ ]] || r=30
  [[ "$c" =~ ^[0-9]+$ ]] || c=120
  (( r < 20 )) && r=20
  (( c < 80 )) && c=80
  printf '%s %s\n' "$r" "$c"
}

_ui_tail_lines() {
  local n="${1:-3}"
  [[ -n "${UI_LOG:-}" && -f "${UI_LOG:-}" ]] || return 0
  tail -n "$n" "$UI_LOG" 2>/dev/null | sed -e 's/\r$//' -e $'s/\t/  /g'
}

_ui_fit_line() {
  local w="$1"; shift
  local s="$*"
  local max=$(( w - 4 ))
  (( max < 20 )) && max=20
  if (( ${#s} > max )); then
    printf '%s…' "${s:0:max-1}"
  else
    printf '%s' "$s"
  fi
}

_ui_gauge_alive() {
  [[ -n "${UI_GAUGE_PID:-}" ]] || return 1
  kill -0 "$UI_GAUGE_PID" 2>/dev/null
}

ui_start() {
  local title="${1:-Working...}"
  local log_file="${2:-/tmp/port_apply.log}"

  if (( UI_ACTIVE == 1 )); then
    ui_stop || true
  fi

  UI_LOG="$log_file"
  : >>"$UI_LOG" 2>/dev/null || true

  UI_STTY="$(stty -g </dev/tty 2>/dev/null || true)"

  local rows cols
  read -r rows cols < <(_ui_term_size)

  local h=15
  local w=$(( cols - 2 ))
  (( w < 80 )) && w=80
  (( h < 8 )) && h=8

  UI_GAUGE_W="$w"
  UI_GAUGE_H="$h"

  local fifo_path
  fifo_path="$(mktemp -u /tmp/meraki_gauge.XXXXXX)"
  rm -f "$fifo_path" 2>/dev/null || true
  mkfifo "$fifo_path" || { UI_FIFO=""; return 1; }
  UI_FIFO="$fifo_path"

  "$DIALOG" --backtitle "$BACKTITLE_PORTS" \
            --title "$title" \
            --gauge "Starting..." "$h" "$w" 0 \
            <"$UI_FIFO" >/dev/tty 2>/dev/tty &
  UI_GAUGE_PID=$!

  exec 3>"$UI_FIFO"

  UI_ACTIVE=1
  UI_LAST_MSG="Starting..."
  UI_LAST_PCT=0
  printf '0\nXXX\nStarting...\nXXX\n' >&3
}

ui_stop() {
  (( UI_ACTIVE == 1 )) || return 0

  exec 3>&- 2>/dev/null || true

  if [[ -n "${UI_GAUGE_PID:-}" ]]; then
    wait "$UI_GAUGE_PID" 2>/dev/null || true
  fi

  rm -f "${UI_FIFO:-}" 2>/dev/null || true
  "$DIALOG" --clear >/dev/null 2>&1 || true

  if [[ -n "${UI_STTY:-}" ]]; then
    stty "$UI_STTY" </dev/tty 2>/dev/null || true
  else
    stty sane </dev/tty 2>/dev/null || true
  fi

  tput cnorm 2>/dev/null || true
  printf '\033[0m' 2>/dev/null || true

  UI_ACTIVE=0
  UI_GAUGE_PID=""
  UI_FIFO=""
  UI_STTY=""
}

ui_update() {
  local msg="${1:-Working...}"
  local pct="${2:-0}"

  (( UI_ACTIVE == 1 )) || return 0
  if ! _ui_gauge_alive; then
    ui_stop || true
    return 0
  fi

  UI_LAST_MSG="$msg"
  UI_LAST_PCT="$pct"

  local w="${UI_GAUGE_W:-120}"
  [[ "$w" =~ ^[0-9]+$ ]] || w=120

  local fitw=$(( w - 2 ))
  (( fitw < 60 )) && fitw=60

  local line1 line2 line3
  line1="$(_ui_tail_lines 3 | sed -n '1p')"
  line2="$(_ui_tail_lines 3 | sed -n '2p')"
  line3="$(_ui_tail_lines 3 | sed -n '3p')"

  line1="$(_ui_fit_line "$fitw" "$line1")"
  line2="$(_ui_fit_line "$fitw" "$line2")"
  line3="$(_ui_fit_line "$fitw" "$line3")"

  local text="$msg"

  if [[ -n "${UI_IDENT_LINE:-}" ]]; then
    while IFS= read -r _ln; do
      [[ -n "$_ln" ]] || continue
      text+=$'\n'"$(_ui_fit_line "$fitw" "$_ln")"
    done <<<"$UI_IDENT_LINE"
  fi

  [[ -n "$line1" || -n "$line2" || -n "$line3" ]] && text+=$'\n\n'"Last log lines:"
  [[ -n "$line1" ]] && text+=$'\n'"  $line1"
  [[ -n "$line2" ]] && text+=$'\n'"  $line2"
  [[ -n "$line3" ]] && text+=$'\n'"  $line3"

  printf '%s\nXXX\n%s\nXXX\n' "$pct" "$text" >&3
}

restore_tty() {
  ui_stop || true
  "$DIALOG" --clear >/dev/null 2>&1 || true
  stty sane </dev/tty 2>/dev/null || true
  tput cnorm 2>/dev/null || true
  printf '\033[0m' 2>/dev/null || true
}
trap restore_tty EXIT INT TERM

apply_ui_update() { ui_update "${1:-Working...}" "${2:-0}"; }

# ============================================================
# Meraki “ignored field” warning helper
# ============================================================

warn_if_meraki_ignored_fields() {
  local req_json="$1"
  local resp_file="$2"
  local is_lag_member="${3:-0}"

  need jq || return 0

  if ! jq -e . >/dev/null 2>&1 <"$resp_file"; then
    echo "WARN: Meraki response is not valid JSON; cannot verify applied fields."
    return 0
  fi

  IS_LAG_MEMBER="$is_lag_member" jq -nr --argjson req "$req_json" --slurpfile r "$resp_file" '
    def norm_link(v):
      if v == null or v == "" then "Auto negotiate" else v end;

    def norm(v):
      if v == null then null
      elif (v|type) == "string" then v
      else v end;

    ($r[0]) as $resp
    | if ($resp|type) != "object" then
        "WARN: Meraki PUT response did not include a port object; cannot verify applied fields."
      else
        ($req | keys_unsorted[]) as $k
        | (
            if $k == "dot3az" then
              if ($resp|has("dot3az")|not) then
                "WARN: Meraki response omitted dot3az; cannot verify applied value."
              else
                ( ($req.dot3az.enabled // null) as $want
                  | ($resp.dot3az.enabled // null) as $got
                  | select(norm($want) != norm($got))
                  | "WARN: Meraki ignored/changed dot3az.enabled: requested=" + ($want|@json) + " got=" + ($got|@json)
                )
              end

            elif $k == "linkNegotiation" then
              if ($resp|has("linkNegotiation")|not) then
                "WARN: Meraki response omitted linkNegotiation; cannot verify applied value."
              else
                ( ($req.linkNegotiation // null) as $want
                  | ($resp.linkNegotiation // null) as $got
                  | select(norm_link($want) != norm_link($got))
                  | "WARN: Meraki ignored/changed linkNegotiation: requested=" + ($want|@json) + " got=" + ($got|@json)
                )
              end

            elif $k == "poeEnabled" then
              if ($resp|has("poeEnabled")|not) then
                empty
              else
                ( ($req.poeEnabled // null) as $want
                  | ($resp.poeEnabled // null) as $got
                  | if ($want == false and $got == null) then empty
                    else
                      select(norm($want) != norm($got))
                      | "WARN: Meraki ignored/changed poeEnabled: requested=" + ($want|@json) + " got=" + ($got|@json)
                    end
                )
              end

            elif $k == "name" then
              if ($ENV.IS_LAG_MEMBER|tonumber) == 1 then
                empty
              else
                if ($resp|has("name")|not) then
                  ("WARN: Meraki response omitted name; cannot verify applied value.")
                else
                  ( ($req.name) as $want
                    | ($resp.name // null) as $got
                    | select(norm($want) != norm($got))
                    | "WARN: Meraki ignored/changed name: requested=" + ($want|@json) + " got=" + ($got|@json)
                  )
                end
              end

            else
              if ($resp|has($k)|not) then
                ("WARN: Meraki response omitted " + $k + "; cannot verify applied value.")
              else
                ( ($req[$k]) as $want
                  | ($resp[$k]) as $got
                  | select(norm($want) != norm($got))
                  | "WARN: Meraki ignored/changed " + $k + ": requested=" + ($want|@json) + " got=" + ($got|@json)
                )
              end
            end
          )
      end
  ' | awk 'NF'
}

# ============================================================
# Meraki GET helpers (device identifier == cloud_id)
# ============================================================

meraki_get_switch_port_for_cloud_id() {
  local device_id="$1"   # <-- this is cloud_id (Meraki serial)
  local port_id="$2"
  local out_json="$3"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$device_id" ]] || { echo "No device_id" >&2; return 1; }
  [[ -n "$port_id" ]] || { echo "No port_id" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/devices/${device_id}/switch/ports/${port_id}" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl rc=$rc getting port $port_id for deviceId=$device_id" >&2
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code getting port $port_id for deviceId=$device_id" >&2
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

# ============================================================
# Uplink prefix discovery
# ============================================================

get_uplink_prefixes_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"

  need jq || return 1

  local f="${UPLINK_TYPES_DIR%/}/${ip}.json"
  if [[ -f "$f" ]]; then
    jq -r --arg m "$member" '
      (.members[$m].prefixes // .members[$m].uplinkPrefixes // [])
      | .[]
    ' "$f" 2>/dev/null | awk 'NF' && return 0
  fi

  if [[ -f "$DISCOVERY_RESULTS_FILE" ]]; then
    local pid
    pid="$(jq -r --arg ip "$ip" --arg m "$member" '
      (if type=="array" then . elif has("results") then .results else [.]
       end)
      | map(select(.ip==$ip)) | .[0]
      | .hw_detail.members[$m].nm_modules[0].pid // empty
    ' "$DISCOVERY_RESULTS_FILE" 2>/dev/null | head -n1)"
    pid="$(trim "$pid")"

    case "$pid" in
      C9300-NM-8X|C9300X-NM-8M)         printf '%s\n' "TenGigabitEthernet" ;;
      C9300-NM-2Y|C9300X-NM-8Y)         printf '%s\n' "TwentyFiveGigE" ;;
      C9300-NM-2Q)                      printf '%s\n' "FortyGigabitEthernet" ;;
      C9300X-NM-2C|C9300X-NM-4C)        printf '%s\n' "HundredGigE" ;;
      C9300-NM-4G)                      printf '%s\n' "GigabitEthernet" ;;
      C9300-NM-4M)                      printf '%s\n' "TenGigabitEthernet" ;;
      *)                                return 1 ;;
    esac
    return 0
  fi

  return 1
}

infer_ios_uplink_type_from_meraki_portid() {
  local portid="$1"

  local mod=""
  if [[ "$portid" =~ ^[0-9]+_([^_]+)_[0-9]+$ ]]; then
    mod="${BASH_REMATCH[1]}"
  fi

  case "$mod" in
    *NM-2Q*|*NM-2-40G*|*MA-MOD-2X40G*)    echo "FortyGigabitEthernet" ;;
    *NM-2Y*|*NM-8Y*|*MA-MOD-2X25G*)       echo "TwentyFiveGigE" ;;
    *NM-8X*|*NM-4M*|*MA-MOD-4X10G*|*MA-MOD-8X10G*) echo "TenGigabitEthernet" ;;
    *C3850-NM-4-10G*|*C3850-NM-8-10G*)    echo "TenGigabitEthernet" ;;
    *NM-4G*)                              echo "GigabitEthernet" ;;
    *)                                    echo "" ;;
  esac
}

is_uplink_module_iface_for_ip() {
  local ip="$1"
  local ifn="$2"

  [[ "$ifn" =~ ^([A-Za-z]+)([0-9]+)/1/[0-9]+$ ]] || return 1
  local type="${BASH_REMATCH[1]}"
  local member="${BASH_REMATCH[2]}"

  local pfx
  while IFS= read -r pfx; do
    [[ -n "$pfx" ]] || continue
    if [[ "$type" == "$pfx" ]]; then
      return 0
    fi
  done < <(get_uplink_prefixes_for_ip_member "$ip" "$member" 2>/dev/null || true)

  return 1
}

# ============================================================
# Migration context loader
# ============================================================

load_migrate_context() {
  local MIGRATE_RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/migrate"
  local MIGRATE_LATEST_ENV="$MIGRATE_RUN_ROOT/latest.env"

  if [[ ! -f "$MIGRATE_LATEST_ENV" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No migration context" \
        --msgbox "Could not find a migration run.\n\nMissing file:\n  $MIGRATE_LATEST_ENV\n\nRun the main migration script (select / map / enable) first." 13 80
    return 1
  fi

  set +H
  # shellcheck disable=SC1090
  source "$MIGRATE_LATEST_ENV"
  set -H 2>/dev/null || true

  local SEL_IPS_RAW="${MIGRATE_SELECTED_IPS:-}"
  RUN_ID="${MIGRATE_RUN_ID:-}"

  if [[ -z "${RUN_ID:-}" || -z "$SEL_IPS_RAW" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Incomplete migration context" \
        --msgbox "latest.env does not contain a valid migration run.\n\nEnsure the main migration workflow has been run for the switches you want to process." 13 80
    return 1
  fi

  local PORT_MIG_ROOT="${CLOUD_ADMIN_BASE}/runs/port_migration"
  RUN_DIR="${PORT_MIG_ROOT}/${RUN_ID}"

  mkdir -p "$RUN_DIR/ports" "$RUN_DIR/devlogs" 2>/dev/null || true

  ln -sfn "$RUN_DIR"         "${PORT_MIG_ROOT}/latest"
  ln -sfn "$RUN_DIR/ports"   "${PORT_MIG_ROOT}/latest.ports"
  ln -sfn "$RUN_DIR/devlogs" "${PORT_MIG_ROOT}/latest.devlogs"
  ln -sfn "$MIGRATE_LATEST_ENV" "${PORT_MIG_ROOT}/latest.env"

  PORTS_SELECTED_IPS=()
  read -r -a PORTS_SELECTED_IPS <<<"$SEL_IPS_RAW"
  if ((${#PORTS_SELECTED_IPS[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No switches selected" \
        --msgbox "There are no switches recorded in MIGRATE_SELECTED_IPS.\n\nRun the selection step in the main migration module first." 11 80
    return 1
  fi

  return 0
}

# ============================================================
# Load Meraki API key
# ============================================================

load_meraki_api_key() {
  if [[ -n "${MERAKI_API_KEY:-}" ]]; then
    return 0
  fi

  if [[ -f "$MERAKI_ENV_FILE" ]]; then
    set +H
    # shellcheck disable=SC1090
    source "$MERAKI_ENV_FILE"
    set -H 2>/dev/null || true
  fi

  if [[ -n "${MERAKI_API_KEY:-}" ]]; then
    export MERAKI_API_KEY
    return 0
  fi

  local key
  key="$(
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Meraki API key required" \
        --inputbox "Enter your Meraki Dashboard API key.\n\nIt will be stored (chmod 600) in:\n  $MERAKI_ENV_FILE" \
        13 80
  )" || return 1

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No API key" \
        --msgbox "No Meraki API key was entered.\n\nCannot continue without it." 10 70
    return 1
  fi

  MERAKI_API_KEY="$key"
  export MERAKI_API_KEY

  mkdir -p "$(dirname "$MERAKI_ENV_FILE")"
  cat >"$MERAKI_ENV_FILE" <<EOF
# Meraki API key – created by port_migration module
MERAKI_API_KEY="$MERAKI_API_KEY"
EOF
  chmod 600 "$MERAKI_ENV_FILE"
  return 0
}

# ============================================================
# Backup config path for an IP (from discovery_results.json)
# ============================================================

find_backup_cfg_for_ip() {
  local ip="$1"
  need jq || return 1

  if [[ ! -f "$DISCOVERY_RESULTS_FILE" ]]; then
    echo "discovery_results.json not found: $DISCOVERY_RESULTS_FILE" >&2
    return 1
  fi

  local filename
  filename="$(
    jq -r --arg ip "$ip" '
      (if type=="array" then .
       elif has("results") then .results
       else [.]
       end)
      | map(select(.ip == $ip)) | .[0]
      | select(.backup_enabled == true and (.backup_status // "") == "OK")
      | .backup_filename // empty
    ' "$DISCOVERY_RESULTS_FILE" 2>/dev/null || echo ""
  )"

  filename="$(trim "$filename")"
  if [[ -z "$filename" ]]; then
    echo "No valid backup entry for IP $ip in discovery_results.json" >&2
    return 1
  fi

  local path="${BACKUP_LOCAL_BASE_DIR%/}/$filename"
  printf '%s\n' "$path"
}

# ============================================================
# Discovery helpers: NM modules per IP
# ============================================================

get_nm_modules_for_ip() {
  local ip="$1"
  need jq || return 0

  [[ -f "$DISCOVERY_RESULTS_FILE" ]] || { echo ""; return 0; }

  jq -r --arg ip "$ip" '
    (if type=="array" then .
     elif has("results") then .results
     else [.]
     end)
    | map(select(.ip == $ip)) | .[0]?
    | (.hw_detail.members // {})
    | to_entries
    | map(.value.nm_modules // [])
    | add
    | map(.pid // empty)
    | map(select(length>0))
    | unique
    | join(",")
  ' "$DISCOVERY_RESULTS_FILE" 2>/dev/null || echo ""
}

allowed_meraki_module_tokens_for_ip() {
  local ip="$1"
  local nm_csv nm
  nm_csv="$(get_nm_modules_for_ip "$ip")"
  nm_csv="$(trim "$nm_csv")"
  [[ -n "$nm_csv" ]] || return 0

  IFS=',' read -r -a _nms <<<"$nm_csv"
  for nm in "${_nms[@]}"; do
    nm="$(trim "$nm")"
    [[ -n "$nm" ]] || continue

    case "$nm" in
      C9300-NM-8X|C9300X-NM-8M) printf '%s\n' "$nm" ;;
      C9300-NM-4M|C9300-NM-2Q|C9300-NM-2Y|C9300-NM-4G|C9300X-NM-2C|C9300X-NM-4C|C9300X-NM-8Y) printf '%s\n' "$nm" ;;
      MA-MOD-8X10G|MA-MOD-4X10G|MA-MOD-2X40G|MA-MOD-2Y-M) printf '%s\n' "$nm" ;;
      *) printf '%s\n' "$nm" ;;
    esac
  done | awk 'NF' | sort -u
}

is_allowed_meraki_module_token_for_ip() {
  local ip="$1"
  local mod="$2"
  local allow
  while IFS= read -r allow; do
    [[ -n "$allow" ]] || continue
    [[ "$mod" == "$allow" ]] && return 0
  done < <(allowed_meraki_module_tokens_for_ip "$ip" 2>/dev/null || true)
  return 1
}

# ============================================================
# Meraki identity / ports helpers
# ============================================================

# Find Meraki identity for a specific IP + member.
# OUTPUT (NO Cisco serials):
#   "cloud_id|model"
find_meraki_identity_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"

  [[ -d "$MERAKI_MEMORY_DIR" ]] || return 1
  need jq || return 1

  local exact
  exact="$(
    jq -r --arg ip "$ip" --arg m "$member" '
      select(.ip == $ip)
      | {
          m: (
            (.member
             // .stack_member
             // .stackMember
             // .stack.member_index
             // .stack.memberIndex
             // empty) | tostring
          ),
          cloud:  (.cloud_id // ""),
          model:  (.model // "")
        }
      | select(.m == $m)
      | "\(.cloud)|\(.model)"
    ' "$MERAKI_MEMORY_DIR"/*.json 2>/dev/null | awk 'NF{print; exit}'
  )"

  if [[ -n "$exact" ]]; then
    printf '%s\n' "$exact"
    return 0
  fi

  # fallback member=1: first match for IP
  if [[ "$member" == "1" ]]; then
    jq -r --arg ip "$ip" '
      select(.ip == $ip)
      | "\(.cloud_id // "")|\(.model // "")"
    ' "$MERAKI_MEMORY_DIR"/*.json 2>/dev/null | awk -F'|' '($1!=""){print; exit}'
    return 0
  fi

  return 1
}

find_meraki_identity_for_ip() {
  find_meraki_identity_for_ip_member "$1" "1"
}

find_meraki_model_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"
  local line
  line="$(find_meraki_identity_for_ip_member "$ip" "$member" 2>/dev/null || true)"
  if [[ -n "$line" ]]; then
    awk -F'|' '{print $2}' <<<"$line" | awk 'NF{print; exit}'
    return 0
  fi
  return 1
}

find_meraki_model_for_ip() {
  find_meraki_model_for_ip_member "$1" "1"
}

# ============================================================
# UDLD Classing (Model-driven)
# ============================================================

is_udld_class_a_model() {
  local m="${1:-}"
  case "$m" in
    C9300X-12Y|C9300X-24Y|C9300-24S|C9300-48S) return 0 ;;
    *) return 1 ;;
  esac
}

get_udld_class_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"
  local model
  model="$(find_meraki_model_for_ip_member "$ip" "$member" 2>/dev/null || true)"
  model="$(trim "$model")"

  if [[ -z "$model" ]]; then
    echo "B|UNKNOWN"
    return 0
  fi

  if is_udld_class_a_model "$model"; then
    echo "A|$model"
  else
    echo "B|$model"
  fi
}

get_udld_class_for_ip() {
  get_udld_class_for_ip_member "$1" "1"
}

# ============================================================
# Meraki port list fetch (device identifier == cloud_id)
# ============================================================

meraki_get_switch_ports_for_cloud_id() {
  local device_id="$1"  # <-- cloud_id (Meraki serial)
  local out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  if [[ -z "${MERAKI_API_KEY:-}" ]]; then
    echo "MERAKI_API_KEY not set – cannot fetch switch ports." >&2
    return 1
  fi
  if [[ -z "$device_id" ]]; then
    echo "No Meraki device (cloud) ID provided – cannot fetch switch ports." >&2
    return 1
  fi

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/devices/${device_id}/switch/ports" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl error talking to Meraki API (rc=$rc) when fetching ports for deviceId ${device_id}" >&2
    sed -n '1,80p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "Meraki API error getting ports for deviceId ${device_id} (HTTP ${http_code})" >&2
    echo "Response (first 40 lines):" >&2
    sed -n '1,40p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

# ============================================================
# Stack detection + per-member identity
# ============================================================

get_stack_members_for_ip() {
  local ip="$1"
  need jq || return 1
  [[ -f "$DISCOVERY_RESULTS_FILE" ]] || return 1

  jq -r --arg ip "$ip" '
    (if type=="array" then .
     elif has("results") then .results
     else [.]
     end)
    | map(select(.ip == $ip)) | .[0]?
    | (.hw_detail.members // {})
    | keys[]
  ' "$DISCOVERY_RESULTS_FILE" 2>/dev/null | awk 'NF' | sort -n
}

get_stack_member_count_for_ip() {
  local ip="$1"
  local c
  c="$(get_stack_members_for_ip "$ip" 2>/dev/null | wc -l | awk "{print \$1}")"
  [[ "$c" =~ ^[0-9]+$ ]] || c=1
  (( c < 1 )) && c=1
  printf '%s\n' "$c"
}

# ============================================================
# IOS config → "intent" JSONL
# ============================================================
# (UNCHANGED from your version)
parse_ios_config_to_intent() {
  local cfg="$1"
  [[ -f "$cfg" ]] || { echo "Config not found: $cfg" >&2; return 1; }

  awk -f /dev/stdin "$cfg" <<'AWK'
BEGIN {
  in_if = 0
  ifname = ""
  desc = ""
  mode = ""
  access_vlan = ""
  voice_vlan = ""
  native_vlan = ""
  allowed_vlans = ""

  portfast = 0
  bpduguard = 0
  rootguard = 0
  loopguard = 0
  portsec = 0
  portsec_max = ""
  portsec_violation = ""

  qos_trust_dscp = 0
  qos_trust_phone = 0
  enabled = 1

  portchannel_id = ""
  portchannel_mode = ""
  is_portchannel = 0

  udld_aggressive = 0

  global_udld_enabled = 0
  global_udld_aggressive = 0

  eee_set = 0
  eee_enabled = 0

  speed_s = ""
  duplex_s = ""
  linkneg = ""
  poe_enabled = 1
  dai_trusted = 0

  stp_map_count = 0
  stp_min = ""
  stp_kv = ""
}

function reset_if_vars() {
  desc = ""
  mode = ""
  access_vlan = ""
  voice_vlan = ""
  native_vlan = ""
  allowed_vlans = ""
  portfast = 0
  bpduguard = 0
  rootguard = 0
  loopguard = 0
  portsec = 0
  portsec_max = ""
  portsec_violation = ""
  qos_trust_dscp = 0
  qos_trust_phone = 0
  enabled = 1

  portchannel_id = ""
  portchannel_mode = ""
  is_portchannel = 0

  udld_aggressive = 0

  eee_set = 0
  eee_enabled = 0

  speed_s = ""
  duplex_s = ""
  linkneg = ""
  poe_enabled = 1
  dai_trusted = 0
}

function add_stp(v, p) {
  # store "v=p" pairs in a csv-ish string
  if (stp_kv != "") stp_kv = stp_kv ","
  stp_kv = stp_kv v "=" p

  if (stp_min == "" || p+0 < stp_min+0) stp_min = p
  stp_map_count++
}

function expand_vlans(list, p) {
  gsub(/[[:space:]]+/, "", list)
  n = split(list, parts, ",")
  for (i=1; i<=n; i++) {
    if (parts[i] ~ /^[0-9]+-[0-9]+$/) {
      split(parts[i], r, "-")
      for (v=r[1]+0; v<=r[2]+0; v++) add_stp(v, p)
    } else if (parts[i] ~ /^[0-9]+$/) {
      add_stp(parts[i]+0, p)
    }
  }
}

function flush_if() {
  if (ifname == "") return

  port_id = ""

  if (!is_portchannel && match(ifname, /[0-9]+$/)) {
    port_id = substr(ifname, RSTART, RLENGTH)
  }

  type = ""
  if (mode == "access") type = "access"
  else if (mode == "trunk") type = "trunk"

  linkneg = ""

  if (speed_s == "auto")  speed_s = ""
  if (duplex_s == "auto") duplex_s = ""

  if (speed_s == "10" || duplex_s == "half") {
    speed_s  = ""
    duplex_s = ""
  }

  if (speed_s == "" && duplex_s == "") {
    linkneg = ""
  }
  else if (speed_s == "100" && duplex_s == "full") {
    linkneg = "100 Megabit full duplex (forced)"
  } else if (speed_s == "100" && (duplex_s == "" || duplex_s == "auto")) {
    linkneg = "100 Megabit (auto)"
  }
  else if (speed_s == "1000") {
    linkneg = "1 Gigabit full duplex (forced)"
  } else if (speed_s == "2500") {
    linkneg = "2.5 Gigabit full duplex (forced)"
  } else if (speed_s == "5000") {
    linkneg = "5 Gigabit full duplex (forced)"
  } else if (speed_s == "10000") {
    linkneg = "10 Gigabit full duplex (forced)"
  } else {
    linkneg = ""
  }

  printf "{"
  printf "\"interface\":\"%s\"", ifname

  if (port_id != "") {
    printf ",\"portId\":%d", port_id
  }

  if (portchannel_id != "") {
    printf ",\"portChannelId\":%d", portchannel_id
  }

  if (portchannel_mode != "") {
    printf ",\"portChannelMode\":\"%s\"", portchannel_mode
  }

  if (is_portchannel) {
    printf ",\"isPortChannel\":true"
  }

  if (desc != "") {
    gsub("\"", "\\\"", desc)
    printf ",\"description\":\"%s\"", desc
  }
  if (type != "") {
    printf ",\"type\":\"%s\"", type
  }
  if (access_vlan != "") {
    printf ",\"accessVlan\":%d", access_vlan
  }
  if (voice_vlan != "") {
    printf ",\"voiceVlan\":%d", voice_vlan
  }
  if (native_vlan != "") {
    printf ",\"nativeVlan\":%d", native_vlan
  }
  if (allowed_vlans != "") {
    printf ",\"allowedVlans\":\"%s\"", allowed_vlans
  }
  if (portfast) {
    printf ",\"portfast\":true"
  }
  if (bpduguard) {
    printf ",\"stpGuard\":\"bpduGuard\""
  } else if (rootguard) {
    printf ",\"stpGuard\":\"rootGuard\""
  } else if (loopguard) {
    printf ",\"stpGuard\":\"loopGuard\""
  }
  if (portsec) {
    printf ",\"portSecurity\":true"
    if (portsec_max != "") {
      printf ",\"portSecurityMax\":%d", portsec_max
    }
    if (portsec_violation != "") {
      printf ",\"portSecurityViolation\":\"%s\"", portsec_violation
    }
  }
  if (qos_trust_dscp) {
    printf ",\"qosTrust\":\"dscp\""
  }
  if (qos_trust_phone) {
    printf ",\"qosTrustDevicePhone\":true"
  }

  if (udld_aggressive) {
    printf ",\"udld\":\"Enforce\""
  }

  if (linkneg != "") {
    printf ",\"linkNegotiation\":\"%s\"", linkneg
  }
  if (!poe_enabled) {
    printf ",\"poeEnabled\":false"
  }
  if (eee_set) {
    if (eee_enabled) printf ",\"eeeEnabled\":true"
    else            printf ",\"eeeEnabled\":false"
  }
  if (dai_trusted) {
    printf ",\"daiTrusted\":true"
  }

  if (!enabled) {
    printf ",\"enabled\":false"
  } else {
    printf ",\"enabled\":true"
  }
  printf "}\n"
}

/^[[:space:]]*udld[[:space:]]+enable[[:space:]]*$/ {
  global_udld_enabled = 1
  next
}
/^[[:space:]]*udld[[:space:]]+aggressive[[:space:]]*$/ {
  global_udld_enabled = 1
  global_udld_aggressive = 1
  next
}

/^[[:space:]]*spanning-tree[[:space:]]+vlan[[:space:]]+/ {
  # match: spanning-tree vlan <vlist> priority <prio>
  if (match($0, /^[[:space:]]*spanning-tree[[:space:]]+vlan[[:space:]]+([^ ]+)[[:space:]]+priority[[:space:]]+([0-9]+)/, m)) {
    vlist = m[1]
    prio  = m[2]+0
    expand_vlans(vlist, prio)
  }
  next
}

function flush_switch_meta() {
  printf "{"
  printf "\"switchMeta\":true"
  if (global_udld_aggressive) {
    printf ",\"globalUdld\":\"Enforce\""
  } else if (global_udld_enabled) {
    printf ",\"globalUdld\":\"Alert only\""
  }

  if (stp_map_count > 0) {
    # store the raw map string + computed min
    printf ",\"stpVlanPriorities\":\"%s\"", stp_kv
    printf ",\"stpPriorityPreferred\":%d", stp_min
  }
  printf "}\n"
}

/^interface[[:space:]]/ {
  if (in_if) flush_if()

  in_if = 1
  ifname = $2
  reset_if_vars()

  if (match(ifname, /^Port-channel[0-9]+$/)) {
    is_portchannel = 1
    if (match(ifname, /[0-9]+$/)) {
      portchannel_id = substr(ifname, RSTART, RLENGTH)
    }
  }
  next
}

/^[[:space:]]*!+[[:space:]]*$/ && in_if {
  flush_if()
  in_if = 0
  next
}

in_if {
  if ($1 == "description" || $1 == "descrption") {
    $1=""
    sub(/^[ \t]+/, "")
    desc=$0
    next
  }

  if ($1 == "switchport" && $2 == "mode") { mode=$3; next }
  if ($1 == "switchport" && $2 == "access" && $3 == "vlan") { access_vlan=$4; next }
  if ($1 == "switchport" && $2 == "voice" && $3 == "vlan") { voice_vlan=$4; next }
  if ($1 == "switchport" && $2 == "trunk" && $3 == "native" && $4 == "vlan") { native_vlan=$5; next }
  if ($1 == "switchport" && $2 == "trunk" && $3 == "allowed" && $4 == "vlan") { allowed_vlans=$5; next }

  if ($1 == "channel-group") {
    portchannel_id = $2
    if ($3 == "mode" && $4 != "") portchannel_mode = $4
    next
  }

  if ($1 == "udld" && $2 == "port") {
    if ($3 == "aggressive") udld_aggressive = 1
    next
  }

  if ($1 == "spanning-tree" && $2 == "portfast") { portfast = 1; next }
  if ($1 == "spanning-tree" && $2 == "bpduguard" && $3 == "enable") { bpduguard=1; rootguard=0; loopguard=0; next }
  if ($1 == "spanning-tree" && $2 == "guard" && $3 == "root") { rootguard=1; loopguard=0; bpduguard=0; next }
  if ($1 == "spanning-tree" && $2 == "guard" && $3 == "loop") { loopguard=1; rootguard=0; bpduguard=0; next }

  if ($1 == "switchport" && $2 == "port-security") {
    portsec = 1
    if ($3 == "maximum") portsec_max = $4
    else if ($3 == "violation") portsec_violation = $4
    next
  }

  if ($1 == "mls" && $2 == "qos" && $3 == "trust") {
    if ($4 == "dscp") qos_trust_dscp = 1
    else if ($4 == "device" && $5 == "cisco-phone") qos_trust_phone = 1
    next
  }

  if ($1 == "speed")  { speed_s = $2; next }
  if ($1 == "duplex") { duplex_s = $2; next }

  if ($1 == "power" && $2 == "inline") {
    if ($3 == "never") poe_enabled = 0
    else poe_enabled = 1
    next
  }

  if ($1 == "ip" && $2 == "arp" && $3 == "inspection" && $4 == "trust") { dai_trusted = 1; next }

  if ($1 == "power" && $2 == "efficient-ethernet") { eee_set=1; eee_enabled=1; next }
  if ($1 == "no" && $2 == "power" && $3 == "efficient-ethernet") { eee_set=1; eee_enabled=0; next }

  if ($1 == "shutdown") { enabled = 0; next }
  if ($1 == "no" && $2 == "shutdown") { enabled = 1; next }
}

END {
  if (in_if) flush_if()
  flush_switch_meta()
}
AWK
}

# ============================================================
# Intent + Meraki ports → diff JSON + human summary
# ============================================================
get_ios_stp_priority_preferred_from_intent() {
  local intent_jsonl="$1"
  jq -r '
    select(type=="object" and .switchMeta==true)
    | (.stpPriorityPreferred // empty)
  ' "$intent_jsonl" 2>/dev/null | awk 'NF{print; exit}'
}

# Given a ports_diff.json path, return matching intent.jsonl path
# Example:
#   /.../10.0.0.1_base_m1_ports_diff.json -> /.../10.0.0.1_base_m1_intent.jsonl
intent_jsonl_from_diff_file() {
  local diff_file="$1"
  [[ -n "$diff_file" ]] || return 1
  echo "${diff_file%_ports_diff.json}_intent.jsonl"
}

# Apply STP bridge priority at NETWORK scope, but only for the provided serials array.
# serials_json MUST be a JSON array, e.g. ["Q5TD-xxxx-xxxx"] or ["Q...","Q..."]
apply_network_stp_priority_for_serials() {
  local network_id="$1"
  local stp_priority="$2"
  local serials_json="$3"
  local log="$4"

  need jq   || return 1
  need curl || return 1

  network_id="$(trim "$network_id")"
  stp_priority="$(trim "$stp_priority")"

  if [[ -z "$network_id" ]]; then
    echo "STP: ERROR: network_id is empty" >>"$log"
    return 1
  fi
  if [[ -z "$stp_priority" ]]; then
    echo "STP: ERROR: stp_priority is empty" >>"$log"
    return 1
  fi
  if ! jq -e . >/dev/null 2>&1 <<<"$serials_json"; then
    echo "STP: ERROR: serials_json is not valid JSON: $serials_json" >>"$log"
    return 1
  fi
  if [[ "$(jq -r 'type' <<<"$serials_json" 2>/dev/null)" != "array" ]]; then
    echo "STP: ERROR: serials_json is not a JSON array: $serials_json" >>"$log"
    return 1
  fi
  if [[ "$(jq -r 'length' <<<"$serials_json" 2>/dev/null || echo 0)" -lt 1 ]]; then
    echo "STP: No serials provided; skipping." >>"$log"
    return 0
  fi

  echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – STP APPLY (networkId=$network_id) ====" >>"$log"
  echo "STP: targetSerials=$serials_json priority=$stp_priority" >>"$log"

  # Get current STP config
  local cur_file cur_json
  cur_file="$(mktemp)"
  if ! meraki_get_network_switch_stp "$network_id" "$cur_file" >>"$log" 2>&1; then
    echo "STP: FAILED to GET /networks/$network_id/switch/stp" >>"$log"
    rm -f "$cur_file" 2>/dev/null || true
    return 1
  fi
  cur_json="$(cat "$cur_file")"
  rm -f "$cur_file" 2>/dev/null || true

  # Preserve rstpEnabled, remove any existing stpBridgePriority entries that overlap our serials,
  # then append the desired entry for our serial set.
  local body
  body="$(
    jq -c --argjson serials "$serials_json" --arg prio "$stp_priority" '
      def set(a): (a|unique|sort);
      def overlaps(a;b):
        (set(a) as $A | set(b) as $B
         | ($A + $B) | group_by(.) | map(select(length>1)) | length) > 0;

      . as $cur
      | ($cur.rstpEnabled // true) as $rstp
      | ($cur.stpBridgePriority // []) as $prioArr
      | ($serials) as $S
      | ($prioArr
          | map(
              if overlaps((.switches // []); $S) then empty else .
              end
            )
        ) as $filtered
      | {
          rstpEnabled: $rstp,
          stpBridgePriority: (
            $filtered + [
              { switches: $S, stpPriority: ($prio|tonumber) }
            ]
          )
        }
    ' <<<"$cur_json"
  )"

  echo "STP: PUT body: $body" >>"$log"

  local out
  out="$(mktemp)"
  if meraki_update_network_switch_stp "$network_id" "$body" "$out" >>"$log" 2>&1; then
    echo "STP: SUCCESS applying priority=$stp_priority to switches=$serials_json" >>"$log"
    rm -f "$out" 2>/dev/null || true
    return 0
  fi

  echo "STP: FAILED applying priority=$stp_priority to switches=$serials_json" >>"$log"
  sed -n '1,80p' "$out" >>"$log" 2>/dev/null || true
  rm -f "$out" 2>/dev/null || true
  return 1
}

apply_meraki_network_stp_from_intent() {
  local ip="$1"
  local intent_jsonl="$2"
  local log="$3"

  need jq || return 1
  need curl || return 1

  [[ -f "$intent_jsonl" ]] || return 0

  local preferred
  preferred="$(get_ios_stp_priority_preferred_from_intent "$intent_jsonl" 2>/dev/null || true)"
  preferred="$(trim "$preferred")"
  [[ -n "$preferred" ]] || { echo "STP: No preferred priority found in intent; skipping." >>"$log"; return 0; }

  # Build serial list (CLOUD IDs) for all stack members we know about
  local -a serials=()
  local m id_line cloud_id
  while IFS= read -r m; do
    m="$(trim "$m")"
    [[ -n "$m" ]] || continue
    id_line="$(find_meraki_identity_for_ip_member "$ip" "$m" 2>/dev/null || true)"
    [[ -n "$id_line" ]] || continue
    IFS='|' read -r cloud_id _ <<<"$id_line"
    cloud_id="$(trim "$cloud_id")"
    [[ -n "$cloud_id" ]] && serials+=("$cloud_id")
  done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

  # If we only have member 1, serials will still be fine
  ((${#serials[@]} > 0)) || { echo "STP: No cloud_id serials for ip=$ip; skipping." >>"$log"; return 0; }

  local serials_json
  # JSON array of CLOUD IDs for the stack members we found
  serials_json="$(printf '%s\n' "${serials[@]}" | jq -R . | jq -s .)"

  # Determine networkId from any member cloud_id
  local any_cloud_id="${serials[0]}"
  local dev_json network_id
  dev_json="$(mktemp)"
  network_id=""
  if meraki_get_device_by_id "$any_cloud_id" "$dev_json" >>"$log" 2>&1; then
    network_id="$(jq -r '.networkId // empty' "$dev_json" 2>/dev/null || true)"
  fi
  rm -f "$dev_json" 2>/dev/null || true
  network_id="$(trim "$network_id")"
  [[ -n "$network_id" ]] || { echo "STP: Could not determine networkId from deviceId=$any_cloud_id; skipping." >>"$log"; return 0; }

  echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – NETWORK STP APPLY for IP $ip ====" >>"$log"
  echo "STP: networkId=$network_id preferredPriority=$preferred serials=${serials[*]}" >>"$log"

  # Get current STP config
  local cur stp_cur
  cur="$(mktemp)"
  if ! meraki_get_network_switch_stp "$network_id" "$cur" >>"$log" 2>&1; then
    echo "STP: FAILED to GET /networks/$network_id/switch/stp" >>"$log"
    rm -f "$cur"
    return 0
  fi

  # Keep rstpEnabled as-is; replace any existing stpBridgePriority entries that mention our switches
  # then append our desired entry (switches:[serials...] stpPriority: preferred)
  stp_cur="$(cat "$cur")"
  rm -f "$cur"

  local body
  body="$(
    jq -c --argjson serials "$serials_json" --argjson pref "$preferred" '
      def set(a): (a|unique|sort);
      def overlaps(a;b):
        (set(a) as $A | set(b) as $B
         | ($A + $B) | group_by(.) | map(select(length>1)) | length) > 0;

      . as $cur
      | ($cur.rstpEnabled // true) as $rstp
      | ($cur.stpBridgePriority // []) as $prio
      | ($serials) as $S
      | ($prio
          | map(
              if overlaps((.switches // []); $S) then empty else .
              end
            )
        ) as $filtered
      | {
          rstpEnabled: $rstp,
          stpBridgePriority: (
            $filtered + [
              { switches: $S, stpPriority: ($pref|tonumber) }
            ]
          )
        }
    ' <<<"$stp_cur"
  )"

  echo "STP: PUT body: $body" >>"$log"

  local out
  out="$(mktemp)"
  if meraki_update_network_switch_stp "$network_id" "$body" "$out" >>"$log" 2>&1; then
    echo "STP: SUCCESS applying preferred priority=$preferred" >>"$log"
  else
    echo "STP: FAILED applying preferred priority=$preferred" >>"$log"
  fi
  rm -f "$out" 2>/dev/null || true

  return 0
}

merge_ios_intent_with_meraki_ports() {
  local ip="$1"
  local ios_cfg="$2"
  local member="${3:-1}"

  need jq || return 1

  if [[ -z "${RUN_DIR:-}" ]]; then
    echo "RUN_DIR is not set – run from migration context." >&2
    return 1
  fi

  mkdir -p "$RUN_DIR/ports" "$RUN_DIR/devlogs" 2>/dev/null || true

  local build_log="$RUN_DIR/devlogs/${ip}_m${member}_build_diff.log"
  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Build port diff for $ip member $member ===="
    echo "IOS config: $ios_cfg"
  } >>"$build_log"

  ui_start "Building port diff for $ip (m${member})" "$build_log"
  exec 2>>"$build_log"
  apply_ui_update "Starting diff build..." 1

  _merge_cleanup() { ui_stop; }
  trap _merge_cleanup RETURN

  if [[ ! -f "$ios_cfg" ]]; then
    echo "ERROR: IOS config file not found: $ios_cfg" >>"$build_log"
    echo "Config not found: $ios_cfg" >&2
    return 1
  fi

  local base_name
  base_name="$(basename "$ios_cfg" | sed 's/\..*$//')"

  local intent_jsonl="$RUN_DIR/ports/${ip}_${base_name}_m${member}_intent.jsonl"
  local ports_current="$RUN_DIR/ports/${ip}_${base_name}_m${member}_ports_current.json"
  local ports_diff_json="$RUN_DIR/ports/${ip}_${base_name}_m${member}_ports_diff.json"
  local ports_diff_txt="$RUN_DIR/ports/${ip}_${base_name}_m${member}_ports_diff.txt"

  echo "Step 1: Parsing IOS config → intent JSONL ($intent_jsonl)" >>"$build_log"
  apply_ui_update "Parsing IOS config → intent" 10
  if ! parse_ios_config_to_intent "$ios_cfg" >"$intent_jsonl" 2>>"$build_log"; then
    echo "ERROR: parse_ios_config_to_intent failed for $ios_cfg" >>"$build_log"
    echo "Failed to parse IOS config $ios_cfg" >&2
    return 1
  fi

  local nm_list nm_present saw_ios_uplink_cfg
  nm_list="$(get_nm_modules_for_ip "$ip")"
  nm_list="$(trim "$nm_list")"
  nm_present=0
  [[ -n "$nm_list" ]] && nm_present=1

  saw_ios_uplink_cfg="$(
    jq -s '
      [ .[]
        | select(type=="object")
        | select((.interface? // "") | test("^[A-Za-z]+[0-9]+/1/[0-9]+$"))
      ] | length
    ' "$intent_jsonl" 2>/dev/null || echo 0
  )"
  saw_ios_uplink_cfg="$(trim "$saw_ios_uplink_cfg")"
  [[ "$saw_ios_uplink_cfg" =~ ^[0-9]+$ ]] || saw_ios_uplink_cfg=0

  if [[ "$nm_present" -eq 0 && "$saw_ios_uplink_cfg" -gt 0 ]]; then
    echo "WARN: IOS config contains uplink-module interfaces (* /1/*) but discovery_results shows NO NM modules for IP=$ip. Proceeding anyway." >>"$build_log"
  elif [[ "$nm_present" -eq 1 && "$saw_ios_uplink_cfg" -eq 0 ]]; then
    echo "INFO: discovery_results shows NM module(s) for IP=$ip ($nm_list) but IOS config contains no * /1/* uplink-module interface stanzas." >>"$build_log"
  else
    echo "INFO: NM check for IP=$ip: nm_present=$nm_present nm_list='${nm_list:-}' ios_uplink_cfg_count=$saw_ios_uplink_cfg" >>"$build_log"
  fi

  local global_udld
  global_udld="$(
    jq -r '
      select(type=="object")
      | select(.switchMeta == true)
      | (.globalUdld // empty)
    ' "$intent_jsonl" 2>/dev/null | head -n1 || true
  )"
  global_udld="$(trim "$global_udld")"
  [[ -n "$global_udld" ]] && echo "  Global UDLD (from IOS): $global_udld" >>"$build_log"

  declare -A IOS_UPLINK_MAP_BY_TYPE=()
  while IFS=$'\t' read -r k v; do
    [[ -n "$k" && -n "$v" ]] || continue
    IOS_UPLINK_MAP_BY_TYPE["$k"]="$v"
  done < <(
    jq -cr '
      select(type=="object")
      | select((.interface? // null) | type=="string")
      | select(.interface | test("^[A-Za-z]+[0-9]+/1/[0-9]+$"))
      | (.interface | capture("^(?<t>[A-Za-z]+)(?<m>[0-9]+)/1/(?<p>[0-9]+)$")) as $c
      | "\($c.m)/\($c.p)/\($c.t)\t" + (.|@json)
    ' "$intent_jsonl" 2>/dev/null
  )

  echo "Step 2: Looking up Meraki identity for IP $ip member $member" >>"$build_log"
  apply_ui_update "Looking up Meraki device identity (meraki_memory)" 25

  local id_line cloud_id model
  id_line="$(find_meraki_identity_for_ip_member "$ip" "$member" 2>>"$build_log" || true)"
  if [[ -z "$id_line" ]]; then
    echo "ERROR: No meraki_memory entry found for IP $ip member $member" >>"$build_log"
    echo "No meraki_memory entry found for IP $ip member $member – cannot fetch ports." >&2
    return 1
  fi

  IFS='|' read -r cloud_id model <<<"$id_line"
  cloud_id="$(trim "$cloud_id")"
  model="$(trim "$model")"
  echo "  Found: cloud_id=$cloud_id model=$model" >>"$build_log"

  local udld_class udld_model
  IFS='|' read -r udld_class udld_model <<<"$(get_udld_class_for_ip_member "$ip" "$member")"
  echo "  UDLD class=$udld_class model=$udld_model" >>"$build_log"

  local host
  host="$(get_discovery_hostname_for_ip "$ip" 2>/dev/null || true)"
  host="$(trim "$host")"
  [[ -z "$host" ]] && host="$(trim "$udld_model")"
  [[ -z "$host" ]] && host="(unknown-host)"
  UI_IDENT_LINE="${host} | IP ${ip} | Cloud ${cloud_id}"

  if [[ -z "$cloud_id" ]]; then
    echo "ERROR: No Cloud ID recorded in meraki_memory for IP $ip member $member." >>"$build_log"
    echo "No Cloud ID for IP $ip member $member – cannot fetch ports." >&2
    return 1
  fi

  echo "Step 3: Fetching Meraki switch ports via API → $ports_current" >>"$build_log"
  apply_ui_update "Fetching switch ports from Meraki Dashboard API" 45
  if ! meraki_get_switch_ports_for_cloud_id "$cloud_id" "$ports_current" >>"$build_log" 2>&1; then
    echo "ERROR: meraki_get_switch_ports_for_cloud_id failed for deviceId $cloud_id" >>"$build_log"
    echo "Meraki ports fetch failed for deviceId $cloud_id" >&2
    return 1
  fi

  echo "Step 4: Building diff → $ports_diff_json" >>"$build_log"
  apply_ui_update "Building diff (merging intent + current ports)" 70

  : >"$ports_diff_json.tmp"
  local first_row=1

  while IFS= read -r meraki_port; do
    local pid
    pid="$(jq -r '.portId // empty | tostring' <<<"$meraki_port" 2>/dev/null || echo "")"
    pid="$(trim "$pid")"
    [[ -z "$pid" ]] && continue

    local ios_entry
    ios_entry="$(
      jq -c --arg pid "$pid" --arg m "$member" '
        def mem_of_if(i):
          if (i|type) != "string" then ""
          elif i | test("^[A-Za-z]+[0-9]+/0/[0-9]+$") then
            (i | capture("^[A-Za-z]+(?<m>[0-9]+)/0/[0-9]+$").m)
          elif i | test("^[A-Za-z]+[0-9]+/1/[0-9]+$") then
            (i | capture("^[A-Za-z]+(?<m>[0-9]+)/1/[0-9]+$").m)
          else "" end;

        select(type=="object")
        | select((.portId? // null) != null)
        | select((.portId|tostring) == $pid)
        | select(mem_of_if(.interface // "") == $m)
      ' "$intent_jsonl" 2>/dev/null | head -n1 || true
    )"

    if [[ -z "$ios_entry" && "$pid" =~ ^([0-9]+)_([^_]+)_([0-9]+)$ ]]; then
      local m mod n type key
      m="${BASH_REMATCH[1]}"
      mod="${BASH_REMATCH[2]}"
      n="${BASH_REMATCH[3]}"

      if [[ "$m" != "$member" ]]; then
        echo "  SKIP-MODULE-PORT: portId=$pid belongs to member=$m (building member=$member)" >>"$build_log"
        continue
      fi

      if ! is_allowed_meraki_module_token_for_ip "$ip" "$mod"; then
        echo "  SKIP-MODULE-PORT: portId=$pid mod=$mod (not in discovery NM list)" >>"$build_log"
        continue
      fi

      type="$(infer_ios_uplink_type_from_meraki_portid "$pid")"
      if [[ -n "$type" ]]; then
        key="${m}/${n}/${type}"
        if [[ -n "${IOS_UPLINK_MAP_BY_TYPE[$key]:-}" ]]; then
          ios_entry="${IOS_UPLINK_MAP_BY_TYPE[$key]}"
        fi
      fi

      if [[ -z "$ios_entry" ]]; then
        local pfx
        while IFS= read -r pfx; do
          [[ -n "$pfx" ]] || continue
          key="${m}/${n}/${pfx}"
          if [[ -n "${IOS_UPLINK_MAP_BY_TYPE[$key]:-}" ]]; then
            ios_entry="${IOS_UPLINK_MAP_BY_TYPE[$key]}"
            break
          fi
        done < <(get_uplink_prefixes_for_ip_member "$ip" "$m" 2>/dev/null || true)
      fi
    fi

    [[ -z "$ios_entry" ]] && continue

    local pcid pc_entry
    pcid="$(jq -r '(.portChannelId|tostring)? // ""' <<<"$ios_entry" 2>/dev/null || echo "")"
    if [[ -n "$pcid" ]]; then
      pc_entry="$(jq -c --arg pcid "$pcid" '
        select(.isPortChannel == true and (.portChannelId|tostring) == $pcid)
      ' "$intent_jsonl" 2>/dev/null | head -n1 || true)"
    fi
    [[ -n "$pc_entry" ]] || pc_entry='{}'

    local ios_if
    ios_if="$(jq -r '.interface // ""' <<<"$ios_entry" 2>/dev/null || echo "")"
    ios_if="$(trim "$ios_if")"

    local is_uplink=0
    if [[ -n "$ios_if" ]] && is_uplink_module_iface_for_ip "$ip" "$ios_if"; then
      is_uplink=1
    fi
    echo "  UPLINK-DECISION: portId=$pid ios_if=$ios_if is_uplink=$is_uplink" >>"$build_log"

    local uplink_note=""
    if [[ "$is_uplink" -eq 1 && "$nm_present" -eq 0 ]]; then
      uplink_note="WARN: IOS interface looks like uplink-module (* /1/*) but discovery reports no NM module"
      echo "  WARN: portId=$pid ios_if=$ios_if -> $uplink_note" >>"$build_log"
    fi

    local row
    row="$(
      jq -n \
        --arg deviceId "$cloud_id" \
        --argjson m  "$meraki_port" \
        --arg uplinkNote "$uplink_note" \
        --argjson i  "$ios_entry" \
        --argjson pc "$pc_entry" \
        --arg udldClass "$udld_class" \
        --arg globalUdld "$global_udld" \
        --argjson isUplink "$is_uplink" '
        def norm_name:
  (. // "")
  | tostring
  | gsub("[^A-Za-z0-9 .,_/-]"; "")
  | gsub(" +"; " ")
  | sub("^ +"; "")
  | sub(" +$"; "");

        def pick_vlan:
          if      ($i.accessVlan   // null) != null then $i.accessVlan
          elif    ($i.nativeVlan   // null) != null then $i.nativeVlan
          elif    ($pc.accessVlan  // null) != null then $pc.accessVlan
          elif    ($pc.nativeVlan  // null) != null then $pc.nativeVlan
          else ($m.vlan // null) end;

        def desired_stp:
          if   $i.stpGuard == "bpduGuard" then "bpdu guard"
          elif $i.stpGuard == "rootGuard" then "root guard"
          elif $i.stpGuard == "loopGuard" then "loop guard"
          elif ($i.portfast // false) == true then "disabled"
          else ($m.stpGuard // null) end;

        def desired_dot3az:
          if ($i | has("eeeEnabled")) then { enabled: $i.eeeEnabled }
          else { enabled: ($m.dot3az.enabled // null) } end;

        def desired_udld:
          if ($i | has("udld")) then
            $i.udld
          elif (($globalUdld // "") | tostring | length) > 0 then
            if ($udldClass == "A") then
              $globalUdld
            elif ($udldClass == "B") then
              if ($isUplink == 1) then $globalUdld else ($m.udld // null) end
            else
              ($m.udld // null)
            end
          else
            ($m.udld // null)
          end;

        def desired_type:
          ($i.type // $pc.type // $m.type);

        def desired_enabled:
          (if ($i | has("enabled")) then $i.enabled else $m.enabled end);

        def desired_voice:
          ($i.voiceVlan // $pc.voiceVlan // ($m.voiceVlan // null));

        def desired_allowed:
          ($i.allowedVlans // $pc.allowedVlans // ($m.allowedVlans // null));

        def desired_link:
          ($i.linkNegotiation // ($m.linkNegotiation // null));

        def desired_dai:
          ($i.daiTrusted // ($m.daiTrusted // false));

        def desired_poe:
          (if ($i | has("poeEnabled")) then $i.poeEnabled else ($m.poeEnabled // null) end);

        def desired_name:
          (
            if ($i.portChannelId != null) and (($pc.description // null) != null) then
              $pc.description
            elif (($i.description // null) != null) then
              $i.description
            else
              ($m.name // null)
            end
          ) | norm_name;

        {
          current_deviceId: $deviceId,
          current_cloud_id: $deviceId,

          # IMPORTANT: "current_serial" is retained for downstream LAG building,
          # but it is now the CLOUD ID (Meraki serial), NEVER the Cisco FCW serial.
          current_serial: $deviceId,

          portId: ($m.portId | tostring),
          interface: ($i.interface // ""),
          portChannelId: ($i.portChannelId // null),

          description_intent: ($i.description // null),
          description_current: ($m.name // null),

          current: {
            enabled: $m.enabled,
            type: $m.type,
            vlan: ($m.vlan // null),
            voiceVlan: ($m.voiceVlan // null),
            allowedVlans: ($m.allowedVlans // null),
            stpGuard: ($m.stpGuard // null),
            poeEnabled: ($m.poeEnabled // null),
            dot3az: ($m.dot3az.enabled // null),
            daiTrusted: ($m.daiTrusted // false),
            udld: ($m.udld // null),
            linkNegotiation: ($m.linkNegotiation // null)
          }
        }
        | .desired = {
            enabled: desired_enabled,
            type: desired_type,
            vlan: pick_vlan,
            voiceVlan: desired_voice,
            allowedVlans: desired_allowed,
            name: desired_name,
            stpGuard: desired_stp,
            dot3az: desired_dot3az,
            udld: desired_udld,
            linkNegotiation: desired_link,
            daiTrusted: desired_dai,
            poeEnabled: desired_poe
          }
        | .notes = (if ($uplinkNote|length) > 0 then [$uplinkNote] else [] end)
        | .changes = [
            (if .current.enabled != .desired.enabled then "enabled" else empty end),
            (if .current.type    != .desired.type    then "type"    else empty end),
            (if (.current.vlan // null) != (.desired.vlan // null) then "vlan" else empty end),
            (if (.current.voiceVlan // null) != (.desired.voiceVlan // null) then "voiceVlan" else empty end),
            (if (.current.allowedVlans // null) != (.desired.allowedVlans // null) then "allowedVlans" else empty end),
            (if (.current.stpGuard // null) != (.desired.stpGuard // null) then "stpGuard" else empty end),
            (if (.current.udld // null) != (.desired.udld // null) then "udld" else empty end),
            (if (.current.linkNegotiation // null) != (.desired.linkNegotiation // null) then "linkNegotiation" else empty end),
            (if (.current.poeEnabled // null) != (.desired.poeEnabled // null) then "poeEnabled" else empty end),
            (if (.current.dot3az // null) != (.desired.dot3az.enabled // null) then "dot3az" else empty end),
            (if (.current.daiTrusted // false) != (.desired.daiTrusted // false) then "daiTrusted" else empty end),
            (if ((.desired.name // "") | tostring | gsub("^ +| +$"; "")) == "" then
              empty
            elif (.description_current // null) != (.desired.name // null) then
              "name"
            else empty end)
          ]
      ' 2>>"$build_log"
    )" || row=""

    [[ -z "$row" ]] && continue

    if [[ $first_row -eq 1 ]]; then
      printf '%s\n' "$row" >"$ports_diff_json.tmp"
      first_row=0
    else
      printf '%s\n' "$row" >>"$ports_diff_json.tmp"
    fi
  done < <(jq -c '.[]' "$ports_current" 2>>"$build_log")

  if [[ ! -s "$ports_diff_json.tmp" ]]; then
    echo "[]" >"$ports_diff_json"
  else
    jq -s '.' "$ports_diff_json.tmp" >"$ports_diff_json" 2>>"$build_log" || {
      echo "ERROR: jq failed when wrapping diff rows into array." >>"$build_log"
      echo "jq diff build failed for $ip" >&2
      rm -f "$ports_diff_json.tmp"
      return 1
    }
  fi
  rm -f "$ports_diff_json.tmp" 2>/dev/null || true

  local count
  count="$(jq 'length' "$ports_diff_json" 2>/dev/null || echo 0)"
  echo "Step 4b: Diff contains $count port entries after merge." >>"$build_log"

  echo "Step 5: Writing summary → $ports_diff_txt" >>"$build_log"
  apply_ui_update "Writing summary report" 90

  {
    jq -r --arg ip "$ip" --arg dev "$cloud_id" '
      def show_val(x): if x == null then "(none)" else (x|tostring) end;

      map(select((.changes|length) > 0)) as $changed
      |
      "Port migration diff for IP " + $ip + " (deviceId " + $dev + ")",
      "======================================================================",
      "",
      "Only ports with changes are shown.",
      "Ports not listed already match the IOS intent.",
      "",
      (
        if ($changed|length) == 0 then
          "(No port-level changes detected.)"
        else
          $changed[] as $row
          | "Port " + ($row.portId|tostring)
              + (if ($row.interface // "") != "" then " (" + $row.interface + ")" else "" end)
              + (if ($row.desired.type // "") != "" then " [" + $row.desired.type + "]" else "" end)
              + " — " + (($row.changes|length)|tostring) + " change(s)",
            (
              $row.changes[] as $chg
              | if   $chg == "enabled" then
                  "  - Enabled: " + show_val($row.current.enabled) + " → " + show_val($row.desired.enabled)
                elif $chg == "type" then
                  "  - Port type: " + show_val($row.current.type) + " → " + show_val($row.desired.type)
                elif $chg == "vlan" then
                  "  - VLAN (access/native): " + show_val($row.current.vlan) + " → " + show_val($row.desired.vlan)
                elif $chg == "voiceVlan" then
                  "  - Voice VLAN: " + show_val($row.current.voiceVlan) + " → " + show_val($row.desired.voiceVlan)
                elif $chg == "allowedVlans" then
                  "  - Allowed VLANs: " + show_val($row.current.allowedVlans) + " → " + show_val($row.desired.allowedVlans)
                elif $chg == "stpGuard" then
                  "  - STP guard: " + show_val($row.current.stpGuard) + " → " + show_val($row.desired.stpGuard)
                elif $chg == "name" then
                  "  - Description: " + show_val($row.description_current) + " → " + show_val($row.desired.name)
                elif $chg == "udld" then
                  "  - UDLD: " + show_val($row.current.udld) + " → " + show_val($row.desired.udld)
                elif $chg == "linkNegotiation" then
                  "  - Link negotiation: " + show_val($row.current.linkNegotiation) + " → " + show_val($row.desired.linkNegotiation)
                elif $chg == "poeEnabled" then
                  "  - PoE: " + show_val($row.current.poeEnabled) + " → " + show_val($row.desired.poeEnabled)
                elif $chg == "dot3az" then
                  "  - EEE (dot3az): " + show_val($row.current.dot3az) + " → " + show_val($row.desired.dot3az.enabled)
                elif $chg == "daiTrusted" then
                  "  - Trusted DAI: " + show_val($row.current.daiTrusted) + " → " + show_val($row.desired.daiTrusted)
                else empty end
            ),
            ""
        end
      )
    ' "$ports_diff_json"

    jq -r '
      [ .[]
        | select(.portChannelId != null)
        | { pc: .portChannelId, member: (if (.interface // "") != "" then .interface else "port " + (.portId|tostring) end) }
      ] as $m
      | if ($m|length) == 0 then empty
        else
          "Port-channel membership summary:",
          ($m | group_by(.pc)[] | "Port-channel " + (.[0].pc|tostring) + ": " + (map(.member)|join(", ")))
        end
    ' "$ports_diff_json"
  } >"$ports_diff_txt"

  echo "SUCCESS: Build diff completed for $ip member $member" >>"$build_log"
  apply_ui_update "Diff build complete" 100

  exec 2>&2
  ui_stop
  trap - RETURN

  {
    echo "Intent JSONL:  $intent_jsonl"
    echo "Current ports: $ports_current"
    echo "Diff JSON:     $ports_diff_json"
    echo "Diff summary:  $ports_diff_txt"
  } >>"$build_log"

  return 0
}

# ============================================================
# Port-channels (Link Aggregations) – helpers + apply
# ============================================================

meraki_get_device_by_id() {
  local device_id="$1"  # <-- cloud_id (Meraki serial)
  local out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$device_id" ]] || { echo "No device_id provided" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/devices/${device_id}" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl rc=$rc getting device for deviceId=$device_id" >&2
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code getting device for deviceId=$device_id" >&2
    sed -n '1,60p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

meraki_get_network_link_aggs() {
  local network_id="$1"
  local out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$network_id" ]] || { echo "No network_id" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/networks/${network_id}/switch/linkAggregations" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl rc=$rc listing link aggs for networkId=$network_id" >&2
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code listing link aggs for networkId=$network_id" >&2
    sed -n '1,60p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

meraki_create_network_link_agg() {
  local network_id="$1"
  local body_json="$2"
  local out_json="$3"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$network_id" ]] || { echo "No network_id" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X POST "${api_base}/networks/${network_id}/switch/linkAggregations" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body_json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl rc=$rc creating link agg for networkId=$network_id" >&2
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code creating link agg for networkId=$network_id" >&2
    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

meraki_update_network_link_agg() {
  local network_id="$1"
  local lag_id="$2"
  local body_json="$3"
  local out_json="$4"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$network_id" ]] || { echo "No network_id" >&2; return 1; }
  [[ -n "$lag_id" ]] || { echo "No lag_id" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X PUT "${api_base}/networks/${network_id}/switch/linkAggregations/${lag_id}" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body_json"
  )" || rc=$?

  if (( rc != 0 )); then
    echo "curl rc=$rc updating link agg $lag_id for networkId=$network_id" >&2
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code updating link agg $lag_id for networkId=$network_id" >&2
    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}
# ------------------------------------------------------------
# Detect stack in IOS config (member indices > 1 appear)
# ------------------------------------------------------------
ios_cfg_implies_stack() {
  local cfg="$1"
  [[ -f "$cfg" ]] || return 1

  # Looks for interfaces like Gi2/0/1, Te3/0/48, Tw5/0/1, etc.
  # If any member number >= 2 exists => stack implied
  awk '
    $1=="interface" && match($2, /^[A-Za-z]+([0-9]+)\/0\/[0-9]+$/, m) {
      if (m[1]+0 >= 2) { found=1; exit }
    }
    END { exit(found?0:1) }
  ' "$cfg"
}

# ------------------------------------------------------------
# Meraki switch stacks API
# ------------------------------------------------------------
meraki_list_network_switch_stacks() {
  local network_id="$1"
  local out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  local tmp rc http_code
  tmp="$(mktemp)"; rc=0
  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/networks/${network_id}/switch/stacks" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?

  (( rc == 0 )) || { rm -f "$tmp"; return 1; }
  [[ "$http_code" =~ ^2 ]] || { rm -f "$tmp"; return 1; }

  mv "$tmp" "$out_json"
  return 0
}

# Return a stack name that is unique in the network.
# If "C9300-Stack1-Stack" exists, returns "C9300-Stack1-Stack-2", then -3, etc.
unique_stack_name_in_network() {
  local network_id="$1"
  local desired="$2"
  local log="${3:-/dev/null}"

  need jq || return 1

  desired="$(trim "$desired")"
  [[ -n "$desired" ]] || desired="AutoStack"

  local tmp
  tmp="$(mktemp)"

  if ! meraki_list_network_switch_stacks "$network_id" "$tmp" >>"$log" 2>&1; then
    rm -f "$tmp"
    # if we can't list stacks, fall back to desired
    printf '%s\n' "$desired"
    return 0
  fi

  # If desired name is unused, return it
  if ! jq -e --arg name "$desired" '.[]? | select((.name // "") == $name)' "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp"
    printf '%s\n' "$desired"
    return 0
  fi

  # Otherwise, find first available suffix -2..-99
  local n
  for n in $(seq 2 99); do
    local cand="${desired}-${n}"
    if ! jq -e --arg name "$cand" '.[]? | select((.name // "") == $name)' "$tmp" >/dev/null 2>&1; then
      rm -f "$tmp"
      printf '%s\n' "$cand"
      return 0
    fi
  done

  rm -f "$tmp"
  # last resort
  printf '%s\n' "${desired}-$(date +%s)"
  return 0
}

meraki_get_network_switch_stp() {
  local network_id="$1" out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  local tmp http_code rc=0
  tmp="$(mktemp)"
  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X GET "${api_base}/networks/${network_id}/switch/stp" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Accept: application/json"
  )" || rc=$?
  (( rc == 0 )) || { rm -f "$tmp"; return 1; }
  [[ "$http_code" =~ ^2 ]] || { rm -f "$tmp"; return 1; }
  mv "$tmp" "$out_json"
}

meraki_update_network_switch_stp() {
  local network_id="$1" body_json="$2" out_json="$3"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  local tmp http_code rc=0
  tmp="$(mktemp)"
  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X PUT "${api_base}/networks/${network_id}/switch/stp" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body_json"
  )" || rc=$?
  (( rc == 0 )) || { rm -f "$tmp"; return 1; }
  [[ "$http_code" =~ ^2 ]] || { rm -f "$tmp"; return 1; }
  mv "$tmp" "$out_json"
}

# Return stack id that contains ALL serials (cloud IDs), else empty
meraki_find_stack_id_for_serials() {
  local network_id="$1"
  local serials_json="$2"     # JSON array: ["Qxxx","Qyyy"]
  local out_var_name="${3:-}" # optional: name of var to set

  need jq || return 1
  local tmp stack_id=""
  tmp="$(mktemp)"

  if meraki_list_network_switch_stacks "$network_id" "$tmp" 2>/dev/null; then
    stack_id="$(
      jq -r --argjson want "$serials_json" '
        def set(a): (a|unique|sort);
        def contains_all(have; want):
          (set(have) as $H | set(want) as $W
           | ($W - $H) | length == 0);
        .[]?
        | select(contains_all(.serials // []; $want))
        | .id // empty
      ' "$tmp" | head -n1
    )"
  fi
  rm -f "$tmp" 2>/dev/null || true

  stack_id="$(trim "$stack_id")"
  if [[ -n "$out_var_name" ]]; then
    printf -v "$out_var_name" '%s' "$stack_id"
  else
    printf '%s\n' "$stack_id"
  fi
}

# Upsert (merge) STP bridge priority for a STACK id (Dashboard stack row)
# Preserves every other existing stpBridgePriority entry.
apply_network_stp_priority_for_stack_id() {
  local network_id="$1"
  local stp_priority="$2"
  local stack_id="$3"
  local serials_json="$4"
  local log="$5"

  need jq   || return 1
  need curl || return 1

  network_id="$(trim "$network_id")"
  stp_priority="$(trim "$stp_priority")"
  stack_id="$(trim "$stack_id")"

[[ -n "$network_id" ]] || { echo "STP: ERROR: network_id empty" >>"$log"; return 1; }
[[ -n "$stp_priority" ]] || { echo "STP: ERROR: stp_priority empty" >>"$log"; return 1; }
[[ -n "$stack_id" ]] || { echo "STP: ERROR: stack_id empty" >>"$log"; return 1; }

if ! jq -e . >/dev/null 2>&1 <<<"$serials_json"; then
  echo "STP: ERROR: serials_json invalid JSON: $serials_json" >>"$log"
  return 1
fi
if [[ "$(jq -r 'type' <<<"$serials_json" 2>/dev/null)" != "array" ]]; then
  echo "STP: ERROR: serials_json is not an array: $serials_json" >>"$log"
  return 1
fi

  echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – STP APPLY (STACK) networkId=$network_id stackId=$stack_id ====" >>"$log"
  echo "STP: targetStack=$stack_id priority=$stp_priority" >>"$log"

  local cur_file cur_json
  cur_file="$(mktemp)"
  if ! meraki_get_network_switch_stp "$network_id" "$cur_file" >>"$log" 2>&1; then
    echo "STP: FAILED to GET /networks/$network_id/switch/stp" >>"$log"
    rm -f "$cur_file" 2>/dev/null || true
    return 1
  fi
  cur_json="$(cat "$cur_file")"
  rm -f "$cur_file" 2>/dev/null || true

  # Remove any existing entry that references THIS stack_id, then append ours.
  local body
  body="$(
  jq -c --arg sid "$stack_id" --argjson prio "$stp_priority" --argjson S "$serials_json" '
    def set(a): (a|unique|sort);
    def overlaps(a;b):
      (set(a) as $A | set(b) as $B
       | ($A + $B) | group_by(.) | map(select(length>1)) | length) > 0;

    . as $cur
    | ($cur.rstpEnabled // true) as $rstp
    | ($cur.stpBridgePriority // []) as $prioArr
    | ($prioArr
        | map(
            if ((.stacks // []) | index($sid)) then empty
            elif overlaps((.switches // []); $S) then empty
            else .
            end
          )
      ) as $filtered
    | {
        rstpEnabled: $rstp,
        stpBridgePriority: (
          $filtered
          + [ { stacks: [$sid], stpPriority: $prio } ]
        )
      }
  ' <<<"$cur_json"
)"

  echo "STP: PUT body: $body" >>"$log"

  local out
  out="$(mktemp)"
  if meraki_update_network_switch_stp "$network_id" "$body" "$out" >>"$log" 2>&1; then
    echo "STP: SUCCESS (STACK) priority=$stp_priority stackId=$stack_id" >>"$log"
    rm -f "$out" 2>/dev/null || true
    return 0
  fi

  echo "STP: FAILED (STACK) priority=$stp_priority stackId=$stack_id" >>"$log"
  sed -n '1,120p' "$out" >>"$log" 2>/dev/null || true
  rm -f "$out" 2>/dev/null || true
  return 1
}

meraki_create_network_switch_stack() {
  local network_id="$1"
  local name="$2"
  local serials_json="$3"   # JSON array: ["Qxxx","Qyyy"]
  local out_json="$4"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  local body
  body="$(jq -c --arg name "$name" --argjson serials "$serials_json" \
    '{name:$name, serials:$serials}' <<<"{}")"

  local tmp rc http_code
  tmp="$(mktemp)"; rc=0
  http_code="$(
    curl -sS -w '%{http_code}' -o "$tmp" \
      -X POST "${api_base}/networks/${network_id}/switch/stacks" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body"
  )" || rc=$?

  (( rc == 0 )) || { rm -f "$tmp"; return 1; }
  [[ "$http_code" =~ ^2 ]] || { rm -f "$tmp"; return 1; }

  mv "$tmp" "$out_json"
  return 0
}

# ------------------------------------------------------------
# Ensure stack exists that contains ALL given serials
# (Create it if missing, then poll until present)
# ------------------------------------------------------------
ensure_dashboard_stack_for_serials() {
  local network_id="$1"
  local serials_json="$2"   # JSON array
  local log="$3"
  local stack_name="${4:-AutoStack-$network_id}"

# If the caller passed a friendly name (hostname-Stack), make it unique in this network.
# This avoids ugly IP-based names and prevents collisions.
stack_name="$(unique_stack_name_in_network "$network_id" "$stack_name" "$log" 2>/dev/null || echo "$stack_name")"
stack_name="$(trim "$stack_name")"

  need jq || return 1

  local tmp stacks stack_id
  tmp="$(mktemp)"

  echo "STACK: Ensuring stack exists for serials=$serials_json" >>"$log"

  # Try to find an existing stack containing all serials
  if meraki_list_network_switch_stacks "$network_id" "$tmp" >>"$log" 2>&1; then
    stack_id="$(
      jq -r --argjson want "$serials_json" '
        def set(a): (a|unique|sort);
        def contains_all(have; want):
          (set(have) as $H | set(want) as $W
           | ($W - $H) | length == 0);
        .[]?
        | select(contains_all(.serials // []; $want))
        | .id // empty
      ' "$tmp" | head -n1
    )"
  fi

  if [[ -n "${stack_id:-}" ]]; then
  echo "STACK: Found existing stack id=$stack_id" >>"$log"
  rm -f "$tmp"
  printf '%s\n' "$stack_id"
  return 0
fi

  # Create stack
  local created
  created="$(mktemp)"
  echo "STACK: No existing stack found; creating stack name='$stack_name'..." >>"$log"
  if ! meraki_create_network_switch_stack "$network_id" "$stack_name" "$serials_json" "$created" >>"$log" 2>&1; then
    echo "STACK: FAILED to create stack." >>"$log"
    rm -f "$tmp" "$created"
    return 1
  fi

  stack_id="$(jq -r '.id // empty' "$created" 2>/dev/null || true)"
  echo "STACK: Create returned id=${stack_id:-<unknown>} (polling until visible)..." >>"$log"
  rm -f "$created"

  # Poll until the stack shows up containing all serials (timing fix)
  local tries=20
  local t
  for ((t=1; t<=tries; t++)); do
    if meraki_list_network_switch_stacks "$network_id" "$tmp" >>"$log" 2>&1; then
      local ok
      ok="$(
        jq -r --argjson want "$serials_json" '
          def set(a): (a|unique|sort);
          def contains_all(have; want):
            (set(have) as $H | set(want) as $W
             | ($W - $H) | length == 0);
          [ .[]? | select(contains_all(.serials // []; $want)) ] | length
        ' "$tmp" 2>/dev/null || echo 0
      )"
      if [[ "$ok" == "1" ]]; then
  # pull id and return it
  stack_id="$(
    jq -r --argjson want "$serials_json" '
      def set(a): (a|unique|sort);
      def contains_all(have; want):
        (set(have) as $H | set(want) as $W
         | ($W - $H) | length == 0);
      .[]?
      | select(contains_all(.serials // []; $want))
      | .id // empty
    ' "$tmp" | head -n1
  )"
  stack_id="$(trim "$stack_id")"
  echo "STACK: Stack is now present (id=$stack_id)." >>"$log"
  rm -f "$tmp"
  printf '%s\n' "$stack_id"
  return 0
fi
    fi
    sleep 3
  done

  echo "STACK: Timed out waiting for stack to appear with all serials." >>"$log"
  rm -f "$tmp"
  return 1
}

# ------------------------------------------------------------
# Utility: get unique serials from lag_defs JSON
# ------------------------------------------------------------
serials_from_lag_defs() {
  local lag_defs="${1:-[]}"
  need jq || return 1
  jq -cr '[ .[]?.members[]?.serial ] | unique | sort' <<<"$lag_defs"
}
# Build LAG defs from member diff JSON files.
# IMPORTANT:
#   - Meraki linkAgg requires switchPorts[].serial
#   - In this script, "serial" == CLOUD_ID ONLY.
build_lag_defs_from_member_diffs() {
  need jq || return 1

  if (( $# < 1 )); then
    echo "[]" ; return 0
  fi

  jq -cs '
    add
    | [ .[] | select(.portChannelId != null) ]
    | map({
        pcid: (.portChannelId|tostring|gsub("[[:space:]]+";"")),
        member: {
          serial: ((.current_cloud_id // .current_deviceId // .current_serial // "") | tostring),
          portId: (.portId|tostring),
          interface: (.interface // "")
        }
      })
    | map(select(.member.serial != null and .member.serial != ""))
    | group_by(.pcid)
    | map({
        pcid: (.[0].pcid),
        members: (map(.member) | unique | sort_by(.serial, .portId))
      })
  ' "$@"
}
# Build LAG defs from a SINGLE member diff JSON file (one switch only).
# Output format matches build_lag_defs_from_member_diffs():
#   [{"pcid":"10","members":[{"serial":"Q5TD-...","portId":"20","interface":"..."}]}]
build_lag_defs_from_single_member_diff() {
  local diff_file="$1"
  need jq || return 1

  [[ -f "$diff_file" ]] || { echo "[]"; return 0; }

  jq -c '
    [ .[] | select(.portChannelId != null) ]
    | map({
        pcid: (.portChannelId|tostring|gsub("[[:space:]]+";"")),
        member: {
          serial: ((.current_cloud_id // .current_deviceId // .current_serial // "") | tostring),
          portId: (.portId|tostring),
          interface: (.interface // "")
        }
      })
    | map(select(.member.serial != null and .member.serial != ""))
    | group_by(.pcid)
    | map({
        pcid: (.[0].pcid),
        members: (map(.member) | unique | sort_by(.serial, .portId))
      })
  ' "$diff_file"
}

# (moved) stack ensure + lag apply is invoked from the flows (apply_port_diff_for_whole_stack / ensure_stack_lags_for_ip)


apply_link_aggs_from_lag_defs() {
  local network_id="$1"
  local lag_defs="$2"
  local apply_log="$3"

  need jq || return 1
  need curl || return 1

  if [[ -z "$network_id" ]]; then
    echo "LAG: ERROR: network_id is empty" >>"$apply_log"
    return 1
  fi

  if [[ -z "$lag_defs" || "$lag_defs" == "null" || "$lag_defs" == "[]" ]]; then
    echo "LAG: No LAG defs (empty). Nothing to do." >>"$apply_log"
    return 0
  fi

  echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – STACK LAG APPLY (networkId=$network_id) ====" >>"$apply_log"
  echo "LAG: Desired LAG defs: $lag_defs" >>"$apply_log"

  local existing_json
  existing_json="$(mktemp)"
  if ! meraki_get_network_link_aggs "$network_id" "$existing_json" >>"$apply_log" 2>&1; then
    echo "LAG: FAILED to list existing link aggregations for networkId=$network_id" >>"$apply_log"
    rm -f "$existing_json"
    return 1
  fi

  local dup_ports
  dup_ports="$(
    jq -r '
      [ .[] as $lag
        | $lag.members[]
        | {
            key: ("\(.serial // ""):\(.portId)"),
            serial: .serial,
            portId: (.portId|tostring),
            interface: (.interface // ""),
            pcid: ($lag.pcid|tostring)
          }
      ]
      | group_by(.key)
      | map(select(length > 1))
      | .[] | (
          .[0].key
          + (if (.[0].interface|length) > 0 then " (" + .[0].interface + ")" else "" end)
          + " appears in multiple port-channels: "
          + ([ .[].pcid ] | unique | sort | join(", "))
        )
    ' <<<"$lag_defs" 2>/dev/null || true
  )"

  if [[ -n "$dup_ports" ]]; then
    echo "LAG: ERROR - same port appears in multiple port-channels (invalid input). Aborting LAG changes." >>"$apply_log"
    while IFS= read -r d; do
      [[ -n "$d" ]] && echo "  - $d" >>"$apply_log"
    done <<<"$dup_ports"
    rm -f "$existing_json" 2>/dev/null || true
    return 1
  fi

  local count
  count="$(jq -r 'length' <<<"$lag_defs" 2>/dev/null || echo 0)"
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  if (( count == 0 )); then
    echo "LAG: No LAGs to apply." >>"$apply_log"
    rm -f "$existing_json"
    return 0
  fi

  local i
  for (( i=0; i<count; i++ )); do
    local pcid members members_key exact_match_id update_candidate_id body member_count

    pcid="$(jq -r ".[$i].pcid" <<<"$lag_defs")"
    members="$(jq -c ".[$i].members" <<<"$lag_defs")"
    member_count="$(jq -r 'length' <<<"$members")"
    if (( member_count < 2 )); then
      echo "LAG: SKIP pcid=$pcid (only $member_count member)" >>"$apply_log"
      continue
    fi

    members_key="$(jq -r '[ .[] | "\(.serial):\(.portId)" ] | sort | join(",")' <<<"$members")"

    echo "" >>"$apply_log"
    echo "LAG: Port-channel $pcid members_key=$members_key" >>"$apply_log"

    exact_match_id="$(
      jq -r --arg mk "$members_key" '
        .[]?
        | {id: (.id|tostring),
           mk: ([ .switchPorts[]? | "\(.serial):\(.portId)" ] | sort | join(","))
          }
        | select(.mk == $mk)
        | .id
      ' "$existing_json" 2>/dev/null | head -n1
    )"

    if [[ -n "${exact_match_id:-}" ]]; then
      echo "LAG: Port-channel $pcid already exists (id=$exact_match_id). Skipping." >>"$apply_log"
      continue
    fi

    update_candidate_id="$(
      jq -r --arg mk "$members_key" '
        def set(a): (a | split(",") | map(select(length>0)) | unique);
        def intersect(a;b):
          (set(a) as $A | set(b) as $B
           | ($A + $B) | group_by(.) | map(select(length>1)) | length);
        .[]?
        | {id: (.id|tostring),
           mk: ([ .switchPorts[]? | "\(.serial):\(.portId)" ] | sort | join(","))
          }
        | select(intersect(.mk; $mk) > 0)
        | .id
      ' "$existing_json" 2>/dev/null | head -n1
    )"

    body="$(jq -c '{switchPorts: (map({serial, portId}))}' <<<"$members")"
    echo "LAG: Request body for Port-channel $pcid: $body" >>"$apply_log"

    if [[ -n "${update_candidate_id:-}" ]]; then
      echo "LAG: Found existing LAG sharing members (id=$update_candidate_id). Updating to match Port-channel $pcid." >>"$apply_log"
      local out
      out="$(mktemp)"
      if meraki_update_network_link_agg "$network_id" "$update_candidate_id" "$body" "$out" >>"$apply_log" 2>&1; then
        echo "LAG: Updated LAG id=$update_candidate_id OK for Port-channel $pcid" >>"$apply_log"
      else
        echo "LAG: FAILED updating LAG id=$update_candidate_id for Port-channel $pcid" >>"$apply_log"
      fi
      rm -f "$out"
    else
      echo "LAG: Creating new LAG for Port-channel $pcid" >>"$apply_log"
      local out
      out="$(mktemp)"
      if meraki_create_network_link_agg "$network_id" "$body" "$out" >>"$apply_log" 2>&1; then
        local new_id
        new_id="$(jq -r '.id // empty' "$out" 2>/dev/null || true)"
        echo "LAG: Created new LAG id=${new_id:-<unknown>} for Port-channel $pcid" >>"$apply_log"
      else
        echo "LAG: FAILED creating LAG for Port-channel $pcid" >>"$apply_log"
      fi
      rm -f "$out"
    fi
  done

  rm -f "$existing_json" 2>/dev/null || true
  return 0
}

# ============================================================
# Apply diff → Meraki Dashboard
# ============================================================

find_latest_intent_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"
  local dir="${RUN_DIR:-}/ports"
  [[ -d "$dir" ]] || return 1
  ls -1t "$dir"/"${ip}"_*_m"${member}"_intent.jsonl 2>/dev/null | head -n1
}

find_latest_ports_diff_for_ip_member() {
  local ip="$1"
  local member="${2:-1}"
  local dir="${RUN_DIR:-}/ports"
  [[ -d "$dir" ]] || return 1
  ls -1t "$dir"/"${ip}"_*_m"${member}"_ports_diff.json 2>/dev/null | head -n1
}

find_latest_ports_diff_for_ip() {
  find_latest_ports_diff_for_ip_member "$1" "1"
}
ensure_stack_lags_for_ip() {
  local ip="$1"

  need jq || return 1

  local members=() m
  while IFS= read -r m; do
    m="$(trim "$m")"
    [[ -n "$m" ]] && members+=("$m")
  done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

  # only meaningful if stack has 2+ members
  ((${#members[@]} >= 2)) || return 0

  local -a diff_files=()
  local any_cloud_id="" id_line df

  for m in "${members[@]}"; do
    # must have identity
    if ! find_meraki_identity_for_ip_member "$ip" "$m" >/dev/null 2>&1; then
      continue
    fi

    df="$(find_latest_ports_diff_for_ip_member "$ip" "$m" 2>/dev/null || true)"
    df="$(trim "$df")"
    [[ -n "$df" ]] && diff_files+=("$df")

    if [[ -z "$any_cloud_id" ]]; then
      id_line="$(find_meraki_identity_for_ip_member "$ip" "$m" 2>/dev/null || true)"
      if [[ -n "$id_line" ]]; then
        IFS='|' read -r any_cloud_id _ <<<"$id_line"
        any_cloud_id="$(trim "$any_cloud_id")"
      fi
    fi
  done

  # need at least 2 member diffs to safely build LAGs
  ((${#diff_files[@]} >= 2)) || return 0
  [[ -n "$any_cloud_id" ]] || return 0

  local stack_apply_log="$RUN_DIR/devlogs/${ip}_stack_lag_apply.log"
  echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – STACK LAG APPLY (AUTO) for IP $ip ====" >>"$stack_apply_log"

  local dev_json network_id
  dev_json="$(mktemp)"
  network_id=""

  if meraki_get_device_by_id "$any_cloud_id" "$dev_json" >>"$stack_apply_log" 2>&1; then
    network_id="$(jq -r '.networkId // empty' "$dev_json" 2>/dev/null || true)"
  fi
  rm -f "$dev_json"
  network_id="$(trim "$network_id")"

  [[ -n "$network_id" ]] || {
    echo "LAG: Could not determine networkId (deviceId=$any_cloud_id). Skipping LAG apply." >>"$stack_apply_log"
    return 0
  }

    local lag_defs serials_json
  lag_defs="$(build_lag_defs_from_member_diffs "${diff_files[@]}")"

  serials_json="$(serials_from_lag_defs "$lag_defs" 2>/dev/null || echo '[]')"
  if [[ "$(jq -r 'length' <<<"$serials_json" 2>/dev/null || echo 0)" -ge 2 ]]; then
    ensure_dashboard_stack_for_serials "$network_id" "$serials_json" "$stack_apply_log" "$(build_stack_name_for_ip "$ip")" >/dev/null 2>&1 || true
  fi

  apply_link_aggs_from_lag_defs "$network_id" "$lag_defs" "$stack_apply_log" || true
  return 0
}

apply_ports_from_diff() {
  local ip="$1"
  local diff_file="$2"
  local member="${3:-1}"
  local apply_mode="${4:-SINGLE}"   # SINGLE | STACK

  need curl || return 1
  need jq   || return 1

  if [[ ! -f "$diff_file" ]]; then
    echo "Diff JSON not found: $diff_file" >&2
    return 1
  fi

  local id_line cloud_id model
  id_line="$(find_meraki_identity_for_ip_member "$ip" "$member" 2>/dev/null || true)"
  if [[ -z "$id_line" ]]; then
    echo "No meraki_memory entry found for IP $ip – cannot determine device identity." >&2
    return 1
  fi
  IFS='|' read -r cloud_id model <<<"$id_line"
  cloud_id="$(trim "$cloud_id")"
  model="$(trim "$model")"

  if [[ -z "$cloud_id" ]]; then
    echo "Cloud ID missing for IP $ip in meraki_memory – cannot apply." >&2
    return 1
  fi

  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"
  local apply_log="$RUN_DIR/devlogs/${ip}_m${member}_ports_apply.log"

  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Applying port diffs for IP $ip member $member (deviceId $cloud_id) ===="
    echo "Diff file: $diff_file"
  } >>"$apply_log"

  local tmp_list; tmp_list="$(mktemp)"

  _apply_cleanup() {
    ui_stop
    rm -f "${tmp_list:-}" 2>/dev/null || true
  }
  trap _apply_cleanup RETURN

  ui_start "Preparing port list for $ip member $member (cloud $cloud_id)" "$apply_log"
  apply_ui_update "Loading diff + preparing checklist..." 5

  # Stack LAGs are handled ONLY by the ALL-members flow.
# Do NOT auto-apply stack LAGs here (it causes retries / wrong timing).
# ensure_stack_lags_for_ip "$ip" >>"$apply_log" 2>&1 || true

  apply_ui_update "Building port checklist from diff..." 45

  jq -r '
    def show(x): if x == null or x == "" then "Auto negotiate" else (x|tostring) end;
    def haschg(k): (.changes | index(k)) != null;

    .[]
    | select((.changes|length) > 0)
    | [
        (.portId|tostring),
        (
          (.description_intent // "<no-desc>")
          + " | " + (if (.desired.type != null) then .desired.type else "" end)
          + " | " + (if (.desired.vlan != null) then "V" + (.desired.vlan|tostring) else "" end)
          + (if haschg("linkNegotiation") then
               " | Link: " + show(.current.linkNegotiation) + " → " + show(.desired.linkNegotiation)
             else
               ""
             end)
          + " | changes=" + ((.changes|length)|tostring)
        )
      ]
    | @tsv
  ' "$diff_file" >"$tmp_list"

  apply_ui_update "Preparing checklist entries..." 55

  if ! [[ -s "$tmp_list" ]]; then
    ui_stop
    "$DIALOG" --clear >/dev/null 2>&1 || true

    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No changes" \
        --msgbox "There are no ports with differences in:\n  $diff_file\n\nNothing to apply." 11 80
    return 0
  fi

  local -a items=()
  while IFS=$'\t' read -r pid label; do
    pid="$(trim "$pid")"
    [[ -z "$pid" ]] && continue
    items+=( "$pid" "$label" "on" )
  done <"$tmp_list"

  local term_rows term_cols height width listheight
  term_rows="$(tput lines 2>/dev/null || echo 30)"
  term_cols="$(tput cols  2>/dev/null || echo 120)"

  height=$(( term_rows - 6 )); (( height < 18 )) && height=18
  width=$(( term_cols - 6  )); (( width  < 110 )) && width=110
  (( width > 180 )) && width=180
  listheight=$(( height - 8 )); (( listheight < 8 )) && listheight=8
  (( listheight > 20 )) && listheight=20

  apply_ui_update "Opening port selection checklist..." 60
  ui_stop
  "$DIALOG" --clear >/dev/null 2>&1 || true

  local selection
  selection="$(
    dlg --backtitle "$BACKTITLE_PORTS" \
        --separate-output \
        --checklist "Select ports on IP $ip member $member (cloud $cloud_id) to apply to Meraki.\n(Use SPACE to toggle, ENTER when done.)" \
        "$height" "$width" "$listheight" \
        "${items[@]}"
  )" || return 1

  selection="$(trim "$selection")"
  if [[ -z "$selection" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No ports selected" \
        --msgbox "No ports were selected for apply.\n\nNothing changed." 9 70
    return 0
  fi

  local -a PORTS_TO_APPLY=()
  while IFS= read -r pid; do
    pid="$(trim "$pid")"
    [[ -n "$pid" ]] && PORTS_TO_APPLY+=("$pid")
  done <<<"$selection"

  echo "Ports selected to apply: ${PORTS_TO_APPLY[*]}" >>"$apply_log"

  ui_start "Applying ports for $ip (m${member}) cloud $cloud_id" "$apply_log"
  apply_ui_update "Starting port apply..." 0

  local p ok_count=0 fail_count=0 warn_count=0
  local total="${#PORTS_TO_APPLY[@]}"
  local idx=0

  for p in "${PORTS_TO_APPLY[@]}"; do
    ((idx++))
    local pct=$(( idx * 100 / (total == 0 ? 1 : total) ))

    apply_ui_update "Port $p ($idx/$total): preparing request" "$pct"
    {
      echo ""
      echo "--- Preparing patch for port $p ---"
    } >>"$apply_log"

    echo "Row debug for port $p:" >>"$apply_log"
    jq -c --arg pid "$p" \
      '.[] | select((.portId|tostring) == $pid) | {portId, changes, desired, portChannelId}' \
      "$diff_file" >>"$apply_log" 2>&1 || true

    local matched_count
    matched_count="$(jq -r --arg pid "$p" '[ .[] | select((.portId|tostring) == $pid) ] | length' "$diff_file" 2>/dev/null || echo 0)"
    if [[ "$matched_count" == "0" ]]; then
      echo "NO MATCH in diff_file for portId=$p (cannot compute body)" >>"$apply_log"
      ((fail_count++))
      continue
    fi

    local body
    body="$(
      jq -c --arg pid "$p" '
        def add(k; v): if v == null then . else . + { (k): v } end;

        .[]
        | select((.portId|tostring) == $pid)
        | . as $r
        | reduce ($r.changes[]) as $c ({};
            if ($c == "name" ) then
              add("name"; $r.desired.name)
            elif $c == "enabled"         then add("enabled";         $r.desired.enabled)
            elif $c == "type"            then add("type";            $r.desired.type)
            elif $c == "vlan"            then add("vlan";            $r.desired.vlan)
            elif $c == "voiceVlan"       then add("voiceVlan";       $r.desired.voiceVlan)
            elif $c == "allowedVlans" then
              (if ($r.desired.allowedVlans // "") == "all" then
                 add("allowedVlans"; "1-1000")
               else
                 add("allowedVlans"; $r.desired.allowedVlans)
               end)
            elif $c == "stpGuard"        then add("stpGuard";        $r.desired.stpGuard)
            elif $c == "udld" then
              (if ($r.desired.udld // "") == "Alert" then
                 add("udld"; "Alert only")
               else
                 add("udld"; $r.desired.udld)
               end)
            elif $c == "linkNegotiation" then add("linkNegotiation"; $r.desired.linkNegotiation)
            elif $c == "poeEnabled"      then add("poeEnabled";      $r.desired.poeEnabled)
            elif $c == "dot3az"          then add("dot3az";          $r.desired.dot3az)
            elif $c == "daiTrusted"      then add("daiTrusted";      $r.desired.daiTrusted)
            else . end
          )
      ' "$diff_file" | head -n1
    )"

    echo "Computed body for port $p: ${body:-<empty>}" >>"$apply_log"

    if [[ -z "$body" || "$body" == "null" || "$body" == "{}" ]]; then
      echo "Skipping port $p – computed empty PUT body (no applicable fields)." >>"$apply_log"
      apply_ui_update "Port $p: skipped (empty body)" "$pct"
      ((fail_count++))
      continue
    fi

    echo "PUT body for port $p: $body" >>"$apply_log"

    local tmp_resp code
    tmp_resp="$(mktemp)"

    code="$(
      curl -sS -o "$tmp_resp" -w "%{http_code}" \
        -X PUT "${api_base}/devices/${cloud_id}/switch/ports/${p}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$body"
    )" || code="000"

    if [[ "$code" =~ ^20[0-9]$ ]]; then
      echo "Port $p: SUCCESS (HTTP $code)" >>"$apply_log"
      apply_ui_update "Port $p: SUCCESS (HTTP $code)" "$pct"
      ((ok_count++))

      local warn_lines warned_this_port=0
      local is_lag_member
      is_lag_member="$(jq -r --arg pid "$p" '
        .[] | select((.portId|tostring) == $pid) | (.portChannelId != null)
      ' "$diff_file" 2>/dev/null | head -n1)"

      [[ "$is_lag_member" == "true" ]] && is_lag_member=1 || is_lag_member=0

      warn_lines="$(warn_if_meraki_ignored_fields "$body" "$tmp_resp" "$is_lag_member" 2>/dev/null || true)"

      if [[ -n "${warn_lines:-}" ]]; then
        echo "Port $p: WARNINGS (Meraki did not apply some fields):" >>"$apply_log"
        while IFS= read -r wl; do
          [[ -n "$wl" ]] && echo "  $wl" >>"$apply_log"
        done <<<"$warn_lines"
        warned_this_port=1
      fi

      if grep -qi "cannot verify" <<<"${warn_lines:-}"; then
        echo "Port $p: PUT response incomplete; verifying via GET..." >>"$apply_log"

        local verify_file warn_lines2
        verify_file="$(mktemp)"

        if meraki_get_switch_port_for_cloud_id "$cloud_id" "$p" "$verify_file" >>"$apply_log" 2>&1; then
          warn_lines2="$(warn_if_meraki_ignored_fields "$body" "$verify_file" "$is_lag_member" 2>/dev/null || true)"

          if [[ -n "${warn_lines2:-}" ]]; then
            echo "Port $p: WARNINGS after GET verify:" >>"$apply_log"
            while IFS= read -r wl; do
              [[ -n "$wl" ]] && echo "  $wl" >>"$apply_log"
            done <<<"$warn_lines2"
            warned_this_port=1
          else
            echo "Port $p: Verification OK after GET." >>"$apply_log"
            warned_this_port=0
          fi
        else
          echo "Port $p: GET verify failed; leaving original warnings." >>"$apply_log"
        fi

        rm -f "$verify_file" 2>/dev/null || true
      fi

      if [[ "$warned_this_port" -eq 1 ]]; then
        ((warn_count++))
      fi
    else
      echo "Port $p: FAILED (HTTP $code)" >>"$apply_log"
      apply_ui_update "Port $p: FAILED (HTTP $code)" "$pct"
      sed -n '1,60p' "$tmp_resp" >>"$apply_log" || true
      ((fail_count++))
    fi

    rm -f "$tmp_resp" 2>/dev/null || true
  done

  {
    echo
    echo "Summary: OK=$ok_count WARN=$warn_count FAIL=$fail_count"
  } >>"$apply_log"

  # ==========================================================
  # Post-ports steps:
  #   - SINGLE mode: apply network STP for THIS device + single-switch LAGs
  #   - STACK mode:  DO NOT do these here (whole-stack flow handles STP+LAG once)
  # ==========================================================
  if [[ "$apply_mode" == "SINGLE" ]]; then

    # ---- STP APPLY (NETWORK SCOPE) ----
    apply_ui_update "Applying NETWORK spanning-tree priority (from IOS-XE config)..." 98

    local dev_json network_id
    dev_json="$(mktemp)"
    network_id=""

    if meraki_get_device_by_id "$cloud_id" "$dev_json" >>"$apply_log" 2>&1; then
      network_id="$(jq -r '.networkId // empty' "$dev_json" 2>/dev/null || true)"
    fi
    rm -f "$dev_json" 2>/dev/null || true
    network_id="$(trim "$network_id")"

    if [[ -n "$network_id" ]]; then
      local intent_jsonl stp_pref serials_json
      intent_jsonl="$(intent_jsonl_from_diff_file "$diff_file")"

      stp_pref=""
      if [[ -f "$intent_jsonl" ]]; then
        stp_pref="$(get_ios_stp_priority_preferred_from_intent "$intent_jsonl")"
        stp_pref="$(trim "$stp_pref")"
      fi

      # Single device = apply to just this switch serial (cloud_id)
      serials_json="$(jq -c --arg s "$cloud_id" '[$s]' <<<"{}")"

      if [[ -n "$stp_pref" ]]; then
        echo "STP: IOS preferred priority (from intent) = $stp_pref" >>"$apply_log"
        apply_ui_update "Applying spanning-tree priority $stp_pref (this switch)..." 99
        apply_network_stp_priority_for_serials "$network_id" "$stp_pref" "$serials_json" "$apply_log" || true
        apply_ui_update "Spanning-tree priority applied (or merged) successfully." 99
      else
        echo "STP: No spanning-tree vlan priority found in IOS; skipping STP update." >>"$apply_log"
        apply_ui_update "No spanning-tree priority found in IOS config — skipping." 99
      fi
    else
      echo "STP: Could not determine networkId (deviceId=$cloud_id). Skipping STP update." >>"$apply_log"
      apply_ui_update "Could not determine networkId — skipping spanning-tree update." 99
    fi

    # ---- SINGLE-SWITCH LAG APPLY (POST-PORTS) ----
    apply_ui_update "Applying link aggregations (single-switch)..." 99

    if [[ -n "${network_id:-}" ]]; then
      local lag_defs
      lag_defs="$(build_lag_defs_from_single_member_diff "$diff_file")"
      echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – SINGLE LAG APPLY (POST-PORTS) for IP $ip member $member ====" >>"$apply_log"
      echo "LAG: Desired LAG defs: $lag_defs" >>"$apply_log"
      apply_link_aggs_from_lag_defs "$network_id" "$lag_defs" "$apply_log" || true
    else
      echo "LAG: No network_id; skipping single-switch LAG apply." >>"$apply_log"
    fi

  else
    echo "POST: apply_mode=$apply_mode -> skipping per-member STP/LAG (handled by whole-stack flow)." >>"$apply_log"
  fi

  apply_ui_update "Apply complete. OK=$ok_count WARN=$warn_count FAIL=$fail_count" 100
  ui_stop

  local msg="Port apply completed for IP $ip (member $member, cloud $cloud_id).\n\n\
Success:  $ok_count port(s)\n\
Warnings: $warn_count port(s)\n\
Failed:   $fail_count port(s)\n\n\
See log file for details:\n  $apply_log"

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Port apply results" \
      --msgbox "$msg" 15 80

  return 0
}

# ============================================================
# Stack member pickers
# ============================================================

pick_stack_member_for_ip() {
  local ip="$1"
  local -a items=()
  local m line cloud_id model label

  items+=( "ALL" "| apply/update the *entire* stack (members 1..N)" )

  while IFS= read -r m; do
    m="$(trim "$m")"
    [[ -n "$m" ]] || continue

    line="$(find_meraki_identity_for_ip_member "$ip" "$m" 2>/dev/null || true)"
    cloud_id=""; model=""
    if [[ -n "$line" ]]; then
      IFS='|' read -r cloud_id model <<<"$line"
    fi
    cloud_id="$(trim "$cloud_id")"
    model="$(trim "$model")"

    [[ -z "$cloud_id" ]] && cloud_id="(no-cloud-id)"
    [[ -z "$model" ]] && model="(unknown-model)"
    label=" | model $model | cloud $cloud_id"

    items+=( "$m" "$label" )
  done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Choose stack member" \
      --menu "Select which STACK MEMBER to operate on for IP $ip." \
      18 90 10 \
      "${items[@]}"
}

pick_switch_ip_from_run() {
  local -a items=()
  local i ip host id_line cloud_id model label

  for i in "${!PORTS_SELECTED_IPS[@]}"; do
    ip="${PORTS_SELECTED_IPS[$i]}"

    host="$(get_discovery_hostname_for_ip "$ip" 2>/dev/null || true)"
    host="$(trim "$host")"
    [[ -z "$host" ]] && host="(no-hostname)"

    id_line="$(find_meraki_identity_for_ip "$ip" 2>/dev/null || true)"
    cloud_id=""; model=""
    if [[ -n "$id_line" ]]; then
      IFS='|' read -r cloud_id model <<<"$id_line"
      cloud_id="$(trim "$cloud_id")"
      model="$(trim "$model")"
    fi
    [[ -z "$cloud_id" ]] && cloud_id="(no-cloud-id)"

    label=" | $host | $cloud_id"
    items+=( "$ip" "$label" )
  done

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Choose switch" \
      --menu "Select a switch (by IP) to work on." \
      20 70 12 \
      "${items[@]}"
}

# ============================================================
# High-level flows
# ============================================================

# ------------------------------------------------------------
# NEW: Non-interactive helpers (operate on a specific IP)
# ------------------------------------------------------------

build_port_diff_for_ip() {
  local ip="$1"
  ip="$(trim "$ip")"
  [[ -n "$ip" ]] || return 1

  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local cfg
  cfg="$(find_backup_cfg_for_ip "$ip" 2>/dev/null || true)"
  cfg="$(trim "$cfg")"

  if [[ -z "$cfg" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No backup config" \
        --msgbox "Could not find a valid backup config for IP $ip in:\n  $DISCOVERY_RESULTS_FILE\n\nEnsure discovery/backup has been run and backup_status is OK." 14 90
    return 1
  fi

  if [[ ! -f "$cfg" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Config file missing" \
        --msgbox "Backup entry found for IP $ip,\n but the local file does not exist:\n  $cfg\n\nVerify your BACKUP_LOCAL_BASE_DIR setting or TFTP path." 14 90
    return 1
  fi

  local base_name
  base_name="$(basename "$cfg" | sed 's/\..*$//')"

  local member_count
  member_count="$(get_stack_member_count_for_ip "$ip")"
  [[ "$member_count" =~ ^[0-9]+$ ]] || member_count=1
  (( member_count < 1 )) && member_count=1

  # Single switch
  if [[ "$member_count" -le 1 ]]; then
    if merge_ios_intent_with_meraki_ports "$ip" "$cfg" "1"; then
      local summary="$RUN_DIR/ports/${ip}_${base_name}_m1_ports_diff.txt"
      if [[ -f "$summary" ]]; then
        dlg --backtitle "$BACKTITLE_PORTS" \
            --title "Port diff built (member 1)" \
            --textbox "$summary" 30 120 || true
      fi
      return 0
    fi

    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Port diff failed" \
        --msgbox "Failed to build port diff for $ip (member 1).\n\nCheck logs under:\n  $RUN_DIR/devlogs\n\nAnd outputs under:\n  $RUN_DIR/ports" 14 90
    return 1
  fi

  # Stack: build all members we can
  local m failures=0 built=0
  while IFS= read -r m; do
    m="$(trim "$m")"
    [[ -n "$m" ]] || continue

    if ! find_meraki_identity_for_ip_member "$ip" "$m" >/dev/null 2>&1; then
      ((failures++))
      continue
    fi

    if merge_ios_intent_with_meraki_ports "$ip" "$cfg" "$m"; then
      ((built++))
    else
      ((failures++))
    fi
  done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

  if (( built == 0 )); then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Stack diff failed" \
        --msgbox "No stack member diffs were built for IP $ip.\n\nCheck logs under:\n  $RUN_DIR/devlogs" 13 90
    return 1
  fi

  # Optional: show viewer menu after build
  show_stack_diffs_menu "$ip" "$base_name" "$RUN_DIR/ports"
  return 0
}

apply_port_diff_for_ip() {
  local ip="$1"
  ip="$(trim "$ip")"
  [[ -n "$ip" ]] || return 1

  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local member_count
  member_count="$(get_stack_member_count_for_ip "$ip")"
  [[ "$member_count" =~ ^[0-9]+$ ]] || member_count=1
  (( member_count < 1 )) && member_count=1

  # If it's a stack, default to whole-stack apply (what you want for automation)
  if [[ "$member_count" -gt 1 ]]; then
    apply_port_diff_for_whole_stack "$ip"
    return $?
  fi

  # Single switch apply
  local diff_file
  diff_file="$(find_latest_ports_diff_for_ip_member "$ip" "1" 2>/dev/null || true)"
  diff_file="$(trim "$diff_file")"

  if [[ -z "$diff_file" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No diff found" \
        --msgbox "Could not find a ports_diff.json file for:\n\n  IP: $ip\n\nLooked under:\n  $RUN_DIR/ports\n\nRun the build step first." 15 90
    return 1
  fi

  apply_ports_from_diff "$ip" "$diff_file" "1" "SINGLE"
}

build_port_diff_for_one_switch() {
  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local ip
  ip="$(pick_switch_ip_from_run)" || return 1
  ip="$(trim "$ip")"

  build_port_diff_for_ip "$ip"
}

apply_port_diff_for_whole_stack() {
  local ip="$1"

  need jq || return 1

  # -----------------------------
  # Determine members
  # -----------------------------
  local members=()
  local m
  while IFS= read -r m; do
    m="$(trim "$m")"
    [[ -n "$m" ]] && members+=("$m")
  done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

  if ((${#members[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No stack members found" \
        --msgbox "Could not determine stack members for IP $ip." 10 70
    return 1
  fi

  if ! "$DIALOG" --backtitle "$BACKTITLE_PORTS" \
                 --title "Apply whole stack?" \
                 --yesno "This will apply the latest diff for EACH stack member for IP $ip.\n\nMembers: ${members[*]}\n\nContinue?" \
                 13 80; then
    return 0
  fi

  # -----------------------------
  # Build diff_files[] + pick any_cloud_id (CLOUD ONLY)
  # -----------------------------
  local -a diff_files=()
  local any_cloud_id=""
  local df id_line cloud_id_tmp

  for m in "${members[@]}"; do
    # require identity for this member
    if ! find_meraki_identity_for_ip_member "$ip" "$m" >/dev/null 2>&1; then
      continue
    fi

    df="$(find_latest_ports_diff_for_ip_member "$ip" "$m" 2>/dev/null || true)"
    df="$(trim "$df")"
    [[ -n "$df" ]] && diff_files+=("$df")

    if [[ -z "$any_cloud_id" ]]; then
      id_line="$(find_meraki_identity_for_ip_member "$ip" "$m" 2>/dev/null || true)"
      if [[ -n "$id_line" ]]; then
        IFS='|' read -r cloud_id_tmp _ <<<"$id_line"
        any_cloud_id="$(trim "$cloud_id_tmp")"
      fi
    fi
  done

    local stack_apply_log
  stack_apply_log="$RUN_DIR/devlogs/${ip}_stack_apply.log"
  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – WHOLE STACK APPLY for IP $ip ===="
    echo "Members: ${members[*]}"
    echo "Diff files: ${diff_files[*]:-<none>}"
    echo "Any cloud id: ${any_cloud_id:-<none>}"
  } >>"$stack_apply_log"

  # ------------------------------------------------------------
  # Whole-stack PRE-FLIGHT gauge (includes STP work)
  # IMPORTANT: Must STOP before per-member apply_ports_from_diff (it opens its own dialogs/gauges)
  # ------------------------------------------------------------
  ui_start "Whole stack preflight (STP + LAG prep) for $ip" "$stack_apply_log"
  apply_ui_update "Preflight: initializing..." 1

  _stack_preflight_cleanup() { ui_stop; }
  trap _stack_preflight_cleanup RETURN

    # -----------------------------
  # Determine network_id (once)
  # -----------------------------
  apply_ui_update "Preflight: determining Meraki networkId..." 5
  local network_id=""
  if [[ -n "$any_cloud_id" ]]; then
    local dev_json
    dev_json="$(mktemp)"
    if meraki_get_device_by_id "$any_cloud_id" "$dev_json" >>"$stack_apply_log" 2>&1; then
      network_id="$(jq -r '.networkId // empty' "$dev_json" 2>/dev/null || true)"
    fi
    rm -f "$dev_json" 2>/dev/null || true
    network_id="$(trim "$network_id")"
  fi

  if [[ -n "$network_id" ]]; then
    apply_ui_update "Preflight: networkId=$network_id" 10
  else
    apply_ui_update "Preflight: networkId not found (STP/LAG may be skipped)" 10
  fi

  # -----------------------------
  # PREP: build lag_defs + serials_json (cloud ids) now,
  # but APPLY LAGs AFTER per-member port PUTs.
  # -----------------------------
    apply_ui_update "Preflight: building stack LAG definitions..." 15
  local lag_defs="[]"
  local serials_json="[]"
  if ((${#diff_files[@]} >= 2)); then
    lag_defs="$(build_lag_defs_from_member_diffs "${diff_files[@]}")"
    serials_json="$(serials_from_lag_defs "$lag_defs" 2>/dev/null || echo '[]')"
  fi

  local _serial_count
  _serial_count="$(jq -r 'length' <<<"$serials_json" 2>/dev/null || echo 0)"
  apply_ui_update "Preflight: detected ${_serial_count} stack serial(s) for STP/LAG" 20

    # -----------------------------
  # STACK STP APPLY (ONCE, network scope) – before ports (under preflight gauge)
  # -----------------------------
  apply_ui_update "STP: evaluating IOS preferred bridge priority..." 30
  if [[ -n "$network_id" ]]; then
    local intent_jsonl stp_pref

    local m1_diff
    m1_diff="$(find_latest_ports_diff_for_ip_member "$ip" "1" 2>/dev/null || true)"
    m1_diff="$(trim "$m1_diff")"

    if [[ -n "$m1_diff" ]]; then
      intent_jsonl="$(intent_jsonl_from_diff_file "$m1_diff")"
      stp_pref=""
      if [[ -f "$intent_jsonl" ]]; then
        stp_pref="$(get_ios_stp_priority_preferred_from_intent "$intent_jsonl" 2>/dev/null || true)"
        stp_pref="$(trim "$stp_pref")"
      fi

            if [[ -n "$stp_pref" ]]; then
        apply_ui_update "STP: preferred priority=$stp_pref (preparing apply)..." 40
        # If we have >=2 serials, ensure stack exists and use stacks:[stackId]
                if [[ "$(jq -r 'length' <<<"$serials_json" 2>/dev/null || echo 0)" -ge 2 ]]; then
          apply_ui_update "STP: ensuring Dashboard stack exists (for stack-scoped STP entry)..." 55
          local stack_id=""
          stack_id="$(
           ensure_dashboard_stack_for_serials "$network_id" "$serials_json" "$stack_apply_log" "$(build_stack_name_for_ip "$ip")" 2>/dev/null
          )" || true
      stack_id="$(trim "$stack_id")"

if [[ -n "$stack_id" ]]; then
  echo "STP: Applying STACK priority using stackId=$stack_id pref=$stp_pref" >>"$stack_apply_log"
  apply_ui_update "STP: applying stack-scoped bridge priority (stackId=$stack_id)..." 70
  apply_network_stp_priority_for_stack_id "$network_id" "$stp_pref" "$stack_id" "$serials_json" "$stack_apply_log" || true
else
  echo "STP: Could not get stackId from ensure; skipping switch-scoped STP (stack members should be stack-scoped)." >>"$stack_apply_log"
fi
      else
          # Single device fallback
          echo "STP: Applying switch-scoped priority pref=$stp_pref" >>"$stack_apply_log"
          apply_ui_update "STP: applying switch-scoped bridge priority..." 70
          apply_network_stp_priority_for_serials "$network_id" "$stp_pref" "$serials_json" "$stack_apply_log" || true
        fi
            else
        echo "STP: No preferred priority found in intent; skipping STP update." >>"$stack_apply_log"
        apply_ui_update "STP: no preferred priority found — skipping" 70
      fi
        else
      echo "STP: No member-1 diff found; skipping STP update." >>"$stack_apply_log"
      apply_ui_update "STP: member-1 diff missing — skipping" 70
    fi
    else
    echo "STP: No network_id; skipping STP update." >>"$stack_apply_log"
    apply_ui_update "STP: networkId missing — skipping" 70
  fi

    # -----------------------------
  # APPLY PORT DIFFS per member
  # NOTE: stop preflight gauge before opening per-member dialogs/gauges
  # -----------------------------
  apply_ui_update "Preflight complete. Starting per-member port apply..." 85
  ui_stop
  trap - RETURN

  local ok=0 fail=0 skipped=0
  for m in "${members[@]}"; do
    if ! find_meraki_identity_for_ip_member "$ip" "$m" >/dev/null 2>&1; then
      ((skipped++))
      continue
    fi

    local diff_file
    diff_file="$(find_latest_ports_diff_for_ip_member "$ip" "$m" 2>/dev/null || true)"
    diff_file="$(trim "$diff_file")"

    if [[ -z "$diff_file" ]]; then
      ((skipped++))
      continue
    fi

        if apply_ports_from_diff "$ip" "$diff_file" "$m" "STACK"; then
      ((ok++))
    else
      ((fail++))
    fi
  done

  # -----------------------------
  # STACK LAG APPLY (AFTER PORTS)
  # Ensure Dashboard stack exists first (cloud ids), then apply link aggs.
  # -----------------------------
  if [[ -n "$network_id" ]] && [[ "$(jq -r 'length' <<<"$serials_json" 2>/dev/null || echo 0)" -ge 2 ]]; then
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – STACK LAG APPLY (POST-PORTS) for IP $ip ====" >>"$stack_apply_log"
    echo "LAG: serials_json=$serials_json" >>"$stack_apply_log"
    echo "LAG: lag_defs=$lag_defs" >>"$stack_apply_log"

    ensure_dashboard_stack_for_serials "$network_id" "$serials_json" "$stack_apply_log" "$(build_stack_name_for_ip "$ip")" >/dev/null 2>&1 || true
    apply_link_aggs_from_lag_defs "$network_id" "$lag_defs" "$stack_apply_log" || true
  else
    echo "LAG: Skipping post-ports LAG apply (need network_id and >=2 serials)." >>"$stack_apply_log"
  fi

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Whole stack apply complete" \
      --msgbox "Whole stack apply finished for IP $ip.\n\nOK:      $ok\nFailed:  $fail\nSkipped: $skipped\n\n(Skipped usually means: missing meraki_memory entry or no diff built for that member.)\n\nLog:\n  $stack_apply_log" \
      16 86

  return 0
}

apply_port_diff_for_one_switch() {
  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local ip
  ip="$(pick_switch_ip_from_run)" || return 1
  ip="$(trim "$ip")"

  apply_port_diff_for_ip "$ip"
}

# ============================================================
# Entry point
# ============================================================

run_auto_build_then_apply_from_checklist() {
  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  # Build checklist items (all ON)
  local -a items=()
  local ip host id_line cloud_id model label

  for ip in "${PORTS_SELECTED_IPS[@]}"; do
    ip="$(trim "$ip")"
    [[ -n "$ip" ]] || continue

    host="$(get_discovery_hostname_for_ip "$ip" 2>/dev/null || true)"
    host="$(trim "$host")"
    [[ -z "$host" ]] && host="(no-hostname)"

    id_line="$(find_meraki_identity_for_ip "$ip" 2>/dev/null || true)"
    cloud_id=""
    model=""
    if [[ -n "$id_line" ]]; then
      IFS='|' read -r cloud_id model <<<"$id_line"
      cloud_id="$(trim "$cloud_id")"
      model="$(trim "$model")"
    fi
    [[ -z "$cloud_id" ]] && cloud_id="(no-cloud-id)"

    label=" | $host | $cloud_id"
    items+=( "$ip" "$label" "on" )
  done

  if ((${#items[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No switches available" \
        --msgbox "No switches found in MIGRATE_SELECTED_IPS.\n\nRun the selection step in the main migration module first." 11 80
    return 1
  fi

  local term_rows term_cols height width listheight
  term_rows="$(tput lines 2>/dev/null || echo 30)"
  term_cols="$(tput cols  2>/dev/null || echo 120)"
  height=$(( term_rows - 6 )); (( height < 18 )) && height=18
  width=$(( term_cols - 6  )); (( width  < 110 )) && width=110
  (( width > 180 )) && width=180
  listheight=$(( height - 8 )); (( listheight < 8 )) && listheight=8
  (( listheight > 20 )) && listheight=20

  local selection
  selection="$(
    dlg --backtitle "$BACKTITLE_PORTS" \
        --separate-output \
        --checklist "Select switch(es) to process.\n\nFlow:\n  1) build-diff runs automatically\n  2) then apply-diff runs automatically\n\n(Use SPACE to toggle, ENTER when done.)" \
        "$height" "$width" "$listheight" \
        "${items[@]}"
  )" || return 0

  selection="$(trim "$selection")"
  if [[ -z "$selection" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Nothing selected" \
        --msgbox "No switches selected.\n\nNothing to do." 9 60
    return 0
  fi

  local -a IPS=()
  while IFS= read -r ip; do
    ip="$(trim "$ip")"
    [[ -n "$ip" ]] && IPS+=("$ip")
  done <<<"$selection"

  local ok=0 fail=0
  local ipx
  for ipx in "${IPS[@]}"; do
    # 1) build-diff
    if ! build_port_diff_for_ip "$ipx"; then
      ((fail++))
      continue
    fi

    # 2) apply-diff
    if apply_port_diff_for_ip "$ipx"; then
      ((ok++))
    else
      ((fail++))
    fi
  done

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Automation run complete" \
      --msgbox "Completed automated build+apply.\n\nOK:   $ok\nFAIL: $fail\n\n(FAIL usually means: missing backup config, missing meraki_memory identity, or no diff built.)" \
      14 70

  return 0
}

# ============================================================
# New main menu: show switch IPs directly (all ON)
# Selecting IP(s) runs build-diff -> apply-diff automatically
# ============================================================

auto_run_for_ip() {
  local ip="$1"

  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  # ---- find backup cfg for IP ----
  local cfg base_name
  cfg="$(find_backup_cfg_for_ip "$ip" 2>/dev/null || true)"
  cfg="$(trim "$cfg")"

  if [[ -z "$cfg" || ! -f "$cfg" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Missing config" \
        --msgbox "No valid backup config file found for:\n\n  IP: $ip\n\nExpected (from discovery_results.json):\n  $cfg\n\nRun discovery/backup first (backup_status must be OK)." \
        16 90
    return 1
  fi

  base_name="$(basename "$cfg" | sed 's/\..*$//')"

  # ---- build diffs (single or stack) ----
  local member_count
  member_count="$(get_stack_member_count_for_ip "$ip")"
  [[ "$member_count" =~ ^[0-9]+$ ]] || member_count=1
  (( member_count < 1 )) && member_count=1

  if (( member_count <= 1 )); then
    # single switch build
    merge_ios_intent_with_meraki_ports "$ip" "$cfg" "1" || return 1
  else
    # stack build: build all member diffs that have meraki_memory identity
    local m built=0
    while IFS= read -r m; do
      m="$(trim "$m")"
      [[ -n "$m" ]] || continue

      if ! find_meraki_identity_for_ip_member "$ip" "$m" >/dev/null 2>&1; then
        continue
      fi

      if merge_ios_intent_with_meraki_ports "$ip" "$cfg" "$m"; then
        ((built++))
      fi
    done < <(get_stack_members_for_ip "$ip" 2>/dev/null || printf '1\n')

    (( built > 0 )) || return 1
  fi

  # ---- apply (single or whole stack) ----
  if (( member_count <= 1 )); then
    local diff_file
    diff_file="$(find_latest_ports_diff_for_ip_member "$ip" "1" 2>/dev/null || true)"
    diff_file="$(trim "$diff_file")"
    [[ -n "$diff_file" ]] || return 1
    apply_ports_from_diff "$ip" "$diff_file" "1" "SINGLE"
  else
    apply_port_diff_for_whole_stack "$ip"
  fi
}

pick_switches_checklist_from_run() {
  local -a items=()
  local ip host id_line cloud_id model label

  for ip in "${PORTS_SELECTED_IPS[@]}"; do
    ip="$(trim "$ip")"
    [[ -n "$ip" ]] || continue

    host="$(get_discovery_hostname_for_ip "$ip" 2>/dev/null || true)"
    host="$(trim "$host")"
    [[ -z "$host" ]] && host="(no-hostname)"

    id_line="$(find_meraki_identity_for_ip "$ip" 2>/dev/null || true)"
    cloud_id=""; model=""
    if [[ -n "$id_line" ]]; then
      IFS='|' read -r cloud_id model <<<"$id_line"
      cloud_id="$(trim "$cloud_id")"
      model="$(trim "$model")"
    fi
    [[ -z "$cloud_id" ]] && cloud_id="(no-cloud-id)"

    # keep description short-ish, but useful
    label="$host | $cloud_id"
    items+=( "$ip" "$label" "on" )
  done

  # add exit option at bottom
  items+=( "exit" "Exit this tool" "off" )

  local term_rows term_cols height width listheight
  term_rows="$(tput lines 2>/dev/null || echo 30)"
  term_cols="$(tput cols  2>/dev/null || echo 120)"

  height=$(( term_rows - 6 )); (( height < 18 )) && height=18
  width=$(( term_cols - 6  )); (( width  < 90 )) && width=90
  (( width > 180 )) && width=180
  listheight=$(( height - 8 )); (( listheight < 8 )) && listheight=8
  (( listheight > 20 )) && listheight=20

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Select switch(es)" \
      --separate-output \
      --checklist "Select which switch IPs to process.\n(All are ON by default.)\n\nContinue = Build diff → Apply diff (automated)" \
      "$height" "$width" "$listheight" \
      "${items[@]}"
}

show_main_menu() {
  while :; do
    load_migrate_context || return 0
    load_meraki_api_key  || return 0

    local selection
    selection="$(pick_switches_checklist_from_run)" || return 0
    selection="$(trim "$selection")"

    # if they checked "exit"
    if grep -qx "exit" <<<"$selection"; then
      return 0
    fi

    # build list of selected IPs, ignoring "exit"
    local -a ips=()
    local line
    while IFS= read -r line; do
      line="$(trim "$line")"
      [[ -z "$line" ]] && continue
      [[ "$line" == "exit" ]] && continue
      ips+=( "$line" )
    done <<<"$selection"

    if ((${#ips[@]} == 0)); then
      dlg --backtitle "$BACKTITLE_PORTS" \
          --title "Nothing selected" \
          --msgbox "No switches selected.\n\nSelect at least one IP (or select Exit)." 10 70
      continue
    fi

    # quick confirm
    if ! "$DIALOG" --backtitle "$BACKTITLE_PORTS" \
                   --title "Run automated flow?" \
                   --yesno "This will run:\n\n  build-diff → apply-diff\n\nfor:\n  ${ips[*]}\n\nContinue?" \
                   14 90; then
      continue
    fi

    # run each selected switch
    local ip ok=0 fail=0
    for ip in "${ips[@]}"; do
      ip="$(trim "$ip")"
      [[ -n "$ip" ]] || continue

      if auto_run_for_ip "$ip"; then
        ((ok++))
      else
        ((fail++))
      fi
    done

    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Run complete" \
        --msgbox "Automated run complete.\n\nOK:     $ok\nFailed: $fail\n\n(Each switch has logs under: $RUN_DIR/devlogs)" \
        12 80
    # Automatically run Mgmt IP migration after port migration
       if (( ok > 0 )); then
       /root/.cloud_admin/per_switch_ip_migration.sh || true
fi
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-menu}"
  shift || true

  case "$cmd" in
    build-diff) build_port_diff_for_one_switch "$@" ;;
    apply-diff) apply_port_diff_for_one_switch "$@" ;;
    menu|*)     show_main_menu ;;
  esac
fi