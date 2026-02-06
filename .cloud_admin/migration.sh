#!/usr/bin/env bash
set -Euo pipefail

# ============================================================
# Shared helpers (dlg, trim, need)
# ============================================================

: "${DIALOG:=dialog}"

DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi

dlg() {
  local common=(--ok-label "Continue" --exit-label "Continue")

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


SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CLOUD_ADMIN_BASE="${CLOUD_ADMIN_BASE:-/root/.cloud_admin}"

# ============================================================
# Shared split-screen UI helpers (tailbox + gauge)
#   – single dialog instance, like IOS-XE upgrader
# ============================================================

VALIDATE_STATUS_FILE=""
VALIDATE_DIALOG_PID=""
VALIDATE_PROG_PIPE=""
VALIDATE_PROG_FD=""

validate_ui_start() {
  local backtitle="$1"
  local title="$2"
  local status_file="$3"

  VALIDATE_STATUS_FILE="$status_file"
  : >"$VALIDATE_STATUS_FILE"

  # Calculate layout based on terminal size
  local rows cols
  read -r rows cols < <(stty size 2>/dev/null || echo "24 80")

  local TOP_MARGIN LEFT_MARGIN GAUGE_H TAIL_H TAIL_W GAUGE_ROW GAUGE_COL
  TOP_MARGIN=${UI_TOP_MARGIN:-2}
  LEFT_MARGIN=${UI_LEFT_MARGIN:-2}

  GAUGE_H=6
  TAIL_H=$(( rows - TOP_MARGIN - GAUGE_H - 3 ))
  (( TAIL_H < 10 )) && TAIL_H=10

  TAIL_W=$(( cols - LEFT_MARGIN - 2 ))
  (( TAIL_W < 70 )) && TAIL_W=70

  GAUGE_ROW=$(( TOP_MARGIN + TAIL_H + 1 ))
  GAUGE_COL=$LEFT_MARGIN

  # Named pipe for gauge progress
  VALIDATE_PROG_PIPE="$(mktemp -u)"
  mkfifo "$VALIDATE_PROG_PIPE"
  exec {VALIDATE_PROG_FD}<>"$VALIDATE_PROG_PIPE"

  # One dialog instance with tailboxbg + gauge
  (
    "$DIALOG" \
      --backtitle "$backtitle" \
      --begin "$TOP_MARGIN" "$LEFT_MARGIN" \
      --title "$title" \
      --tailboxbg "$VALIDATE_STATUS_FILE" "$TAIL_H" "$TAIL_W" \
      --and-widget \
      --begin "$GAUGE_ROW" "$GAUGE_COL" \
      --title "Meraki connect – progress" \
      --gauge "Starting…" "$GAUGE_H" "$TAIL_W" 0 <"$VALIDATE_PROG_PIPE"
  ) &
  VALIDATE_DIALOG_PID=$!

  # Small kick so the gauge paints
  sleep 0.2
  # Initial 1% bar
  if [[ -n "$VALIDATE_PROG_FD" ]]; then
    printf 'XXX\n1\nStarting…\nXXX\n' >&"$VALIDATE_PROG_FD" 2>/dev/null || true
  fi
}

validate_ui_status() {
  local msg="$1"
  [[ -z "${VALIDATE_STATUS_FILE:-}" ]] && return 0
  printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$msg" >>"$VALIDATE_STATUS_FILE"
}

validate_ui_gauge() {
  local pct="${1:-0}"
  local text="${2:-}"
  if [[ -n "$VALIDATE_PROG_FD" ]]; then
    printf 'XXX\n%s\n%s\nXXX\n' "$pct" "${text:-Working…}" >&"$VALIDATE_PROG_FD" 2>/dev/null || true
  else
    # Fallback if dialog/gauge is not active
    echo "[progress] $pct% - $text"
  fi
}

validate_ui_stop() {
  if [[ -n "${VALIDATE_PROG_FD:-}" ]]; then
    # Try to show 100% before closing
    printf 'XXX\n100\nDone.\nXXX\n' >&"$VALIDATE_PROG_FD" 2>/dev/null || true
    exec {VALIDATE_PROG_FD}>&- 2>/dev/null || true
  fi
  if [[ -n "${VALIDATE_PROG_PIPE:-}" ]]; then
    rm -f "$VALIDATE_PROG_PIPE" 2>/dev/null || true
  fi
  if [[ -n "${VALIDATE_DIALOG_PID:-}" ]]; then
    kill "$VALIDATE_DIALOG_PID" 2>/dev/null || true
    wait "$VALIDATE_DIALOG_PID" 2>/dev/null || true
  fi
  VALIDATE_STATUS_FILE=""
  VALIDATE_DIALOG_PID=""
  VALIDATE_PROG_PIPE=""
  VALIDATE_PROG_FD=""
}

# ============================================================
# Global Meraki logging + "createnetworks" run structure
# ============================================================

MERAKI_LOG_FILE=""

CREATE_NET_RUN_ROOT=""
CREATE_NET_RUN_ID=""
CREATE_NET_RUN_DIR=""
CREATE_NET_LOG=""
CREATE_NET_CSV=""
# Optional context for Meraki logging (org/network friendly names)
MERAKI_CTX_ORG_ID=""
MERAKI_CTX_ORG_NAME=""
MERAKI_CTX_NET_ID=""
MERAKI_CTX_NET_NAME=""

init_createnetwork_run() {
  local org_id="$1" org_name="$2"

  # Only initialize once per script run
  if [[ -n "${CREATE_NET_RUN_DIR:-}" ]]; then
    return 0
  fi

  local RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/createnetworks"
  mkdir -p "$RUN_ROOT"

  local RUN_ID="createnetwork-$(date -u +%Y%m%d%H%M%S)"
  local RUN_DIR="$RUN_ROOT/$RUN_ID"
  mkdir -p "$RUN_DIR/devlogs"

  local LOG_FILE="$RUN_DIR/meraki_create_network.log"
  local CSV_FILE="$RUN_DIR/created_networks.csv"

  # CSV header
  echo "created_at_utc,org_id,org_name,network_id,network_name,product_types,address,url" >"$CSV_FILE"

  # latest.env + symlinks (mirrors runs/migrate layout)
  local LATEST_ENV="$RUN_ROOT/latest.env"
  {
    echo "# Generated by create-network wizard on $(date +'%Y-%m-%d %H:%M:%S %Z')"
    printf 'export CREATENET_RUN_ID=%q\n' "$RUN_ID"
    printf 'export CREATENET_RUN_DIR=%q\n' "$RUN_DIR"
    printf 'export CREATENET_LOG=%q\n' "$LOG_FILE"
    printf 'export CREATENET_CREATED_CSV=%q\n' "$CSV_FILE"
    printf 'export CREATENET_ORG_ID=%q\n' "$org_id"
    printf 'export CREATENET_ORG_NAME=%q\n' "$org_name"
  } >"$LATEST_ENV"

  ln -sfn "$RUN_DIR"   "$RUN_ROOT/latest"
  ln -sfn "$CSV_FILE"  "$RUN_ROOT/latest_created_networks.csv"
  ln -sfn "$LOG_FILE"  "$RUN_ROOT/latest_meraki_create_network.log"

  CREATE_NET_RUN_ROOT="$RUN_ROOT"
  CREATE_NET_RUN_ID="$RUN_ID"
  CREATE_NET_RUN_DIR="$RUN_DIR"
  CREATE_NET_LOG="$LOG_FILE"
  CREATE_NET_CSV="$CSV_FILE"

  # default Meraki log for this flow
  MERAKI_LOG_FILE="$CREATE_NET_LOG"
}
# ============================================================
# Phase 1 – multi-switch selector (from preflight)
# ============================================================

cloud_migration_select_switches() {
  local BACKTITLE="Cloud Migration – Select IOS-XE switches to convert"

  local PREFLIGHT_OK="${CLOUD_ADMIN_BASE}/preflight.ok"
  local SELECTED_ENV="${CLOUD_ADMIN_BASE}/selected_upgrade.env"
  local DISC_JSON="${CLOUD_ADMIN_BASE}/discovery_results.json"
  local SELECTED_JSON="${CLOUD_ADMIN_BASE}/selected_upgrade.json"

  # ---------- 1) Gate on preflight.ok ----------
  if [[ ! -f "$PREFLIGHT_OK" ]]; then
    dlg --backtitle "$BACKTITLE" \
        --title "Preflight not completed" \
        --msgbox "The IOS-XE configuration preflight step has not been completed.\n\nMissing file:\n  $PREFLIGHT_OK\n\nRun the \"Validate IOS-XE configuration\" step first,\nthen re-run this option." 13 78
    return 1
  fi

  # ---------- 2) Ensure selected_upgrade.env exists ----------
  if [[ ! -f "$SELECTED_ENV" ]]; then
    dlg --backtitle "$BACKTITLE" \
        --title "Preflight selection not found" \
        --msgbox "Could not find the preflight selection file:\n  $SELECTED_ENV\n\nThis file should be created by the Validate IOS-XE configuration step.\nRun that step again, then re-run this option." 13 78
    return 1
  fi

  # ---------- 3) Load UPGRADE_* variables ----------
  set +H
  # shellcheck disable=SC1090
  source "$SELECTED_ENV"
  set -H 2>/dev/null || true

  local BASE_ENV="${UPGRADE_BASE_ENV:-}"
  local SELECTED_IPS_RAW="${UPGRADE_SELECTED_IPS:-}"

  if [[ -z "$SELECTED_IPS_RAW" ]]; then
    dlg --backtitle "$BACKTITLE" \
        --title "No switches selected" \
        --msgbox "UPGRADE_SELECTED_IPS is empty in:\n  $SELECTED_ENV\n\nThe preflight step did not record any switches to migrate.\nRun the Validate IOS-XE configuration / selection step again." 13 78
    return 1
  fi

  local -a IP_LIST=()
  read -r -a IP_LIST <<<"$SELECTED_IPS_RAW"

  if ((${#IP_LIST[@]} == 0)); then
    dlg --backtitle "$BACKTITLE" \
        --title "No switches found" \
        --msgbox "No IPs were parsed from UPGRADE_SELECTED_IPS.\nRaw value:\n  $SELECTED_IPS_RAW\n\nCheck ${SELECTED_ENV} for formatting issues." 13 80
    return 1
  fi

  # ---------- 4) Enrich from discovery_results.json + selected_upgrade.json ----------
  need jq || return 1

  declare -A HOST_MAP PID_MAP SERIAL_MAP

  if [[ -s "$DISC_JSON" ]]; then
    while IFS=$'\t' read -r ip host pid serial; do
      ip="$(trim "$ip")"
      [[ -z "$ip" ]] && continue
      HOST_MAP["$ip"]="$(trim "$host")"
      PID_MAP["$ip"]="$(trim "$pid")"
      SERIAL_MAP["$ip"]="$(trim "$serial")"
    done < <(
      jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' \
        "$DISC_JSON" 2>/dev/null || true
    )
  fi

  if [[ -s "$SELECTED_JSON" ]]; then
    while IFS=$'\t' read -r ip host pid serial; do
      ip="$(trim "$ip")"
      [[ -z "$ip" ]] && continue
      [[ -z "${HOST_MAP[$ip]:-}" ]]   && HOST_MAP["$ip"]="$(trim "$host")"
      [[ -z "${PID_MAP[$ip]:-}" ]]    && PID_MAP["$ip"]="$(trim "$pid")"
      [[ -z "${SERIAL_MAP[$ip]:-}" ]] && SERIAL_MAP["$ip"]="$(trim "$serial")"
    done < <(
      jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' \
        "$SELECTED_JSON" 2>/dev/null || true
    )
  fi

  # ---------- 5) Build checklist (multi-select) ----------
  local -a items=()
  local ip h p s label
  for ip in "${IP_LIST[@]}"; do
    h="${HOST_MAP[$ip]:-<unknown>}"
    p="${PID_MAP[$ip]:--}"
    s="${SERIAL_MAP[$ip]:--}"
    printf -v label "%-15s %-24s %-12s %s" "$ip" "$h" "$p" "$s"
    # Default all to "on" so user can just hit ENTER to migrate all
    items+=( "$ip" "$label" "on" )
  done

  if ((${#items[@]} == 0)); then
    dlg --backtitle "$BACKTITLE" \
        --title "No switches to show" \
        --msgbox "There are no switches in UPGRADE_SELECTED_IPS after parsing.\n\nCheck ${SELECTED_ENV} and rerun the preflight step." 11 80
    return 1
  fi

  local selection
  selection="$(
    dlg --separate-output \
        --backtitle "$BACKTITLE" \
        --title "Select switches to migrate" \
        --checklist "These switches passed the IOS-XE preflight validation.\n\nSelect one or more switches to include in THIS migration run.\n(Use SPACE to toggle, ENTER when done.)" \
        22 110 14 \
        "${items[@]}"
  )" || return 1

  selection="$(trim "$selection")"
  if [[ -z "$selection" ]]; then
    dlg --backtitle "$BACKTITLE" \
        --title "No switches selected" \
        --msgbox "No switches were selected for migration.\n\nNothing to do." 10 60
    return 1
  fi

  local -a SEL_IPS=()
  mapfile -t SEL_IPS <<<"$selection"

  # ---------- 6) Create runs/migrate structure ----------
  local RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/migrate"
  mkdir -p "$RUN_ROOT"

  local RUN_ID="migrate-$(date -u +%Y%m%d%H%M%S)"
  local RUN_DIR="$RUN_ROOT/$RUN_ID"
  mkdir -p "$RUN_DIR/devlogs"

  local SUMMARY_CSV="$RUN_DIR/selection_summary.csv"
  echo "ip,hostname,pid,serial,selected_for_migration" >"$SUMMARY_CSV"

  # helper: is IP in SEL_IPS?
  local sel flag
  for ip in "${IP_LIST[@]}"; do
    h="${HOST_MAP[$ip]:-}"
    p="${PID_MAP[$ip]:-}"
    s="${SERIAL_MAP[$ip]:-}"
    flag="no"
    for sel in "${SEL_IPS[@]}"; do
      if [[ "$sel" == "$ip" ]]; then
        flag="yes"
        break
      fi
    done
    printf '%s,%s,%s,%s,%s\n' "$ip" "$h" "$p" "$s" "$flag" >>"$SUMMARY_CSV"
  done

  local SUMMARY_TXT="$RUN_DIR/selection_summary.txt"
  {
    echo "Cloud Migration – Switch selection"
    echo "=================================="
    echo
    echo "All switches from preflight selection:"
    echo
    printf "%-16s %-24s %-12s %-16s %-8s\n" \
      "IP" "Hostname" "PID" "Serial" "Selected"
    printf "%-16s %-24s %-12s %-16s %-8s\n" \
      "----------------" "------------------------" "------------" "----------------" "--------"
    for ip in "${IP_LIST[@]}"; do
      h="${HOST_MAP[$ip]:-<unknown>}"
      p="${PID_MAP[$ip]:--}"
      s="${SERIAL_MAP[$ip]:--}"
      flag="no"
      for sel in "${SEL_IPS[@]}"; do
        if [[ "$sel" == "$ip" ]]; then
          flag="yes"
          break
        fi
      done
      printf "%-16s %-24s %-12s %-16s %-8s\n" \
        "$ip" "$h" "$p" "$s" "$flag"
    done
    echo
    echo "Selected switches for this migration run:"
    for sel in "${SEL_IPS[@]}"; do
      h="${HOST_MAP[$sel]:-<unknown>}"
      p="${PID_MAP[$sel]:--}"
      s="${SERIAL_MAP[$sel]:--}"
      printf "  - %-16s %-24s %-12s %-16s\n" "$sel" "$h" "$p" "$s"
    done
    echo
    echo "Run directory:"
    echo "  $RUN_DIR"
  } >"$SUMMARY_TXT"

  local LATEST_ENV="$RUN_ROOT/latest.env"
  {
    printf 'export MIGRATE_RUN_ID=%q\n' "$RUN_ID"
    printf 'export MIGRATE_RUN_DIR=%q\n' "$RUN_DIR"
    printf 'export MIGRATE_SELECTION_CSV=%q\n' "$SUMMARY_CSV"
    printf 'export MIGRATE_SELECTED_IPS=%q\n' "${SEL_IPS[*]}"
    printf 'export MIGRATE_SELECTED_ENV=%q\n' "$SELECTED_ENV"
    printf 'export MIGRATE_BASE_ENV=%q\n' "${BASE_ENV:-}"
  } >"$LATEST_ENV"

  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"
  ln -sfn "$SUMMARY_CSV" "$RUN_ROOT/latest_selection.csv"

  dlg --backtitle "$BACKTITLE" \
      --title "Switch selection saved" \
      --textbox "$SUMMARY_TXT" 24 120 || true

  return 0
}

# ============================================================
# Phase 2 – Meraki org/network mapper for selected switches
#           (multi-switch, multi-network)
# ============================================================

cloud_migration_map_selected_switches() {
  local BACKTITLE_M="Meraki mapping – map selected IOS-XE switches"
  local RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/migrate"
  local LATEST_ENV="$RUN_ROOT/latest.env"
  local DISC_JSON="${CLOUD_ADMIN_BASE}/discovery_results.json"
  local SELECTED_JSON="${CLOUD_ADMIN_BASE}/selected_upgrade.json"

  need curl || return 1
  need jq   || return 1

  # ---------- 1) Load latest selection info ----------
  if [[ ! -f "$LATEST_ENV" ]]; then
    dlg --backtitle "$BACKTITLE_M" \
        --title "No selection found" \
        --msgbox "Could not find a migration selection run.\n\nMissing file:\n  $LATEST_ENV\n\nRun the switch selection step first." 12 80
    return 1
  fi

  set +H
  # shellcheck disable=SC1090
  source "$LATEST_ENV"
  set -H 2>/dev/null || true

  local RUN_ID="${MIGRATE_RUN_ID:-}"
  local RUN_DIR="${MIGRATE_RUN_DIR:-}"
  local SEL_IPS_RAW="${MIGRATE_SELECTED_IPS:-}"

  if [[ -z "$RUN_DIR" || -z "$SEL_IPS_RAW" ]]; then
    dlg --backtitle "$BACKTITLE_M" \
        --title "Incomplete selection" \
        --msgbox "latest.env does not contain a list of selected switches.\n\nRun the switch selection step again." 12 80
    return 1
  fi
  mkdir -p "$RUN_DIR"

  local -a SEL_IPS=()
  read -r -a SEL_IPS <<<"$SEL_IPS_RAW"
  if ((${#SEL_IPS[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_M" \
        --title "No selected switches" \
        --msgbox "MIGRATE_SELECTED_IPS is empty in latest.env.\n\nRun the switch selection step again." 11 80
    return 1
  fi

  # ---------- 2) Find ENV file with MERAKI_API_KEY ----------
  local ENV_FILE=""
  if [[ -n "${1:-}" && "${1:-}" != "-h" && "${1:-}" != "--help" ]]; then
    ENV_FILE="$1"
  else
    local base_dir="$CLOUD_ADMIN_BASE"
    local -a CANDIDATES=(
      "$base_dir/meraki_discovery.env"
      "$base_dir/meraki.env"
      "$base_dir/.env"
      "$base_dir/ENV"
    )
    while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$base_dir/*.env" 2>/dev/null || true)

    for f in "${CANDIDATES[@]}"; do
      [[ -f "$f" && -r "$f" ]] || continue
      if grep -Eq '(^|\s)(export\s+)?MERAKI_API_KEY=' "$f"; then
        ENV_FILE="$f"
        break
      fi
    done
  fi

  if [[ -z "$ENV_FILE" ]]; then
    dlg --backtitle "$BACKTITLE_M" \
        --title "Meraki ENV not found" \
        --msgbox "Could not find an ENV-like file with MERAKI_API_KEY in:\n  $CLOUD_ADMIN_BASE\n\nCreate meraki_discovery.env / meraki.env or pass a path to this script." 13 80
    return 1
  fi

  # ---------- 3) Load API key ----------
  set +H
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set -H 2>/dev/null || true
  : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"

  MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"

  local API_BASE="https://api.meraki.com/api/v1"
  local AUTH_MODE="${AUTH_MODE:-auto}"

  local TMPDIR
  TMPDIR="$(mktemp -d)"

  _mask_key() {
    local k="$1"; local n=${#k}
    [[ $n -gt 8 ]] && echo "${k:0:4}…${k: -4} (len=$n)" || echo "(len=$n)"
  }

  _do_curl() {
    local method="$1" path="$2" body="${3:-}" query="${4:-}" mode="$5"
    local hdr="$TMPDIR/hdr.$$" bodyf="$TMPDIR/body.$$"
    local -a H; H=(-H "Accept: application/json")
    if [[ "$mode" == "x-cisco" ]]; then
      H+=(-H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY")
    else
      H+=(-H "Authorization: Bearer $MERAKI_API_KEY")
    fi
    [[ -n "$body" ]] && H+=(-H "Content-Type: application/json")

    if [[ -n "$body" ]]; then
      curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' -X "$method" "${H[@]}" \
        "$API_BASE$path$query" --data "$body"
    else
      curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' -X "$method" "${H[@]}" \
        "$API_BASE$path$query"
    fi
  }

    _meraki_call() {
    local method="$1" path="$2" body="${3:-}" query="${4:-}"
    local code mode
    local -a attempt_modes
    if [[ "$AUTH_MODE" == "auto" ]]; then
      attempt_modes=("bearer" "x-cisco")
    else
      attempt_modes=("$AUTH_MODE")
    fi

    for mode in "${attempt_modes[@]}"; do
      while :; do
        code="$(_do_curl "$method" "$path" "$body" "$query" "$mode")"
        cp "$TMPDIR/hdr.$$" "$TMPDIR/last_headers" 2>/dev/null || true
        cp "$TMPDIR/body.$$" "$TMPDIR/last_body"   2>/dev/null || true

        # Basic rate-limit handling
        if [[ "$code" == "429" ]]; then
          local wait; wait="$(awk '/^Retry-After:/ {print $2}' "$TMPDIR/last_headers" | tr -d '\r')"
          [[ -z "$wait" ]] && wait=1
          sleep "$wait"
          continue
        fi
        break
      done

      if [[ "$code" == "401" && "$AUTH_MODE" == "auto" && "$mode" == "bearer" ]]; then
        # Retry with X-Cisco-Meraki-API-Key
        continue
      fi

      AUTH_MODE="$mode"
      break
    done

    # ---- Logging (both success and failures) ----
        if [[ -n "${MERAKI_LOG_FILE:-}" ]]; then
      {
        echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] $method $path$query"
        echo "  auth_mode=$AUTH_MODE  http_status=$code"

        # If we have org/network context, show it in the log
        if [[ -n "${MERAKI_CTX_ORG_NAME:-}" || -n "${MERAKI_CTX_NET_NAME:-}" ]]; then
          echo "  org:     ${MERAKI_CTX_ORG_NAME:-<unknown>} (${MERAKI_CTX_ORG_ID:-})"
          echo "  network: ${MERAKI_CTX_NET_NAME:-<unknown>} (${MERAKI_CTX_NET_ID:-})"
        fi

        if [[ -n "$body" ]]; then
          echo "  request_body: $body"
        fi
        # For non-2xx, dump a short snippet of the response body
        if ! [[ "$code" =~ ^20[0-9]$ ]]; then
          echo "  response_body (first 40 lines):"
          sed -n '1,40p' "$TMPDIR/last_body" 2>/dev/null || true
        fi
        echo "------------------------------------------------------------"
      } >>"$MERAKI_LOG_FILE" 2>&1
    fi

    echo "$code" > "$TMPDIR/code.$$"
  }

  _meraki_get_all_pages() {
    local path="$1" query="${2:-?perPage=1000}"
    local accumulator="$TMPDIR/accum.$$"
    printf '[]' > "$accumulator"
    local nextStart=""
    while :; do
      local q="$query"
      [[ -n "$nextStart" ]] && q="${query}&startingAfter=$nextStart"
      _meraki_call GET "$path" "" "$q"
      local code; code="$(cat "$TMPDIR/code.$$")"
      if ! [[ "$code" =~ ^20[01]$ ]]; then
        echo "Meraki API error ($code) while paging:" >&2
        echo "Auth mode: $AUTH_MODE ; Key: $(_mask_key "$MERAKI_API_KEY")" >&2
        sed -n '1,160p' "$TMPDIR/last_body" >&2 || true
        return 1
      fi
      jq -s '.[0] + .[1]' "$accumulator" "$TMPDIR/last_body" > "$accumulator.tmp" && mv "$accumulator.tmp" "$accumulator"

      local link; link="$(grep -i '^Link:' "$TMPDIR/last_headers" | tr -d '\r' || true)"
      if grep -qi 'rel="next"' <<<"$link"; then
        nextStart="$(grep -oi 'startingAfter=[^&>;]*' <<<"$link" | tail -n1 | cut -d= -f2)"
        [[ -z "$nextStart" ]] && break
      else
        break
      fi
    done
    cat "$accumulator"
  }

  # ---------- 4) Build switch info arrays from selection + discovery ----------
  declare -a IPS HOSTS PIDS SER

  IPS=("${SEL_IPS[@]}")

  declare -A HOST_MAP PID_MAP SERIAL_MAP
  if [[ -s "$DISC_JSON" ]]; then
    while IFS=$'\t' read -r ip host pid serial; do
      ip="$(trim "$ip")"
      [[ -z "$ip" ]] && continue
      HOST_MAP["$ip"]="$(trim "$host")"
      PID_MAP["$ip"]="$(trim "$pid")"
      SERIAL_MAP["$ip"]="$(trim "$serial")"
    done < <(
      jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' \
        "$DISC_JSON" 2>/dev/null || true
    )
  fi
  if [[ -s "$SELECTED_JSON" ]]; then
    while IFS=$'\t' read -r ip host pid serial; do
      ip="$(trim "$ip")"
      [[ -z "$ip" ]] && continue
      [[ -z "${HOST_MAP[$ip]:-}" ]]   && HOST_MAP["$ip"]="$(trim "$host")"
      [[ -z "${PID_MAP[$ip]:-}" ]]    && PID_MAP["$ip"]="$(trim "$pid")"
      [[ -z "${SERIAL_MAP[$ip]:-}" ]] && SERIAL_MAP["$ip"]="$(trim "$serial")"
    done < <(
      jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' \
        "$SELECTED_JSON" 2>/dev/null || true
    )
  fi

  HOSTS=(); PIDS=(); SER=()
  for ip in "${IPS[@]}"; do
    HOSTS+=( "${HOST_MAP[$ip]:-}" )
    PIDS+=(  "${PID_MAP[$ip]:-}" )
    SER+=(   "${SERIAL_MAP[$ip]:-}" )
  done

  # Quick review of switches being mapped
  local SWITCH_INFO_TXT="$RUN_DIR/mapping_switches_info.txt"
  {
    echo "Switches selected for this migration run:"
    echo
    printf "%-16s %-24s %-12s %-16s\n" "IP" "Hostname" "PID" "Serial"
    printf "%-16s %-24s %-12s %-16s\n" "----------------" "------------------------" "------------" "----------------"
    local i
    for i in "${!IPS[@]}"; do
      printf "%-16s %-24s %-12s %-16s\n" \
        "${IPS[$i]}" \
        "${HOSTS[$i]:-<unknown>}" \
        "${PIDS[$i]:--}" \
        "${SER[$i]:--}"
    done
  } >"$SWITCH_INFO_TXT"

  dlg --backtitle "$BACKTITLE_M" \
      --title "Switches to map" \
      --textbox "$SWITCH_INFO_TXT" 20 110 || true

  # ---------- 5) Pick org ----------
  local ORG_ID ORG_NAME

  pick_org() {
    local orgs_json; orgs_json="$(_meraki_get_all_pages "/organizations" "?perPage=1000")" || return 1
    local -a items=()
    while IFS=$'\t' read -r oid oname; do
      [[ -z "$oname" ]] && oname="(unnamed)"
      items+=( "$oid" "$oname" )
    done < <(jq -r '.[] | "\(.id)\t\(.name)"' <<<"$orgs_json")

    (( ${#items[@]} > 0 )) || { dlg --backtitle "$BACKTITLE_M" --msgbox "No organizations visible to this API key." 7 60; return 1; }

    local choice
    choice="$(dlg --clear \
                  --backtitle "$BACKTITLE_M – select Meraki organization" \
                  --menu "Select a Meraki Organization for this migration." \
                  20 80 14 "${items[@]}")" || return 1

    ORG_ID="$choice"
    ORG_NAME="$(jq -r --arg id "$ORG_ID" '.[] | select(.id==$id) | .name' <<<"$orgs_json")"
  }

  # ---------- 6) Networks & mapping helpers ----------
    declare -a NET_IDS NET_NAMES NET_LABELS
  declare -A NET_TYPES_BY_ID NET_ADDR
  declare -A MAP_NETID MAP_NETNAME USED_NETS


  # ------------------------------------------
  # Switch Settings Wizard for a NEW network
  # (Mgmt VLAN, STP, QoS ONLY)
  # Storm control and multicast routing are *not*
  # configured here; they can be enabled later
  # in the Meraki Dashboard once switches are
  # onboarded into the network.
  # ------------------------------------------
  configure_switch_settings_wizard() {
    local nid="$1"
    local nname="$2"
    local BACKTITLE_SW="$BACKTITLE_M – Switch settings ($nname)"

    # QoS rules array lives for the life of the wizard
    local -a QOS_RULE_JSON=()

    # helper: render current QoS rules (human-readable) to stdout
    _render_qos_summary() {
      if ((${#QOS_RULE_JSON[@]} == 0)); then
        echo "No QoS rules have been defined yet for this network."
        return
      fi

      echo "Current QoS rules for network:"
      echo "  $nname ($nid)"
      echo
      local idx=1
      local rule_json
      for rule_json in "${QOS_RULE_JSON[@]}"; do
        jq -r --arg idx "$idx" '
          . as $r
          | "Rule #\($idx): "
            + "VLAN=" + ( if ($r.vlan == null) then "ANY" else ($r.vlan|tostring) end )
            + ", Proto=" + ($r.protocol // "ANY")
            + ", Src=" +
              ( if ($r.srcPortRange? != null) then $r.srcPortRange
                elif ($r.srcPort? != null) then ($r.srcPort|tostring)
                else "ANY" end )
            + ", Dst=" +
              ( if ($r.dstPortRange? != null) then $r.dstPortRange
                elif ($r.dstPort? != null) then ($r.dstPort|tostring)
                else "ANY" end )
            + ", DSCP=" + (($r.dscp // -1)|tostring)
        ' <<<"$rule_json"
        idx=$((idx+1))
      done
    }

    # Ask if we even want to do this now
    if ! dlg --backtitle "$BACKTITLE_SW" \
             --yesno "Would you like to configure basic Switch Settings now for:\n\n  $nname\n  ($nid)\n\nThis wizard will configure:\n  - Management VLAN\n  - STP (RSTP)\n  - QoS rules\n\nStorm control and multicast routing are NOT configured by this wizard.\nThey can be enabled la
ter in the Meraki Dashboard after switches are onboarded." \
             18 82; then
      return 0
    fi

    local done=0
    local mgmt_vlan=""
    local stp_enable="yes"

    while (( !done )); do
      QOS_RULE_JSON=()

      # ---- Management VLAN ----
      while :; do
        mgmt_vlan="$(dlg --backtitle "$BACKTITLE_SW" \
                         --inputbox "Management VLAN for $nname\n\nEnter a VLAN ID (1–4094) or leave blank to keep the Meraki default." \
                         11 70 "$mgmt_vlan")" || {
          dlg --backtitle "$BACKTITLE_SW" \
              --msgbox "Switch settings wizard cancelled.\nExisting defaults will remain in place.\n\nYou can always adjust Management VLAN, STP, QoS, storm control,\nand multicast later in the Meraki Dashboard." 11 80
          return 0
        }
        mgmt_vlan="$(trim "$mgmt_vlan")"
        if [[ -z "$mgmt_vlan" ]]; then
          break
        fi
        if [[ "$mgmt_vlan" =~ ^[0-9]+$ ]] && (( mgmt_vlan>=1 && mgmt_vlan<=4094 )); then
          break
        fi
        dlg --backtitle "$BACKTITLE_SW" \
            --msgbox "Invalid VLAN ID: $mgmt_vlan\n\nPlease enter a number between 1 and 4094, or leave blank." 9 70
      done

      # ---- STP (RSTP) ----
      if dlg --backtitle "$BACKTITLE_SW" \
             --yesno "Enable RSTP for this network?\n\n(Recommended: Yes)" 9 60; then
        stp_enable="yes"
      else
        stp_enable="no"
      fi

      # ---- QoS rules loop ----
      while :; do
        # If we already have rules, show a tracker before asking for another
        if ((${#QOS_RULE_JSON[@]} > 0)); then
          local q_summary
          q_summary="$(mktemp)"
          _render_qos_summary >"$q_summary"
          dlg --backtitle "$BACKTITLE_SW – QoS rules" \
              --title "Current QoS rules" \
              --textbox "$q_summary" 20 90 || true
          rm -f "$q_summary"
        fi

        if ! dlg --backtitle "$BACKTITLE_SW" \
                 --yesno "Would you like to add a QoS rule?\n\n(Choose \"No\" when you are done adding rules.)" 10 80; then
          break
        fi

        local q_vlan q_proto q_src_port q_dst_port q_dscp_choice q_dscp_val

        # VLAN: ANY or specific
        q_vlan="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                      --inputbox "QoS rule – VLAN\n\nEnter VLAN ID (1–4094) or \"ANY\" for all VLANs.\nLeave blank for ANY." \
                      11 70 "ANY")" || break
        q_vlan="$(trim "$q_vlan")"
        [[ "$q_vlan" == "any" ]] && q_vlan="ANY"

        # Normalize to vlan_arg: "" means ANY
        local vlan_arg=""
        if [[ -n "$q_vlan" && "$q_vlan" != "ANY" ]]; then
          if [[ "$q_vlan" =~ ^[0-9]+$ ]] && (( q_vlan>=1 && q_vlan<=4094 )); then
            vlan_arg="$q_vlan"
          else
            dlg --backtitle "$BACKTITLE_SW" \
                --msgbox "Invalid VLAN for QoS rule. Using ANY." 7 70
            vlan_arg=""
          fi
        fi

        # Protocol
        q_proto="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                        --menu "QoS rule – protocol" \
                        12 60 5 \
                        "ANY" "Any protocol" \
                        "TCP" "TCP only" \
                        "UDP" "UDP only")" || break

        # Ports – only if TCP/UDP
        q_src_port=""
        q_dst_port=""
        if [[ "$q_proto" == "TCP" || "$q_proto" == "UDP" ]]; then
          # Source port
          q_src_port="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                            --inputbox "QoS rule – source port\n\nEnter a single port (1–65535), a range (e.g. 7000-7100), or \"ANY\".\nLeave blank for ANY." \
                            12 70 "ANY")" || break
          q_src_port="$(trim "$q_src_port")"
          [[ "$q_src_port" == "any" ]] && q_src_port="ANY"

          # Destination port
          q_dst_port="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                            --inputbox "QoS rule – destination port\n\nEnter a single port (1–65535), a range (e.g. 7000-7100), or \"ANY\".\nLeave blank for ANY." \
                            12 70 "ANY")" || break
          q_dst_port="$(trim "$q_dst_port")"
          [[ "$q_dst_port" == "any" ]] && q_dst_port="ANY"
        fi

        # DSCP behaviour
        q_dscp_choice="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                              --menu "QoS rule – DSCP action" \
                              18 70 8 \
                              "TRUST"  "Trust incoming DSCP" \
                              "0"      "0  → 0 (default)" \
                              "10"     "10 → 0 (AF11)" \
                              "18"     "18 → 1 (AF21)" \
                              "26"     "26 → 2 (AF31)" \
                              "34"     "34 → 3 (AF41)" \
                              "46"     "46 → 3 (EF voice)" \
                              "CUSTOM" "Enter custom DSCP (0–63)" )" || break

        case "$q_dscp_choice" in
          TRUST)  q_dscp_val="-1" ;;   # Meraki uses -1 to mean "trust incoming DSCP"
          CUSTOM)
            while :; do
              q_dscp_val="$(dlg --backtitle "$BACKTITLE_SW – QoS rule" \
                                 --inputbox "Custom DSCP value (0–63)\n\nEnter -1 to trust incoming DSCP." \
                                 11 60 "")" || { q_dscp_val=""; break; }
              q_dscp_val="$(trim "$q_dscp_val")"
              [[ -z "$q_dscp_val" ]] && q_dscp_val="-1"
              if [[ "$q_dscp_val" =~ ^-?[0-9]+$ ]] && (( q_dscp_val>=-1 && q_dscp_val<=63 )); then
                break
              fi
              dlg --backtitle "$BACKTITLE_SW" \
                  --msgbox "Invalid DSCP value. Must be between -1 and 63." 8 60
            done
            ;;
          *)
            q_dscp_val="$q_dscp_choice"
            ;;
        esac

        # Build QoS rule JSON
        # vlan: null  => ANY VLAN
        # vlan: <num> => specific VLAN
        local rule_json
        rule_json="$(
          jq -n \
             --arg vlan_str "$vlan_arg" \
             --arg proto "$q_proto" \
             --arg src_p "$q_src_port" \
             --arg dst_p "$q_dst_port" \
             --arg dscp_str "$q_dscp_val" \
             '
             {
               protocol: $proto,
               dscp: ($dscp_str|tonumber),
               vlan: ( if $vlan_str == "" then null else ($vlan_str|tonumber) end )
             }
             + ( if $src_p == "" or $src_p == "ANY" then {} else
                   ( if ($src_p|test("^[0-9]+-[0-9]+$")) then {srcPortRange:$src_p}
                     else {srcPort: ($src_p|tonumber)} end )
                 end )
             + ( if $dst_p == "" or $dst_p == "ANY" then {} else
                   ( if ($dst_p|test("^[0-9]+-[0-9]+$")) then {dstPortRange:$dst_p}
                     else {dstPort: ($dst_p|tonumber)} end )
                 end )
             '
        )"

        QOS_RULE_JSON+=( "$rule_json" )
      done  # QoS loop

      # ---- Final summary / review ----
      local summary; summary="$(mktemp)"
      {
        echo "Switch Settings to apply for network:"
        echo "  $nname ($nid)"
        echo
        echo "Management VLAN: ${mgmt_vlan:-<leave default>}"
        echo "RSTP enabled:   $stp_enable"
        echo
        echo "QoS rules to create: ${#QOS_RULE_JSON[@]}"
        echo

        _render_qos_summary

        echo
        echo "Note:"
        echo "  - Storm control is NOT configured by this wizard."
        echo "  - Multicast routing is NOT configured by this wizard."
        echo
        echo "After switches are onboarded into this network, you can:"
        echo "  • Configure storm control in Dashboard:"
        echo "      Switch > Switch settings > Storm control"
        echo "  • Configure multicast settings in Dashboard:"
        echo "      Switch > Switch settings > Multicast"
      } >"$summary"

      dlg --backtitle "$BACKTITLE_SW" \
          --title "Review switch settings" \
          --textbox "$summary" 24 90 || true
      rm -f "$summary"

      if dlg --backtitle "$BACKTITLE_SW" \
             --yesno "Apply these switch settings now?\n\nSelect \"No\" to re-run the wizard and edit values." 10 70; then
        # Show a quick "working" infobox while we hit the API
        "$DIALOG" --backtitle "$BACKTITLE_SW" \
                  --infobox "Applying network switch settings to:\n\n  $nname ($nid)\n\nThis may take a few moments, please wait..." \
                  11 80
        sleep 1
        done=1
      else
        continue    # loop back and re-run wizard
      fi
    done  # while !done

    # Set Meraki logging context so log entries show org + network names
    MERAKI_CTX_ORG_ID="$ORG_ID"
    MERAKI_CTX_ORG_NAME="$ORG_NAME"
    MERAKI_CTX_NET_ID="$nid"
    MERAKI_CTX_NET_NAME="$nname"

    # ============================
    # Apply settings via Meraki API
    # ============================

    local apply_ok=1
    local apply_errors=""

    # Management VLAN
    if [[ -n "$mgmt_vlan" ]]; then
      local body_mv code
      body_mv="$(jq -n --arg vlan "$mgmt_vlan" '{vlan:($vlan|tonumber)}')"
      _meraki_call PUT "/networks/$nid/switch/settings" "$body_mv" ""
      code="$(cat "$TMPDIR/code.$$")"
      if [[ "$code" != "200" ]]; then
        apply_ok=0
        apply_errors+="\n - Failed to set Management VLAN (HTTP $code)"
        dlg --backtitle "$BACKTITLE_SW" \
            --msgbox "Warning: Failed to set Management VLAN (HTTP $code).\nSee logs for details." 9 80 || true
      fi
    fi

    # STP (RSTP toggle)
    local body_stp code
    if [[ "$stp_enable" == "yes" ]]; then
      body_stp='{"rstpEnabled":true}'
    else
      body_stp='{"rstpEnabled":false}'
    fi
    _meraki_call PUT "/networks/$nid/switch/stp" "$body_stp" ""
    code="$(cat "$TMPDIR/code.$$")"
    if [[ "$code" != "200" ]]; then
      apply_ok=0
      apply_errors+="\n - Failed to update STP settings (HTTP $code)"
      dlg --backtitle "$BACKTITLE_SW" \
          --msgbox "Warning: Failed to update STP settings (HTTP $code).\nSee logs for details." 9 80 || true
    fi

    # QoS rules
    local rule_json
    local requested_qos_count=${#QOS_RULE_JSON[@]}
    local qos_apply_errors=0

    for rule_json in "${QOS_RULE_JSON[@]}"; do
      _meraki_call POST "/networks/$nid/switch/qosRules" "$rule_json" ""
      code="$(cat "$TMPDIR/code.$$")"
      if [[ "$code" != "201" && "$code" != "200" ]]; then
        apply_ok=0
        qos_apply_errors=$((qos_apply_errors+1))
        apply_errors+="\n - Failed to create one QoS rule (HTTP $code)"
        dlg --backtitle "$BACKTITLE_SW" \
            --msgbox "Warning: Failed to create one QoS rule (HTTP $code).\nSee logs for details." 9 80 || true
      fi
    done

    # ------------------------------------------------
    # Post-apply verification from Meraki Dashboard
    # ------------------------------------------------
    local verify_ok=1
    local verify_notes=""

    # Give Dashboard a tiny moment to settle
    sleep 2

    # Verify switch settings (Mgmt VLAN)
    _meraki_call GET "/networks/$nid/switch/settings" "" ""
    code="$(cat "$TMPDIR/code.$$")"
    if [[ "$code" =~ ^20[01]$ ]]; then
      local v_mgmt_vlan
      v_mgmt_vlan="$(jq -r '.vlan // ""' "$TMPDIR/last_body")"
      if [[ -n "$mgmt_vlan" ]]; then
        if [[ "$v_mgmt_vlan" != "$mgmt_vlan" ]]; then
          verify_ok=0
          verify_notes+="\n - Management VLAN in Dashboard is '$v_mgmt_vlan' (expected '$mgmt_vlan')."
        else
          verify_notes+="\n - Management VLAN verified as $v_mgmt_vlan."
        fi
      else
        verify_notes+="\n - Management VLAN left at Dashboard default."
      fi
    else
      verify_ok=0
      verify_notes+="\n - Could not read switch settings from Dashboard (HTTP $code)."
    fi

    # Verify STP
    _meraki_call GET "/networks/$nid/switch/stp" "" ""
    code="$(cat "$TMPDIR/code.$$")"
    if [[ "$code" =~ ^20[01]$ ]]; then
      local v_rstp
      v_rstp="$(jq -r '.rstpEnabled // "false"' "$TMPDIR/last_body")"
      if [[ "$stp_enable" == "yes" ]]; then
        if [[ "$v_rstp" != "true" ]]; then
          verify_ok=0
          verify_notes+="\n - RSTP is not enabled in Dashboard (expected enabled)."
        else
          verify_notes+="\n - RSTP verified as enabled."
        fi
      else
        if [[ "$v_rstp" != "false" ]]; then
          verify_ok=0
          verify_notes+="\n - RSTP is enabled in Dashboard (expected disabled)."
        else
          verify_notes+="\n - RSTP verified as disabled."
        fi
      fi
    else
      verify_ok=0
      verify_notes+="\n - Could not read STP settings from Dashboard (HTTP $code)."
    fi

    # Verify QoS rule count (basic sanity check)
    _meraki_call GET "/networks/$nid/switch/qosRules" "" ""
    code="$(cat "$TMPDIR/code.$$")"
    if [[ "$code" =~ ^20[01]$ ]]; then
      local v_qos_count
      v_qos_count="$(jq 'length' "$TMPDIR/last_body")"
      if (( requested_qos_count > 0 )); then
        if (( v_qos_count < requested_qos_count )); then
          verify_ok=0
          verify_notes+="\n - Dashboard shows $v_qos_count QoS rule(s) (wizard created $requested_qos_count)."
        else
          verify_notes+="\n - Dashboard shows $v_qos_count QoS rule(s); wizard created $requested_qos_count."
        fi
      else
        verify_notes+="\n - No QoS rules were created by the wizard."
      fi
    else
      verify_ok=0
      verify_notes+="\n - Could not read QoS rules from Dashboard (HTTP $code)."
    fi

    # ------------------------------------------------
    # Final status message to the user
    # ------------------------------------------------
    local final_msg
    if (( apply_ok == 1 && verify_ok == 1 )); then
      final_msg="Switch settings have been applied and verified for:\n\n  $nname ($nid)\n\nDashboard verification indicates everything looks good.\n$verify_notes"
    else
      final_msg="Switch settings have been applied for:\n\n  $nname ($nid)\n\nHowever, one or more issues were detected.\n\nApply phase:\n${apply_errors:-  - No explicit apply errors recorded.}\n\nVerification phase:\n${verify_notes:-  - No additional verification notes.}\n\nPlease
review the Meraki Dashboard and the log file for details."
    fi

        dlg --backtitle "$BACKTITLE_SW" \
        --title "Switch settings – results" \
        --msgbox "$final_msg" 22 90 || true

    # Clear Meraki logging context
    MERAKI_CTX_ORG_ID=""
    MERAKI_CTX_ORG_NAME=""
    MERAKI_CTX_NET_ID=""
    MERAKI_CTX_NET_NAME=""

    return 0
  }

  create_network_dialog() {
    local NET_NAME
    NET_NAME="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                    --inputbox "Enter a name for the new Network (Org: $ORG_NAME)" \
                    10 70 "Catalyst Switch Migration")" || return 1
    NET_NAME="$(trim "$NET_NAME")"
    [[ -n "$NET_NAME" ]] || { dlg --backtitle "$BACKTITLE_M" --msgbox "Network name cannot be empty." 7 60; return 1; }

    local -a checklist=(
      "appliance"        "MX / SD-WAN"                           off
      "switch"           "Switch (Meraki MS or Catalyst)"        on
      "wireless"         "MR / Wireless"                         off
      "camera"           "MV / Cameras"                          off
      "cellularGateway"  "MG / Cellular"                         off
      "sensor"           "MT / Sensors"                          off
      "systemsManager"   "SM / MDM"                              off
    )

    local selection
    selection="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                     --separate-output \
                     --checklist "Select product types for \"$NET_NAME\"\n(Keep 'switch' enabled for Catalyst migration.)" \
                     20 80 12 "${checklist[@]}")" || return 1
    [[ -n "$selection" ]] || { dlg --backtitle "$BACKTITLE_M" --msgbox "At least one product type must be selected." 7 70; return 1; }

    mapfile -t PRODUCTS <<<"$selection"
    local ptypes_json; ptypes_json="$(printf '%s\n' "${PRODUCTS[@]}" | jq -R . | jq -s .)"

    local default_tz="America/New_York"
    local tz; tz="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                        --inputbox "Optional: timeZone (IANA) for \"$NET_NAME\".\nLeave blank to let Dashboard default." \
                        10 70 "$default_tz")" || return 1
    tz="$(trim "$tz")"

    local addr; addr="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                            --inputbox "Physical address for \"$NET_NAME\" (one line)\nExample: 123 AnyStreet St. City ST 12345" \
                            10 70 "")" || return 1
    addr="$(trim "$addr")"

    local body
    if [[ -n "$tz" && -n "$addr" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg tz "$tz" --arg addr "$addr" \
        '{name:$name, productTypes:$productTypes, timeZone:$tz, address:$addr}')"
    elif [[ -n "$tz" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg tz "$tz" \
        '{name:$name, productTypes:$productTypes, timeZone:$tz}')"
    elif [[ -n "$addr" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg addr "$addr" \
        '{name:$name, productTypes:$productTypes, address:$addr}')"
    else
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" \
        '{name:$name, productTypes:$productTypes}')"
    fi

    _meraki_call POST "/organizations/$ORG_ID/networks" "$body" ""
    local code; code="$(cat "$TMPDIR/code.$$")"
    [[ "$code" == "201" ]] || {
      dlg --backtitle "$BACKTITLE_M" --msgbox "Create network failed ($code).\n\nSee logs for details." 9 70
      return 1
    }

    local NET_ID NET_PRODUCT_TYPES
    NET_ID="$(jq -r '.id' "$TMPDIR/last_body")"
    NET_PRODUCT_TYPES="$(jq -c '.productTypes' "$TMPDIR/last_body")"
    local addr_ret; addr_ret="$(jq -r '.address // ""' "$TMPDIR/last_body")"
    [[ -z "$addr_ret" ]] && addr_ret="$addr"
    NET_ADDR["$NET_ID"]="$addr_ret"

    local url; url="$(jq -r '.url' "$TMPDIR/last_body")"

        dlg --backtitle "$BACKTITLE_M" \
        --msgbox "Created Network:\n\nName: $NET_NAME\nID:   $NET_ID\nTypes: $(jq -r '.|join(", ")' <<<"$NET_PRODUCT_TYPES")\nAddress: ${addr_ret:-<none>}\nURL:  $url\n" 15 90

    # Track in memory for this script run
    NET_IDS+=( "$NET_ID" )
    NET_NAMES+=( "$NET_NAME" )
    NET_TYPES_BY_ID["$NET_ID"]="$NET_PRODUCT_TYPES"
    local types_flat; types_flat="$(jq -r '.|join(",")' <<<"$NET_PRODUCT_TYPES")"
    NET_LABELS+=( "$NET_NAME  [$types_flat]" )
    NET_ADDR["$NET_ID"]="$addr_ret"

    # Persist a record of the created network in the createnetworks run
    if [[ -n "${CREATE_NET_CSV:-}" ]]; then
      local ts
      ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      {
        printf '%s,' "$ts"
        printf '%s,' "$ORG_ID"
        printf '%q,' "$ORG_NAME"
        printf '%s,' "$NET_ID"
        printf '%q,' "$NET_NAME"
        printf '%q,' "$types_flat"
        printf '%q,' "${addr_ret:-}"
        printf '%s\n' "$url"
      } >>"$CREATE_NET_CSV"
    fi

    # NEW: run Switch Settings wizard for this newly created network
    configure_switch_settings_wizard "$NET_ID" "$NET_NAME" || true
  }

  load_switch_networks() {
    NET_IDS=(); NET_NAMES=(); NET_LABELS=(); NET_TYPES_BY_ID=(); NET_ADDR=()

    local nets_json; nets_json="$(_meraki_get_all_pages "/organizations/$ORG_ID/networks" "?perPage=1000")" || return 1

    while IFS=$'\t' read -r nid nname ptypes addr; do
      [[ -z "$nid" ]] && continue
      [[ -z "$nname" ]] && nname="(unnamed)"
      if ! jq -e '. | index("switch")' <<<"$ptypes" >/dev/null 2>&1; then
        continue
      fi
      NET_IDS+=( "$nid" )
      NET_NAMES+=( "$nname" )
      NET_TYPES_BY_ID["$nid"]="$ptypes"
      NET_ADDR["$nid"]="$(trim "$addr")"
      local types_flat; types_flat="$(jq -r '.|join(",")' <<<"$ptypes")"
      NET_LABELS+=( "$nname  [$types_flat]" )
    done < <(jq -r '.[] | "\(.id)\t\(.name)\t\(.productTypes)\t\(.address // "")"' <<<"$nets_json")

    if [[ ${#NET_IDS[@]} -eq 0 ]]; then
      dlg --backtitle "$BACKTITLE_M" --title "No switch networks" --msgbox \
        "No Meraki networks with product type 'switch' were found in:\n  $ORG_NAME ($ORG_ID)\n\nCreate one first, then rerun this step." 12 80
      create_network_dialog || return 1
    fi
  }

  get_existing_address_for_network() {
    local nid="$1"
    local addr="${NET_ADDR[$nid]:-}"
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return
    fi
    local devs; devs="$(_meraki_get_all_pages "/networks/$nid/devices" "?perPage=1000")"
    addr="$(jq -r '[.[] | .address? // "" | select(. != "")][0] // ""' <<<"$devs")"
    echo "$addr"
  }

  ensure_addresses_for_used_networks() {
    local nid i nname addr
    for nid in "${!USED_NETS[@]}"; do
      addr="${NET_ADDR[$nid]:-}"
      if [[ -z "$addr" ]]; then
        addr="$(get_existing_address_for_network "$nid")"
      fi

      nname=""
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
          nname="${NET_NAMES[$i]}"
          break
        fi
      done
      [[ -z "$nname" ]] && nname="$nid"

      addr="$(dlg --backtitle "$BACKTITLE_M: confirm network address" \
                  --inputbox "Enter physical address for network:\n  $nname ($nid)\n\nExample: 123 AnyStreet St. City ST 12345\n\nLeave blank if you prefer to set it later." \
                  13 80 "$addr")" || return 1
      NET_ADDR["$nid"]="$(trim "$addr")"
    done
  }

  map_switches_to_networks() {
    local -a UNASSIGNED=("${IPS[@]}")

    while :; do
      local remaining=${#UNASSIGNED[@]}
      (( remaining == 0 )) && break

      local -a menu_items=()
      local i
      for i in "${!NET_IDS[@]}"; do
        menu_items+=( "${NET_IDS[$i]}" "${NET_LABELS[$i]}" )
      done
      menu_items+=( "NEW" "Create a new 'switch' network" )
      menu_items+=( "DONE" "Finish mapping (leave remaining unmapped)" )

      local net_choice
      net_choice="$(dlg --backtitle "$BACKTITLE_M: assign switches to networks" \
                        --menu "Select a network for the next batch of switches.\nUnmapped switches remaining: $remaining" \
                        22 90 16 "${menu_items[@]}")" || return 1

      if [[ "$net_choice" == "DONE" ]]; then
        if (( remaining > 0 )); then
          if ! dlg --backtitle "$BACKTITLE_M" \
                   --yesno "You still have $remaining switch(es) without a network mapping.\n\nAre you sure you want to finish and leave them unmapped?" 11 70; then
            continue
          fi
        fi
        break
      fi

      if [[ "$net_choice" == "NEW" ]]; then
        create_network_dialog || return 1
        continue
      fi

      local nid="$net_choice"
      local nname=""
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
          nname="${NET_NAMES[$i]}"; break
        fi
      done
      [[ -z "$nname" ]] && nname="$nid"

      # checklist of UNASSIGNED switches for this network
      local -a chk_items=()
      local ip idx desc
      for ip in "${UNASSIGNED[@]}"; do
        idx=""
        for i in "${!IPS[@]}"; do
          if [[ "${IPS[$i]}" == "$ip" ]]; then idx="$i"; break
          fi
        done
        if [[ -n "$idx" ]]; then
          desc="$(trim "${HOSTS[$idx]:-$ip}  ${PIDS[$idx]:+(${PIDS[$idx]}) }${SER[$idx]:+SN:${SER[$idx]}}")"
        else
          desc="$ip"
        fi
        chk_items+=( "$ip" "$desc" "off" )
      done

      local selection
      selection="$(dlg --backtitle "$BACKTITLE_M: assign switches to networks" \
                       --separate-output \
                       --checklist "Select switch(es) to assign to:\n  $nname ($nid)" \
                       22 90 14 "${chk_items[@]}")" || continue

      selection="$(trim "$selection")"
      [[ -z "$selection" ]] && continue
      local -a chosen_ips=()
      mapfile -t chosen_ips <<<"$selection"

      local -a new_unassigned=()
      local assigned_here ip2
      for ip in "${UNASSIGNED[@]}"; do
        assigned_here=0
        for ip2 in "${chosen_ips[@]}"; do
          if [[ "$ip2" == "$ip" ]]; then
            MAP_NETID["$ip"]="$nid"
            MAP_NETNAME["$ip"]="$nname"
            assigned_here=1
            break
          fi
        done
        (( assigned_here == 0 )) && new_unassigned+=( "$ip" )
      done
      UNASSIGNED=("${new_unassigned[@]}")
    done

    USED_NETS=()
    local ip
    for ip in "${IPS[@]}"; do
      local nid="${MAP_NETID[$ip]:-}"
      [[ -z "$nid" ]] && continue
      USED_NETS["$nid"]=1
    done

    ensure_addresses_for_used_networks || return 1
  }

    # ---------- 7) Run org + network mapping ----------
  pick_org || { rm -rf "$TMPDIR"; return 1; }

  # Initialize 'createnetworks' run + Meraki log structure
  init_createnetwork_run "$ORG_ID" "$ORG_NAME"

  load_switch_networks || { rm -rf "$TMPDIR"; return 1; }
  map_switches_to_networks || { rm -rf "$TMPDIR"; return 1; }

  # ---------- 8) Save mapping (per-run + global) ----------
  local MAP_RUN_JSON="$RUN_DIR/mapping.json"
  local MAP_RUN_TXT="$RUN_DIR/mapping_summary.txt"
  local MAP_JSON="${CLOUD_ADMIN_BASE}/meraki_switch_network_map.json"
  local MAP_ENV="${CLOUD_ADMIN_BASE}/meraki_switch_network_map.env"

  # Per-run JSON – one object per *mapped* switch
  {
    echo '['
    local first=1
    local i ip nid nname addr h p s
    for i in "${!IPS[@]}"; do
      ip="${IPS[$i]}"
      nid="${MAP_NETID[$ip]:-}"
      [[ -z "$nid" ]] && continue
      nname="${MAP_NETNAME[$ip]:-}"
      addr="${NET_ADDR[$nid]:-}"
      h="${HOSTS[$i]:-}"
      p="${PIDS[$i]:-}"
      s="${SER[$i]:-}"

      if (( first )); then
        first=0
      else
        echo ','
      fi
      jq -n --arg ip "$ip" \
            --arg hostname "$h" \
            --arg pid "$p" \
            --arg serial "$s" \
            --arg orgId "$ORG_ID" \
            --arg orgName "$ORG_NAME" \
            --arg networkId "$nid" \
            --arg networkName "$nname" \
            --arg networkAddress "$addr" \
            '{ip:$ip, hostname:$hostname, pid:$pid, serial:$serial,
              orgId:$orgId, orgName:$orgName,
              networkId:$networkId, networkName:$networkName,
              networkAddress:$networkAddress}'
    done
    echo
    echo ']'
  } >"$MAP_RUN_JSON"

  # Global map JSON: merge (one latest row per IP)
  local tmp_new="$TMPDIR/new_map_entry.json"
  cp "$MAP_RUN_JSON" "$tmp_new"
  if [[ ! -s "$MAP_JSON" ]]; then
    cp "$tmp_new" "$MAP_JSON"
  else
    jq -s '
      (.[0] // []) as $old
      | (.[1] // []) as $newset
      | [
          $old[]
          | select( .ip as $ip
                   | all( $newset[]?; .ip != $ip )
            )
        ]
        + $newset
    ' "$MAP_JSON" "$tmp_new" >"$MAP_JSON.tmp" && mv "$MAP_JSON.tmp" "$MAP_JSON"
  fi

  # Global env pointing at map + default org (net is per-switch now)
  {
    echo "# Generated by cloud_migration_map_selected_switches on $(date +'%Y-%m-%d %H:%M:%S %Z')"
    printf 'export MERAKI_ORG_ID=%q\n' "$ORG_ID"
    printf 'export MERAKI_ORG_NAME=%q\n' "$ORG_NAME"
    printf 'export MERAKI_SWITCH_NETWORK_MAP_FILE=%q\n' "$MAP_JSON"
  } >"$MAP_ENV"

  # Refresh latest.env with org info (net is per-switch now)
  {
    printf 'export MIGRATE_RUN_ID=%q\n'        "$RUN_ID"
    printf 'export MIGRATE_RUN_DIR=%q\n'       "$RUN_DIR"
    printf 'export MIGRATE_SELECTION_CSV=%q\n' "${MIGRATE_SELECTION_CSV:-$RUN_DIR/selection_summary.csv}"
    printf 'export MIGRATE_SELECTED_IPS=%q\n'  "${SEL_IPS[*]}"
    printf 'export MIGRATE_SELECTED_ENV=%q\n'  "${MIGRATE_SELECTED_ENV:-${CLOUD_ADMIN_BASE}/selected_upgrade.env}"
    printf 'export MIGRATE_BASE_ENV=%q\n'      "${MIGRATE_BASE_ENV:-}"
    printf 'export MIGRATE_MERAKI_ORG_ID=%q\n' "$ORG_ID"
    printf 'export MIGRATE_MERAKI_ORG_NAME=%q\n' "$ORG_NAME"
    printf 'export MIGRATE_MERAKI_MAP_FILE=%q\n' "$MAP_JSON"
  } >"$LATEST_ENV"

  # ---------- 9) Review window ----------
  {
    echo "Meraki mapping summary for this migration run"
    echo "============================================"
    echo
    echo "Run ID:    $RUN_ID"
    echo "Run dir:   $RUN_DIR"
    echo
    echo "Organization:"
    echo "  $ORG_NAME ($ORG_ID)"
    echo
    echo "Switch-to-network mappings:"
    echo
    printf "%-16s %-24s %-12s %-16s %-18s %-12s\n" \
      "IP" "Hostname" "PID" "Serial" "Network" "Net ID"
    printf "%-16s %-24s %-12s %-16s %-18s %-12s\n" \
      "----------------" "------------------------" "------------" "----------------" "------------------" "------------"
    local i ip nid nname
    for i in "${!IPS[@]}"; do
      ip="${IPS[$i]}"
      nname="${MAP_NETNAME[$ip]:-<unmapped>}"
      nid="${MAP_NETID[$ip]:-<none>}"
      printf "%-16s %-24s %-12s %-16s %-18s %-12s\n" \
        "$ip" "${HOSTS[$i]:-<unknown>}" "${PIDS[$i]:--}" "${SER[$i]:--}" "$nname" "$nid"
    done
    echo
    echo "Network addresses used in this mapping:"
    echo
    for nid in "${!USED_NETS[@]}"; do
      local nname2=""
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
          nname2="${NET_NAMES[$i]}"
          break
        fi
      done
      [[ -z "$nname2" ]] && nname2="$nid"
      printf "  %s (%s): %s\n" "$nname2" "$nid" "${NET_ADDR[$nid]:-<none>}"
    done
    echo
    echo "Files written:"
    echo "  Per-run mapping JSON:  $MAP_RUN_JSON"
    echo "  Global map JSON:       $MAP_JSON"
    echo "  Global map ENV:        $MAP_ENV"
  } >"$MAP_RUN_TXT"

  dlg --backtitle "$BACKTITLE_M" \
      --title "Meraki mapping saved" \
      --textbox "$MAP_RUN_TXT" 30 110 || true

  rm -rf "$TMPDIR"
  return 0
}
# ============================================================
# Phase 3 – Meraki connect enablement / Dashboard Claim
# ============================================================

need curl
need jq

# Backtitle for this phase
BACKTITLE_C="Cloud Migration – Onboard switches to Meraki Dashboard"

# Global “hard fail” – if we ever see HTTP 401 (invalid API key),
# stop attempting further claims in this run.
MERAKI_CLAIM_HARD_FAILURE=0

# MIGRATE_MERAKI_MAP_FILE should already be exported by the mapping phase
# and contains JSON entries like: [{ "ip":"192.168.1.10", "networkId":"N_1234" }, ...]
get_network_id_for_ip() {
  local ip="$1"
  [[ -n "${MIGRATE_MERAKI_MAP_FILE:-}" && -s "$MIGRATE_MERAKI_MAP_FILE" ]] || return 1
  jq -r --arg ip "$ip" '
    .[] | select(.ip == $ip) | .networkId // empty
  ' "$MIGRATE_MERAKI_MAP_FILE" 2>/dev/null | awk 'NF {print; exit}'
}
# Return original IOS-XE hostname for an IP (from meraki_switch_network_map.json)
get_hostname_for_ip() {
  local ip="$1"
  [[ -n "${MIGRATE_MERAKI_MAP_FILE:-}" && -s "$MIGRATE_MERAKI_MAP_FILE" ]] || return 1

  jq -r --arg ip "$ip" '
    .[] | select(.ip == $ip) | .hostname // empty
  ' "$MIGRATE_MERAKI_MAP_FILE" 2>/dev/null | awk 'NF {print; exit}'
}
# Look up the physical/mailing address we associated with this switch's network
get_network_address_for_ip() {
  local ip="$1"
  [[ -n "${MIGRATE_MERAKI_MAP_FILE:-}" && -s "$MIGRATE_MERAKI_MAP_FILE" ]] || return 1
  jq -r --arg ip "$ip" '
    .[] | select(.ip == $ip) | .networkAddress // empty
  ' "$MIGRATE_MERAKI_MAP_FILE" 2>/dev/null | awk 'NF {print; exit}'
}
# ----------------- Meraki Memory JSON Helper -----------------------
# Record per-device onboarding metadata to a JSON file.
# Uses MIGRATE_MERAKI_MAP_FILE (from Phase 2) to pull org/network/serial info.
#
# Args:
#   $1 = ip
#   $2 = cloud_id
#   $3 = device_name (final Dashboard name)
#   $4 = stack_count    (default 1)
#   $5 = member_index   (default 1)
#   $6 = stack_base_name (e.g. "c9300-stack1" for stacks; empty for singles)
mc_record_meraki_memory() {
  local ip="$1"
  local cloud_id="$2"
  local device_name="$3"
  local stack_count="${4:-1}"
  local member_index="${5:-1}"
  local stack_base_name="${6:-}"

  # Where to store JSON snapshots
  local mem_root="${MERAKI_MEMORY_DIR:-${CLOUD_ADMIN_BASE}/meraki_memory}"
  mkdir -p "$mem_root" 2>/dev/null || {
    mc_log "[$ip] MEMORY: Failed to create dir $mem_root"
    return 0
  }

  # Mapping file from Phase 2 (per-IP org/net/serial mapping)
  local map_file="${MIGRATE_MERAKI_MAP_FILE:-${MERAKI_SWITCH_NETWORK_MAP_FILE:-}}"

  local org_id="" org_name="" net_id="" net_name="" net_addr="" pid="" serial=""
  if [[ -n "$map_file" && -s "$map_file" ]]; then
    org_id="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .orgId // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    org_name="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .orgName // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    net_id="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .networkId // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    net_name="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .networkName // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    net_addr="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .networkAddress // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    pid="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .pid // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
    serial="$(
      jq -r --arg ip "$ip" '
        .[] | select(.ip == $ip) | .serial // empty
      ' "$map_file" 2>/dev/null | awk 'NF{print;exit}'
    )"
  fi

  local ts; ts="$(date +'%Y-%m-%dT%H:%M:%S%z')"
  local run_id="${RUN_ID:-}"
  local fname="${mem_root}/${cloud_id:-$ip}.json"

  mc_log "[$ip] MEMORY: Writing Meraki onboarding snapshot to $fname"

  jq -n \
    --arg ts "$ts" \
    --arg run_id "$run_id" \
    --arg ip "$ip" \
    --arg cloud_id "$cloud_id" \
    --arg serial "$serial" \
    --arg model "$pid" \
    --arg device_name "$device_name" \
    --arg org_id "$org_id" \
    --arg org_name "$org_name" \
    --arg net_id "$net_id" \
    --arg net_name "$net_name" \
    --arg net_addr "$net_addr" \
    --arg stack_base "$stack_base_name" \
    --arg stack_count_s "$stack_count" \
    --arg member_index_s "$member_index" \
    '
    {
      timestamp: $ts,
      run_id: $run_id,
      ip: $ip,
      cloud_id: $cloud_id,
      serial: $serial,
      model: $model,
      device_name: $device_name,
      org_id: $org_id,
      org_name: $org_name,
      network_id: $net_id,
      network_name: $net_name,
      network_address: $net_addr,
      status: "CLAIMED",
      ssh_status: "OK",
      stack: {
        stack_count: ($stack_count_s|tonumber? // 1),
        member_index: ($member_index_s|tonumber? // 1),
        stack_base_name: $stack_base
      }
    }
    ' >"$fname" 2>/dev/null

  if [[ $? -ne 0 ]]; then
    mc_log "[$ip] MEMORY: Failed to write snapshot for Cloud ID $cloud_id"
  else
    mc_log "[$ip] MEMORY: Snapshot updated for Cloud ID $cloud_id"
  fi
}
# Parse "show meraki connect" + logging output for status bits.
# Returns: "fetch_ok|tunnels_ok|reg_ok|cloud_id|migrating_ok"
# Parse "show meraki connect" output for status bits.
# Returns: "fetch_ok|tunnels_ok|reg_ok|cloud_id"
meraki_status_from_file() {
  local file="$1"

  local fetch_ok=0 tunnels_ok=0 reg_ok=0 cloud_id=""

  # 1) Fetch State
  if grep -qi 'Fetch State[[:space:]]*:.*Config fetch succeeded' "$file"; then
    fetch_ok=1
  fi

  # 2) Tunnel State (Primary + Secondary Up)
  #    (6 lines is plenty, but bump a bit to be safe)
  if grep -i 'Meraki Tunnel State' -A8 "$file" | grep -qi 'Primary[[:space:]]*:[[:space:]]*Up'; then
    if grep -i 'Meraki Tunnel State' -A8 "$file" | grep -qi 'Secondary[[:space:]]*:[[:space:]]*Up'; then
      tunnels_ok=1
    fi
  fi

  # 3) Device Registration status
  #    (we bumped -A to 12 so the Status line is definitely in range)
  if grep -i 'Meraki Device Registration' -A12 "$file" | grep -qi 'Status[[:space:]]*:[[:space:]]*Registered'; then
    reg_ok=1
  fi

  # 4) Cloud ID
  cloud_id="$(
    grep -i 'Cloud ID' "$file" 2>/dev/null \
      | head -n1 \
      | sed -E 's/.*Cloud ID[[:space:]]*:[[:space:]]*//I' \
      | awk '{print $1}'
  )"

  echo "${fetch_ok}|${tunnels_ok}|${reg_ok}|${cloud_id}"
}

# Parse "show meraki" stack table.
# Emits one line per member:
#   "<num>|<pid>|<serial>|<cloud_id>|<mac>|<status>|<mode>"
meraki_stack_members_from_file() {
  local file="$1"

  awk '
    # Header line with columns
    /^Num[[:space:]]+PID[[:space:]]+Number[[:space:]]+Cloud[[:space:]]+ID[[:space:]]+Mac[[:space:]]+Address[[:space:]]+Status[[:space:]]+Mode/ {
      header=1
      next
    }

    # Skip the dashed separator line
    header && /^-+/ { next }

    # Data lines: start with a numeric switch number
    header && NF >= 6 && $1 ~ /^[0-9]+$/ {
      num    = $1
      pid    = $2
      serial = $3
      cloud  = $4
      mac    = $5
      status = $6

      mode = ""
      for (i = 7; i <= NF; i++) {
        if (mode == "") {
          mode = $i
        } else {
          mode = mode " " $i
        }
      }

      printf "%s|%s|%s|%s|%s|%s|%s\n", num, pid, serial, cloud, mac, status, mode
    }
  ' "$file"
}
# ───────────────── Phase 3 UI helpers (mc_*) ─────────────────

MC_STATUS_FILE=""
MC_DLG_PID=""
MC_PROG_PIPE=""
MC_PROG_FD=""

mc_log() {
  local msg="$1"
  [[ -z "${MC_STATUS_FILE:-}" ]] && return 0
  printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$msg" >>"$MC_STATUS_FILE"
}

mc_gauge() {
  local pct="${1:-0}"
  local text="${2:-Working…}"
  if [[ -n "${MC_PROG_FD:-}" ]]; then
    printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$text" >&"$MC_PROG_FD" 2>/dev/null || true
  fi
}

mc_ui_start() {
  local RUN_ID_TXT="${RUN_ID:-unknown}"

  local rows cols
  read -r rows cols < <(stty size 2>/dev/null || echo "24 80")
  (( rows < 18 )) && rows=18
  (( cols < 80 )) && cols=80

  local TOP_MARGIN=2 LEFT_MARGIN=2
  local GAUGE_H=6
  local TAIL_H=$(( rows - TOP_MARGIN - GAUGE_H - 3 ))
  (( TAIL_H < 10 )) && TAIL_H=10
  local TAIL_W=$(( cols - LEFT_MARGIN - 2 ))
  (( TAIL_W < 70 )) && TAIL_W=70
  local GAUGE_ROW=$(( TOP_MARGIN + TAIL_H + 1 ))
  local GAUGE_COL=$LEFT_MARGIN

  MC_PROG_PIPE="$(mktemp -u)"
  mkfifo "$MC_PROG_PIPE"
  exec {MC_PROG_FD}<>"$MC_PROG_PIPE"

  (
    "$DIALOG" \
      --backtitle "$BACKTITLE_C" \
      --begin "$TOP_MARGIN" "$LEFT_MARGIN" \
      --title "Activity (Run: $RUN_ID_TXT)" \
      --tailboxbg "$MC_STATUS_FILE" "$TAIL_H" "$TAIL_W" \
      --and-widget \
      --begin "$GAUGE_ROW" "$GAUGE_COL" \
      --title "Meraki connect – progress" \
      --gauge "Onboarding selected switches to Meraki Dashboard…" \
      "$GAUGE_H" "$TAIL_W" 0 <"$MC_PROG_PIPE"
  ) & MC_DLG_PID=$!

  sleep 0.2
  mc_gauge 1 "Starting Meraki connect onboarding…"
}

mc_ui_stop() {
  if [[ -n "${MC_PROG_FD:-}" ]]; then
    mc_gauge 100 "Done."
    exec {MC_PROG_FD}>&- 2>/dev/null || true
  fi
  [[ -n "${MC_PROG_PIPE:-}" ]] && rm -f "$MC_PROG_PIPE" 2>/dev/null || true
  [[ -n "${MC_DLG_PID:-}" ]] && kill "$MC_DLG_PID" 2>/dev/null || true
}

# ───────────────── Meraki claim helper ─────────────────

# ───────────────── Stack ─────────────────
# ───────────────── Stack ─────────────────
# ───────────────── Stack ─────────────────
meraki_claim_stack_devices() {
  # $1 = IP (for logging only)
  # $2 = networkId
  # $3 = comma-separated list of Cloud IDs for the stack
  local ip="$1"
  local net_id="$2"
  local stack_cloud_ids_csv="$3"

  # Base hostname (IOS-XE hostname from the mapping file)
  local base_hostname=""
  base_hostname="$(get_hostname_for_ip "$ip" 2>/dev/null || true)"

  local -a cid_arr=()
  IFS=',' read -r -a cid_arr <<<"$stack_cloud_ids_csv"

  local total="${#cid_arr[@]}"
  local cid
  local any_success=0
  local idx=1

  for cid in "${cid_arr[@]}"; do
    cid="${cid//[[:space:]]/}"   # trim spaces just in case
    [[ -z "$cid" ]] && { ((idx++)); continue; }

    # Per-member name: base[1], base[2], ...
    local member_name=""
    if [[ -n "$base_hostname" ]]; then
      member_name="${base_hostname}[${idx}]"
    fi

    mc_log "[$ip] STACK: Attempting claim into network ${net_id} using Cloud ID ${cid} (name='${member_name:-<unchanged>}')…"

    # Pass stack metadata so the memory snapshot knows position
    if meraki_claim_device "$ip" "$cid" "$net_id" "$member_name" "$total" "$idx" "$base_hostname"; then
      any_success=1
      mc_log "[$ip] STACK: Claim SUCCESS for member index ${idx} (Cloud ID ${cid}, name='${member_name:-<unchanged>}')."
    else
      mc_log "[$ip] STACK: Claim FAILED for member index ${idx} (Cloud ID ${cid})."
    fi

    ((idx++))
  done

  if (( any_success )); then
    return 0
  else
    return 1
  fi
}

# ───────────────── Single ─────────────────

# ───────────────── Single ─────────────────
# ───────────────── Single / per-member claim ─────────────────
meraki_claim_device() {
  local ip="$1"
  local cloud_id="$2"
  local net_id="$3"
  local override_name="${4:-}"   # optional per-call name (e.g. base[1])

  # Optional stack metadata used only for JSON memory snapshots
  local stack_count="${5:-1}"
  local member_index="${6:-1}"
  local stack_base_name="${7:-}"

  # Original IOS-XE hostname from the mapping file (if available)
  local host_from_map=""
  host_from_map="$(get_hostname_for_ip "$ip" 2>/dev/null || true)"

  # Final dashboard name:
  #   - If override_name is set (stack member), use that (e.g. c9300-stack1[1])
  #   - Otherwise fall back to host_from_map (single switch)
  local final_name=""
  if [[ -n "$override_name" ]]; then
    final_name="$override_name"
  else
    final_name="$host_from_map"
  fi

  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"
  local rc=0 http_code=""

  if [[ -z "${MERAKI_API_KEY:-}" ]]; then
    mc_log "[$ip] CLAIM: MERAKI_API_KEY not set – skipping claim."
    return 1
  fi

  if [[ -z "$cloud_id" ]]; then
    mc_log "[$ip] CLAIM: No Cloud ID – cannot claim."
    return 1
  fi

  if [[ -z "$net_id" ]]; then
    mc_log "[$ip] CLAIM: No networkId mapping – cannot claim."
    return 1
  fi

  # ---------------- Claim device into network ----------------
  mc_log "[$ip] CLAIM: Attempting claim into network $net_id using Cloud ID $cloud_id…"

  local body
  body="$(jq -n --arg s "$cloud_id" '
    {
      serials: [$s],
      addAtomically: true,
      detailsByDevice: [
        {
          serial: $s,
          details: [
            {"name":"device mode","value":"managed"}
          ]
        }
      ]
    }
  ' )"

  local resp_file
  resp_file="$(mktemp)"
  http_code="$(
    curl -sS -w '%{http_code}' -o "$resp_file" \
      -X POST "${api_base}/networks/${net_id}/devices/claim" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body"
  )" || rc=$?

  if (( rc != 0 )); then
    mc_log "[$ip] CLAIM: curl error (rc=$rc). See $resp_file."
    {
      echo "=== CLAIM curl ERROR (rc=$rc) for IP $ip ==="
      sed -n '1,80p' "$resp_file" 2>/dev/null || true
    } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
    return 1
  fi

  # Treat 2xx as success; also treat 409 as "already claimed" success
  if [[ "$http_code" =~ ^2 || "$http_code" == "409" ]]; then
    mc_log "[$ip] CLAIM: Success into network $net_id using Cloud ID $cloud_id (HTTP $http_code)."
    {
      echo "=== CLAIM SUCCESS into network $net_id using Cloud ID $cloud_id (HTTP $http_code) ==="
    } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
  else
    mc_log "[$ip] CLAIM: FAILED (HTTP $http_code). See $resp_file."
    {
      echo "=== CLAIM FAILED: HTTP $http_code for IP $ip ==="
      sed -n '1,80p' "$resp_file" 2>/dev/null || true
    } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
    return 1
  fi

  # ----------------------------------------------------------
  # After claim: update device address (move map marker)
  # ----------------------------------------------------------
  local addr=""
  addr="$(get_network_address_for_ip "$ip" 2>/dev/null || true)"

  if [[ -z "$addr" ]]; then
    mc_log "[$ip] ADDRESS: No networkAddress found for this IP; skipping address update."
  else
    mc_log "[$ip] ADDRESS: Will try to set device address to: $addr"

    local dev_body resp2 code rc2 tries=0 update_ok=0
    dev_body="$(jq -n --arg a "$addr" \
      '{address:$a, updateLocation:true, moveMapMarker:true}')"

    # Give Dashboard a moment after claim so the device record is visible
    sleep 5

    while (( tries < 5 )); do
      resp2="$(mktemp)"
      rc2=0
      code="$(
        curl -sS -w '%{http_code}' -o "$resp2" \
          -X PUT "${api_base}/devices/${cloud_id}" \
          -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
          -H "Content-Type: application/json" \
          -H "Accept: application/json" \
          --data "$dev_body"
      )" || rc2=$?

      if (( rc2 != 0 )); then
        mc_log "[$ip] ADDRESS: curl error rc=$rc2 (HTTP $code)."
      fi

      # 404/000/503 → device not ready yet: retry
      if [[ "$code" == "404" || "$code" == "000" || "$code" == "503" ]]; then
        ((tries++))
        mc_log "[$ip] ADDRESS: Device not ready yet (HTTP $code). Waiting 5s and retrying ${tries}/5…"
        sleep 5
        rm -f "$resp2"
        continue
      fi

      if [[ "$code" =~ ^2 ]]; then
        mc_log "[$ip] ADDRESS: Successfully updated device address."
        {
          echo "=== ADDRESS UPDATE SUCCESS for Cloud ID $cloud_id (HTTP $code) ==="
        } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
        update_ok=1
      else
        mc_log "[$ip] ADDRESS: FAILED to update device address (HTTP $code)."
        {
          echo "=== ADDRESS UPDATE FAILED for Cloud ID $cloud_id (HTTP $code) ==="
          sed -n '1,80p' "$resp2" 2>/dev/null || true
        } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
      fi

      rm -f "$resp2"
      break
    done

    if (( ! update_ok )); then
      mc_log "[$ip] ADDRESS: Giving up on updating device address after $tries attempt(s)."
    else
      mc_log "[$ip] ADDRESS: Switch released to Dashboard; location now controlled by Dashboard."
    fi
  fi

  # --- NAME UPDATE (uses final_name: either base or base[idx]) ---
  if [[ -n "$final_name" ]]; then
    local name_body resp_name code_name
    name_body="$(jq -n --arg n "$final_name" '{name:$n}')"

    mc_log "[$ip] NAME: Attempting to update device name to '$final_name'..."
    resp_name="$(mktemp)"
    code_name="$(
      curl -sS -w '%{http_code}' -o "$resp_name" \
        -X PUT "${api_base}/devices/${cloud_id}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$name_body"
    )" || true

    if [[ "$code_name" =~ ^2 ]]; then
      mc_log "[$ip] NAME: Successfully updated device name to '$final_name'."
      {
        echo "=== NAME UPDATE SUCCESS for Cloud ID $cloud_id (HTTP $code_name) ==="
      } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
    else
      mc_log "[$ip] NAME: FAILED to update device name (HTTP $code_name)."
      {
        echo "=== NAME UPDATE FAILED for Cloud ID $cloud_id (HTTP $code_name) ==="
        sed -n '1,80p' "$resp_name" 2>/dev/null || true
      } >>"$RUN_DIR/devlogs/${ip}_meraki_connect.log" 2>/dev/null || true
    fi
  fi

  # --- JSON MEMORY SNAPSHOT ---
  mc_record_meraki_memory "$ip" "$cloud_id" "$final_name" "$stack_count" "$member_index" "$stack_base_name"

  return 0
}
# -----------------Stack Worker -----------------------
# Run "show meraki" on a switch and log stack information (if any).
meraki_log_stack_state() {
  local ip="$1"
  local LOGFILE="$2"

  local raw norm rc=0
  local stack_env=""
  if [[ -n "${RUN_DIR:-}" ]]; then
    stack_env="$RUN_DIR/stack_members.${ip}.env"
  else
    stack_env=""
  fi

  raw="$(mktemp)"
  norm="$(mktemp)"

  {
    echo
    echo "---- $(date +'%Y-%m-%d %H:%M:%S %Z') – show meraki ----"

    sshpass -p "$IOS_PASSWORD" \
      ssh -o StrictHostKeyChecking=accept-new \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=25 \
          -tt "$IOS_USERNAME@$ip" 2>&1 <<'EOSSH'
terminal length 0
terminal width 511
show meraki
exit
EOSSH

    rc=$?
  } >"$raw"

  tr -d '\r' <"$raw" >"$norm"
  cat "$norm" >>"$LOGFILE"
  rm -f "$raw"

  # Clear any previous env file
  if [[ -n "$stack_env" ]]; then
    rm -f "$stack_env"
  fi

  if (( rc != 0 )); then
    mc_log "[$ip] STACK: 'show meraki' failed over SSH (rc=$rc) – treating as non-stack."
    return 0
  fi

  local members=()
  local cloud_ids=()

  # Parse the "show meraki" table
  while IFS= read -r line; do
    # Data lines start with a number (switch member)
    [[ "$line" =~ ^[0-9]+[[:space:]]+ ]] || continue

    # Tokenize line
    set -- $line
    local num="$1"
    local pid="$2"
    local serial="$3"
    local cloud="$4"
    local mac="$5"
    local status="$6"
    local mode="${*:7}"

    mc_log "[$ip]   • Member ${num}: PID=${pid}, Serial=${serial}, CloudID=${cloud}, MAC=${mac}, MigrationStatus=${status}, Mode=${mode}"

    members+=("$num")
    if [[ -n "$cloud" && "$cloud" != "-" ]]; then
      cloud_ids+=("$cloud")
    fi
  done <"$norm"

  local count="${#members[@]}"

  if (( count > 1 )); then
  mc_log "[$ip] STACK DETECT: ${count} member switches reported by 'show meraki'."

  if [[ -n "$stack_env" ]]; then
    {
      echo "STACK_COUNT=$count"
      if ((${#cloud_ids[@]})); then
        local joined
        # Join Cloud IDs with commas (e.g. ID1,ID2,ID3)
        joined="$(IFS=,; echo "${cloud_ids[*]}")"
        echo "STACK_CLOUD_IDS=$joined"
      fi
    } >"$stack_env"
  fi

elif (( count == 1 )); then
  mc_log "[$ip] SINGLE DETECT: (1 member; not a stack)."

  if [[ -n "$stack_env" ]]; then
    {
      echo "STACK_COUNT=$count"
      if ((${#cloud_ids[@]})); then
        local joined
        joined="$(IFS=,; echo "${cloud_ids[*]}")"
        echo "STACK_CLOUD_IDS=$joined"
      fi
    } >"$stack_env"
  fi

else
  mc_log "[$ip] STACK: No member lines found in 'show meraki' output – treating as single switch."
fi

  return 0
}
# ───────────────── Per-stack worker ─────────────────
# Parse 'show meraki' output and:
#  - log stack info
#  - write a per-IP stack member file:
#      $3 (e.g. "$RUN_DIR/stack_members.${ip}.txt")
# Format per line in that file:
#   index|pid|serial|cloud_id|mac|migration_status|mode
meraki_parse_stack_members() {
  local ip="$1"
  local infile="$2"
  local outfile="$3"

  [[ -z "$ip" || -z "$infile" || -z "$outfile" ]] && return 0
  [[ ! -s "$infile" ]] && return 0

  # Extract member rows from the "show meraki" table
  local table
  table="$(
    awk '
      /^Switch[[:space:]]+Serial[[:space:]]+Number/ { in_table=1; next }
      in_table && /^-+/ { next }
      in_table && NF >= 6 {
        num=$1
        pid=$2
        serial=$3
        cloud=$4
        mac=$5
        status=$6
        mode=""
        if (NF > 6) {
          mode=$7
          for (i=8; i<=NF; i++) mode = mode " " $i
        }
        printf "%s|%s|%s|%s|%s|%s|%s\n", num,pid,serial,cloud,mac,status,mode
      }
    ' "$infile"
  )"

  if [[ -z "$table" ]]; then
    mc_log "[$ip] STACK: No stack members found in 'show meraki' output."
    return 0
  fi

  : >"$outfile"
  local count=0
  while IFS='|' read -r num pid serial cloud mac status mode; do
    [[ -z "$num" ]] && continue
    ((count++))
    printf "%s|%s|%s|%s|%s|%s|%s\n" \
      "$num" "$pid" "$serial" "$cloud" "$mac" "$status" "$mode" >>"$outfile"
  done <<<"$table"

  if (( count > 1 )); then
  mc_log "[$ip] STACK DETECT: ${count} member switches reported by 'show meraki'."
elif (( count == 1 )); then
  mc_log "[$ip] SINGLE DETECT: (1 member; not a stack)."
fi

while IFS='|' read -r num pid serial cloud mac status mode; do
  [[ -z "$num" ]] && continue
  mc_log "[$ip]   • Member ${num}: PID=${pid}, Serial=${serial}, CloudID=${cloud}, MAC=${mac}, MigrationStatus=${status}, Mode=${mode}"
done <"$outfile"
}
# Claim either a whole stack (all members in stack file) or fall back to single cloud_id
meraki_claim_stack_members() {
  local ip="$1"
  local net_id="$2"
  local stack_file="$3"
  local fallback_cloud_id="${4:-}"

  if [[ -z "$net_id" || -z "${MERAKI_API_KEY:-}" ]]; then
    mc_log "[$ip] STACK: No networkId or API key for stack claim – skipping."
    return 1
  fi

  local any_success=0
  local attempted=0

  if [[ -s "$stack_file" ]]; then
    mc_log "[$ip] STACK: Attempting claim for each stack member into network ${net_id}…"

    local line num pid serial cloud mac status mode
    while IFS='|' read -r num pid serial cloud mac status mode; do
      [[ -z "$num" ]] && continue
      ((attempted++))

      if [[ -z "$cloud" ]]; then
        mc_log "[$ip] STACK: Member ${num} has no Cloud ID – skipping."
        continue
      fi

      mc_log "[$ip] STACK: Member ${num} – claiming Cloud ID ${cloud}…"
      if meraki_claim_device "$ip" "$cloud" "$net_id"; then
        mc_log "[$ip] STACK: Member ${num} claim SUCCESS (Cloud ID ${cloud})."
        any_success=1
      else
        mc_log "[$ip] STACK: Member ${num} claim FAILED (Cloud ID ${cloud})."
      fi
    done <"$stack_file"
  fi

  # If we had no stack file or no usable lines, fall back to single-device claim
  if (( attempted == 0 )) && [[ -n "$fallback_cloud_id" ]]; then
    mc_log "[$ip] STACK: No member list – falling back to single-device claim using Cloud ID ${fallback_cloud_id}."
    if meraki_claim_device "$ip" "$fallback_cloud_id" "$net_id"; then
      any_success=1
    fi
  fi

  if (( any_success )); then
    mc_log "[$ip] STACK: At least one member claim succeeded."
    return 0
  else
    mc_log "[$ip] STACK: All member claims failed."
    return 1
  fi
}



# ───────────────── Per-switch worker ─────────────────

meraki_connect_onboard_ip() {
  local ip="$1"
  local LOGFILE="$2"

  # These will be filled later from per-IP stack env file (if present)
  local stack_count=0
  local stack_cloud_ids=""

  local raw norm rc=0

  : >"$LOGFILE"

  mc_log "[$ip] Starting Meraki connect onboarding…"
  mc_log "[$ip] Logging in and enabling 'service meraki connect'…"

  raw="$(mktemp)"
  norm="$(mktemp)"

  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Initial Meraki connect on $ip ===="
    echo "SSH username: $IOS_USERNAME"
    echo

    sshpass -p "$IOS_PASSWORD" \
      ssh -o StrictHostKeyChecking=accept-new \
          -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=25 \
          -tt "$IOS_USERNAME@$ip" 2>&1 <<'EOSSH'
terminal length 0
terminal width 511
conf t
 service meraki connect
 do show meraki connect
end
exit
EOSSH

    rc=$?
    echo
    echo "==== Initial Meraki connect commands complete (rc=$rc) ===="
  } >"$raw"

  tr -d '\r' <"$raw" >"$norm"
  cat "$norm" >>"$LOGFILE"
  rm -f "$raw"

  if (( rc != 0 )); then
  mc_log "[$ip] SSH ERROR during initial Meraki connect enablement (rc=$rc)."
  echo "SSH_ERROR"
  return 1
fi

  # ----- First status parse -----
  local fetch_ok tunnels_ok reg_ok cloud_id
  local status_line
  status_line="$(meraki_status_from_file "$norm")"
  IFS='|' read -r fetch_ok tunnels_ok reg_ok cloud_id <<<"$status_line"

  mc_log "[$ip] Initial status:"
  if (( fetch_ok )); then
    mc_log "[$ip]   • Fetch State: Config fetch succeeded"
  else
    mc_log "[$ip]   • Fetch State: NOT yet succeeded"
  fi
  if (( tunnels_ok )); then
    mc_log "[$ip]   • Tunnels: Primary=Up, Secondary=Up"
  else
    mc_log "[$ip]   • Tunnels: NOT both Up yet"
  fi
  if (( reg_ok )); then
    mc_log "[$ip]   • Device Registration: Registered (Cloud ID: ${cloud_id:-none})"
  else
    mc_log "[$ip]   • Device Registration: NOT Registered yet."
  fi

   # --- NEW: detect stack + load member Cloud IDs before any claim ---
  meraki_log_stack_state "$ip" "$LOGFILE"

  # Read stack info from env file without sourcing it
  local stack_env="$RUN_DIR/stack_members.${ip}.env"
  if [[ -f "$stack_env" ]]; then
    local sc_tmp sci_tmp
    sc_tmp="$(grep '^STACK_COUNT=' "$stack_env" 2>/dev/null | head -n1 | cut -d= -f2- || true)"
    sci_tmp="$(grep '^STACK_CLOUD_IDS=' "$stack_env" 2>/dev/null | head -n1 | cut -d= -f2- || true)"

    stack_count="${sc_tmp:-0}"
    stack_cloud_ids="${sci_tmp:-}"
  fi

  # networkId mapping (from Phase 2 map file)
  local net_id
  net_id="$(get_network_id_for_ip "$ip" 2>/dev/null || true)"

  if [[ -z "$net_id" ]]; then
    mc_log "[$ip] WARNING: No Meraki networkId mapping found – will enable Meraki connect but skip Dashboard claim."
  fi

  # track whether we've successfully claimed this device / stack
  local claimed=0
  if [[ -f "$RUN_DIR/claimed.$ip" ]]; then
    claimed=1
  fi

  # --- First claim attempt (before polling) ---
  if [[ -n "$net_id" && -n "${MERAKI_API_KEY:-}" && $claimed -eq 0 ]]; then
    if (( stack_count > 1 )) && [[ -n "$stack_cloud_ids" ]]; then
      mc_log "[$ip] STACK: At least one member switch detected; attempting to claim ALL member Cloud IDs into network ${net_id}…"

      if meraki_claim_stack_devices "$ip" "$net_id" "$stack_cloud_ids"; then
        claimed=1
        mc_log "[$ip] STACK: Stack member claim attempts completed (see logs for per-member status)."
      else
        mc_log "[$ip] STACK: All member claims failed – falling back to single-device claim using Cloud ID ${cloud_id:-unknown}."
        if [[ -n "$cloud_id" ]]; then
          if meraki_claim_device "$ip" "$cloud_id" "$net_id"; then
            claimed=1
            mc_log "[$ip] STACK: Fallback single-device claim succeeded."
          else
            mc_log "[$ip] STACK: Fallback single-device claim also failed."
          fi
        fi
      fi

    elif [[ -n "$cloud_id" ]]; then
      mc_log "[$ip] Attempting Dashboard claim using Cloud ID ${cloud_id} into network ${net_id}…"
      if meraki_claim_device "$ip" "$cloud_id" "$net_id"; then
        claimed=1
        mc_log "[$ip] Claim successful (Cloud ID ${cloud_id} into network ${net_id})."
      else
        mc_log "[$ip] Claim attempt failed – will retry while polling."
      fi
    fi
  fi

  # If everything is already perfect + claimed, we’re done.
  if (( fetch_ok && tunnels_ok && reg_ok )); then
    if (( claimed )) || [[ -z "${MERAKI_API_KEY:-}" ]]; then
      mc_log "[$ip] All Meraki connect checks passed and device is claimed."
      mc_log "[$ip] Switch released and under Meraki Dashboard connection control."
      echo "READY"
      return 0
    fi
  fi

  # ----- Poll loop -----
  local max_polls="${MERAKI_CONNECT_MAX_POLLS:-8}"
  local poll_sleep="${MERAKI_CONNECT_POLL_SEC:-15}"
  local poll=1

  while (( poll <= max_polls )); do
    mc_log "[$ip] Poll ${poll}/${max_polls} – waiting ${poll_sleep}s before next check…"
    sleep "$poll_sleep"

    raw="$(mktemp)"
    norm="$(mktemp)"

    {
      echo
      echo "---- $(date +'%Y-%m-%d %H:%M:%S %Z') – Poll ${poll}/${max_polls} ----"

      sshpass -p "$IOS_PASSWORD" \
        ssh -o StrictHostKeyChecking=accept-new \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=25 \
            -tt "$IOS_USERNAME@$ip" 2>&1 <<'EOSSH'
terminal length 0
terminal width 511
conf t
 do show meraki connect
end
exit
EOSSH

      rc=$?
      echo
      echo "---- Poll ${poll}/${max_polls} SSH complete (rc=$rc) ----"
    } >"$raw"

    tr -d '\r' <"$raw" >"$norm"
    cat "$norm" >>"$LOGFILE"
    rm -f "$raw"

    if (( rc != 0 )); then
      mc_log "[$ip] SSH ERROR during poll ${poll} (rc=$rc)."
      echo "SSH_ERROR"
      return 1
    fi

    status_line="$(meraki_status_from_file "$norm")"
    IFS='|' read -r fetch_ok tunnels_ok reg_ok cloud_id <<<"$status_line"

    mc_log "[$ip] Parsed status after poll ${poll}:"
    if (( fetch_ok )); then
      mc_log "[$ip]   • Fetch State: Config fetch succeeded"
    else
      mc_log "[$ip]   • Fetch State: NOT yet succeeded"
    fi
    if (( tunnels_ok )); then
      mc_log "[$ip]   • Tunnels: Primary=Up, Secondary=Up"
    else
      mc_log "[$ip]   • Tunnels: NOT both Up yet"
    fi
    if (( reg_ok )); then
      mc_log "[$ip]   • Device Registration: Registered (Cloud ID: ${cloud_id:-none})"
    else
      mc_log "[$ip]   • Device Registration: NOT Registered yet."
    fi

    # Retry claim if we now have mapping + API key and not yet claimed
    if [[ -n "$net_id" && -n "${MERAKI_API_KEY:-}" && $claimed -eq 0 ]]; then
      if (( stack_count > 1 )) && [[ -n "$stack_cloud_ids" ]]; then
        mc_log "[$ip] STACK: Ensuring stack claim completed (Cloud IDs now available)…"

        if meraki_claim_stack_devices "$ip" "$net_id" "$stack_cloud_ids"; then
          claimed=1
          mc_log "[$ip] STACK: Stack claim succeeded into network ${net_id}."
        else
          mc_log "[$ip] STACK: Stack claim attempt failed again – will keep trying until polling completes."
          if [[ -n "$cloud_id" ]]; then
            mc_log "[$ip] STACK: Falling back to single-device claim using Cloud ID ${cloud_id}."
            if meraki_claim_device "$ip" "$cloud_id" "$net_id"; then
              claimed=1
              mc_log "[$ip] STACK: Fallback single-device claim succeeded."
            else
              mc_log "[$ip] STACK: Fallback single-device claim also failed."
            fi
          fi
        fi

      elif [[ -n "$cloud_id" ]]; then
        mc_log "[$ip] Ensuring claim completed (Cloud ID now available)…"
        if meraki_claim_device "$ip" "$cloud_id" "$net_id"; then
          claimed=1
          mc_log "[$ip] Claim successful (Cloud ID ${cloud_id} into network ${net_id})."
        else
          mc_log "[$ip] Claim attempt failed again – will keep trying until polling completes."
        fi
      fi
    fi

    # Final success condition: ready + claimed (or no API key configured)
    if (( fetch_ok && tunnels_ok && reg_ok )); then
      if (( claimed )) || [[ -z "${MERAKI_API_KEY:-}" ]]; then
        mc_log "[$ip] Meraki connect ready (fetch OK, tunnels UP, device Registered)."
        if (( claimed )); then
          mc_log "[$ip] Device successfully claimed – switch released and under Meraki Dashboard connection control."
        else
          mc_log "[$ip] No MERAKI_API_KEY configured – Meraki connect is ready; you may claim device manually in Dashboard."
        fi
        echo "READY"
        return 0
      fi
    fi

    ((poll++))
  done

  mc_log "[$ip] Meraki connect polling finished without full ready+claimed state."
  mc_log "[$ip] Review ${LOGFILE} and Meraki Dashboard – you may need to complete claim manually."
  echo "PARTIAL"
  return 1
}

# ───────────────── Phase 3 controller ─────────────────

cloud_migration_enable_meraki_connect() {
  local RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/migrate"
  local LATEST_ENV="$RUN_ROOT/latest.env"

  need ssh || return 1
  need sshpass || {
    dlg --backtitle "$BACKTITLE_C" \
        --title "Missing dependency" \
        --msgbox "sshpass is required to non-interactively SSH to the switches.\n\nInstall sshpass and re-run this step." 10 70
    return 1
  }

  if [[ ! -f "$LATEST_ENV" ]]; then
    dlg --backtitle "$BACKTITLE_C" \
        --title "No selection found" \
        --msgbox "Could not find a migration selection run.\n\nMissing file:\n  $LATEST_ENV\n\nRun the switch selection/mapping steps first." 13 80
    return 1
  fi

  set +H
  # shellcheck disable=SC1090
  source "$LATEST_ENV"
  set -H 2>/dev/null || true

  RUN_ID="${MIGRATE_RUN_ID:-}"
  RUN_DIR="${MIGRATE_RUN_DIR:-}"       # NOTE: NOT local – used by meraki_claim_device()
  local SEL_IPS_RAW="${MIGRATE_SELECTED_IPS:-}"
  MIGRATE_MERAKI_MAP_FILE="${MIGRATE_MERAKI_MAP_FILE:-${MERAKI_SWITCH_NETWORK_MAP_FILE:-}}"

  if [[ -z "$RUN_DIR" || -z "$SEL_IPS_RAW" ]]; then
    dlg --backtitle "$BACKTITLE_C" \
        --title "Incomplete selection" \
        --msgbox "latest.env does not contain selected switches.\n\nRun the earlier migration steps again." 12 80
    return 1
  fi

  mkdir -p "$RUN_DIR/devlogs"

  local -a SEL_IPS=()
  read -r -a SEL_IPS <<<"$SEL_IPS_RAW"
  if ((${#SEL_IPS[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_C" \
        --title "No switches selected" \
        --msgbox "There are no switches recorded in MIGRATE_SELECTED_IPS.\n\nRun the switch selection step again." 11 80
    return 1
  fi

  # ---------- SSH + Meraki API ENV ----------
  local ENV_FILE="$CLOUD_ADMIN_BASE/meraki_discovery.env"
  if [[ ! -f "$ENV_FILE" ]]; then
    dlg --backtitle "$BACKTITLE_C" \
        --title "SSH ENV not found" \
        --msgbox "Expected SSH credentials file:\n  $ENV_FILE\n\nCreate meraki_discovery.env with SSH_USERNAME, SSH_PASSWORD and MERAKI_API_KEY before running this step." 14 80
    return 1
  fi

  set +H
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set -H 2>/dev/null || true

  : "${SSH_USERNAME:?SSH_USERNAME is not set in $ENV_FILE}"
  : "${SSH_PASSWORD:?SSH_PASSWORD is not set in $ENV_FILE}"
  IOS_USERNAME="$SSH_USERNAME"
  IOS_PASSWORD="$SSH_PASSWORD"
  MERAKI_API_KEY="${MERAKI_API_KEY:-}"
  # Trim any stray whitespace/CR just in case
  MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"

  # ---------- Summary file ----------
  local SUMMARY_TXT="$RUN_DIR/meraki_connect_summary.txt"
  : >"$SUMMARY_TXT"
  {
    echo "Meraki connect onboarding summary for this migration run"
    echo "========================================================"
    echo
    echo "Run ID:  $RUN_ID"
    echo "Run dir: $RUN_DIR"
    echo
    printf "%-16s %-16s %-18s\n" "IP" "SSH" "Final status"
    printf "%-16s %-16s %-18s\n" "----------------" "----------------" "------------------"
  } >>"$SUMMARY_TXT"

  # ---------- Split-screen UI ----------
  MC_STATUS_FILE="$RUN_DIR/meraki_connect_status.log"
  : >"$MC_STATUS_FILE"

  mc_ui_start

  local total=${#SEL_IPS[@]}
  local done=0

  local ip
  for ip in "${SEL_IPS[@]}"; do
    ((done++))
    local LOGFILE="$RUN_DIR/devlogs/${ip}_meraki_connect.log"

    mc_log "[$ip] === Starting Meraki connect phase (${done}/${total}) ==="

    local final_status
    final_status="$(meraki_connect_onboard_ip "$ip" "$LOGFILE" || true)"

    local ssh_col="OK"
    if [[ "$final_status" == "SSH_ERROR" ]]; then
      ssh_col="SSH_FAIL"
      final_status="SSH_ERROR"
    elif [[ -z "$final_status" ]]; then
      final_status="UNKNOWN"
    fi

    # Collapse multi-line status into a single short label
local summary_status="$final_status"

# Normalize some known states
if [[ "$final_status" == "READY_RELOAD" ]]; then
  summary_status="READY (reload in progress)"
elif grep -q "READY" <<<"$final_status"; then
  if grep -qi "CLAIM" <<<"$final_status"; then
    summary_status="READY (claimed)"
  else
    summary_status="READY"
  fi
elif grep -qi "PARTIAL" <<<"$final_status"; then
  summary_status="PARTIAL"
elif grep -qi "SSH_ERROR" <<<"$final_status"; then
  summary_status="SSH_ERROR"
fi



    printf "%-16s %-16s %-24s\n" "$ip" "$ssh_col" "$summary_status" >>"$SUMMARY_TXT"
    mc_log "[$ip] Final Meraki connect status: $final_status (SSH=$ssh_col). See $LOGFILE for details."

    local pct=$(( done * 100 / total ))
    mc_gauge "$pct" "Processed $done / $total (last: $ip, status: $final_status)"
  done

  mc_gauge 100 "Meraki connect onboarding complete."
  sleep 2
  mc_ui_stop

 dlg --backtitle "$BACKTITLE_C" \
      --title "Meraki connect – results" \
      --textbox "$SUMMARY_TXT" 30 150 || true

  return 0
}

# ============================================================
# Entry point
#   select    -> choose switches for this migration run
#   map       -> map selected switches to Meraki networks
#   enable    -> run service meraki connect on selected switches
#   all       -> select, map, then enable
# ============================================================

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-all}"
  shift || true

  case "$cmd" in
    select)
      cloud_migration_select_switches "$@"
      ;;
    map)
      cloud_migration_map_selected_switches "$@"
      ;;
    enable)
      cloud_migration_enable_meraki_connect "$@"
      ;;
    all|*)
      cloud_migration_select_switches "$@" || exit $?
      cloud_migration_map_selected_switches "$@" || exit $?
      cloud_migration_enable_meraki_connect "$@" || exit $?
      ;;
  esac
fi