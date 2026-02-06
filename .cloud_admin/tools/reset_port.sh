#!/usr/bin/env bash
set -Euo pipefail

# ============================================================
# Meraki Switch Port RESET (OOB Baseline)
# - Builds diff vs baseline
# - Applies selected/all ports
# - WARN (not fail) if Meraki ignores a field
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
MERAKI_MEMORY_DIR="${MERAKI_MEMORY_DIR:-${CLOUD_ADMIN_BASE}/meraki_memory}"
MERAKI_ENV_FILE="${MERAKI_ENV_FILE:-${CLOUD_ADMIN_BASE}/meraki_discovery.env}"

BACKTITLE_RESET="Meraki Port RESET – OOB Baseline"

# ============================================================
# Run root
# ============================================================

RUN_ID="$(date +'%Y%m%d-%H%M%S')"
RUN_ROOT="${CLOUD_ADMIN_BASE}/runs/port_reset/${RUN_ID}"
RUN_PORTS_DIR="${RUN_ROOT}/ports"
RUN_LOGS_DIR="${RUN_ROOT}/devlogs"
mkdir -p "$RUN_PORTS_DIR" "$RUN_LOGS_DIR" 2>/dev/null || true

RESET_ROOT="${CLOUD_ADMIN_BASE}/runs/port_reset"
ln -sfn "$RUN_ROOT"       "${RESET_ROOT}/latest"
ln -sfn "$RUN_PORTS_DIR"  "${RESET_ROOT}/latest.ports"
ln -sfn "$RUN_LOGS_DIR"   "${RESET_ROOT}/latest.devlogs"

# ============================================================
# Meraki API key
# ============================================================

load_meraki_api_key() {
  if [[ -n "${MERAKI_API_KEY:-}" ]]; then
    export MERAKI_API_KEY
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
    dlg --backtitle "$BACKTITLE_RESET" \
        --title "Meraki API key required" \
        --inputbox "Enter your Meraki Dashboard API key.\n\nIt will be stored (chmod 600) in:\n  $MERAKI_ENV_FILE" \
        13 80
  )" || return 1

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "No API key" \
        --msgbox "No Meraki API key was entered.\n\nCannot continue." 9 70
    return 1
  fi

  MERAKI_API_KEY="$key"
  export MERAKI_API_KEY

  mkdir -p "$(dirname "$MERAKI_ENV_FILE")"
  cat >"$MERAKI_ENV_FILE" <<EOF
# Meraki API key – created by port_reset module
MERAKI_API_KEY="$MERAKI_API_KEY"
EOF
  chmod 600 "$MERAKI_ENV_FILE"
  return 0
}

# ============================================================
# Device selection helpers (from meraki_memory)
# Expected format in each *.json: { ip, serial, cloud_id, ... }
# ============================================================

list_meraki_memory_ips() {
  [[ -d "$MERAKI_MEMORY_DIR" ]] || return 1
  need jq || return 1

  jq -r '
    select(.ip != null and .ip != "" and .serial != null and .serial != "" and .cloud_id != null and .cloud_id != "")
    | "\(.ip)|\(.serial)|\(.cloud_id)"
  ' "$MERAKI_MEMORY_DIR"/*.json 2>/dev/null | awk 'NF'
}

pick_device_from_meraki_memory() {
  local -a items=()
  local line ip serial cloud_id

  while IFS= read -r line; do
    ip="${line%%|*}"
    serial="$(cut -d'|' -f2 <<<"$line")"
    cloud_id="$(cut -d'|' -f3 <<<"$line")"
    items+=( "$ip" "serial=$serial deviceId=$cloud_id" )
  done < <(list_meraki_memory_ips || true)

  if ((${#items[@]} == 0)); then
    dlg --backtitle "$BACKTITLE_RESET" --title "No meraki_memory" \
        --msgbox "No usable entries found under:\n  $MERAKI_MEMORY_DIR\n\nExpected JSONs containing ip, serial, cloud_id." 12 80
    return 1
  fi

  dlg --backtitle "$BACKTITLE_RESET" \
      --title "Choose device" \
      --menu "Select a Meraki switch by IP (from meraki_memory)." \
      20 92 12 \
      "${items[@]}"
}

find_meraki_identity_for_ip() {
  local ip="$1"
  [[ -d "$MERAKI_MEMORY_DIR" ]] || return 1
  need jq || return 1

  jq -r --arg ip "$ip" '
    select(.ip == $ip)
    | "\(.serial // "")|\(.cloud_id // "")"
  ' "$MERAKI_MEMORY_DIR"/*.json 2>/dev/null | awk 'NF {print; exit}'
}

# ============================================================
# Meraki API helpers
# ============================================================

meraki_get_switch_ports() {
  local device_id="$1"
  local out_json="$2"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$device_id" ]] || { echo "No device_id" >&2; return 1; }

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
    echo "curl rc=$rc getting ports for deviceId=$device_id" >&2
    sed -n '1,80p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code getting ports for deviceId=$device_id" >&2
    sed -n '1,80p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_json"
  return 0
}

meraki_put_switch_port() {
  local device_id="$1"
  local port_id="$2"
  local body_json="$3"
  local resp_out="$4"
  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }
  [[ -n "$device_id" ]] || { echo "No device_id" >&2; return 1; }
  [[ -n "$port_id" ]] || { echo "No port_id" >&2; return 1; }

  local http_code
  http_code="$(
    curl -sS -o "$resp_out" -w "%{http_code}" \
      -X PUT "${api_base}/devices/${device_id}/switch/ports/${port_id}" \
      -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json" \
      --data "$body_json"
  )" || http_code="000"

  printf '%s\n' "$http_code"
}

# ============================================================
# Baseline
# ============================================================

baseline_json() {
  # NOTE: Meraki requires linkNegotiation to be a STRING.
  # "Auto negotiate" corresponds to auto/auto (default speed/duplex).
  cat <<'JSON'
{
  "name": "DEFAULT",
  "enabled": true,
  "type": "trunk",
  "vlan": 1,
  "allowedVlans": "1-1000",
  "poeEnabled": true,
  "stpGuard": "disabled",
  "udld": "Alert only",
  "dot3az": { "enabled": false },
  "linkNegotiation": "Auto negotiate"
}
JSON
}

# ============================================================
# Diff build
# ============================================================

build_reset_diff_for_device() {
  local ip="$1"
  local serial="$2"
  local device_id="$3"

  need jq || return 1

  local log="$RUN_LOGS_DIR/${ip}_reset_build.log"
  local ports_current="$RUN_PORTS_DIR/${ip}_${serial}_ports_current.json"
  local diff_json="$RUN_PORTS_DIR/${ip}_${serial}_ports_reset_diff.json"
  local diff_txt="$RUN_PORTS_DIR/${ip}_${serial}_ports_reset_diff.txt"

  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Build RESET diff ===="
    echo "IP: $ip"
    echo "Serial: $serial"
    echo "DeviceId: $device_id"
  } >>"$log"

  echo "Fetching current ports -> $ports_current" >>"$log"
  if ! meraki_get_switch_ports "$device_id" "$ports_current" >>"$log" 2>&1; then
    dlg --backtitle "$BACKTITLE_RESET" --title "Fetch failed" \
        --msgbox "Failed to fetch switch ports for:\n  $ip (serial $serial)\n\nSee log:\n  $log" 12 90
    return 1
  fi

  local baseline
  baseline="$(baseline_json)"

  # Build diff entries (one per port)
  jq -n \
    --arg ip "$ip" \
    --arg serial "$serial" \
    --arg deviceId "$device_id" \
    --argjson baseline "$baseline" \
    --slurpfile ports "$ports_current" '
    def norm_link(x):
      if x == null or x == "" then "Auto negotiate" else x end;

    ($ports[0] // []) as $p
    | $p
    | map({
        portId: (.portId | tostring),
        interface: (.portId | tostring),
        current: {
          enabled: (.enabled // null),
          type: (.type // null),
          vlan: (.vlan // null),
          allowedVlans: (.allowedVlans // null),
          name: (.name // null),
          poeEnabled: (.poeEnabled // null),
          stpGuard: (.stpGuard // null),
          udld: (.udld // null),
          dot3az: (.dot3az // null),
          linkNegotiation: (norm_link(.linkNegotiation // null))
        },
        desired: ($baseline | .linkNegotiation = norm_link(.linkNegotiation // null))
      }
      | .changes = [
          (if (.current.name // null) != (.desired.name // null) then "name" else empty end),
          (if (.current.enabled // null) != (.desired.enabled // null) then "enabled" else empty end),
          (if (.current.type // null) != (.desired.type // null) then "type" else empty end),
          (if (.current.vlan // null) != (.desired.vlan // null) then "vlan" else empty end),
          (if (.current.allowedVlans // null) != (.desired.allowedVlans // null) then "allowedVlans" else empty end),
          (if (.current.poeEnabled // null) != (.desired.poeEnabled // null) then "poeEnabled" else empty end),
          (if (.current.stpGuard // null) != (.desired.stpGuard // null) then "stpGuard" else empty end),
          (if (.current.udld // null) != (.desired.udld // null) then "udld" else empty end),
          # dot3az compare (enabled)
          (if ((.current.dot3az.enabled // null) != (.desired.dot3az.enabled // null)) then "dot3az" else empty end),
          (if (norm_link(.current.linkNegotiation) != norm_link(.desired.linkNegotiation)) then "linkNegotiation" else empty end)
        ]
      | .notes = []
    )
  ' >"$diff_json" 2>>"$log" || {
    dlg --backtitle "$BACKTITLE_RESET" --title "Diff build failed" \
        --msgbox "Failed building diff for:\n  $ip (serial $serial)\n\nSee log:\n  $log" 12 90
    return 1
  }

  # Human summary
  jq -r --arg ip "$ip" --arg serial "$serial" --arg dev "$device_id" '
    def show(x): if x == null or x == "" then "(none/auto)" else (x|tostring) end;

    "RESET diff for IP " + $ip + " (serial " + $serial + ", deviceId " + $dev + ")",
    "======================================================================",
    "",
    "Baseline target:",
    "  - Name: DEFAULT",
    "  - Enabled: true",
    "  - Type: trunk",
    "  - VLAN: 1",
    "  - Allowed VLANs: 1-1000",
    "  - PoE: enabled",
    "  - STP guard: disabled",
    "  - UDLD: Alert only",
    "  - EEE (dot3az): OFF",
    "  - Link negotiation: Auto negotiate",
    "",
    "Ports with changes:",
    "",
    (
      map(select((.changes|length) > 0)) as $c
      | if ($c|length)==0 then "(No changes detected; already matches baseline.)"
        else
          $c[] as $r
          | "Port " + $r.portId + " — " + (($r.changes|length)|tostring) + " change(s)",
            (
              $r.changes[] as $ch
              | if $ch=="name" then "  - name: " + show($r.current.name) + " → " + show($r.desired.name)
                elif $ch=="enabled" then "  - enabled: " + show($r.current.enabled) + " → " + show($r.desired.enabled)
                elif $ch=="type" then "  - type: " + show($r.current.type) + " → " + show($r.desired.type)
                elif $ch=="vlan" then "  - vlan: " + show($r.current.vlan) + " → " + show($r.desired.vlan)
                elif $ch=="allowedVlans" then "  - allowedVlans: " + show($r.current.allowedVlans) + " → " + show($r.desired.allowedVlans)
                elif $ch=="poeEnabled" then "  - poeEnabled: " + show($r.current.poeEnabled) + " → " + show($r.desired.poeEnabled)
                elif $ch=="stpGuard" then "  - stpGuard: " + show($r.current.stpGuard) + " → " + show($r.desired.stpGuard)
                elif $ch=="udld" then "  - udld: " + show($r.current.udld) + " → " + show($r.desired.udld)
                elif $ch=="dot3az" then "  - dot3az.enabled: " + show($r.current.dot3az.enabled) + " → " + show($r.desired.dot3az.enabled)
                elif $ch=="linkNegotiation" then "  - linkNegotiation: " + show($r.current.linkNegotiation) + " → " + show($r.desired.linkNegotiation)
                else empty end
            ),
            ""
        end
    )
  ' "$diff_json" >"$diff_txt" 2>/dev/null || true

  echo "Diff JSON: $diff_json" >>"$log"
  echo "Diff TXT:  $diff_txt" >>"$log"

  if [[ -f "$diff_txt" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" \
        --title "RESET diff built" \
        --textbox "$diff_txt" 30 120 || true
  else
    dlg --backtitle "$BACKTITLE_RESET" \
        --title "RESET diff built" \
        --msgbox "Diff built for:\n  $ip (serial $serial)\n\nFiles:\n  $diff_json\n  $diff_txt" 12 90
  fi

  return 0
}

find_latest_reset_diff_for_ip() {
  local ip="$1"
  local dir="${RESET_ROOT}/latest.ports"
  [[ -d "$dir" ]] || return 1
  ls -1t "$dir"/"${ip}"_*_ports_reset_diff.json 2>/dev/null | head -n1
}

# ============================================================
# Apply + Warn if ignored
# ============================================================

warn_if_ignored_fields() {
  # args: log_file, port_id, requested_body_json, response_json_file
  local log="$1"
  local port="$2"
  local req="$3"
  local resp_file="$4"
  need jq || return 0

  local warnings
  warnings="$(
    jq -n \
      --arg port "$port" \
      --argjson req "$req" \
      --slurpfile resp "$resp_file" '
      def norm_link(x):
        if x == null or x == "" then "Auto negotiate" else x end;

      ($resp[0] // {}) as $r
      | def neq(a;b): (a!=b);
      | [
          (if neq(($r.name//null); ($req.name//null)) then "name" else empty end),
          (if neq(($r.enabled//null); ($req.enabled//null)) then "enabled" else empty end),
          (if neq(($r.type//null); ($req.type//null)) then "type" else empty end),
          (if neq(($r.vlan//null); ($req.vlan//null)) then "vlan" else empty end),
          (if neq(($r.allowedVlans//null); ($req.allowedVlans//null)) then "allowedVlans" else empty end),
          (if neq(($r.poeEnabled//null); ($req.poeEnabled//null)) then "poeEnabled" else empty end),
          (if neq(($r.stpGuard//null); ($req.stpGuard//null)) then "stpGuard" else empty end),
          (if neq(($r.udld//null); ($req.udld//null)) then "udld" else empty end),
          (if neq((($r.dot3az.enabled)//null); (($req.dot3az.enabled)//null)) then "dot3az.enabled" else empty end),
          (if neq(norm_link($r.linkNegotiation//null); norm_link($req.linkNegotiation//null)) then "linkNegotiation" else empty end)
        ] as $w
      | if ($w|length)==0 then empty
        else
          "WARN: Port " + $port + " ignored/overrode fields: " + ($w|join(", "))
        end
    ' 2>/dev/null || true
  )"

  if [[ -n "${warnings:-}" ]]; then
    echo "$warnings" >>"$log"
    echo "$warnings"
  fi
}

apply_reset_diff_for_device() {
  local ip="$1"
  local serial="$2"
  local device_id="$3"
  local diff_file="$4"

  need jq || return 1
  need curl || return 1

  if [[ ! -f "$diff_file" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "No diff" \
        --msgbox "Diff file not found:\n  $diff_file" 10 90
    return 1
  fi

  local log="$RUN_LOGS_DIR/${ip}_reset_apply.log"
  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – APPLY RESET ===="
    echo "IP: $ip"
    echo "Serial: $serial"
    echo "DeviceId: $device_id"
    echo "Diff: $diff_file"
  } >>"$log"

  local tmp_list=""
  tmp_list="$(mktemp)"
  trap '[[ -n "${tmp_list:-}" ]] && rm -f "$tmp_list" 2>/dev/null || true' RETURN

  jq -r '
    .[]
    | select((.changes|length) > 0)
    | [(.portId|tostring), ("changes=" + ((.changes|length)|tostring))] | @tsv
  ' "$diff_file" >"$tmp_list"

  if ! [[ -s "$tmp_list" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "No changes" \
        --msgbox "There are no ports with differences.\n\nAlready matches baseline." 10 70
    return 0
  fi

  local -a items=()
  while IFS=$'\t' read -r pid label; do
    pid="$(trim "$pid")"
    [[ -z "$pid" ]] && continue
    items+=( "$pid" "$label" "on" )
  done <"$tmp_list"

  local choice
  choice="$(
    dlg --backtitle "$BACKTITLE_RESET" \
        --title "Apply mode" \
        --menu "How do you want to apply the RESET?" \
        14 70 6 \
        "selected" "Choose specific ports (checklist)" \
        "all"      "Apply to ALL ports that have changes" \
        "cancel"   "Cancel"
  )" || return 1

  if [[ "$choice" == "cancel" ]]; then
    return 0
  fi

  local -a PORTS_TO_APPLY=()

  if [[ "$choice" == "all" ]]; then
    while IFS=$'\t' read -r pid _; do
      pid="$(trim "$pid")"
      [[ -n "$pid" ]] && PORTS_TO_APPLY+=("$pid")
    done <"$tmp_list"
  else
    local selection
    local term_rows term_cols height width listheight
    term_rows="$(tput lines 2>/dev/null || echo 30)"
    term_cols="$(tput cols  2>/dev/null || echo 120)"
    height=$(( term_rows - 6 )); (( height < 18 )) && height=18
    width=$(( term_cols - 6  )); (( width  < 110 )) && width=110
    (( width > 180 )) && width=180
    listheight=$(( height - 8 )); (( listheight < 8 )) && listheight=8
    (( listheight > 20 )) && listheight=20

    selection="$(
      dlg --backtitle "$BACKTITLE_RESET" \
          --separate-output \
          --checklist "Select ports on IP $ip (serial $serial) to reset to baseline.\n(Use SPACE to toggle, ENTER when done.)" \
          "$height" "$width" "$listheight" \
          "${items[@]}"
    )" || return 1

    selection="$(trim "$selection")"
    if [[ -z "$selection" ]]; then
      dlg --backtitle "$BACKTITLE_RESET" --title "No ports selected" \
          --msgbox "No ports selected.\n\nNothing changed." 9 60
      return 0
    fi

    while IFS= read -r pid; do
      pid="$(trim "$pid")"
      [[ -n "$pid" ]] && PORTS_TO_APPLY+=("$pid")
    done <<<"$selection"
  fi

  local ok=0 fail=0 warn=0
  local baseline
  baseline="$(baseline_json)"

  for p in "${PORTS_TO_APPLY[@]}"; do
    {
      echo ""
      echo "--- Port $p ---"
    } >>"$log"

    # Build full baseline body (includes linkNegotiation as STRING)
    local body
    body="$(jq -c '.' <<<"$baseline" 2>/dev/null || echo "")"

    if [[ -z "$body" ]]; then
      echo "ERROR: could not build baseline JSON body" >>"$log"
      ((fail++))
      continue
    fi

    local resp_file http_code
    resp_file="$(mktemp)"

    http_code="$(meraki_put_switch_port "$device_id" "$p" "$body" "$resp_file")"
    echo "HTTP $http_code" >>"$log"

    if [[ "$http_code" =~ ^20[0-9]$ ]]; then
      echo "SUCCESS port $p" >>"$log"
      ((ok++))

      # Warn if Meraki ignored any requested fields
      local wline
      wline="$(warn_if_ignored_fields "$log" "$p" "$baseline" "$resp_file" || true)"
      if [[ -n "${wline:-}" ]]; then
        ((warn++))
      fi
    else
      echo "FAILED port $p (HTTP $http_code)" >>"$log"
      sed -n '1,120p' "$resp_file" >>"$log" || true
      ((fail++))
    fi

    rm -f "$resp_file" 2>/dev/null || true
  done

  local msg
  msg="RESET apply complete for IP $ip (serial $serial).\n\nSuccess: $ok\nFailed:  $fail\nWarnings: $warn\n\nLog:\n  $log"
  dlg --backtitle "$BACKTITLE_RESET" --title "RESET results" --msgbox "$msg" 14 80

  return 0
}

# ============================================================
# Flows
# ============================================================

build_diff_flow() {
  load_meraki_api_key || return 1

  local ip
  ip="$(pick_device_from_meraki_memory)" || return 1

  local id_line serial device_id
  id_line="$(find_meraki_identity_for_ip "$ip" || true)"
  if [[ -z "$id_line" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "Missing identity" \
        --msgbox "No meraki_memory entry found for IP:\n  $ip" 10 70
    return 1
  fi
  IFS='|' read -r serial device_id <<<"$id_line"

  build_reset_diff_for_device "$ip" "$serial" "$device_id"
}

apply_diff_flow() {
  load_meraki_api_key || return 1

  local ip
  ip="$(pick_device_from_meraki_memory)" || return 1

  local id_line serial device_id
  id_line="$(find_meraki_identity_for_ip "$ip" || true)"
  if [[ -z "$id_line" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "Missing identity" \
        --msgbox "No meraki_memory entry found for IP:\n  $ip" 10 70
    return 1
  fi
  IFS='|' read -r serial device_id <<<"$id_line"

  local diff_file
  diff_file="$(find_latest_reset_diff_for_ip "$ip" || true)"

  if [[ -z "$diff_file" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "No diff found" \
        --msgbox "No reset diff found for IP $ip.\n\nRun \"Build reset diff\" first." 11 70
    return 1
  fi

  apply_reset_diff_for_device "$ip" "$serial" "$device_id" "$diff_file"
}

build_and_apply_now_flow() {
  load_meraki_api_key || return 1

  local ip
  ip="$(pick_device_from_meraki_memory)" || return 1

  local id_line serial device_id
  id_line="$(find_meraki_identity_for_ip "$ip" || true)"
  if [[ -z "$id_line" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "Missing identity" \
        --msgbox "No meraki_memory entry found for IP:\n  $ip" 10 70
    return 1
  fi
  IFS='|' read -r serial device_id <<<"$id_line"

  if build_reset_diff_for_device "$ip" "$serial" "$device_id"; then
    local diff_file
    diff_file="$(find_latest_reset_diff_for_ip "$ip" || true)"
    [[ -n "$diff_file" ]] || return 1
    apply_reset_diff_for_device "$ip" "$serial" "$device_id" "$diff_file"
  fi
}

show_main_menu() {
  while :; do
    local choice
    choice="$(
      dlg --backtitle "$BACKTITLE_RESET" \
          --title "Port RESET (OOB baseline)" \
          --menu "Select an action." \
          18 86 8 \
          "build-diff"    "Build RESET diff for one switch" \
          "apply-diff"    "Apply latest RESET diff for one switch" \
          "build-apply"   "Build diff then apply (one flow)" \
          "exit"          "Exit"
    )" || return 0

    case "$choice" in
      build-diff)  build_diff_flow ;;
      apply-diff)  apply_diff_flow ;;
      build-apply) build_and_apply_now_flow ;;
      exit) return 0 ;;
    esac
  done
}

# ============================================================
# Entry point
# ============================================================

main() {
  need jq   || exit 1
  need curl || exit 1

  local cmd="${1:-menu}"
  shift || true

  case "$cmd" in
    build-diff)  build_diff_flow ;;
    apply-diff)  apply_diff_flow ;;
    build-apply) build_and_apply_now_flow ;;
    menu|*)      show_main_menu ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi