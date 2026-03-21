#!/usr/bin/env bash
set -Euo pipefail

# ============================================================
# Meraki Switch Port RESET (Direct OOB-style reset)
# - Choose Org -> Network -> Switch
# - Remove any LAGs involving the selected switch
# - Reset ALL switch ports on that switch to a baseline
# - No diff/build phase
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
CAT_ADMIN_BASE="${CAT_ADMIN_BASE:-/root/.cat_admin}"
MERAKI_ENV_FILE="${MERAKI_ENV_FILE:-${CAT_ADMIN_BASE}/meraki_discovery.env}"

BACKTITLE_RESET="Meraki Port RESET – OOB-style"

# ============================================================
# Run root
# ============================================================

RUN_ID="$(date +'%Y%m%d-%H%M%S')"
RESET_ROOT="${CAT_ADMIN_BASE}/runs/port_reset"
RUN_ROOT="${RESET_ROOT}/reset-${RUN_ID}"
RUN_PORTS_DIR="${RUN_ROOT}/ports"
RUN_LOGS_DIR="${RUN_ROOT}/devlogs"
mkdir -p "$RUN_PORTS_DIR" "$RUN_LOGS_DIR" 2>/dev/null || true

mkdir -p "$RESET_ROOT" 2>/dev/null || true
ln -sfn "$RUN_ROOT"      "${RESET_ROOT}/latest"
ln -sfn "$RUN_PORTS_DIR" "${RESET_ROOT}/latest.ports"
ln -sfn "$RUN_LOGS_DIR"  "${RESET_ROOT}/latest.devlogs"

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
# Generic API helper
# ============================================================

MERAKI_API_BASE="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"

meraki_api_json() {
  local method="$1"
  local path="$2"
  local out_file="$3"
  local body="${4:-}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }

  local tmp rc http_code
  tmp="$(mktemp)"
  rc=0

  if [[ -n "$body" ]]; then
    http_code="$(
      curl -sS -w '%{http_code}' -o "$tmp" \
        -X "$method" "${MERAKI_API_BASE}${path}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$body"
    )" || rc=$?
  else
    http_code="$(
      curl -sS -w '%{http_code}' -o "$tmp" \
        -X "$method" "${MERAKI_API_BASE}${path}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Accept: application/json"
    )" || rc=$?
  fi

  if (( rc != 0 )); then
    echo "curl rc=$rc ${method} ${path}" >&2
    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  if [[ ! "$http_code" =~ ^2 ]]; then
    echo "HTTP $http_code ${method} ${path}" >&2
    sed -n '1,120p' "$tmp" >&2 || true
    rm -f "$tmp"
    return 1
  fi

  mv "$tmp" "$out_file"
  return 0
}

meraki_api_code() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local resp_out="${4:-/dev/null}"

  [[ -n "${MERAKI_API_KEY:-}" ]] || { echo "MERAKI_API_KEY not set" >&2; return 1; }

  local http_code
  if [[ -n "$body" ]]; then
    http_code="$(
      curl -sS -o "$resp_out" -w '%{http_code}' \
        -X "$method" "${MERAKI_API_BASE}${path}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        --data "$body"
    )" || http_code="000"
  else
    http_code="$(
      curl -sS -o "$resp_out" -w '%{http_code}' \
        -X "$method" "${MERAKI_API_BASE}${path}" \
        -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
        -H "Accept: application/json"
    )" || http_code="000"
  fi

  printf '%s\n' "$http_code"
}

# ============================================================
# Selection helpers
# ============================================================

pick_org() {
  local jf="${RUN_ROOT}/organizations.json"
  meraki_api_json GET "/organizations?perPage=1000" "$jf" || {
    dlg --backtitle "$BACKTITLE_RESET" --title "API error" \
        --msgbox "Failed to fetch organizations." 8 60
    return 1
  }

  local -a items=()
  while IFS=$'\t' read -r oid oname; do
    [[ -n "$oid" ]] || continue
    items+=( "$oid" "$oname" )
  done < <(
    jq -r '.[] | [(.id|tostring), (.name // "(unnamed organization)")] | @tsv' "$jf" 2>/dev/null
  )

  ((${#items[@]} > 0)) || {
    dlg --backtitle "$BACKTITLE_RESET" --title "No organizations" \
        --msgbox "No organizations returned by the API." 8 60
    return 1
  }

  dlg --backtitle "$BACKTITLE_RESET" \
      --title "Choose organization" \
      --menu "Select a Meraki organization." \
      20 90 12 \
      "${items[@]}"
}

pick_network() {
  local org_id="$1"
  local jf="${RUN_ROOT}/org_${org_id}_networks.json"

  meraki_api_json GET "/organizations/${org_id}/networks?perPage=1000" "$jf" || {
    dlg --backtitle "$BACKTITLE_RESET" --title "API error" \
        --msgbox "Failed to fetch networks for organization:\n  $org_id" 9 70
    return 1
  }

  local -a items=()
  while IFS=$'\t' read -r nid nname product_types; do
    [[ -n "$nid" ]] || continue
    items+=( "$nid" "${nname} [${product_types:-unknown}]" )
  done < <(
    jq -r '
      .[]
      | [(.id|tostring), (.name // "(unnamed network)"),
         ((.productTypes // []) | join(","))]
      | @tsv
    ' "$jf" 2>/dev/null
  )

  ((${#items[@]} > 0)) || {
    dlg --backtitle "$BACKTITLE_RESET" --title "No networks" \
        --msgbox "No networks returned for organization:\n  $org_id" 9 70
    return 1
  }

  dlg --backtitle "$BACKTITLE_RESET" \
      --title "Choose network" \
      --menu "Select a Meraki network." \
      22 100 14 \
      "${items[@]}"
}

pick_switch() {
  local network_id="$1"
  local jf="${RUN_ROOT}/network_${network_id}_devices.json"

  meraki_api_json GET "/networks/${network_id}/devices" "$jf" || {
    dlg --backtitle "$BACKTITLE_RESET" --title "API error" \
        --msgbox "Failed to fetch devices for network:\n  $network_id" 9 70
    return 1
  }

  local -a items=()
  while IFS=$'\t' read -r serial name model; do
    [[ -n "$serial" ]] || continue
    items+=( "$serial" "${name} (${model})" )
  done < <(
    jq -r '
      .[]
      | select(.serial != null and .serial != "")
      | select(
          ((.model // "") | test("^(MS|C9)")) or
          ((.firmware // "") | ascii_downcase | contains("switch"))
        )
      | [(.serial|tostring),
         (.name // .serial // "(unnamed device)"),
         (.model // "unknown-model")]
      | @tsv
    ' "$jf" 2>/dev/null
  )

  ((${#items[@]} > 0)) || {
    dlg --backtitle "$BACKTITLE_RESET" --title "No switches found" \
        --msgbox "No switch-like devices were returned for network:\n  $network_id\n\nIf needed, relax the model filter in the script." 11 80
    return 1
  }

  dlg --backtitle "$BACKTITLE_RESET" \
      --title "Choose switch" \
      --menu "Select the switch to reset." \
      22 100 14 \
      "${items[@]}"
}

device_meta_for_serial() {
  local network_id="$1"
  local serial="$2"
  local jf="${RUN_ROOT}/network_${network_id}_devices.json"

  [[ -f "$jf" ]] || return 1

  jq -r --arg s "$serial" '
    .[]
    | select(.serial == $s)
    | [(.name // .serial // "(unnamed device)"), (.model // "unknown-model")]
    | @tsv
  ' "$jf" 2>/dev/null | head -n1
}

# ============================================================
# API actions
# ============================================================

get_switch_ports() {
  local serial="$1"
  local out_json="$2"
  meraki_api_json GET "/devices/${serial}/switch/ports" "$out_json"
}

get_network_link_aggs() {
  local network_id="$1"
  local out_json="$2"
  meraki_api_json GET "/networks/${network_id}/switch/linkAggregations" "$out_json"
}

delete_network_link_agg() {
  local network_id="$1"
  local lag_id="$2"
  local resp_out="$3"
  meraki_api_code DELETE "/networks/${network_id}/switch/linkAggregations/${lag_id}" "" "$resp_out"
}

update_switch_port() {
  local serial="$1"
  local port_id="$2"
  local body_json="$3"
  local resp_out="$4"
  meraki_api_code PUT "/devices/${serial}/switch/ports/${port_id}" "$body_json" "$resp_out"
}

# ============================================================
# Baseline
# ============================================================

baseline_json() {
  cat <<'JSON'
{
  "name": "DEFAULT",
  "tags": [],
  "enabled": true,
  "poeEnabled": true,
  "type": "trunk",
  "vlan": 1,
  "allowedVlans": "1-1000",
  "isolationEnabled": false,
  "rstpEnabled": true,
  "stpGuard": "disabled",
  "stpPortFastTrunk": false,
  "linkNegotiation": "Auto negotiate",
  "portScheduleId": null,
  "udld": "Alert only",
  "stormControlEnabled": false,
  "daiTrusted": false,
  "profile": {
    "enabled": false
  }
}
JSON
}

# ============================================================
# Compare requested vs response and warn
# ============================================================

warn_if_ignored_fields() {
  local log="$1"
  local port="$2"
  local req_json="$3"
  local resp_file="$4"

  local warnings
  warnings="$(
    jq -n \
      --arg port "$port" \
      --argjson req "$req_json" \
      --slurpfile resp "$resp_file" '
      ($resp[0] // {}) as $r
      | [
          (if (($r.name // null) != ($req.name // null)) then "name" else empty end),
          (if (($r.enabled // null) != ($req.enabled // null)) then "enabled" else empty end),
          (if (($r.poeEnabled // null) != ($req.poeEnabled // null)) then "poeEnabled" else empty end),
          (if (($r.type // null) != ($req.type // null)) then "type" else empty end),
          (if (($r.vlan // null) != ($req.vlan // null)) then "vlan" else empty end),
          (if (($r.allowedVlans // null) != ($req.allowedVlans // null)) then "allowedVlans" else empty end),
          (if (($r.isolationEnabled // null) != ($req.isolationEnabled // null)) then "isolationEnabled" else empty end),
          (if (($r.rstpEnabled // null) != ($req.rstpEnabled // null)) then "rstpEnabled" else empty end),
          (if (($r.stpGuard // null) != ($req.stpGuard // null)) then "stpGuard" else empty end),
          (if (($r.stpPortFastTrunk // null) != ($req.stpPortFastTrunk // null)) then "stpPortFastTrunk" else empty end),
          (if (($r.linkNegotiation // null) != ($req.linkNegotiation // null)) then "linkNegotiation" else empty end),
          (if (($r.portScheduleId // null) != ($req.portScheduleId // null)) then "portScheduleId" else empty end),
          (if (($r.udld // null) != ($req.udld // null)) then "udld" else empty end),
          (if (($r.stormControlEnabled // null) != ($req.stormControlEnabled // null)) then "stormControlEnabled" else empty end),
          (if (($r.daiTrusted // null) != ($req.daiTrusted // null)) then "daiTrusted" else empty end),
          (if (($r.profile.enabled // null) != ($req.profile.enabled // null)) then "profile.enabled" else empty end)
        ] as $w
      | if ($w|length)==0 then empty
        else "WARN: Port " + $port + " ignored/overrode fields: " + ($w|join(", "))
        end
      ' 2>/dev/null || true
  )"

  if [[ -n "${warnings:-}" ]]; then
    echo "$warnings" >>"$log"
    echo "$warnings"
  fi
}

# ============================================================
# Reset flow
# ============================================================

remove_lags_for_switch() {
  local network_id="$1"
  local serial="$2"
  local log="$3"

  local lag_json="${RUN_ROOT}/network_${network_id}_link_aggs.json"
  if ! get_network_link_aggs "$network_id" "$lag_json" >>"$log" 2>&1; then
    echo "WARN: Could not fetch link aggregations for network ${network_id}" >>"$log"
    return 0
  fi

  mapfile -t lag_ids < <(
    jq -r --arg serial "$serial" '
      .[]
      | select(any(.switchPorts[]?; .serial == $serial))
      | .id
    ' "$lag_json" 2>/dev/null
  )

  if ((${#lag_ids[@]} == 0)); then
    echo "No LAGs found involving switch ${serial}" >>"$log"
    return 0
  fi

  local lag_id resp http_code
  for lag_id in "${lag_ids[@]}"; do
    resp="$(mktemp)"
    http_code="$(delete_network_link_agg "$network_id" "$lag_id" "$resp")"
    echo "Delete LAG ${lag_id}: HTTP ${http_code}" >>"$log"
    if [[ ! "$http_code" =~ ^20[0-9]$|^204$ ]]; then
      echo "WARN: Failed deleting LAG ${lag_id}" >>"$log"
      sed -n '1,120p' "$resp" >>"$log" 2>/dev/null || true
    fi
    rm -f "$resp"
  done
}

reset_all_ports_on_switch() {
  local org_id="$1"
  local network_id="$2"
  local serial="$3"
  local switch_name="$4"
  local switch_model="$5"

  local log="${RUN_LOGS_DIR}/${serial}_reset_apply.log"
  local ports_json="${RUN_PORTS_DIR}/${serial}_ports_current.json"
  local results_jsonl="${RUN_PORTS_DIR}/${serial}_results.jsonl"

  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – DIRECT RESET START ===="
    echo "Org ID:     $org_id"
    echo "Network ID: $network_id"
    echo "Switch:     $switch_name"
    echo "Model:      $switch_model"
    echo "Serial:     $serial"
    echo ""
  } >>"$log"

  echo "Removing LAGs involving this switch..." >>"$log"
  remove_lags_for_switch "$network_id" "$serial" "$log"

  echo "Fetching current port list..." >>"$log"
  if ! get_switch_ports "$serial" "$ports_json" >>"$log" 2>&1; then
    dlg --backtitle "$BACKTITLE_RESET" --title "Fetch failed" \
        --msgbox "Failed to fetch switch ports for:\n  $switch_name ($serial)\n\nSee log:\n  $log" 12 90
    return 1
  fi

  local baseline
  baseline="$(baseline_json)"

  local count
  count="$(jq 'length' "$ports_json" 2>/dev/null || echo 0)"
  if [[ "$count" == "0" ]]; then
    dlg --backtitle "$BACKTITLE_RESET" --title "No ports found" \
        --msgbox "No switch ports were returned for:\n  $switch_name ($serial)" 10 70
    return 1
  fi

  local confirm
  confirm="$(
    dlg --backtitle "$BACKTITLE_RESET" \
        --title "Confirm full reset" \
        --menu "This will:\n- remove any LAGs involving this switch\n- reset ALL ${count} ports on the selected switch\n- set Name to DEFAULT\n- set trunk/native VLAN 1/allowed VLANs 1-1000\n- clear schedule/profile and apply OOB-style defaults\n\nContinue?" \
        18 90 6 \
        "yes" "Yes, reset this switch now" \
        "no"  "No, cancel"
  )" || return 1

  [[ "$confirm" == "yes" ]] || return 0

  : >"$results_jsonl"

  local ok=0 fail=0 warn=0
  local port_id body resp_file http_code wline

  while IFS= read -r port_id; do
    [[ -n "$port_id" ]] || continue

    {
      echo ""
      echo "--- Port ${port_id} ---"
    } >>"$log"

    body="$(jq -c '.' <<<"$baseline" 2>/dev/null || true)"
    if [[ -z "$body" ]]; then
      echo "ERROR: could not build baseline JSON body for port ${port_id}" >>"$log"
      ((fail++))
      continue
    fi

    resp_file="$(mktemp)"
    http_code="$(update_switch_port "$serial" "$port_id" "$body" "$resp_file")"
    echo "HTTP ${http_code}" >>"$log"

    if [[ "$http_code" =~ ^20[0-9]$ ]]; then
      echo "SUCCESS port ${port_id}" >>"$log"
      ((ok++))

      wline="$(warn_if_ignored_fields "$log" "$port_id" "$baseline" "$resp_file" || true)"
      if [[ -n "${wline:-}" ]]; then
        ((warn++))
      fi

      jq -cn \
        --arg portId "$port_id" \
        --arg status "success" \
        --arg httpCode "$http_code" \
        '{portId:$portId,status:$status,httpCode:$httpCode}' >>"$results_jsonl" 2>/dev/null || true
      echo >>"$results_jsonl"
    else
      echo "FAILED port ${port_id} (HTTP ${http_code})" >>"$log"
      sed -n '1,120p' "$resp_file" >>"$log" 2>/dev/null || true
      ((fail++))

      jq -cn \
        --arg portId "$port_id" \
        --arg status "failed" \
        --arg httpCode "$http_code" \
        '{portId:$portId,status:$status,httpCode:$httpCode}' >>"$results_jsonl" 2>/dev/null || true
      echo >>"$results_jsonl"
    fi

    rm -f "$resp_file" 2>/dev/null || true
  done < <(jq -r '.[].portId | tostring' "$ports_json" 2>/dev/null)

  local msg
  msg="Reset complete for:\n  ${switch_name} (${serial})\n\nSuccess:  ${ok}\nFailed:   ${fail}\nWarnings: ${warn}\n\nRun root:\n  ${RUN_ROOT}\n\nLog:\n  ${log}"
  dlg --backtitle "$BACKTITLE_RESET" --title "Reset results" --msgbox "$msg" 16 90

  return 0
}

reset_one_switch_flow() {
  load_meraki_api_key || return 1

  local org_id network_id serial meta switch_name switch_model
  org_id="$(pick_org)" || return 1
  network_id="$(pick_network "$org_id")" || return 1
  serial="$(pick_switch "$network_id")" || return 1

  meta="$(device_meta_for_serial "$network_id" "$serial" || true)"
  switch_name="$(cut -f1 <<<"$meta")"
  switch_model="$(cut -f2 <<<"$meta")"

  [[ -n "$switch_name" ]] || switch_name="$serial"
  [[ -n "$switch_model" ]] || switch_model="unknown-model"

  reset_all_ports_on_switch "$org_id" "$network_id" "$serial" "$switch_name" "$switch_model"
}

show_main_menu() {
  while :; do
    local choice
    choice="$(
      dlg --backtitle "$BACKTITLE_RESET" \
          --title "Port RESET (direct)" \
          --menu "Select an action." \
          14 82 6 \
          "reset-now" "Choose Org -> Network -> Switch and reset all ports now" \
          "exit"      "Exit"
    )" || return 0

    case "$choice" in
      reset-now) reset_one_switch_flow ;;
      exit) return 0 ;;
    esac
  done
}

main() {
  need jq   || exit 1
  need curl || exit 1

  local cmd="${1:-menu}"
  shift || true

  case "$cmd" in
    reset-now) reset_one_switch_flow ;;
    menu|*)    show_main_menu ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi