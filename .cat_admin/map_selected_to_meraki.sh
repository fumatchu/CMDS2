#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# map_selected_to_meraki.sh
#   - dialog-driven mapping: selected_upgrade.json -> Meraki device in a network
#   - reads MERAKI_API_KEY from meraki_discovery.env
#   - safe dialog output capture via --output-fd 1
#
# SOURCE STACK SUPPORT:
#   - If a source entry is a stack, it is expanded into per-member rows:
#       hostname[1], hostname[2], ...
#   - Expansion no longer requires stack_serials[] to exist.
#   - Stack evidence can come from:
#       is_stack:true + stack_members > 1
#       or stack_detail.members length > 1
#       or stack_serials length > 1
#       or stack_macs length > 1
#
# TARGET SCOPE:
#   - Select ONE org for the run
#   - Map source rows into MULTIPLE networks inside that org
#   - Different source rows may map to different networks
#
# OUTPUT:
#   runs/mappings/map-<UTCSTAMP>/mapping.json
#   runs/mappings/latest -> that run dir
#   meraki_switch_map.json (merged latest-per-source.key)
#
# CLOUD CONFIG / MONITORING BLOCKING:
#   - Uses org inventory details[] field: "Cloud configuration"
#   - If cloud configuration == "monitoring" -> NONCOMPLIANT (blocked)
#   - If cloud configuration missing -> treated by CFG_UNKNOWN_POLICY (default: allow)
#
# IMPORTANT TERMINOLOGY:
#   - Meraki API uses field name "serial" everywhere.
#   - For Catalyst in Meraki, that value is your "Cloud ID" (Q5TD-....).
#   - We treat "serial" == "cloud_id" and DO NOT use "Catalyst serial" for anything.
#
# GUARDRAILS:
#   - Wizard asks whether to enable guardrails.
#   - When enabled (WARN/CONFIRM), it prompts before “risky/illegal” mappings:
#       1) Mapping a non-stacked source to a target that is a Meraki switch stack
#       2) Splitting a source stack across multiple target stacks/devices
#       3) Mapping between different copper port counts (24 vs 48, etc.)
#   - Default behavior is WARN/CONFIRM (not hard-block).
# ============================================================

: "${DIALOG:=dialog}"

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
BASE_DIR="$SCRIPT_DIR"

SELECTED_JSON="${SELECTED_JSON:-$BASE_DIR/selected_upgrade.json}"
DISCOVERY_JSON="${DISCOVERY_JSON:-$BASE_DIR/discovery_results.json}"
ENV_FILE="${ENV_FILE:-$BASE_DIR/meraki_discovery.env}"

RUN_ROOT="$BASE_DIR/runs/mappings"
API_BASE="https://api.meraki.com/api/v1"

# Policy for when Cloud configuration detail is missing
#   allow   -> treat as OK
#   exclude -> treat as NONCOMPLIANT
CFG_UNKNOWN_POLICY="${CFG_UNKNOWN_POLICY:-allow}"   # allow|exclude

# Guardrails:
#   off  -> do not prompt
#   warn -> confirm dialogs on risky mappings
GUARDRAILS_MODE="${GUARDRAILS_MODE:-ask}"  # ask|off|warn

# ---------------- dialog wrapper (SAFE) ----------------
DIALOG_HAS_OUTPUT_FD=0
DIALOG_HAS_STDOUT=0
if "$DIALOG" --help 2>&1 | grep -q -- '--output-fd'; then DIALOG_HAS_OUTPUT_FD=1; fi
if "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then DIALOG_HAS_STDOUT=1; fi

dlg() {
  local common=(--clear --ok-label "Continue" --cancel-label "Back")
  if [[ $DIALOG_HAS_OUTPUT_FD -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --output-fd 1 "$@" 2>/dev/tty
    return $?
  fi
  if [[ $DIALOG_HAS_STDOUT -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --stdout "$@" 2>/dev/tty
    return $?
  fi
  echo "ERROR: dialog supports neither --output-fd nor --stdout. Install a newer 'dialog'." >&2
  return 1
}

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; return 1; }; }

# ---------------- model / port helpers ----------------
model_copper_port_count() {
  local model="${1:-}"
  local up
  up="$(tr '[:lower:]' '[:upper:]' <<<"$model")"

  if [[ "$up" =~ (^|[^0-9])48([^0-9]|$) ]]; then echo 48; return 0; fi
  if [[ "$up" =~ (^|[^0-9])24([^0-9]|$) ]]; then echo 24; return 0; fi
  if [[ "$up" =~ (^|[^0-9])16([^0-9]|$) ]]; then echo 16; return 0; fi
  if [[ "$up" =~ (^|[^0-9])12([^0-9]|$) ]]; then echo 12; return 0; fi
  if [[ "$up" =~ (^|[^0-9])8([^0-9]|$) ]]; then echo 8; return 0; fi

  echo ""
}

source_target_port_mismatch_confirm() {
  local src_disp="$1"
  local src_pid="$2"
  local tgt_cid="$3"
  local tgt_name="$4"
  local tgt_model="$5"
  local tgt_netname="$6"

  local src_ports tgt_ports
  src_ports="$(model_copper_port_count "$src_pid")"
  tgt_ports="$(model_copper_port_count "$tgt_model")"

  log_status "Port-count check: source_pid='$src_pid' -> ${src_ports:-unknown}, target_model='$tgt_model' -> ${tgt_ports:-unknown}, target_cloud_id='$tgt_cid', target_network='$tgt_netname'"

  [[ -n "$src_ports" && -n "$tgt_ports" ]] || return 0
  [[ "$src_ports" == "$tgt_ports" ]] && return 0

  if ! guardrails_confirm "Guardrail: Copper Port Count Mismatch" \
    "The source and target appear to have different copper port counts.\n\nSOURCE:\n  $src_disp\n  PID: $src_pid\n  Copper ports detected: $src_ports\n\nTARGET:\n  $tgt_cid\n  ${tgt_name:-<unnamed>}\n  Model: $tgt_model\n  Network: ${tgt_netname:-<unknown>}\n  Copper ports detected: $tgt_ports\n\nThis may require port remapping, split migrations, or leaving ports unmapped.\n\nContinue anyway?"; then
    return 1
  fi

  return 0
}

# ---------------- run structure ----------------
RUN_ID="map-$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="$RUN_ROOT/$RUN_ID"
DEVLOG_DIR="$RUN_DIR/devlogs"
STATUS_LOG="$RUN_DIR/status.log"
MERAKI_LOG="$RUN_DIR/meraki_api.log"
MAP_JSON="$RUN_DIR/mapping.json"
MAP_SUMMARY="$RUN_DIR/mapping_summary.txt"

GLOBAL_MAP_JSON="$BASE_DIR/meraki_switch_map.json"

mkdir -p "$DEVLOG_DIR"
: >"$STATUS_LOG"
: >"$MERAKI_LOG"

log_status() {
  local msg="$1"
  printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$msg" >>"$STATUS_LOG"
}

mask_key() {
  local k="${1-}" n
  n=${#k}
  if (( n > 8 )); then
    printf '%s…%s (len=%s)' "${k:0:4}" "${k: -4}" "$n"
  else
    printf '(len=%s)' "$n"
  fi
}

# ---------------- Meraki API helpers ----------------
AUTH_MODE="${AUTH_MODE:-auto}"   # auto|bearer|x-cisco

TMPDIR="$(mktemp -d)"
CACHE_DIR="$TMPDIR/netcache"
mkdir -p "$CACHE_DIR"

cleanup() { rm -rf "$TMPDIR" 2>/dev/null || true; }
trap cleanup EXIT

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
  local -a attempt_modes=()

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

      if [[ "$code" == "429" ]]; then
        local wait
        wait="$(awk '/^Retry-After:/ {print $2}' "$TMPDIR/last_headers" | tr -d '\r')"
        [[ -z "$wait" ]] && wait=1
        sleep "$wait"
        continue
      fi
      break
    done

    if [[ "$code" == "401" && "$AUTH_MODE" == "auto" && "$mode" == "bearer" ]]; then
      continue
    fi

    AUTH_MODE="$mode"
    break
  done

  {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] $method $path$query"
    echo "  auth_mode=$AUTH_MODE http_status=$code api_key=$(mask_key "${MERAKI_API_KEY-}")"
    if [[ -n "$body" ]]; then
      echo "  request_body: $body"
    fi
    if ! [[ "$code" =~ ^20[0-9]$ ]]; then
      echo "  response_body (first 60 lines):"
      sed -n '1,60p' "$TMPDIR/last_body" 2>/dev/null || true
    fi
    echo "------------------------------------------------------------"
  } >>"$MERAKI_LOG" 2>&1

  echo "$code" >"$TMPDIR/code.$$"
}

_meraki_get_all_pages() {
  local path="$1" query="${2:-?perPage=1000}"
  local accum="$TMPDIR/accum.$$"
  printf '[]' >"$accum"
  local nextStart=""

  while :; do
    local q="$query"
    [[ -n "$nextStart" ]] && q="${query}&startingAfter=$nextStart"

    _meraki_call GET "$path" "" "$q"
    local code; code="$(cat "$TMPDIR/code.$$")"
    if ! [[ "$code" =~ ^20[01]$ ]]; then
      return 1
    fi

    jq -s '.[0] + .[1]' "$accum" "$TMPDIR/last_body" >"$accum.tmp" && mv "$accum.tmp" "$accum"

    local link; link="$(grep -i '^Link:' "$TMPDIR/last_headers" | tr -d '\r' || true)"
    if grep -qi 'rel="next"' <<<"$link"; then
      nextStart="$(grep -oi 'startingAfter=[^&>;]*' <<<"$link" | tail -n1 | cut -d= -f2)"
      [[ -z "$nextStart" ]] && break
    else
      break
    fi
  done

  cat "$accum"
}

# ---------------- load env ----------------
load_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    dlg --backtitle "Meraki Mapping" --title "Missing env file" \
      --msgbox "Expected env file not found:\n\n  $ENV_FILE\n\nThis file must define:\n  export MERAKI_API_KEY=...\n\nFix that and re-run." 14 78
    exit 1
  fi

  set +H
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set -H 2>/dev/null || true

  : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"
  MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"
}

# ---------------- guardrails UI ----------------
pick_guardrails_mode() {
  if [[ "$GUARDRAILS_MODE" != "ask" ]]; then
    return 0
  fi

  local choice
  choice="$(dlg --backtitle "Meraki Mapping" --title "Guardrails" \
    --menu "Enable guardrails?\n\nGuardrails will WARN/CONFIRM on risky mappings:\n - Mapping a standalone source into a target stack\n - Splitting a source stack across multiple targets\n - Mapping between different copper port counts\n\n(They do NOT block; they just make you confirm.)" \
    20 88 8 \
    "warn" "ON  (warn + confirm prompts)" \
    "off"  "OFF (no prompts)" )" || exit 1

  GUARDRAILS_MODE="$choice"
  log_status "Guardrails mode: $GUARDRAILS_MODE"
}

guardrails_confirm() {
  local title="$1"
  local msg="$2"

  [[ "${GUARDRAILS_MODE:-off}" == "off" ]] && return 0

  "$DIALOG" --backtitle "Meraki Mapping" --title "$title" \
    --yesno "$msg" 18 96
  return $?
}

# ---------------- normalize selection (STACK -> member rows) ----------------
normalize_selected_sources() {
  local in_json="$1"
  jq '
    def arr(x):
      if (x | type) == "array" then x else [] end;

    def obj(x):
      if (x | type) == "object" then x else {} end;

    map(
      . as $o
      | (arr($o.stack_detail.members)) as $sdm
      | (arr($o.stack_serials)) as $sss
      | (arr($o.stack_macs)) as $sms
      | (obj($o.hw_detail.members)) as $hwm

      | if (($o.is_stack // false) == true) and (
           (($o.stack_members // 0) > 1)
           or (($sdm | length) > 1)
           or (($sss | length) > 1)
           or (($sms | length) > 1)
         ) then

          if ($sdm | length) > 0 then
            $sdm
            | map(select(type == "object"))
            | sort_by(.member_index // 999999)
            | map(
                (.member_index // 1) as $idx
                | {
                    key: (($o.ip // "") + "|" + ($idx|tostring)),
                    ip: ($o.ip // ""),
                    stack_ip: ($o.ip // ""),
                    hostname: ($o.hostname // ""),
                    hostname_disp: (($o.hostname // "") + "[" + ($idx|tostring) + "]"),
                    pid: (
                      ($hwm[$idx|tostring].chassis_pid // "")
                      | if . != "" then . else ($o.pid // "") end
                    ),
                    serial: (
                      ($hwm[$idx|tostring].chassis_sn // "")
                      | if . != "" then . else ($sss[$idx - 1] // "") end
                    ),
                    cloud_id: ($o.cloud_id // ""),
                    is_stack: true,
                    member_index: $idx,
                    member_role: (.role // ""),
                    member_state: (.state // ""),
                    member_mac: (
                      (.mac // "")
                      | if . != "" then . else ($sms[$idx - 1] // $o.base_mac // "") end
                    )
                  }
              )
          else
            [ range(1; (($o.stack_members // 1) + 1)) as $idx
              | {
                  key: (($o.ip // "") + "|" + ($idx|tostring)),
                  ip: ($o.ip // ""),
                  stack_ip: ($o.ip // ""),
                  hostname: ($o.hostname // ""),
                  hostname_disp: (($o.hostname // "") + "[" + ($idx|tostring) + "]"),
                  pid: (
                    ($hwm[$idx|tostring].chassis_pid // "")
                    | if . != "" then . else ($o.pid // "") end
                  ),
                  serial: (
                    ($hwm[$idx|tostring].chassis_sn // "")
                    | if . != "" then . else ($sss[$idx - 1] // "") end
                  ),
                  cloud_id: ($o.cloud_id // ""),
                  is_stack: true,
                  member_index: $idx,
                  member_role: "",
                  member_state: "",
                  member_mac: ($sms[$idx - 1] // $o.base_mac // "")
                }
            ]
          end

        else
          [{
            key: (($o.ip // "") + "|1"),
            ip: ($o.ip // ""),
            stack_ip: ($o.ip // ""),
            hostname: ($o.hostname // ""),
            hostname_disp: ($o.hostname // ""),
            pid: ($o.pid // ""),
            serial: ($o.serial // ""),
            cloud_id: ($o.cloud_id // ""),
            is_stack: false,
            member_index: 1,
            member_role: "",
            member_state: "",
            member_mac: ($o.base_mac // "")
          }]
        end
    )
    | add
  ' "$in_json"
}

# ---------------- load selected switches ----------------
best_source_pid_for_key() {
  local key="$1"
  local pid_norm ip member_idx pid_enriched

  pid_norm="$(jq -r --arg k "$key" '.[] | select(.key==$k) | (.pid // "")' "$TMPDIR/selected_norm.json" | head -n1)"
  pid_norm="$(trim "$pid_norm")"
  if [[ -n "$pid_norm" ]]; then
    printf '%s' "$pid_norm"
    return 0
  fi

  ip="${key%%|*}"
  member_idx="${key##*|}"

  pid_enriched="$(jq -r --arg ip "$ip" --arg idx "$member_idx" '
    .[]
    | select((.ip // "") == $ip)
    | (
        .hw_detail.members[$idx].chassis_pid
        // .pid
        // ""
      )
  ' "$TMPDIR/sel_enriched.json" | head -n1)"
  pid_enriched="$(trim "$pid_enriched")"

  printf '%s' "$pid_enriched"
}

load_selected() {
  need jq || exit 1
  if [[ ! -s "$SELECTED_JSON" ]]; then
    dlg --backtitle "Meraki Mapping" --title "Missing selection" \
      --msgbox "Selected file not found or empty:\n\n  $SELECTED_JSON\n\nRun your selection step first." 12 78
    exit 1
  fi

  local enriched="$TMPDIR/sel_enriched.json"

  if [[ -s "$DISCOVERY_JSON" ]]; then
    jq -s '
      (.[0] // []) as $sel
      | (.[1] // []) as $disc
      | $sel
      | map(
          . as $s
          | ($disc[]? | select(.ip == $s.ip)) as $d
          | {
              ip:        ($s.ip),
              hostname:  ($s.hostname // $d.hostname // ""),
              pid:       ($s.pid // $d.pid // ""),
              serial:    ($s.serial // $d.serial // ""),
              cloud_id:  ($s.cloud_id // $d.cloud_id // $d.cloudId // ""),
              base_mac:  ($d.base_mac // ""),
              is_stack:  ($d.is_stack // false),
              stack_members: ($d.stack_members // 0),
              stack_serials: ($d.stack_serials // []),
              stack_macs:    ($d.stack_macs // []),
              stack_detail:  ($d.stack_detail // {}),
              hw_detail:     ($d.hw_detail // {source:"", members:{}})
            }
        )
    ' "$SELECTED_JSON" "$DISCOVERY_JSON" >"$enriched" 2>/dev/null || cp "$SELECTED_JSON" "$enriched"
  else
    jq '
      map({
        ip:.ip,
        hostname:(.hostname//""),
        pid:(.pid//""),
        serial:(.serial//""),
        cloud_id:(.cloud_id//.cloudId//""),
        base_mac:(.base_mac//""),
        is_stack:(.is_stack//false),
        stack_members:(.stack_members//0),
        stack_serials:(.stack_serials//[]),
        stack_macs:(.stack_macs//[]),
        stack_detail:(.stack_detail//{}),
        hw_detail:(.hw_detail//{source:"", members:{}})
      })
    ' "$SELECTED_JSON" >"$enriched"
  fi

  local count
  count="$(jq 'length' "$enriched" 2>/dev/null || echo 0)"
  if [[ "$count" == "0" ]]; then
    dlg --backtitle "Meraki Mapping" --title "No switches" \
      --msgbox "No switches found in:\n\n  $SELECTED_JSON\n\nNothing to map." 10 70
    exit 1
  fi

  normalize_selected_sources "$enriched" >"$TMPDIR/selected_norm.json"

  local norm_count
  norm_count="$(jq 'length' "$TMPDIR/selected_norm.json" 2>/dev/null || echo 0)"
  if [[ "$norm_count" == "0" ]]; then
    dlg --backtitle "Meraki Mapping" --title "No normalized rows" \
      --msgbox "Selection exists, but normalization produced 0 rows.\n\nCheck JSON format in:\n  $SELECTED_JSON\n\nand:\n  $DISCOVERY_JSON" 12 78
    exit 1
  fi
}

show_selected_review() {
  local txt="$TMPDIR/selected_review.txt"
  {
    echo "Selected switches to map (source side)"
    echo "====================================="
    echo
    printf "%-15s %-26s %-12s %-16s %-12s %-14s %-12s\n" "IP" "Hostname" "PID" "Serial" "Member" "Role" "State"
    printf "%-15s %-26s %-12s %-16s %-12s %-14s %-12s\n" "---------------" "--------------------------" "------------" "----------------" "------------" "--------------" "------------"

    jq -r '
      .[] |
      [
        (.ip // "-"),
        (.hostname_disp // .hostname // "-"),
        (.pid // "-"),
        (.serial // "-"),
        (if .is_stack then ("#" + (.member_index|tostring)) else "-" end),
        (.member_role // "-"),
        (.member_state // "-")
      ] | @tsv
    ' "$TMPDIR/selected_norm.json" | while IFS=$'\t' read -r ip host pid serial mem role state; do
      printf "%-15s %-26s %-12s %-16s %-12s %-14s %-12s\n" \
        "$ip" "${host:0:26}" "${pid:0:12}" "${serial:0:16}" "$mem" "${role:0:14}" "${state:0:12}"
    done
    echo
    echo "NOTE: Stacks are expanded to per-member rows so each member can be mapped independently."
  } >"$txt"

  dlg --backtitle "Meraki Mapping" --title "Selected switches" --textbox "$txt" 26 140 || true
}

# ---------------- pick org / load networks ----------------
ORG_ID=""
ORG_NAME=""

declare -a ORG_NET_IDS=()
declare -a ORG_NET_NAMES=()
declare -a ORG_NET_LABELS=()

pick_org() {
  log_status "Fetching organizations..."
  "$DIALOG" --backtitle "Meraki Mapping" --infobox "Fetching organizations from Meraki Dashboard..." 5 70
  local orgs_json
  orgs_json="$(_meraki_get_all_pages "/organizations" "?perPage=1000")" || {
    dlg --backtitle "Meraki Mapping" --title "Meraki API error" \
      --msgbox "Failed to fetch organizations.\n\nSee:\n  $MERAKI_LOG" 10 70
    exit 1
  }

  local -a items=()
  while IFS=$'\t' read -r oid oname; do
    [[ -z "$oid" ]] && continue
    [[ -z "$oname" ]] && oname="(unnamed)"
    items+=( "$oid" "$oname" )
  done < <(jq -r '.[] | [(.id//""), (.name//"")] | @tsv' <<<"$orgs_json")

  if ((${#items[@]} == 0)); then
    dlg --backtitle "Meraki Mapping" --title "No orgs" --msgbox "No organizations visible to this API key." 7 60
    exit 1
  fi

  ORG_ID="$(dlg --backtitle "Meraki Mapping" --title "Select Organization" \
    --menu "Select the Meraki Organization for this migration." 20 80 14 "${items[@]}")" || exit 1

  ORG_NAME="$(jq -r --arg id "$ORG_ID" '.[] | select(.id==$id) | (.name//"")' <<<"$orgs_json" | head -n1)"
  ORG_NAME="$(trim "${ORG_NAME:-}")"
  [[ -z "$ORG_NAME" ]] && ORG_NAME="(unnamed)"

  log_status "Selected org: $ORG_NAME ($ORG_ID)"
}

load_org_networks() {
  log_status "Fetching networks for org $ORG_ID..."
  "$DIALOG" --backtitle "Meraki Mapping" --infobox "Fetching networks for:\n\n  $ORG_NAME\n\n(Filtering to networks with product type: switch)" 8 70

  local nets_json
  nets_json="$(_meraki_get_all_pages "/organizations/$ORG_ID/networks" "?perPage=1000")" || {
    dlg --backtitle "Meraki Mapping" --title "Meraki API error" \
      --msgbox "Failed to fetch networks for org.\n\nSee:\n  $MERAKI_LOG" 11 70
      exit 1
  }

  ORG_NET_IDS=()
  ORG_NET_NAMES=()
  ORG_NET_LABELS=()

  while IFS=$'\t' read -r nid nname types; do
    [[ -z "$nid" ]] && continue
    [[ -z "$nname" ]] && nname="(unnamed)"
    types="$(trim "$types")"
    ORG_NET_IDS+=( "$nid" )
    ORG_NET_NAMES+=( "$nname" )
    ORG_NET_LABELS+=( "$nname  [$types]" )
  done < <(
    jq -r '
      .[]
      | select(.productTypes? and (.productTypes | index("switch")))
      | [(.id//""), (.name//""), (.productTypes|join(","))] | @tsv
    ' <<<"$nets_json"
  )

  if ((${#ORG_NET_IDS[@]} == 0)); then
    dlg --backtitle "Meraki Mapping" --title "No switch networks" \
      --msgbox "No networks with product type 'switch' were found in:\n\n  $ORG_NAME\n\nCreate one in Dashboard and re-run." 12 78
    exit 1
  fi
}

show_org_network_review() {
  local txt="$TMPDIR/network_review.txt"
  {
    echo "Switch-capable target networks in selected org"
    echo "============================================="
    echo
    echo "Org: $ORG_NAME ($ORG_ID)"
    echo
    printf "%-18s %-40s\n" "Network ID" "Network Name"
    printf "%-18s %-40s\n" "------------------" "----------------------------------------"
    local i
    for i in "${!ORG_NET_IDS[@]}"; do
      printf "%-18s %-40s\n" "${ORG_NET_IDS[$i]}" "${ORG_NET_NAMES[$i]:0:40}"
    done
  } >"$txt"
  dlg --backtitle "Meraki Mapping" --title "Available networks" --textbox "$txt" 24 90 || true
}

network_name_by_id() {
  local nid="$1"
  local i
  for i in "${!ORG_NET_IDS[@]}"; do
    if [[ "${ORG_NET_IDS[$i]}" == "$nid" ]]; then
      printf '%s' "${ORG_NET_NAMES[$i]}"
      return 0
    fi
  done
  printf ''
}

# ---------------- target cache / stack info ----------------
CURRENT_NET_ID=""
CURRENT_NET_NAME=""
CURRENT_TARGETS_JSON=""
CURRENT_TARGET_STACKS_JSON=""

declare -A T_STACK_ID=()
declare -A T_STACK_NAME=()
declare -A T_STACK_SIZE=()
declare -A STACK_DESC=()

declare -A MAP_TARGET=()
declare -A MAP_TARGET_NETID=()
declare -A MAP_TARGET_NETNAME=()
declare -A USED_TARGET=()

net_cache_prefix() {
  local nid="$1"
  printf '%s/%s' "$CACHE_DIR" "$(sed 's/[^A-Za-z0-9_.-]/_/g' <<<"$nid")"
}

targets_json_path_for_net() {
  local nid="$1"
  printf '%s.targets.json' "$(net_cache_prefix "$nid")"
}

target_stacks_json_path_for_net() {
  local nid="$1"
  printf '%s.stacks.json' "$(net_cache_prefix "$nid")"
}

build_target_stack_maps_from_files() {
  local targets_json="$1"
  local stacks_json="$2"

  T_STACK_ID=()
  T_STACK_NAME=()
  T_STACK_SIZE=()
  STACK_DESC=()

  local tsv="$TMPDIR/target_stack_maps.tsv"
  : >"$tsv"

  jq -r --slurpfile stacks "$stacks_json" '
    (reduce ($stacks[0][]?) as $s ({}; .[$s.id] = $s)) as $byId
    | (reduce ($stacks[0][]?) as $s ({}; .[$s.id] = (($s.serials|length) // 0))) as $byIdSize
    | (reduce ($stacks[0][]?) as $s ({}; .[$s.id] = ($s.name // ""))) as $byIdName
    | .[]?
    | .cloud_id as $cid
    | (
        ($stacks[0][]? | select((.serials // []) | index($cid)) | .id) // ""
      ) as $sid
    | [
        $cid,
        $sid,
        (if $sid=="" then "" else ($byIdName[$sid] // "") end),
        (if $sid=="" then 1 else ($byIdSize[$sid] // 0) end)
      ] | @tsv
  ' "$targets_json" >"$tsv" 2>/dev/null || true

  while IFS=$'\t' read -r cid sid sname ssize; do
    [[ -z "$cid" ]] && continue
    T_STACK_ID["$cid"]="$sid"
    T_STACK_NAME["$cid"]="$sname"
    T_STACK_SIZE["$cid"]="${ssize:-1}"
  done <"$tsv"

  while IFS=$'\t' read -r sid sname ssize; do
    [[ -z "$sid" ]] && continue
    [[ -z "$sname" ]] && sname="(unnamed stack)"
    STACK_DESC["$sid"]="$sname (${ssize} members)"
  done < <(jq -r '.[]? | [(.id//""), (.name//""), ((.serials|length)//0)] | @tsv' "$stacks_json" 2>/dev/null || true)
}

target_group_id_for_cloud() {
  local cid="${1-}"
  local sid="${T_STACK_ID[$cid]:-}"
  if [[ -n "$sid" ]]; then
    printf '%s' "$sid"
  else
    printf 'solo:%s' "$cid"
  fi
}

target_group_desc_for_cloud() {
  local cid="${1-}"
  local sid="${T_STACK_ID[$cid]:-}"
  local ssize="${T_STACK_SIZE[$cid]:-1}"
  local sname="${T_STACK_NAME[$cid]:-}"

  if [[ -n "$sid" && "${ssize:-1}" -gt 1 ]]; then
    local d="${STACK_DESC[$sid]:-}"
    [[ -n "$d" ]] && printf '%s' "$d" || printf '%s (%s members)' "${sname:-stack}" "$ssize"
  else
    printf 'standalone device (%s)' "$cid"
  fi
}

ensure_org_inventory_cache() {
  local inv_file="$TMPDIR/org_inventory_switch.json"
  if [[ -s "$inv_file" ]]; then
    return 0
  fi

  log_status "Fetching org inventory for $ORG_ID..."
  "$DIALOG" --backtitle "Meraki Mapping" --infobox "Fetching org inventory details...\n\n(Used for Cloud configuration compliance checks)" 7 70

  local inv_json
  inv_json="$(_meraki_get_all_pages "/organizations/$ORG_ID/inventory/devices" "?perPage=1000&productTypes[]=switch")" || {
    dlg --backtitle "Meraki Mapping" --title "Meraki API error" \
      --msgbox "Failed to fetch organization inventory.\n\nSee:\n  $MERAKI_LOG" 11 70
    exit 1
  }

  printf '%s\n' "$inv_json" >"$inv_file"
  printf '%s\n' "$inv_json" >"$DEVLOG_DIR/org_inventory_switch.json" || true
  log_status "Inventory cache created: $(jq 'length' <<<"$inv_json" 2>/dev/null || echo 0) rows"
}

load_target_switches_for_network() {
  local nid="$1"
  local nname="$2"

  ensure_org_inventory_cache

  local targets_json_path stacks_json_path
  targets_json_path="$(targets_json_path_for_net "$nid")"
  stacks_json_path="$(target_stacks_json_path_for_net "$nid")"

  if [[ ! -s "$targets_json_path" || ! -s "$stacks_json_path" ]]; then
    log_status "Building target cache for network $nname ($nid)..."
    "$DIALOG" --backtitle "Meraki Mapping" --infobox "Fetching switch devices in network:\n\n  $nname\n\nPlease wait..." 8 70

    local devs_json
    devs_json="$(_meraki_get_all_pages "/networks/$nid/devices" "?perPage=1000")" || {
      dlg --backtitle "Meraki Mapping" --title "Meraki API error" \
        --msgbox "Failed to fetch devices for network.\n\nSee:\n  $MERAKI_LOG" 11 70
      exit 1
    }

    jq '
      map(
        select(
          (.productType? == "switch")
          or
          ((.productType? // "") == "" and ((.model? // "") | test("^(MS|C9|C8|C7)")))
        )
      )
      | map({
          cloud_id:(.serial // ""),
          name:(.name // ""),
          model:(.model // ""),
          mac:(.mac // ""),
          lanIp:(.lanIp // ""),
          address:(.address // "")
        })
    ' <<<"$devs_json" >"$TMPDIR/targets_base.json"

    local base_count
    base_count="$(jq 'length' "$TMPDIR/targets_base.json")"
    if [[ "$base_count" == "0" ]]; then
      dlg --backtitle "Meraki Mapping" --title "No switches found" \
        --msgbox "No switch devices were returned for:\n\n  $nname\n\nIf this is a new network, add/claim devices first, then re-run." 12 78
      exit 1
    fi

    log_status "Fetching switch stacks for network $nid..."
    "$DIALOG" --backtitle "Meraki Mapping" --infobox "Fetching switch stacks for network...\n\n(Used for stack guardrails)" 7 70
    local stacks_json
    stacks_json="$(_meraki_get_all_pages "/networks/$nid/switch/stacks" "?perPage=1000")" || stacks_json="[]"
    printf '%s\n' "$stacks_json" >"$stacks_json_path" || printf '[]' >"$stacks_json_path"

    local inv_file="$TMPDIR/org_inventory_switch.json"

    jq -r --arg net "$nid" '
      [
        .[]
        | select((.networkId // "") == $net)
        | {
            cloud_id: (.serial // ""),
            cloud_cfg: (
              (.details // [])
              | map(select((.name // "" | ascii_downcase) == "cloud configuration"))
              | .[0].value // ""
            )
          }
        | select(.cloud_id != "")
      ]
    ' "$inv_file" >"$TMPDIR/cloudcfg_by_cloudid.json"

    jq '
      reduce .[] as $d ({}; .[$d.cloud_id] = ($d.cloud_cfg // ""))
    ' "$TMPDIR/cloudcfg_by_cloudid.json" >"$TMPDIR/cloudcfg_map.json"

    jq --slurpfile m "$TMPDIR/cloudcfg_map.json" --arg pol "$CFG_UNKNOWN_POLICY" '
      def norm(s): (s // "" | ascii_downcase | gsub("^[[:space:]]+|[[:space:]]+$";""));
      def cloudcfg_for($id): (($m[0][$id] // "") as $v | $v);

      map(
        . as $t
        | ($t.cloud_id // "") as $id
        | (cloudcfg_for($id)) as $cfg
        | ($cfg | if .=="" then "Unknown" else . end) as $cfgDisp
        | (norm($cfgDisp)) as $cfgNorm
        | (
            if $cfgNorm == "monitoring" then "NONCOMPLIANT"
            elif $cfgNorm == "unknown" then (if ($pol=="allow") then "OK" else "NONCOMPLIANT" end)
            else "OK"
            end
          ) as $comp
        | $t + { cloud_cfg: $cfgDisp, compliance: $comp }
      )
    ' "$TMPDIR/targets_base.json" >"$targets_json_path"

    printf '%s\n' "$devs_json"   >"$DEVLOG_DIR/network_devices_${nid}.json"       || true
    printf '%s\n' "$stacks_json" >"$DEVLOG_DIR/network_switch_stacks_${nid}.json" || true

    local total nonc okc
    total="$(jq 'length' "$targets_json_path")"
    nonc="$(jq '[.[] | select(.compliance=="NONCOMPLIANT")] | length' "$targets_json_path")"
    okc="$(jq '[.[] | select(.compliance=="OK")] | length' "$targets_json_path")"
    log_status "Cached target switches for network $nid: total=$total ok=$okc noncompliant=$nonc"
  fi

  CURRENT_NET_ID="$nid"
  CURRENT_NET_NAME="$nname"
  CURRENT_TARGETS_JSON="$targets_json_path"
  CURRENT_TARGET_STACKS_JSON="$stacks_json_path"

  build_target_stack_maps_from_files "$CURRENT_TARGETS_JSON" "$CURRENT_TARGET_STACKS_JSON"
}

show_target_review_current_network() {
  local txt="$TMPDIR/target_review_${CURRENT_NET_ID}.txt"

  local total nonc
  total="$(jq 'length' "$CURRENT_TARGETS_JSON")"
  nonc="$(jq '[.[] | select(.compliance=="NONCOMPLIANT")] | length' "$CURRENT_TARGETS_JSON")"

  {
    echo "Target switches available (Meraki side)"
    echo "===================================="
    echo
    echo "Org:     $ORG_NAME ($ORG_ID)"
    echo "Network: $CURRENT_NET_NAME ($CURRENT_NET_ID)"
    echo
    echo "Switches visible in network: $total"
    echo "NON-COMPLIANT targets:       $nonc"
    echo
    echo "NOTE:"
    echo " - Devices with Cloud configuration=monitoring are blocked from mapping."
    echo " - Cloud configuration is extracted from org inventory details[] (\"Cloud configuration\")."
    echo " - Unknown cloud configuration is treated as: $CFG_UNKNOWN_POLICY"
    echo " - Guardrails target-stack detection uses /networks/{netId}/switch/stacks"
    echo
    printf "%-18s %-26s %-10s %-15s %-18s %-12s %-20s\n" \
      "CloudID" "Name" "Model" "LAN IP" "CloudCfg" "Compliance" "TargetStack"
    printf "%-18s %-26s %-10s %-15s %-18s %-12s %-20s\n" \
      "------------------" "--------------------------" "----------" "---------------" "------------------" "------------" "--------------------"

    jq -r '
      .[]
      | [
          (.cloud_id//""),
          (.name//"(unnamed)"),
          (.model//"-"),
          (.lanIp//"-"),
          (.cloud_cfg//"Unknown"),
          (.compliance//"OK")
        ] | @tsv
    ' "$CURRENT_TARGETS_JSON" \
    | while IFS=$'\t' read -r id name model ip cfg comp; do
        [[ -z "$id" ]] && continue
        local sid="${T_STACK_ID[$id]:-}"
        local ssize="${T_STACK_SIZE[$id]:-1}"
        local sdesc
        if [[ -n "$sid" && "${ssize:-1}" -gt 1 ]]; then
          sdesc="${STACK_DESC[$sid]:-(stack)}"
        else
          sdesc="(standalone)"
        fi
        printf "%-18s %-26s %-10s %-15s %-18s %-12s %-20s\n" \
          "$id" "${name:0:26}" "${model:0:10}" "$ip" "${cfg:0:18}" "$comp" "${sdesc:0:20}"
      done
  } >"$txt"

  dlg --backtitle "Meraki Mapping" --title "Target switches – $CURRENT_NET_NAME" --textbox "$txt" 28 160 || true
}

# ---------------- mapping UI / guardrails ----------------
declare -A SOURCE_DONE=()

stack_mapping_summary() {
  local stack_ip="$1"
  local out=""
  local -A seen=()
  local k
  for k in "${!MAP_TARGET[@]}"; do
    [[ "$k" == "$stack_ip|"* ]] || continue
    local tcid="${MAP_TARGET[$k]:-}"
    [[ -z "$tcid" ]] && continue
    local tnet="${MAP_TARGET_NETNAME[$k]:-}"
    local tgkey="${MAP_TARGET_NETID[$k]:-}|$(target_group_id_for_cloud "$tcid")"
    if [[ -z "${seen[$tgkey]:-}" ]]; then
      seen["$tgkey"]=1
      out+="- ${k} -> ${tcid}  ($(target_group_desc_for_cloud "$tcid"))"
      [[ -n "$tnet" ]] && out+="  [${tnet}]"
      out+=$'\n'
    else
      out+="- ${k} -> ${tcid}"
      [[ -n "$tnet" ]] && out+="  [${tnet}]"
      out+=$'\n'
    fi
  done
  printf '%s' "$out"
}

guardrail_check_proposed_mapping() {
  local src_is_stack="$1"
  local src_ip="$2"
  local src_stack_ip="$3"
  local src_disp="$4"
  local target_cid="$5"
  local target_netid="$6"
  local target_netname="$7"

  [[ "${GUARDRAILS_MODE:-off}" == "off" ]] && return 0

  local t_sid="${T_STACK_ID[$target_cid]:-}"
  local t_ssize="${T_STACK_SIZE[$target_cid]:-1}"
  local t_sdesc; t_sdesc="$(target_group_desc_for_cloud "$target_cid")"

  if [[ "$src_is_stack" != "true" ]]; then
    if [[ -n "$t_sid" && "${t_ssize:-1}" -gt 1 ]]; then
      if ! guardrails_confirm "Guardrail: Standalone -> Stack" \
        "You are mapping a NON-STACKED source switch to a TARGET STACK.\n\nSOURCE:\n  $src_disp\n\nTARGET:\n  $target_cid\n  $t_sdesc\n  Network: $target_netname\n\nThis can cause port-channel/uplink design issues if the source had LAGs that must stay together.\n\nContinue anyway?"; then
        return 1
      fi
    fi
    return 0
  fi

  local -A groups=()
  local k
  for k in "${!MAP_TARGET[@]}"; do
    [[ "$k" == "$src_stack_ip|"* ]] || continue
    local tcid="${MAP_TARGET[$k]:-}"
    [[ -z "$tcid" ]] && continue
    groups["${MAP_TARGET_NETID[$k]:-}|$(target_group_id_for_cloud "$tcid")"]=1
  done
  groups["${target_netid}|$(target_group_id_for_cloud "$target_cid")"]=1

  local gcount=0
  for _ in "${!groups[@]}"; do gcount=$((gcount+1)); done

  if (( gcount > 1 )); then
    local summary
    summary="$(stack_mapping_summary "$src_stack_ip")"
    if ! guardrails_confirm "Guardrail: Stack Split" \
      "You are SPLITTING a SOURCE STACK across multiple target stacks/devices.\n\nSOURCE STACK:\n  $src_stack_ip\n  $src_disp\n\nCURRENT/PROPOSED MAPPINGS:\n${summary}\n+ (this choice) -> $target_cid  ($t_sdesc)  [${target_netname}]\n\nContinue anyway?"; then
      return 1
    fi
  fi

  return 0
}

choose_network_for_source() {
  local source_label="$1"

  local -a items=()
  local i
  for i in "${!ORG_NET_IDS[@]}"; do
    items+=( "${ORG_NET_IDS[$i]}" "${ORG_NET_LABELS[$i]}" )
  done
  items+=( "__DONE__" "Finish mapping now (leave remaining unmapped)" )

  local choice
  choice="$(dlg --backtitle "Meraki Mapping" --title "Choose target network" \
    --menu "Select the target Meraki network for this source.\n\nSOURCE:\n$source_label\n\nOrg:\n  $ORG_NAME" \
    24 100 16 "${items[@]}")" || exit 1

  printf '%s' "$choice"
}

show_remaining_sources() {
  local txt="$TMPDIR/remaining_sources.txt"
  {
    echo "Remaining unmapped source rows"
    echo "============================="
    echo
    printf "%-8s %-15s %-26s %-12s %-10s\n" "Done?" "IP" "Hostname" "PID" "Member"
    printf "%-8s %-15s %-26s %-12s %-10s\n" "------" "---------------" "--------------------------" "------------" "----------"
    jq -r '
      .[] |
      [
        .key,
        (.ip // "-"),
        (.hostname_disp // .hostname // "-"),
        (.pid // "-"),
        (if .is_stack then ("#" + (.member_index|tostring)) else "-" end)
      ] | @tsv
    ' "$TMPDIR/selected_norm.json" | while IFS=$'\t' read -r key ip host pid mem; do
      local done="no"
      [[ -n "${SOURCE_DONE[$key]:-}" ]] && done="yes"
      printf "%-8s %-15s %-26s %-12s %-10s\n" "$done" "$ip" "${host:0:26}" "${pid:0:12}" "$mem"
    done
  } >"$txt"
  dlg --backtitle "Meraki Mapping" --title "Mapping progress" --textbox "$txt" 26 90 || true
}

map_each_source() {
  local n_src
  n_src="$(jq 'length' "$TMPDIR/selected_norm.json")"

  local i
  for ((i=0; i<n_src; i++)); do
    local key ip stack_ip host host_disp pid serial cloud is_stack member_index role state
    key="$(jq -r ".[$i].key" "$TMPDIR/selected_norm.json")"
    ip="$(jq -r ".[$i].ip" "$TMPDIR/selected_norm.json")"
    stack_ip="$(jq -r ".[$i].stack_ip" "$TMPDIR/selected_norm.json")"
    host="$(jq -r ".[$i].hostname // \"\"" "$TMPDIR/selected_norm.json")"
    host_disp="$(jq -r ".[$i].hostname_disp // .[$i].hostname // \"\"" "$TMPDIR/selected_norm.json")"
    pid="$(jq -r ".[$i].pid // \"\"" "$TMPDIR/selected_norm.json")"
    serial="$(jq -r ".[$i].serial // \"\"" "$TMPDIR/selected_norm.json")"
    cloud="$(jq -r ".[$i].cloud_id // \"\"" "$TMPDIR/selected_norm.json")"
    is_stack="$(jq -r ".[$i].is_stack" "$TMPDIR/selected_norm.json")"
    member_index="$(jq -r ".[$i].member_index" "$TMPDIR/selected_norm.json")"
    role="$(jq -r ".[$i].member_role // \"\"" "$TMPDIR/selected_norm.json")"
    state="$(jq -r ".[$i].member_state // \"\"" "$TMPDIR/selected_norm.json")"

    host="$(trim "$host")"
    host_disp="$(trim "$host_disp")"
    pid="$(trim "$pid")"
    if [[ -z "$pid" ]]; then
      pid="$(best_source_pid_for_key "$key")"
      pid="$(trim "$pid")"
    fi
    serial="$(trim "$serial")"
    cloud="$(trim "$cloud")"
    role="$(trim "$role")"
    state="$(trim "$state")"

    local src_label
    local src_disp_line
    if [[ "$is_stack" == "true" ]]; then
      src_label="Stack IP: $stack_ip\nMember: #$member_index  (${role:-unknown}/${state:-unknown})\nHost: $host_disp\nPID: ${pid:-<unknown>}\nMember Serial: ${serial:-<unknown>}\nCloud ID: ${cloud:-<unknown>}"
      src_disp_line="Stack $stack_ip member #$member_index ($host_disp)"
    else
      src_label="IP: $ip\nHost: ${host_disp:-<unknown>}\nPID: ${pid:-<unknown>}\nSerial: ${serial:-<unknown>}\nCloud ID: ${cloud:-<unknown>}"
      src_disp_line="Switch $ip ($host_disp)"
    fi

    while :; do
      local net_choice
      net_choice="$(choose_network_for_source "$src_label")"

      if [[ "$net_choice" == "__DONE__" ]]; then
        if dlg --backtitle "Meraki Mapping" --title "Finish mapping" \
             --yesno "Stop mapping now?\n\nAny remaining source rows will stay unmapped for this run." 10 70; then
          return 0
        else
          continue
        fi
      fi

      local chosen_net_id="$net_choice"
      local chosen_net_name
      chosen_net_name="$(network_name_by_id "$chosen_net_id")"
      chosen_net_name="$(trim "$chosen_net_name")"
      [[ -z "$chosen_net_name" ]] && chosen_net_name="$chosen_net_id"

      load_target_switches_for_network "$chosen_net_id" "$chosen_net_name"


      local -a items=()
      items+=( "__CHG_NET__" "Choose a different target network" )
      items+=( "__SKIP__"    "Skip mapping for this source" )
      items+=( "__CLEAR__"   "Clear existing mapping (if set)" )

      while IFS=$'\t' read -r cid name model lan; do
        [[ -z "$cid" ]] && continue
        [[ -z "$name" ]] && name="(unnamed)"
        [[ -z "$model" ]] && model="-"
        [[ -z "$lan" ]] && lan="-"
        [[ -n "${USED_TARGET[$cid]:-}" ]] && continue
        local hint=""
        local sid="${T_STACK_ID[$cid]:-}"
        local ssize="${T_STACK_SIZE[$cid]:-1}"
        if [[ -n "$sid" && "${ssize:-1}" -gt 1 ]]; then
          hint=" stack:${STACK_DESC[$sid]:-stack}"
        fi
        items+=( "$cid" "$name  [$model]  ip:$lan$hint" )
      done < <(jq -r '
        .[]
        | select((.compliance//"OK") == "OK")
        | [(.cloud_id//""), (.name//""), (.model//""), (.lanIp//"")] | @tsv
      ' "$CURRENT_TARGETS_JSON")

      local choice
      choice="$(dlg --backtitle "Meraki Mapping" --title "Map source ($((i+1))/$n_src)" \
        --menu "Select target Meraki switch for this source.\n\nSOURCE:\n$src_label\n\nTarget network:\n  $chosen_net_name\n\nCurrent mapping: ${MAP_TARGET[$key]:-<none>}\n\n(Non-compliant targets are hidden.)" \
        30 132 22 "${items[@]}")" || exit 1

      case "$choice" in
        "__CHG_NET__")
          continue
          ;;
        "__SKIP__")
          SOURCE_DONE["$key"]=1
          log_status "SKIP mapping for source.key=$key"
          break
          ;;
        "__CLEAR__")
          if [[ -n "${MAP_TARGET[$key]:-}" ]]; then
            local old="${MAP_TARGET[$key]}"
            unset MAP_TARGET["$key"]
            unset MAP_TARGET_NETID["$key"]
            unset MAP_TARGET_NETNAME["$key"]
            unset USED_TARGET["$old"]
            log_status "CLEARED mapping: source.key=$key -> $old"
          fi
          SOURCE_DONE["$key"]=1
          break
          ;;
        *)
          if ! guardrail_check_proposed_mapping "$is_stack" "$ip" "$stack_ip" "$src_disp_line" "$choice" "$chosen_net_id" "$chosen_net_name"; then
            continue
          fi

          local tgt_name tgt_model
          tgt_name="$(jq -r --arg id "$choice" '.[] | select(.cloud_id==$id) | (.name // "")' "$CURRENT_TARGETS_JSON" | head -n1)"
          tgt_model="$(jq -r --arg id "$choice" '.[] | select(.cloud_id==$id) | (.model // "")' "$CURRENT_TARGETS_JSON" | head -n1)"
          log_status "Selected mapping candidate: source.key=$key source.is_stack='$is_stack' source.member_index='$member_index' source.pid='$pid' target.cloud_id='$choice' target.name='$tgt_name' target.model='$tgt_model' target.network='$chosen_net_name'"

          if ! source_target_port_mismatch_confirm "$src_disp_line" "$pid" "$choice" "$tgt_name" "$tgt_model" "$chosen_net_name"; then
            continue
          fi

          if [[ -n "${MAP_TARGET[$key]:-}" ]]; then
            local old="${MAP_TARGET[$key]}"
            unset USED_TARGET["$old"]
          fi

          MAP_TARGET["$key"]="$choice"
          MAP_TARGET_NETID["$key"]="$chosen_net_id"
          MAP_TARGET_NETNAME["$key"]="$chosen_net_name"
          USED_TARGET["$choice"]=1
          SOURCE_DONE["$key"]=1
          log_status "MAPPED: source.key=$key -> $choice [network=$chosen_net_name/$chosen_net_id]"
          break
          ;;
      esac
    done
  done
}

# ---------------- write outputs ----------------
write_outputs() {
  {
    echo '['
    local first=1
    local n_src; n_src="$(jq 'length' "$TMPDIR/selected_norm.json")"
    local i
    for ((i=0; i<n_src; i++)); do
      local key tcloud tnetid tnetname
      key="$(jq -r ".[$i].key" "$TMPDIR/selected_norm.json")"
      tcloud="${MAP_TARGET[$key]:-}"
      [[ -z "$tcloud" ]] && continue

      tnetid="${MAP_TARGET_NETID[$key]:-}"
      tnetname="${MAP_TARGET_NETNAME[$key]:-}"
      [[ -z "$tnetid" ]] && continue

      local targets_json_for_net stacks_json_for_net
      targets_json_for_net="$(targets_json_path_for_net "$tnetid")"
      stacks_json_for_net="$(target_stacks_json_path_for_net "$tnetid")"

      local ip stack_ip host host_disp pid sersrc cloud is_stack member_index role state
      ip="$(jq -r ".[$i].ip" "$TMPDIR/selected_norm.json")"
      stack_ip="$(jq -r ".[$i].stack_ip" "$TMPDIR/selected_norm.json")"
      host="$(jq -r ".[$i].hostname // \"\"" "$TMPDIR/selected_norm.json")"
      host_disp="$(jq -r ".[$i].hostname_disp // .[$i].hostname // \"\"" "$TMPDIR/selected_norm.json")"
      pid="$(jq -r ".[$i].pid // \"\"" "$TMPDIR/selected_norm.json")"
      pid="$(trim "$pid")"
      if [[ -z "$pid" ]]; then
        pid="$(best_source_pid_for_key "$key")"
      fi
      sersrc="$(jq -r ".[$i].serial // \"\"" "$TMPDIR/selected_norm.json")"
      cloud="$(jq -r ".[$i].cloud_id // \"\"" "$TMPDIR/selected_norm.json")"
      is_stack="$(jq -r ".[$i].is_stack" "$TMPDIR/selected_norm.json")"
      member_index="$(jq -r ".[$i].member_index" "$TMPDIR/selected_norm.json")"
      role="$(jq -r ".[$i].member_role // \"\"" "$TMPDIR/selected_norm.json")"
      state="$(jq -r ".[$i].member_state // \"\"" "$TMPDIR/selected_norm.json")"

      local tname tmodel tlan tmac tcfg tcomp
      tname="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.name // "")' "$targets_json_for_net" | head -n1)"
      tmodel="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.model // "")' "$targets_json_for_net" | head -n1)"
      tlan="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.lanIp // "")' "$targets_json_for_net" | head -n1)"
      tmac="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.mac // "")' "$targets_json_for_net" | head -n1)"
      tcfg="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.cloud_cfg // "Unknown")' "$targets_json_for_net" | head -n1)"
      tcomp="$(jq -r --arg id "$tcloud" '.[] | select(.cloud_id==$id) | (.compliance // "OK")' "$targets_json_for_net" | head -n1)"

      local tsid tsname tssize
      tsid="$(jq -r --arg cid "$tcloud" '
        ($cid) as $target
        | [ .[]? | select((.serials // []) | index($target)) ][0].id // ""
      ' "$stacks_json_for_net" 2>/dev/null || true)"
      tsname="$(jq -r --arg sid "$tsid" '
        .[]? | select(.id==$sid) | (.name // "")
      ' "$stacks_json_for_net" 2>/dev/null | head -n1)"
      tssize="$(jq -r --arg sid "$tsid" '
        [ .[]? | select(.id==$sid) ][0].serials | length // 1
      ' "$stacks_json_for_net" 2>/dev/null || echo 1)"

      if [[ -z "$tsid" || "${tssize:-1}" -le 1 ]]; then
        tsid=""
        tsname=""
        tssize=1
      fi

      if (( first )); then
        first=0
      else
        echo ','
      fi

      jq -n \
        --arg orgId "$ORG_ID" \
        --arg orgName "$ORG_NAME" \
        --arg netId "$tnetid" \
        --arg netName "$tnetname" \
        --arg key "$key" \
        --arg ip "$ip" \
        --arg stackIp "$stack_ip" \
        --arg hostname "$host" \
        --arg hostnameDisp "$host_disp" \
        --arg pid "$pid" \
        --arg srcSerial "$sersrc" \
        --arg srcCloudId "$cloud" \
        --argjson isStack "$is_stack" \
        --argjson memberIndex "$member_index" \
        --arg memberRole "$role" \
        --arg memberState "$state" \
        --arg targetCloudId "$tcloud" \
        --arg targetName "$tname" \
        --arg targetModel "$tmodel" \
        --arg targetLanIp "$tlan" \
        --arg targetMac "$tmac" \
        --arg targetCloudCfg "$tcfg" \
        --arg targetCompliance "$tcomp" \
        --arg targetStackId "$tsid" \
        --arg targetStackName "$tsname" \
        --argjson targetStackSize "$tssize" '
        {
          orgId: $orgId,
          orgName: $orgName,
          networkId: $netId,
          networkName: $netName,
          source: {
            key: $key,
            ip: $ip,
            stack_ip: $stackIp,
            hostname: $hostname,
            hostname_disp: $hostnameDisp,
            pid: $pid,
            serial: $srcSerial,
            cloud_id: $srcCloudId,
            is_stack: $isStack,
            member_index: $memberIndex,
            member_role: $memberRole,
            member_state: $memberState
          },
          target: {
            cloud_id: $targetCloudId,
            name: $targetName,
            model: $targetModel,
            lanIp: $targetLanIp,
            mac: $targetMac,
            cloud_configuration: $targetCloudCfg,
            compliance: $targetCompliance,
            switch_stack: {
              id: $targetStackId,
              name: $targetStackName,
              size: $targetStackSize
            }
          }
        }'
    done
    echo
    echo ']'
  } >"$MAP_JSON"

  mkdir -p "$RUN_ROOT"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"
  ln -sfn "$MAP_JSON" "$RUN_ROOT/latest_mapping.json"
  ln -sfn "$STATUS_LOG" "$RUN_ROOT/latest_status.log"
  ln -sfn "$MERAKI_LOG" "$RUN_ROOT/latest_meraki_api.log"

  if [[ ! -s "$GLOBAL_MAP_JSON" ]]; then
    cp "$MAP_JSON" "$GLOBAL_MAP_JSON"
  else
    jq -s '
      (.[0] // []) as $old
      | (.[1] // []) as $new
      | [
          $old[]
          | select(.source.key as $k | all($new[]?; .source.key != $k))
        ] + $new
    ' "$GLOBAL_MAP_JSON" "$MAP_JSON" >"$GLOBAL_MAP_JSON.tmp" && mv "$GLOBAL_MAP_JSON.tmp" "$GLOBAL_MAP_JSON"
  fi

  {
    echo "Meraki mapping saved"
    echo "===================="
    echo
    echo "Run file:"
    echo "  $MAP_JSON"
    echo
    echo "Mappings:"
    echo
    jq -r '
      .[]
      | [
          (.source.key // "-"),
          (.source.hostname_disp // .source.hostname // "-"),
          (.networkName // "-"),
          (.target.name // "(unnamed)"),
          (.target.model // "-"),
          (.target.cloud_id // "-")
        ] | @tsv
    ' "$MAP_JSON" | while IFS=$'\t' read -r skey shost nname tname tmodel tcid; do
      printf "  %-22s -> %-24s | %-24s | %-10s | %s\n" "$skey" "$nname" "$tname" "$tmodel" "$tcid"
    done
  } >"$MAP_SUMMARY"
}

main() {
  need curl || exit 1
  need jq || exit 1

  load_env
  mkdir -p "$RUN_ROOT"

  log_status "Using selection: $SELECTED_JSON"
  log_status "Using env:       $ENV_FILE"

  load_selected

  dlg --backtitle "Meraki Mapping" --title "Meraki switch mapper" \
    --msgbox "This wizard will map your selected/discovered switches to target Meraki switches.\n\nOrg is selected once.\nNetworks may vary per source row.\n\nNOTE: stacks are expanded to per-member rows." 14 82

  pick_guardrails_mode

  pick_org
  load_org_networks

  if dlg --backtitle "Meraki Mapping" --title "Show remaining list?" \
       --yesno "Would you like to review the remaining unmapped source rows before you begin?" 9 72; then
    show_remaining_sources
  fi

  map_each_source

  write_outputs
  dlg --backtitle "Meraki Mapping" --title "Mapping saved" --textbox "$MAP_SUMMARY" 18 120 || true
}

main "$@"
