#!/usr/bin/env bash
# ============================================================
# CMDS VLAN PROFILE PIPELINE (v37 - PRESTACK + VLAN ADD FIX)
# ============================================================

set -Euo pipefail

BASE_DIR="/root/.cloud_admin"
PUSH_RUN_ROOT="$BASE_DIR/runs/vlan_push"
MEMORY_DIR="$BASE_DIR/meraki_memory"

DISCOVERY_FILE="$BASE_DIR/discovery_results.json"
SELECTED_ENV="$BASE_DIR/selected_upgrade.env"
MAP_FILE="$BASE_DIR/meraki_switch_network_map.json"

CONFIG_DIR="/var/lib/tftpboot/mig"
MERAKI_ENV_FILE="$BASE_DIR/meraki_discovery.env"

RUN_ID="vlanpush-$(date +%Y%m%d%H%M%S)"
RUN_DIR="$PUSH_RUN_ROOT/$RUN_ID"
LATEST_LINK="$PUSH_RUN_ROOT/latest"

mkdir -p "$RUN_DIR/devlogs" "$RUN_DIR/results" "$RUN_DIR/vlans"
ln -sfn "$RUN_DIR" "$LATEST_LINK"

STATUS_LOG="$RUN_DIR/devlogs/status.log"
SUMMARY_TXT="$RUN_DIR/results/summary.txt"
SUMMARY_FILE="$RUN_DIR/vlans/network_vlan_summary.json"

log() {
  printf '[%s] %s\n' "$(date +'%F %T %Z')" "$*" | tee -a "$STATUS_LOG"
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1" >&2
    exit 1
  }
}

# ------------------------------------------------------------
# LOAD ENV
# ------------------------------------------------------------
load_env() {
  [[ -f "$MERAKI_ENV_FILE" ]] || { log "Missing Meraki env"; exit 1; }
  [[ -f "$SELECTED_ENV" ]] || { log "Missing selected_upgrade.env"; exit 1; }
  [[ -f "$DISCOVERY_FILE" ]] || { log "Missing discovery_results.json"; exit 1; }
  [[ -f "$MAP_FILE" ]] || { log "Missing map file"; exit 1; }

  set -a
  source "$MERAKI_ENV_FILE"
  source "$SELECTED_ENV"
  set +a

  [[ -n "${MERAKI_API_KEY:-}" ]] || { log "API key missing"; exit 1; }

  log "API Loaded: ${MERAKI_API_KEY:0:8}********"
}

# ------------------------------------------------------------
# API
# ------------------------------------------------------------
meraki_api() {
  local method="$1"
  local endpoint="$2"
  local data="${3:-}"
  local response body code

  if [[ -n "$data" ]]; then
    response=$(curl -sS -w "\n%{http_code}" \
      -X "$method" \
      -H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "https://api.meraki.com/api/v1$endpoint")
  else
    response=$(curl -sS -w "\n%{http_code}" \
      -X "$method" \
      -H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY" \
      "https://api.meraki.com/api/v1$endpoint")
  fi

  body=$(sed '$d' <<<"$response")
  code=$(tail -n1 <<<"$response")

  log "API $method $endpoint -> HTTP $code" >&2
  echo "$body"
}

# ------------------------------------------------------------
# LOOKUPS
# ------------------------------------------------------------
get_network_name() {
  local net="$1"
  jq -r --arg n "$net" '.[] | select(.networkId==$n) | .networkName' "$MAP_FILE" | head -n1
}

get_switches() {
  local net="$1"
  jq -r --arg n "$net" '
    select(.network_id == $n and .status == "CLAIMED") | .cloud_id
  ' "$MEMORY_DIR"/*.json 2>/dev/null | sort -u
}

get_label() {
  local serial="$1"
  jq -r --arg s "$serial" '
    select(.cloud_id == $s) |
    (
      if (.stack.stack_count // 1) > 1 then
        ((.stack.stack_base_name // (.device_name // .hostname // "unknown"))
          + " (member "
          + ((.stack.member_index // 0) | tostring)
          + ")")
      else
        (.device_name // .hostname // "unknown")
      end
    )
  ' "$MEMORY_DIR"/*.json 2>/dev/null | head -n1
}

get_stack_name() {
  local stack_id="$1"
  local net="$2"

  meraki_api GET "/networks/$net/switch/stacks" \
    | jq -r --arg sid "$stack_id" '.[] | select(.id == $sid) | (.name // "stack")' \
    | head -n1
}

get_stack_members() {
  local net="$1"
  local sid="$2"

  meraki_api GET "/networks/$net/switch/stacks" \
    | jq -r --arg sid "$sid" '.[] | select(.id == $sid) | .serials[]?'
}

# ------------------------------------------------------------
# VLAN HELPERS
# ------------------------------------------------------------
extract_vlans() {
  awk '
    /^[[:space:]]*switchport access vlan[[:space:]]+[0-9]+/ {
      print $NF + 0
      next
    }

    /^[[:space:]]*switchport trunk native vlan[[:space:]]+[0-9]+/ {
      print $NF + 0
      next
    }

    /^[[:space:]]*switchport trunk allowed vlan/ {
      line = $0
      sub(/^[[:space:]]*switchport[[:space:]]+trunk[[:space:]]+allowed[[:space:]]+vlan[[:space:]]+/, "", line)
      sub(/^[[:space:]]*add[[:space:]]+/, "", line)

      n = split(line, parts, ",")
      for (i = 1; i <= n; i++) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", parts[i])

        if (parts[i] ~ /^[0-9]+-[0-9]+$/) {
          split(parts[i], a, "-")
          for (v = a[1]; v <= a[2]; v++) print v
        }
        else if (parts[i] ~ /^[0-9]+$/) {
          print parts[i]
        }
      }
      next
    }
  ' "$1" | sort -n | uniq
}

active_vlans_to_json() {
  local s="${1:-}"

  if [[ -z "$s" || "$s" == "null" ]]; then
    echo '[]'
    return 0
  fi

  printf '%s\n' "$s" \
    | tr ',' '\n' \
    | awk '
        /^[0-9]+-[0-9]+$/ {
          split($0, a, "-");
          for (i = a[1]; i <= a[2]; i++) print i;
          next
        }
        /^[0-9]+$/ { print $0 }
      ' \
    | sort -n \
    | uniq \
    | jq -R . \
    | jq -s 'map(select(length > 0) | tonumber)'
}

normalize_vlans_json() {
  local v="$1"
  jq -n --argjson a "$v" '($a + [1]) | unique | sort'
}

# ------------------------------------------------------------
# BUILD VLAN SUMMARY
# ------------------------------------------------------------
build_vlan_summary() {
  local tmpfile ip net cfg vlan_list vlans
  local -a SELECTED

  log "Building VLAN summary..."
  tmpfile=$(mktemp)

  read -r -a SELECTED <<< "${UPGRADE_SELECTED_IPS:-}"

  for ip in "${SELECTED[@]}"; do
    [[ -z "$ip" ]] && continue

    net=$(jq -r --arg ip "$ip" '.[] | select(.ip == $ip) | .networkId' "$MAP_FILE" | head -n1)
    [[ -z "$net" || "$net" == "null" ]] && { log "WARN: No network mapping for $ip"; continue; }

    cfg=$(jq -r --arg ip "$ip" '
      .[] | select(.ip == $ip and .backup_status == "OK") | .backup_filename
    ' "$DISCOVERY_FILE" | head -n1)

    if [[ -z "$cfg" || "$cfg" == "null" ]]; then
      log "WARN: No backup mapping for $ip"
      continue
    fi

    cfg="$CONFIG_DIR/$cfg"
    if [[ ! -f "$cfg" ]]; then
      log "WARN: Config file missing: $cfg"
      continue
    fi

    vlan_list=$(extract_vlans "$cfg" | grep -E '^[0-9]+$' | sort -n | uniq || true)
    if [[ -z "$vlan_list" ]]; then
      log "WARN: No VLANs found in $cfg"
      continue
    fi

    vlans=$(printf '%s\n' $vlan_list | jq -R . | jq -s 'map(tonumber)')
    vlans=$(normalize_vlans_json "$vlans")

    jq -n --arg net "$net" --argjson v "$vlans" \
      '{networkId:$net, vlans:$v}' >> "$tmpfile"
  done

  if [[ ! -s "$tmpfile" ]]; then
    log "ERROR: No VLAN data collected"
    echo "[]" > "$SUMMARY_FILE"
    rm -f "$tmpfile"
    return 1
  fi

  jq -s '
    group_by(.networkId) |
    map({
      networkId: .[0].networkId,
      vlans: (map(.vlans[]) | unique | sort)
    })
  ' "$tmpfile" > "$SUMMARY_FILE"

  rm -f "$tmpfile"
  log "VLAN summary built -> $SUMMARY_FILE"
}

# ------------------------------------------------------------
# STACK PREP
# ------------------------------------------------------------
get_expected_stack_groups() {
  local net="$1"

  jq -s -c --arg n "$net" '
    map(
      select(
        .network_id == $n
        and .status == "CLAIMED"
        and ((.stack.stack_count // 1) > 1)
        and ((.stack.stack_base_name // "") != "")
      )
    )
    | sort_by(.stack.stack_base_name, .stack.member_index)
    | group_by(.stack.stack_base_name)
    | map({
        name: .[0].stack.stack_base_name,
        expected: (.[0].stack.stack_count // (length)),
        serials: ([.[].cloud_id] | unique | sort)
      })
    | .[]
  ' "$MEMORY_DIR"/*.json 2>/dev/null
}

find_existing_stack_id_for_serials() {
  local net="$1"
  local want_json="$2"

  meraki_api GET "/networks/$net/switch/stacks" \
    | jq -r --argjson want "$want_json" '
        .[]
        | (.serials // []) as $have
        | select(
            (($want - $have | length) == 0)
            and
            (($have - $want | length) == 0)
          )
        | .id
      ' | head -n1
}
wait_for_stack() {
  local net="$1"
  local want_json="$2"
  local tries="${3:-12}"
  local sleep_s="${4:-5}"
  local sid=""

  for ((i=1; i<=tries; i++)); do
    sid="$(find_existing_stack_id_for_serials "$net" "$want_json")"
    if [[ -n "$sid" && "$sid" != "null" ]]; then
      echo "$sid"
      return 0
    fi
    sleep "$sleep_s"
  done

  return 1
}

ensure_stacks_exist() {
  local net="$1"
  local group name expected serials_json existing_id payload resp created_id
  local -i group_count=0

  while read -r group; do
  [[ -z "$group" ]] && continue
  ((group_count++))

  # 🔥 UPDATED BLOCK STARTS HERE
  stack_base_name="$(jq -r '.name' <<<"$group")"

  clean_name="$(echo "$stack_base_name" | tr ' ' '-' | tr -cd 'A-Za-z0-9_-')"

  if [[ "$clean_name" != *-stack ]]; then
    name="${clean_name}-stack"
  else
    name="$clean_name"
  fi
  # 🔥 UPDATED BLOCK ENDS HERE

  expected="$(jq -r '.expected' <<<"$group")"
  serials_json="$(jq -c '.serials' <<<"$group")"

    if [[ -z "$serials_json" || "$serials_json" == "[]" ]]; then
      continue
    fi

    if [[ "$(jq 'length' <<<"$serials_json")" -lt 2 ]]; then
      continue
    fi

    existing_id="$(find_existing_stack_id_for_serials "$net" "$serials_json")"
    if [[ -n "$existing_id" && "$existing_id" != "null" ]]; then
      log "Stack already exists for $name in $net -> $existing_id"
      continue
    fi

    log "Creating stack for $name in $net"

    payload=$(jq -n \
      --arg name "$name" \
      --argjson serials "$serials_json" '
      { name: $name, serials: $serials }
    ')

    resp="$(meraki_api POST "/networks/$net/switch/stacks" "$payload")"

    if echo "$resp" | jq -e '.errors' >/dev/null 2>&1; then
      log "WARN: Stack create returned errors for $name -> $resp"
      continue
    fi

    created_id="$(wait_for_stack "$net" "$serials_json" 12 5 || true)"
    if [[ -n "$created_id" && "$created_id" != "null" ]]; then
      log "Stack formed for $name in $net -> $created_id"
    else
      log "WARN: Stack create requested for $name but formation not yet visible"
    fi

  done < <(get_expected_stack_groups "$net")

  if (( group_count == 0 )); then
    log "No expected pre-stack groups for $net"
  fi
}

# ------------------------------------------------------------
# PROFILE CREATE / UPDATE
# ------------------------------------------------------------
apply_profile() {
  local net="$1"
  local vlans="$2"
  local name iname existing existing_vlans existing_json merged vlan_str payload resp update_resp

  ACTION_REASON=""
  ACTION=""

  name="CMDS-VLAN-PROFILE-$net"
  iname=$(echo "$name" | tr -cd 'A-Za-z0-9')

  existing=$(meraki_api GET "/networks/$net/vlanProfiles")

  existing_vlans=$(echo "$existing" | jq -r --arg i "$iname" '
    .[] | select(.iname == $i) | .activeVlans // ""
  ' | head -n1)

  existing_json=$(active_vlans_to_json "$existing_vlans")

  merged=$(jq -n \
    --argjson a "$existing_json" \
    --argjson b "$vlans" \
    '($a + $b + [1]) | unique | sort')

  vlan_str=$(echo "$merged" | jq -r 'join(",")')

  payload=$(jq -n \
    --arg n "$name" \
    --arg i "$iname" \
    --arg v "$vlan_str" '
    {
      name: $n,
      iname: $i,
      activeVlans: $v,
      vlanNames: [{name:"default", vlanId:"1"}],
      vlanGroups: []
    }')

  resp=$(meraki_api POST "/networks/$net/vlanProfiles" "$payload")

  if echo "$resp" | jq -e '.errors' >/dev/null 2>&1; then
    log "INFO: Profile exists or POST returned errors -> updating"
    update_resp=$(meraki_api PUT "/networks/$net/vlanProfiles/$iname" "$payload")

    if echo "$update_resp" | jq -e '.errors' >/dev/null 2>&1; then
      ACTION="FAILED"
      ACTION_REASON="$update_resp"
      return 1
    fi

    ACTION="UPDATED"
  else
    ACTION="CREATED"
  fi

  return 0
}

# ------------------------------------------------------------
# ASSIGN (MIXED NETWORK SAFE)
# ------------------------------------------------------------
assign_profile() {
  local net="$1"
  local iname="$2"
  local stacks_json stack_ids_json stacked_serials_json
  local all_serials_json standalone_serials_json payload resp
  local stack_count standalone_count stack_name label
  local -a all_serials_arr members

  ASSIGN_REASON=""
  results=()

  mapfile -t all_serials_arr < <(get_switches "$net")

  if [[ ${#all_serials_arr[@]} -eq 0 ]]; then
    ASSIGN_REASON="No claimed switches found for network $net"
    return 1
  fi

  all_serials_json=$(printf '%s\n' "${all_serials_arr[@]}" | jq -R . | jq -s 'map(select(length > 0))')

  stacks_json=$(meraki_api GET "/networks/$net/switch/stacks")
  stack_ids_json=$(echo "$stacks_json" | jq '[ .[]?.id ]')
  stacked_serials_json=$(echo "$stacks_json" | jq '[ .[]?.serials[]? ] | unique')

  standalone_serials_json=$(jq -n \
    --argjson all "$all_serials_json" \
    --argjson stacked "$stacked_serials_json" \
    '$all - $stacked')

  stack_count=$(jq 'length' <<<"$stack_ids_json")
  standalone_count=$(jq 'length' <<<"$standalone_serials_json")

  if (( stack_count == 0 && standalone_count == 0 )); then
    ASSIGN_REASON="No stacks or standalone serials resolved for network $net"
    return 1
  fi

  if (( stack_count > 0 && standalone_count > 0 )); then
    results+=("Assignment mode: MIXED")
    log "Using MIXED assignment"
  elif (( stack_count > 0 )); then
    results+=("Assignment mode: STACK")
    log "Using STACK assignment"
  else
    results+=("Assignment mode: SERIAL")
    log "Using SERIAL assignment"
  fi

  payload=$(jq -n \
    --arg i "$iname" \
    --argjson stacks "$stack_ids_json" \
    --argjson serials "$standalone_serials_json" \
    '{ vlanProfile:{iname:$i}, stackIds:$stacks, serials:$serials }')

  resp=$(meraki_api POST "/networks/$net/vlanProfiles/assignments/reassign" "$payload")

  if echo "$resp" | jq -e '.errors' >/dev/null 2>&1; then
    ASSIGN_REASON="$resp"
    return 1
  fi

  if (( stack_count > 0 )); then
    while read -r sid; do
      [[ -z "$sid" ]] && continue
      stack_name="$(get_stack_name "$sid" "$net")"
      [[ -z "$stack_name" || "$stack_name" == "null" ]] && stack_name="stack"
      results+=("[OK] STACK $sid ($stack_name)")

      mapfile -t members < <(get_stack_members "$net" "$sid")
      for s in "${members[@]}"; do
        [[ -z "$s" ]] && continue
        label="$(get_label "$s")"
        [[ -z "$label" || "$label" == "null" ]] && label="unknown"
        results+=("   |- $s ($label)")
      done
    done < <(jq -r '.[]' <<<"$stack_ids_json")
  fi

  if (( standalone_count > 0 )); then
    while read -r s; do
      [[ -z "$s" ]] && continue
      label="$(get_label "$s")"
      [[ -z "$label" || "$label" == "null" ]] && label="unknown"
      results+=("[OK] $s ($label)")
    done < <(jq -r '.[]' <<<"$standalone_serials_json")
  fi

  return 0
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
main() {
  local ok fail row net vlans net_name name iname

  need jq
  need curl
  need awk
  need sed
  need grep
  need base64

  load_env
  build_vlan_summary || true

  ok=0
  fail=0

  : > "$SUMMARY_TXT"

  while read -r row; do
    [[ -z "$row" ]] && continue

    net=$(jq -r '.networkId' <<<"$row")
    vlans=$(jq '.vlans' <<<"$row")

    name="CMDS-VLAN-PROFILE-$net"
    iname=$(echo "$name" | tr -cd 'A-Za-z0-9')
    net_name="$(get_network_name "$net")"

    if [[ -n "$net_name" && "$net_name" != "null" ]]; then
      echo "Network: $net ($net_name)" | tee -a "$SUMMARY_TXT"
    else
      echo "Network: $net" | tee -a "$SUMMARY_TXT"
    fi

    echo "Profile: $name" | tee -a "$SUMMARY_TXT"

    # NEW: ensure logical stacks are formed before profile assignment
    ensure_stacks_exist "$net"

    if apply_profile "$net" "$vlans"; then
      echo "Action: $ACTION" | tee -a "$SUMMARY_TXT"
    else
      echo "Action: FAILED" | tee -a "$SUMMARY_TXT"
      [[ -n "${ACTION_REASON:-}" ]] && echo "$ACTION_REASON" | tee -a "$SUMMARY_TXT"
      ((fail++))
      echo "" | tee -a "$SUMMARY_TXT"
      continue
    fi

    if assign_profile "$net" "$iname"; then
      echo "Assignment: SUCCESS" | tee -a "$SUMMARY_TXT"
      printf '%s\n' "${results[@]}" | tee -a "$SUMMARY_TXT"
      ((ok++))
    else
      echo "Assignment: FAILED" | tee -a "$SUMMARY_TXT"
      [[ -n "${ASSIGN_REASON:-}" ]] && echo "$ASSIGN_REASON" | tee -a "$SUMMARY_TXT"
      ((fail++))
    fi

    echo "" | tee -a "$SUMMARY_TXT"
  done < <(jq -c '.[]' "$SUMMARY_FILE" 2>/dev/null || true)

  echo "Success: $ok" | tee -a "$SUMMARY_TXT"
  echo "Failed : $fail" | tee -a "$SUMMARY_TXT"

  log "DONE"
}

main "$@"