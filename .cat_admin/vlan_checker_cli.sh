#!/usr/bin/env bash
# ============================================================
# CMDS VLAN PROFILE PIPELINE (CAT VERSION - v1)
# ============================================================

set -Euo pipefail

BASE_DIR="/root/.cat_admin"
PUSH_RUN_ROOT="$BASE_DIR/runs/vlan_push"

DISCOVERY_FILE="$BASE_DIR/discovery_results.json"
SELECTED_ENV="$BASE_DIR/selected_upgrade.env"
MAP_FILE="$BASE_DIR/meraki_switch_map.json"

CONFIG_DIR="/var/lib/tftpboot/cat"
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
  [[ -f "$MAP_FILE" ]] || { log "Missing meraki_switch_map.json"; exit 1; }

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
# LOOKUPS (CAT VERSION)
# ------------------------------------------------------------
get_network_from_ip() {
  local ip="$1"

  jq -r --arg ip "$ip" '
    .[]
    | select(.source.ip == $ip)
    | .networkId
  ' "$MAP_FILE" | head -n1
}

get_network_name() {
  local net="$1"

  jq -r --arg n "$net" '
    .[]
    | select(.networkId == $n)
    | .networkName
  ' "$MAP_FILE" | head -n1
}

get_switches() {
  local net="$1"

  jq -r \
    --arg net "$net" \
    --arg ips "$UPGRADE_SELECTED_IPS" '

    ($ips | split(" ")) as $selected_ips

    | .[]
    | select(.networkId == $net)
    | select(.source.ip as $ip | $selected_ips | index($ip))
    | .target.cloud_id
    | select(type == "string" and length > 0)

  ' "$MAP_FILE" | sort -u
}
get_label() {
  local serial="$1"

  jq -r --arg s "$serial" '
    .[]
    | select(.target.cloud_id == $s)
    | (.target.name // .source.hostname // "unknown")
  ' "$MAP_FILE" | head -n1
}

# ------------------------------------------------------------
# VLAN EXTRACTION (UNCHANGED - GOOD LOGIC)
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
    }
  ' "$1" | sort -n | uniq
}

normalize_vlans_json() {
  local v="$1"
  jq -n --argjson a "$v" '($a + [1]) | unique | sort'
}

# ------------------------------------------------------------
# BUILD VLAN SUMMARY (UPDATED)
# ------------------------------------------------------------
build_vlan_summary() {
  local tmpfile ip net cfg vlan_list vlans
  local -a SELECTED

  log "Building VLAN summary..."
  tmpfile=$(mktemp)

  read -r -a SELECTED <<< "${UPGRADE_SELECTED_IPS:-}"

  for ip in "${SELECTED[@]}"; do
    [[ -z "$ip" ]] && continue

    net="$(get_network_from_ip "$ip")"
    [[ -z "$net" || "$net" == "null" ]] && {
      log "WARN: No network mapping for $ip"
      continue
    }

    cfg=$(jq -r --arg ip "$ip" '
      .[]
      | select(.ip == $ip and .backup_status == "OK" and .blacklisted == false)
      | .backup_filename
    ' "$DISCOVERY_FILE" | head -n1)

    [[ -z "$cfg" || "$cfg" == "null" ]] && {
      log "WARN: No valid config for $ip"
      continue
    }

    cfg="$CONFIG_DIR/$cfg"
    [[ ! -f "$cfg" ]] && {
      log "WARN: Missing config file $cfg"
      continue
    }

    vlan_list=$(extract_vlans "$cfg" || true)
    [[ -z "$vlan_list" ]] && {
      log "WARN: No VLANs in $cfg"
      continue
    }

    vlans=$(printf '%s\n' $vlan_list | jq -R . | jq -s 'map(tonumber)')
    vlans=$(normalize_vlans_json "$vlans")

    jq -n --arg net "$net" --argjson v "$vlans" \
      '{networkId:$net, vlans:$v}' >> "$tmpfile"

  done

  jq -s '
    group_by(.networkId)
    | map({
        networkId: .[0].networkId,
        vlans: (map(.vlans[]) | unique | sort)
      })
  ' "$tmpfile" > "$SUMMARY_FILE"

  rm -f "$tmpfile"

  log "VLAN summary built -> $SUMMARY_FILE"
}

# ------------------------------------------------------------
# PROFILE + ASSIGN (UNCHANGED CORE)
# ------------------------------------------------------------
apply_profile() {
  local net="$1"
  local vlans="$2"
  local name iname payload resp

  name="CMDS-VLAN-PROFILE-$net"
  iname=$(echo "$name" | tr -cd 'A-Za-z0-9')

  payload=$(jq -n \
    --arg n "$name" \
    --arg i "$iname" \
    --arg v "$(echo "$vlans" | jq -r 'join(",")')" '
    {
      name: $n,
      iname: $i,
      activeVlans: $v,
      vlanNames: [{name:"default", vlanId:"1"}],
      vlanGroups: []
    }')

  resp=$(meraki_api POST "/networks/$net/vlanProfiles" "$payload")

  if echo "$resp" | jq -e '.errors' >/dev/null; then
    meraki_api PUT "/networks/$net/vlanProfiles/$iname" "$payload" >/dev/null
    ACTION="UPDATED"
  else
    ACTION="CREATED"
  fi
}

assign_profile() {
  local net="$1"
  local iname="$2"

  local stacks_json stack_ids_json stacked_serials_json
  local all_serials_json standalone_serials_json payload resp
  local -a all_serials_arr

  ASSIGN_REASON=""

  #Get ALL selected serials (same logic as your script)
  mapfile -t all_serials_arr < <(get_switches "$net")

  if [[ ${#all_serials_arr[@]} -eq 0 ]]; then
    log "No switches found for network $net"
    return 1
  fi

  all_serials_json=$(printf '%s\n' "${all_serials_arr[@]}" | jq -R . | jq -s 'map(select(length > 0))')

  #REAL STACK STATE FROM MERAKI (THIS IS THE FIX)
  stacks_json=$(meraki_api GET "/networks/$net/switch/stacks")

  stack_ids_json=$(echo "$stacks_json" | jq '[ .[]?.id ]')
  stacked_serials_json=$(echo "$stacks_json" | jq '[ .[]?.serials[]? ] | unique')

  #Determine standalone devices correctly
  standalone_serials_json=$(jq -n \
    --argjson all "$all_serials_json" \
    --argjson stacked "$stacked_serials_json" \
    '$all - $stacked')

  log "Assignment Debug (FIXED):"
  log "  stackIds: $stack_ids_json"
  log "  serials : $standalone_serials_json"

  payload=$(jq -n \
    --arg i "$iname" \
    --argjson stacks "$stack_ids_json" \
    --argjson serials "$standalone_serials_json" '
    {
      vlanProfile: { iname: $i },
      stackIds: $stacks,
      serials: $serials
    }
  ')

  resp=$(meraki_api POST "/networks/$net/vlanProfiles/assignments/reassign" "$payload")

  if echo "$resp" | jq -e '.errors' >/dev/null 2>&1; then
    log "ASSIGN FAILED: $resp"
    return 1
  fi

  log "Assignment successful"
  return 0
}

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
main() {
  need jq
  need curl
  need awk

  load_env
  build_vlan_summary

  : > "$SUMMARY_TXT"

  ok=0
  fail=0

  while read -r row; do
    net=$(jq -r '.networkId' <<<"$row")
    vlans=$(jq '.vlans' <<<"$row")

    name="CMDS-VLAN-PROFILE-$net"
    iname=$(echo "$name" | tr -cd 'A-Za-z0-9')

    echo "Processing $net"

    # ---- SUMMARY OUTPUT START ----
    echo "Network: $net" >> "$SUMMARY_TXT"
    echo "Profile: $name" >> "$SUMMARY_TXT"
    # ---- SUMMARY OUTPUT END ----

    if apply_profile "$net" "$vlans"; then
      echo "Profile: $ACTION" >> "$SUMMARY_TXT"
    else
      echo "Profile: FAILED" >> "$SUMMARY_TXT"
      ((fail++))
      echo "" >> "$SUMMARY_TXT"
      continue
    fi

    if assign_profile "$net" "$iname"; then
      echo "Assignment: SUCCESS" >> "$SUMMARY_TXT"
      ((ok++))
    else
      echo "Assignment: FAILED" >> "$SUMMARY_TXT"
      ((fail++))
    fi

    echo "" >> "$SUMMARY_TXT"

  done < <(jq -c '.[]' "$SUMMARY_FILE")

  echo "Success: $ok" >> "$SUMMARY_TXT"
  echo "Failed : $fail" >> "$SUMMARY_TXT"

  log "DONE"
}
main @