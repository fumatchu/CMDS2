#!/usr/bin/env bash
set -Euo pipefail

# ============================================================
# Cloud Migration – IOS Port Intent → Meraki Switch Ports
# ============================================================

: "${DIALOG:=dialog}"

DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi

dlg() {
  local common=(--clear --ok-label "Continue" --exit-label "Continue")

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
# UI helpers: SINGLE dialog gauge (no concurrent tailboxbg)
# ============================================================

UI_ACTIVE=0
UI_LOG=""
UI_LAST_MSG=""
UI_LAST_PCT=0
UI_GAUGE_PID=""
UI_FIFO=""
UI_STTY=""

_ui_term_size() {
  local r c
  r="$(tput lines 2>/dev/null || echo 30)"
  c="$(tput cols  2>/dev/null || echo 120)"
  (( r < 20 )) && r=20
  (( c < 80 )) && c=80
  printf '%s %s\n' "$r" "$c"
}

_ui_tail_lines() {
  local n="${1:-3}"
  [[ -n "${UI_LOG:-}" && -f "${UI_LOG:-}" ]] || return 0

  # last N lines, strip CR (windows), tabs → spaces
  tail -n "$n" "$UI_LOG" 2>/dev/null \
    | sed -e 's/\r$//' -e $'s/\t/  /g'
}

_ui_fit_line() {
  # truncate a single line to width-4 (roughly), add …
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

ui_start() {
  local title="${1:-Working...}"
  local log_file="${2:-/tmp/port_apply.log}"

  UI_LOG="$log_file"
  : >>"$UI_LOG"

  UI_STTY="$(stty -g 2>/dev/null || true)"

  local rows cols
  read -r rows cols < <(_ui_term_size)

  local h=12
  (( h > rows-2 )) && h=$(( rows-2 ))
  (( h < 10 )) && h=10

  local w=$(( cols - 4 ))
  (( w < 70 )) && w=70

  UI_FIFO="$(mktemp -u /tmp/meraki_gauge.XXXXXX)"
  mkfifo "$UI_FIFO"

  "$DIALOG" --backtitle "$BACKTITLE_PORTS" \
            --title "$title" \
            --gauge "Starting..." "$h" "$w" 0 <"$UI_FIFO" &
  UI_GAUGE_PID=$!

  exec 3>"$UI_FIFO"

  UI_ACTIVE=1
  UI_LAST_MSG="Starting..."
  UI_LAST_PCT=0

  printf '0\nXXX\nStarting...\nXXX\n' >&3
}

ui_stop() {
  (( UI_ACTIVE == 1 )) || return 0

  # Close FIFO writer so gauge gets EOF and exits normally
  exec 3>&- || true

  if [[ -n "${UI_GAUGE_PID:-}" ]]; then
    wait "$UI_GAUGE_PID" 2>/dev/null || true
  fi

  rm -f "${UI_FIFO:-}" 2>/dev/null || true

  "$DIALOG" --clear >/dev/null 2>&1 || true

  if [[ -n "${UI_STTY:-}" ]]; then
    stty "$UI_STTY" 2>/dev/null || true
  else
    stty sane 2>/dev/null || true
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

  UI_LAST_MSG="$msg"
  UI_LAST_PCT="$pct"

  local rows cols
  read -r rows cols < <(_ui_term_size)

  # Compose gauge text: status line + last log lines
  local header
  header="$msg"

  # Pull last 2–3 log lines and fit to width
  local line1 line2 line3
  line1="$(_ui_tail_lines 3 | sed -n '1p')"
  line2="$(_ui_tail_lines 3 | sed -n '2p')"
  line3="$(_ui_tail_lines 3 | sed -n '3p')"

  line1="$(_ui_fit_line "$cols" "$line1")"
  line2="$(_ui_fit_line "$cols" "$line2")"
  line3="$(_ui_fit_line "$cols" "$line3")"

  local text="$header"
  [[ -n "$line1" || -n "$line2" || -n "$line3" ]] && text+=$'\n\n'"Last log lines:"
  [[ -n "$line1" ]] && text+=$'\n'"  $line1"
  [[ -n "$line2" ]] && text+=$'\n'"  $line2"
  [[ -n "$line3" ]] && text+=$'\n'"  $line3"

  printf '%s\nXXX\n%s\nXXX\n' "$pct" "$text" >&3
}

restore_tty() {
  # Stop any active dialog gauge
  ui_stop || true

  # Tell dialog to clear its screen artifacts
  "$DIALOG" --clear >/dev/null 2>&1 || true

  # Restore terminal state
  stty sane 2>/dev/null || true
  tput cnorm 2>/dev/null || true
  printf '\033[0m' 2>/dev/null || true
}
trap restore_tty EXIT INT TERM

# Keep your name from earlier guidance
apply_ui_update() {
  # usage: apply_ui_update "message" [percent]
  ui_update "${1:-Working...}" "${2:-0}"
}

# Compare request body vs Meraki response and warn if Meraki didn't apply a field.
# Prints warnings to stdout (one per line). Returns 0 always.
warn_if_meraki_ignored_fields() {
  local req_json="$1"     # JSON object (string)
  local resp_file="$2"    # file containing JSON response from Meraki

  need jq || return 0

  # Valid JSON check (note: JSON "null" is valid)
  if ! jq -e . >/dev/null 2>&1 <"$resp_file"; then
    echo "WARN: Meraki response is not valid JSON; cannot verify applied fields."
    return 0
  fi

  jq -nr --argjson req "$req_json" --slurpfile r "$resp_file" '
    def norm_link(v):
      if v == null or v == "" then "Auto negotiate" else v end;

    def norm(v):
      if v == null then null
      elif (v|type) == "string" then v
      else v end;

    # The PUT response should be an object; sometimes it’s null/empty-ish.
    ($r[0]) as $resp
    | if ($resp|type) != "object" then
        "WARN: Meraki PUT response did not include a port object; cannot verify applied fields."
      else
        # Compare only keys we set in req
        ($req | keys_unsorted[]) as $k
        | (
            if $k == "dot3az" then
              # Verify nested enabled
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
              # Special-case: poeEnabled=false on non-PoE ports often returns null/missing in response.
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

            else
              # Generic field
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

meraki_get_switch_port_for_cloud_id() {
  local device_id="$1"
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


SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
CLOUD_ADMIN_BASE="${CLOUD_ADMIN_BASE:-/root/.cloud_admin}"
MERAKI_MEMORY_DIR="${MERAKI_MEMORY_DIR:-${CLOUD_ADMIN_BASE}/meraki_memory}"

# discovery + backup locations
DISCOVERY_RESULTS_FILE="${DISCOVERY_RESULTS_FILE:-${CLOUD_ADMIN_BASE}/discovery_results.json}"
BACKUP_LOCAL_BASE_DIR="${BACKUP_LOCAL_BASE_DIR:-/var/lib/tftpboot/mig}"

BACKTITLE_PORTS="Cloud Migration – IOS port profiles → Meraki"

# ============================================================
# Shared context loaders
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

  # latest symlinks
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
# Get API Key
# ============================================================

MERAKI_ENV_FILE="${MERAKI_ENV_FILE:-${CLOUD_ADMIN_BASE}/meraki_discovery.env}"

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
# Get backup config path for an IP from discovery_results.json
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
# Meraki identity / ports helpers
# ============================================================

find_meraki_identity_for_ip() {
  local ip="$1"
  [[ -d "$MERAKI_MEMORY_DIR" ]] || return 1

  jq -r --arg ip "$ip" '
    select(.ip == $ip)
    | "\(.serial // "")|\(.cloud_id // "")"
  ' "$MERAKI_MEMORY_DIR"/*.json 2>/dev/null | awk 'NF {print; exit}'
}

meraki_get_switch_ports_for_cloud_id() {
  local device_id="$1"
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
# IOS config → "intent" JSONL
# ============================================================

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

  udld_enabled = 0
  udld_aggressive = 0

  eee_set = 0
  eee_enabled = 0

  speed_s = ""
  duplex_s = ""
  linkneg = ""
  poe_enabled = 1
  dai_trusted = 0
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

  udld_enabled = 0
  udld_aggressive = 0

  eee_set = 0
  eee_enabled = 0

  speed_s = ""
  duplex_s = ""
  linkneg = ""
  poe_enabled = 1
  dai_trusted = 0
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

  if (udld_enabled) {
    mode_str = "Alert only"
    if (udld_aggressive) mode_str = "Enforce"
    printf ",\"udld\":\"%s\"", mode_str
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

/^!/ && in_if {
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

  if ($1 == "switchport" && $2 == "mode") {
    mode=$3
    next
  }

  if ($1 == "switchport" && $2 == "access" && $3 == "vlan") {
    access_vlan=$4
    next
  }

  if ($1 == "switchport" && $2 == "voice" && $3 == "vlan") {
    voice_vlan=$4
    next
  }

  if ($1 == "switchport" && $2 == "trunk" && $3 == "native" && $4 == "vlan") {
    native_vlan=$5
    next
  }

  if ($1 == "switchport" && $2 == "trunk" && $3 == "allowed" && $4 == "vlan") {
    allowed_vlans=$5
    next
  }

  if ($1 == "channel-group") {
    portchannel_id = $2
    if ($3 == "mode" && $4 != "") {
      portchannel_mode = $4
    }
    next
  }

  if ($1 == "udld" && $2 == "port") {
    udld_enabled = 1
    if ($3 == "aggressive") udld_aggressive = 1
    next
  }

  if ($1 == "spanning-tree" && $2 == "portfast") {
    portfast = 1
    next
  }

  if ($1 == "spanning-tree" && $2 == "bpduguard" && $3 == "enable") {
    bpduguard = 1
    rootguard = 0
    loopguard = 0
    next
  }

  if ($1 == "spanning-tree" && $2 == "guard" && $3 == "root") {
    rootguard = 1
    loopguard = 0
    bpduguard = 0
    next
  }

  if ($1 == "spanning-tree" && $2 == "guard" && $3 == "loop") {
    loopguard = 1
    rootguard = 0
    bpduguard = 0
    next
  }

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

  if ($1 == "speed") {
    speed_s = $2
    next
  }

  if ($1 == "duplex") {
    duplex_s = $2
    next
  }

  if ($1 == "power" && $2 == "inline") {
    if ($3 == "never") poe_enabled = 0
    else poe_enabled = 1
    next
  }

  if ($1 == "ip" && $2 == "arp" && $3 == "inspection" && $4 == "trust") {
    dai_trusted = 1
    next
  }

    # EEE (802.3az) intent
  # IOS-XE commonly uses: "power efficient-ethernet auto"
  if ($1 == "power" && $2 == "efficient-ethernet") {
    # treat any appearance as "enabled"
    eee_set = 1
    eee_enabled = 1
    next
  }

  if ($1 == "no" && $2 == "power" && $3 == "efficient-ethernet") {
    eee_set = 1
    eee_enabled = 0
    next
  }

  if ($1 == "shutdown") {
    enabled = 0
    next
  }

  if ($1 == "no" && $2 == "shutdown") {
    enabled = 1
    next
  }
}

END {
  if (in_if) flush_if()
}
AWK
}

# ============================================================
# Intent + Meraki ports → diff JSON + human summary
# ============================================================

merge_ios_intent_with_meraki_ports() {
  local ip="$1"
  local ios_cfg="$2"

  need jq || return 1

  if [[ -z "${RUN_DIR:-}" ]]; then
    echo "RUN_DIR is not set – run from migration context." >&2
    return 1
  fi

  mkdir -p "$RUN_DIR/ports" "$RUN_DIR/devlogs" 2>/dev/null || true

  local build_log="$RUN_DIR/devlogs/${ip}_build_diff.log"
  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Build port diff for $ip ===="
    echo "IOS config: $ios_cfg"
  } >>"$build_log"

    # UI: show live progress instead of blank screen during diff build
  ui_start "Building port diff for $ip" "$build_log"
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

  local intent_jsonl="$RUN_DIR/ports/${ip}_${base_name}_intent.jsonl"
  local ports_current="$RUN_DIR/ports/${ip}_${base_name}_ports_current.json"
  local ports_diff_json="$RUN_DIR/ports/${ip}_${base_name}_ports_diff.json"
  local ports_diff_txt="$RUN_DIR/ports/${ip}_${base_name}_ports_diff.txt"

  echo "Step 1: Parsing IOS config → intent JSONL ($intent_jsonl)" >>"$build_log"
    apply_ui_update "Parsing IOS config → intent" 10
  if ! parse_ios_config_to_intent "$ios_cfg" >"$intent_jsonl" 2>>"$build_log"; then
    echo "ERROR: parse_ios_config_to_intent failed for $ios_cfg" >>"$build_log"
    echo "Failed to parse IOS config $ios_cfg" >&2
    return 1
  fi

  echo "Step 2: Looking up Meraki identity in meraki_memory for IP $ip" >>"$build_log"
    apply_ui_update "Looking up Meraki device identity (meraki_memory)" 25
  local id_line serial cloud_id
  id_line="$(find_meraki_identity_for_ip "$ip" 2>>"$build_log" || true)"
  if [[ -z "$id_line" ]]; then
    echo "ERROR: No meraki_memory entry found for IP $ip" >>"$build_log"
    echo "No meraki_memory entry found for IP $ip – cannot fetch ports." >&2
    return 1
  fi

  IFS='|' read -r serial cloud_id <<<"$id_line"
  echo "  Found: serial=$serial cloud_id=$cloud_id" >>"$build_log"

  if [[ -z "$cloud_id" ]]; then
    echo "ERROR: No Cloud ID recorded in meraki_memory for IP $ip." >>"$build_log"
    echo "No Cloud ID for IP $ip – cannot fetch ports." >&2
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

  # Iterate each Meraki port object
  while IFS= read -r meraki_port; do
    local pid
    pid="$(jq -r '.portId // empty | tostring' <<<"$meraki_port" 2>/dev/null || echo "")"
    pid="$(trim "$pid")"
    [[ -z "$pid" ]] && continue

    # Matching IOS intent row by portId (normalize to tostring compare)
    local ios_entry
    ios_entry="$(jq -c --arg pid "$pid" 'select((.portId|tostring) == $pid)' "$intent_jsonl" 2>/dev/null | head -n1 || true)"
    [[ -z "$ios_entry" ]] && continue

    # Optional port-channel template
    local pcid pc_entry
    pcid="$(jq -r '(.portChannelId|tostring)? // ""' <<<"$ios_entry" 2>/dev/null || echo "")"
    if [[ -n "$pcid" ]]; then
      pc_entry="$(jq -c --arg pcid "$pcid" '
        select(.isPortChannel == true and (.portChannelId|tostring) == $pcid)
      ' "$intent_jsonl" 2>/dev/null | head -n1 || true)"
    fi
    [[ -n "$pc_entry" ]] || pc_entry='{}'

    # ---------- jq merge logic ----------
    local row
    row="$(
      jq -n \
        --argjson m  "$meraki_port" \
        --argjson i  "$ios_entry" \
        --argjson pc "$pc_entry" '
        # IMPORTANT: normalize portId to string everywhere
        {
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
            daiTrusted: ($m.daiTrusted // null),
            udld: ($m.udld // null),
            linkNegotiation: ($m.linkNegotiation // null)
          }
        }
        as $base

        | {
            enabled: (if ($i | has("enabled")) then $i.enabled else $base.current.enabled end),
            type:   ($i.type // $pc.type // $base.current.type),

            vlan: (
              if      ($i.accessVlan   // null) != null then $i.accessVlan
              elif    ($i.nativeVlan   // null) != null then $i.nativeVlan
              elif    ($pc.accessVlan  // null) != null then $pc.accessVlan
              elif    ($pc.nativeVlan  // null) != null then $pc.nativeVlan
              else $base.current.vlan end
            ),

            voiceVlan: ($i.voiceVlan // $pc.voiceVlan // $base.current.voiceVlan),

            allowedVlans: ($i.allowedVlans // $pc.allowedVlans // $base.current.allowedVlans),

            name: (
              if $i.description != null then
                ($i.description
                  | gsub("[^A-Za-z0-9 .,_/-]"; "")
                  | gsub(" +"; " ")
                  | sub("^ +"; "")
                  | sub(" +$"; "")
                )
              else
                $base.description_current
              end
            ),

            stpGuard: (
              if   $i.stpGuard == "bpduGuard" then "bpdu guard"
              elif $i.stpGuard == "rootGuard" then "root guard"
              elif $i.stpGuard == "loopGuard" then "loop guard"
              elif ($i.portfast // false) == true then "disabled"
              else $base.current.stpGuard
              end
            ),

            dot3az: (
              if ($i | has("eeeEnabled")) then { enabled: $i.eeeEnabled }
              else { enabled: ($base.current.dot3az // null) } end
            ),

            udld: ($i.udld // $base.current.udld),

            linkNegotiation: ($i.linkNegotiation // $base.current.linkNegotiation),

            daiTrusted: ($i.daiTrusted // $base.current.daiTrusted),

            poeEnabled: (
              if ($i | has("poeEnabled")) then $i.poeEnabled else $base.current.poeEnabled end
            )
          }
        as $desired

        | $base
        | .desired = $desired
        | .notes = []

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
            (if (.description_current // null) != (.desired.name // null) then "name" else empty end)
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
    jq -r --arg ip "$ip" --arg dev "$cloud_id" --arg serial "$serial" '
      def show_val(x): if x == null then "(none)" else (x|tostring) end;

      map(select((.changes|length) > 0)) as $changed
      |
      "Port migration diff for IP " + $ip + " (deviceId " + $dev + ", serial " + $serial + ")",
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

  echo "SUCCESS: Build diff completed for $ip" >>"$build_log"
    apply_ui_update "Diff build complete" 100
  echo "  intent: $intent_jsonl" >>"$build_log"
  echo "  ports:  $ports_current" >>"$build_log"
  echo "  diff:   $ports_diff_json" >>"$build_log"
  echo "  txt:    $ports_diff_txt" >>"$build_log"

  echo "Intent JSONL:  $intent_jsonl"
  echo "Current ports: $ports_current"
  echo "Diff JSON:     $ports_diff_json"
  echo "Diff summary:  $ports_diff_txt"

  return 0
}

# ============================================================
# Port-channels (Link Aggregations) – helpers + apply (all interfaces)
# ============================================================

# Get full device record (includes networkId) from Meraki by Meraki device identifier
# NOTE: Meraki expects its own device identifier here (often called "serial" in docs).
meraki_get_device_by_id() {
  local device_id="$1"
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

# List link aggregations for a network
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

# Create a link aggregation group
meraki_create_network_link_agg() {
  local network_id="$1"
  local body_json="$2"   # JSON object string
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

# Update a link aggregation group
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

# Build desired LAG definitions from diff_file (group by portChannelId) – ALL interfaces
# Output: JSON array of {pcid, members:[{serial,portId,interface}]}
build_lag_defs_from_diff_all() {
  local diff_file="$1"
  local meraki_id="$2"   # this is the Meraki identifier used in API (your cloud_id like Q5TJ-...)

  jq -c --arg serial "$meraki_id" '
    [ .[]
      | select(.portChannelId != null)
      | { pcid: (.portChannelId|tostring),
          member: { serial: $serial, portId: (.portId|tostring), interface: (.interface // "") }
        }
    ]
    | group_by(.pcid)
    | map({
        pcid: (.[0].pcid),
        members: (map(.member) | sort_by(.portId))
      })
  ' "$diff_file"
}

# Apply link aggregations for this switch based on diff_file (ALL interfaces)
apply_link_aggs_from_diff_all() {
  local meraki_id="$1"     # pass cloud_id / deviceId value you already use successfully
  local diff_file="$2"
  local apply_log="$3"

  need jq || return 1
  need curl || return 1

  local dev_json network_id
  dev_json="$(mktemp)"
  if ! meraki_get_device_by_id "$meraki_id" "$dev_json" >>"$apply_log" 2>&1; then
    echo "LAG: FAILED to fetch device record for deviceId=$meraki_id" >>"$apply_log"
    rm -f "$dev_json"
    return 1
  fi

  network_id="$(jq -r '.networkId // empty' "$dev_json" 2>/dev/null || true)"
  rm -f "$dev_json"
  network_id="$(trim "$network_id")"
  if [[ -z "$network_id" ]]; then
    echo "LAG: DeviceId=$meraki_id returned no networkId; cannot manage link aggregations." >>"$apply_log"
    return 1
  fi

  local existing_json
  existing_json="$(mktemp)"
  if ! meraki_get_network_link_aggs "$network_id" "$existing_json" >>"$apply_log" 2>&1; then
    echo "LAG: FAILED to list existing link aggregations for networkId=$network_id" >>"$apply_log"
    rm -f "$existing_json"
    return 1
  fi

  local lag_defs
  lag_defs="$(build_lag_defs_from_diff_all "$diff_file" "$meraki_id")"
  if [[ -z "$lag_defs" || "$lag_defs" == "null" || "$lag_defs" == "[]" ]]; then
    echo "LAG: No port-channel members found in diff; nothing to do." >>"$apply_log"
    rm -f "$existing_json"
    return 0
  fi

    echo "LAG: Desired LAG defs: $lag_defs" >>"$apply_log"

  # SAFETY: Detect if the same physical port is assigned to multiple port-channels.
  # Log it using interface names + which pcids conflict, then abort before making changes.
  local dup_ports
  dup_ports="$(
    jq -r '
      # Build flat records of each member with its pcid
      [ .[] as $lag
        | $lag.members[]
        | {
            key: ("\(.serial):\(.portId)"),
            serial: .serial,
            portId: (.portId|tostring),
            interface: (.interface // ""),
            pcid: ($lag.pcid|tostring)
          }
      ]
      # Group by physical port (serial:portId)
      | group_by(.key)
      # Keep only ports that appear more than once (i.e., in multiple LAGs)
      | map(select(length > 1))
      # Render readable lines for logs
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
  if [[ "$count" -eq 0 ]]; then
    echo "LAG: No LAGs to apply." >>"$apply_log"
    rm -f "$existing_json"
    return 0
  fi

  local i
  for (( i=0; i<count; i++ )); do
    local pcid members members_key exact_match_id update_candidate_id body

    pcid="$(jq -r ".[$i].pcid" <<<"$lag_defs")"
    members="$(jq -c ".[$i].members" <<<"$lag_defs")"

    # Stable key: sorted list of "serial:portId"
    members_key="$(jq -r '[ .[] | "\(.serial):\(.portId)" ] | sort | join(",")' <<<"$members")"

    echo "" >>"$apply_log"
    echo "LAG: Port-channel $pcid members_key=$members_key" >>"$apply_log"

    # EXACT match among existing link aggs
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

    # Candidate LAG that shares at least one member
    update_candidate_id="$(
      jq -r --arg mk "$members_key" '
        def set(a): (a | split(",") | map(select(length>0)) | unique);
        def intersect(a;b): (set(a) as $A | set(b) as $B | ($A + $B) | group_by(.) | map(select(length>1)) | length);
        .[]?
        | {id: (.id|tostring),
           mk: ([ .switchPorts[]? | "\(.serial):\(.portId)" ] | sort | join(","))
          }
        | select(intersect(.mk; $mk) > 0)
        | .id
      ' "$existing_json" 2>/dev/null | head -n1
    )"

    # POST/PUT body: {switchPorts:[{serial,portId},...]}
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

find_latest_ports_diff_for_ip() {
  local ip="$1"
  local dir="${RUN_DIR:-}/ports"
  [[ -d "$dir" ]] || return 1
  ls -1t "$dir"/"${ip}"_*_ports_diff.json 2>/dev/null | head -n1
}

apply_ports_from_diff() {
  local ip="$1"
  local diff_file="$2"

  need curl || return 1
  need jq   || return 1

  if [[ ! -f "$diff_file" ]]; then
    echo "Diff JSON not found: $diff_file" >&2
    return 1
  fi

  local id_line serial cloud_id
  id_line="$(find_meraki_identity_for_ip "$ip" 2>/dev/null || true)"
  if [[ -z "$id_line" ]]; then
    echo "No meraki_memory entry found for IP $ip – cannot determine device identity." >&2
    return 1
  fi
  IFS='|' read -r serial cloud_id <<<"$id_line"

  if [[ -z "$cloud_id" ]]; then
    echo "Cloud ID missing for IP $ip in meraki_memory – cannot apply." >&2
    return 1
  fi

  local api_base="${MERAKI_API_BASE:-https://api.meraki.com/api/v1}"
  local apply_log="$RUN_DIR/devlogs/${ip}_ports_apply.log"

  {
    echo "==== $(date +'%Y-%m-%d %H:%M:%S %Z') – Applying port diffs for IP $ip (serial $serial, deviceId $cloud_id) ===="
    echo "Diff file: $diff_file"
  } >>"$apply_log"

  # Build checklist list of ports w/ changes
  local tmp_list=""
  tmp_list="$(mktemp)"
    # Cleanup handler for this function (tmp files + UI)
  _apply_cleanup() {
    ui_stop
    rm -f "${tmp_list:-}" 2>/dev/null || true
  }
  trap _apply_cleanup RETURN

    # UI: show progress while preparing (prevents blank blue screen)
  ui_start "Preparing port list for $ip (serial $serial)" "$apply_log"
  apply_ui_update "Loading diff + preparing checklist..." 5

  {
  echo ""
  echo "==== LAG STEP: Applying port-channels (link aggregations) for deviceId $cloud_id ===="
} >>"$apply_log"

apply_ui_update "Applying link aggregations (port-channels)..." 20
apply_link_aggs_from_diff_all "$cloud_id" "$diff_file" "$apply_log" || true
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

  # Dialog selection (one portId per line)
  local selection

  # Size dialog to terminal (avoid wrap artifacts)
  local term_rows term_cols height width listheight
  term_rows="$(tput lines 2>/dev/null || echo 30)"
  term_cols="$(tput cols  2>/dev/null || echo 120)"

  height=$(( term_rows - 6 )); (( height < 18 )) && height=18
  width=$(( term_cols - 6  )); (( width  < 110 )) && width=110
  (( width > 180 )) && width=180
  listheight=$(( height - 8 )); (( listheight < 8 )) && listheight=8
  (( listheight > 20 )) && listheight=20

  # Stop progress UI BEFORE interactive checklist  (MUST be before dlg)
apply_ui_update "Opening port selection checklist..." 60
ui_stop

"$DIALOG" --clear >/dev/null 2>&1 || true

selection="$(
  dlg --backtitle "$BACKTITLE_PORTS" \
      --separate-output \
      --checklist "Select ports on IP $ip (serial $serial) to apply to Meraki.\n(Use SPACE to toggle, ENTER when done.)" \
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

  # Robustly turn newline-separated selection into an array
  local -a PORTS_TO_APPLY=()
  while IFS= read -r pid; do
    pid="$(trim "$pid")"
    [[ -n "$pid" ]] && PORTS_TO_APPLY+=("$pid")
  done <<<"$selection"

  echo "Ports selected to apply: ${PORTS_TO_APPLY[*]}" >>"$apply_log"

  ui_start "Applying ports for $ip (serial $serial)" "$apply_log"
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

    # --- NEW DEBUG: prove the row we think we’re using ---
    echo "Row debug for port $p:" >>"$apply_log"
    if ! jq -c --arg pid "$p" \
      '.[] | select((.portId|tostring) == $pid) | {portId, changes, desired}' \
      "$diff_file" >>"$apply_log" 2>&1; then
      echo "Row debug jq failed for port $p" >>"$apply_log"
    fi

    # Also log if we matched nothing
    local matched_count
    matched_count="$(jq -r --arg pid "$p" '[ .[] | select((.portId|tostring) == $pid) ] | length' "$diff_file" 2>/dev/null || echo 0)"
    if [[ "$matched_count" == "0" ]]; then
      echo "NO MATCH in diff_file for portId=$p (cannot compute body)" >>"$apply_log"
      ((fail_count++))
      continue
    fi

    # Build PUT body directly from diff row, only including changed fields.
    local body
    body="$(
  jq -c --arg pid "$p" '
    def add(k; v): if v == null then . else . + { (k): v } end;

    .[]
    | select((.portId|tostring) == $pid)
    | . as $r
    | reduce ($r.changes[]) as $c ({};
        if      $c == "name" then
          if ($r.portChannelId != null) then .
          else add("name"; $r.desired.name) end
        elif    $c == "enabled"         then add("enabled";         $r.desired.enabled)
        elif    $c == "type"            then add("type";            $r.desired.type)
        elif    $c == "vlan"            then add("vlan";            $r.desired.vlan)
        elif    $c == "voiceVlan"       then add("voiceVlan";       $r.desired.voiceVlan)
        elif $c == "allowedVlans" then
  (if ($r.desired.allowedVlans // "") == "all" then
      add("allowedVlans"; "1-1000")
   else
      add("allowedVlans"; $r.desired.allowedVlans)
   end)

        elif    $c == "stpGuard"        then add("stpGuard";        $r.desired.stpGuard)
        elif    $c == "udld"            then add("udld";            $r.desired.udld)
        elif    $c == "linkNegotiation" then add("linkNegotiation"; $r.desired.linkNegotiation)
        elif    $c == "poeEnabled"      then add("poeEnabled";      $r.desired.poeEnabled)
        elif    $c == "dot3az"          then add("dot3az";          $r.desired.dot3az)
        elif    $c == "daiTrusted"      then add("daiTrusted";      $r.desired.daiTrusted)
        else . end
      )
  ' "$diff_file" | head -n1
)"


    # --- DEBUG: show computed body every time ---
    echo "Computed body for port $p: ${body:-<empty>}" >>"$apply_log"

    # If body is empty, skip so we don't send {} (Meraki rejects it)
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

      # Warn (don’t fail) if Meraki ignores a field we tried to set.
      # NOTE: $body is the JSON we sent, $tmp_resp is the PUT response file.
      local warn_lines warned_this_port=0
      warn_lines="$(warn_if_meraki_ignored_fields "$body" "$tmp_resp" 2>/dev/null || true)"

      if [[ -n "${warn_lines:-}" ]]; then
        echo "Port $p: WARNINGS (Meraki did not apply some fields):" >>"$apply_log"
        while IFS= read -r wl; do
          [[ -n "$wl" ]] && echo "  $wl" >>"$apply_log"
        done <<<"$warn_lines"
        warned_this_port=1
      fi

      # OPTIONAL VERIFY: if PUT response was incomplete (can't verify), do a GET and re-check.
      # This avoids false positives when Meraki returns partial/null PUT responses.
      if grep -qi "cannot verify" <<<"${warn_lines:-}"; then
        echo "Port $p: PUT response incomplete; verifying via GET..." >>"$apply_log"

        local verify_file warn_lines2
        verify_file="$(mktemp)"

        if meraki_get_switch_port_for_cloud_id "$cloud_id" "$p" "$verify_file" >>"$apply_log" 2>&1; then
          warn_lines2="$(warn_if_meraki_ignored_fields "$body" "$verify_file" 2>/dev/null || true)"

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
          # keep warned_this_port as-is
        fi

        rm -f "$verify_file" 2>/dev/null || true
      fi

      # Count warnings per-port (not per-line)
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

  # Final progress update (100%)
  apply_ui_update "Apply complete. OK=$ok_count WARN=$warn_count FAIL=$fail_count" 100

  # Stop any active progress UI BEFORE opening a msgbox
  ui_stop

  local msg="Port apply completed for IP $ip (serial $serial).\n\n\
Success: $ok_count port(s)\n\
Warnings: $warn_count port(s)\n\
Failed:  $fail_count port(s)\n\n\
See log file for details:\n  $apply_log"

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Port apply results" \
      --msgbox "$msg" 15 80

  return 0
}

# ============================================================
# High-level flows
# ============================================================

pick_switch_ip_from_run() {
  local -a items=()
  local i ip
  for i in "${!PORTS_SELECTED_IPS[@]}"; do
    ip="${PORTS_SELECTED_IPS[$i]}"
    items+=( "$ip" "Selected switch #$((i+1)) in this run" )
  done

  dlg --backtitle "$BACKTITLE_PORTS" \
      --title "Choose switch" \
      --menu "Select a switch (by IP) to work on." \
      20 70 12 \
      "${items[@]}"
}

build_port_diff_for_one_switch() {
  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local ip
  ip="$(pick_switch_ip_from_run)" || return 1

  local cfg
  cfg="$(find_backup_cfg_for_ip "$ip" 2>/dev/null || true)"

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

  if merge_ios_intent_with_meraki_ports "$ip" "$cfg"; then
    local base_name
    base_name="$(basename "$cfg" | sed 's/\..*$//')"
    local summary="$RUN_DIR/ports/${ip}_${base_name}_ports_diff.txt"

    if [[ -f "$summary" ]]; then
      dlg --backtitle "$BACKTITLE_PORTS" \
          --title "Port diff built" \
          --textbox "$summary" 30 120 || true
    else
      dlg --backtitle "$BACKTITLE_PORTS" \
          --title "Port diff built" \
          --msgbox "Port diff files for $ip have been written under:\n  $RUN_DIR/ports\n\nReview the *_ports_diff.txt file for this switch before applying changes." 13 90
    fi
  else
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "Port diff failed" \
        --msgbox "Failed to build port diff for $ip.\n\nCheck logs under:\n  $RUN_DIR/devlogs\n\nAnd outputs under:\n  $RUN_DIR/ports" 14 90
    return 1
  fi
}

apply_port_diff_for_one_switch() {
  load_migrate_context || return 1
  load_meraki_api_key  || return 1

  local ip
  ip="$(pick_switch_ip_from_run)" || return 1

  local diff_file
  diff_file="$(find_latest_ports_diff_for_ip "$ip" || true)"

  if [[ -z "$diff_file" ]]; then
    dlg --backtitle "$BACKTITLE_PORTS" \
        --title "No diff found" \
        --msgbox "Could not find a ports_diff.json file for IP $ip in:\n  $RUN_DIR/ports\n\nRun the \"Build port diff\" option first." 13 90
    return 1
  fi

  apply_ports_from_diff "$ip" "$diff_file"
}

# ============================================================
# Entry point
# ============================================================

show_main_menu() {
  while :; do
    local choice
    choice="$(
      dlg --backtitle "$BACKTITLE_PORTS" \
          --title "IOS port profiles → Meraki" \
          --menu "Select an action." \
          18 80 8 \
          "build-diff" "Parse IOS config + build port diff for one switch" \
          "apply-diff" "Apply most recent diff to Meraki for one switch" \
          "exit"       "Exit this tool"
    )" || return 0

    case "$choice" in
      build-diff) build_port_diff_for_one_switch ;;
      apply-diff) apply_port_diff_for_one_switch ;;
      exit) return 0 ;;
    esac
  done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-menu}"
  shift || true

  case "$cmd" in
    build-diff) build_port_diff_for_one_switch "$@" ;;
    apply-diff) apply_port_diff_for_one_switch "$@" ;;
    menu|*)      show_main_menu ;;
  esac
fi