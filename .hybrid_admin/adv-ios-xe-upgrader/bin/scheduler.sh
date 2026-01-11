#!/usr/bin/env bash
# scheduler.sh — Schedule-only dialog scheduler for at_image_upgrade.sh (ADV module)
# - NO "view scheduled upgrades" browser (schedule creation only)
# - Assumes project root: /root/.hybrid_admin/adv-ios-xe-upgrader
# - Reads env/json created by discovery from project root
# - Writes job snapshots under project_root/schedules/
# - Schedules via 'at' to run bin/at_image_upgrade.sh later

set -Eeuo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need date; need at; need grep; need sed; need cut; need tr; need sort; need jq

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"

BACKTITLE="${BACKTITLE:-Advanced IOS-XE Image Deployment Module — Scheduler}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
pad2(){ printf '%02d' "$((10#${1:-0}))"; }
pad4(){ printf '%04d' "$((10#${1:-0}))"; }

dlg(){
  local _t rc
  _t="$(mktemp)"
  dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"
  rc=$?
  DOUT=""
  [[ -s "$_t" ]] && DOUT="$(cat "$_t")"
  rm -f "$_t"
  return "$rc"
}

# --- Paths (project-root outputs) ---
DISC_PATH="$PROJECT_ROOT/meraki_discovery.env"
SEL_PATH="$PROJECT_ROOT/selected_upgrade.env"
DISC_JSON="$PROJECT_ROOT/discovery_results.json"

# --- Scheduled runner script (will be moved here) ---
UPGRADER="$SCRIPT_DIR/at_image_upgrade.sh"

# ---------- Discovery gating eligibility ----------
declare -a ELIGIBLE_IPS=()
ELIGIBILITY_BUILT=0

build_eligibility(){
  (( ELIGIBILITY_BUILT == 1 )) && return
  ELIGIBILITY_BUILT=1
  [[ -s "$DISC_JSON" ]] || return
  mapfile -t ELIGIBLE_IPS < <(
    jq -r '.[]
      | select((.ssh // false) == true
               and (.login // false) == true
               and (.blacklisted // false) != true)
      | .ip' "$DISC_JSON" 2>/dev/null | awk 'NF'
  )
}

is_ip_eligible(){
  local ip="$1"
  build_eligibility
  (( ${#ELIGIBLE_IPS[@]} == 0 )) && return 0   # no discovery info → treat all as eligible
  local e
  for e in "${ELIGIBLE_IPS[@]}"; do
    [[ "$e" == "$ip" ]] && return 0
  done
  return 1
}

epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

# Extract friendly image/version from meraki_discovery.env
extract_target_image_from_discovery() {
  local disc="$1" ver="" uni="" lite=""
  [[ -f "$disc" ]] || { echo "unknown"; return; }

  ver="$(awk -F= '/^[[:space:]]*(export[[:space:]]+)?FW_CAT9K_VERSION=/{sub(/^[[:space:]]*export[[:space:]]+FW_CAT9K_VERSION=|^FW_CAT9K_VERSION=/,""); gsub(/^"|"|^\x27|\x27$/,""); print; exit}' "$disc" 2>/dev/null)"
  uni="$(awk -F= '/^[[:space:]]*(export[[:space:]]+)?FW_CAT9K_FILE=/{sub(/^[[:space:]]*export[[:space:]]+FW_CAT9K_FILE=|^FW_CAT9K_FILE=/,""); gsub(/^"|"|^\x27|\x27$/,""); print; exit}' "$disc" 2>/dev/null)"
  lite="$(awk -F= '/^[[:space:]]*(export[[:space:]]+)?FW_CAT9K_LITE_FILE=/{sub(/^[[:space:]]*export[[:space:]]+FW_CAT9K_LITE_FILE=|^FW_CAT9K_LITE_FILE=/,""); gsub(/^"|"|^\x27|\x27$/,""); print; exit}' "$disc" 2>/dev/null)"

  if [[ -n "$ver" || -n "$uni" || -n "$lite" ]]; then
    local parts=()
    [[ -n "$ver"  ]] && parts+=("$ver")
    if [[ -n "$uni" || -n "$lite" ]]; then
      local imgs=""
      [[ -n "$uni"  ]] && imgs+="$uni"
      [[ -n "$uni" && -n "$lite" ]] && imgs+=", "
      [[ -n "$lite" ]] && imgs+="$lite"
      parts+=("/ $imgs")
    fi
    printf '%s\n' "${parts[*]}"
  else
    echo "unknown"
  fi
}

# Targets preview from selected_upgrade.env (IPs) with discovery gating.
extract_targets_preview(){
  local sel="$1"
  [[ -f "$sel" ]] || { echo "<none>"; return; }

  mapfile -t ips < <(
    awk -F'=' 'BEGIN{IGNORECASE=1}
      $1 ~ /(select|target|upgrade|hosts?|ips?)/ {
        v=$2
        gsub(/^ *"/,"",v); gsub(/" *$/,"",v)
        gsub(/^ *'\''/,"",v); gsub(/'\'' *$/,"",v)
        print v
      }' "$sel" 2>/dev/null \
    | tr ',;' ' ' \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}'
  )
  if ((${#ips[@]}==0)); then echo "<none>"; return; fi

  mapfile -t uniq < <(
    printf '%s\n' "${ips[@]}" \
      | awk -F. '!seen[$0]++ { if ($4 != 0 && $4 != 255) print $0 }' \
      | sort -V
  )

  local total=${#uniq[@]}
  (( total == 0 )) && { echo "<none>"; return; }

  build_eligibility
  local eligible=() ip
  for ip in "${uniq[@]}"; do
    if is_ip_eligible "$ip"; then
      eligible+=("$ip")
    fi
  done

  local etotal=${#eligible[@]}
  if (( etotal == 0 )); then
    echo "<none (0 eligible by discovery)>"
    return
  fi

  local first="${eligible[0]}"
  if (( etotal == 1 )); then
    echo "$first"
  else
    echo "$first (+$((etotal-1)))"
  fi
}

# ---------- Schedule new (only action) ----------
schedule_new(){
  if [[ ! -x "$UPGRADER" ]]; then
    dlg --title "Missing scheduled runner" --msgbox \
"at_image_upgrade.sh is not found or not executable:

  $UPGRADER

Move it into:
  $SCRIPT_DIR

and chmod +x it." 14 80
    clear; exit 1
  fi

  if [[ ! -f "$DISC_PATH" || ! -f "$SEL_PATH" ]]; then
    dlg --title "Missing prerequisites" --msgbox \
"Required files not found in project root:

  - $DISC_PATH
  - $SEL_PATH

Run Setup Wizard and Discovery first." 12 78
    clear; exit 1
  fi

  local TARGETS_PREVIEW
  TARGETS_PREVIEW="$(extract_targets_preview "$SEL_PATH")"
  if [[ "$TARGETS_PREVIEW" == "<none>" || "$TARGETS_PREVIEW" == "<none (0 eligible by discovery)>" ]]; then
    dlg --title "No eligible targets" --msgbox \
"selected_upgrade.env contains no eligible targets after applying discovery gating.

Discovery eligibility requires:
  - ssh=true
  - login=true
  - blacklisted!=true

Fix discovery/selection and try again." 15 80
    clear; exit 1
  fi

  local IMG_PREVIEW
  IMG_PREVIEW="$(extract_target_image_from_discovery "$DISC_PATH")"

  local NOTE=""
  dlg --title "Optional note" --inputbox "Enter an optional note (ticket/window/etc.)." 8 72
  [[ $? -eq 0 ]] && NOTE="$(trim "${DOUT:-}")"

  local today_y today_m today_d
  today_y="$(date +%Y)"; today_m="$(date +%m)"; today_d="$(date +%d)"
  dlg --title "Run date" --calendar "Select the date for the deployment" 0 0 "$today_d" "$today_m" "$today_y" \
    || { clear; exit 1; }
  IFS='/' read -r DD MM YYYY <<<"$(trim "${DOUT:-}")"
  YYYY="$(pad4 "$YYYY")"; MM="$(pad2 "$MM")"; DD="$(pad2 "$DD")"

  local default_time="02:00 AM"
  dlg --title "Run time (12-hour)" --inputbox \
"Enter time as:  HH:MM AM/PM

Examples:
  2:30 am
  11:05 PM
  12:00 pm" 12 48 "$default_time" || { clear; exit 1; }

  local time_raw canon HH12 MIN AMPM HH24 SS
  time_raw="$(trim "${DOUT:-}")"
  canon="$(printf '%s' "$time_raw" | tr '[:lower:]' '[:upper:]' | sed 's/\./:/g; s/[^0-9APM: ]//g')"
  if [[ ! "$canon" =~ ^[[:space:]]*([0-1]?[0-9])[[:space:]]*:[[:space:]]*([0-5][0-9])[[:space:]]*(AM|PM)[[:space:]]*$ ]]; then
    dlg --title "Invalid time" --msgbox "Use format: HH:MM AM/PM (e.g., 02:30 PM)" 8 50
    clear; exit 1
  fi
  HH12="${BASH_REMATCH[1]}"; MIN="${BASH_REMATCH[2]}"; AMPM="${BASH_REMATCH[3]}"
  (( 10#$HH12 < 1 || 10#$HH12 > 12 )) && { dlg --title "Invalid hour" --msgbox "Hour must be 1..12." 7 40; clear; exit 1; }
  HH12="$(pad2 "$HH12")"; MIN="$(pad2 "$MIN")"
  HH24="$HH12"; [[ "$AMPM" == "AM" ]] && [[ "$HH12" == "12" ]] && HH24="00"
  [[ "$AMPM" == "PM" ]] && [[ "$HH12" != "12" ]] && HH24="$(pad2 "$((10#$HH12 + 12))")"
  SS="00"

  local sel_iso="${YYYY}-${MM}-${DD} ${HH24}:${MIN}:${SS}"
  local sel_ts now_ts
  sel_ts="$(date -d "$sel_iso" +%s)" || true
  now_ts="$(date +%s)"
  [[ -z "${sel_ts:-}" ]] && { dlg --title "Error" --msgbox "Could not parse selected datetime: $sel_iso" 8 70; clear; exit 1; }
  (( sel_ts <= now_ts )) && {
    dlg --title "Time is in the past" --msgbox "Please pick a later time.\n\nSelected: $(date -d "$sel_iso")\nNow: $(date)" 10 70
    clear; exit 1; }

  local RUN_LOCAL_HUMAN AT_TSTAMP
  RUN_LOCAL_HUMAN="$(date -d "$sel_iso" '+%a %b %d, %Y  %I:%M:%S %p %Z')"
  AT_TSTAMP="${YYYY}${MM}${DD}${HH24}${MIN}.${SS}"

  local summary="Schedule summary

Date/time (local):       ${RUN_LOCAL_HUMAN}
Targets (by discovery):  ${TARGETS_PREVIEW}
Image:                   ${IMG_PREVIEW}
Note:                    ${NOTE:-<none>}

This will snapshot:
  $DISC_PATH
  $SEL_PATH
"
  dlg --title "Confirm schedule" --yesno "$summary\nProceed to create the scheduled job?" 22 78 || { clear; exit 0; }

  local JOB_ID="job-${YYYY}${MM}${DD}-${HH24}${MIN}${SS}-$RANDOM"
  local JOB_DIR="$PROJECT_ROOT/schedules/$JOB_ID"
  mkdir -p "$JOB_DIR" "$JOB_DIR/runs" "$JOB_DIR/logs"

  cp -f -- "$DISC_PATH" "$JOB_DIR/meraki_discovery.env"
  cp -f -- "$SEL_PATH"  "$JOB_DIR/selected_upgrade.env"
  chmod 600 "$JOB_DIR/meraki_discovery.env" "$JOB_DIR/selected_upgrade.env"
  chmod 700 "$JOB_DIR"

  cat > "$JOB_DIR/job.sh" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
THIS_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# Project root is two levels up: schedules/job-xxx/
PROJECT_ROOT="$(cd -- "$THIS_DIR/../.." >/dev/null 2>&1 && pwd -P)"
UPGRADER="$PROJECT_ROOT/bin/at_image_upgrade.sh"
[[ -x "$UPGRADER" ]] || { echo "[FATAL] $UPGRADER not found or not executable" >&2; exit 1; }

cd "$PROJECT_ROOT"
export RUN_ROOT="$THIS_DIR/runs"
export BASE_ENV="$THIS_DIR/meraki_discovery.env"
SEL_ENV_FILE="$THIS_DIR/selected_upgrade.env"

mkdir -p "$THIS_DIR/logs" "$THIS_DIR/runs"
bash "$UPGRADER" "$SEL_ENV_FILE" >>"$THIS_DIR/logs/stdout.log" 2>>"$THIS_DIR/logs/stderr.log"
EOS
  chmod +x "$JOB_DIR/job.sh"

  {
    echo "job_id=$JOB_ID"
    echo "created_utc=$(date -u '+%F %T')"
    echo "scheduled_local=${RUN_LOCAL_HUMAN}"
    echo "note=$(printf '%s' "$NOTE" | tr '\n' ' ')"
    echo "backend=at"
    echo "backend_id="
  } > "$JOB_DIR/job.meta"

  cat > "$JOB_DIR/at.payload.sh" <<EOF
#!/bin/sh
exec /usr/bin/env bash "$JOB_DIR/job.sh"
EOF
  chmod +x "$JOB_DIR/at.payload.sh"

  local SUBMIT_OUT AT_JOB
  SUBMIT_OUT="$(at -t "$AT_TSTAMP" -f "$JOB_DIR/at.payload.sh" 2>&1)" || {
    dlg --title "Schedule error" --msgbox "Failed to submit job to 'at':\n\n$SUBMIT_OUT" 14 78
    clear; exit 1
  }
  AT_JOB="$(printf '%s\n' "$SUBMIT_OUT" | awk '/job/ {print $2; exit}')"
  [[ -z "$AT_JOB" ]] && AT_JOB="unknown"
  sed -i -e "s/^backend_id=.*/backend_id=${AT_JOB}/" "$JOB_DIR/job.meta"

  dlg --title "Scheduled" --msgbox \
"Scheduled with 'at' (job ${AT_JOB}).

When:   ${RUN_LOCAL_HUMAN}
Folder: ${JOB_DIR}

Logs:
  ${JOB_DIR}/logs/stdout.log
  ${JOB_DIR}/logs/stderr.log" 16 78

  clear
}

# --- run schedule-only ---
schedule_new