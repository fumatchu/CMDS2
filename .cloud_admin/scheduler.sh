#!/usr/bin/env bash
# scheduler.sh — dialog scheduler for at_image_upgrade.sh
# Includes a friendly "View scheduled upgrades" browser and consistent status logic.

set -Eeuo pipefail
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need date; need at; need grep; need sed; need cut; need tr; need sort; need jq

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit — Scheduler}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
pad2(){ printf '%02d' "$((10#${1:-0}))"; }
pad4(){ printf '%04d' "$((10#${1:-0}))"; }
dlg(){ local _t; _t="$(mktemp)"; dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"; local rc=$?; DOUT=""
       [[ -s "$_t" ]] && DOUT="$(cat "$_t")"; rm -f "$_t"; return $rc; }

view_file(){
  local f="$1" t="${2:-File}"
  if [[ -s "$f" ]]; then dlg --title "$t" --textbox "$f" 0 0
  else dlg --title "$t" --msgbox "No content found:\n$f" 8 80; fi
}

UPGRADER="$SCRIPT_DIR/at_image_upgrade.sh"

DISC_JSON="$SCRIPT_DIR/discovery_results.json"
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
  (( ${#ELIGIBLE_IPS[@]} == 0 )) && return 0
  local e
  for e in "${ELIGIBLE_IPS[@]}"; do [[ "$e" == "$ip" ]] && return 0; done
  return 1
}

epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

find_spawned_run_dir(){
  local d="$1" p
  p="$(awk -F'Run dir:[[:space:]]*' '/Run dir:/ {print $2; exit}' "$d/logs/stdout.log" 2>/dev/null || true)"
  [[ -n "$p" && -d "$p" ]] && { echo "$p"; return; }

  shopt -s nullglob
  for p in "$d"/runs/run-*; do [[ -d "$p" ]] && { echo "$p"; return; }; done
  echo ""
}

at_has_job(){ atq 2>/dev/null | awk '{print $1}' | grep -qx -- "$1"; }

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
    if is_ip_eligible "$ip"; then eligible+=("$ip"); fi
  done

  local etotal=${#eligible[@]}
  if (( etotal == 0 )); then echo "<none (0 eligible by discovery)>"; return; fi

  local first="${eligible[0]}"
  (( etotal == 1 )) && echo "$first" || echo "$first (+$((etotal-1)))"
}

# ---- NEW: run status from markers in spawned run dir ----
run_dir_status(){
  local run="$1"
  [[ -z "$run" || ! -d "$run" ]] && { echo ""; return; }
  if [[ -f "$run/RUNNING" ]]; then echo "running"; return; fi
  if [[ -f "$run/DONE" ]]; then echo "done"; return; fi
  echo "unknown"
}

run_dir_exit_code(){
  local run="$1"
  [[ -f "$run/EXIT_CODE" ]] && cat "$run/EXIT_CODE" 2>/dev/null || true
}

# Prints: jobdir|when|note|image|targets|status|atid|run_dir
build_jobs_list(){
  local meta dir when note atid img targets status when_ep now spawned rstat rc
  now="$(date +%s)"
  shopt -s nullglob
  for meta in "$SCRIPT_DIR"/schedules/job-*/job.meta; do
    dir="$(dirname -- "$meta")"
    when="$(awk -F= '/^scheduled_local=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
    note="$(awk -F= '/^note=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
    atid="$(awk -F= '/^backend_id=/{print $2}' "$meta" 2>/dev/null || true)"

    img="$(extract_target_image_from_discovery "$dir/meraki_discovery.env")"
    targets="$(extract_targets_preview "$dir/selected_upgrade.env")"

    spawned="$(find_spawned_run_dir "$dir")"
    when_ep="$(epoch_from_human "$when")"

    if [[ -n "$spawned" ]]; then
      rstat="$(run_dir_status "$spawned")"
      case "$rstat" in
        running) status="Scheduled — running" ;;
        done)
          rc="$(run_dir_exit_code "$spawned")"
          [[ -n "$rc" ]] && status="Scheduled — done (rc=$rc)" || status="Scheduled — done"
          ;;
        *) status="Scheduled — started (state unknown)" ;;
      esac
    elif [[ -n "$atid" ]] && at_has_job "$atid"; then
      status="Scheduled — pending"
    else
      if (( when_ep > now )); then status="Canceled / not queued"
      else status="Expired / missed"; fi
    fi

    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "$dir" "${when:-<unknown>}" "${note:-<none>}" "$img" "$targets" "$status" "${atid:-}" "${spawned:-}"
  done
}

friendly_jobs_menu(){
  mapfile -t rows < <(build_jobs_list | sort -t'|' -k2)
  if ((${#rows[@]}==0)); then
    dlg --title "Scheduled upgrades" --msgbox "No scheduled upgrades found." 7 60
    return
  fi

  local choices=() r dir when note img targets status atid run_dir
  for r in "${rows[@]}"; do
    dir="$(cut -d'|' -f1 <<<"$r")"
    when="$(cut -d'|' -f2 <<<"$r")"
    note="$(cut -d'|' -f3 <<<"$r")"
    img="$(cut -d'|' -f4 <<<"$r")"
    targets="$(cut -d'|' -f5 <<<"$r")"
    status="$(cut -d'|' -f6 <<<"$r")"
    atid="$(cut -d'|' -f7 <<<"$r")"
    local tag; tag="$(basename -- "$dir")"
    local line="When: $when | Status: $status | Image: $img | Targets: $targets | Note: $note"
    choices+=("$tag" "$line")
  done

  while true; do
    dlg --title "Scheduled upgrades" --menu "Select a scheduled job" 20 240 10 "${choices[@]}" || return
    local sel="$DOUT" chosen=""
    for r in "${rows[@]}"; do
      [[ "$(basename -- "$(cut -d'|' -f1 <<<"$r")")" == "$sel" ]] && { chosen="$r"; break; }
    done
    [[ -z "$chosen" ]] && return

    dir="$(cut -d'|' -f1 <<<"$chosen")"
    when="$(cut -d'|' -f2 <<<"$chosen")"
    note="$(cut -d'|' -f3 <<<"$chosen")"
    img="$(cut -d'|' -f4 <<<"$chosen")"
    targets="$(cut -d'|' -f5 <<<"$chosen")"
    status="$(cut -d'|' -f6 <<<"$chosen")"
    atid="$(cut -d'|' -f7 <<<"$chosen")"
    run_dir="$(cut -d'|' -f8 <<<"$chosen")"

    while true; do
      local items=()
      items+=("sum" "Summary")
      items+=("note" "View note")
      items+=("path" "Show job folder path")
      items+=("sel"  "View selected_upgrade.env")
      items+=("disc" "View meraki_discovery.env")
      if [[ -n "$run_dir" && -d "$run_dir" ]]; then
        items+=("run"  "Open spawned run dir (ui.status)")
      fi
      if [[ -n "$atid" && "$status" == "Scheduled — pending" ]]; then
        items+=("del"  "Delete from schedule (remove from queue)")
      fi
      items+=("back" "Back")

      dlg --title "$sel" --menu "Choose an action" 18 95 11 "${items[@]}" || break
      case "$DOUT" in
        sum)
          dlg --title "Summary" --msgbox \
"When:    $when
Status:  $status
Image:   $img
Targets: $targets
Run dir: ${run_dir:-<not started>}

Note:
$note" 17 95
          ;;
        note)  dlg --title "Job note" --msgbox "${note:-<none>}" 10 70 ;;
        path)  dlg --title "Job folder" --msgbox "$dir" 8 90 ;;
        sel)   view_file "$dir/selected_upgrade.env"  "selected_upgrade.env" ;;
        disc)  view_file "$dir/meraki_discovery.env"  "meraki_discovery.env" ;;
        run)   view_file "$run_dir/ui.status" "ui.status (live)" ;;
        del)
          dlg --title "Confirm" --yesno "Remove this job from the 'at' queue?\n\nJob ID: ${atid}" 9 72 || continue
          if atrm "$atid" 2>/dev/null; then
            sed -i -e 's/^backend_id=.*/backend_id=/' "$dir/job.meta"
            echo "canceled_local=$(date '+%F %T %Z')" >> "$dir/job.meta"
            : > "$dir/CANCELED"
            dlg --title "Removed" --msgbox "Removed job ${atid} from the queue.\nMarked as canceled:\n$dir" 10 80
            mapfile -t rows < <(build_jobs_list | sort -t'|' -k2)
            break
          else
            dlg --title "Error" --msgbox "Failed to remove job ${atid}.\n(It may already be gone.)" 8 70
          fi
          ;;
        back) break ;;
      esac
    done
  done
}

schedule_new(){
  if [[ ! -x "$UPGRADER" ]]; then
    dlg --title "Error" --msgbox "at_image_upgrade.sh not found or not executable in:\n$SCRIPT_DIR" 9 80
    clear; exit 1
  fi

  local DISC_PATH="$SCRIPT_DIR/meraki_discovery.env"
  local SEL_PATH="$SCRIPT_DIR/selected_upgrade.env"
  if [[ ! -f "$DISC_PATH" || ! -f "$SEL_PATH" ]]; then
    dlg --title "Missing prerequisites" --msgbox \
"Required files not found:

  - $DISC_PATH
  - $SEL_PATH

Run Setup Wizard and Discovery/Selection first." 12 74
    clear; exit 1
  fi

  local TARGETS_PREVIEW
  TARGETS_PREVIEW="$(extract_targets_preview "$SEL_PATH")"
  if [[ "$TARGETS_PREVIEW" == "<none>" || "$TARGETS_PREVIEW" == "<none (0 eligible by discovery)>" ]]; then
    dlg --title "No eligible targets" --msgbox \
"selected_upgrade.env contains no eligible targets after applying discovery gating.

Discovery requires:
  - ssh=true
  - login=true
  - blacklisted!=true" 12 80
    clear; exit 1
  fi

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
"Enter time as:  HH:MM AM/PM" 10 48 "$default_time" || { clear; exit 1; }
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
  (( sel_ts <= now_ts )) && { dlg --title "Time is in the past" --msgbox "Pick a later time." 7 40; clear; exit 1; }

  local RUN_LOCAL_HUMAN AT_TSTAMP
  RUN_LOCAL_HUMAN="$(date -d "$sel_iso" '+%a %b %d, %Y  %I:%M:%S %p %Z')"
  AT_TSTAMP="${YYYY}${MM}${DD}${HH24}${MIN}.${SS}"

  dlg --title "Confirm schedule" --yesno \
"Date/time (local):       ${RUN_LOCAL_HUMAN}
Targets (by discovery):  ${TARGETS_PREVIEW}
Note:                    ${NOTE:-<none>}

Proceed to create the scheduled job?" 16 78 || { clear; exit 0; }

  local JOB_ID="job-${YYYY}${MM}${DD}-${HH24}${MIN}${SS}-$RANDOM"
  local JOB_DIR="$SCRIPT_DIR/schedules/$JOB_ID"
  mkdir -p "$JOB_DIR" "$JOB_DIR/runs" "$JOB_DIR/logs"

  cp -f -- "$DISC_PATH" "$JOB_DIR/meraki_discovery.env"
  cp -f -- "$SEL_PATH"  "$JOB_DIR/selected_upgrade.env"
  chmod 600 "$JOB_DIR/meraki_discovery.env" "$JOB_DIR/selected_upgrade.env"
  chmod 700 "$JOB_DIR"

  cat > "$JOB_DIR/job.sh" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
THIS_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

CANDIDATES=(
  "$THIS_DIR/../../at_image_upgrade.sh"
  "$THIS_DIR/../at_image_upgrade.sh"
  "$THIS_DIR/at_image_upgrade.sh"
)
UPGRADER=""
for c in "${CANDIDATES[@]}"; do [[ -x "$c" ]] && { UPGRADER="$c"; break; }; done
if [[ -z "$UPGRADER" ]]; then echo "[FATAL] at_image_upgrade.sh not found" >&2; exit 1; fi

ROOT_DIR="$(cd -- "$(dirname "$UPGRADER")" >/dev/null 2>&1 && pwd -P)"
cd "$ROOT_DIR"

export RUN_ROOT="$THIS_DIR/runs"
export BASE_ENV="$THIS_DIR/meraki_discovery.env"
SEL_ENV_FILE="$THIS_DIR/selected_upgrade.env"

mkdir -p "$THIS_DIR/logs" "$THIS_DIR/runs"

# Wrapper markers (job-level)
echo "$$" > "$THIS_DIR/JOB_RUNNING" 2>/dev/null || true
rm -f "$THIS_DIR/JOB_DONE" 2>/dev/null || true

rc=0
bash "$UPGRADER" "$SEL_ENV_FILE" >>"$THIS_DIR/logs/stdout.log" 2>>"$THIS_DIR/logs/stderr.log" || rc=$?

rm -f "$THIS_DIR/JOB_RUNNING" 2>/dev/null || true
echo "$rc" > "$THIS_DIR/JOB_EXIT_CODE" 2>/dev/null || true
date -u '+%F %T' > "$THIS_DIR/JOB_DONE" 2>/dev/null || true
exit "$rc"
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

Run artifacts will appear in:
  ${JOB_DIR}/runs/run-<timestamp>/" 15 78
  clear
}

while true; do
  dlg --title "IOS-XE Upgrade Scheduler" --menu "Choose an option:" 12 72 6 \
    1 "Schedule new IOS-XE upgrade" \
    2 "View scheduled upgrades" \
    0 "Exit" || { clear; exit 0; }
  case "$DOUT" in
    1) schedule_new ;;
    2) friendly_jobs_menu ;;
    0) clear; exit 0 ;;
  esac
done