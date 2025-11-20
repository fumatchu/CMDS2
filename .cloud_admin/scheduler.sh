#!/usr/bin/env bash
# scheduler.sh — dialog scheduler for at_image_upgrade.sh
# Includes a friendly "View scheduled upgrades" browser and consistent status logic.

set -Eeuo pipefail
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need date; need at; need grep; need sed; need cut; need tr; need sort

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit — Scheduler}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
pad2(){ printf '%02d' "$((10#${1:-0}))"; }
pad4(){ printf '%04d' "$((10#${1:-0}))"; }
dlg(){ local _t; _t="$(mktemp)"; dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"; local rc=$?; DOUT=""
       [[ -s "$_t" ]] && DOUT="$(cat "$_t")"; rm -f "$_t"; return $rc; }

view_file(){  # $1=file $2=title
  local f="$1" t="${2:-File}"
  if [[ -s "$f" ]]; then dlg --title "$t" --textbox "$f" 0 0
  else dlg --title "$t" --msgbox "No content found:\n$f" 8 80; fi
}

UPGRADER="$SCRIPT_DIR/at_image_upgrade.sh"

# ---------- Helpers ----------
epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

find_spawned_run_dir(){
  # $1 = job dir
  local d="$1" p
  p="$(awk -F'Run dir:[[:space:]]*' '/Run dir:/ {print $2; exit}' "$d/logs/stdout.log" 2>/dev/null || true)"
  [[ -n "$p" && -d "$p" ]] && { echo "$p"; return; }
  shopt -s nullglob
  for p in "$d"/runs/run-*; do [[ -d "$p" ]] && { echo "$p"; return; }; done
  echo ""
}

# Read a KEY=value from an env snapshot (best-effort)
read_env_kv(){ # $1=file $2=key -> prints value or empty
  local f="$1" k="$2"
  awk -F'=' -v k="$k" '
    $1 ~ "^[[:space:]]*"k"[[:space:]]*$" {
      sub(/^[[:space:]]*/, "", $2); sub(/[[:space:]]*$/, "", $2);
      gsub(/^"|"$/, "", $2); gsub(/^'\''|'\''$/, "", $2);
      print $2; exit
    }' "$f" 2>/dev/null || true
}

# Extract friendly image/version from meraki_discovery.env
# -> "17.15.03 / cat9k_iosxe.17.15.03.SPA.bin, cat9k_lite_iosxe.17.15.03.SPA.bin"
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

# Targets preview from selected_upgrade.env (IPs)
# Show only the first IP; if more, append (+N)
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
  mapfile -t uniq < <(printf '%s\n' "${ips[@]}" | awk -F. '!seen[$0]++ { if ($4 != 0 && $4 != 255) print $0 }' | sort -V)

  local total=${#uniq[@]}
  (( total == 0 )) && { echo "<none>"; return; }

  local first="${uniq[0]}"
  if (( total == 1 )); then
    echo "$first"
  else
    echo "$first (+$((total-1)))"
  fi
}

at_has_job(){ # $1=id -> 0 if present
  atq 2>/dev/null | awk '{print $1}' | grep -qx -- "$1"
}

# ---------- Friendly list ----------
# Prints: jobdir|when|note|image|targets|status|atid
build_jobs_list(){
  local meta dir when note atid img targets status when_ep now spawned
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
      status="Scheduled — done"
    elif [[ -n "$atid" ]] && at_has_job "$atid"; then
      status="Scheduled — pending"
    else
      if (( when_ep > now )); then
        status="Canceled / not queued"
      else
        status="Expired / missed"
      fi
    fi

    printf '%s|%s|%s|%s|%s|%s|%s\n' "$dir" "${when:-<unknown>}" "${note:-<none>}" "$img" "$targets" "$status" "${atid:-}"
  done
}

friendly_jobs_menu(){
  mapfile -t rows < <(build_jobs_list | sort -t'|' -k2)
  if ((${#rows[@]}==0)); then
    dlg --title "Scheduled upgrades" --msgbox "No scheduled upgrades found." 7 60
    return
  fi

  local choices=() r dir when note img targets status atid
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

  # width 240 is fine; reduce if you prefer (e.g., 200)
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

    while true; do
      local items=()
      items+=("sum" "Summary")
      items+=("note" "View note")
      items+=("path" "Show job folder path")
      items+=("sel"  "View selected_upgrade.env")
      items+=("disc" "View meraki_discovery.env")
      if [[ -n "$atid" && "$status" == "Scheduled — pending" ]]; then
        items+=("del"  "Delete from schedule (remove from queue)")
      fi
      items+=("back" "Back")

      dlg --title "$sel" --menu "Choose an action" 16 90 10 "${items[@]}" || break
      case "$DOUT" in
        sum)
          dlg --title "Summary" --msgbox \
"When:    $when
Status:  $status
Image:   $img
Targets: $targets

Note:
$note" 15 90
          ;;
        note)  dlg --title "Job note" --msgbox "${note:-<none>}" 10 70 ;;
        path)  dlg --title "Job folder" --msgbox "$dir" 8 90 ;;
        sel)   view_file "$dir/selected_upgrade.env"  "selected_upgrade.env" ;;
        disc)  view_file "$dir/meraki_discovery.env"  "meraki_discovery.env" ;;
        del)
          dlg --title "Confirm" --yesno "Remove this job from the 'at' queue?\n\nJob ID: ${atid}" 9 72 || continue
          if atrm "$atid" 2>/dev/null; then
            # mark cancellation
            sed -i -e 's/^backend_id=.*/backend_id=/' "$dir/job.meta"
            echo "canceled_local=$(date '+%F %T %Z')" >> "$dir/job.meta"
            : > "$dir/CANCELED"
            dlg --title "Removed" --msgbox "Removed job ${atid} from the queue.\nMarked as canceled:\n$dir" 10 80
            # refresh
            mapfile -t rows < <(build_jobs_list | sort -t'|' -k2)
            choices=()
            for r in "${rows[@]}"; do
              _dir="$(cut -d'|' -f1 <<<"$r")"
              _when="$(cut -d'|' -f2 <<<"$r")"
              _note="$(cut -d'|' -f3 <<<"$r")"
              _img="$(cut -d'|' -f4 <<<"$r")"
              _targets="$(cut -d'|' -f5 <<<"$r")"
              _status="$(cut -d'|' -f6 <<<"$r")"
              tag="$(basename -- "$_dir")"
              line="When: $_when | Status: $_status | Image: $_img | Targets: $_targets | Note: $_note"
              choices+=("$tag" "$line")
            done
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

# ---------- Schedule new ----------
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

Date/time (local):  ${RUN_LOCAL_HUMAN}
Note:               ${NOTE:-<none>}

Env snapshots (from current directory):
  meraki_discovery.env
  selected_upgrade.env
"
  dlg --title "Confirm schedule" --yesno "$summary\nProceed to create the scheduled job?" 18 78 || { clear; exit 0; }

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
ROOT_DIR="$(cd -- "$(dirname "$UPGRADER")" >/dev/null 2>&1 && pwd -P)"; cd "$ROOT_DIR"
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

Run artifacts will appear in:
  ${JOB_DIR}/runs/run-<timestamp>/" 15 78
  clear
}

# ---------- Top-level ----------
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
