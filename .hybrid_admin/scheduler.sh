#!/usr/bin/env bash
# scheduler.sh — dialog scheduler for at_image_upgrade.sh (CLI headless upgrader)
# - Calendar -> US date (DD/MM/YYYY from dialog calendar parsed to YYYY-MM-DD)
# - Time: single input line like "02:40 AM" (case/spacing tolerant)
# - DST-safe local comparison, then schedule via `at -t`

set -Eeuo pipefail
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need date; need at

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit — Scheduler}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
pad2(){ printf '%02d' "$((10#${1:-0}))"; }
pad4(){ printf '%04d' "$((10#${1:-0}))"; }

dlg(){ local _t; _t="$(mktemp)"; dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"; local rc=$?; DOUT=""
       [[ -s "$_t" ]] && DOUT="$(cat "$_t")"; rm -f "$_t"; return $rc; }

# fixed runner name
UPGRADER="$SCRIPT_DIR/at_image_upgrade.sh"
if [[ ! -x "$UPGRADER" ]]; then
  dlg --title "Error" --msgbox "at_image_upgrade.sh not found or not executable in:\n$SCRIPT_DIR" 9 80
  clear; exit 1
fi

DISC_PATH="$SCRIPT_DIR/meraki_discovery.env"
SEL_PATH="$SCRIPT_DIR/selected_upgrade.env"
if [[ ! -f "$DISC_PATH" || ! -f "$SEL_PATH" ]]; then
  dlg --title "Missing prerequisites" --msgbox \
"Required files not found:

  - $DISC_PATH
  - $SEL_PATH

Run Setup Wizard and Discovery/Selection first." 12 74
  clear; exit 1
fi

# Optional note
NOTE=""
dlg --title "Optional note" --inputbox "Enter an optional note (ticket/window/etc.)." 8 72
[[ $? -eq 0 ]] && NOTE="$(trim "${DOUT:-}")"

# -------- Date (dialog calendar returns DD/MM/YYYY) -> US order --------
today_y="$(date +%Y)"; today_m="$(date +%m)"; today_d="$(date +%d)"
dlg --title "Run date" --calendar "Select the date for the deployment" 0 0 "$today_d" "$today_m" "$today_y" \
  || { clear; exit 1; }
IFS='/' read -r DD MM YYYY <<<"$(trim "${DOUT:-}")"
YYYY="$(pad4 "$YYYY")"; MM="$(pad2 "$MM")"; DD="$(pad2 "$DD")"

# -------- Time (single line, text: 'HH:MM AM/PM') --------
default_time="02:00 AM"
dlg --title "Run time (12-hour)" --inputbox \
"Enter time as:  HH:MM AM/PM

Examples:
  2:30 am
  11:05 PM
  12:00 pm" 12 48 "$default_time" || { clear; exit 1; }
time_raw="$(trim "${DOUT:-}")"

# normalize and validate (case/spacing tolerant)
# Accept 'H:MM AM', 'HH:MM PM', also '.' instead of ':' and extra spaces
canon="$(printf '%s' "$time_raw" | tr '[:lower:]' '[:upper:]' | sed 's/\./:/g; s/[^0-9APM: ]//g')"

if [[ ! "$canon" =~ ^[[:space:]]*([0-1]?[0-9])[[:space:]]*:[[:space:]]*([0-5][0-9])[[:space:]]*(AM|PM)[[:space:]]*$ ]]; then
  dlg --title "Invalid time" --msgbox "Use format: HH:MM AM/PM (e.g., 02:30 PM)" 8 50
  clear; exit 1
fi

HH12="${BASH_REMATCH[1]}"; MIN="${BASH_REMATCH[2]}"; AMPM="${BASH_REMATCH[3]}"
# range check hour 1..12
if (( 10#$HH12 < 1 || 10#$HH12 > 12 )); then
  dlg --title "Invalid hour" --msgbox "Hour must be 1..12." 7 40; clear; exit 1
fi
HH12="$(pad2 "$HH12")"; MIN="$(pad2 "$MIN")"

# convert to 24h
HH24="$HH12"
if [[ "$AMPM" == "AM" ]]; then
  [[ "$HH12" == "12" ]] && HH24="00"
else # PM
  [[ "$HH12" != "12" ]] && HH24="$(pad2 "$((10#$HH12 + 12))")"
fi
SS="00"

# -------- Build timestamp + DST-safe past check --------
sel_iso="${YYYY}-${MM}-${DD} ${HH24}:${MIN}:${SS}"
sel_ts="$(date -d "$sel_iso" +%s)" || true
now_ts="$(date +%s)"
if [[ -z "${sel_ts:-}" ]]; then
  dlg --title "Error" --msgbox "Could not parse selected datetime: $sel_iso" 8 70; clear; exit 1; fi
if (( sel_ts <= now_ts )); then
  now_human="$(date '+%F %T %Z')"
  sel_human="$(date -d "$sel_iso" '+%F %T %Z')"
  dlg --title "Time is in the past" --msgbox \
"That selection resolves to the past.

Selected (local):  ${sel_human}
Now (local):       ${now_human}

Please pick a later time." 12 72
  clear; exit 1
fi

RUN_LOCAL_HUMAN="$(date -d "$sel_iso" '+%a %b %d, %Y  %I:%M:%S %p %Z')"
AT_TSTAMP="${YYYY}${MM}${DD}${HH24}${MIN}.${SS}"

# -------- Confirm --------
summary="Schedule summary

Date/time (local):  ${RUN_LOCAL_HUMAN}
Note:               ${NOTE:-<none>}

Env snapshots (from current directory):
  meraki_discovery.env
  selected_upgrade.env
"
dlg --title "Confirm schedule" --yesno "$summary\nProceed to create the scheduled job?" 18 78 \
  || { clear; exit 0; }

# -------- Create job folder + files --------
JOB_ID="job-${YYYY}${MM}${DD}-${HH24}${MIN}${SS}-$RANDOM"
JOB_DIR="$SCRIPT_DIR/schedules/$JOB_ID"
mkdir -p "$JOB_DIR" "$JOB_DIR/runs" "$JOB_DIR/logs"

cp -f -- "$DISC_PATH" "$JOB_DIR/meraki_discovery.env"
cp -f -- "$SEL_PATH"  "$JOB_DIR/selected_upgrade.env"
chmod 600 "$JOB_DIR/meraki_discovery.env" "$JOB_DIR/selected_upgrade.env"
chmod 700 "$JOB_DIR"

# Runner script (stays fixed to at_image_upgrade.sh)
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

# Metadata
{
  echo "job_id=$JOB_ID"
  echo "created_utc=$(date -u '+%F %T')"
  echo "scheduled_local=${RUN_LOCAL_HUMAN}"
  echo "note=$(printf '%s' "$NOTE" | tr '\n' ' ')"
  echo "backend=at"
  echo "backend_id="
} > "$JOB_DIR/job.meta"

# at wrapper
cat > "$JOB_DIR/at.payload.sh" <<EOF
#!/bin/sh
exec /usr/bin/env bash "$JOB_DIR/job.sh"
EOF
chmod +x "$JOB_DIR/at.payload.sh"

# Submit
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
exit 0
