#!/usr/bin/env bash
# scheduler.sh
# Dialog-based scheduler for at_image_upgrade.sh using 'at'
# Creates a per-schedule folder with env snapshots + wrapper + metadata.

set -Eeuo pipefail

# -------------------- requirements --------------------
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need awk
need date
need at

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

# Backtitle (can be overridden by env)
BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit — Scheduler}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

# --------------- dialog helpers ---------------
DOUT=""
dlg() {
  local _tmp; _tmp="$(mktemp)"
  dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_tmp"
  local rc=$?; DOUT=""
  [[ -s "$_tmp" ]] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $rc
}
trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# ---- Headless upgrader (no dialog) ----
UPGRADER="$SCRIPT_DIR/at_image_upgrade.sh"
if [[ ! -x "$UPGRADER" ]]; then
  dlg --title "Error" --msgbox "at_image_upgrade.sh not found or not executable in:\n$SCRIPT_DIR" 9 80
  clear; exit 1
fi

# Expected env files
DISC_PATH="$SCRIPT_DIR/meraki_discovery.env"
SEL_PATH="$SCRIPT_DIR/selected_upgrade.env"

# If either env file is missing, instruct the user to run prerequisites.
if [[ ! -f "$DISC_PATH" || ! -f "$SEL_PATH" ]]; then
  dlg --title "Missing prerequisites" --msgbox \
"Required files not found:

  - $DISC_PATH
  - $SEL_PATH

Please run:
  • Setup Wizard (to generate meraki_discovery.env)
  • Switch Discovery/Selection (to generate selected_upgrade.env)

Return to the main menu and complete those steps before scheduling." 16 78
  clear; exit 1
fi

# ---------- base-10 safe helpers (avoid octal pitfalls like 08/09) ----------
to10() { printf '%d' "$((10#${1:-0}))"; }
pad2() { printf '%02d' "$((10#${1:-0}))"; }
pad4() { printf '%04d' "$((10#${1:-0}))"; }

# --------------- optional note ---------------
NOTE=""
dlg --title "Optional note" --inputbox \
"Enter an optional note to store with the schedule (ticket #, window, etc.)." 9 72
[[ $? -eq 0 ]] && NOTE="$(trim "${DOUT:-}")"

# --------------- select date/time ---------------
today_y="$(date +%Y)"; today_m="$(date +%m)"; today_d="$(date +%d)"
dlg --title "Run date" --calendar "Select the date for the deployment" 0 0 "$today_d" "$today_m" "$today_y" \
  || { clear; exit 1; }
cal_raw="$(trim "${DOUT:-}")"

IFS='/' read -r A B C <<<"$cal_raw"
if [[ -z "$A" || -z "$B" || -z "$C" ]]; then
  dlg --title "Error" --msgbox "Could not parse date from dialog: '$cal_raw'" 8 70; clear; exit 1
fi
# dialog --calendar can be DD/MM/YYYY or MM/DD/YYYY depending on locale
if [[ "$(to10 "$A")" -gt 12 ]]; then
  DD="$A"; MM="$B"; YYYY="$C"
else
  MM="$A"; DD="$B"; YYYY="$C"
fi

HH="02"; MIN="00"; SS="00"
if dialog --help 2>&1 | grep -q -- '--timebox'; then
  dlg --title "Run time (24h)" --timebox "Select the time for the deployment" 0 0 "$HH" "$MIN" "$SS" \
    || { clear; exit 1; }
  IFS=':' read -r HH MIN SS <<<"$(trim "${DOUT:-}")"
else
  dlg --title "Run time" --inputbox "Enter time (24h, HH:MM)" 8 40 "02:00" || { clear; exit 1; }
  time_raw="$(trim "${DOUT:-}")"
  HH="$(printf '%s' "$time_raw" | awk -F: '{print $1}')"
  MIN="$(printf '%s' "$time_raw" | awk -F: '{print $2}')"
  SS="00"
fi

# Coerce to base-10 and zero-pad safely
YYYY="$(pad4 "$YYYY")"; MM="$(pad2 "$MM")"; DD="$(pad2 "$DD")"
HH="$(pad2 "$HH")"; MIN="$(pad2 "$MIN")"; SS="$(pad2 "$SS")"

# Validate the assembled timestamp (local time)
if ! date -d "${YYYY}-${MM}-${DD} ${HH}:${MIN}:${SS}" >/dev/null 2>&1; then
  dlg --title "Error" --msgbox "Invalid date/time selected." 8 50; clear; exit 1
fi

RUN_LOCAL_HUMAN="$(date -d "${YYYY}-${MM}-${DD} ${HH}:${MIN}:${SS}" '+%F %T %Z')"
AT_TSTAMP="${YYYY}${MM}${DD}${HH}${MIN}.${SS}"

# --------------- confirm ---------------
summary="Schedule summary

Date/time (local):  ${RUN_LOCAL_HUMAN}
Note:               ${NOTE:-<none>}

Env snapshots (from current directory):
  meraki_discovery.env
  selected_upgrade.env
"
dlg --title "Confirm schedule" --yesno "$summary\nProceed to create the scheduled job?" 20 78 \
  || { clear; exit 1; }

# --------------- create job folder + files ---------------
JOB_ID="job-${YYYY}${MM}${DD}-${HH}${MIN}${SS}-$RANDOM"
JOB_DIR="$SCRIPT_DIR/schedules/$JOB_ID"
mkdir -p "$JOB_DIR" "$JOB_DIR/runs" "$JOB_DIR/logs"

# Always copy fresh snapshots for each schedule
cp -f -- "$DISC_PATH" "$JOB_DIR/meraki_discovery.env"
cp -f -- "$SEL_PATH"  "$JOB_DIR/selected_upgrade.env"
chmod 600 "$JOB_DIR/meraki_discovery.env" "$JOB_DIR/selected_upgrade.env"
chmod 700 "$JOB_DIR"

# -------- FIXED job runner: search at_image_upgrade.sh relative to schedule --------
cat > "$JOB_DIR/job.sh" <<'EOS'
#!/usr/bin/env bash
set -Eeuo pipefail
THIS_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

# Prefer repo root two levels up from schedules/<job>/ (i.e., .../.hybrid_admin)
CANDIDATES=(
  "$THIS_DIR/../../at_image_upgrade.sh"
  "$THIS_DIR/../at_image_upgrade.sh"
  "$THIS_DIR/at_image_upgrade.sh"
)

UPGRADER=""
for c in "${CANDIDATES[@]}"; do
  if [[ -x "$c" ]]; then UPGRADER="$c"; break; fi
done

if [[ -z "$UPGRADER" ]]; then
  echo "[FATAL] at_image_upgrade.sh not found relative to $THIS_DIR" >&2
  exit 1
fi

# Directory that contains the upgrader (repo root)
ROOT_DIR="$(cd -- "$(dirname "$UPGRADER")" >/dev/null 2>&1 && pwd -P)"
cd "$ROOT_DIR"

# Point all run artifacts under this schedule's folder
export RUN_ROOT="$THIS_DIR/runs"

# Use the snapshot envs from the schedule folder
export BASE_ENV="$THIS_DIR/meraki_discovery.env"
SEL_ENV_FILE="$THIS_DIR/selected_upgrade.env"

mkdir -p "$THIS_DIR/logs" "$THIS_DIR/runs"

# Execute the headless upgrader; keep stdout/stderr logs
bash "$UPGRADER" "$SEL_ENV_FILE" \
  >>"$THIS_DIR/logs/stdout.log" 2>>"$THIS_DIR/logs/stderr.log"
EOS
chmod +x "$JOB_DIR/job.sh"

# metadata
{
  echo "job_id=$JOB_ID"
  echo "created_utc=$(date -u '+%F %T')"
  echo "scheduled_local=${RUN_LOCAL_HUMAN}"
  echo "note=$(printf '%s' "$NOTE" | tr '\n' ' ')"
  echo "backend=at"
  echo "backend_id="
} > "$JOB_DIR/job.meta"

# 'at' payload wrapper
cat > "$JOB_DIR/at.payload.sh" <<EOF
#!/bin/sh
exec /usr/bin/env bash "$JOB_DIR/job.sh"
EOF
chmod +x "$JOB_DIR/at.payload.sh"

# --------------- submit to 'at' ---------------
SUBMIT_OUT="$(at -t "$AT_TSTAMP" -f "$JOB_DIR/at.payload.sh" 2>&1)" || {
  dlg --title "Schedule error" --msgbox "Failed to submit job to 'at':\n\n$SUBMIT_OUT" 14 78
  clear; exit 1
}
AT_JOB="$(printf '%s\n' "$SUBMIT_OUT" | awk '/job/ {print $2; exit}')"
[[ -z "$AT_JOB" ]] && AT_JOB="unknown"
sed -i -e "s/^backend_id=.*/backend_id=${AT_JOB}/" "$JOB_DIR/job.meta"

# --------------- done ---------------
dlg --title "Scheduled" --msgbox \
"Scheduled with 'at' (job ${AT_JOB}).

When:   ${RUN_LOCAL_HUMAN}
Folder: ${JOB_DIR}

Run artifacts (summary.csv, actions.csv, devlogs, etc.) will appear under:
  ${JOB_DIR}/runs/run-<timestamp>/" 16 80
clear
exit 0
