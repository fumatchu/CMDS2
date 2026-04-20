#!/usr/bin/env bash
# ============================================================
# CMDS VLAN PIPELINE - CAT VERSION (DIALOG UI)
# ============================================================

set -Euo pipefail

BASE_DIR="/root/.cat_admin"
SCRIPT="$BASE_DIR/vlan_checker_cli.sh"
RUN_ROOT="$BASE_DIR/runs/vlan_push"

# ------------------------------------------------------------
# DYNAMIC FULLSCREEN LAYOUT
# ------------------------------------------------------------
if read -r LINES COLS < <(stty size 2>/dev/null); then
  :
else
  LINES=30
  COLS=120
fi

TAIL_H=$((LINES - 10))
TAIL_W=$((COLS - 4))

GAUGE_H=7
GAUGE_W=$TAIL_W

GAUGE_ROW=$((TAIL_H + 3))
GAUGE_COL=2

((TAIL_H < 10)) && TAIL_H=10
((TAIL_W < 70)) && TAIL_W=70

# ------------------------------------------------------------
# UI FILES
# ------------------------------------------------------------
STATUS_FILE="$(mktemp)"
PROG_PIPE="$(mktemp -u)"
: > "$STATUS_FILE"

# ------------------------------------------------------------
# START UI
# ------------------------------------------------------------
mkfifo "$PROG_PIPE"

(
  dialog --no-shadow \
    --backtitle "CMDS Deployment System" \
    --begin 2 2 --title "Activity" \
    --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
    --and-widget \
    --begin "$GAUGE_ROW" "$GAUGE_COL" \
    --title "Progress" \
    --gauge "Starting..." "$GAUGE_H" "$GAUGE_W" 0 < "$PROG_PIPE"
) &

DIALOG_PID=$!

# open FD for gauge
exec 3<>"$PROG_PIPE"

# ------------------------------------------------------------
# UI HELPERS
# ------------------------------------------------------------
ui_log() {
  printf '%(%H:%M:%S)T %s\n' -1 "$*" >> "$STATUS_FILE"
}

ui_progress() {
  local pct="$1"
  shift
  local msg="$*"
  printf "XXX\n%s\n%s\nXXX\n" "$pct" "$msg" >&3
}

# ------------------------------------------------------------
# CLEANUP
# ------------------------------------------------------------
cleanup() {
  exec 3>&- 2>/dev/null || true
  rm -f "$PROG_PIPE" "$STATUS_FILE" 2>/dev/null || true
  kill "$DIALOG_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ------------------------------------------------------------
# RUN PIPELINE
# ------------------------------------------------------------
ui_log "Starting VLAN pipeline..."
ui_progress 5 "Initializing..."

(
  "$SCRIPT" 2>&1 | while read -r line; do
    ui_log "$line"

    # 🔥 UPDATED PROGRESS MAPPING (CAT AWARE)
    case "$line" in
      *"Building VLAN summary"*)
        ui_progress 15 "Building VLAN summary..."
        ;;
      *"API GET"*)
        ui_progress 30 "Querying Meraki..."
        ;;
      *"CREATED"*|*"UPDATED"*)
        ui_progress 50 "Processing VLAN profiles..."
        ;;
      *"Assignment Debug"*)
        ui_progress 70 "Preparing assignment..."
        ;;
      *"Assignment successful"*)
        ui_progress 85 "Applying profile..."
        ;;
      *"ASSIGN FAILED"*)
        ui_progress 85 "Assignment failed (see logs)..."
        ;;
      *"DONE"*)
        ui_progress 100 "Complete"
        ;;
    esac

  done
) &

SCRIPT_PID=$!
wait $SCRIPT_PID

# ------------------------------------------------------------
# COMPLETE
# ------------------------------------------------------------
ui_progress 100 "Done."
ui_log "Pipeline complete."

sleep 1

# ------------------------------------------------------------
# SHOW SUMMARY
# ------------------------------------------------------------
LATEST_RUN="$(readlink -f "$RUN_ROOT/latest")"
SUMMARY_FILE="$LATEST_RUN/results/summary.txt"

if [[ -f "$SUMMARY_FILE" ]]; then

  SUM_H=$((LINES - 10))
  SUM_W=$((COLS - 20))

  ((SUM_H > 30)) && SUM_H=30
  ((SUM_W > 120)) && SUM_W=120
  ((SUM_H < 15)) && SUM_H=15
  ((SUM_W < 60)) && SUM_W=60

  dialog --title "VLAN Pipeline Results" \
         --backtitle "CMDS Deployment System" \
         --ok-label "Done" \
         --textbox "$SUMMARY_FILE" "$SUM_H" "$SUM_W"

else
  dialog --msgbox "No summary file found." 10 50
fi

clear