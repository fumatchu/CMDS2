#!/usr/bin/env bash
# unified_logs.sh — Dialog viewer for:
#   • IOS-XE upgrade logs (manual + scheduled)
#   • Discovery scans (nmap/SSH discovery + upgrade_plan)

# NOTE: no -e here on purpose; we want Cancel/Esc to be handled manually.
set -Euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need sed; need date; need grep; need cut; need sort; need tr

ROOT="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
RUNS_DIR="$ROOT/runs"
SCHED_DIR="$ROOT/schedules"
DISC_ROOT="$RUNS_DIR/discoveryscans"

BACKTITLE="${BACKTITLE:-Main Menu}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

# -----------------------------------------------------------------------------
# dialog wrapper — NEVER fails so the shell doesn't exit on Cancel/Esc.
# Real exit code is stored in $DIALOG_RC, text in $DOUT.
# -----------------------------------------------------------------------------
dlg() {
  local _t; _t="$(mktemp)"
  dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"
  DIALOG_RC=$?            # 0=OK, 1=Cancel, 255=Esc
  DOUT=""
  [[ -s "$_t" ]] && DOUT="$(cat "$_t")"
  rm -f "$_t"
  return 0                # always 0
}

# ----- time helpers for IOS-XE run-YYYYmmddHHMMSS (UTC) -----
to_local_from_runid(){
  local rid="$1"; rid="${rid#run-}"
  date -d "@$(date -ud "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$rid"
}
epoch_from_runid(){
  local rid="$1"; rid="${rid#run-}"
  date -ud "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s 2>/dev/null || echo 0
}

# ----- time helpers for discovery scan-YYYYmmddHHMMSS (UTC) -----
to_local_from_scanid(){
  local sid="$1"; sid="${sid#scan-}"
  date -d "@$(date -ud "${sid:0:4}-${sid:4:2}-${sid:6:2} ${sid:8:2}:${sid:10:2}:${sid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$sid"
}
epoch_from_scanid(){
  local sid="$1"; sid="${sid#scan-}"
  date -ud "${sid:0:4}-${sid:4:2}-${sid:6:2} ${sid:8:2}:${sid:10:2}:${sid:12:2}" +%s 2>/dev/null || echo 0
}

epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

in_at_queue(){
  local id="$1"
  [[ -z "$id" || "$id" == "unknown" ]] && return 1
  atq 2>/dev/null | awk '{print $1}' | grep -qx -- "$id"
}

extract_spawned_run_dir_from_stdout(){
  local f="$1"
  awk -F'Run dir:[[:space:]]*' '/Run dir:/ {print $2; exit}' "$f" 2>/dev/null || true
}

view_file(){
  local f="$1" ttl="${2:-File}"
  if [[ -s "$f" ]]; then
    dlg --title "$ttl" --textbox "$f" 0 0
    # ignore DIALOG_RC here; just return
  else
    dlg --title "$ttl" --msgbox "No content found:\n$f" 8 70
  fi
}

# ---------------------------------------------------------------------------
# IOS-XE upgrade run viewer
# ---------------------------------------------------------------------------
show_upgrade_run_menu(){
  local rdir="$1" title="$2"
  while true; do
    local items=()
    local ui="$rdir/ui.status" sum="$rdir/summary.csv" act="$rdir/actions.csv"
    items+=("ui"   "Overview (ui.status)")
    items+=("sum"  "summary.csv")
    items+=("act"  "actions.csv")

    local devdir="$rdir/devlogs"
    if [[ -d "$devdir" ]]; then
      items+=("dev" "Per-device session logs")
    fi

    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 18 90 10 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return   # Cancel/Esc => back one level

    case "$DOUT" in
      ui)  view_file "$ui"  "ui.status" ;;
      sum) view_file "$sum" "summary.csv" ;;
      act) view_file "$act" "actions.csv" ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/*session.log 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Device logs" --msgbox "No device logs found." 7 50
          continue
        fi
        local devitems=() d
        for d in "${devs[@]}"; do devitems+=("$d" "$(basename "$d")"); done
        dlg --title "Device logs" --menu "Pick a device log" 20 90 12 "${devitems[@]}"
        local rc2=$DIALOG_RC
        (( rc2 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path)
        dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back)
        return ;;
    esac
  done
}

iosxe_menu(){
  local rows=()

  # Manual runs
  if [[ -d "$RUNS_DIR" ]]; then
    local d base ep loc
    for d in "$RUNS_DIR"/run-*; do
      [[ -d "$d" ]] || continue
      base="$(basename "$d")"
      ep="$(epoch_from_runid "$base")"
      loc="$(to_local_from_runid "$base")"
      rows+=("${ep}|M:${base}|${loc}  (Live)|${d}")
    done
  fi

  # Scheduled jobs
  if [[ -d "$SCHED_DIR" ]]; then
    local j meta when_local when_ep backend state text sstdout spawned_dir
    for j in "$SCHED_DIR"/job-*; do
      [[ -d "$j" ]] || continue
      meta="$j/job.meta"
      when_local="$(awk -F= '/^scheduled_local=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
      backend="$(awk -F= '/^backend_id=/{print $2}' "$meta" 2>/dev/null || echo "")"
      when_ep="$(epoch_from_human "$when_local")"
      sstdout="$j/logs/stdout.log"
      spawned_dir=""; [[ -s "$sstdout" ]] && spawned_dir="$(extract_spawned_run_dir_from_stdout "$sstdout")"

      if [[ -n "$spawned_dir" && -d "$spawned_dir" ]]; then
        state="(Scheduled — done)"
        text="${when_local}  ${state}"
        rows+=("${when_ep}|S:$(basename "$j")|${text}|${spawned_dir}")
      else
        if in_at_queue "$backend"; then
          state="(Scheduled — pending)"
        else
          if (( when_ep>0 && when_ep > $(date +%s) )); then
            state="(Scheduled — pending)"
          else
            state="(Scheduled — unknown/expired)"
          fi
        fi
        text="${when_local:-$(basename "$j")}  ${state}"
        rows+=("${when_ep}|P:$(basename "$j")|${text}|${j}")
      fi
    done
  fi

  if ((${#rows[@]}==0)); then
    dlg --title "IOS-XE Upgrade Logs" --msgbox "No runs found yet." 7 50
    return
  fi

  mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)
  local choices=() line tag txt
  for line in "${sorted[@]}"; do
    tag="$(cut -d'|' -f2 <<<"$line")"
    txt="$(cut -d'|' -f3 <<<"$line")"
    choices+=("$tag" "$txt")
  done

  while true; do
    dlg --title "IOS-XE Upgrade Logs" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return   # Cancel/Esc => back to Main Menu

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      M:run-*)
        show_upgrade_run_menu "$path" "Manual: ${sel#M:}" ;;
      S:job-*)
        show_upgrade_run_menu "$path" "Scheduled (done): ${sel#S:}" ;;
      P:job-*)
        while true; do
          local items=()
          items+=("meta" "job.meta")
          items+=("sout" "logs/stdout.log")
          items+=("serr" "logs/stderr.log")
          items+=("back" "Back")
          dlg --title "Scheduled: ${sel#P:}" --menu "Pending / not yet executed" 16 90 8 "${items[@]}"
          local rc2=$DIALOG_RC
          [[ $rc2 -ne 0 ]] && break
          case "$DOUT" in
            meta) view_file "$path/job.meta"        "job.meta"   ;;
            sout) view_file "$path/logs/stdout.log" "stdout.log" ;;
            serr) view_file "$path/logs/stderr.log" "stderr.log" ;;
            back) break ;;
          esac
        done
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Discovery scan viewer
# ---------------------------------------------------------------------------
show_discovery_run_menu(){
  local rdir="$1" title="$2"
  while true; do
    local items=()
    local ui="$rdir/ui.status"
    local disc_csv="$rdir/discovery_results.csv"
    local disc_json="$rdir/discovery_results.json"
    local plan_csv="$rdir/upgrade_plan.csv"
    local plan_json="$rdir/upgrade_plan.json"
    local devdir="$rdir/devlogs"

    items+=("ui"        "Overview (ui.status)")
    items+=("disc_csv"  "discovery_results.csv")
    items+=("disc_json" "discovery_results.json")
    items+=("plan_csv"  "upgrade_plan.csv")
    items+=("plan_json" "upgrade_plan.json")
    if [[ -d "$devdir" ]]; then
      items+=("dev" "Per-device probe logs")
    fi
    items+=("path" "Show scan folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return   # Cancel/Esc => back one level

    case "$DOUT" in
      ui)        view_file "$ui"        "ui.status"              ;;
      disc_csv)  view_file "$disc_csv"  "discovery_results.csv"  ;;
      disc_json) view_file "$disc_json" "discovery_results.json" ;;
      plan_csv)  view_file "$plan_csv"  "upgrade_plan.csv"       ;;
      plan_json) view_file "$plan_json" "upgrade_plan.json"      ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/*.log 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Device logs" --msgbox "No device logs found." 7 50
          continue
        fi
        local devitems=() d
        for d in "${devs[@]}"; do devitems+=("$d" "$(basename "$d")"); done
        dlg --title "Discovery device logs" --menu "Pick a device log" 20 90 12 "${devitems[@]}"
        local rc2=$DIALOG_RC
        (( rc2 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path)
        dlg --title "Scan path" --msgbox "$rdir" 7 70 ;;
      back)
        return ;;
    esac
  done
}

discovery_menu(){
  if [[ ! -d "$DISC_ROOT" ]]; then
    dlg --title "Discovery Scans" --msgbox "No discovery scans found yet.\n\nExpected directory:\n$DISC_ROOT" 9 70
    return
  fi

  local rows=()
  local d base ep loc
  for d in "$DISC_ROOT"/scan-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"        # scan-YYYYmmddHHMMSS
    ep="$(epoch_from_scanid "$base")"
    loc="$(to_local_from_scanid "$base")"
    rows+=("${ep}|D:${base}|${loc}  (Discovery scan)|${d}")
  done

  if ((${#rows[@]}==0)); then
    dlg --title "Discovery Scans" --msgbox "No discovery scans found yet." 7 50
    return
  fi

  mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)
  local choices=() line tag txt
  for line in "${sorted[@]}"; do
    tag="$(cut -d'|' -f2 <<<"$line")"
    txt="$(cut -d'|' -f3 <<<"$line")"
    choices+=("$tag" "$txt")
  done

  while true; do
    dlg --title "Discovery Scans" --menu "Select a scan run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return   # Cancel/Esc => back to Main Menu

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      D:scan-*)
        show_discovery_run_menu "$path" "Discovery: ${sel#D:}" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Top-level main menu
# ---------------------------------------------------------------------------
main(){
  while true; do
    dlg --title "Main Menu" --menu "Select an option:" 11 70 4 \
      1 "IOS-XE Upgrade Logs" \
      2 "Discovery Scans" \
      0 "Exit"
    local rc=$DIALOG_RC

    # Cancel/Esc at Main Menu acts like Exit
    [[ $rc -ne 0 ]] && break

    case "$DOUT" in
      1) iosxe_menu     ;;
      2) discovery_menu ;;
      0) break          ;;
    esac
  done
}

main
