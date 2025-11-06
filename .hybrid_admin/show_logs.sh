#!/usr/bin/env bash
# iosxe_logs.sh — Dialog viewer for IOS-XE upgrade logs (manual + scheduled)

set -Eeuo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need sed; need date; need grep; need cut; need sort; need tr

ROOT="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
RUNS_DIR="$ROOT/runs"
SCHED_DIR="$ROOT/schedules"

BACKTITLE="${BACKTITLE:-IOS-XE Upgrade Logs}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

dlg(){ local _t; _t="$(mktemp)"; dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"; rc=$?; DOUT=""; [[ -s "$_t" ]] && DOUT="$(cat "$_t")"; rm -f "$_t"; return $rc; }

pad2(){ printf '%02d' "$((10#${1:-0}))"; }

to_local_from_runid(){
  # run-YYYYmmddHHMMSS is in UTC in your upgrader
  local rid="$1"; rid="${rid#run-}"
  date -d "@$(date -ud "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s)" '+%F %T %Z' 2>/dev/null || echo "$rid"
}

epoch_from_runid(){
  local rid="$1"; rid="${rid#run-}"
  date -ud "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s 2>/dev/null || echo 0
}

epoch_from_human(){
  # robust parse (scheduled_local line e.g. 'Wed Nov 05, 2025 12:24:00 PM EST')
  date -d "$1" +%s 2>/dev/null || echo 0
}

in_at_queue(){
  local id="$1"
  [[ -z "$id" || "$id" == "unknown" ]] && return 1
  atq 2>/dev/null | awk '{print $1}' | grep -qx -- "$id"
}

extract_spawned_run_dir_from_stdout(){
  # looks for 'Run dir: /root/.hybrid_admin/runs/run-YYYY...' in stdout.log
  local f="$1"
  awk -F'Run dir:[[:space:]]*' '/Run dir:/ {print $2; exit}' "$f" 2>/dev/null || true
}

view_file(){
  local f="$1" ttl="${2:-File}"
  if [[ -s "$f" ]]; then
    dlg --title "$ttl" --textbox "$f" 0 0
  else
    dlg --title "$ttl" --msgbox "No content found:\n$f" 8 70
  fi
}

show_run_menu(){
  local rdir="$1" title="$2"
  while true; do
    local items=()
    local ui="$rdir/ui.status" sum="$rdir/summary.csv" act="$rdir/actions.csv"
    items+=("ui"     "Overview (ui.status)")
    items+=("sum"    "summary.csv")
    items+=("act"    "actions.csv")
    # device logs
    local devdir="$rdir/devlogs"
    if [[ -d "$devdir" ]]; then
      items+=("dev"  "Per-device session logs")
    fi
    items+=("path"   "Show run folder path")
    items+=("back"   "Back")

    dlg --title "$title" --menu "Choose what to view" 18 90 10 "${items[@]}" || return
    case "$DOUT" in
      ui)  view_file "$ui"  "ui.status";;
      sum) view_file "$sum" "summary.csv";;
      act) view_file "$act" "actions.csv";;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/*session.log 2>/dev/null || true)
        if ((${#devs[@]}==0)); then dlg --msgbox "No device logs found." 7 50; continue; fi
        local devitems=() d
        for d in "${devs[@]}"; do devitems+=("$d" "$(basename "$d")"); done
        dlg --title "Device logs" --menu "Pick a device log" 20 90 12 "${devitems[@]}" || continue
        view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path)
        dlg --msgbox "$rdir" 7 70;;
      back) return;;
    esac
  done
}

main_menu(){
  # collect rows: epoch|TAG|TEXT|RDIR(optional)
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
          # not in queue; mark by time
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
    dlg --title "IOS-XE Upgrade Logs" --msgbox "No runs found yet." 7 40; return
  fi

  # sort by epoch desc, build dialog menu
  mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)
  local choices=() line tag txt
  for line in "${sorted[@]}"; do
    tag="$(cut -d'|' -f2 <<<"$line")"
    txt="$(cut -d'|' -f3 <<<"$line")"
    choices+=("$tag" "$txt")
  done

  while true; do
    dlg --title "IOS-XE Upgrade Logs" --menu "Select a run" 22 120 12 "${choices[@]}" || return
    local sel="$DOUT"
    # find matching row to extract path
    local match path
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      M:run-*)
        show_run_menu "$path" "Manual: ${sel#M:}"
        ;;
      S:job-*)
        # Completed scheduled; jump to spawned run dir (already parsed)
        show_run_menu "$path" "Scheduled (done): ${sel#S:}"
        ;;
      P:job-*)
        # Pending/unknown scheduled; show job folder logs/meta
        while true; do
          local items=()
          items+=("meta"   "job.meta")
          items+=("sout"   "logs/stdout.log")
          items+=("serr"   "logs/stderr.log")
          items+=("back"   "Back")
          dlg --title "Scheduled: ${sel#P:}" --menu "Pending / not yet executed" 16 90 8 "${items[@]}" || break
          case "$DOUT" in
            meta) view_file "$path/job.meta"   "job.meta" ;;
            sout) view_file "$path/logs/stdout.log" "stdout.log" ;;
            serr) view_file "$path/logs/stderr.log" "stderr.log" ;;
            back) break ;;
          esac
        done
        ;;
    esac
  done
}

main_menu
