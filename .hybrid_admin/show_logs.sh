#!/usr/bin/env bash
# unified_logs.sh — Dialog viewer for:
#   • IOS-XE upgrade logs (manual + scheduled)
#   • IOS-XE *Advanced* upgrade logs (manual + scheduled)
#   • Discovery scans (nmap/SSH discovery + upgrade_plan)
#   • Meraki migration / switch-claim logs
#   • AAA / DNS / IP-routing / NTP remediation runs

# NOTE: no -e here on purpose; we want Cancel/Esc to be handled manually.
set -Euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need sed; need date; need grep; need cut; need sort; need tr
# atq is used by iosxe menus (scheduled jobs)
need atq

ROOT="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
RUNS_DIR="$ROOT/runs"
SCHED_DIR="$ROOT/schedules"

# Normal roots
DISC_ROOT="$RUNS_DIR/discoveryscans"
MIGRATION_DIR="$RUNS_DIR/migration"   # Meraki migration / claim runs
AAA_DIR="$RUNS_DIR/aaafix"
DNS_DIR="$RUNS_DIR/dnsfix"
IPR_DIR="$RUNS_DIR/iprfix"
NTP_DIR="$RUNS_DIR/ntpfix"

# ---------------------------
# CMDS Patch/Update logs (server)
# ---------------------------
SERVER_ADMIN_ROOT="/root/.server_admin"
CMDS_UPDATE_ROOT="$SERVER_ADMIN_ROOT/runs/cmds-update"

# ---------------------------
# Advanced IOS-XE locations
# ---------------------------
ADV_ROOT="${ADV_ROOT:-/root/.hybrid_admin/adv-ios-xe-upgrader}"
ADV_RUNS_DIR="$ADV_ROOT/runs"
ADV_SCHED_DIR="$ADV_ROOT/schedules"
ADV_DISC_ROOT="$ADV_RUNS_DIR/discoveryscans"

BACKTITLE="${BACKTITLE:-Main Menu}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

# One consistent local-time display format everywhere
TS_FMT='+%a %b %d, %Y %I:%M:%S %p %Z'

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
epoch_from_runid(){
  local rid="$1"; rid="${rid#run-}"
  date -ud "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_runid(){
  local ep; ep="$(epoch_from_runid "$1")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$1"
}

# ----- time helpers for discovery scan-YYYYmmddHHMMSS (UTC) -----
epoch_from_scanid(){
  local sid="$1"; sid="${sid#scan-}"
  date -ud "${sid:0:4}-${sid:4:2}-${sid:6:2} ${sid:8:2}:${sid:10:2}:${sid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_scanid(){
  local ep; ep="$(epoch_from_scanid "$1")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$1"
}

# ----- time helpers for Meraki migration dirs: run-YYYYmmddHHMMSS or claim-YYYYmmddHHMMSS -----
epoch_from_migrationid(){
  local mid="$1"
  mid="${mid#run-}"
  mid="${mid#claim-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_migrationid(){
  local ep; ep="$(epoch_from_migrationid "$1")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$1"
}

# ----- time helpers for generic prefix-YYYYmmddHHMMSS dirs (aaa-, dns-, ipr-, ntp-, runall-) -----
epoch_from_genericid(){
  local gid="$1"
  gid="${gid#*-}"   # strip everything up to first '-'
  date -ud "${gid:0:4}-${gid:4:2}-${gid:6:2} ${gid:8:2}:${gid:10:2}:${gid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_genericid(){
  local ep; ep="$(epoch_from_genericid "$1")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$1"
}

epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }
fmt_local_from_human(){
  local s="$1"
  local ep; ep="$(epoch_from_human "$s")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$s"
}

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
  else
    dlg --title "$ttl" --msgbox "No content found:\n$f" 8 70
  fi
}

# ---------------------------------------------------------------------------
# IOS-XE upgrade run viewer (shared)
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
    [[ $rc -ne 0 ]] && return

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
        dlg --title "Device logs" --menu "Pick a device log" 20 120 12 "${devitems[@]}"
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

# ---------------------------------------------------------------------------
# Regular IOS-XE menu
# ---------------------------------------------------------------------------
iosxe_menu(){
  local rows=()

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

  if [[ -d "$SCHED_DIR" ]]; then
    local j meta when_local when_local_fmt when_ep backend state text sstdout spawned_dir
    for j in "$SCHED_DIR"/job-*; do
      [[ -d "$j" ]] || continue
      meta="$j/job.meta"
      when_local="$(awk -F= '/^scheduled_local=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
      when_local_fmt="$when_local"
      when_ep="$(epoch_from_human "$when_local")"
      (( when_ep > 0 )) && when_local_fmt="$(date -d "@$when_ep" "$TS_FMT" 2>/dev/null || echo "$when_local")"
      backend="$(awk -F= '/^backend_id=/{print $2}' "$meta" 2>/dev/null || echo "")"

      sstdout="$j/logs/stdout.log"
      spawned_dir=""; [[ -s "$sstdout" ]] && spawned_dir="$(extract_spawned_run_dir_from_stdout "$sstdout")"

      if [[ -n "$spawned_dir" && -d "$spawned_dir" ]]; then
        state="(Scheduled — done)"
        text="${when_local_fmt}  ${state}"
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
        text="${when_local_fmt:-$(basename "$j")}  ${state}"
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
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      M:run-*) show_upgrade_run_menu "$path" "Manual: ${sel#M:}" ;;
      S:job-*) show_upgrade_run_menu "$path" "Scheduled (done): ${sel#S:}" ;;
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
# Advanced IOS-XE menu (ONLY under /root/.hybrid_admin/adv-ios-xe-upgrader)
# NOTE: Advanced runs store upgrade artifacts under: run-*/upgrade/
# ---------------------------------------------------------------------------
iosxe_advanced_menu(){
  if [[ ! -d "$ADV_ROOT" ]]; then
    dlg --title "IOS-XE Advanced Upgrade Logs" --msgbox \
"Advanced upgrader root not found:

$ADV_ROOT" 9 70
    return
  fi

  local rows=()

  if [[ -d "$ADV_RUNS_DIR" ]]; then
    local d base ep loc
    shopt -s nullglob
    for d in "$ADV_RUNS_DIR"/run-* "$ADV_RUNS_DIR"/runall-*; do
      [[ -d "$d" ]] || continue
      base="$(basename "$d")"
      [[ "$base" == "latest" || "$base" == "runall-latest" ]] && continue

      if [[ "$base" == run-* ]]; then
        ep="$(epoch_from_runid "$base")"
        loc="$(to_local_from_runid "$base")"
      else
        ep="$(epoch_from_genericid "$base")"
        loc="$(to_local_from_genericid "$base")"
      fi

      rows+=("${ep}|AM:${base}|${loc}  (Advanced)|${d}")
    done
    shopt -u nullglob
  fi

  if [[ -d "$ADV_SCHED_DIR" ]]; then
    local j meta when_local when_local_fmt when_ep backend state text sstdout spawned_dir
    for j in "$ADV_SCHED_DIR"/job-*; do
      [[ -d "$j" ]] || continue
      meta="$j/job.meta"
      when_local="$(awk -F= '/^scheduled_local=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
      when_local_fmt="$when_local"
      when_ep="$(epoch_from_human "$when_local")"
      (( when_ep > 0 )) && when_local_fmt="$(date -d "@$when_ep" "$TS_FMT" 2>/dev/null || echo "$when_local")"
      backend="$(awk -F= '/^backend_id=/{print $2}' "$meta" 2>/dev/null || echo "")"

      sstdout="$j/logs/stdout.log"
      spawned_dir=""; [[ -s "$sstdout" ]] && spawned_dir="$(extract_spawned_run_dir_from_stdout "$sstdout")"

      if [[ -n "$spawned_dir" && -d "$spawned_dir" ]]; then
        state="(Scheduled — done)"
        text="${when_local_fmt}  ${state}"
        rows+=("${when_ep}|AS:$(basename "$j")|${text}|${spawned_dir}")
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
        text="${when_local_fmt:-$(basename "$j")}  ${state}"
        rows+=("${when_ep}|AP:$(basename "$j")|${text}|${j}")
      fi
    done
  fi

  if ((${#rows[@]}==0)); then
    dlg --title "IOS-XE Advanced Upgrade Logs" --msgbox \
"No advanced runs found yet.

Expected:
  $ADV_RUNS_DIR/run-*
  $ADV_RUNS_DIR/runall-*
  $ADV_SCHED_DIR/job-*" 12 76
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
    dlg --title "IOS-XE Advanced Upgrade Logs" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      AM:run-*|AM:runall-*)
        if [[ -d "$path/upgrade" && -s "$path/upgrade/ui.status" ]]; then
          show_upgrade_run_menu "$path/upgrade" "Advanced: ${sel#AM:}"
        else
          show_upgrade_run_menu "$path" "Advanced: ${sel#AM:}"
        fi
        ;;
      AS:job-*)
        if [[ -d "$path/upgrade" && -s "$path/upgrade/ui.status" ]]; then
          show_upgrade_run_menu "$path/upgrade" "Advanced Scheduled (done): ${sel#AS:}"
        else
          show_upgrade_run_menu "$path" "Advanced Scheduled (done): ${sel#AS:}"
        fi
        ;;
      AP:job-*)
        while true; do
          local items=()
          items+=("meta" "job.meta")
          items+=("sout" "logs/stdout.log")
          items+=("serr" "logs/stderr.log")
          items+=("back" "Back")
          dlg --title "Advanced Scheduled: ${sel#AP:}" --menu "Pending / not yet executed" 16 92 8 "${items[@]}"
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
    [[ $rc -ne 0 ]] && return

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
        dlg --title "Discovery device logs" --menu "Pick a device log" 20 120 12 "${devitems[@]}"
        local rc2=$DIALOG_RC
        (( rc2 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path) dlg --title "Scan path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
    esac
  done
}

discovery_menu(){
  local have_any=0
  local rows=()

  # -----------------------
  # Normal discovery scans
  # -----------------------
  if [[ -d "$DISC_ROOT" ]]; then
    local d base ep loc
    for d in "$DISC_ROOT"/scan-*; do
      [[ -d "$d" ]] || continue
      base="$(basename "$d")"        # scan-YYYYmmddHHMMSS (UTC)
      ep="$(epoch_from_scanid "$base")"
      loc="$(to_local_from_scanid "$base")"
      rows+=("${ep}|N:${base}|${loc}  (Normal)|${d}")
      have_any=1
    done
  fi

  # -------------------------
  # Advanced discovery scans
  # -------------------------
  if [[ -n "${ADV_DISC_ROOT:-}" && -d "$ADV_DISC_ROOT" ]]; then
    local d base ep loc
    for d in "$ADV_DISC_ROOT"/scan-*; do
      [[ -d "$d" ]] || continue
      base="$(basename "$d")"        # scan-YYYYmmddHHMMSS (UTC)
      ep="$(epoch_from_scanid "$base")"
      loc="$(to_local_from_scanid "$base")"
      rows+=("${ep}|A:${base}|${loc}  (Advanced IOS-XE)|${d}")
      have_any=1
    done
  fi

  if (( have_any == 0 )) || ((${#rows[@]}==0)); then
    dlg --title "Discovery Scans" --msgbox \
"No discovery scans found yet.

Expected (Normal):
  $DISC_ROOT

Expected (Advanced IOS-XE):
  ${ADV_DISC_ROOT:-$ADV_RUNS_DIR/discoveryscans}" 12 80
    return
  fi

  # Newest first across BOTH sets
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
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      N:scan-*) show_discovery_run_menu "$path" "Discovery (Normal): ${sel#N:}" ;;
      A:scan-*) show_discovery_run_menu "$path" "Discovery (Advanced IOS-XE): ${sel#A:}" ;;
    esac
  done
}





# ---------------------------------------------------------------------------
# Generic "fix" viewer (AAA / DNS / IP routing / NTP)
# ---------------------------------------------------------------------------
show_fix_run_menu(){
  local rdir="$1" title="$2" summary_name="$3"
  while true; do
    local items=()
    local ui="$rdir/ui.status"
    local summary="$rdir/$summary_name"
    local devdir="$rdir/devlogs"

    items+=("ui"   "Overview (ui.status)")
    items+=("sum"  "$summary_name")
    if [[ -d "$devdir" ]]; then
      items+=("dev" "Per-device logs")
    fi
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 18 90 10 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      ui)  view_file "$ui"  "ui.status" ;;
      sum) view_file "$summary" "$summary_name" ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/*.log 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Device logs" --msgbox "No device logs found." 7 50
          continue
        fi
        local devitems=() d
        for d in "${devs[@]}"; do devitems+=("$d" "$(basename "$d")"); done
        dlg --title "Device logs" --menu "Pick a device log" 20 120 12 "${devitems[@]}"
        local rc2=$DIALOG_RC
        (( rc2 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
    esac
  done
}

fix_menu(){
  local root="$1" title="$2" tag="$3" desc="$4" summary_name="$5"

  if [[ ! -d "$root" ]]; then
    dlg --title "$title" --msgbox "No runs found yet.\n\nExpected directory:\n$root" 9 70
    return
  fi

  local rows=()
  local d base ep loc
  for d in "$root"/*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    [[ "$base" == "latest" ]] && continue
    ep="$(epoch_from_genericid "$base")"
    loc="$(to_local_from_genericid "$base")"
    rows+=("${ep}|${tag}:${base}|${loc}  (${desc})|${d}")
  done

  if ((${#rows[@]}==0)); then
    dlg --title "$title" --msgbox "No runs found yet in:\n$root" 8 70
    return
  fi

  mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)
  local choices=() line tagtxt txt
  for line in "${sorted[@]}"; do
    tagtxt="$(cut -d'|' -f2 <<<"$line")"
    txt="$(cut -d'|' -f3 <<<"$line")"
    choices+=("$tagtxt" "$txt")
  done

  while true; do
    dlg --title "$title" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      "${tag}:"*) show_fix_run_menu "$path" "$title: ${sel#${tag}:}" "$summary_name" ;;
    esac
  done
}

aaafix_menu(){ fix_menu "$AAA_DIR" "AAA Fix Runs"        "A" "AAA remediation run"        "aaafix.csv"; }
dnsfix_menu(){ fix_menu "$DNS_DIR" "DNS Fix Runs"        "N" "DNS remediation run"        "dnsfix.csv"; }
iprfix_menu(){ fix_menu "$IPR_DIR" "IP Routing Fix Runs" "R" "IP routing remediation run" "iprfix.csv"; }
ntpfix_menu(){ fix_menu "$NTP_DIR" "NTP Fix Runs"        "T" "NTP remediation run"        "ntpfix.csv"; }

# ---------------------------------------------------------------------------
# Meraki switch-claim viewer
# ---------------------------------------------------------------------------
show_meraki_claim_run_menu(){
  local rdir="$1" title="$2"

  while true; do
    local items=()
    local claim_log="$rdir/meraki_claim.log"
    local connect_txt="$rdir/meraki_connect_summary.txt"
    local connect_csv="$rdir/meraki_connect_summary.csv"
    local cloud_ids="$rdir/meraki_cloud_ids.json"
    local map_json="$rdir/meraki_switch_network_map.json"

    items+=("claim"    "meraki_claim.log")
    items+=("conn_txt" "meraki_connect_summary.txt")
    items+=("conn_csv" "meraki_connect_summary.csv")
    items+=("cloud"    "meraki_cloud_ids.json")
    items+=("map"      "meraki_switch_network_map.json")
    items+=("path"     "Show run folder path")
    items+=("back"     "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      claim)    view_file "$claim_log"   "meraki_claim.log" ;;
      conn_txt) view_file "$connect_txt" "meraki_connect_summary.txt" ;;
      conn_csv) view_file "$connect_csv" "meraki_connect_summary.csv" ;;
      cloud)    view_file "$cloud_ids"   "meraki_cloud_ids.json" ;;
      map)      view_file "$map_json"    "meraki_switch_network_map.json" ;;
      path)     dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back)     return ;;
    esac
  done
}

meraki_claims_menu(){
  if [[ ! -d "$MIGRATION_DIR" ]]; then
    dlg --title "Meraki SwitchClaims" \
        --msgbox "No Meraki migration runs found yet.\n\nExpected directory:\n$MIGRATION_DIR" 9 80
    return
  fi

  local rows=()
  local log rdir base ep loc

  shopt -s nullglob
  for log in "$MIGRATION_DIR"/*/meraki_claim.log; do
    [[ -f "$log" ]] || continue
    rdir="$(dirname "$log")"
    base="$(basename "$rdir")"
    ep="$(epoch_from_migrationid "$base")"
    loc="$(to_local_from_migrationid "$base")"
    rows+=("${ep}|C:${base}|${loc}  (Meraki switch claims)|${rdir}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Meraki SwitchClaims" \
        --msgbox "No meraki_claim.log files found.\n\nExpected under:\n$MIGRATION_DIR/*/meraki_claim.log" 10 80
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
    dlg --title "Meraki SwitchClaims" \
        --menu "Select a Meraki claim run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_meraki_claim_run_menu "$path" "Meraki claims: ${sel#C:}"
  done
}

# ---------------------------------------------------------------------------
# Search by IP / text across runs
#
# Rules (as you specified):
#   - "normal <term>"   => ONLY search:  $RUNS_DIR
#   - "advanced <term>" => ONLY search:  $ADV_RUNS_DIR
#   - "<term>"          => search BOTH: $RUNS_DIR first (200), then $ADV_RUNS_DIR (200)
#   - "normal"          => ALL results from $RUNS_DIR (up to 200)
#   - "advanced"        => ALL results from $ADV_RUNS_DIR (up to 200)
#   - NEVER mix roots unless mode is BOTH (i.e., no explicit normal/advanced prefix)
#
# Debug log: $ROOT/unified_logs_search.debug
# ---------------------------------------------------------------------------

ip_search_menu(){
  local NORMAL_ROOT="/root/.hybrid_admin/runs"
  local ADVANCED_ROOT="/root/.hybrid_admin/adv-ios-xe-upgrader/runs"

  while true; do
    dlg --title "Search logs by IP / text" \
        --inputbox "Enter an IP address or search string:\n(Cancel or empty input to go back.)" 10 70 ""
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local needle="$DOUT"
    needle="$(echo "$needle" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$needle" ]] && return

    # Menu width
    local term_lines term_cols menu_w=140
    if read -r term_lines term_cols < <(stty size 2>/dev/null); then
      menu_w=$(( term_cols - 4 ))
      (( menu_w < 100 )) && menu_w=100
      (( menu_w > 200 )) && menu_w=200
    fi

    local cap_total=2000

    local tmpN tmpA tmpAll
    tmpN="$(mktemp)"; tmpA="$(mktemp)"; tmpAll="$(mktemp)"
    : >"$tmpN"; : >"$tmpA"; : >"$tmpAll"

    # FIXED-STRING grep (dots are literal), with common texty includes
    local -a GREP_ARGS=(
      -R -n -F
      --include='*.log'
      --include='*.csv'
      --include='*.json'
      --include='*.status'
      --include='*.env'
      -e "$needle"
    )

    # Gather normal first, then advanced
    local ncount=0 acount=0

    if [[ -d "$NORMAL_ROOT" ]]; then
      grep "${GREP_ARGS[@]}" -- "$NORMAL_ROOT" 2>/dev/null >"$tmpN" || true
    fi
    if [[ -d "$ADVANCED_ROOT" ]]; then
      grep "${GREP_ARGS[@]}" -- "$ADVANCED_ROOT" 2>/dev/null >"$tmpA" || true
    fi

    # Build up to cap_total lines, preferring NORMAL first
    if [[ -s "$tmpN" ]]; then
      head -n "$cap_total" "$tmpN" >"$tmpAll"
      ncount="$(wc -l <"$tmpAll" 2>/dev/null || echo 0)"
    fi

    local remaining=$(( cap_total - ncount ))
    if (( remaining > 0 )) && [[ -s "$tmpA" ]]; then
      head -n "$remaining" "$tmpA" >>"$tmpAll"
      acount="$(wc -l <"$tmpA" 2>/dev/null || echo 0)"
    fi

    if [[ ! -s "$tmpAll" ]]; then
      dlg --title "Search results" --msgbox "No matches found for:\n$needle" 8 70
      rm -f "$tmpN" "$tmpA" "$tmpAll"
      continue
    fi

    # Build menu
    local -a FILES=()
    local -a LINES=()
    local -a MENU_ITEMS=()
    local idx=0

    while IFS=: read -r file line rest; do
      ((idx++))
      FILES[idx]="$file"
      LINES[idx]="$line"

      local label rel
      if [[ "$file" == "$NORMAL_ROOT/"* ]]; then
        label="(Normal)"
        rel="runs/${file#$NORMAL_ROOT/}"
      elif [[ "$file" == "$ADVANCED_ROOT/"* ]]; then
        label="(Advanced)"
        rel="runs/${file#$ADVANCED_ROOT/}"
      else
        label="(Other)"
        rel="$file"
      fi

      local max_snip=$(( menu_w - 38 ))
      (( max_snip < 40 )) && max_snip=40
      local snippet
      snippet="$(echo "$rest" | sed 's/^[[:space:]]*//' | cut -c1-"$max_snip")"

      MENU_ITEMS+=( "$idx" "$label $rel:$line: $snippet" )
    done <"$tmpAll"

    rm -f "$tmpN" "$tmpA" "$tmpAll"

    while true; do
      dlg --title "Search results for: $needle" \
          --menu "Showing up to $cap_total matches (Normal first, then Advanced). Select one to view context." \
          22 "$menu_w" 14 "${MENU_ITEMS[@]}"
      local rc2=$DIALOG_RC
      [[ $rc2 -ne 0 ]] && break

      local n="$DOUT"
      local f="${FILES[n]}"
      local ln="${LINES[n]}"

      local start end
      if (( ln > 10 )); then start=$((ln-10)); else start=1; fi
      end=$((ln+10))

      local ctx; ctx="$(mktemp)"
      sed -n "${start},${end}p" "$f" >"$ctx" 2>/dev/null || echo "Unable to read file $f" >"$ctx"

      local title="Context: $(basename "$f") (lines ${start}-${end}, match at ${ln})"
      local full_title="Full file: $(basename "$f")"

      while true; do
        dialog "${DIALOG_OPTS[@]}" \
          --extra-button --extra-label "Full file" \
          --title "$title" --textbox "$ctx" 0 0
        local vb_rc=$?
        case "$vb_rc" in
          3)  view_file "$f" "$full_title"; continue ;;
          0|1|255) break ;;
        esac
      done

      rm -f "$ctx"
    done
  done
}
# ---------------------------------------------------------------------------
# CMDS Patch/Updates viewer (server logs)
#   Root: /root/.server_admin/runs/cmds-update
#     - patch_history.log
#     - run-YYYYmmddHHMMSS/{cmds_updater.log,stdout.log,stderr.log}
# ---------------------------------------------------------------------------

epoch_from_cmdsupdate_runid(){
  local rid="$1"; rid="${rid#run-}"
  date -d "${rid:0:4}-${rid:4:2}-${rid:6:2} ${rid:8:2}:${rid:10:2}:${rid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_cmdsupdate_runid(){
  local ep; ep="$(epoch_from_cmdsupdate_runid "$1")"
  (( ep > 0 )) && date -d "@$ep" "$TS_FMT" 2>/dev/null || echo "$1"
}

show_cmds_update_run_menu(){
  local rdir="$1" title="$2"
  while true; do
    local items=()
    local ulog="$rdir/cmds_updater.log"
    local sout="$rdir/stdout.log"
    local serr="$rdir/stderr.log"

    items+=("ulog" "cmds_updater.log")
    items+=("sout" "stdout.log")
    items+=("serr" "stderr.log")
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 16 80 8 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      ulog) view_file "$ulog" "cmds_updater.log" ;;
      sout) view_file "$sout" "stdout.log" ;;
      serr) view_file "$serr" "stderr.log" ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
    esac
  done
}

cmds_updates_menu(){
  if [[ ! -d "$CMDS_UPDATE_ROOT" ]]; then
    dlg --title "CMDS Patch/Updates" --msgbox \
"No CMDS update logs found.

Expected:
  $CMDS_UPDATE_ROOT" 10 76
    return
  fi

  local rows=()
  local d base ep loc

  shopt -s nullglob
  for d in "$CMDS_UPDATE_ROOT"/run-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(epoch_from_cmdsupdate_runid "$base")"
    loc="$(to_local_from_cmdsupdate_runid "$base")"
    rows+=("${ep}|R:${base}|${loc}|${d}")
  done
  shopt -u nullglob

  while true; do
    local choices=()

    # Top entry: patch history
    if [[ -s "$CMDS_UPDATE_ROOT/patch_history.log" ]]; then
      choices+=("HISTORY" "patch_history.log")
    else
      choices+=("HISTORY" "patch_history.log (missing/empty)")
    fi

    # Separator line (dialog "tag/desc" needs tag to be unique; we just ignore it)
    choices+=("__SEP__" "------------- Server Logs -----------")

    if ((${#rows[@]}==0)); then
      choices+=("NONE" "(No run-* folders found)")
    else
      mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)
      local line tag txt path
      for line in "${sorted[@]}"; do
        tag="$(cut -d'|' -f2 <<<"$line")"      # R:run-...
        txt="$(cut -d'|' -f3 <<<"$line")"
        path="$(cut -d'|' -f4- <<<"$line")"
        choices+=("$tag" "$txt")
      done
    fi

    choices+=("BACK" "Back")

    dlg --title "CMDS Patch/Updates" --menu "Select an option:" 22 90 14 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      HISTORY) view_file "$CMDS_UPDATE_ROOT/patch_history.log" "patch_history.log" ;;
      __SEP__) continue ;;  # ignore the separator
      NONE) continue ;;
      BACK) return ;;
      R:run-*)
        # Find selected path
        local sel="$DOUT" path=""
        local line2
        for line2 in "${sorted[@]:-}"; do
          [[ "$sel" == "$(cut -d'|' -f2 <<<"$line2")" ]] || continue
          path="$(cut -d'|' -f4- <<<"$line2")"
          break
        done
        [[ -n "$path" ]] && show_cmds_update_run_menu "$path" "CMDS Update: ${sel#R:}"
        ;;
    esac
  done
}
# ---------------------------------------------------------------------------
# Top-level main menu
# ---------------------------------------------------------------------------
main(){
  while true; do
        dlg --title "Main Menu" --menu "Select an option:" 22 90 12 \
      1 "IOS-XE Upgrade Logs" \
      2 "IOS-XE Advanced Upgrade Logs" \
      3 "Discovery Scans" \
      4 "Meraki SwitchClaims" \
      5 "AAA Fix Runs" \
      6 "DNS Fix Runs" \
      7 "IP Routing Fix Runs" \
      8 "NTP Fix Runs" \
      9 "Search by IP / text" \
      10 "------------- Server Logs -----------" \
      11 "CMDS Patch/Updates" \
      0 "Exit"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && break

        case "$DOUT" in
      1) iosxe_menu          ;;
      2) iosxe_advanced_menu ;;
      3) discovery_menu      ;;
      4) meraki_claims_menu  ;;
      5) aaafix_menu         ;;
      6) dnsfix_menu         ;;
      7) iprfix_menu         ;;
      8) ntpfix_menu         ;;
      9) ip_search_menu      ;;
      10) : ;;               # header line: do nothing
      11) cmds_updates_menu  ;;
      0) break               ;;
    esac
  done
}

main