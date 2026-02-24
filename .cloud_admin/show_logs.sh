#!/usr/bin/env bash
# unified_logs.sh — Dialog viewer for:
#   • IOS-XE upgrade logs (manual + scheduled)
#   • Discovery scans (nmap/SSH discovery + upgrade_plan)
#   • Meraki preflight runs (connectivity / DNS / HTTP client src-if)
#   • Meraki switch-claim inventory (meraki_memory/*.json)
#   • DNS / HTTP client remediation runs
#   • Meraki network creation runs
#   • Port migration runs (runs/port_migration)
#   • Management IP Migration runs (runs/mgmt_ip)  <-- NEW (menu item 10)

# NOTE: no -e here on purpose; we want Cancel/Esc to be handled manually.
set -Euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need sed; need date; need grep; need cut; need sort; need tr

# -----------------------------------------------------------------------------
# Root selection policy:
#   1) If CLOUD_ADMIN_ROOT is set, use it.
#   2) Else if /root/.cloud_admin exists, use it.
#   3) Else fall back to the directory containing this script.
# -----------------------------------------------------------------------------
SCRIPT_ROOT="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

if [[ -n "${CLOUD_ADMIN_ROOT:-}" ]]; then
  ROOT="$CLOUD_ADMIN_ROOT"
elif [[ -d /root/.cloud_admin ]]; then
  ROOT="/root/.cloud_admin"
else
  ROOT="$SCRIPT_ROOT"
fi

RUNS_DIR="$ROOT/runs"
SCHED_DIR="$ROOT/schedules"

DISC_ROOT="$RUNS_DIR/discoveryscans"
MIGRATION_DIR="$RUNS_DIR/migration"        # legacy run folders (kept)
PORT_MIG_DIR="$RUNS_DIR/port_migration"    # port migration runs
MGMTIP_DIR="$RUNS_DIR/mgmt_ip"             # NEW: management IP migration runs

PREFLIGHT_DIR="$RUNS_DIR/preflight"
DNS_DIR="$RUNS_DIR/dnsfix"
HTTP_DIR="$RUNS_DIR/httpfix"
CREATENET_DIR="$RUNS_DIR/createnetworks"

MERAKI_MEMORY_DIR="$ROOT/meraki_memory"

BACKTITLE="${BACKTITLE:-Main Menu}"

HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"   # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"

declare -A HELP_TEXT=(
  [1]="View IOS-XE upgrade runs (manual and scheduled)."
  [2]="View discovery scan results and upgrade plans."
  [3]="View Meraki preflight runs (DNS/HTTP/ping readiness)."
  [4]="View Meraki switch claim inventory (meraki_memory/*.json)."
  [5]="View DNS remediation runs triggered by preflight."
  [6]="View HTTP client source-interface remediation runs."
  [7]="Search across all logs by IP address or text."
  [8]="View Meraki network creation runs (createnetwork-*)."
  [9]="View port migration runs (devlogs + diffs)."
  [10]="View management IP migration runs (actions/items/report/stats/index)."
  [0]="Return to the previous CMDS menu."
)

color_help(){ printf '%b%s%b' "$HELP_COLOR_PREFIX" "$1" "$HELP_COLOR_RESET"; }

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

# ----- time helpers for Meraki migration dirs: run-YYYYmmddHHMMSS or claim-YYYYmmddHHMMSS -----
to_local_from_migrationid(){
  local mid="$1"
  mid="${mid#run-}"
  mid="${mid#claim-}"
  date -d "@$(date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$mid"
}
epoch_from_migrationid(){
  local mid="$1"
  mid="${mid#run-}"
  mid="${mid#claim-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}

# ----- time helpers for generic prefix-YYYYmmddHHMMSS dirs (preflight-, dns-, http-, etc.) -----
to_local_from_genericid(){
  local gid="$1"
  gid="${gid#*-}"   # strip everything up to first '-'
  date -d "@$(date -ud "${gid:0:4}-${gid:4:2}-${gid:6:2} ${gid:8:2}:${gid:10:2}:${gid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$gid"
}
epoch_from_genericid(){
  local gid="$1"
  gid="${gid#*-}"
  date -ud "${gid:0:4}-${gid:4:2}-${gid:6:2} ${gid:8:2}:${gid:10:2}:${gid:12:2}" +%s 2>/dev/null || echo 0
}

epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

# epoch helper for ISO timestamps in JSON (e.g. 2026-02-22T02:47:04-0500)
epoch_from_iso(){ date -d "$1" +%s 2>/dev/null || echo 0; }

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

# -----------------------------------------------------------------------------
# Filtered view for port apply logs (strip payload noise)
# -----------------------------------------------------------------------------
filter_ports_apply_log(){
  awk '
    BEGIN { skip_next=0 }
    skip_next==1 { skip_next=0; next }
    /^Row debug for port [0-9]+:/ { skip_next=1; next }
    /^Computed body for port [0-9]+:/ { next }
    /^PUT body for port [0-9]+:/ { next }
    { print }
  ' "$1" 2>/dev/null
}

view_ports_apply_log_filtered(){
  local f="$1" ttl="${2:-$(basename "$f")}"
  if [[ ! -s "$f" ]]; then
    dlg --title "$ttl" --msgbox "No content found:\n$f" 8 70
    return
  fi

  local tmp; tmp="$(mktemp)"
  filter_ports_apply_log "$f" >"$tmp" || true
  dlg --title "$ttl (filtered)" --textbox "$tmp" 0 0
  rm -f "$tmp"
}

# -----------------------------------------------------------------------------
# Tiny JSON extractors (no jq dependency)
# -----------------------------------------------------------------------------
json_str(){
  # $1=file $2=key => extracts string value for "key": "value"
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$1" 2>/dev/null | head -n1
}
json_int(){
  # $1=file $2=key => extracts integer value for "key": 123
  sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\\([0-9]\\+\\).*/\\1/p" "$1" 2>/dev/null | head -n1
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
    local j meta when_local when_ep backend state text sstdout spawned_dir rcfile rcval
    for j in "$SCHED_DIR"/job-*; do
      [[ -d "$j" ]] || continue
      meta="$j/job.meta"
      when_local="$(awk -F= '/^scheduled_local=/{print substr($0,index($0,$2))}' "$meta" 2>/dev/null || true)"
      backend="$(awk -F= '/^backend_id=/{print $2}' "$meta" 2>/dev/null || echo "")"
      when_ep="$(epoch_from_human "$when_local")"
      sstdout="$j/logs/stdout.log"
      spawned_dir=""; [[ -s "$sstdout" ]] && spawned_dir="$(extract_spawned_run_dir_from_stdout "$sstdout")"

      if [[ -n "$spawned_dir" && -d "$spawned_dir" ]]; then
        if [[ -f "$spawned_dir/RUNNING" ]]; then
          state="(Scheduled — running)"
        elif [[ -f "$spawned_dir/DONE" ]]; then
          rcval=""
          rcfile="$spawned_dir/EXIT_CODE"
          [[ -f "$rcfile" ]] && rcval="$(cat "$rcfile" 2>/dev/null || true)"
          [[ -n "$rcval" ]] && state="(Scheduled — done, rc=$rcval)" || state="(Scheduled — done)"
        else
          state="(Scheduled — started)"
        fi

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
    dlg --title "IOS-XE Upgrade Logs" --msgbox "No runs found yet.\n\nLooking under:\n$RUNS_DIR" 9 70
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
      M:run-*)
        show_upgrade_run_menu "$path" "Manual: ${sel#M:}" ;;
      S:job-*)
        local st="Scheduled"
        if [[ -f "$path/RUNNING" ]]; then
          st="Scheduled (running)"
        elif [[ -f "$path/DONE" ]]; then
          local rcc=""
          [[ -f "$path/EXIT_CODE" ]] && rcc="$(cat "$path/EXIT_CODE" 2>/dev/null || true)"
          [[ -n "$rcc" ]] && st="Scheduled (done, rc=$rcc)" || st="Scheduled (done)"
        else
          st="Scheduled (started)"
        fi
        show_upgrade_run_menu "$path" "${st}: ${sel#S:}" ;;
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
            meta) view_file "$path/job.meta"         "job.meta"   ;;
            sout) view_file "$path/logs/stdout.log"  "stdout.log" ;;
            serr) view_file "$path/logs/stderr.log"  "stderr.log" ;;
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
    base="$(basename "$d")"
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
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    case "$sel" in
      D:scan-*) show_discovery_run_menu "$path" "Discovery: ${sel#D:}" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Generic "fix" viewer (Preflight / DNS / HTTP)
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

preflight_menu(){ fix_menu "$PREFLIGHT_DIR" "Preflight Runs" "P" "Meraki preflight run" "summary.csv"; }
dnsfix_menu(){     fix_menu "$DNS_DIR"       "DNS Fix Runs"  "N" "DNS remediation run"  "dnsfix.csv"; }
httpfix_menu(){    fix_menu "$HTTP_DIR"      "HTTP Client Fix Runs" "H" "HTTP client source-if remediation run" "httpfix.csv"; }

# ---------------------------------------------------------------------------
# Meraki "create network" runs (createnetwork-YYYYmmddHHMMSS)
# ---------------------------------------------------------------------------
show_createnet_run_menu(){
  local rdir="$1" title="$2"

  while true; do
    local items=()
    local create_log="$rdir/meraki_create_network.log"
    local created_csv="$rdir/created_networks.csv"
    local devdir="$rdir/devlogs"

    items+=("log" "meraki_create_network.log")
    items+=("csv" "created_networks.csv")
    if [[ -d "$devdir" ]]; then
      items+=("dev" "Per-run dev logs")
    fi
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      log)  view_file "$create_log"  "meraki_create_network.log" ;;
      csv)  view_file "$created_csv" "created_networks.csv"      ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/* 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Per-run dev logs" --msgbox "No dev logs found in:\n$devdir" 9 70
          continue
        fi
        local devitems=() d
        for d in "${devs[@]}"; do devitems+=("$d" "$(basename "$d")"); done
        dlg --title "Create-network dev logs" --menu "Pick a log to view" 20 120 12 "${devitems[@]}"
        local rc2=$DIALOG_RC
        (( rc2 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
    esac
  done
}

createnetworks_menu(){
  if [[ ! -d "$CREATENET_DIR" ]]; then
    dlg --title "Created Networks" --msgbox "No create-network runs found yet.\n\nExpected directory:\n$CREATENET_DIR" 9 80
    return
  fi

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$CREATENET_DIR"/createnetwork-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(epoch_from_genericid "$base")"
    loc="$(to_local_from_genericid "$base")"
    rows+=("${ep}|CN:${base}|${loc}  (Meraki create-network run)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Created Networks" --msgbox "No createnetwork-* runs found under:\n$CREATENET_DIR" 9 80
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
    dlg --title "Created Networks" --menu "Select a create-network run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT" path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_createnet_run_menu "$path" "Created Networks: ${sel#CN:}"
  done
}

# ---------------------------------------------------------------------------
# Search by IP / text across runs
# ---------------------------------------------------------------------------
ip_search_menu(){
  while true; do
    dlg --title "Search logs by IP / text" \
        --inputbox "Enter an IP address or search string:\n(Cancel or empty input to go back.)" 10 70 ""
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local needle="$DOUT"
    needle="$(echo "$needle" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$needle" ]] && return

    local term_lines term_cols menu_w=140
    if read -r term_lines term_cols < <(stty size 2>/dev/null); then
      menu_w=$(( term_cols - 4 ))
      (( menu_w < 100 )) && menu_w=100
      (( menu_w > 200 )) && menu_w=200
    fi

    local tmp; tmp="$(mktemp)"
    grep -R -n \
      --include='*.log' \
      --include='*.csv' \
      --include='*.json' \
      --include='*.status' \
      --include='*.env' \
      -e "$needle" "$RUNS_DIR" >"$tmp" 2>/dev/null || true

    if [[ ! -s "$tmp" ]]; then
      dlg --title "Search results" --msgbox "No matches found for:\n$needle\n\nSearched under:\n$RUNS_DIR" 10 70
      rm -f "$tmp"
      continue
    fi

    local -a FILES LINES MENU_ITEMS
    local idx=0
    while IFS=: read -r file line rest; do
      ((idx++))
      FILES[idx]="$file"
      LINES[idx]="$line"
      local rel="${file#$ROOT/}"
      local max_snip=$(( menu_w - 35 ))
      (( max_snip < 40 )) && max_snip=40
      local snippet
      snippet="$(echo "$rest" | sed 's/^[[:space:]]*//' | cut -c1-"$max_snip")"
      MENU_ITEMS+=( "$idx" "$rel:$line: $snippet" )
      (( idx >= 99 )) && break
    done <"$tmp"
    rm -f "$tmp"

    while true; do
      dlg --title "Search results for: $needle" \
          --menu "Showing first $idx matches. Select one to view context." 22 "$menu_w" 14 "${MENU_ITEMS[@]}"
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
# Meraki switch-claim inventory viewer (meraki_memory/*.json)
# ---------------------------------------------------------------------------
meraki_memory_build_csv(){
  local f
  echo "timestamp,run_id,ip,cloud_id,serial,model,device_name,org_name,network_name,status,ssh_status,stack_count,member_index,stack_base_name,file"

  shopt -s nullglob
  for f in "$MERAKI_MEMORY_DIR"/*.json; do
    [[ -f "$f" ]] || continue

    local ts rid ip cloud serial model dev org net status ssh sc mi sbn
    ts="$(json_str "$f" "timestamp")"
    rid="$(json_str "$f" "run_id")"
    ip="$(json_str "$f" "ip")"
    cloud="$(json_str "$f" "cloud_id")"
    serial="$(json_str "$f" "serial")"
    model="$(json_str "$f" "model")"
    dev="$(json_str "$f" "device_name")"
    org="$(json_str "$f" "org_name")"
    net="$(json_str "$f" "network_name")"
    status="$(json_str "$f" "status")"
    ssh="$(json_str "$f" "ssh_status")"
    sc="$(json_int "$f" "stack_count")"
    mi="$(json_int "$f" "member_index")"
    sbn="$(json_str "$f" "stack_base_name")"

    esc(){ printf '%s' "$1" | sed 's/"/""/g'; }

    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n" \
      "$(esc "$ts")" "$(esc "$rid")" "$(esc "$ip")" "$(esc "$cloud")" "$(esc "$serial")" "$(esc "$model")" \
      "$(esc "$dev")" "$(esc "$org")" "$(esc "$net")" "$(esc "$status")" "$(esc "$ssh")" \
      "$(esc "${sc:-}")" "$(esc "${mi:-}")" "$(esc "$sbn")" "$(esc "$f")"
  done
  shopt -u nullglob
}

meraki_memory_device_summary(){
  local f="$1"
  local ts rid ip cloud serial model dev org net addr status ssh sc mi sbn
  ts="$(json_str "$f" "timestamp")"
  rid="$(json_str "$f" "run_id")"
  ip="$(json_str "$f" "ip")"
  cloud="$(json_str "$f" "cloud_id")"
  serial="$(json_str "$f" "serial")"
  model="$(json_str "$f" "model")"
  dev="$(json_str "$f" "device_name")"
  org="$(json_str "$f" "org_name")"
  net="$(json_str "$f" "network_name")"
  addr="$(json_str "$f" "network_address")"
  status="$(json_str "$f" "status")"
  ssh="$(json_str "$f" "ssh_status")"
  sc="$(json_int "$f" "stack_count")"
  mi="$(json_int "$f" "member_index")"
  sbn="$(json_str "$f" "stack_base_name")"

  cat <<EOF
Meraki Claim Memory Entry

Timestamp:     ${ts:-}
Run ID:        ${rid:-}
IP:            ${ip:-}
Cloud ID:      ${cloud:-}
Serial:        ${serial:-}
Model:         ${model:-}
Device Name:   ${dev:-}

Org:           ${org:-}
Network:       ${net:-}
Address:       ${addr:-}

Status:        ${status:-}
SSH Status:    ${ssh:-}

Stack Count:   ${sc:-}
Member Index:  ${mi:-}
Stack Base:    ${sbn:-}

File:          $f
EOF
}

show_meraki_memory_entry_menu(){
  local json_file="$1" title="$2"

  while true; do
    local items=()
    items+=("raw"  "View raw JSON")
    items+=("sum"  "View summary")
    items+=("path" "Show file path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 16 90 8 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      raw)  view_file "$json_file" "$(basename "$json_file")" ;;
      sum)
        local tmp; tmp="$(mktemp)"
        meraki_memory_device_summary "$json_file" >"$tmp"
        dlg --title "Summary: $(basename "$json_file")" --textbox "$tmp" 0 0
        rm -f "$tmp"
        ;;
      path) dlg --title "File path" --msgbox "$json_file" 7 80 ;;
      back) return ;;
    esac
  done
}

meraki_claims_menu(){
  if [[ ! -d "$MERAKI_MEMORY_DIR" ]]; then
    dlg --title "Meraki SwitchClaims" --msgbox "No meraki_memory directory found.\n\nExpected:\n$MERAKI_MEMORY_DIR" 9 80
    return
  fi

  local rows=() f
  shopt -s nullglob
  for f in "$MERAKI_MEMORY_DIR"/*.json; do
    [[ -f "$f" ]] || continue
    local ts ep ip cloud dev net status
    ts="$(json_str "$f" "timestamp")"
    ep="$(epoch_from_iso "$ts")"
    ip="$(json_str "$f" "ip")"
    cloud="$(json_str "$f" "cloud_id")"
    dev="$(json_str "$f" "device_name")"
    net="$(json_str "$f" "network_name")"
    status="$(json_str "$f" "status")"
    [[ -z "$cloud" ]] && cloud="$(basename "$f" .json)"
    rows+=("${ep}|${cloud}|${ts}|${ip}|${dev}|${net}|${status}|${f}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Meraki SwitchClaims" --msgbox "No *.json entries found in:\n$MERAKI_MEMORY_DIR" 9 80
    return
  fi

  mapfile -t sorted < <(printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr)

  local choices=()
  choices+=("ALL" "Compiled summary (all devices)")

  local line cloud ts ip dev net status
  for line in "${sorted[@]}"; do
    cloud="$(cut -d'|' -f2 <<<"$line")"
    ts="$(cut -d'|' -f3 <<<"$line")"
    ip="$(cut -d'|' -f4 <<<"$line")"
    dev="$(cut -d'|' -f5 <<<"$line")"
    net="$(cut -d'|' -f6 <<<"$line")"
    status="$(cut -d'|' -f7 <<<"$line")"
    choices+=("$cloud" "${ts}  ${ip}  ${dev}  (${net})  [${status}]")
  done

  while true; do
    dlg --title "Meraki SwitchClaims" \
        --menu "Inventory Root: $MERAKI_MEMORY_DIR\n\nSelect an entry:" 24 130 14 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    if [[ "$sel" == "ALL" ]]; then
      local tmp; tmp="$(mktemp)"
      meraki_memory_build_csv >"$tmp"
      dlg --title "Compiled Claim Summary (CSV)" --textbox "$tmp" 0 0
      rm -f "$tmp"
      continue
    fi

    local path=""
    for line in "${sorted[@]}"; do
      cloud="$(cut -d'|' -f2 <<<"$line")"
      [[ "$cloud" == "$sel" ]] || continue
      path="$(cut -d'|' -f8- <<<"$line")"
      break
    done

    [[ -n "$path" && -f "$path" ]] || {
      dlg --title "Not found" --msgbox "Could not locate JSON for:\n$sel" 8 60
      continue
    }

    show_meraki_memory_entry_menu "$path" "Claim: $sel"
  done
}

# ---------------------------------------------------------------------------
# Port Migration viewer (runs/port_migration/migrate-*)
# ---------------------------------------------------------------------------
portmig_epoch_from_id(){
  local mid="$1"; mid="${mid#migrate-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}
portmig_local_from_id(){
  local mid="$1"; mid="${mid#migrate-}"
  date -d "@$(date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$mid"
}

show_portmig_run_menu(){
  local rdir="$1" title="$2"
  local devdir="$rdir/devlogs"
  local portsdir="$rdir/ports"

  while true; do
    local items=()
    [[ -d "$devdir" ]] && items+=("dev" "Device logs (devlogs/)")
    [[ -d "$portsdir" ]] && items+=("ports" "Port diffs/intents (ports/)")
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 18 90 10 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      dev)
        if [[ ! -d "$devdir" ]]; then
          dlg --title "Device logs" --msgbox "No devlogs directory found:\n$devdir" 8 70
          continue
        fi
        mapfile -t logs < <(ls -1 "$devdir"/*.log 2>/dev/null || true)
        if ((${#logs[@]}==0)); then
          dlg --title "Device logs" --msgbox "No *.log files found in:\n$devdir" 9 70
          continue
        fi
        local devitems=() f base
        for f in "${logs[@]}"; do
          base="$(basename "$f")"
          devitems+=("$f" "$base")
        done
        while true; do
          dlg --title "Port Migration Device Logs" --menu "Pick a log to view" 22 120 14 "${devitems[@]}"
          local rc2=$DIALOG_RC
          [[ $rc2 -ne 0 ]] && break

          local pick="$DOUT"
          local b; b="$(basename "$pick")"
          if [[ "$b" == *_ports_apply.log ]]; then
            view_ports_apply_log_filtered "$pick" "$b"
          else
            view_file "$pick" "$b"
          fi
        done
        ;;
      ports)
        if [[ ! -d "$portsdir" ]]; then
          dlg --title "Ports" --msgbox "No ports directory found:\n$portsdir" 8 70
          continue
        fi
        mapfile -t pf < <(ls -1 "$portsdir"/* 2>/dev/null || true)
        if ((${#pf[@]}==0)); then
          dlg --title "Ports" --msgbox "No files found in:\n$portsdir" 8 70
          continue
        fi
        local pitems=() p
        for p in "${pf[@]}"; do pitems+=("$p" "$(basename "$p")"); done
        dlg --title "Ports" --menu "Pick a file to view" 22 120 14 "${pitems[@]}"
        local rc3=$DIALOG_RC
        (( rc3 == 0 )) && view_file "$DOUT" "$(basename "$DOUT")"
        ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
    esac
  done
}

port_migration_menu(){
  if [[ ! -d "$PORT_MIG_DIR" ]]; then
    dlg --title "Port Migration Runs" --msgbox "No port migration runs found yet.\n\nExpected directory:\n$PORT_MIG_DIR" 9 80
    return
  fi

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$PORT_MIG_DIR"/migrate-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(portmig_epoch_from_id "$base")"
    loc="$(portmig_local_from_id "$base")"
    rows+=("${ep}|PM:${base}|${loc}  (Port migration)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Port Migration Runs" --msgbox "No migrate-* runs found under:\n$PORT_MIG_DIR" 9 80
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
    dlg --title "Port Migration Runs" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_portmig_run_menu "$path" "Port Migration: ${sel#PM:}"
  done
}

# ---------------------------------------------------------------------------
# NEW: Management IP Migration viewer (runs/mgmt_ip/mgmtip-*)
# ---------------------------------------------------------------------------
mgmtip_epoch_from_id(){
  # mgmtip-YYYYmmddHHMMSS
  local mid="$1"; mid="${mid#mgmtip-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}
mgmtip_local_from_id(){
  local mid="$1"; mid="${mid#mgmtip-}"
  date -d "@$(date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$mid"
}

show_mgmtip_run_menu(){
  local rdir="$1" title="$2"

  local actions="$rdir/actions.log"
  local items="$rdir/items.jsonl"
  local report="$rdir/report.json"
  local stats="$rdir/stats.env"
  local swidx="$rdir/switch_index.tsv"
  local grpidx="$rdir/group_index.tsv"

  while true; do
    local menu=()

    [[ -s "$actions" ]] && menu+=("act"  "actions.log")
    [[ -s "$report"  ]] && menu+=("rep"  "report.json")
    [[ -s "$items"   ]] && menu+=("it"   "items.jsonl")
    [[ -s "$stats"   ]] && menu+=("st"   "stats.env")
    [[ -s "$swidx"   ]] && menu+=("sw"   "switch_index.tsv")
    [[ -s "$grpidx"  ]] && menu+=("gr"   "group_index.tsv")

    menu+=("path" "Show run folder path")
    menu+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${menu[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      act)  view_file "$actions" "actions.log" ;;
      rep)  view_file "$report"  "report.json" ;;
      it)   view_file "$items"   "items.jsonl" ;;
      st)   view_file "$stats"   "stats.env" ;;
      sw)   view_file "$swidx"   "switch_index.tsv" ;;
      gr)   view_file "$grpidx"  "group_index.tsv" ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 80 ;;
      back) return ;;
    esac
  done
}

mgmt_ip_menu(){
  if [[ ! -d "$MGMTIP_DIR" ]]; then
    dlg --title "Management IP Migration" --msgbox "No mgmt_ip runs found yet.\n\nExpected directory:\n$MGMTIP_DIR" 9 80
    return
  fi

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$MGMTIP_DIR"/mgmtip-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    [[ "$base" == "latest" ]] && continue
    ep="$(mgmtip_epoch_from_id "$base")"
    loc="$(mgmtip_local_from_id "$base")"
    rows+=("${ep}|MI:${base}|${loc}  (Mgmt IP migration)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Management IP Migration" --msgbox "No mgmtip-* runs found under:\n$MGMTIP_DIR" 9 80
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
    dlg --title "Management IP Migration" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_mgmtip_run_menu "$path" "Management IP Migration: ${sel#MI:}"
  done
}

# ---------------------------------------------------------------------------
# Top-level main menu
# ---------------------------------------------------------------------------
main(){
  while true; do
    local MENU_ITEMS=()

    MENU_ITEMS+=("1"  "IOS-XE Upgrade Logs"           "$(color_help "${HELP_TEXT[1]}")")
    MENU_ITEMS+=("2"  "Discovery Scans"               "$(color_help "${HELP_TEXT[2]}")")
    MENU_ITEMS+=("3"  "Preflight Runs"                "$(color_help "${HELP_TEXT[3]}")")
    MENU_ITEMS+=("4"  "Meraki SwitchClaims"           "$(color_help "${HELP_TEXT[4]}")")
    MENU_ITEMS+=("5"  "DNS Fix Runs"                  "$(color_help "${HELP_TEXT[5]}")")
    MENU_ITEMS+=("6"  "HTTP Client Fix Runs"          "$(color_help "${HELP_TEXT[6]}")")
    MENU_ITEMS+=("7"  "Search by IP / text"           "$(color_help "${HELP_TEXT[7]}")")
    MENU_ITEMS+=("8"  "Created Networks"              "$(color_help "${HELP_TEXT[8]}")")
    MENU_ITEMS+=("9"  "Port Migration Runs"           "$(color_help "${HELP_TEXT[9]}")")
    MENU_ITEMS+=("10" "Management IP Migration"       "$(color_help "${HELP_TEXT[10]}")")
    MENU_ITEMS+=("0"  "Exit"                          "$(color_help "${HELP_TEXT[0]}")")

    local CHOICE
    CHOICE=$(
      dialog --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "Logging & Reports" \
        --menu "Log Root: $ROOT\n\nSelect an option:" 24 95 12 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || break

    case "$CHOICE" in
      1)  iosxe_menu           ;;
      2)  discovery_menu       ;;
      3)  preflight_menu       ;;
      4)  meraki_claims_menu   ;;
      5)  dnsfix_menu          ;;
      6)  httpfix_menu         ;;
      7)  ip_search_menu       ;;
      8)  createnetworks_menu  ;;
      9)  port_migration_menu  ;;
      10) mgmt_ip_menu         ;;
      0)  break                ;;
    esac
  done
}

main