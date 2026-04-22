#!/usr/bin/env bash
# unified_logs.sh — Dialog viewer for CAT admin logging / reports
#
# Includes:
#   • Discovery scans
#   • Catalyst/Meraki switch mapping runs
#   • Meraki probe runs
#   • Search by IP / text
#   • Port migration runs
#   • Management IP migration runs
#   • Uplink decision / suggestion runs

# NOTE: no -e here on purpose; we want Cancel/Esc to be handled manually.
set -Euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need sed; need date; need grep; need cut; need sort; need tr

# -----------------------------------------------------------------------------
# Root selection policy:
#   1) If CAT_ADMIN_ROOT is set, use it.
#   2) Else if /root/.cat_admin exists, use it.
#   3) Else fall back to the directory containing this script.
# -----------------------------------------------------------------------------
SCRIPT_ROOT="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

if [[ -n "${CAT_ADMIN_ROOT:-}" ]]; then
  ROOT="$CAT_ADMIN_ROOT"
elif [[ -d /root/.cat_admin ]]; then
  ROOT="/root/.cat_admin"
else
  ROOT="$SCRIPT_ROOT"
fi

RUNS_DIR="$ROOT/runs"

DISC_ROOT="$RUNS_DIR/discoveryscans"
MAPPINGS_DIR="$RUNS_DIR/mappings"
MERAKI_PROBE_DIR="$RUNS_DIR/meraki_probe"
PORT_MIG_DIR="$RUNS_DIR/port_migration"
MGMTIP_DIR="$RUNS_DIR/mgmt_ip"
UPLINK_DIR="$RUNS_DIR/uplink_suggest"

BACKTITLE="${BACKTITLE:-Main Menu}"

HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"   # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"

declare -A HELP_TEXT=(
  [1]="View discovery scan results and device probe logs."
  [2]="View Catalyst-to-Meraki switch mapping runs, summaries, and API logs."
  [3]="View Meraki probe runs and captured inventory/network data."
  [4]="View port migration runs (devlogs + port diffs + intent files)."
  [5]="View management IP migration runs (actions/items/report/stats/index)."
  [6]="View uplink decision runs, batch review logs, manifests, reports, previews, and JSON artifacts."
  [7]="Search across CAT admin logs by IP address or text."
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
  DIALOG_RC=$?
  DOUT=""
  [[ -s "$_t" ]] && DOUT="$(cat "$_t")"
  rm -f "$_t"
  return 0
}

view_file(){
  local f="$1" ttl="${2:-File}"
  if [[ -s "$f" ]]; then
    dlg --title "$ttl" --textbox "$f" 0 0
  else
    dlg --title "$ttl" --msgbox "No content found:\n$f" 8 70
  fi
}

epoch_from_genericid(){
  local gid="$1"
  gid="${gid#*-}"
  date -ud "${gid:0:4}-${gid:4:2}-${gid:6:2} ${gid:8:2}:${gid:10:2}:${gid:12:2}" +%s 2>/dev/null || echo 0
}
to_local_from_genericid(){
  local gid="$1"
  gid="${gid#*-}"
  date -d "@$(date -ud "${gid:0:4}-${gid:4:2}-${gid:6:2} ${gid:8:2}:${gid:10:2}:${gid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$gid"
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
# helper: build short picker menu from file list
# outputs arrays by nameref:
#   $1 = input file array name
#   $2 = output menu items array name
#   $3 = output pick paths array name
# -----------------------------------------------------------------------------
build_short_file_menu(){
  local in_name="$1"
  local items_name="$2"
  local picks_name="$3"

  declare -n _in="$in_name"
  declare -n _items="$items_name"
  declare -n _picks="$picks_name"

  _items=()
  _picks=()

  local idx=1 f
  for f in "${_in[@]}"; do
    _picks[idx]="$f"
    _items+=("$idx" "$(basename "$f")")
    ((idx++))
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
    local devdir="$rdir/devlogs"

    [[ -s "$ui" ]] && items+=("ui" "Overview (ui.status)")
    [[ -e "$disc_csv" ]] && items+=("disc_csv" "discovery_results.csv")
    [[ -e "$disc_json" ]] && items+=("disc_json" "discovery_results.json")
    [[ -d "$devdir" ]] && items+=("dev" "Per-device probe logs")
    items+=("path" "Show scan folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      ui)        view_file "$ui"        "ui.status" ;;
      disc_csv)  view_file "$disc_csv"  "discovery_results.csv" ;;
      disc_json) view_file "$disc_json" "discovery_results.json" ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/*.log 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Device logs" --msgbox "No device logs found." 7 50
          continue
        fi
        local devitems=() pick_paths=()
        build_short_file_menu devs devitems pick_paths
        dlg --title "Discovery device logs" --menu "Pick a device log" 20 110 12 "${devitems[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      path) dlg --title "Scan path" --msgbox "$rdir" 7 70 ;;
      back) return ;;
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
    ep="$(epoch_from_genericid "$base")"
    loc="$(to_local_from_genericid "$base")"
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

    show_discovery_run_menu "$path" "Discovery: ${sel#D:}"
  done
}

# ---------------------------------------------------------------------------
# Mapping runs viewer
# ---------------------------------------------------------------------------
show_mapping_run_menu(){
  local rdir="$1" title="$2"

  while true; do
    local items=()
    local devdir="$rdir/devlogs"
    local mapping_json="$rdir/mapping.json"
    local mapping_summary="$rdir/mapping_summary.txt"
    local api_log="$rdir/meraki_api.log"
    local status_log="$rdir/status.log"
    local map_log="$rdir/map.log"

    [[ -s "$mapping_json" ]] && items+=("mjson" "mapping.json")
    [[ -s "$mapping_summary" ]] && items+=("msum" "mapping_summary.txt")
    [[ -s "$api_log" ]] && items+=("api" "meraki_api.log")
    [[ -s "$status_log" ]] && items+=("status" "status.log")
    [[ -s "$map_log" ]] && items+=("maplog" "map.log")
    [[ -d "$devdir" ]] && items+=("dev" "Dev logs / captured API data")
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      mjson)  view_file "$mapping_json" "mapping.json" ;;
      msum)   view_file "$mapping_summary" "mapping_summary.txt" ;;
      api)    view_file "$api_log" "meraki_api.log" ;;
      status) view_file "$status_log" "status.log" ;;
      maplog) view_file "$map_log" "map.log" ;;
      dev)
        mapfile -t devs < <(ls -1 "$devdir"/* 2>/dev/null || true)
        if ((${#devs[@]}==0)); then
          dlg --title "Dev logs" --msgbox "No files found in:\n$devdir" 8 70
          continue
        fi
        local devitems=() pick_paths=()
        build_short_file_menu devs devitems pick_paths
        dlg --title "Mapping dev logs" --menu "Pick a file to view" 22 110 14 "${devitems[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      path) dlg --title "Run path" --msgbox "$rdir" 7 80 ;;
      back) return ;;
    esac
  done
}

mappings_menu(){
  if [[ ! -d "$MAPPINGS_DIR" ]]; then
    dlg --title "Catalyst/Meraki Switch Mapping" --msgbox "No mapping runs found yet.\n\nExpected directory:\n$MAPPINGS_DIR" 9 80
    return
  fi

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$MAPPINGS_DIR"/map-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(epoch_from_genericid "$base")"
    loc="$(to_local_from_genericid "$base")"
    rows+=("${ep}|MP:${base}|${loc}  (Switch mapping run)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Catalyst/Meraki Switch Mapping" --msgbox "No map-* runs found under:\n$MAPPINGS_DIR" 9 80
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
    dlg --title "Catalyst/Meraki Switch Mapping" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_mapping_run_menu "$path" "Mapping: ${sel#MP:}"
  done
}

# ---------------------------------------------------------------------------
# Meraki probe viewer
# ---------------------------------------------------------------------------
show_meraki_probe_run_menu(){
  local rdir="$1" title="$2"

  while true; do
    local items=()
    local probe_log="$rdir/probe.log"

    [[ -s "$probe_log" ]] && items+=("log" "probe.log")

    local f extra_files=()
    for f in "$rdir"/*; do
      [[ -f "$f" ]] || continue
      [[ "$(basename "$f")" == "probe.log" ]] && continue
      extra_files+=("$f")
    done

    [[ ${#extra_files[@]} -gt 0 ]] && items+=("files" "Other files")
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 22 110 14 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      log)
        view_file "$probe_log" "probe.log"
        ;;
      files)
        local fileitems=() pick_paths=()
        build_short_file_menu extra_files fileitems pick_paths
        dlg --title "Meraki Probe Files" --menu "Pick a file to view" 22 110 14 "${fileitems[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      path)
        dlg --title "Run path" --msgbox "$rdir" 7 80
        ;;
      back)
        return
        ;;
    esac
  done
}

meraki_probe_menu(){
  if [[ ! -d "$MERAKI_PROBE_DIR" ]]; then
    dlg --title "Meraki Probe Runs" --msgbox "No Meraki probe runs found yet.\n\nExpected directory:\n$MERAKI_PROBE_DIR" 9 80
    return
  fi

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$MERAKI_PROBE_DIR"/probe-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(epoch_from_genericid "$base")"
    loc="$(to_local_from_genericid "$base")"
    rows+=("${ep}|PR:${base}|${loc}  (Meraki probe run)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Meraki Probe Runs" --msgbox "No probe-* runs found under:\n$MERAKI_PROBE_DIR" 9 80
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
    dlg --title "Meraki Probe Runs" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_meraki_probe_run_menu "$path" "Meraki Probe: ${sel#PR:}"
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
      --include='*.jsonl' \
      --include='*.txt' \
      --include='*.status' \
      --include='*.env' \
      --include='*.tsv' \
      --include='*.cfg' \
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
# Port Migration viewer (runs/port_migration/port-mig-*)
# ---------------------------------------------------------------------------
portmig_epoch_from_id(){
  local mid="$1"; mid="${mid#port-mig-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}
portmig_local_from_id(){
  local mid="$1"; mid="${mid#port-mig-}"
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
        local devitems=() pick_paths=()
        build_short_file_menu logs devitems pick_paths
        while true; do
          dlg --title "Port Migration Device Logs" --menu "Pick a log to view" 22 110 14 "${devitems[@]}"
          local rc2=$DIALOG_RC
          [[ $rc2 -ne 0 ]] && break

          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] || continue

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
        local pitems=() pick_paths=()
        build_short_file_menu pf pitems pick_paths
        dlg --title "Ports" --menu "Pick a file to view" 22 110 14 "${pitems[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
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
  for d in "$PORT_MIG_DIR"/port-mig-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    ep="$(portmig_epoch_from_id "$base")"
    loc="$(portmig_local_from_id "$base")"
    rows+=("${ep}|PM:${base}|${loc}  (Port migration)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Port Migration Runs" --msgbox "No port-mig-* runs found under:\n$PORT_MIG_DIR" 9 80
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
# Management IP Migration viewer (runs/mgmt_ip/mgmtip-*)
# ---------------------------------------------------------------------------
mgmtip_epoch_from_id(){
  local mid="$1"
  mid="${mid#mgmtip-}"

  date -d "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}

mgmtip_local_from_id(){
  local mid="$1"
  mid="${mid#mgmtip-}"

  date -d "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" '+%F %T %Z' 2>/dev/null || echo "$mid"
}

show_mgmtip_run_menu(){
  local rdir="$1" title="$2"

  local actions="$rdir/actions.log"
  local items="$rdir/items.jsonl"
  local report="$rdir/report.json"
  local stats="$rdir/stats.env"
  local swidx="$rdir/switch_index.tsv"

  while true; do
    local menu=()

    # ---- Core files ----
    [[ -s "$actions" ]] && menu+=("act"  "actions.log (timeline)")
    [[ -s "$report"  ]] && menu+=("rep"  "report.json (summary)")
    [[ -s "$items"   ]] && menu+=("it"   "items.jsonl (per-device)")
    [[ -s "$stats"   ]] && menu+=("st"   "stats.env (counts)")
    [[ -s "$swidx"   ]] && menu+=("sw"   "switch_index.tsv")

    # ---- Dynamic: curl outputs ----
    mapfile -t CURL_FILES < <(ls -1 "$rdir"/curl_*.out 2>/dev/null || true)
    if ((${#CURL_FILES[@]} > 0)); then
      menu+=("curl" "Meraki API responses (curl_*.out)")
    fi

    # ---- Dynamic: DHCP cutover logs ----
    mapfile -t DHCP_FILES < <(ls -1 "$rdir"/source_dhcp_*.out 2>/dev/null || true)
    if ((${#DHCP_FILES[@]} > 0)); then
      menu+=("dhcp" "Source DHCP cutover logs")
    fi

    # ---- Catch-all ----
    mapfile -t OTHER_FILES < <(
      find "$rdir" -maxdepth 1 -type f \
        ! -name "actions.log" \
        ! -name "items.jsonl" \
        ! -name "report.json" \
        ! -name "stats.env" \
        ! -name "switch_index.tsv" \
        ! -name "curl_*.out" \
        ! -name "source_dhcp_*.out" \
        2>/dev/null || true
    )
    if ((${#OTHER_FILES[@]} > 0)); then
      menu+=("other" "Other files")
    fi

    menu+=("path" "Show run folder path")
    menu+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 22 110 14 "${menu[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      act) view_file "$actions" "actions.log" ;;
      rep) view_file "$report"  "report.json" ;;
      it)  view_file "$items"   "items.jsonl" ;;
      st)  view_file "$stats"   "stats.env" ;;
      sw)  view_file "$swidx"   "switch_index.tsv" ;;

      curl)
        local items2=() pick_paths=()
        build_short_file_menu CURL_FILES items2 pick_paths
        dlg --title "Meraki API Responses" --menu "Select a file" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;

      dhcp)
        if ((${#DHCP_FILES[@]}==0)); then
          dlg --title "DHCP logs" --msgbox "No DHCP logs found." 7 60
          continue
        fi

        local items2=() pick_paths=()
        build_short_file_menu DHCP_FILES items2 pick_paths

        dlg --title "DHCP Cutover Logs" --menu "Select a device log" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] || continue

          local tmp; tmp="$(mktemp)"

          # ---- FILTER THE NOISE ----
          awk '
            !/terminal length 0/ &&
            !/StrictHostKeyChecking/ &&
            !/Warning: Permanently added/ &&
            !/client_loop:/ &&
            !/Broken pipe/ &&
            !/^$/ {
              print
            }
          ' "$pick" > "$tmp"

          dlg --title "$(basename "$pick") (cleaned)" --textbox "$tmp" 0 0
          rm -f "$tmp"
        fi
        ;;

      other)
        local items2=() pick_paths=()
        build_short_file_menu OTHER_FILES items2 pick_paths
        dlg --title "Other Files" --menu "Select a file" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;

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
# Uplink Suggest / Decision viewer (runs/uplink_suggest/run-*)
# ---------------------------------------------------------------------------
uplink_epoch_from_id(){
  local mid="$1"; mid="${mid#run-}"
  date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s 2>/dev/null || echo 0
}
uplink_local_from_id(){
  local mid="$1"; mid="${mid#run-}"
  date -d "@$(date -ud "${mid:0:4}-${mid:4:2}-${mid:6:2} ${mid:8:2}:${mid:10:2}:${mid:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$mid"
}
uplink_batch_epoch_from_name(){
  local n="$1"
  local ts
  ts="$(sed -E 's/^batch_uplink_review_([0-9]{8})_([0-9]{6})\.log$/\1\2/' <<<"$n")"
  date -ud "${ts:0:4}-${ts:4:2}-${ts:6:2} ${ts:8:2}:${ts:10:2}:${ts:12:2}" +%s 2>/dev/null || echo 0
}
uplink_batch_local_from_name(){
  local n="$1"
  local ts
  ts="$(sed -E 's/^batch_uplink_review_([0-9]{8})_([0-9]{6})\.log$/\1\2/' <<<"$n")"
  date -d "@$(date -ud "${ts:0:4}-${ts:4:2}-${ts:6:2} ${ts:8:2}:${ts:10:2}:${ts:12:2}" +%s)" \
       '+%F %T %Z' 2>/dev/null || echo "$n"
}

show_uplink_run_menu(){
  local rdir="$1" title="$2"

  while true; do
    local items=()
    local run_summary="$rdir/run_summary.txt"
    local manifest="$rdir/normalized_manifest.json"

    [[ -s "$run_summary" ]] && items+=("summary" "run_summary.txt")
    [[ -s "$manifest" ]] && items+=("manifest" "normalized_manifest.json")
    items+=("reports" "Per-switch/member reports")
    items+=("json" "JSON artifacts")
    items+=("preview" "Preview configs")
    items+=("path" "Show run folder path")
    items+=("back" "Back")

    dlg --title "$title" --menu "Choose what to view" 20 100 12 "${items[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      summary)
        view_file "$run_summary" "run_summary.txt"
        ;;
      manifest)
        view_file "$manifest" "normalized_manifest.json"
        ;;
      reports)
        mapfile -t files < <(ls -1 "$rdir"/report_*.txt 2>/dev/null || true)
        if ((${#files[@]}==0)); then
          dlg --title "Reports" --msgbox "No report_*.txt files found." 7 60
          continue
        fi

        local items2=() pick_paths=()
        build_short_file_menu files items2 pick_paths
        dlg --title "Uplink Reports" --menu "Pick a report to view" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      json)
        mapfile -t files < <(ls -1 \
          "$rdir"/raw_ports_*.json \
          "$rdir"/source_*.json \
          "$rdir"/suggest_*.json \
          "$rdir"/target_*.json \
          "$rdir"/target_stage1_*.json \
          2>/dev/null | sort || true)
        if ((${#files[@]}==0)); then
          dlg --title "JSON artifacts" --msgbox "No uplink JSON artifacts found." 7 60
          continue
        fi

        local items2=() pick_paths=()
        build_short_file_menu files items2 pick_paths
        dlg --title "Uplink JSON Artifacts" --menu "Pick a JSON file to view" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      preview)
        mapfile -t files < <(ls -1 "$rdir"/preview_*.cfg 2>/dev/null || true)
        if ((${#files[@]}==0)); then
          dlg --title "Preview configs" --msgbox "No preview_*.cfg files found." 7 60
          continue
        fi

        local items2=() pick_paths=()
        build_short_file_menu files items2 pick_paths
        dlg --title "Preview Configs" --menu "Pick a preview config to view" 22 110 14 "${items2[@]}"
        if (( DIALOG_RC == 0 )); then
          local pick="${pick_paths[$DOUT]:-}"
          [[ -n "$pick" ]] && view_file "$pick" "$(basename "$pick")"
        fi
        ;;
      path)
        dlg --title "Run path" --msgbox "$rdir" 7 80
        ;;
      back)
        return
        ;;
    esac
  done
}

uplink_batch_logs_menu(){
  [[ -d "$UPLINK_DIR" ]] || {
    dlg --title "Uplink Batch Review Logs" --msgbox "No uplink_suggest directory found.\n\nExpected directory:\n$UPLINK_DIR" 9 80
    return
  }

  local rows=() f base ep loc
  shopt -s nullglob
  for f in "$UPLINK_DIR"/batch_uplink_review_*.log; do
    [[ -f "$f" ]] || continue
    base="$(basename "$f")"
    ep="$(uplink_batch_epoch_from_name "$base")"
    loc="$(uplink_batch_local_from_name "$base")"
    rows+=("${ep}|UB:${base}|${loc}  (Batch uplink review log)|${f}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Uplink Batch Review Logs" --msgbox "No batch_uplink_review_*.log files found under:\n$UPLINK_DIR" 9 85
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
    dlg --title "Uplink Batch Review Logs" --menu "Select a batch log" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    view_file "$path" "$(basename "$path")"
  done
}

uplink_runs_menu(){
  [[ -d "$UPLINK_DIR" ]] || {
    dlg --title "Uplink Decision Runs" --msgbox "No uplink_suggest directory found.\n\nExpected directory:\n$UPLINK_DIR" 9 80
    return
  }

  local rows=() d base ep loc
  shopt -s nullglob
  for d in "$UPLINK_DIR"/run-*; do
    [[ -d "$d" ]] || continue
    base="$(basename "$d")"
    [[ "$base" == "latest" ]] && continue
    ep="$(uplink_epoch_from_id "$base")"
    loc="$(uplink_local_from_id "$base")"
    rows+=("${ep}|UR:${base}|${loc}  (Uplink decision run)|${d}")
  done
  shopt -u nullglob

  if ((${#rows[@]}==0)); then
    dlg --title "Uplink Decision Runs" --msgbox "No run-* directories found under:\n$UPLINK_DIR" 9 80
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
    dlg --title "Uplink Decision Runs" --menu "Select a run" 22 120 12 "${choices[@]}"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    local sel="$DOUT"
    local path=""
    for line in "${sorted[@]}"; do
      [[ "$sel" == "$(cut -d'|' -f2 <<<"$line")" ]] || continue
      path="$(cut -d'|' -f4- <<<"$line")"
      break
    done

    show_uplink_run_menu "$path" "Uplink Run: ${sel#UR:}"
  done
}

uplink_menu(){
  if [[ ! -d "$UPLINK_DIR" ]]; then
    dlg --title "Uplink Decisions / Suggestions" --msgbox "No uplink_suggest runs found yet.\n\nExpected directory:\n$UPLINK_DIR" 9 80
    return
  fi

  while true; do
    dlg --title "Uplink Decisions / Suggestions" \
        --menu "Select what to view" 16 90 8 \
        "1" "Uplink decision runs (run-*)" \
        "2" "Batch review logs (batch_uplink_review_*.log)" \
        "0" "Back"
    local rc=$DIALOG_RC
    [[ $rc -ne 0 ]] && return

    case "$DOUT" in
      1) uplink_runs_menu ;;
      2) uplink_batch_logs_menu ;;
      0) return ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Top-level main menu
# ---------------------------------------------------------------------------
main(){
  while true; do
    local MENU_ITEMS=()

    MENU_ITEMS+=("1" "Discovery Scans"                        "$(color_help "${HELP_TEXT[1]}")")
    MENU_ITEMS+=("2" "Catalyst/Meraki Switch Mapping Runs"   "$(color_help "${HELP_TEXT[2]}")")
    MENU_ITEMS+=("3" "Meraki Probe Runs"                     "$(color_help "${HELP_TEXT[3]}")")
    MENU_ITEMS+=("4" "Port Migration Runs"                   "$(color_help "${HELP_TEXT[5]}")")
    MENU_ITEMS+=("5" "Management IP Migration"               "$(color_help "${HELP_TEXT[6]}")")
    MENU_ITEMS+=("6" "Uplink Decisions / Suggestions"        "$(color_help "${HELP_TEXT[7]}")")
    MENU_ITEMS+=("7" "Search by IP / text"                   "$(color_help "${HELP_TEXT[4]}")")
    MENU_ITEMS+=("0" "Exit"                                  "$(color_help "${HELP_TEXT[0]}")")

    local CHOICE
    CHOICE=$(
      dialog --colors --item-help \
        --backtitle "$BACKTITLE" \
        --title "Logging & Reports" \
        --menu "Log Root: $ROOT\n\nSelect an option:" 20 100 12 \
        "${MENU_ITEMS[@]}" \
        3>&1 1>&2 2>&3
    ) || break

    case "$CHOICE" in
      1) discovery_menu      ;;
      2) mappings_menu       ;;
      3) meraki_probe_menu   ;;
      4) port_migration_menu ;;
      5) mgmt_ip_menu        ;;
      6) uplink_menu         ;;
      7) ip_search_menu      ;;
      0) break               ;;
    esac
  done
}
main