#!/usr/bin/env bash
# view_scheduled_upgrades.sh — dialog browser for scheduled IOS-XE upgrades
# Extracted from scheduler.sh (Option 2: "View scheduled upgrades")
#
# IMPORTANT:
# - This script is intended to run with the "tool root" being:
#     /root/.hybrid_admin/adv-ios-xe-upgrader
# - That directory contains: schedules/, runs/, discovery_results.json, etc.
# - Safe to call from a menu wrapper (no scheduling actions unless you choose "Delete" on a pending at-job).

set -Eeuo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need awk; need date; need atq; need atrm; need grep; need sed; need cut; need tr; need sort; need jq

###############################################################################
# Base paths (view everything from adv-ios-xe-upgrader root)
###############################################################################
BASE_DIR="${BASE_DIR:-/root/.hybrid_admin/adv-ios-xe-upgrader}"

# If this script lives under $BASE_DIR/bin, we can auto-detect BASE_DIR too:
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
if [[ -d "$SCRIPT_DIR/.." && -f "$SCRIPT_DIR/../upgrade_plan.json" && -d "$SCRIPT_DIR/../schedules" ]]; then
  BASE_DIR="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd -P)"
fi

cd "$BASE_DIR"

BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit — Advanced IOS-XE — Scheduled Upgrades}"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

trim(){ printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

dlg(){
  local _t rc
  _t="$(mktemp)"
  dialog "${DIALOG_OPTS[@]}" "$@" 2>"$_t"
  rc=$?
  DOUT=""
  [[ -s "$_t" ]] && DOUT="$(cat "$_t")"
  rm -f "$_t"
  return $rc
}

view_file(){  # $1=file $2=title
  local f="$1" t="${2:-File}"
  if [[ -s "$f" ]]; then
    dlg --title "$t" --textbox "$f" 0 0
  else
    dlg --title "$t" --msgbox "No content found:\n$f" 8 80
  fi
}

###############################################################################
# Discovery gating (eligible IPs)
###############################################################################
DISC_JSON="$BASE_DIR/discovery_results.json"
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

# Return 0 if IP is eligible according to discovery (or if we have no discovery info)
is_ip_eligible(){
  local ip="$1"
  build_eligibility
  (( ${#ELIGIBLE_IPS[@]} == 0 )) && return 0   # no discovery info → treat all as eligible
  local e
  for e in "${ELIGIBLE_IPS[@]}"; do
    [[ "$e" == "$ip" ]] && return 0
  done
  return 1
}

###############################################################################
# Helpers / status logic
###############################################################################
epoch_from_human(){ date -d "$1" +%s 2>/dev/null || echo 0; }

find_spawned_run_dir(){
  # $1 = job dir
  local d="$1" p
  p="$(awk -F'Run dir:[[:space:]]*' '/Run dir:/ {print $2; exit}' "$d/logs/stdout.log" 2>/dev/null || true)"
  [[ -n "$p" && -d "$p" ]] && { echo "$p"; return; }
  shopt -s nullglob
  for p in "$d"/runs/run-*; do
    [[ -d "$p" ]] && { echo "$p"; return; }
  done
  echo ""
}

at_has_job(){ # $1=id -> 0 if present
  atq 2>/dev/null | awk '{print $1}' | grep -qx -- "$1"
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

# Targets preview from selected_upgrade.env (IPs) with discovery gating.
# Show only eligible IPs (ssh=true, login=true, blacklisted!=true).
# Show only the first IP; if more, append (+N).
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

  # Dedup / sanitize
  mapfile -t uniq < <(
    printf '%s\n' "${ips[@]}" \
      | awk -F. '!seen[$0]++ { if ($4 != 0 && $4 != 255) print $0 }' \
      | sort -V
  )

  local total=${#uniq[@]}
  (( total == 0 )) && { echo "<none>"; return; }

  # Apply discovery eligibility gating (if discovery_results.json is present)
  build_eligibility
  local eligible=()
  local ip
  for ip in "${uniq[@]}"; do
    if is_ip_eligible "$ip"; then
      eligible+=("$ip")
    fi
  done

  local etotal=${#eligible[@]}
  if (( etotal == 0 )); then
    echo "<none (0 eligible by discovery)>"
    return
  fi

  local first="${eligible[0]}"
  if (( etotal == 1 )); then
    echo "$first"
  else
    echo "$first (+$((etotal-1)))"
  fi
}

# ---------- Friendly list ----------
# Prints: jobdir|when|note|image|targets|status|atid
build_jobs_list(){
  local meta dir when note atid img targets status when_ep now spawned
  now="$(date +%s)"
  shopt -s nullglob
  for meta in "$BASE_DIR"/schedules/job-*/job.meta; do
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
    dlg --title "Scheduled upgrades" --msgbox "No scheduled upgrades found in:\n$BASE_DIR/schedules" 8 78
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
      items+=("sum"  "Summary")
      items+=("note" "View note")
      items+=("path" "Show job folder path")
      items+=("sel"  "View selected_upgrade.env")
      items+=("disc" "View meraki_discovery.env")
      items+=("out"  "View logs/stdout.log")
      items+=("err"  "View logs/stderr.log")
      if [[ -n "$atid" && "$status" == "Scheduled — pending" ]]; then
        items+=("del"  "Delete from schedule (remove from queue)")
      fi
      items+=("back" "Back")

      dlg --title "$sel" --menu "Choose an action" 18 92 12 "${items[@]}" || break
      case "$DOUT" in
        sum)
          dlg --title "Summary" --msgbox \
"When:    $when
Status:  $status
Image:   $img
Targets: $targets

Note:
$note" 15 92
          ;;
        note)  dlg --title "Job note" --msgbox "${note:-<none>}" 10 70 ;;
        path)  dlg --title "Job folder" --msgbox "$dir" 8 92 ;;
        sel)   view_file "$dir/selected_upgrade.env"  "selected_upgrade.env" ;;
        disc)  view_file "$dir/meraki_discovery.env"  "meraki_discovery.env" ;;
        out)   view_file "$dir/logs/stdout.log"       "stdout.log" ;;
        err)   view_file "$dir/logs/stderr.log"       "stderr.log" ;;
        del)
          dlg --title "Confirm" --yesno "Remove this job from the 'at' queue?\n\nJob ID: ${atid}" 9 72 || continue
          if atrm "$atid" 2>/dev/null; then
            # mark cancellation
            sed -i -e 's/^backend_id=.*/backend_id=/' "$dir/job.meta"
            echo "canceled_local=$(date '+%F %T %Z')" >> "$dir/job.meta"
            : > "$dir/CANCELED"
            dlg --title "Removed" --msgbox "Removed job ${atid} from the queue.\nMarked as canceled:\n$dir" 10 86
            # refresh list/choices
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

###############################################################################
# Main (viewer only)
###############################################################################
friendly_jobs_menu
clear