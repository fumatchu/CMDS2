#!/usr/bin/env bash
set -Euo pipefail

# ============================================================
# Uplink Suggest Dialog Wrapper
#
# Front-end UI for the existing uplink_suggest_cli.sh backend.
# This script:
#   - lets operator choose a mapped source/target pair
#   - can process one entry OR all entries
#   - auto-skips unchanged / no-review entries during batch mode
#   - pops a msgbox for every switch/member needing operator review
#   - writes a batch audit log under runs/uplink_suggest/
#   - reads normalized_manifest.json + backend artifacts
#   - forces manual mapping for low / needs_review
#   - writes manual pairs JSON and re-runs backend if needed
#
# IMPORTANT:
#   This does NOT replace your backend script. It wraps it.
#
# BATCH FIX:
#   In __ALL__ mode, backend runs are still per-IP, but this wrapper
#   now builds a COMBINED batch run directory and accumulates every
#   processed source_key into one normalized_manifest.json.
#   At the end of batch mode, runs/uplink_suggest/latest points to the
#   combined batch run, so downstream port_migration sees ALL entries.
# ============================================================

BASE_DIR="/root/.cat_admin"
BACKEND_SCRIPT="${BASE_DIR}/uplink_suggest_cli.sh"
MAPPING_JSON_FILE="${BASE_DIR}/runs/mappings/latest/mapping.json"
RUNS_BASE="${BASE_DIR}/runs/uplink_suggest"
DIALOG_TMP_DIR="${BASE_DIR}/.tmp_uplink_suggest_dialog"

BACKTITLE="Cloud Migration – Uplink Mapping"
mkdir -p "$DIALOG_TMP_DIR"
mkdir -p "$RUNS_BASE"

BATCH_TS="$(date +%Y%m%d_%H%M%S)"
BATCH_LOG_FILE="${RUNS_BASE}/batch_uplink_review_${BATCH_TS}.log"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: $1" >&2
    exit 1
  }
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need dialog
need jq
need awk
need sed
need grep
need sort
need mktemp
need stty
need readlink
need cp

[[ -t 0 && -t 1 && -t 2 ]] || die "This dialog UI must be run from an interactive terminal."
[[ -x "$BACKEND_SCRIPT" ]] || die "Backend script not found or not executable: $BACKEND_SCRIPT"
[[ -f "$MAPPING_JSON_FILE" ]] || die "Mapping file not found: $MAPPING_JSON_FILE"
[[ -d "$RUNS_BASE" ]] || mkdir -p "$RUNS_BASE"

trim() {
  local s="${1:-}"
  s="$(printf '%s' "$s" | tr -d '\r')"
  s="$(printf '%s' "$s" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  printf '%s' "$s"
}

safe_name() {
  printf '%s' "$1" | tr ' /:' '---' | tr -cd 'A-Za-z0-9_.-'
}

cleanup() {
  rm -f "${DIALOG_TMP_DIR}/"dialog_* 2>/dev/null || true
}

trap 'stty sane 2>/dev/null || true; cleanup' EXIT INT TERM

log_batch_line() {
  local text="$1"
  printf '%s %s\n' "$(date '+%F %T')" "$text" >> "$BATCH_LOG_FILE"
}
wide_textbox() {
  local file="$1"

  local rows cols
  rows=$(tput lines)
  cols=$(tput cols)

  local height=$((rows - 4))
  local width=$((cols - 6))

  dialog \
    --backtitle "$BACKTITLE" \
    --title "View Report" \
    --textbox "$file" "$height" "$width" \
    </dev/tty >/dev/tty
}
entry_log_prefix() {
  local entry_json="$1"
  local target_model ip member
  target_model="$(jq -r '.target_model // "UNKNOWN"' <<<"$entry_json")"
  ip="$(jq -r '.ip // ""' <<<"$entry_json")"
  member="$(jq -r '.member_index // ""' <<<"$entry_json")"
  printf '%s|%s|%s' "$target_model" "$ip" "$member"
}

entry_effective_uplink() {
  local entry_json="$1"
  jq -r '
    if (.final_pairs // [] | length) > 0
    then (
      .final_pairs
      | map(.targetInterface // "")
      | map(select(. != ""))
      | .[0] // (.effective_config // "")
    )
    else (.effective_config // "")
    end
  ' <<<"$entry_json"
}

log_apply_entry() {
  local entry_json="$1"
  local prefix uplink
  prefix="$(entry_log_prefix "$entry_json")"
  uplink="$(entry_effective_uplink "$entry_json")"
  [[ -n "$uplink" ]] || uplink="UNKNOWN"
  log_batch_line "APPLY ${prefix} uplink=${uplink}"
}

log_review_entry() {
  local entry_json="$1"
  local conf status prefix
  prefix="$(entry_log_prefix "$entry_json")"
  conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
  status="$(jq -r '.status // "needs_review"' <<<"$entry_json")"
  log_batch_line "OPERATOR_REVIEW ${prefix} confidence=${conf} status=${status}"
}

log_skip_entry() {
  local entry_json="$1"
  local reason prefix
  reason="$2"
  prefix="$(entry_log_prefix "$entry_json")"
  log_batch_line "AUTO_SKIP ${prefix} reason=${reason}"
}

msgbox() {
  local text="$1"
  dialog \
    --backtitle "$BACKTITLE" \
    --title "Uplink Suggest" \
    --msgbox "$text" 20 90 \
    </dev/tty >/dev/tty
}

yesno() {
  local text="$1"
  dialog \
    --backtitle "$BACKTITLE" \
    --title "Uplink Suggest" \
    --yes-label "Yes" \
    --no-label "No" \
    --yesno "$text" 20 90 \
    </dev/tty >/dev/tty
}

infobox() {
  local text="$1"
  dialog \
    --backtitle "$BACKTITLE" \
    --title "Uplink Suggest" \
    --infobox "$text" 8 70 \
    </dev/tty >/dev/tty
}

menu() {
  local title="$1"
  local prompt="$2"
  shift 2

  local choice
  choice="$(
    dialog \
      --stdout \
      --backtitle "$BACKTITLE" \
      --title "$title" \
      --menu "$prompt" 22 110 12 \
      "$@" \
      </dev/tty
  )" || return 1

  printf '%s\n' "$choice"
}

radiolist() {
  local title="$1"
  local prompt="$2"
  shift 2

  local choice
  choice="$(
    dialog \
      --stdout \
      --backtitle "$BACKTITLE" \
      --title "$title" \
      --radiolist "$prompt" 24 120 14 \
      "$@" \
      </dev/tty
  )" || return 1

  printf '%s\n' "$choice"
}

textbox() {
  local file="$1"
  dialog \
    --backtitle "$BACKTITLE" \
    --title "View Report" \
    --textbox "$file" 28 120 \
    </dev/tty >/dev/tty
}

get_mapping_choices() {
  jq -r '
    .[]?
    | select((.source.ip // "") != "" and (.target.cloud_id // "") != "")
    | [
        (.source.key // (((.source.ip // "")|tostring) + "|" + (((.source.member_index // 1)|tostring)))),
        (
          ((.source.hostname // "UNKNOWN")|tostring)
          + " | src=" + ((.source.ip // "")|tostring)
          + " | member=" + (((.source.member_index // 1)|tostring))
          + " | target=" + ((.target.name // .target.cloud_id // "UNKNOWN")|tostring)
          + " | model=" + ((.target.model // "UNKNOWN")|tostring)
        )
      ] | @tsv
  ' "$MAPPING_JSON_FILE"
}

get_mapping_field() {
  local source_key="$1"
  local field="$2"
  jq -r --arg sk "$source_key" "
    first(.[] | select((.source.key // (((.source.ip // \"\")|tostring) + \"|\" + (((.source.member_index // 1)|tostring)))) == \$sk) | ${field}) // \"\"
  " "$MAPPING_JSON_FILE"
}

get_latest_run_dir() {
  local latest="${RUNS_BASE}/latest"
  if [[ -L "$latest" || -d "$latest" ]]; then
    readlink -f "$latest" 2>/dev/null || printf '%s\n' "$latest"
    return 0
  fi
  return 1
}

compute_base_name() {
  local source_key="$1"
  local host ip member
  host="$(get_mapping_field "$source_key" '.source.hostname // "UNKNOWN"')"
  ip="$(get_mapping_field "$source_key" '.source.ip // ""')"
  member="$(get_mapping_field "$source_key" '(.source.member_index // 1)')"
  safe_name "${host}_${ip}_member${member}"
}

backend_log_file_for_source() {
  local source_key="$1"
  printf '%s/backend_%s.log\n' "$DIALOG_TMP_DIR" "$(safe_name "$source_key")"
}

run_backend_for_source() {
  local source_key="$1"
  local pairs_file="${2:-}"
  local ip member log_file
  ip="$(get_mapping_field "$source_key" '.source.ip // ""')"
  member="$(get_mapping_field "$source_key" '(.source.member_index // 1)')"

  [[ -n "$ip" ]] || die "No source IP found for source_key=$source_key"

  log_file="$(backend_log_file_for_source "$source_key")"
  : > "$log_file"

  if [[ -n "$pairs_file" ]]; then
    "$BACKEND_SCRIPT" --ip "$ip" --pairs-file "$pairs_file" \
      >"$log_file" 2>&1
  else
    "$BACKEND_SCRIPT" --ip "$ip" \
      >"$log_file" 2>&1
  fi
}

manifest_entry_json() {
  local run_dir="$1"
  local source_key="$2"
  local manifest="${run_dir}/normalized_manifest.json"
  [[ -f "$manifest" ]] || return 1
  jq -c --arg sk "$source_key" 'first(.[] | select(.source_key == $sk))' "$manifest"
}

report_file_for_source() {
  local run_dir="$1"
  local source_key="$2"
  local base_name
  base_name="$(compute_base_name "$source_key")"
  printf '%s/report_%s.txt\n' "$run_dir" "$base_name"
}

target_json_for_source() {
  local run_dir="$1"
  local source_key="$2"
  local base_name
  base_name="$(compute_base_name "$source_key")"
  printf '%s/target_%s.json\n' "$run_dir" "$base_name"
}

source_json_for_source() {
  local run_dir="$1"
  local source_key="$2"
  local base_name
  base_name="$(compute_base_name "$source_key")"
  printf '%s/source_%s.json\n' "$run_dir" "$base_name"
}

suggest_json_for_source() {
  local run_dir="$1"
  local source_key="$2"
  local base_name
  base_name="$(compute_base_name "$source_key")"
  printf '%s/suggest_%s.json\n' "$run_dir" "$base_name"
}

manual_pairs_file_for_source() {
  local run_dir="$1"
  local source_key="$2"
  local base_name
  base_name="$(compute_base_name "$source_key")"
  printf '%s/manual_pairs_%s.json\n' "$run_dir" "$base_name"
}

create_batch_combined_run() {
  local batch_run_dir="${RUNS_BASE}/batch-run-${BATCH_TS}"
  mkdir -p "$batch_run_dir"
  printf '[]\n' > "${batch_run_dir}/normalized_manifest.json"
  printf '%s\n' "$batch_run_dir"
}

copy_source_artifacts_to_batch_run() {
  local src_run_dir="$1"
  local dst_run_dir="$2"
  local source_key="$3"

  local src_manifest entry_json base_name
  src_manifest="${src_run_dir}/normalized_manifest.json"
  [[ -f "$src_manifest" ]] || return 1

  entry_json="$(jq -c --arg sk "$source_key" 'first(.[] | select(.source_key == $sk))' "$src_manifest")"
  [[ -n "$entry_json" && "$entry_json" != "null" ]] || return 1

  base_name="$(compute_base_name "$source_key")"
  mkdir -p "$dst_run_dir"

  local f
  for f in \
    "report_${base_name}.txt" \
    "target_${base_name}.json" \
    "source_${base_name}.json" \
    "suggest_${base_name}.json" \
    "manual_pairs_${base_name}.json" \
    "preview_${base_name}.cfg"
  do
    if [[ -f "${src_run_dir}/${f}" ]]; then
      cp -f "${src_run_dir}/${f}" "${dst_run_dir}/${f}"
    fi
  done

  local dst_manifest="${dst_run_dir}/normalized_manifest.json"
  [[ -f "$dst_manifest" ]] || printf '[]\n' > "$dst_manifest"

  local tmp_manifest
  tmp_manifest="$(mktemp)"

  jq -c --arg sk "$source_key" --argjson entry "$entry_json" '
    map(select(.source_key != $sk)) + [$entry]
  ' "$dst_manifest" > "$tmp_manifest" && mv -f "$tmp_manifest" "$dst_manifest"
}

show_summary_from_entry() {
  local entry_json="$1"

  local hostname ip member target_model target_cloud_id status changed conf review pair_count reason
  hostname="$(jq -r '.hostname // "UNKNOWN"' <<<"$entry_json")"
  ip="$(jq -r '.ip // ""' <<<"$entry_json")"
  member="$(jq -r '.member_index // 1' <<<"$entry_json")"
  target_model="$(jq -r '.target_model // ""' <<<"$entry_json")"
  target_cloud_id="$(jq -r '.target_cloud_id // ""' <<<"$entry_json")"
  status="$(jq -r '.status // ""' <<<"$entry_json")"
  changed="$(jq -r '.changed // false' <<<"$entry_json")"
  conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
  review="$(jq -r 'if has("operator_review_required") then .operator_review_required else true end' <<<"$entry_json")"
  pair_count="$(jq -r '.pair_count // 0' <<<"$entry_json")"
  reason="$(jq -r '.reason // ""' <<<"$entry_json")"

  dialog \
    --backtitle "$BACKTITLE" \
    --title "Uplink Summary" \
    --msgbox "Source: ${hostname} (${ip}) member ${member}

Target: ${target_model} / ${target_cloud_id}

----------------------------------------
Status: ${status}
Changed: ${changed}
Confidence: ${conf}
Operator review required: ${review}
Pair count: ${pair_count}
----------------------------------------

Reason:
${reason}
" 22 120 \
    </dev/tty >/dev/tty
}

operator_intervention_msg() {
  local entry_json="$1"
  local source_key="$2"

  local hostname ip member conf status reason
  hostname="$(jq -r '.hostname // "UNKNOWN"' <<<"$entry_json")"
  ip="$(jq -r '.ip // ""' <<<"$entry_json")"
  member="$(jq -r '.member_index // ""' <<<"$entry_json")"
  conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
  status="$(jq -r '.status // "needs_review"' <<<"$entry_json")"
  reason="$(jq -r '.reason // ""' <<<"$entry_json")"

  msgbox "Operator intervention required.

Source key: ${source_key}
Switch: ${hostname} (${ip}) member ${member}

Status: ${status}
Confidence: ${conf}

Automatic uplink mapping could not be completed with sufficient confidence for this switch/member.

Reason:
${reason}

Press Continue to review the report or manually edit the mapping."
}

build_manual_target_choices() {
  local target_json="$1"
  local preferred_family="$2"

  jq -r --arg fam "$preferred_family" '
    .targetModuleCandidates
    | map(
        . + {
          effectiveInterface:
            (if (.interface // "") != "" then .interface
             else
               (
                 .family
                 + (
                     (
                       .portId
                       | capture("^(?<member>[0-9]+)_(?<module>[^_]+)_(?<port>[0-9]+)$")
                     ) as $m
                     | "\($m.member)/1/\($m.port)"
                   )
               )
             end)
        }
      )
    | map(select((.family // "") != ""))
    | (if ($fam != "") then map(select(.family == $fam)) else . end)
    | sort_by(
        (if (.namedPort // false) then 0 else 1 end),
        (.effectiveInterface // ""),
        (.portId // "")
      )
    | .[]
    | [
        (.portId // ""),
        (
          (if (.effectiveInterface // "") != "" then .effectiveInterface else "(unnamed)" end)
          + " | module=" + (.moduleModel // "")
          + " | family=" + (.family // "")
          + " | named=" + ((.namedPort // false)|tostring)
        )
      ] | @tsv
  ' "$target_json"
}

build_source_iface_choices() {
  local source_json="$1"
  jq -r '
    .configuredSourceUplinks[]
    | [
        (.name // ""),
        (
          (.name // "")
          + " | family=" + (.family // "")
          + " | configCount=" + ((.configCount // 0)|tostring)
        )
      ] | @tsv
  ' "$source_json"
}

manual_mapping_dialog() {
  local run_dir="$1"
  local source_key="$2"

  local source_json target_json suggest_json manual_file preferred_family
  source_json="$(source_json_for_source "$run_dir" "$source_key")"
  target_json="$(target_json_for_source "$run_dir" "$source_key")"
  suggest_json="$(suggest_json_for_source "$run_dir" "$source_key")"
  manual_file="$(manual_pairs_file_for_source "$run_dir" "$source_key")"

  [[ -f "$source_json" ]] || die "Missing source JSON: $source_json"
  [[ -f "$target_json" ]] || die "Missing target JSON: $target_json"
  [[ -f "$suggest_json" ]] || die "Missing suggest JSON: $suggest_json"

  preferred_family="$(jq -r '.preferredTargetFamily // ""' "$suggest_json")"

  local source_lines=()
  while IFS=$'\t' read -r key desc; do
    [[ -n "$key" ]] || continue
    source_lines+=("$key"$'\t'"$desc")
  done < <(build_source_iface_choices "$source_json")

  [[ "${#source_lines[@]}" -gt 0 ]] || {
    msgbox "No configured source uplinks found for manual mapping."
    return 1
  }

  local manual_json='[]'

  local src_key src_desc
  for row in "${source_lines[@]}"; do
    src_key="${row%%$'\t'*}"
    src_desc="${row#*$'\t'}"

    local choices=()
    while IFS=$'\t' read -r tkey tdesc; do
      [[ -n "$tkey" ]] || continue
      choices+=("$tkey" "$tdesc" "off")
    done < <(build_manual_target_choices "$target_json" "$preferred_family")

    if [[ "${#choices[@]}" -eq 0 ]]; then
      msgbox "No valid target candidates were found for source:\n\n${src_key}"
      return 1
    fi

    local selected
    selected="$(radiolist \
      "Manual Mapping" \
      "Choose target for source interface:

${src_desc}" \
      "${choices[@]}")" || return 1

    local target_portid="$selected"
    local target_iface target_family target_module
    target_iface="$(jq -r --arg pid "$target_portid" '
      .targetModuleCandidates
      | map(
          . + {
            effectiveInterface:
              (if (.interface // "") != "" then .interface
               else
                 (
                   .family
                   + (
                       (
                         .portId
                         | capture("^(?<member>[0-9]+)_(?<module>[^_]+)_(?<port>[0-9]+)$")
                       ) as $m
                       | "\($m.member)/1/\($m.port)"
                     )
                 )
               end)
          }
        )
      | first(.[] | select(.portId == $pid)) | .effectiveInterface // ""
    ' "$target_json")"
    target_family="$(jq -r --arg pid "$target_portid" 'first(.targetModuleCandidates[] | select(.portId == $pid) | .family) // ""' "$target_json")"
    target_module="$(jq -r --arg pid "$target_portid" 'first(.targetModuleCandidates[] | select(.portId == $pid) | .moduleModel) // ""' "$target_json")"

    manual_json="$(jq \
      --arg source "$src_key" \
      --arg targetPortId "$target_portid" \
      --arg targetInterface "$target_iface" \
      --arg targetFamily "$target_family" \
      --arg targetModuleModel "$target_module" \
      '. + [{
        source: $source,
        targetPortId: $targetPortId,
        targetInterface: $targetInterface,
        targetFamily: $targetFamily,
        targetModuleModel: $targetModuleModel
      }]' <<<"$manual_json")"
  done

  printf '%s\n' "$manual_json" > "$manual_file"
  printf '%s\n' "$manual_file"
  return 0
}

handle_result() {
  local run_dir="$1"
  local source_key="$2"
  local batch_mode="${3:-0}"

  local entry_json report_file conf review status
  entry_json="$(manifest_entry_json "$run_dir" "$source_key")" || {
    msgbox "Could not find manifest entry for source_key=${source_key}"
    return 1
  }

  report_file="$(report_file_for_source "$run_dir" "$source_key")"

  conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
  review="$(jq -r 'if has("operator_review_required") then .operator_review_required else true end' <<<"$entry_json")"
  status="$(jq -r '.status // "needs_review"' <<<"$entry_json")"

  local hostname ip member
  hostname="$(jq -r '.hostname // "UNKNOWN"' <<<"$entry_json")"
  ip="$(jq -r '.ip // ""' <<<"$entry_json")"
  member="$(jq -r '.member_index // 1' <<<"$entry_json")"

  local uplink_preview
  uplink_preview="$(
    jq -r '
      if (.final_pairs // [] | length) > 0 then
        .final_pairs[]
        | "  " + (.source // "?") + " → " + (.targetInterface // "?")
      else
        "  (none detected)"
      end
    ' <<<"$entry_json"
  )"

  while true; do

    # ✅ FIXED SIZE (clean + readable)
    local height=28
    local width=110
    local list_height=12

    local prompt
    prompt="Device: ${hostname} (${ip})  [member ${member}]

----------------------------------------
Confidence: ${conf}
Status: ${status}
Review required: ${review}
----------------------------------------

Detected uplink:
${uplink_preview}

----------------------------------------
Select an option:"

    local choice
    choice="$(
      dialog --stdout \
        --backtitle "$BACKTITLE" \
        --title "Uplink Review" \
        --menu "$prompt" \
        "$height" "$width" "$list_height" \
        1  "---------------- Logging ----------------" \
        2  "View summary" \
        3  "View full report" \
        4  "---------------- Actions ----------------" \
        5  "Edit mapping (manual)" \
        6  "$( [[ "$batch_mode" == "1" ]] && echo 'Accept and continue' || echo 'Accept current result' )" \
        7  "$( [[ "$batch_mode" == "1" ]] && echo 'Skip / next' || echo 'Back' )" \
        </dev/tty
    )" || continue

    case "$choice" in
      2)
        show_summary_from_entry "$entry_json"
        ;;
      3)
        if [[ -f "$report_file" ]]; then
          wide_textbox "$report_file"
        else
          msgbox "Report not found"
        fi
        ;;
      5)
        local manual_file
        manual_file="$(manual_mapping_dialog "$run_dir" "$source_key")" || continue

        infobox "Re-running uplink analysis..."
        run_backend_for_source "$source_key" "$manual_file"
        clear

        run_dir="$(get_latest_run_dir)"
        entry_json="$(manifest_entry_json "$run_dir" "$source_key")" || {
          msgbox "Re-run failed"
          return 1
        }

        # refresh values
        conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
        review="$(jq -r 'if has("operator_review_required") then .operator_review_required else true end' <<<"$entry_json")"
        status="$(jq -r '.status // "needs_review"' <<<"$entry_json")"

        uplink_preview="$(
          jq -r '
            if (.final_pairs // [] | length) > 0 then
              .final_pairs[]
              | "  " + (.source // "?") + " → " + (.targetInterface // "?")
            else
              "  (none detected)"
            end
          ' <<<"$entry_json"
        )"

        msgbox "Manual mapping applied."
        ;;
      6)
        if [[ "$batch_mode" == "1" ]]; then
          log_apply_entry "$entry_json"
        fi
        return 0
        ;;
      7)
        if [[ "$batch_mode" == "1" ]]; then
          log_batch_line "SKIP_OPERATOR ${source_key}"
        fi
        return 1
        ;;
    esac

  done
}

process_single_mapping() {
  local source_key="$1"

  infobox "Running uplink analysis for selected switch/member..."
  run_backend_for_source "$source_key"
  clear

  local run_dir
  run_dir="$(get_latest_run_dir)" || die "Could not locate latest run directory"

  if handle_result "$run_dir" "$source_key" 0; then
    local entry_json effective_cfg
    entry_json="$(manifest_entry_json "$run_dir" "$source_key")" || exit 1
    hostname="$(jq -r '.hostname // "UNKNOWN"' <<<"$entry_json")"
    ip="$(jq -r '.ip // ""' <<<"$entry_json")"
    member="$(jq -r '.member_index // 1' <<<"$entry_json")"
    effective_cfg="$(jq -r '.effective_config // ""' <<<"$entry_json")"

    msgbox "Uplink review complete.

Selected source key:
${source_key}

Effective config:
${effective_cfg}

This entry is now ready for downstream handoff if approved_for_migration=true."
  fi
}

process_all_mappings() {
  local source_keys=()
  local source_key desc
  while IFS=$'\t' read -r source_key desc; do
    [[ -n "$source_key" ]] || continue
    source_keys+=("$source_key")
  done < <(get_mapping_choices)

  [[ "${#source_keys[@]}" -gt 0 ]] || die "No valid mappings found in ${MAPPING_JSON_FILE}"

  local batch_run_dir
  batch_run_dir="$(create_batch_combined_run)" || die "Could not create combined batch run dir"

  local last_ip=""
  local run_dir=""
  local total_count=0
  local skipped_auto=0
  local intervention_count=0
  local apply_count=0

  log_batch_line "BATCH_START total_entries=${#source_keys[@]}"
  log_batch_line "BATCH_COMBINED_RUN ${batch_run_dir}"

  for source_key in "${source_keys[@]}"; do
    local ip
    ip="$(get_mapping_field "$source_key" '.source.ip // ""')"
    ip="$(trim "$ip")"

    if [[ "$ip" != "$last_ip" ]]; then
      infobox "Running uplink analysis for source IP ${ip}..."
      run_backend_for_source "$source_key"
      clear
      run_dir="$(get_latest_run_dir)" || die "Could not locate latest run directory"
      last_ip="$ip"
    fi

    total_count=$((total_count + 1))

    local entry_json conf review status
    entry_json="$(manifest_entry_json "$run_dir" "$source_key")" || {
    hostname="$(jq -r '.hostname // "UNKNOWN"' <<<"$entry_json")"
    ip="$(jq -r '.ip // ""' <<<"$entry_json")"
    member="$(jq -r '.member_index // 1' <<<"$entry_json")"
      msgbox "Could not find manifest entry for source_key=${source_key}"
      log_batch_line "ERROR_MISSING_MANIFEST ${source_key}"
      continue
    }

    conf="$(jq -r '.match_confidence // "low"' <<<"$entry_json")"
    review="$(jq -r 'if has("operator_review_required") then .operator_review_required else true end' <<<"$entry_json")"
    status="$(jq -r '.status // "needs_review"' <<<"$entry_json")"

    if [[ "$status" == "unchanged" && "$review" == "false" ]]; then
      skipped_auto=$((skipped_auto + 1))
      apply_count=$((apply_count + 1))
      log_skip_entry "$entry_json" "unchanged"
      log_apply_entry "$entry_json"
      copy_source_artifacts_to_batch_run "$run_dir" "$batch_run_dir" "$source_key" || true
      continue
    fi

    case "$conf" in
      high|medium-high)
        if [[ "$review" == "false" ]]; then
          skipped_auto=$((skipped_auto + 1))
          apply_count=$((apply_count + 1))
          log_skip_entry "$entry_json" "$conf"
          log_apply_entry "$entry_json"
          copy_source_artifacts_to_batch_run "$run_dir" "$batch_run_dir" "$source_key" || true
          continue
        fi
        ;;
    esac

    intervention_count=$((intervention_count + 1))
    handle_result "$run_dir" "$source_key" 1 || true

    entry_json="$(manifest_entry_json "$run_dir" "$source_key")" || true
    if [[ -n "${entry_json:-}" && "$entry_json" != "null" ]]; then
      review="$(jq -r 'if has("operator_review_required") then .operator_review_required else true end' <<<"$entry_json")"
      if [[ "$review" == "false" ]]; then
        apply_count=$((apply_count + 1))
      fi
      copy_source_artifacts_to_batch_run "$run_dir" "$batch_run_dir" "$source_key" || true
    fi
  done

  ln -sfn "$batch_run_dir" "${RUNS_BASE}/latest"

  log_batch_line "BATCH_COMPLETE total_entries=${total_count} auto_skipped=${skipped_auto} operator_attention=${intervention_count} applied=${apply_count}"
  log_batch_line "BATCH_LOG_FILE ${BATCH_LOG_FILE}"
  log_batch_line "BATCH_FINAL_LATEST ${RUNS_BASE}/latest -> ${batch_run_dir}"

  while :; do

  # -------- BUILD REVIEW PREVIEW --------
  preview="$(
  jq -r '
    .[]
    | . as $e
    | (
        ($e.hostname // "-") + " (" + ($e.ip // "-") + ") m" + (($e.member_index // 1)|tostring)
      ) as $header
    | (
        if ($e.final_pairs // [] | length) > 0 then
          $e.final_pairs[]
          | "    " + (.source // "?") + "  ->  " + (.targetInterface // "?")
        else
          "    (no uplink mapping)"
        end
      ) as $pairs
    | [$header, $pairs]
    | @tsv
  ' "${batch_run_dir}/normalized_manifest.json" 2>/dev/null |
  awk -F'\t' '
    {
      if ($1 != last) {
        if (NR > 1) print ""
        print $1
        last=$1
      }
      print $2
    }
  '
)"

  line_count=$(echo "$preview" | wc -l)

  # -------- SMALL LIST --------
  if (( line_count <= 20 )); then

    preview_msg="Review uplink mappings before finalizing?

Current results:
────────────────────────────────────────

$preview

────────────────────────────────────────
"

    height=$((line_count + 14))
    (( height > 24 )) && height=24

    dialog \
      --backtitle "$BACKTITLE" \
      --title "Review uplinks" \
      --yes-label "Re-run Review" \
      --no-label "Finalize" \
      --yesno "$preview_msg" "$height" 100

    rc=$?

  else

    # -------- LARGE LIST --------
    tmpfile="${DIALOG_TMP_DIR}/uplink_preview.txt"

    {
      echo "Review uplink mappings before finalizing?"
      echo
      echo "Current results:"
      echo "────────────────────────────────────────"
      echo
      echo "$preview"
      echo
      echo "────────────────────────────────────────"
      echo
      echo "Scroll with ↑/↓. Press ENTER to continue."
    } > "$tmpfile"

    dialog \
      --backtitle "$BACKTITLE" \
      --title "Review uplinks (scrollable)" \
      --textbox "$tmpfile" 28 110

    dialog \
      --backtitle "$BACKTITLE" \
      --title "Confirm uplinks" \
      --yes-label "Re-run Review" \
      --no-label "Finalize" \
      --yesno "Proceed with these uplink mappings?

Choose 'Re-run Review' to run analysis again." 10 70

    rc=$?
  fi

  # -------- HANDLE DECISION --------
  if [[ $rc -eq 0 ]]; then
    msgbox "Re-running uplink analysis..."
    process_all_mappings
    return 0
  fi

  # -------- FINALIZE --------
  dialog \
    --clear \
    --backtitle "$BACKTITLE" \
    --title "Uplink mapping complete" \
    --msgbox "Uplink mapping finalized.

Total entries processed: ${total_count}
Auto-skipped: ${skipped_auto}
Operator reviewed: ${intervention_count}
Apply-ready: ${apply_count}
" 14 80

  clear
  return 0

done
}

main() {
  local top_menu=(
    "__ALL__" "Process ALL mapped switch/member entries"
    "__ONE__" "Choose ONE mapped switch/member entry"
  )

  local mode
  mode="$(menu \
    "Run Mode" \
    "Choose how you want to run uplink review:" \
    "${top_menu[@]}")" || exit 0

  if [[ "$mode" == "__ALL__" ]]; then
    if yesno "Process all mapped switch/member entries now?

Batch mode will:
- auto-skip unchanged entries
- auto-skip high / medium-high entries that do not require review
- stop only when operator intervention is required
- write a batch log under runs/uplink_suggest/"; then
      process_all_mappings
    fi
    exit 0
  fi

  local mapping_items=()
  while IFS=$'\t' read -r key desc; do
    [[ -n "$key" ]] || continue
    mapping_items+=("$key" "$desc")
  done < <(get_mapping_choices)

  [[ "${#mapping_items[@]}" -gt 0 ]] || die "No valid mappings found in ${MAPPING_JSON_FILE}"

  local selected
  selected="$(menu \
    "Select Switch / Member" \
    "Choose the mapped source/target entry to analyze:" \
    "${mapping_items[@]}")" || exit 0

  process_single_mapping "$selected"
}

main "$@"