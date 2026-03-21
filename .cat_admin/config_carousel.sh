
#!/usr/bin/env bash
set -Euo pipefail

BASE_DIR="/root/.cat_admin"
JSON_FILE="$BASE_DIR/selected_upgrade.json"
CFG_DIR="/var/lib/tftpboot/cat"
TMP_DIR="$BASE_DIR/.tmp_edit_switch_configs"

mkdir -p "$TMP_DIR"

cleanup() {
  rm -f "$TMP_DIR"/* 2>/dev/null || true
}
trap cleanup EXIT

die() {
  dialog --no-shadow \
    --backtitle "CAT Admin - Config Editor" \
    --title "Error" \
    --msgbox "$1" 10 90
  clear
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

need dialog
need jq
need cp
need cmp
need date
need awk
need sed
need grep

[[ -f "$JSON_FILE" ]] || die "Missing JSON file: $JSON_FILE"
[[ -d "$CFG_DIR" ]] || die "Missing config directory: $CFG_DIR"

clean_field() {
  local s
  s="$(printf '%s' "${1:-}" | tr -d '\r\n')"
  s="$(printf '%s' "$s" | sed -E 's/[[:space:]]+$//; s/^[[:space:]]+//')"
  printf '%s' "$s"
}

get_json_value() {
  local ip="$1"
  local field="$2"
  jq -r --arg ip "$ip" '
    .[] | select(.ip == $ip) | .[$field]
  ' --arg field "$field" "$JSON_FILE" 2>/dev/null
}

# safer helper because jq .[$field] can be awkward in some shells
get_field() {
  local ip="$1"
  local field="$2"
  jq -r --arg ip "$ip" --arg field "$field" '
    .[] | select(.ip == $ip) | .[$field] // ""
  ' "$JSON_FILE"
}

resolve_cfg_path() {
  local ip="$1"
  local backup_filename
  backup_filename="$(get_field "$ip" "backup_filename")"
  backup_filename="$(clean_field "$backup_filename")"

  [[ -n "$backup_filename" ]] || return 1

  local path="$CFG_DIR/$backup_filename"
  [[ -f "$path" ]] || return 1

  printf '%s\n' "$path"
}

build_items() {
  ITEMS=()
  local US=$'\x1f'

  while IFS=$US read -r ip host pid ver blacklisted bl_reason; do
    ip="$(clean_field "$ip")"
    [[ -n "$ip" ]] || continue

    host="${host:-UNKNOWN}"
    pid="${pid:-UNKNOWN}"
    ver="${ver:-UNKNOWN}"
    blacklisted="${blacklisted:-false}"
    bl_reason="${bl_reason:-}"

    local text="${host} (${ip})  ${pid}  Ver:${ver}"
    local def="off"

    if [[ "$blacklisted" == "true" ]]; then
      [[ -z "$bl_reason" ]] && bl_reason="blacklisted"
      text="[BLACKLISTED: ${bl_reason}]  ${host} (${ip})  ${pid}  Ver:${ver}"
      def="off"
    fi

    ITEMS+=("$ip" "$text" "$def")
  done < <(
    jq -r --arg us "$US" '
      .[]
      | [
          (.ip // ""),
          (.hostname // "UNKNOWN"),
          (.pid // "UNKNOWN"),
          (.version // "UNKNOWN"),
          ((.blacklisted // false) | tostring),
          (.blacklist_reason // "")
        ]
      | join($us)
    ' "$JSON_FILE"
  )
}

do_selection_dialog() {
  local tmp_sel="$TMP_DIR/selection.out"
  local -a filtered=()
  local ip blacklisted

  build_items

  ((${#ITEMS[@]} > 0)) || {
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "No Devices" \
      --msgbox "No switches were found in selected_upgrade.json." 8 60
    return 1
  }

  dialog --no-shadow \
    --backtitle "CAT Admin - Config Editor" \
    --title "Select switches to edit" \
    --checklist "Use SPACE to select one or more switch configs to edit." \
    22 140 12 \
    "${ITEMS[@]}" 2>"$tmp_sel"

  local rc=$?
  (( rc == 0 )) || return 1

  local sel_raw
  sel_raw="$(tr -d '"' < "$tmp_sel")"
  [[ -n "$sel_raw" ]] || return 1

  local -a sel_arr=()
  # shellcheck disable=SC2206
  sel_arr=($sel_raw)

  for ip in "${sel_arr[@]}"; do
    ip="$(clean_field "$ip")"
    [[ -n "$ip" ]] || continue
    blacklisted="$(get_field "$ip" "blacklisted")"
    [[ "$blacklisted" == "true" ]] && continue
    filtered+=("$ip")
  done

  ((${#filtered[@]} > 0)) || {
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "Nothing to Edit" \
      --msgbox "All selected devices were blacklisted or invalid." 8 70
    return 1
  }

  printf '%s\n' "${filtered[@]}" > "$TMP_DIR/selected_ips.txt"
  return 0
}

show_summary() {
  local ip="$1"
  local host pid ver file path

  host="$(get_field "$ip" "hostname")"
  pid="$(get_field "$ip" "pid")"
  ver="$(get_field "$ip" "version")"
  file="$(get_field "$ip" "backup_filename")"

  if path="$(resolve_cfg_path "$ip" 2>/dev/null)"; then
    :
  else
    path="$CFG_DIR/$file"
  fi

  dialog --no-shadow \
    --backtitle "CAT Admin - Config Editor" \
    --title "Switch Summary" \
    --msgbox "Host: ${host}
IP: ${ip}
PID: ${pid}
Version: ${ver}
Backup file: ${file}

Resolved path:
${path}" 16 90
}

save_if_changed() {
  local original="$1"
  local edited="$2"

  if cmp -s "$original" "$edited"; then
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "No Changes" \
      --msgbox "No changes were made." 7 40
    return 0
  fi

  local ts backup
  ts="$(date +%Y%m%d-%H%M%S)"
  backup="${original}.bak.${ts}"

  cp -a "$original" "$backup" || {
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "Save Failed" \
      --msgbox "Failed to create backup:\n$backup" 10 90
    return 1
  }

  cp -f "$edited" "$original" || {
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "Save Failed" \
      --msgbox "Failed to save file:\n$original" 10 90
    return 1
  }

  dialog --no-shadow \
    --backtitle "CAT Admin - Config Editor" \
    --title "Saved" \
    --msgbox "Config saved successfully.

File:
$original

Backup:
$backup" 14 90
}

edit_config() {
  local ip="$1"
  local cfg
  cfg="$(resolve_cfg_path "$ip")" || {
    local file
    file="$(get_field "$ip" "backup_filename")"
    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "Missing Config" \
      --msgbox "Could not find config file:

$CFG_DIR/$file" 10 90
    return 1
  }

  local tmp_edit="$TMP_DIR/edit_${ip}.tmp"
  local tmp_out="$TMP_DIR/edit_${ip}.out"

  cp -f "$cfg" "$tmp_edit" || return 1

  dialog --no-shadow \
    --backtitle "CAT Admin - Config Editor" \
    --title "Editing $(get_field "$ip" "hostname") ($ip)" \
    --editbox "$tmp_edit" 28 120 2>"$tmp_out"

  local rc=$?
  (( rc == 0 )) || return 1

  save_if_changed "$cfg" "$tmp_out"
}

carousel_editor() {
  local selected_file="$TMP_DIR/selected_ips.txt"
  [[ -s "$selected_file" ]] || return 1

  mapfile -t SELECTED_IPS < "$selected_file"
  local total="${#SELECTED_IPS[@]}"
  (( total > 0 )) || return 1

  local pos=0

  while true; do
    local ip host pid ver file path current_num tmp_choice
    ip="${SELECTED_IPS[$pos]}"
    current_num=$((pos + 1))

    host="$(get_field "$ip" "hostname")"
    pid="$(get_field "$ip" "pid")"
    ver="$(get_field "$ip" "version")"
    file="$(get_field "$ip" "backup_filename")"

    if path="$(resolve_cfg_path "$ip" 2>/dev/null)"; then
      :
    else
      path="$CFG_DIR/$file"
    fi

    tmp_choice="$TMP_DIR/menu_choice.out"

    dialog --no-shadow \
      --backtitle "CAT Admin - Config Editor" \
      --title "Config Carousel (${current_num}/${total})" \
      --menu "Switch: ${host} (${ip})
PID:    ${pid}
Ver:    ${ver}

Config path:
${path}" \
      20 100 8 \
      1 "Edit this config" \
      2 "Next switch" \
      3 "Previous switch" \
      4 "Show switch summary" \
      5 "Done" \
      2>"$tmp_choice"

    local rc=$?
    (( rc == 0 )) || break

    local choice
    choice="$(<"$tmp_choice")"

    case "$choice" in
      1) edit_config "$ip" ;;
      2) pos=$(((pos + 1) % total)) ;;
      3) pos=$(((pos - 1 + total) % total)) ;;
      4) show_summary "$ip" ;;
      5) break ;;
    esac
  done
}

main() {
  do_selection_dialog || {
    clear
    exit 0
  }

  carousel_editor
  clear
}

main "$@"