#!/usr/bin/env bash
set -euo pipefail

# CMDS Restore (dialog-based)
# - Full restore OR selective restore (pick trees/files)
# - Safe manifest parsing (DOES NOT source manifest.env)
# - Local restore
# - Remote restore (SSH password-only via sshpass; stage remote bundle locally)
#
# IMPORTANT:
# - NO passkey / NO key auth. Remote is PASSWORD-ONLY.
# - NO split UI. Only stable infobox/msgbox/textbox.

DIALOG_BIN="${DIALOG_BIN:-dialog}"
TITLE="CMDS Restore"
BACKTITLE="CMDS-Restore"

DEFAULT_LOCAL_ROOT="/root/cmds-backups"
DEFAULT_REMOTE_ROOT="/root/cmds-backups"
RUNS_BASE="/root/.server_admin/runs/cmds-restore"

umask 077

# -----------------------------
# TTY handling (critical for nested dialog)
# -----------------------------
TTY_PATH="/dev/tty"
if [[ -e "$TTY_PATH" ]]; then
  exec 9<> "$TTY_PATH" || true
fi
fd9_ok() { [[ -e /proc/$$/fd/9 ]]; }

# ---------- helpers ----------
need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Must run as root." >&2
    exit 1
  fi
}

have_dialog() { command -v "$DIALOG_BIN" >/dev/null 2>&1; }

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
escape_ere() { sed 's/[][\.^$*+?(){}|\\/]/\\&/g'; }

# Dialog wrappers (fd9-safe)
msgbox() {
  local title="${1:-Info}"; shift || true
  if have_dialog && fd9_ok; then
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --msgbox "$*" 12 78 <&9 >&9 2>&9
  else
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --msgbox "$*" 12 78
  fi
}

infobox() {
  local title="${1:-Info}"; shift || true
  if have_dialog && fd9_ok; then
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --infobox "$*" 6 78 <&9 >&9 2>&9
  else
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --infobox "$*" 6 78
  fi
}

yesno() {
  local title="$1"; local prompt="$2"
  if have_dialog && fd9_ok; then
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --yesno "$prompt" 12 78 <&9 >&9 2>&9
  else
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" --title "$title" --yesno "$prompt" 12 78
  fi
}

inputbox() {
  local title="$1"; local prompt="$2"; local def="${3:-}"
  local out=""
  if have_dialog && fd9_ok; then
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --inputbox "$prompt" 12 78 "$def" <&9 2>&9)" || return 1
  else
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --inputbox "$prompt" 12 78 "$def")" || return 1
  fi
  printf "%s" "$out"
}

passwordbox() {
  local title="$1"; local prompt="$2"
  local out=""
  if have_dialog && fd9_ok; then
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --insecure --passwordbox "$prompt" 12 78 <&9 2>&9)" || return 1
  else
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --insecure --passwordbox "$prompt" 12 78)" || return 1
  fi
  printf "%s" "$out"
}

menu() {
  local title="$1"; local prompt="$2"; shift 2
  local out=""
  # NOTE: dialog will scroll when there are more items than "menu height"
  # Increase list-height so it's nicer (still scrolls).
  local mh=15
  local h=20
  local w=110
  if have_dialog && fd9_ok; then
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --menu "$prompt" "$h" "$w" "$mh" "$@" <&9 2>&9)" || return 1
  else
    out="$("$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" --title "$title" --menu "$prompt" "$h" "$w" "$mh" "$@")" || return 1
  fi
  printf "%s" "$out"
}

checklist() {
  if have_dialog && fd9_ok; then
    "$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" "$@" <&9 2>&9
  else
    "$DIALOG_BIN" --stdout --no-shadow --backtitle "$BACKTITLE" "$@"
  fi
}

textbox() {
  if have_dialog && fd9_ok; then
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" "$@" <&9 >&9 2>&9
  else
    "$DIALOG_BIN" --no-shadow --backtitle "$BACKTITLE" "$@"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    msgbox "Missing dependency" "Missing required command: $1"
    exit 1
  }
}

make_run_dir() {
  local ts run_dir
  ts="$(date '+%Y%m%d-%H%M%S')"
  run_dir="$RUNS_BASE/run-$ts"
  mkdir -p "$run_dir"
  chmod 700 "$run_dir" 2>/dev/null || true
  echo "$run_dir"
}

is_backup_dir_name() {
  # Accept any host/prefix with underscore, matching your real dirs:
  #   cmds_cmds-backup-YYYYMMDD-HHMMSS
  #   test1_cmds-backup-YYYYMMDD-HHMMSS
  #   <anything>_cmds-backup-YYYYMMDD-HHMMSS
  [[ "$(basename "$1")" =~ ^[A-Za-z0-9._-]+_cmds-backup-[0-9]{8}-[0-9]{6}$ ]]
}

pick_mode_local_remote() {
  menu "$TITLE" "Select restore source:" \
    "local"  "Restore from local backups on this server" \
    "remote" "Restore from remote host over SSH (password-only)"
}

pick_restore_mode_full_selective() {
  menu "Restore Mode" "Choose how to restore:" \
    "full"   "Restore everything in the backup (overwrite included paths)" \
    "select" "Restore selected areas/files only"
}

cleanup_archive_on_success() {
  # $1 = tarfile path
  local tarfile="${1:-}"

  [[ -n "$tarfile" && -f "$tarfile" ]] || return 0

  # Always clean staged archives under the runs base (remote staging lives here)
  if [[ "$tarfile" == "$RUNS_BASE"/run-*/staging/*/*.tar.gz ]]; then
    rm -f -- "$tarfile" 2>/dev/null || true
    return 0
  fi

  # Optional: allow deleting local backup archives ONLY if explicitly enabled
  if [[ "${CLEANUP_LOCAL_ARCHIVE:-0}" == "1" ]]; then
    rm -f -- "$tarfile" 2>/dev/null || true
  fi
}

# ---------- SAFE manifest parsing ----------
manifest_get() {
  local key="$1" file="$2" line val
  line="$(grep -m1 -E "^${key}=" "$file" 2>/dev/null || true)"
  [[ -n "$line" ]] || return 0
  val="${line#*=}"

  if [[ "$val" =~ ^\".*\"$ ]]; then
    val="${val:1:-1}"
  elif [[ "$val" =~ ^\'.*\'$ ]]; then
    val="${val:1:-1}"
  fi

  printf "%s" "$val"
}

# ---------- discover backups (local) ----------
find_backup_candidates_local() {
  local root="$1"
  [[ -d "$root" ]] || return 0

  find "$root" -maxdepth 2 -mindepth 1 -type d 2>/dev/null | while read -r d; do
    is_backup_dir_name "$d" || continue
    [[ -f "$d/manifest.env" ]] || continue
    [[ -f "$d/sha256sums.txt" ]] || continue

    local tarfile
    tarfile="$(ls -1 "$d"/*.tar.gz 2>/dev/null | head -n 1 || true)"
    [[ -n "$tarfile" && -f "$tarfile" ]] || continue

    local mf="$d/manifest.env"
    local created mode
    created="$(manifest_get CREATED_AT "$mf" | tr -d '\r' | trim || true)"
    mode="$(manifest_get MODE "$mf" | tr -d '\r' | trim || true)"

    echo "$d|$tarfile|${created:-unknown}|${mode:-unknown}"
  done
}

menu_pick_backup_from_lines() {
  # stdin: lines "dir|tar|created|mode"
  local tmp items line idx
  tmp="$(mktemp)"
  cat >"$tmp" || true
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 1
  fi

  items=()
  idx=1
  while IFS= read -r line; do
    local d created mode
    d="${line%%|*}"
    created="$(echo "$line" | cut -d'|' -f3)"
    mode="$(echo "$line" | cut -d'|' -f4)"
    items+=("$idx" "$(basename "$d")  |  $created  |  $mode")
    idx=$((idx+1))
  done <"$tmp"

  local choice
  choice="$(menu "Select Backup Set" "Pick one to restore:" "${items[@]}")" || { rm -f "$tmp"; return 1; }

  local selected_line
  selected_line="$(sed -n "${choice}p" "$tmp")"
  rm -f "$tmp"
  [[ -n "$selected_line" ]] || return 1
  echo "$selected_line"
}

show_manifest_summary() {
  local mf="$1"
  local tmp
  tmp="$(mktemp)"
  {
    echo "===== Backup Manifest ====="
    sed -n '1,250p' "$mf"
    echo
    echo "NOTE: Restore will overwrite destination paths that exist."
  } >"$tmp"
  textbox --title "Manifest" --textbox "$tmp" 22 92
  rm -f "$tmp"
}

# ---------- tar listing / selective restore ----------
list_tar_paths() { tar -tzf "$1" 2>/dev/null; }

build_top_level_items() {
  local tarfile="$1" tmp
  tmp="$(mktemp)"
  list_tar_paths "$tarfile" >"$tmp" || true
  [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }

  grep -q '^root/.hybrid_admin/' "$tmp" && printf "root/.hybrid_admin/\tHybrid Admin tools\toff\n"
  grep -q '^root/.server_admin/' "$tmp" && printf "root/.server_admin/\tServer Admin tools\toff\n"
  grep -q '^var/lib/tftpboot/' "$tmp"     && printf "var/lib/tftpboot/\tTFTP Boot images/files\toff\n"

  rm -f "$tmp"
}

select_top_level_targets() {
  local tarfile="$1" items=()
  while IFS=$'\t' read -r tag desc onoff; do
    [[ -n "$tag" ]] || continue
    items+=("$tag" "$desc" "$onoff")
  done < <(build_top_level_items "$tarfile" || true)

  [[ "${#items[@]}" -gt 0 ]] || return 1

  local out
  out="$(checklist --title "Selective Restore" \
    --checklist "Select high-level areas to restore (fast):" 18 92 10 \
    "${items[@]}")" || return 1

  echo "$out" | tr -d '"'
}

select_subtree_menu() {
  menu "Choose Subtree" "Pick a subtree to drill into:" \
    "root/.hybrid_admin/" "Pick individual files under .hybrid_admin" \
    "root/.server_admin/" "Pick individual files under .server_admin" \
    "var/lib/tftpboot/"   "Pick individual files under tftpboot"
}

select_files_under_prefix() {
  local tarfile="$1" prefix="$2" tmp
  tmp="$(mktemp)"
  local pre_ere
  pre_ere="$(printf "%s" "$prefix" | escape_ere)"

  list_tar_paths "$tarfile" | grep -E "^${pre_ere}" >"$tmp" || true
  [[ -s "$tmp" ]] || { rm -f "$tmp"; return 1; }

  local count
  count="$(wc -l <"$tmp" | tr -d ' ')"

  if (( count > 500 )); then
    local filter
    filter="$(inputbox "Too Many Files" \
"Archive has $count entries under:\n$prefix\n\nEnter a narrower filter (examples: cmds_backup.sh  OR  runs/  OR  images/):" "")" || { rm -f "$tmp"; return 1; }
    filter="$(printf "%s" "$filter" | trim)"
    if [[ -n "$filter" ]]; then
      grep -F "$filter" "$tmp" >"$tmp.f" || true
      mv -f "$tmp.f" "$tmp"
    fi
  fi

  [[ -s "$tmp" ]] || { rm -f "$tmp"; msgbox "No Matches" "No files matched under:\n$prefix"; return 1; }

  local items=() shown=0
  while IFS= read -r p; do
    [[ "$p" == */ ]] && continue
    items+=("$p" "" "off")
    shown=$((shown+1))
    (( shown >= 500 )) && break
  done <"$tmp"
  rm -f "$tmp"

  [[ "${#items[@]}" -gt 0 ]] || { msgbox "No Files" "No files selectable under:\n$prefix"; return 1; }

  local out
  out="$(checklist --title "Pick Files" \
    --checklist "Select files to restore (showing up to 500 items):\n$prefix" 22 92 14 \
    "${items[@]}")" || return 1

  echo "$out" | tr -d '"'
}

search_paths_in_tar() {
  local tarfile="$1" term tmp
  term="$(inputbox "Search Archive" "Enter a search term (filename or partial path):" "")" || return 1
  term="$(printf "%s" "$term" | trim)"
  [[ -n "$term" ]] || return 1

  tmp="$(mktemp)"
  list_tar_paths "$tarfile" | grep -F "$term" >"$tmp" || true
  [[ -s "$tmp" ]] || { rm -f "$tmp"; msgbox "No Matches" "No entries matched:\n$term"; return 1; }

  local items=() shown=0
  while IFS= read -r p; do
    [[ "$p" == */ ]] && continue
    items+=("$p" "" "off")
    shown=$((shown+1))
    (( shown >= 500 )) && break
  done <"$tmp"
  rm -f "$tmp"

  local out
  out="$(checklist --title "Search Results" \
    --checklist "Select files to restore (showing up to 500 results):\nSearch: $term" 22 92 14 \
    "${items[@]}")" || return 1

  echo "$out" | tr -d '"'
}

# ---------- SSH option bundles (PASSWORD ONLY) ----------
ssh_opts() {
  echo \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o PasswordAuthentication=yes \
    -o KbdInteractiveAuthentication=yes \
    -o NumberOfPasswordPrompts=1 \
    -o ConnectTimeout=10 \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=2
}

# ---------- restore runner (NO split UI) ----------
run_restore_simple() {
  local d="$1" tarfile="$2" log="$3" run_dir="$4" mode="$5" selected_paths="${6:-}"

  : >"$log"
  chmod 600 "$log" 2>/dev/null || true

  # Always show a persistent wait window before we do anything heavy.
  infobox "Please wait" "Retrieving information and preparing restore…"
  sleep 0.4

  {
    echo "===== CMDS RESTORE LOG ====="
    echo "Started   : $(date '+%F %T')"
    echo "BackupDir : $d"
    echo "Archive   : $tarfile"
    echo "Mode      : $mode"
    [[ "$mode" == "select" ]] && echo "Selected  : $selected_paths"
    echo
    echo "[1/2] sha256 verify..."
  } >>"$log" 2>&1

  infobox "Please wait" "Verifying checksums…"
  sleep 0.2
  ( cd "$d" && sha256sum -c "sha256sums.txt" ) >>"$log" 2>&1 || {
    local rc=$?
    echo "sha256 verify FAILED (exit $rc)" >>"$log"
    msgbox "Restore Failed" "Checksum verify failed (exit $rc).\n\nLog:\n$log"
    return "$rc"
  }

  {
    echo
    echo "[2/2] extracting to / ..."
    echo
  } >>"$log" 2>&1

  # “Decompressing files” window that stays up during the whole extract.
  infobox "Please wait" "Decompressing files…\n\n(This can take several minutes)"
  sleep 0.2

  local tar_flags=(--numeric-owner --acls --xattrs --xattrs-include='*')

  if [[ "$mode" == "select" ]]; then
    # shellcheck disable=SC2086
    tar -xvpzf "$tarfile" -C / "${tar_flags[@]}" $selected_paths >>"$log" 2>&1
  else
    tar -xvpzf "$tarfile" -C / "${tar_flags[@]}" >>"$log" 2>&1
  fi

  local rc=$?
  {
    echo
    echo "Finished  : $(date '+%F %T')"
    echo "ExitCode  : $rc"
  } >>"$log" 2>&1

  return "$rc"
}

# ---------- restore core ----------
restore_from_backup_dir() {
  local d="$1" run_dir="$2"

  # IMPORTANT: show a stable wait window *before* reading manifest/tar listing etc.
  infobox "Please wait" "Retrieving information…"
  sleep 0.6

  local mf="$d/manifest.env"
  local tarfile
  tarfile="$(ls -1 "$d"/*.tar.gz 2>/dev/null | head -n 1 || true)"
  [[ -f "$tarfile" ]] || { msgbox "Error" "No tar.gz found in:\n$d"; return 1; }

  local NAME MODE CREATED_AT
  NAME="$(manifest_get NAME "$mf" | trim || true)"
  MODE="$(manifest_get MODE "$mf" | trim || true)"
  CREATED_AT="$(manifest_get CREATED_AT "$mf" | trim || true)"

  local log="$run_dir/restore.log"
  local status="$run_dir/status.env"

  {
    echo "NAME=${NAME:-$(basename "$d")}"
    echo "SOURCE_DIR=$d"
    echo "ARCHIVE=$tarfile"
    echo "MANIFEST_CREATED_AT=${CREATED_AT:-unknown}"
    echo "MANIFEST_MODE=${MODE:-unknown}"
    echo "STARTED_AT=$(date '+%F %T')"
    echo "HOSTNAME=$(hostname -s 2>/dev/null || hostname)"
    echo "FQDN=$(hostname -f 2>/dev/null || true)"
  } >"$status"

  local restore_mode
  restore_mode="$(pick_restore_mode_full_selective)" || { echo "RESULT=cancelled" >>"$status"; return 0; }

  local selected_paths=""
  if [[ "$restore_mode" == "select" ]]; then
    infobox "Please wait" "A few moments… decompressing/indexing archive for selection…"
    sleep 0.4

    selected_paths="$(select_top_level_targets "$tarfile" || true)"

    if yesno "Advanced Selection" "Do you want to pick individual files too?"; then
      local adv
      adv="$(menu "How to pick files?" "Choose selection method:" \
        "subtree" "Pick from a known subtree (.hybrid_admin/.server_admin/tftpboot)" \
        "search"  "Search inside the archive by filename/path")" || adv=""

      if [[ "$adv" == "subtree" ]]; then
        local subtree file_pick
        subtree="$(select_subtree_menu)" || subtree=""
        [[ -n "$subtree" ]] && file_pick="$(select_files_under_prefix "$tarfile" "$subtree" || true)" || file_pick=""
        selected_paths="$(printf "%s %s" "$selected_paths" "$file_pick" | trim)"
      elif [[ "$adv" == "search" ]]; then
        local picks
        picks="$(search_paths_in_tar "$tarfile" || true)"
        selected_paths="$(printf "%s %s" "$selected_paths" "$picks" | trim)"
      fi
    fi

    if [[ -z "$selected_paths" ]]; then
      msgbox "Nothing Selected" "No files/paths selected. Cancelling."
      echo "RESULT=cancelled" >>"$status"
      return 0
    fi
  fi

  local confirm_msg
  if [[ "$restore_mode" == "select" ]]; then
    confirm_msg="Restore set: $(basename "$d")\n\nMODE: Selective\n\nSelected entries:\n${selected_paths}\n\nThis will overwrite files in place.\n\nProceed?"
  else
    confirm_msg="Restore set: $(basename "$d")\n\nMODE: Full Restore\n\nThis will overwrite files in place (e.g. /root/.hybrid_admin, /root/.server_admin, /var/lib/tftpboot).\n\nProceed?"
  fi

  if ! yesno "Confirm Restore" "$confirm_msg"; then
    echo "RESULT=cancelled" >>"$status"
    return 0
  fi

  local typed
  typed="$(inputbox "Final Confirmation" "Type RESTORE to proceed:" "")" || typed=""
  if [[ "$typed" != "RESTORE" ]]; then
    msgbox "Cancelled" "Restore cancelled (confirmation not provided)."
    echo "RESULT=cancelled" >>"$status"
    return 0
  fi

  run_restore_simple "$d" "$tarfile" "$log" "$run_dir" "$restore_mode" "$selected_paths"
  local rc=$?

  echo "FINISHED_AT=$(date '+%F %T')" >>"$status"
  if (( rc != 0 )); then
    echo "RESULT=failed" >>"$status"
    echo "EXIT_CODE=$rc" >>"$status"
    msgbox "Restore Failed" "Restore failed (exit $rc).\n\nLog:\n$log"
    return 1
  fi
  cleanup_archive_on_success "$tarfile"
  echo "RESULT=success" >>"$status"
  msgbox "Restore Complete" "Restore finished successfully.\n\nRun dir:\n$run_dir\n\nLog:\n$log"
}

# -----------------------------
# Remote restore (SSH PASSWORD ONLY; stage locally)
# -----------------------------
prompt_remote_restore_creds() {
  local host user pass rroot
  host="$(inputbox "Remote Host" "Enter SSH host/IP:" "")" || return 1
  host="$(printf "%s" "$host" | trim)"
  [[ -n "$host" ]] || return 1

  user="$(inputbox "Remote User" "Enter SSH username:" "root")" || return 1
  user="$(printf "%s" "$user" | trim)"
  [[ -n "$user" ]] || return 1

  pass="$(passwordbox "SSH Password" "Enter SSH password for ${user}@${host}:")" || return 1
  [[ -n "$pass" ]] || return 1

  rroot="$(inputbox "Remote Backup Root" "Remote directory containing backup sets:" "$DEFAULT_REMOTE_ROOT")" || return 1
  rroot="$(printf "%s" "$rroot" | trim)"
  [[ -n "$rroot" ]] || return 1

  echo "${host}|${user}|${pass}|${rroot}"
}

remote_list_candidates() {
  local host="$1" user="$2" pass="$3" rroot="$4" log_file="${5:-}"

  local -a SSHO
  read -r -a SSHO <<<"$(ssh_opts)"

  {
    echo "===== remote_list_candidates ====="
    echo "When : $(date '+%F %T')"
    echo "Host : ${user}@${host}"
    echo "Root : ${rroot}"
    echo
  } >>"$log_file" 2>/dev/null || true

  local tmp_out tmp_err rc out
  tmp_out="$(mktemp)"
  tmp_err="$(mktemp)"
  out=""

  set +e
  sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" \
    "echo '__SANITY__'; id; pwd; ls -ald '$rroot'; echo; ls -1 '$rroot' | head -n 80" \
    >"$tmp_out" 2>"$tmp_err"
  rc=$?
  set -e

  {
    echo "----- sanity rc=$rc -----"
    echo "-- STDERR --"
    sed -n '1,200p' "$tmp_err"
    echo "-- STDOUT --"
    sed -n '1,300p' "$tmp_out"
    echo
  } >>"$log_file" 2>/dev/null || true

  if (( rc != 0 )); then
    rm -f "$tmp_out" "$tmp_err" 2>/dev/null || true
    return 0
  fi

  : >"$tmp_out"; : >"$tmp_err"

  set +e
  sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" bash -s -- "$rroot" \
    >"$tmp_out" 2>"$tmp_err" <<'REMOTE_BASH'
set -eo pipefail
shopt -s nullglob

root="${1:-/root/cmds-backups}"
[[ -d "$root" ]] || exit 0

# Accept any prefix: <something>_cmds-backup-YYYYMMDD-HHMMSS
for d in "$root"/*_cmds-backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]; do
  [[ -d "$d" ]] || continue
  [[ -f "$d/manifest.env" ]] || continue
  [[ -f "$d/sha256sums.txt" ]] || continue

  tars=( "$d"/*.tar.gz )
  [[ -f "${tars[0]:-}" ]] || continue

  created="$(grep -m1 '^CREATED_AT=' "$d/manifest.env" 2>/dev/null | sed 's/^CREATED_AT=//' | sed 's/^"//;s/"$//;s/^\x27//;s/\x27$//' || true)"
  mode="$(grep -m1 '^MODE=' "$d/manifest.env" 2>/dev/null | sed 's/^MODE=//' | sed 's/^"//;s/"$//;s/^\x27//;s/\x27$//' || true)"
  [[ -n "$created" ]] || created="unknown"
  [[ -n "$mode" ]] || mode="unknown"

  printf "%s|%s|%s|%s\n" "$d" "${tars[0]}" "$created" "$mode"
done
REMOTE_BASH
  rc=$?
  set -e

  {
    echo "----- scan rc=$rc -----"
    echo "-- STDERR --"
    sed -n '1,240p' "$tmp_err"
    echo "-- STDOUT --"
    sed -n '1,400p' "$tmp_out"
    echo
  } >>"$log_file" 2>/dev/null || true

  out="$(cat "$tmp_out" 2>/dev/null || true)"
  rm -f "$tmp_out" "$tmp_err" 2>/dev/null || true
  printf "%s" "$out"
}

remote_stage_selected_bundle() {
  local run_dir="$1" host="$2" user="$3" pass="$4" rdir="$5" _rtar_hint="${6:-}"

  local staging="$run_dir/staging"
  mkdir -p "$staging"
  chmod 700 "$staging" 2>/dev/null || true

  local bundle_name
  bundle_name="$(basename "$rdir")"

  local local_bundle="$staging/$bundle_name"
  mkdir -p "$local_bundle"
  chmod 700 "$local_bundle" 2>/dev/null || true

  local stage_log="$run_dir/stage.log"
  : >"$stage_log"
  chmod 600 "$stage_log" 2>/dev/null || true

  local local_mf="$local_bundle/manifest.env"
  local local_sha="$local_bundle/sha256sums.txt"
  local local_tlog="$local_bundle/tar.log"

  local -a SSHO
  read -r -a SSHO <<<"$(ssh_opts)"

  # Stable wait window (doesn't flash)
  infobox "Please wait" "Retrieving information…"
  sleep 0.6

  {
    echo "===== CMDS REMOTE STAGING ====="
    echo "Started: $(date '+%F %T')"
    echo "Remote : ${user}@${host}:${rdir}"
    echo "Local  : ${local_bundle}"
    echo
  } >>"$stage_log" 2>&1

  infobox "Please wait" "Retrieving information…\n\nDownloading metadata (manifest/shas)…"
  sleep 0.4

  if ! sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" "cat '$rdir/manifest.env'" \
      >>"$stage_log" 2>&1 >"$local_mf"; then
    msgbox "Remote Restore Failed" "Could not fetch manifest.env\n\nSee:\n$stage_log"
    return 1
  fi

  if ! sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" "cat '$rdir/sha256sums.txt'" \
      >>"$stage_log" 2>&1 >"$local_sha"; then
    msgbox "Remote Restore Failed" "Could not fetch sha256sums.txt\n\nSee:\n$stage_log"
    return 1
  fi

  sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" "cat '$rdir/tar.log' 2>/dev/null || true" \
    >>"$stage_log" 2>&1 >"$local_tlog" || : >"$local_tlog"

  infobox "Please wait" "Retrieving information…\n\nLocating archive…"
  sleep 0.3

  local remote_tar
  remote_tar="$(sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" \
      "ls -1 '$rdir'/*.tar.gz 2>/dev/null | head -n 1" \
      2>>"$stage_log" | tr -d '\r' | head -n1 || true)"

  if [[ -z "${remote_tar:-}" ]]; then
    msgbox "Remote Restore Failed" "No *.tar.gz found in remote bundle.\n\nSee:\n$stage_log"
    return 1
  fi

  local local_tar="$local_bundle/$(basename "$remote_tar")"

  infobox "Please wait" "Retrieving information…\n\nSizing archive…"
  sleep 0.3

  local rsize
  rsize="$(sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" \
      "stat -c %s '$remote_tar' 2>/dev/null || wc -c < '$remote_tar' 2>/dev/null || echo 0" \
      2>>"$stage_log" | tr -d '\r' | tr -d ' ' | tail -n1 || true)"
  [[ "$rsize" =~ ^[0-9]+$ ]] || rsize=0
  (( rsize > 0 )) || rsize=1

  {
    echo "Archive: $remote_tar"
    echo "Size   : $rsize"
    echo
  } >>"$stage_log" 2>&1

  # Download with simple “please wait…” updates (no blank screen).
  infobox "Please wait" "Downloading archive…\n\n0% (starting)"
  sleep 0.2

  : >"$local_tar"
  chmod 600 "$local_tar" 2>/dev/null || true

  (
    set +e
    sshpass -p "$pass" ssh "${SSHO[@]}" "${user}@${host}" "cat '$remote_tar'" \
      2>>"$stage_log" >"$local_tar"
    echo "$?" >"$run_dir/ssh.rc"
    exit 0
  ) &
  local dl_pid=$!

  local last_shown=-1
  while kill -0 "$dl_pid" 2>/dev/null; do
    local got p
    got="$(wc -c <"$local_tar" 2>/dev/null | tr -d ' ' | tr -d '\r' || echo 0)"
    [[ "$got" =~ ^[0-9]+$ ]] || got=0

    p=$(( got * 100 / rsize ))
    (( p < 0 )) && p=0
    (( p > 100 )) && p=100

    # only redraw when percent changes (keeps it stable)
    if (( p != last_shown )); then
      infobox "Please wait" "Downloading archive…\n\n${p}%"
      last_shown=$p
    fi
    sleep 1
  done

  wait "$dl_pid" 2>/dev/null || true

  local ssh_rc="1"
  [[ -f "$run_dir/ssh.rc" ]] && ssh_rc="$(tr -d '[:space:]' <"$run_dir/ssh.rc" 2>/dev/null || echo 1)"
  rm -f "$run_dir/ssh.rc" 2>/dev/null || true

  if (( ssh_rc != 0 )); then
    msgbox "Remote Restore Failed" "Archive download failed (ssh=$ssh_rc).\n\nSee:\n$stage_log"
    return 1
  fi

  if [[ ! -s "$local_tar" ]]; then
    msgbox "Remote Restore Failed" "Downloaded archive is empty.\n\nSee:\n$stage_log"
    return 1
  fi

  infobox "Please wait" "Finalizing…"
  sleep 0.4

  {
    echo "Staged OK: $local_bundle"
    ls -al "$local_bundle" >>"$stage_log" 2>&1 || true
    echo "Finished: $(date '+%F %T')"
  } >>"$stage_log" 2>&1

  echo "$local_bundle"
}

remote_restore_flow() {
  local creds host user pass rroot
  creds="$(prompt_remote_restore_creds)" || return 0
  IFS='|' read -r host user pass rroot <<<"$creds"

  local run_dir
  run_dir="$(make_run_dir)"
  local rlog="$run_dir/remote_list.log"
  : >"$rlog"
  chmod 600 "$rlog" 2>/dev/null || true

  infobox "Please wait" "Querying remote backups…"
  sleep 0.6

  local lines
  lines="$(remote_list_candidates "$host" "$user" "$pass" "$rroot" "$rlog")"

  if [[ -z "${lines:-}" ]]; then
    msgbox "No Remote Backups Found" \
"No valid backup sets found under:\n${user}@${host}:${rroot}\n\nA debug log was written to:\n$rlog"
    return 0
  fi

  local selected_line
  selected_line="$(printf "%s\n" "$lines" | menu_pick_backup_from_lines)" || return 0

  local rdir rtar
  rdir="$(printf "%s" "$selected_line" | cut -d'|' -f1)"
  rtar="$(printf "%s" "$selected_line" | cut -d'|' -f2)"

  local local_bundle
  local_bundle="$(remote_stage_selected_bundle "$run_dir" "$host" "$user" "$pass" "$rdir" "$rtar")" || return 0

  # Same behavior as local: stable wait -> manifest
  infobox "Please wait" "Retrieving information…"
  sleep 0.6
  show_manifest_summary "$local_bundle/manifest.env"
  restore_from_backup_dir "$local_bundle" "$run_dir"
}

# ---------- main ----------
main() {
  need_root
  have_dialog || { echo "dialog not installed." >&2; exit 1; }

  need_cmd tar
  need_cmd sha256sum
  need_cmd ssh
  need_cmd sshpass
  need_cmd awk
  need_cmd sed
  need_cmd grep
  need_cmd stat
  need_cmd wc

  mkdir -p "$RUNS_BASE"
  chmod 700 "$RUNS_BASE" 2>/dev/null || true

  local src_mode
  src_mode="$(pick_mode_local_remote)" || exit 0

  if [[ "$src_mode" == "remote" ]]; then
    remote_restore_flow
    exit 0
  fi

  local base_dir
  if yesno "Backup Location" "Default search directory:\n$DEFAULT_LOCAL_ROOT\n\nUse this directory?"; then
    base_dir="$DEFAULT_LOCAL_ROOT"
  else
    base_dir="$(inputbox "Backup Directory" "Enter the base directory containing backup sets:" "$DEFAULT_LOCAL_ROOT")" || exit 0
    base_dir="$(printf "%s" "$base_dir" | trim)"
  fi

  if [[ ! -d "$base_dir" ]]; then
    msgbox "Error" "Directory not found:\n$base_dir"
    exit 0
  fi

  infobox "Please wait" "Retrieving information…"
  sleep 0.6

  local tmp
  tmp="$(mktemp)"
  find_backup_candidates_local "$base_dir" >"$tmp" || true
  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    msgbox "No Backups Found" \
"No valid backup sets found under:\n$base_dir\n\nLooking for dirs like:\n<host>_cmds-backup-YYYYMMDD-HHMMSS\nwith:\n- manifest.env\n- sha256sums.txt\n- *.tar.gz"
    exit 0
  fi

  local selected_line
  selected_line="$(cat "$tmp" | menu_pick_backup_from_lines)" || { rm -f "$tmp"; exit 0; }
  rm -f "$tmp"

  local backup_dir
  backup_dir="$(printf "%s" "$selected_line" | cut -d'|' -f1)"

  infobox "Please wait" "Retrieving information…"
  sleep 0.6
  show_manifest_summary "$backup_dir/manifest.env"

  local run_dir
  run_dir="$(make_run_dir)"
  restore_from_backup_dir "$backup_dir" "$run_dir"
}

main "$@"