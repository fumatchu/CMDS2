#!/bin/bash
# ============================================================
# CMDS Backup Core (Local + Remote via SSH-only upload)
#
# Backups:
#   /root/.hybrid_admin
#   /root/.server_admin
#   /var/lib/tftpboot  (and all subdirectories)
#
# Optional:
#   /var/lib/tftpboot/images   (IOS-XE images; huge)
#
# Output (LOCAL + REMOTE are UNIFORM):
#   <backup_root>/<name>/
#       <name>.tar.gz
#       manifest.env
#       sha256sums.txt
#       tar.log
#
# Operational logs (always):
#   /root/.server_admin/runs/cmds-backup/<name>/
#       run.env
#       manifest.env
#       sha256sums.txt
#       tar.log
#
# Remote upload:
#   - SSH/SCP only (no rsync required on remote)
#   - pv required only on CMDS server for % progress
#   - Streams tar via: pv file | ssh "cat > remote.tar.gz"
#   - Ships metadata via scp
#
# Headless mode:
#   ./cmds_backup.sh --headless
#     Reads env overrides:
#       BACKUP_ROOT_OVERRIDE
#       CMDS_BACKUP_MODE_OVERRIDE  (local|remote)
#       INCLUDE_IOSXE_IMAGES_OVERRIDE (yes|no)
#       REMOTE_CLEANUP_AFTER_UPLOAD (0|1)
#     Remote creds are loaded from:
#       /root/.server_admin/cmds-backup-remote.conf
# ============================================================

set -euo pipefail

# -----------------------------
# Globals / flags
# -----------------------------
HEADLESS=0

# -----------------------------
# UI / colors
# -----------------------------
TEXTRESET=$(tput sgr0 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)

trim(){ printf '%s' "${1:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}This script must be run as root!${TEXTRESET}"
    exit 1
  fi
}

has_dialog() { command -v dialog >/dev/null 2>&1; }

# -----------------------------
# TTY handling (critical for nested dialog)
# -----------------------------
TTY_PATH="/dev/tty"
if [[ -e "$TTY_PATH" ]]; then
  exec 9<> "$TTY_PATH" || true
fi
fd9_ok() { [[ -e /proc/$$/fd/9 ]]; }

# -----------------------------
# Dialog wrappers (headless-safe)
# -----------------------------
msgbox() {
  local title="${1:-Info}"; shift || true
  if (( HEADLESS )); then
    echo "$title: $*"
    return 0
  fi
  if has_dialog && fd9_ok; then
    dialog --title "$title" --msgbox "$*" 10 90 <&9 >&9 2>&9
  elif has_dialog; then
    dialog --title "$title" --msgbox "$*" 10 90
  else
    echo "$title: $*"
  fi
}

infobox() {
  local title="${1:-Info}"; shift || true
  if (( HEADLESS )); then
    echo "$title: $*"
    return 0
  fi
  if has_dialog && fd9_ok; then
    dialog --title "$title" --infobox "$*" 6 90 <&9 >&9 2>&9
  elif has_dialog; then
    dialog --title "$title" --infobox "$*" 6 90
  else
    echo "$title: $*"
  fi
}

inputbox() {
  local title="$1"; local prompt="$2"; local def="${3:-}"
  if (( HEADLESS )); then
    echo "${def}"
    return 0
  fi
  if has_dialog && fd9_ok; then
    dialog --stdout --title "$title" --inputbox "$prompt" 10 70 "$def" <&9 2>&9
  elif has_dialog; then
    dialog --stdout --title "$title" --inputbox "$prompt" 10 70 "$def"
  else
    read -r -p "$prompt [$def]: " val
    echo "${val:-$def}"
  fi
}

passwordbox() {
  local title="$1"; local prompt="$2"
  if (( HEADLESS )); then
    echo ""
    return 0
  fi
  if has_dialog && fd9_ok; then
    dialog --stdout --insecure --title "$title" --passwordbox "$prompt" 10 70 <&9 2>&9
  elif has_dialog; then
    dialog --stdout --insecure --title "$title" --passwordbox "$prompt" 10 70
  else
    read -r -s -p "$prompt: " val; echo; echo "$val"
  fi
}

yesno() {
  local title="$1"; local prompt="$2"
  if (( HEADLESS )); then
    return 1
  fi
  if has_dialog && fd9_ok; then
    dialog --title "$title" --yesno "$prompt" 10 90 <&9 >&9 2>&9
    return $?
  elif has_dialog; then
    dialog --title "$title" --yesno "$prompt" 10 90
    return $?
  else
    local ans
    read -r -p "$prompt [y/N]: " ans
    [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
  fi
}

menu() {
  local title="$1"; local prompt="$2"; shift 2
  if (( HEADLESS )); then
    echo ""
    return 1
  fi
  if has_dialog && fd9_ok; then
    dialog --stdout --title "$title" --menu "$prompt" 15 90 12 "$@" <&9 2>&9
  elif has_dialog; then
    dialog --stdout --title "$title" --menu "$prompt" 15 90 12 "$@"
  else
    echo "$1"
  fi
}

# -----------------------------
# Split UI (tailboxbg + gauge) for long operations
# -----------------------------
DIALOG_AVAILABLE=0
if has_dialog; then DIALOG_AVAILABLE=1; fi

STATUS_FILE=""
PROG_PIPE=""
PROG_FD=""
DIALOG_PID=""

TAIL_H=; TAIL_W=; GAUGE_H=; GAUGE_W=; GAUGE_ROW=; GAUGE_COL=

_ui_calc_layout() {
  local lines cols
  if ! read -r lines cols < <(stty size 2>/dev/null); then lines=24 cols=80; fi
  if (( lines < 18 || cols < 70 )); then DIALOG_AVAILABLE=0; return; fi

  TAIL_H=$((lines - 10)); (( TAIL_H < 10 )) && TAIL_H=10
  TAIL_W=$((cols - 4));   (( TAIL_W < 68 )) && TAIL_W=68

  GAUGE_H=7
  GAUGE_W=$TAIL_W
  GAUGE_ROW=$((TAIL_H + 3))
  GAUGE_COL=2
}

_ui_fd_open() {
  [[ -n "${PROG_FD:-}" ]] || return 1
  [[ -e "/proc/$$/fd/$PROG_FD" ]] || return 1
  return 0
}

ui_start() {
  local backtitle="${1:-CMDS Backup}"
  (( HEADLESS )) && { DIALOG_AVAILABLE=0; return 0; }

  _ui_calc_layout

  STATUS_FILE="$(mktemp)"; : > "$STATUS_FILE"
  PROG_PIPE="$(mktemp -u)"
  PROG_FD=""
  DIALOG_PID=""

  if (( DIALOG_AVAILABLE )) && fd9_ok; then
    mkfifo "$PROG_PIPE"
    exec {PROG_FD}<>"$PROG_PIPE"

    (
      dialog --no-shadow \
             --backtitle "$backtitle" \
             --begin 2 2 --title "Activity" --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
             --and-widget \
             --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Overall Progress" \
             --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$PROG_PIPE" >&9 2>&9
    ) & DIALOG_PID=$!
    sleep 0.15
  else
    DIALOG_AVAILABLE=0
  fi
}

ui_status() {
  local msg="$1"
  if [[ -n "${STATUS_FILE:-}" ]]; then
    printf '%(%Y-%m-%d %I:%M:%S %p)T %s\n' -1 "$msg" >> "$STATUS_FILE"
  fi
  (( DIALOG_AVAILABLE )) || echo "$msg"
}

ui_gauge() {
  local p="$1"; shift || true
  local m="${*:-Working…}"
  if (( DIALOG_AVAILABLE )) && _ui_fd_open; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$PROG_FD"; } 2>/dev/null || true
  else
    echo "[progress] $p% - $m"
  fi
}

ui_stop() {
  (( HEADLESS )) && return 0

  if (( DIALOG_AVAILABLE )) && _ui_fd_open; then
    { printf 'XXX\n100\nDone.\nXXX\n' >&"$PROG_FD"; } 2>/dev/null || true
  fi

  if [[ -n "${PROG_FD:-}" ]]; then
    exec {PROG_FD}>&- 2>/dev/null || true
    PROG_FD=""
  fi
  if [[ -n "${PROG_PIPE:-}" ]]; then
    rm -f "$PROG_PIPE" 2>/dev/null || true
    PROG_PIPE=""
  fi
  if [[ -n "${DIALOG_PID:-}" ]]; then
    kill "$DIALOG_PID" 2>/dev/null || true
    DIALOG_PID=""
  fi
  if [[ -n "${STATUS_FILE:-}" ]]; then
    rm -f "$STATUS_FILE" 2>/dev/null || true
    STATUS_FILE=""
  fi
}

# -----------------------------
# Paths / defaults
# -----------------------------
BACKUP_ROOT_DEFAULT="/root/cmds-backups"
SCRIPT_PATH="$(readlink -f "$0")"

CONFIG_DIR="/root/.server_admin"
REMOTE_CONF="${CONFIG_DIR}/cmds-backup-remote.conf"

RUNS_ROOT="${CONFIG_DIR}/runs/cmds-backup"

TFTP_IMAGES_DIR="/var/lib/tftpboot/images"

BASE_INCLUDE_DIRS=(
  "/root/.hybrid_admin"
  "/root/.server_admin"
  "/var/lib/tftpboot"
)

BACKUP_ARCHIVE=""
BACKUP_OUTDIR=""
BACKUP_NAME=""

REMOTE_CLEANUP_AFTER_UPLOAD="${REMOTE_CLEANUP_AFTER_UPLOAD:-1}"
REMOTE_UPLOAD_DEST=""

TAR_EXCLUDES=()
TAR_ADD=()

RUN_STARTED_AT=""

# -----------------------------
# Helpers
# -----------------------------
ensure_config_dir() {
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  chmod 700 "$CONFIG_DIR" 2>/dev/null || true
}

ensure_runs_root() {
  ensure_config_dir
  mkdir -p "$RUNS_ROOT" 2>/dev/null || true
  chmod 700 "$RUNS_ROOT" 2>/dev/null || true
}

runs_dir_for_name() {
  local name="$1"
  echo "${RUNS_ROOT}/${name}"
}

runs_copy_bundle_logs() {
  local outdir="$1"
  local name="$2"

  ensure_runs_root
  local rdir; rdir="$(runs_dir_for_name "$name")"
  mkdir -p "$rdir" 2>/dev/null || true
  chmod 700 "$rdir" 2>/dev/null || true

  [[ -f "$outdir/manifest.env" ]]   && cp -f "$outdir/manifest.env"   "$rdir/" 2>/dev/null || true
  [[ -f "$outdir/sha256sums.txt" ]] && cp -f "$outdir/sha256sums.txt" "$rdir/" 2>/dev/null || true
  [[ -f "$outdir/tar.log" ]]        && cp -f "$outdir/tar.log"        "$rdir/" 2>/dev/null || true
}

runs_write_status() {
  local name="$1"
  local status="$2"
  local mode="$3"
  local include_images="$4"
  local outdir="${5:-}"
  local archive="${6:-}"
  local remote_dest="${7:-}"
  local err="${8:-}"

  ensure_runs_root
  local rdir; rdir="$(runs_dir_for_name "$name")"
  mkdir -p "$rdir" 2>/dev/null || true
  chmod 700 "$rdir" 2>/dev/null || true

  {
    echo "NAME=${name}"
    echo "STATUS=${status}"
    echo "MODE=${mode}"
    echo "INCLUDE_IOSXE_IMAGES=${include_images}"
    echo "STARTED_AT=${RUN_STARTED_AT:-}"
    echo "FINISHED_AT=$(date '+%Y-%m-%d %I:%M:%S %p')"
    echo "BUNDLE_DIR=${outdir}"
    echo "ARCHIVE=${archive}"
    echo "REMOTE_DEST=${remote_dest}"
    echo "SCRIPT=${SCRIPT_PATH}"
    echo "ERROR=${err:-}"
  } > "${rdir}/run.env" 2>/dev/null || true

  ln -sfn "$rdir" "${RUNS_ROOT}/latest" 2>/dev/null || true
}

# -----------------------------
# Dependencies
# -----------------------------
ensure_sshpass() {
  command -v sshpass >/dev/null 2>&1 && return 0
  infobox "Dependency" "Installing sshpass..."
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install sshpass >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum -y install sshpass >/dev/null 2>&1 || true
  fi
  command -v sshpass >/dev/null 2>&1 || {
    msgbox "Error" "sshpass is required for password-based SSH/SCP but could not be installed."
    exit 1
  }
}

ensure_pv() {
  command -v pv >/dev/null 2>&1 && return 0
  ui_status "Installing pv (progress viewer)…"
  ui_gauge 8 "Installing pv…"
  if command -v dnf >/dev/null 2>&1; then
    dnf -y install pv >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum -y install pv >/dev/null 2>&1 || true
  fi
  command -v pv >/dev/null 2>&1
}

ensure_backup_root() {
  local root="$1"
  mkdir -p "$root"
  chmod 700 "$root" 2>/dev/null || true
}

# -----------------------------
# Remote config helpers (SAFE FOR SPECIAL CHARS)
# -----------------------------
save_remote_config() {
  ensure_config_dir
  local host="$1" user="$2" dir="$3" pass="$4"
  {
    printf 'REMOTE_HOST=%q\n' "$(trim "$host")"
    printf 'REMOTE_USER=%q\n' "$(trim "$user")"
    printf 'REMOTE_DIR=%q\n'  "$(trim "$dir")"
    printf 'REMOTE_PASS=%q\n' "$pass"
  } > "$REMOTE_CONF"
  chmod 600 "$REMOTE_CONF" 2>/dev/null || true
}

load_remote_config() {
  [[ -f "$REMOTE_CONF" ]] || return 1
  # shellcheck disable=SC1090
  source "$REMOTE_CONF" || return 1
  [[ -n "${REMOTE_HOST:-}" && -n "${REMOTE_USER:-}" && -n "${REMOTE_DIR:-}" && -n "${REMOTE_PASS:-}" ]] || return 1
  return 0
}

# -----------------------------
# Include Images prompt (interactive)
# -----------------------------
ask_include_images_interactive() {
  local prompt="Include IOS-XE images in this backup?

This includes:
  ${TFTP_IMAGES_DIR}

NOTE: This can significantly increase backup size and runtime."
  if yesno "Include IOS-XE Images?" "$prompt"; then
    echo "yes"
  else
    echo "no"
  fi
}

# -----------------------------
# Cleanup helpers
# -----------------------------
cleanup_local_bundle_in_current_ui() {
  local outdir="$1"
  [[ -z "${outdir:-}" || ! -d "$outdir" ]] && return 0

  ui_status "Cleanup: removing local staged bundle (remote upload cache)…"
  ui_gauge 97 "Cleaning local cache…"
  rm -rf --one-file-system "$outdir" 2>/dev/null || rm -rf "$outdir" 2>/dev/null || true
  ui_status "Cleanup complete."
  ui_gauge 99 "Cleanup complete."
}

cleanup_local_bundle_no_ui() {
  local outdir="$1"
  [[ -z "${outdir:-}" || ! -d "$outdir" ]] && return 0
  rm -rf --one-file-system "$outdir" 2>/dev/null || rm -rf "$outdir" 2>/dev/null || true
}

# -----------------------------
# Run tar with split-UI progress
# -----------------------------
run_tar_with_split_ui() {
  local target_archive="$1"
  local tar_log="$2"
  local mode="$3"

  local label="Creating archive"
  [[ "$mode" == "remote" ]] && label="Creating local archive for upload"

  ui_start "CMDS Backup"
  ui_status "$label"
  ui_gauge 1 "Preparing…"

  local total=0 rel abs cnt
  for rel in "${TAR_ADD[@]}"; do
    abs="/$rel"
    if [[ -e "$abs" ]]; then
      cnt="$(find "$abs" -mindepth 0 -print 2>/dev/null | wc -l || echo 0)"
      total=$(( total + cnt ))
    fi
  done
  [[ "$total" -lt 1 ]] && total=1

  ui_status "Estimated entries: $total"
  ui_status "Archive: $target_archive"
  ui_status "Tar flags: --numeric-owner --acls --xattrs --xattrs-include='*'"
  ui_gauge 3 "Archiving…"

  {
    echo "===== CMDS BACKUP TAR LOG ====="
    echo "Mode     : $mode"
    echo "Time     : $(date '+%F %T')"
    echo "Archive  : $target_archive"
    echo "TarFlags : --numeric-owner --acls --xattrs --xattrs-include='*'"
    echo "Estimated entries: $total"
    if ((${#TAR_EXCLUDES[@]})); then
      echo "Excludes : ${TAR_EXCLUDES[*]}"
    else
      echo "Excludes : (none)"
    fi
    echo
    echo "----- tar output (verbose) -----"
  } >> "$tar_log"

  local -a exclude_args=()
  local ex
  for ex in "${TAR_EXCLUDES[@]}"; do
    exclude_args+=( "--exclude=$ex" )
  done

  local progfd="${PROG_FD:-}"
  local statusf="${STATUS_FILE:-}"

  set +e
  tar -C / --numeric-owner --acls --xattrs --xattrs-include='*' \
      "${exclude_args[@]}" \
      -czvf "$target_archive" "${TAR_ADD[@]}" 2>&1 \
    | tee -a "$tar_log" \
    | awk -v total="$total" -v fd="$progfd" -v sf="$statusf" '
        BEGIN { c=0; lastpct=-1; }
        {
          c++
          pct=int((c*100)/total); if(pct>99) pct=99
          msg=$0
          if(length(msg)>140) msg=substr(msg,1,137)"..."

          if (sf != "") {
            cmd="date +%Y-%m-%d\\ %I:%M:%S\\ %p"; cmd | getline t; close(cmd)
            print t " " msg >> sf
            fflush(sf)
          }

          if (fd != "" && pct != lastpct) {
            printf "XXX\n%d\n%s\nXXX\n", pct, "Archiving… (" pct "%)" > ("/dev/fd/" fd)
            fflush("/dev/fd/" fd)
            lastpct=pct
          }
        }
        END {
          if (fd != "") {
            printf "XXX\n100\nArchive complete.\nXXX\n" > ("/dev/fd/" fd)
            fflush("/dev/fd/" fd)
          }
          if (sf != "") {
            cmd="date +%Y-%m-%d\\ %I:%M:%S\\ %p"; cmd | getline t; close(cmd)
            print t " Archive complete." >> sf
            fflush(sf)
          }
        }'
  local tar_rc=${PIPESTATUS[0]}
  set -e

  ui_gauge 100 "Archive complete."
  sleep 0.2
  ui_stop
  return "$tar_rc"
}

# -----------------------------
# Build backup bundle
# -----------------------------
make_backup() {
  local backup_root="$1"
  local mode="${2:-local}"
  local include_images="${3:-no}"

  BACKUP_ARCHIVE=""
  BACKUP_OUTDIR=""
  BACKUP_NAME=""

  ensure_backup_root "$backup_root"

  local fqdn created stamp host
  host="$(hostname -s 2>/dev/null || echo host)"
  fqdn="$(hostname -f 2>/dev/null || echo "$host")"
  stamp="$(date +%Y%m%d-%H%M%S)"
  created="$(date '+%Y-%m-%d %I:%M:%S %p')"

  local name="${host}_cmds-backup-${stamp}"
  BACKUP_NAME="$name"

  local outdir archive_final
  outdir="${backup_root}/${name}"
  archive_final="${outdir}/${name}.tar.gz"

  mkdir -p "$outdir"

  local -a to_add=()
  local d
  for d in "${BASE_INCLUDE_DIRS[@]}"; do
    [[ -d "$d" ]] && to_add+=("${d#/}")
  done

  if [[ ${#to_add[@]} -eq 0 ]]; then
    msgbox "Error" "None of the base backup directories exist:\n\n${BASE_INCLUDE_DIRS[*]}"
    rm -rf "$outdir"
    return 1
  fi

  local -a excludes=()
  local include_note="no"
  if [[ "$include_images" == "yes" ]]; then
    include_note="yes"
  else
    excludes+=( "var/lib/tftpboot/images" "var/lib/tftpboot/images/*" )
  fi

  {
    echo "NAME=${name}"
    echo "HOSTNAME=${host}"
    echo "FQDN=${fqdn}"
    echo "CREATED_AT=${created}"
    echo "SCRIPT=${SCRIPT_PATH}"
    echo "FORMAT=tar.gz"
    echo "MODE=${mode}"
    echo "INCLUDES=${BASE_INCLUDE_DIRS[*]}"
    echo "INCLUDE_IOSXE_IMAGES=${include_note}"
    if ((${#excludes[@]})); then
      echo "TAR_EXCLUDES=${excludes[*]}"
    else
      echo "TAR_EXCLUDES=(none)"
    fi
    echo "TAR_FLAGS=--numeric-owner --acls --xattrs --xattrs-include='\''*'\''"
  } > "${outdir}/manifest.env"

  local tar_log="${outdir}/tar.log"
  : > "$tar_log"

  TAR_ADD=("${to_add[@]}")
  TAR_EXCLUDES=("${excludes[@]}")

  if ! run_tar_with_split_ui "$archive_final" "$tar_log" "$mode"; then
    echo "ERROR: tar failed" >> "$tar_log" 2>/dev/null || true
    runs_copy_bundle_logs "$outdir" "$name"
    runs_write_status "$name" "failed" "$mode" "$include_note" "$outdir" "$archive_final" "" "tar failed"
    rm -rf "$outdir"
    rm -f "$archive_final" 2>/dev/null || true
    return 1
  fi

  ui_start "CMDS Backup"
  ui_status "Generating SHA256 checksum…"
  ui_gauge 20 "Hashing archive…"

  if ! sha256sum "$archive_final" 2>>"$tar_log" \
      | sed "s|$archive_final|$(basename "$archive_final")|" \
      > "${outdir}/sha256sums.txt"; then
    ui_stop
    echo "ERROR: sha256sum failed" >> "$tar_log" 2>/dev/null || true
    runs_copy_bundle_logs "$outdir" "$name"
    runs_write_status "$name" "failed" "$mode" "$include_note" "$outdir" "$archive_final" "" "sha256sum failed"
    rm -rf "$outdir"
    return 1
  fi

  ui_gauge 100 "Checksum complete."
  sleep 0.2
  ui_stop

  BACKUP_ARCHIVE="$archive_final"
  BACKUP_OUTDIR="$outdir"

  runs_copy_bundle_logs "$outdir" "$name"
  return 0
}

# -----------------------------
# Remote transfer (SSH-only tar stream + pv progress)
# -----------------------------
upload_with_pv_ssh_stream() {
  local local_file="$1" remote_user="$2" remote_host="$3" remote_path="$4" remote_pass="$5"

  local size
  size="$(stat -c %s "$local_file" 2>/dev/null || echo 0)"
  [[ "$size" =~ ^[0-9]+$ ]] || size=0
  (( size > 0 )) || size=1

  ui_status "Uploading $(basename "$local_file") → ${remote_user}@${remote_host}:${remote_path}"
  ui_gauge 10 "Uploading archive…"

  local progfd="${PROG_FD:-}"
  local statusf="${STATUS_FILE:-}"
  local up_err; up_err="$(mktemp)"

  set +e
  pv -s "$size" -f -n "$local_file" 2> >( \
    awk -v fd="$progfd" -v sf="$statusf" '
      BEGIN { last=-1; }
      function stamp(){ cmd="date +%Y-%m-%d\\ %I:%M:%S\\ %p"; cmd|getline t; close(cmd); return t }
      {
        pct=int($1+0); if(pct<0)pct=0; if(pct>100)pct=100
        if (pct != last) {
          if (sf != "") { print stamp() " upload: " pct "%" >> sf; fflush(sf) }
          if (fd != "") {
            printf "XXX\n%d\n%s\nXXX\n", pct, "Uploading archive… (" pct "%)" > ("/dev/fd/" fd)
            fflush("/dev/fd/" fd)
          }
          last=pct
        }
      }' \
  ) | sshpass -p "$remote_pass" ssh -o StrictHostKeyChecking=no \
        "${remote_user}@${remote_host}" \
        "cat > '$remote_path'" 2>"$up_err"
  local rc=$?
  set -e

  if (( rc != 0 )); then
    ui_status "ERROR: archive upload failed"
    ui_gauge 100 "Upload failed"
    rm -f "$up_err"
    return 1
  fi

  rm -f "$up_err"
  ui_status "Archive upload complete."
  return 0
}

remote_upload_bundle() {
  local outdir="$1"
  local remote_host="$2" remote_user="$3" remote_dir="$4" remote_pass="$5"
  local name="$6"
  local include_images="$7"

  REMOTE_UPLOAD_DEST=""

  if [[ -z "${outdir:-}" || ! -d "$outdir" ]]; then
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "" "" "bundle folder missing"
    msgbox "Upload Failed" "Internal error: local bundle folder missing/empty:\n\n$outdir"
    return 1
  fi

  local tarball
  tarball="$(find "$outdir" -maxdepth 1 -type f -name '*.tar.gz' | head -n1 || true)"
  if [[ -z "$tarball" || ! -f "$tarball" ]]; then
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "" "" "tarball missing"
    msgbox "Upload Failed" "Could not find tar.gz inside:\n\n$outdir"
    return 1
  fi

  ensure_sshpass

  ui_start "CMDS Backup"
  ui_status "Remote upload (SSH-only)…"
  ui_gauge 3 "Connecting…"

  local base_outdir base_tarball
  base_outdir="$(basename "$outdir")"
  base_tarball="$(basename "$tarball")"

  local remote_bundle_dir remote_tar_path
  remote_bundle_dir="${remote_dir%/}/${base_outdir}"
  remote_tar_path="${remote_bundle_dir}/${base_tarball}"

  local test_err; test_err="$(mktemp)"
  if ! sshpass -p "$remote_pass" ssh -o StrictHostKeyChecking=no "${remote_user}@${remote_host}" \
      "mkdir -p '$remote_bundle_dir' && test -w '$remote_bundle_dir'" \
      2>"$test_err"; then
    ui_stop
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "$tarball" "" "remote mkdir/test failed"
    msgbox "Remote Failed" "Could not login/create/write to:
${remote_user}@${remote_host}:${remote_bundle_dir}

Error:
$(tail -n 120 "$test_err")"
    rm -f "$test_err"
    return 1
  fi
  rm -f "$test_err"

  if ! ensure_pv; then
    ui_stop
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "$tarball" "" "pv missing"
    msgbox "Error" "pv is required on the CMDS server to show upload % progress."
    return 1
  fi

  if ! upload_with_pv_ssh_stream "$tarball" "$remote_user" "$remote_host" "$remote_tar_path" "$remote_pass"; then
    ui_stop
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "$tarball" "" "archive upload failed"
    msgbox "Upload Failed" "Archive upload failed."
    return 1
  fi

  ui_status "Uploading metadata (manifest/checksums/log)…"
  ui_gauge 95 "Uploading metadata…"

  local scp_err; scp_err="$(mktemp)"
  if ! sshpass -p "$remote_pass" scp -o StrictHostKeyChecking=no \
      "$outdir/manifest.env" "$outdir/sha256sums.txt" "$outdir/tar.log" \
      "${remote_user}@${remote_host}:${remote_bundle_dir}/" 2>"$scp_err"; then
    ui_stop
    runs_write_status "$name" "failed" "remote" "$include_images" "$outdir" "$tarball" "" "metadata upload failed"
    msgbox "Upload Failed" "Metadata upload failed:

$(tail -n 200 "$scp_err")"
    rm -f "$scp_err"
    return 1
  fi
  rm -f "$scp_err"

  ui_status "Remote upload verified (tar + metadata)."
  ui_gauge 96 "Upload verified."

  REMOTE_UPLOAD_DEST="${remote_user}@${remote_host}:${remote_bundle_dir}/"

  runs_write_status "$name" "success" "remote" "$include_images" "$outdir" "$tarball" "$REMOTE_UPLOAD_DEST" ""

  if [[ "${REMOTE_CLEANUP_AFTER_UPLOAD}" == "1" ]]; then
    if (( HEADLESS )); then
      cleanup_local_bundle_no_ui "$outdir"
    else
      cleanup_local_bundle_in_current_ui "$outdir"
    fi
  else
    ui_status "Cleanup: skipped (REMOTE_CLEANUP_AFTER_UPLOAD=0)"
  fi

  ui_gauge 100 "All done."
  sleep 0.2
  ui_stop
  return 0
}

prompt_remote_creds() {
  local _rh _ru _rd _rp
  _rh="$(inputbox "Remote Host" "Enter SSH server IP or hostname:" "")" || true
  _rh="$(trim "$_rh")"
  [[ -z "$_rh" ]] && { msgbox "Cancelled" "No host provided."; return 1; }

  _ru="$(inputbox "Remote User" "Enter SSH username:" "")" || true
  _ru="$(trim "$_ru")"
  [[ -z "$_ru" ]] && { msgbox "Cancelled" "No user provided."; return 1; }

  _rd="$(inputbox "Remote Directory" "Enter remote directory to store backups:" "/root/cmds-backups")" || true
  _rd="$(trim "$_rd")"
  [[ -z "$_rd" ]] && { msgbox "Cancelled" "No remote directory provided."; return 1; }

  _rp="$(passwordbox "SSH Password" "Enter SSH password for ${_ru}@${_rh}:")" || true
  [[ -z "$_rp" ]] && { msgbox "Cancelled" "No password provided."; return 1; }

  save_remote_config "$_rh" "$_ru" "$_rd" "$_rp"
  echo "${_rh}|${_ru}|${_rd}|${_rp}"
}

# -----------------------------
# Headless runner
# -----------------------------
headless_run() {
  HEADLESS=1
  DIALOG_AVAILABLE=0

  local backup_root="${BACKUP_ROOT_OVERRIDE:-$BACKUP_ROOT_DEFAULT}"
  local mode="${CMDS_BACKUP_MODE_OVERRIDE:-local}"
  local include_images="${INCLUDE_IOSXE_IMAGES_OVERRIDE:-no}"

  mode="$(echo "$mode" | tr '[:upper:]' '[:lower:]')"
  include_images="$(echo "$include_images" | tr '[:upper:]' '[:lower:]')"
  [[ "$include_images" != "yes" ]] && include_images="no"
  [[ "$mode" != "remote" ]] && mode="local"

  RUN_STARTED_AT="$(date '+%Y-%m-%d %I:%M:%S %p')"
  export RUN_STARTED_AT

  echo "$(date '+%F %T') headless: start mode=$mode include_images=$include_images backup_root=$backup_root"

  if [[ "$mode" == "remote" ]]; then
    if ! load_remote_config; then
      echo "$(date '+%F %T') headless: ERROR: remote config missing/invalid: $REMOTE_CONF" >&2
      return 2
    fi

    if ! make_backup "$backup_root" "remote" "$include_images"; then
      echo "$(date '+%F %T') headless: ERROR: failed to build local archive" >&2
      return 3
    fi

    if remote_upload_bundle "$BACKUP_OUTDIR" "$REMOTE_HOST" "$REMOTE_USER" "$REMOTE_DIR" "$REMOTE_PASS" "$BACKUP_NAME" "$include_images"; then
      echo "$(date '+%F %T') headless: OK remote dest=$REMOTE_UPLOAD_DEST logs=$(runs_dir_for_name "$BACKUP_NAME")"
      return 0
    else
      echo "$(date '+%F %T') headless: ERROR: remote upload failed logs=$(runs_dir_for_name "$BACKUP_NAME")" >&2
      return 4
    fi
  fi

  if make_backup "$backup_root" "local" "$include_images"; then
    runs_write_status "$BACKUP_NAME" "success" "local" "$include_images" "$BACKUP_OUTDIR" "$BACKUP_ARCHIVE" "" ""
    echo "$(date '+%F %T') headless: OK local bundle=$BACKUP_OUTDIR logs=$(runs_dir_for_name "$BACKUP_NAME")"
    return 0
  fi

  runs_write_status "$BACKUP_NAME" "failed" "local" "$include_images" "$BACKUP_OUTDIR" "$BACKUP_ARCHIVE" "" "headless local backup failed"
  echo "$(date '+%F %T') headless: ERROR local backup failed logs=$(runs_dir_for_name "$BACKUP_NAME")" >&2
  return 5
}

# -----------------------------
# Core menu (interactive)
# -----------------------------
main_menu() {
  local choice
  choice="$(menu "CMDS Backups" "Select an action:" \
    1 "Run LOCAL backup now" \
    2 "Run REMOTE backup now (SSH upload w/ progress)" \
  )" || { clear; exit 0; }

  local backup_root
  backup_root="$(inputbox "Backup Directory" "Enter local backup directory path:" "$BACKUP_ROOT_DEFAULT")" || true
  backup_root="$(trim "$backup_root")"
  [[ -z "$backup_root" ]] && { clear; exit 0; }

  local include_images
  include_images="$(ask_include_images_interactive)"

  RUN_STARTED_AT="$(date '+%Y-%m-%d %I:%M:%S %p')"
  export RUN_STARTED_AT

  case "$choice" in
    1)
      if make_backup "$backup_root" "local" "$include_images"; then
        runs_write_status "$BACKUP_NAME" "success" "local" "$include_images" "$BACKUP_OUTDIR" "$BACKUP_ARCHIVE" "" ""
        msgbox "Backup Complete" "Backup created successfully.

Bundle folder:
$BACKUP_OUTDIR

Archive:
$BACKUP_ARCHIVE

Include IOS-XE images:
$include_images

Operational logs:
$(runs_dir_for_name "$BACKUP_NAME")"
      else
        msgbox "Backup Failed" "Local backup failed.

Operational logs:
$(runs_dir_for_name "$BACKUP_NAME")"
      fi
      ;;
    2)
      local creds remote_host remote_user remote_dir remote_pass
      creds="$(prompt_remote_creds)" || return 0
      IFS='|' read -r remote_host remote_user remote_dir remote_pass <<<"$creds"

      if ! make_backup "$backup_root" "remote" "$include_images"; then
        msgbox "Backup Failed" "Failed to build local archive for remote upload.

Operational logs:
$(runs_dir_for_name "$BACKUP_NAME")"
        return 0
      fi

      if remote_upload_bundle "$BACKUP_OUTDIR" "$remote_host" "$remote_user" "$remote_dir" "$remote_pass" "$BACKUP_NAME" "$include_images"; then
        msgbox "Remote Backup Successful" "Backup bundle uploaded to:

${REMOTE_UPLOAD_DEST}

Local cache cleanup:
$( [[ "${REMOTE_CLEANUP_AFTER_UPLOAD}" == "1" ]] && echo "DONE" || echo "SKIPPED" )

Operational logs:
$(runs_dir_for_name "$BACKUP_NAME")"
      else
        msgbox "Remote Backup Failed" "Remote upload failed.

Operational logs:
$(runs_dir_for_name "$BACKUP_NAME")"
      fi
      ;;
  esac
}

# -----------------------------
# Entry
# -----------------------------
need_root

case "${1:-}" in
  --headless)
    shift || true
    headless_run
    exit $?
    ;;
esac

if has_dialog && fd9_ok; then
  main_menu
  clear || true
else
  # If run without TTY/dialog, default to headless local (no images)
  HEADLESS=1
  DIALOG_AVAILABLE=0
  RUN_STARTED_AT="$(date '+%Y-%m-%d %I:%M:%S %p')"
  if make_backup "$BACKUP_ROOT_DEFAULT" "local" "no"; then
    runs_write_status "$BACKUP_NAME" "success" "local" "no" "$BACKUP_OUTDIR" "$BACKUP_ARCHIVE" "" ""
    echo "Backup created: $BACKUP_OUTDIR ($BACKUP_ARCHIVE)"
    echo "Operational logs: $(runs_dir_for_name "$BACKUP_NAME")"
    exit 0
  fi
  runs_write_status "$BACKUP_NAME" "failed" "local" "no" "$BACKUP_OUTDIR" "$BACKUP_ARCHIVE" "" "non-interactive backup failed"
  echo "Backup failed. Operational logs: $(runs_dir_for_name "$BACKUP_NAME")" >&2
  exit 1
fi