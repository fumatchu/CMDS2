#!/bin/bash
# ============================================================
# CMDS Backup Scheduler (Wizard + Sturdy Cron Runner)
#
# Core backup script (fixed path):
#   /root/.server_admin/cmds_backup.sh
#
# Scheduler config (wizard writes this):
#   /root/.server_admin/cmds-backup-scheduler.conf
#
# Remote conf (only used if MODE=remote):
#   /root/.server_admin/cmds-backup-remote.conf
#
# Cron runs:
#   this script --cron-run
#
# Logging (NO /var/log usage):
#   /root/.server_admin/runs/cmds-cron-scheduler/
#     run-YYYYmmdd-HHMMSS/
#       scheduler.log
#       status.env
#       stdout.log
#       stderr.log
#
# Symlinks:
#   latest, last_success, last_failure
#
# Goals:
# - Wizard/UI only writes config + installs cron block.
# - Cron-run is deterministic/headless and always writes proof-of-life.
# ============================================================

set -Eeuo pipefail

# -----------------------------
# UI / colors
# -----------------------------
TEXTRESET="$(tput sgr0 2>/dev/null || true)"
RED="$(tput setaf 1 2>/dev/null || true)"

trim(){ printf '%s' "${1:-}" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
pad2(){ printf '%02d' "$((10#${1:-0}))"; }
pad4(){ printf '%04d' "$((10#${1:-0}))"; }

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo -e "${RED}This script must be run as root!${TEXTRESET}"
    exit 1
  fi
}

has_dialog(){ command -v dialog >/dev/null 2>&1; }

TTY_PATH="/dev/tty"
if [[ -e "$TTY_PATH" ]]; then
  exec 9<> "$TTY_PATH" || true
fi
fd9_ok(){ [[ -e /proc/$$/fd/9 ]]; }

msgbox() {
  local title="${1:-Info}"; shift || true
  if has_dialog && fd9_ok; then
    dialog --title "$title" --msgbox "$*" 12 95 <&9 >&9 2>&9
  elif has_dialog; then
    dialog --title "$title" --msgbox "$*" 12 95
  else
    echo "$title: $*"
  fi
}

inputbox() {
  local title="$1"; local prompt="$2"; local def="${3:-}"
  if has_dialog && fd9_ok; then
    dialog --stdout --title "$title" --inputbox "$prompt" 10 86 "$def" <&9 2>&9
  elif has_dialog; then
    dialog --stdout --title "$title" --inputbox "$prompt" 10 86 "$def"
  else
    local val=""
    read -r -p "$prompt [$def]: " val || true
    echo "${val:-$def}"
  fi
}

passwordbox() {
  local title="$1"; local prompt="$2"
  if has_dialog && fd9_ok; then
    dialog --stdout --insecure --title "$title" --passwordbox "$prompt" 10 86 <&9 2>&9
  elif has_dialog; then
    dialog --stdout --insecure --title "$title" --passwordbox "$prompt" 10 86
  else
    local val=""
    read -r -s -p "$prompt: " val; echo
    echo "$val"
  fi
}

yesno() {
  local title="$1"; local prompt="$2"
  if has_dialog && fd9_ok; then
    dialog --title "$title" --yesno "$prompt" 12 95 <&9 >&9 2>&9
    return $?
  elif has_dialog; then
    dialog --title "$title" --yesno "$prompt" 12 95
    return $?
  else
    local ans=""
    read -r -p "$prompt [y/N]: " ans || true
    [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
  fi
}

menu() {
  local title="$1"; local prompt="$2"; shift 2
  if has_dialog && fd9_ok; then
    dialog --stdout --title "$title" --menu "$prompt" 18 95 12 "$@" <&9 2>&9
  elif has_dialog; then
    dialog --stdout --title "$title" --menu "$prompt" 18 95 12 "$@"
  else
    echo ""
    return 1
  fi
}

textbox() {
  local title="$1" file="$2"
  if has_dialog && fd9_ok; then
    dialog --title "$title" --textbox "$file" 24 110 <&9 >&9 2>&9
  elif has_dialog; then
    dialog --title "$title" --textbox "$file" 24 110
  else
    cat "$file"
  fi
}

calendar_pick() {
  # outputs YYYY-MM-DD
  local title="${1:-Select date}"
  local today_y today_m today_d
  today_y="$(date +%Y)"; today_m="$(date +%m)"; today_d="$(date +%d)"

  local out=""
  if has_dialog && fd9_ok; then
    out="$(dialog --stdout --title "$title" --calendar "Choose the start date" 0 0 "$today_d" "$today_m" "$today_y" <&9 2>&9)" || return 1
  else
    out="$(dialog --stdout --title "$title" --calendar "Choose the start date" 0 0 "$today_d" "$today_m" "$today_y")" || return 1
  fi

  out="$(trim "$out")"
  local DD MM YYYY
  IFS='/' read -r DD MM YYYY <<<"$out"
  YYYY="$(pad4 "$YYYY")"; MM="$(pad2 "$MM")"; DD="$(pad2 "$DD")"
  printf '%s\n' "${YYYY}-${MM}-${DD}"
}

parse_time_12h_to_hm() {
  # input: "HH:MM AM/PM" variants
  # output: "HH MM" (24-hour)
  local raw="${1:-}"
  local canon
  canon="$(printf '%s' "$raw" | tr '[:lower:]' '[:upper:]' | sed 's/\./:/g; s/[^0-9APM: ]//g')"
  if [[ ! "$canon" =~ ^[[:space:]]*([0-1]?[0-9])[[:space:]]*:[[:space:]]*([0-5][0-9])[[:space:]]*(AM|PM)[[:space:]]*$ ]]; then
    return 1
  fi

  local HH12 MIN AMPM HH24
  HH12="${BASH_REMATCH[1]}"; MIN="${BASH_REMATCH[2]}"; AMPM="${BASH_REMATCH[3]}"

  (( 10#$HH12 < 1 || 10#$HH12 > 12 )) && return 1
  HH12="$(pad2 "$HH12")"; MIN="$(pad2 "$MIN")"

  HH24="$HH12"
  [[ "$AMPM" == "AM" && "$HH12" == "12" ]] && HH24="00"
  if [[ "$AMPM" == "PM" && "$HH12" != "12" ]]; then
    HH24="$(pad2 "$((10#$HH12 + 12))")"
  fi

  printf '%s %s\n' "$HH24" "$MIN"
}

dow_from_date() { date -d "$1" +%w 2>/dev/null || echo 0; }   # 0=Sun..6=Sat
date_to_epoch(){ date -d "$1" +%s 2>/dev/null || echo 0; }

# -----------------------------
# Paths / config
# -----------------------------
CONFIG_DIR="/root/.server_admin"
SCHED_CONF="${CONFIG_DIR}/cmds-backup-scheduler.conf"
REMOTE_CONF="${CONFIG_DIR}/cmds-backup-remote.conf"

CRON_MARKER="# CMDS_BACKUP_SCHEDULER_JOB"

RUNS_ROOT="${CONFIG_DIR}/runs/cmds-cron-scheduler"
LATEST_LINK="${RUNS_ROOT}/latest"
LAST_SUCCESS_LINK="${RUNS_ROOT}/last_success"
LAST_FAILURE_LINK="${RUNS_ROOT}/last_failure"

# HARD-LOCKED CORE (ALWAYS)
CORE_SCRIPT="/root/.server_admin/cmds_backup.sh"

ensure_config_dir() {
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  chmod 700 "$CONFIG_DIR" 2>/dev/null || true
}

ensure_runs_root() {
  ensure_config_dir
  mkdir -p "$RUNS_ROOT" 2>/dev/null || true
  chmod 700 "$RUNS_ROOT" 2>/dev/null || true
}

default_sched_conf() {
  cat <<EOF
BACKUP_ROOT=/root/cmds-backups
MODE=local
INCLUDE_IOSXE_IMAGES=no
SCHEDULE_TYPE=daily
SCHEDULE_EXPR=15 2 * * *
START_DATE=
REMOTE_CLEANUP_AFTER_UPLOAD=1
EOF
}

load_sched_conf() {
  ensure_config_dir
  if [[ ! -f "$SCHED_CONF" ]]; then
    default_sched_conf > "$SCHED_CONF"
    chmod 600 "$SCHED_CONF" 2>/dev/null || true
  fi

  # shellcheck disable=SC1090
  source "$SCHED_CONF" || true

  BACKUP_ROOT="${BACKUP_ROOT:-/root/cmds-backups}"
  MODE="${MODE:-local}"
  INCLUDE_IOSXE_IMAGES="${INCLUDE_IOSXE_IMAGES:-no}"
  SCHEDULE_TYPE="${SCHEDULE_TYPE:-daily}"
  SCHEDULE_EXPR="${SCHEDULE_EXPR:-15 2 * * *}"
  START_DATE="${START_DATE:-}"
  REMOTE_CLEANUP_AFTER_UPLOAD="${REMOTE_CLEANUP_AFTER_UPLOAD:-1}"

  MODE="$(echo "$MODE" | tr '[:upper:]' '[:lower:]')"
  INCLUDE_IOSXE_IMAGES="$(echo "$INCLUDE_IOSXE_IMAGES" | tr '[:upper:]' '[:lower:]')"
  [[ "$INCLUDE_IOSXE_IMAGES" != "yes" ]] && INCLUDE_IOSXE_IMAGES="no"
  [[ "$MODE" != "remote" ]] && MODE="local"
  [[ "$REMOTE_CLEANUP_AFTER_UPLOAD" != "0" ]] && REMOTE_CLEANUP_AFTER_UPLOAD="1"
  START_DATE="$(trim "$START_DATE")"
}

save_sched_conf() {
  ensure_config_dir
  {
    printf 'BACKUP_ROOT=%q\n' "$(trim "$BACKUP_ROOT")"
    printf 'MODE=%q\n' "$(trim "$MODE")"
    printf 'INCLUDE_IOSXE_IMAGES=%q\n' "$(trim "$INCLUDE_IOSXE_IMAGES")"
    printf 'SCHEDULE_TYPE=%q\n' "$(trim "$SCHEDULE_TYPE")"
    printf 'SCHEDULE_EXPR=%q\n' "$(trim "$SCHEDULE_EXPR")"
    printf 'START_DATE=%q\n' "$(trim "$START_DATE")"
    printf 'REMOTE_CLEANUP_AFTER_UPLOAD=%q\n' "$(trim "$REMOTE_CLEANUP_AFTER_UPLOAD")"
  } > "$SCHED_CONF"
  chmod 600 "$SCHED_CONF" 2>/dev/null || true
}

save_remote_conf() {
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

remote_conf_ok() {
  [[ -f "$REMOTE_CONF" ]] || return 1
  # shellcheck disable=SC1090
  source "$REMOTE_CONF" || return 1
  [[ -n "${REMOTE_HOST:-}" && -n "${REMOTE_USER:-}" && -n "${REMOTE_DIR:-}" && -n "${REMOTE_PASS:-}" ]] || return 1
  return 0
}

core_ok() {
  [[ -f "$CORE_SCRIPT" ]]
}

# -----------------------------
# Run dir + status helpers
# -----------------------------
new_run_dir() {
  ensure_runs_root
  local stamp
  stamp="$(date +%Y%m%d-%H%M%S)"
  local d="${RUNS_ROOT}/run-${stamp}"
  mkdir -p "$d" 2>/dev/null || true
  chmod 700 "$d" 2>/dev/null || true
  ln -sfn "$d" "$LATEST_LINK" 2>/dev/null || true
  printf '%s\n' "$d"
}

write_status_env() {
  local run_dir="$1"
  local status="$2"          # success|failure|skipped|running
  local msg="${3:-}"
  local now
  now="$(date '+%F %T')"

  {
    echo "STATUS=$status"
    echo "UPDATED_AT=$now"
    [[ -n "$msg" ]] && echo "MESSAGE=$(printf '%s' "$msg" | tr '\n' ' ')"
  } > "${run_dir}/status.env"
  chmod 600 "${run_dir}/status.env" 2>/dev/null || true
}

link_success_failure() {
  local run_dir="$1" status="$2"
  if [[ "$status" == "success" ]]; then
    ln -sfn "$run_dir" "$LAST_SUCCESS_LINK" 2>/dev/null || true
  elif [[ "$status" == "failure" ]]; then
    ln -sfn "$run_dir" "$LAST_FAILURE_LINK" 2>/dev/null || true
  fi
}

# -----------------------------
# Cron block management
# -----------------------------
remove_cron_job() {
  local tmp; tmp="$(mktemp)"

  ( crontab -l 2>/dev/null || true ) | awk -v m="$CRON_MARKER" '
    $0==m {c++; next}
    c%2==1 {next}
    {print}
  ' > "$tmp"

  crontab "$tmp" >/dev/null 2>&1 || true
  rm -f "$tmp"
}

install_cron_job() {
  load_sched_conf
  ensure_runs_root

  if ! core_ok; then
    msgbox "Error" "Backup core is missing:\n\n$CORE_SCRIPT\n\nRestore it, then try again."
    return 1
  fi

  if [[ "$MODE" == "remote" ]] && ! remote_conf_ok; then
    msgbox "Remote Config Missing" "Scheduled mode is REMOTE but remote settings are missing.\n\nRun the wizard and configure remote settings."
    return 1
  fi

  remove_cron_job

  # IMPORTANT: Cron must call a stable, absolute path.
  local self; self="$(readlink -f "$0" 2>/dev/null || echo "$0")"

  local tmp; tmp="$(mktemp)"
  crontab -l 2>/dev/null > "$tmp" || true

  {
    echo ""
    echo "$CRON_MARKER"
    echo "SHELL=/bin/bash"
    echo "PATH=/usr/sbin:/usr/bin:/sbin:/bin"
    # do NOT redirect cron output; script logs internally
    echo "$SCHEDULE_EXPR $self --cron-run"
    echo "$CRON_MARKER"
  } >> "$tmp"

  crontab "$tmp" >/dev/null 2>&1 || {
    rm -f "$tmp"
    msgbox "Error" "Failed to install cron entry (crontab write failed)."
    return 1
  }
  rm -f "$tmp"
  return 0
}

view_cron_block() {
  local cur tmpf
  cur="$(
    ( crontab -l 2>/dev/null || true ) | awk -v m="$CRON_MARKER" '
      $0==m {c++; print; next}
      c%2==1 {print; next}
    '
  )"
  [[ -z "$cur" ]] && cur="(no CMDS backup scheduler cron entry found)"

  tmpf="$(mktemp)"
  {
    echo "===== CMDS Backup Scheduler Cron Block ====="
    echo
    echo "$cur"
  } > "$tmpf"

  textbox "Cron Block" "$tmpf" || true
  rm -f "$tmpf"
  return 0
}

# -----------------------------
# Wizard steps (build conf)
# -----------------------------
wizard_pick_backup_root() {
  load_sched_conf
  local p
  p="$(inputbox "Backup Root" "Local backup root directory:" "$BACKUP_ROOT")" || true
  p="$(trim "$p")"
  [[ -z "$p" ]] && return 1
  BACKUP_ROOT="$p"
  return 0
}

wizard_pick_mode() {
  local c
  c="$(menu "Backup Mode" "Choose scheduled backup mode:" \
    1 "LOCAL  (store backups on this server)" \
    2 "REMOTE (upload backups over SSH/SCP)" \
  )" || return 1

  case "$c" in
    1) MODE="local" ;;
    2) MODE="remote" ;;
  esac
  return 0
}

wizard_pick_images() {
  if yesno "IOS-XE Images" "Include IOS-XE images (/var/lib/tftpboot/images)?\n\nThis can significantly increase backup size and runtime."; then
    INCLUDE_IOSXE_IMAGES="yes"
  else
    INCLUDE_IOSXE_IMAGES="no"
  fi
  return 0
}

wizard_pick_remote_cleanup() {
  if yesno "Remote Cleanup" "After a successful REMOTE upload, delete the local staged bundle cache?\n\n(Operational logs remain under /root/.server_admin/runs/ either way.)"; then
    REMOTE_CLEANUP_AFTER_UPLOAD="1"
  else
    REMOTE_CLEANUP_AFTER_UPLOAD="0"
  fi
  return 0
}

wizard_remote_settings() {
  local host user dir pass

  host="$(inputbox "Remote Host" "Enter SSH server IP or hostname:" "")" || true
  host="$(trim "$host")"
  [[ -z "$host" ]] && return 1

  user="$(inputbox "Remote User" "Enter SSH username:" "")" || true
  user="$(trim "$user")"
  [[ -z "$user" ]] && return 1

  dir="$(inputbox "Remote Directory" "Remote directory for backups:" "/root/cmds-backups")" || true
  dir="$(trim "$dir")"
  [[ -z "$dir" ]] && return 1

  pass="$(passwordbox "SSH Password" "Enter SSH password for ${user}@${host}:")" || true
  [[ -z "$pass" ]] && return 1

  save_remote_conf "$host" "$user" "$dir" "$pass"
  return 0
}

wizard_pick_schedule_calendar() {
  # Daily or Weekly + calendar start date + time -> cron + START_DATE
  local c
  c="$(menu "Schedule" "Choose schedule frequency:" \
    1 "Daily  (choose start date + time)" \
    2 "Weekly (choose start date + time; weekday taken from date)" \
  )" || return 1

  local start_date
  start_date="$(calendar_pick "Start date")" || return 1

  local default_time="02:00 AM"
  local time_raw hm HH24 MM
  time_raw="$(inputbox "Run time (12-hour)" "Enter time as: HH:MM AM/PM\n\nExamples:\n  2:30 am\n  11:05 PM\n  12:00 pm" "$default_time")" || true
  time_raw="$(trim "$time_raw")"

  hm="$(parse_time_12h_to_hm "$time_raw")" || {
    msgbox "Invalid time" "Use format: HH:MM AM/PM (e.g. 02:30 PM)."
    return 1
  }
  HH24="$(awk '{print $1}' <<<"$hm")"
  MM="$(awk '{print $2}' <<<"$hm")"

  START_DATE="$start_date"

  case "$c" in
    1)
      SCHEDULE_TYPE="daily"
      SCHEDULE_EXPR="${MM} ${HH24} * * *"
      ;;
    2)
      SCHEDULE_TYPE="weekly"
      local dow
      dow="$(dow_from_date "$start_date")"
      SCHEDULE_EXPR="${MM} ${HH24} * * ${dow}"
      ;;
  esac

  return 0
}

run_setup_wizard() {
  load_sched_conf

  msgbox "Setup Wizard" "This wizard builds the scheduler config file and installs the cron block.\n\nYou will choose:\n- Local or Remote\n- Include IOS-XE images or not\n- Remote cleanup (remote mode)\n- Daily or Weekly\n- Start date + time (calendar)\n\nThen it saves settings and installs cron."

  wizard_pick_backup_root || { msgbox "Cancelled" "Wizard cancelled."; return 0; }
  wizard_pick_mode        || { msgbox "Cancelled" "Wizard cancelled."; return 0; }
  wizard_pick_images      || { msgbox "Cancelled" "Wizard cancelled."; return 0; }

  if [[ "$MODE" == "remote" ]]; then
    msgbox "Remote Settings" "Next: configure remote SSH upload settings."
    wizard_remote_settings     || { msgbox "Cancelled" "Wizard cancelled during remote settings."; return 0; }
    wizard_pick_remote_cleanup || { msgbox "Cancelled" "Wizard cancelled."; return 0; }
  else
    REMOTE_CLEANUP_AFTER_UPLOAD="1"
  fi

  wizard_pick_schedule_calendar || { msgbox "Cancelled" "Wizard cancelled."; return 0; }

  if ! core_ok; then
    msgbox "Error" "Backup core is missing:\n\n$CORE_SCRIPT\n\nRestore it, then rerun this wizard."
    return 1
  fi

  if [[ "$MODE" == "remote" ]] && ! remote_conf_ok; then
    msgbox "Error" "Remote mode selected but remote upload settings are missing/invalid.\n\nRe-run wizard and configure remote settings."
    return 1
  fi

  save_sched_conf

  if install_cron_job; then
    msgbox "Scheduled!" "Scheduled backups are now enabled.\n\nMode: $MODE\nInclude images: $INCLUDE_IOSXE_IMAGES\nStart date: ${START_DATE:-<none>}\nCron: $SCHEDULE_EXPR\nRemote cleanup: $REMOTE_CLEANUP_AFTER_UPLOAD\n\nConfig:\n$SCHED_CONF\n\nLogs:\n$RUNS_ROOT/"
  else
    msgbox "Error" "Failed to install cron job."
    return 1
  fi
}

show_current_settings() {
  load_sched_conf
  local rcfg="MISSING"
  remote_conf_ok && rcfg="PRESENT"

  local tmpf; tmpf="$(mktemp)"
  {
    echo "===== CMDS Backup Scheduler Settings ====="
    echo "Config file           : $SCHED_CONF"
    echo "Core script           : $CORE_SCRIPT (fixed)"
    echo "Backup root           : $BACKUP_ROOT"
    echo "Mode                  : $MODE"
    echo "Include IOS-XE images : $INCLUDE_IOSXE_IMAGES"
    echo "Remote cleanup        : $REMOTE_CLEANUP_AFTER_UPLOAD"
    echo "Schedule type         : $SCHEDULE_TYPE"
    echo "Cron expression       : $SCHEDULE_EXPR"
    echo "Start date (gate)     : ${START_DATE:-<none>}"
    echo "Remote config         : $rcfg ($REMOTE_CONF)"
    echo "Runs root             : $RUNS_ROOT"
    echo "Latest run            : $LATEST_LINK"
    echo "Last success          : $LAST_SUCCESS_LINK"
    echo "Last failure          : $LAST_FAILURE_LINK"
  } > "$tmpf"
  textbox "Current Settings" "$tmpf"
  rm -f "$tmpf"
}

# -----------------------------
# Sturdy cron runner (headless)
# -----------------------------
cron_run() {
  # Very defensive: cron environment can be minimal.
  export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  export SHELL="/bin/bash"
  export HOME="/root"

  ensure_runs_root

  # PROOF-OF-LIFE: this must happen even if later steps fail
  {
    echo "[$(date '+%F %T')] cron_run invoked pid=$$ uid=$(id -u) argv=$* shell=${SHELL:-?} path=${PATH:-?}"
  } >> "${RUNS_ROOT}/cron_proof.log" 2>/dev/null || true

  load_sched_conf

  local run_dir
  run_dir="$(new_run_dir)"

  local slog="${run_dir}/scheduler.log"
  local sout="${run_dir}/stdout.log"
  local serr="${run_dir}/stderr.log"

  : >"$slog" 2>/dev/null || true
  : >"$sout" 2>/dev/null || true
  : >"$serr" 2>/dev/null || true
  chmod 600 "$slog" "$sout" "$serr" 2>/dev/null || true

  {
    echo "============================================================"
    echo "$(date '+%F %T') scheduler: start"
    echo "mode=$MODE include_images=$INCLUDE_IOSXE_IMAGES backup_root=$BACKUP_ROOT cleanup=$REMOTE_CLEANUP_AFTER_UPLOAD"
    echo "schedule_expr=$SCHEDULE_EXPR start_date=${START_DATE:-<none>}"
    echo "run_dir=$run_dir"
  } >>"$slog" 2>/dev/null || true

  write_status_env "$run_dir" "running" "scheduler started"

  # gate by START_DATE (date-only gate)
  if [[ -n "${START_DATE:-}" ]]; then
    local start_ts today_ts
    start_ts="$(date_to_epoch "${START_DATE} 00:00:00")"
    today_ts="$(date_to_epoch "$(date +%F) 00:00:00")"
    if (( start_ts > 0 && today_ts < start_ts )); then
      echo "$(date '+%F %T') scheduler: SKIP (today is before start date)" >>"$slog"
      write_status_env "$run_dir" "skipped" "today before START_DATE"
      echo "$(date '+%F %T') scheduler: end (skipped)" >>"$slog"
      exit 0
    fi
  fi

  if ! core_ok; then
    echo "$(date '+%F %T') scheduler: ERROR: backup core missing/unusable: $CORE_SCRIPT" >>"$slog"
    write_status_env "$run_dir" "failure" "core missing/unusable"
    link_success_failure "$run_dir" "failure"
    exit 1
  fi

  if [[ "$MODE" == "remote" ]] && ! remote_conf_ok; then
    echo "$(date '+%F %T') scheduler: ERROR: remote mode set but remote config missing/invalid: $REMOTE_CONF" >>"$slog"
    write_status_env "$run_dir" "failure" "remote config missing/invalid"
    link_success_failure "$run_dir" "failure"
    exit 1
  fi

  # Pass overrides to core
  export BACKUP_ROOT_OVERRIDE="$BACKUP_ROOT"
  export CMDS_BACKUP_MODE_OVERRIDE="$MODE"
  export INCLUDE_IOSXE_IMAGES_OVERRIDE="$INCLUDE_IOSXE_IMAGES"
  export REMOTE_CLEANUP_AFTER_UPLOAD="$REMOTE_CLEANUP_AFTER_UPLOAD"

  echo "$(date '+%F %T') scheduler: launching core (headless)" >>"$slog"
  if /usr/bin/env bash "$CORE_SCRIPT" --headless >>"$sout" 2>>"$serr"; then
    echo "$(date '+%F %T') scheduler: OK" >>"$slog"
    write_status_env "$run_dir" "success" "core OK"
    link_success_failure "$run_dir" "success"
    exit 0
  fi

  local rc=$?
  echo "$(date '+%F %T') scheduler: ERROR: core run failed (rc=$rc)" >>"$slog"
  write_status_env "$run_dir" "failure" "core failed rc=$rc"
  link_success_failure "$run_dir" "failure"
  exit "$rc"
}

# -----------------------------
# UI simulation (optional)
# -----------------------------
ui_simulate_cron_run() {
  ensure_runs_root
  load_sched_conf

  local run_dir slog sout serr
  run_dir="$(new_run_dir)"
  slog="${run_dir}/scheduler.log"
  sout="${run_dir}/stdout.log"
  serr="${run_dir}/stderr.log"

  : >"$slog"; : >"$sout"; : >"$serr"
  chmod 600 "$slog" "$sout" "$serr" 2>/dev/null || true

  {
    echo "============================================================"
    echo "$(date '+%F %T') scheduler: start (UI simulation)"
    echo "mode=$MODE include_images=$INCLUDE_IOSXE_IMAGES backup_root=$BACKUP_ROOT cleanup=$REMOTE_CLEANUP_AFTER_UPLOAD"
    echo "run_dir=$run_dir"
  } >>"$slog"

  (
    export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
    export SHELL="/bin/bash"
    export HOME="/root"

    export BACKUP_ROOT_OVERRIDE="$BACKUP_ROOT"
    export CMDS_BACKUP_MODE_OVERRIDE="$MODE"
    export INCLUDE_IOSXE_IMAGES_OVERRIDE="$INCLUDE_IOSXE_IMAGES"
    export REMOTE_CLEANUP_AFTER_UPLOAD="$REMOTE_CLEANUP_AFTER_UPLOAD"

    write_status_env "$run_dir" "running" "scheduler started"

    echo "$(date '+%F %T') scheduler: launching core (headless)" >>"$slog"
    if /usr/bin/env bash "$CORE_SCRIPT" --headless >>"$sout" 2>>"$serr"; then
      echo "$(date '+%F %T') scheduler: OK" >>"$slog"
      write_status_env "$run_dir" "success" "core OK"
      link_success_failure "$run_dir" "success"
      exit 0
    else
      rc=$?
      echo "$(date '+%F %T') scheduler: ERROR core failed rc=$rc" >>"$slog"
      write_status_env "$run_dir" "failure" "core failed rc=$rc"
      link_success_failure "$run_dir" "failure"
      exit "$rc"
    fi
  ) &
  local job_pid=$!

  if has_dialog && fd9_ok; then
    while kill -0 "$job_pid" 2>/dev/null; do
      local tail_sched tail_out tail_err
      tail_sched="$(tail -n 12 "$slog" 2>/dev/null || true)"
      tail_out="$(tail -n 8 "$sout" 2>/dev/null || true)"
      tail_err="$(tail -n 4 "$serr" 2>/dev/null || true)"

      dialog --title "Cron-run Simulation (live)" \
        --infobox \
"Run dir: $run_dir

--- scheduler.log (tail) ---
$tail_sched

--- core stdout (tail) ---
$tail_out

--- core stderr (tail) ---
$tail_err

(Updates every 1s…)" \
        28 118 <&9 >&9 2>&9 || true

      sleep 1
    done
    dialog --clear <&9 >&9 2>&9 || true
  fi

  local rc=0
  wait "$job_pid" || rc=$?

  local status="unknown"
  status="$(grep -m1 '^STATUS=' "$run_dir/status.env" 2>/dev/null | cut -d= -f2 || true)"

  msgbox "Done" \
"Simulation finished.

Exit code: $rc
Status   : ${status:-unknown}

Logs:
- $run_dir/scheduler.log
- $run_dir/stdout.log
- $run_dir/stderr.log"

  return "$rc"
}

# -----------------------------
# Main menu
# -----------------------------
main_menu() {
  while true; do
    local choice
    choice="$(menu "CMDS Backup Scheduler" "Choose an action:" \
      1 "Run Setup Wizard (build conf + install cron)" \
      2 "View current settings" \
      3 "View current cron block" \
      4 "Disable scheduled backups (remove cron block)" \
      5 "Run one scheduled test now (simulate cron-run)" \
      6 "Show last run status (latest / last success / last failure)" \
    )" || { clear; exit 0; }

    case "$choice" in
      1) run_setup_wizard ;;
      2) show_current_settings ;;
      3) view_cron_block ;;
      4)
        remove_cron_job
        msgbox "Disabled" "Scheduled backups disabled (cron block removed)."
        ;;
      5) ui_simulate_cron_run || true ;;
      6)
        ensure_runs_root
        local tmpf; tmpf="$(mktemp)"
        {
          echo "===== CMDS Backup Scheduler — Last Run Status ====="
          echo
          echo "LATEST:"
          if [[ -L "$LATEST_LINK" && -f "$LATEST_LINK/status.env" ]]; then
            echo "  Dir : $(readlink -f "$LATEST_LINK")"
            sed 's/^/  /' "$LATEST_LINK/status.env" || true
          else
            echo "  (none)"
          fi
          echo
          echo "LAST SUCCESS:"
          if [[ -L "$LAST_SUCCESS_LINK" && -f "$LAST_SUCCESS_LINK/status.env" ]]; then
            echo "  Dir : $(readlink -f "$LAST_SUCCESS_LINK")"
            sed 's/^/  /' "$LAST_SUCCESS_LINK/status.env" || true
          else
            echo "  (none)"
          fi
          echo
          echo "LAST FAILURE:"
          if [[ -L "$LAST_FAILURE_LINK" && -f "$LAST_FAILURE_LINK/status.env" ]]; then
            echo "  Dir : $(readlink -f "$LAST_FAILURE_LINK")"
            sed 's/^/  /' "$LAST_FAILURE_LINK/status.env" || true
          else
            echo "  (none)"
          fi
          echo
          echo "PROOF OF LIFE:"
          if [[ -f "${RUNS_ROOT}/cron_proof.log" ]]; then
            tail -n 20 "${RUNS_ROOT}/cron_proof.log" | sed 's/^/  /'
          else
            echo "  (no cron_proof.log yet)"
          fi
        } > "$tmpf"
        textbox "Last Run Status" "$tmpf"
        rm -f "$tmpf"
        ;;
    esac
  done
}
# -----------------------------
# Entry
# -----------------------------
need_root

case "${1:-}" in
  --cron-run)
    cron_run
    ;;
  --install-cron)
    load_sched_conf
    install_cron_job
    ;;
  *)
    if has_dialog; then
      main_menu
      clear || true
    else
      echo "dialog not installed; cannot run interactive scheduler UI."
      exit 1
    fi
    ;;
esac