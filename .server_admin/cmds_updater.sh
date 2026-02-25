#!/usr/bin/env bash
# /root/.server_admin/cmds_updater.sh
# CMDS Updater (public repo) — uses raw.githubusercontent.com (NO GitHub API)
#
# Expects updates published as:
#   updates/INDEX.txt   (preferred)  OR updates/index.txt (fallback)
#   updates/<version>/cmds-<version>.tar
#   updates/<version>/<version>.notes
#
# INDEX format (pipe-separated) — 5 columns (preferred / locked):
#   <version>|<tar_filename>|<notes_filename>|<description>|sha256:<hash_optional>
#
# Backward compatible with 4 columns:
#   <version>|<tar_filename>|<notes_filename>|sha256:<hash_optional>
#
# BEHAVIOR:
# - Only installs tooling under:
#     /root/.cloud_admin
#     /root/.hybrid_admin
#     /root/.wlc_admin
#     /root/.cat_admin
#     /root/.server_admin
# - Preserves customer data/artifacts:
#     */runs/*
#     *.env *.json *.csv *.flag
#     discovery_results.* upgrade_plan.*
# - Creates updater logs here:
#     /root/.server_admin/runs/cmds-update/<run-id>/
# - Appends patch history here:
#     /root/.server_admin/runs/cmds-update/patch_history.log
#
# VERSIONING:
# - Writes /root/.server_admin/CMDS_VERSION as: VERSION=<selected_version>
# - Writes /root/.server_admin/CMDS_INSTALL_DATE as: INSTALLED_AT='<timestamp>'
# - If CMDS_VERSION is missing/invalid, the updater auto-selects the latest version
#   from INDEX (cumulative patches) and proceeds.

set -Eeuo pipefail

REPO_OWNER="fumatchu"
REPO_NAME="CMDS2"
BRANCH="main"

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}"

INDEX_CANDIDATES=(
  "${RAW_BASE}/updates/INDEX.txt"
  "${RAW_BASE}/updates/index.txt"
  "${RAW_BASE}/updates/Index.txt"
)

ROOT_DIR="/root"
CLOUD_DIR="${ROOT_DIR}/.cloud_admin"
HYBRID_DIR="${ROOT_DIR}/.hybrid_admin"
WLC_DIR="${ROOT_DIR}/.wlc_admin"
CAT_DIR="${ROOT_DIR}/.cat_admin"
SERVER_DIR="${ROOT_DIR}/.server_admin"

WORKDIR="$(mktemp -d /tmp/cmds_updater.XXXXXX)"

BACKTITLE="CMDS Updater"
DIALOG_OPTS=(--no-shadow --backtitle "$BACKTITLE")

cleanup(){ rm -rf "$WORKDIR" 2>/dev/null || true; }
trap cleanup EXIT

# ---------------- Persistent run logging ----------------
UPD_RUNS_DIR="${SERVER_DIR}/runs/cmds-update"
RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="${UPD_RUNS_DIR}/${RUN_ID}"
mkdir -p "$RUN_DIR"

LOG_FILE="${RUN_DIR}/cmds_updater.log"
STDOUT_LOG="${RUN_DIR}/stdout.log"
STDERR_LOG="${RUN_DIR}/stderr.log"

PATCH_HISTORY="${UPD_RUNS_DIR}/patch_history.log"

ts(){ date '+%Y-%m-%d %H:%M:%S'; }
log(){ printf '[%s] %s\n' "$(ts)" "$*" >>"$LOG_FILE"; }

need(){
  command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }
}

dlg_msg(){
  local title="$1" msg="$2" h="${3:-10}" w="${4:-78}"
  dialog "${DIALOG_OPTS[@]}" --title "$title" --msgbox "$msg" "$h" "$w" || true
}

dlg_infobox(){
  local msg="$1"
  dialog "${DIALOG_OPTS[@]}" --infobox "$msg" 6 78 || true
}

show_logfile(){
  if [[ -s "$LOG_FILE" ]]; then
    dialog "${DIALOG_OPTS[@]}" --title "Update log ($RUN_ID)" --textbox "$LOG_FILE" 0 0 || true
  else
    dlg_msg "Update log" "No log content found:\n$LOG_FILE" 8 70
  fi
}

fail(){
  local msg="$*"
  log "ERROR: $msg"
  dlg_msg "Update failed" "Update failed:\n\n$msg\n\nYou will now be shown the log file." 12 78
  show_logfile
  dlg_msg "Exit" "Please EXIT the program fully.\n\nRun logs are saved under:\n$UPD_RUNS_DIR" 10 78
  exit 1
}

run_cmd(){
  # Run a command while capturing stdout/stderr to run logs without breaking dialog TTY
  log "RUN: $*"
  "$@" >>"$STDOUT_LOG" 2>>"$STDERR_LOG"
}

# ---------------- Local CMDS version tracking ----------------
VERSION_FILE="${SERVER_DIR}/CMDS_VERSION"
INSTALL_DATE_FILE="${SERVER_DIR}/CMDS_INSTALL_DATE"

read_installed_version(){
  local v=""
  [[ -r "$VERSION_FILE" ]] || { echo ""; return 0; }
  v="$(grep -m1 '^VERSION=' "$VERSION_FILE" 2>/dev/null | cut -d'=' -f2- | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ "$v" =~ ^[0-9]+(\.[0-9]+)*$ ]] || v=""
  printf "%s" "$v"
}

write_installed_version(){
  local ver="${1:-}"
  [[ -n "$ver" ]] || return 0
  mkdir -p "$SERVER_DIR" 2>/dev/null || true
  { echo "VERSION=$ver"; } >"$VERSION_FILE"
  { echo "INSTALLED_AT='$(date '+%Y-%m-%d %H:%M:%S %Z')'"; } >"$INSTALL_DATE_FILE"
  chmod 600 "$VERSION_FILE" "$INSTALL_DATE_FILE" 2>/dev/null || true
  log "Wrote CMDS version files: $VERSION_FILE ($ver), $INSTALL_DATE_FILE"
}

# ---------------- Updater state ----------------
INDEX_LINES=()
INDEX_USED_URL=""
SELECTED_VERSION=""

SELECTED_TAR=""
SELECTED_NOTES=""
SELECTED_DESC=""
SELECTED_SHA=""

normalize_desc(){
  local d="${1:-}"
  d="${d//$'\r'/}"
  d="$(printf '%s' "$d" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
  if [[ "$d" =~ ^\[(.*)\]$ ]]; then
    d="${BASH_REMATCH[1]}"
    d="$(printf '%s' "$d" | sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//')"
  fi
  [[ -n "$d" ]] || d="No description"
  printf '[%s]' "$d"
}

parse_index_line(){
  local line="$1"
  local ver="" tar="" notes="" desc="" sha=""
  IFS='|' read -r ver tar notes desc sha <<<"$line"

  if [[ -z "${sha:-}" && "${desc:-}" == sha256:* ]]; then
    sha="$desc"
    desc=""
  fi

  if [[ "${desc:-}" == *.notes && "${notes:-}" != *.notes ]]; then
    local tmp="$notes"
    notes="$desc"
    desc="$tmp"
  fi

  [[ -n "${notes:-}" ]] || notes="${ver}.notes"
  printf '%s|%s|%s|%s|%s\n' "${ver:-}" "${tar:-}" "${notes:-}" "${desc:-}" "${sha:-}"
}

fetch_versions_raw(){
  local tmp="${WORKDIR}/INDEX.txt"
  : >"$tmp"

  dlg_infobox "Checking GitHub for available CMDS updates..."
  log "Starting CMDS updater. Repo=${REPO_OWNER}/${REPO_NAME} Branch=${BRANCH}"
  log "Run logs: $RUN_DIR"
  log "Index candidates:"
  for u in "${INDEX_CANDIDATES[@]}"; do log "  - $u"; done

  local ok=0
  for url in "${INDEX_CANDIDATES[@]}"; do
    log "curl GET: $url"
    if run_cmd curl -fsSL --connect-timeout 8 --max-time 30 -H "Cache-Control: no-cache" "$url" -o "$tmp"; then
      ok=1
      INDEX_USED_URL="$url"
      break
    fi
  done

  if (( ok == 0 )); then
    fail "Unable to fetch update index.

Tried:
$(printf '%s\n' "${INDEX_CANDIDATES[@]}")

Check:
- does updates/index.txt (or INDEX.txt) exist in the repo?
- can this server reach raw.githubusercontent.com?

Log:
$LOG_FILE"
  fi

  dlg_infobox "Found update index:\n${INDEX_USED_URL}\n\nLoading versions..."
  log "Using index: $INDEX_USED_URL"

  mapfile -t INDEX_LINES < <(grep -Ev '^[[:space:]]*($|#)' "$tmp" | tr -d '\r')
  ((${#INDEX_LINES[@]} > 0)) || fail "Update index was fetched but is empty."

  log "Index entries: ${#INDEX_LINES[@]}"
}

latest_index_version(){
  local ver
  ver="$(
    printf '%s\n' "${INDEX_LINES[@]}" \
      | cut -d'|' -f1 \
      | tr -d '\r' \
      | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
      | grep -E '^[0-9]+(\.[0-9]+)*$' \
      | sort -V \
      | tail -n 1
  )"
  printf "%s" "${ver:-}"
}

auto_select_latest_version(){
  local latest
  latest="$(latest_index_version)"
  [[ -n "${latest:-}" ]] || fail "Could not determine latest version from update index."
  SELECTED_VERSION="$latest"
  log "Auto-selected latest version (no/invalid local CMDS_VERSION): $SELECTED_VERSION"
}

pick_version_menu(){
  local -a MENU_ITEMS=()
  local line parsed ver tar notes desc sha

  mapfile -t sorted < <(printf '%s\n' "${INDEX_LINES[@]}" | sort -t'|' -k1,1Vr)

  for line in "${sorted[@]}"; do
    parsed="$(parse_index_line "$line")"
    IFS='|' read -r ver tar notes desc sha <<<"$parsed"
    [[ -n "${ver:-}" && -n "${tar:-}" ]] || continue

    local shown_desc
    shown_desc="$(normalize_desc "$desc")"

    local item
    item="$(printf '%-22s %-40s' "$tar" "$shown_desc")"

    MENU_ITEMS+=("$ver" "$item")
  done

  ((${#MENU_ITEMS[@]} > 0)) || fail "Index contained no usable entries."

  local choice
  choice=$(
    dialog "${DIALOG_OPTS[@]}" --title "CMDS Updates" \
      --menu "Select an update version:" 20 92 12 \
      "${MENU_ITEMS[@]}" \
      3>&1 1>&2 2>&3
  ) || return 1

  SELECTED_VERSION="$choice"
  return 0
}

get_meta_for_version(){
  local want="$1"
  local line parsed ver tar notes desc sha
  for line in "${INDEX_LINES[@]}"; do
    parsed="$(parse_index_line "$line")"
    IFS='|' read -r ver tar notes desc sha <<<"$parsed"
    if [[ "$ver" == "$want" ]]; then
      echo "${tar:-}|${notes:-}|${desc:-}|${sha:-}"
      return 0
    fi
  done
  return 1
}

download_update_raw(){
  local ver="$1" tar="$2" notes="$3" desc="$4" sha="$5"

  local tar_url="${RAW_BASE}/updates/${ver}/${tar}"
  local notes_url="${RAW_BASE}/updates/${ver}/${notes}"

  dlg_infobox "Downloading release notes for v${ver}..."
  log "curl GET: $notes_url"
  run_cmd curl -fsSL --connect-timeout 8 --max-time 30 -H "Cache-Control: no-cache" \
    "$notes_url" -o "${WORKDIR}/release.notes" || true

  dlg_infobox "Downloading update package v${ver}..."
  log "curl GET: $tar_url"
  if ! run_cmd curl -fL --connect-timeout 8 --max-time 600 -H "Cache-Control: no-cache" \
      "$tar_url" -o "${WORKDIR}/update.tar"; then
    fail "Failed downloading update package:

$tar_url

Log:
$LOG_FILE"
  fi

  if [[ -n "${sha:-}" && "$sha" == sha256:* ]]; then
    local want_sha="${sha#sha256:}"
    if [[ -n "$want_sha" ]]; then
      local got
      got="$(sha256sum "${WORKDIR}/update.tar" | awk '{print $1}')"
      if [[ "$got" != "$want_sha" ]]; then
        fail "SHA256 mismatch for $tar

Expected: $want_sha
Got:      $got"
      fi
      log "SHA256 verified: $got"
    fi
  fi
}

show_release_notes(){
  local f="${WORKDIR}/release.notes"
  local title="Release notes"
  if [[ -n "${SELECTED_DESC:-}" ]]; then
    title="Release notes $(normalize_desc "$SELECTED_DESC")"
  fi
  if [[ -s "$f" ]]; then
    dialog "${DIALOG_OPTS[@]}" --title "$title" --textbox "$f" 0 0 || true
  else
    dlg_msg "Release notes" "No release notes file found or it was empty." 7 60
  fi
}

should_include_member(){
  local m="$1"

  # Only allow these module roots
  case "$m" in
    .cloud_admin/*|.hybrid_admin/*|.wlc_admin/*|.cat_admin/*|.server_admin/*) ;;
    *) return 1 ;;
  esac

  # Preserve customer artifacts/data
  case "$m" in
    */runs/*) return 1 ;;
    *.env|*.json|*.csv|*.flag) return 1 ;;
    */discovery_results.*|*/upgrade_plan.*) return 1 ;;
  esac

  # Installable tooling patterns
  case "$m" in
    */bin/*) return 0 ;;
    *.sh)    return 0 ;;
    */menu.sh|*/readme.sh|*/read.me) return 0 ;;
    *) return 1 ;;
  esac
}

INSTALL_MEMBERS=()

build_install_list(){
  local tarfile="${WORKDIR}/update.tar"
  local list="${WORKDIR}/members.txt"
  : >"$list"

  if ! tar -tf "$tarfile" >"$list" 2>>"$STDERR_LOG"; then
    fail "Unable to read tar contents. Log: $LOG_FILE"
  fi

  INSTALL_MEMBERS=()
  local m
  while IFS= read -r m; do
    m="${m#./}"
    [[ -z "$m" ]] && continue
    [[ "$m" == */ ]] && continue
    if should_include_member "$m"; then
      INSTALL_MEMBERS+=("$m")
    fi
  done <"$list"

  ((${#INSTALL_MEMBERS[@]} > 0)) || fail "Update tar contains no installable files (after exclusions)."
  log "Installable members after exclusions: ${#INSTALL_MEMBERS[@]}"
}

dry_run_report(){
  local tmp="${WORKDIR}/dryrun.txt"
  : >"$tmp"
  {
    echo "CMDS Update Dry Run"
    echo "-------------------"
    echo "Index used: ${INDEX_USED_URL}"
    echo "Version: ${SELECTED_VERSION}"
    echo "Description: $(normalize_desc "${SELECTED_DESC:-}")"
    echo "Run ID: ${RUN_ID}"
    echo "Logs: ${RUN_DIR}"
    echo
    echo "The following files WOULD be installed/updated:"
    echo
    for m in "${INSTALL_MEMBERS[@]}"; do
      echo "  - /root/$m"
    done
    echo
    echo "Preserved (NOT overwritten):"
    echo "  - */runs/*"
    echo "  - *.env, *.json, *.csv, *.flag"
    echo "  - discovery_results.*, upgrade_plan.*"
  } >"$tmp"

  dialog "${DIALOG_OPTS[@]}" --title "Dry Run" --textbox "$tmp" 0 0 || true
}

ensure_dirs_exist(){
  [[ -d "$CLOUD_DIR"  ]] || mkdir -p "$CLOUD_DIR"
  [[ -d "$HYBRID_DIR" ]] || mkdir -p "$HYBRID_DIR"
  [[ -d "$WLC_DIR"    ]] || mkdir -p "$WLC_DIR"
  [[ -d "$CAT_DIR"    ]] || mkdir -p "$CAT_DIR"
  [[ -d "$SERVER_DIR" ]] || mkdir -p "$SERVER_DIR"
  mkdir -p "$UPD_RUNS_DIR" || true
}

apply_update(){
  local tarfile="${WORKDIR}/update.tar"
  ensure_dirs_exist

  local member_file="${WORKDIR}/install_members.list"
  : >"$member_file"
  for m in "${INSTALL_MEMBERS[@]}"; do printf '%s\n' "$m" >>"$member_file"; done

  dlg_infobox "Applying update v${SELECTED_VERSION}..."
  log "Applying update. Members: ${#INSTALL_MEMBERS[@]}"

  if ! tar -xf "$tarfile" -C /root --no-same-owner --no-same-permissions -T "$member_file" \
      >>"$STDOUT_LOG" 2>>"$STDERR_LOG"; then
    fail "Failed extracting update tar.

Log:
$LOG_FILE"
  fi

  for m in "${INSTALL_MEMBERS[@]}"; do
    local fp="/root/$m"
    [[ -f "$fp" ]] || continue
    case "$fp" in
      *.sh|*/bin/*|*/readme.sh|*/read.me|*/menu.sh) chmod +x "$fp" 2>/dev/null || true ;;
    esac
  done

  log "Update applied successfully."
}

append_patch_history(){
  mkdir -p "$UPD_RUNS_DIR" || true
  {
    echo "================================================================"
    echo "Applied: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Version: ${SELECTED_VERSION}"
    echo "Description: $(normalize_desc "${SELECTED_DESC:-}")"
    echo "Repo: ${REPO_OWNER}/${REPO_NAME}  Branch: ${BRANCH}"
    echo "Index: ${INDEX_USED_URL}"
    echo "Tar: ${SELECTED_TAR}"
    echo "Notes: ${SELECTED_NOTES}"
    echo "SHA: ${SELECTED_SHA:-<none>}"
    echo "Run ID: ${RUN_ID}"
    echo "Run logs: ${RUN_DIR}"
    echo
    echo "--- Release notes (as applied) ---"
    if [[ -s "${WORKDIR}/release.notes" ]]; then
      cat "${WORKDIR}/release.notes"
    else
      echo "(No release notes file found or it was empty.)"
    fi
    echo
  } >>"$PATCH_HISTORY" 2>/dev/null || true

  log "Patch history appended: $PATCH_HISTORY"
}

finish_success(){
  write_installed_version "${SELECTED_VERSION}"
  append_patch_history

  dlg_msg "Update complete" "CMDS update v${SELECTED_VERSION} applied successfully.

Description: $(normalize_desc "${SELECTED_DESC:-}")

Version file written:
  ${VERSION_FILE}

Run ID: $RUN_ID
Logs saved to:
$RUN_DIR

Patch history:
$PATCH_HISTORY

Next: You'll be shown the update log." 18 92

  show_logfile

  dlg_msg "One last step" "Please EXIT the program fully and then re-launch CMDS using:

  meraki_migration.sh

(This ensures the menus/scripts reload with the updated files.)" 10 78

  exit 0
}

main(){
  need dialog
  need curl
  need tar
  need awk
  need sed
  need grep
  need sha256sum
  need cut
  need sort
  need tr

  log "Starting CMDS updater. Repo=${REPO_OWNER}/${REPO_NAME} Branch=${BRANCH}"
  log "RAW_BASE=${RAW_BASE}"

  fetch_versions_raw

  local installed latest
  installed="$(read_installed_version)"
  latest="$(latest_index_version)"

  if [[ -n "${installed:-}" && -n "${latest:-}" && "$installed" == "$latest" ]]; then
    log "Already up to date: installed=$installed latest=$latest"
    dlg_msg "Up to date" "This system is already up to date.

Installed: $installed
Latest:    $latest" 10 60
    exit 0
  fi

  if [[ -z "${installed:-}" ]]; then
    dlg_msg "Version not found" "This system does not have a local CMDS_VERSION recorded yet.

We'll assume this is an unknown install state and prepare the latest update.

Latest available: ${latest:-<unknown>}" 12 70
    auto_select_latest_version
  else
    if ! pick_version_menu; then
      log "User cancelled at version selection."
      exit 0
    fi
  fi

  local meta
  meta="$(get_meta_for_version "$SELECTED_VERSION")" || fail "Selected version not found in index."

  local tar_name notes_name desc sha
  IFS='|' read -r tar_name notes_name desc sha <<<"$meta"

  [[ -n "${tar_name:-}" ]] || fail "Index entry for ${SELECTED_VERSION} is missing tar filename."
  [[ -n "${notes_name:-}" ]] || notes_name="${SELECTED_VERSION}.notes"

  SELECTED_TAR="$tar_name"
  SELECTED_NOTES="$notes_name"
  SELECTED_DESC="${desc:-}"
  SELECTED_SHA="${sha:-}"

  download_update_raw "$SELECTED_VERSION" "$tar_name" "$notes_name" "$desc" "$sha"
  show_release_notes
  build_install_list

  while true; do
    local choice
    choice=$(
      dialog "${DIALOG_OPTS[@]}" --title "Update v${SELECTED_VERSION} $(normalize_desc "${SELECTED_DESC:-}")" \
        --menu "Choose an action:" 14 92 8 \
        1 "Dry run (show files that would change)" \
        2 "Apply update (install now)" \
        3 "View release notes again" \
        4 "View updater log (this run)" \
        5 "View patch history (all applied)" \
        0 "Cancel" \
        3>&1 1>&2 2>&3
    ) || { log "Dialog cancelled."; exit 0; }

    case "$choice" in
      1) dry_run_report ;;
      2)
        dialog "${DIALOG_OPTS[@]}" --title "Confirm update" --yesno \
"Apply CMDS update v${SELECTED_VERSION} now?

Description: $(normalize_desc "${SELECTED_DESC:-}")

This will overwrite installed tools under:
  /root/.cloud_admin
  /root/.hybrid_admin
  /root/.wlc_admin
  /root/.cat_admin
  /root/.server_admin

It will preserve:
  - runs/ directories
  - *.env, *.json, *.csv, *.flag
  - generated discovery/plan artifacts (discovery_results.*, upgrade_plan.*)

Proceed?" 19 92
        if (( $? == 0 )); then
          apply_update
          finish_success
        fi
        ;;
      3) show_release_notes ;;
      4) show_logfile ;;
      5)
        if [[ -s "$PATCH_HISTORY" ]]; then
          dialog "${DIALOG_OPTS[@]}" --title "Patch history" --textbox "$PATCH_HISTORY" 0 0 || true
        else
          dlg_msg "Patch history" "No patch history yet.\n\n$PATCH_HISTORY" 9 70
        fi
        ;;
      0)
        log "User cancelled before applying update."
        exit 0
        ;;
    esac
  done
}

main "$@"