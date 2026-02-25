#!/usr/bin/env bash
# cmds_repo_sync.sh
# Pulls two "golden" files from the CMDS GitHub repo and installs them locally:
#  1) meraki_migration.sh  -> /usr/local/bin/meraki_migration.sh (chmod 700)
#  2) .server_admin/cmds_updater.sh -> /root/.server_admin/cmds_updater.sh (chmod 700)
#
# Safe behaviors:
# - Overwrites existing targets (as requested)
# - Makes timestamped backups of the previous files (optional but handy)
# - Verifies curl success + non-empty downloads
# - Auto-detects /root/.server_admin vs /root/.serv_admin (uses whichever exists, prefers .server_admin)
#
# Run as root.

set -Eeuo pipefail

# ---- Repo settings (override via env if desired) ----
REPO_OWNER="${REPO_OWNER:-fumatchu}"
REPO_NAME="${REPO_NAME:-CMDS2}"
BRANCH="${BRANCH:-main}"

RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}"

# ---- Sources in repo ----
SRC_MERAKI="${RAW_BASE}/meraki_migration.sh"
SRC_UPDATER="${RAW_BASE}/.server_admin/cmds_updater.sh"

# ---- Destinations on system ----
DEST_MERAKI="/usr/local/bin/meraki_migration.sh"

# Prefer /root/.server_admin; fallback to /root/.serv_admin if that exists and server_admin doesn't
ROOT_BASE="/root"
SERVER_ADMIN_DIR=""
if [[ -d "${ROOT_BASE}/.server_admin" ]]; then
  SERVER_ADMIN_DIR="${ROOT_BASE}/.server_admin"
elif [[ -d "${ROOT_BASE}/.serv_admin" ]]; then
  SERVER_ADMIN_DIR="${ROOT_BASE}/.serv_admin"
else
  # default to canonical name
  SERVER_ADMIN_DIR="${ROOT_BASE}/.server_admin"
fi
DEST_UPDATER="${SERVER_ADMIN_DIR}/cmds_updater.sh"

# ---- Helpers ----
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need curl
need install
need mktemp
need chmod
need mkdir
need date

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Please run as root." >&2; exit 1; }

ts() { date '+%Y%m%d-%H%M%S'; }

backup_if_exists() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(ts)" 2>/dev/null || true
}

download_to_tmp() {
  local url="$1"
  local tmp="$2"

  # -f: fail on 404/50x, -L: follow redirects, -sS: silent but show errors
  curl -fLsS --connect-timeout 8 --max-time 60 \
    -H "Cache-Control: no-cache" \
    "$url" -o "$tmp"

  # Basic sanity: non-empty and has a shebang (these are scripts)
  [[ -s "$tmp" ]] || { echo "Download failed/empty: $url" >&2; return 1; }
  head -n 1 "$tmp" | grep -q '^#!' || {
    echo "Downloaded file from $url does not look like a script (missing shebang)." >&2
    return 1
  }
}

install_script() {
  local tmp="$1"
  local dest="$2"

  mkdir -p "$(dirname "$dest")"
  backup_if_exists "$dest"

  # install gives atomic-ish replace and sets perms/owner nicely
  install -m 700 -o root -g root "$tmp" "$dest"
  chmod 700 "$dest" 2>/dev/null || true
}

# ---- Main ----
echo "Repo: ${REPO_OWNER}/${REPO_NAME} (${BRANCH})"
echo "RAW_BASE: $RAW_BASE"
echo
echo "Installing:"
echo "  - $SRC_MERAKI  -> $DEST_MERAKI"
echo "  - $SRC_UPDATER -> $DEST_UPDATER"
echo

tmp1="$(mktemp)"
tmp2="$(mktemp)"
cleanup(){ rm -f "$tmp1" "$tmp2" 2>/dev/null || true; }
trap cleanup EXIT

echo "Downloading meraki_migration.sh..."
download_to_tmp "$SRC_MERAKI" "$tmp1"

echo "Downloading cmds_updater.sh..."
download_to_tmp "$SRC_UPDATER" "$tmp2"

echo "Installing meraki_migration.sh to /usr/local/bin (chmod 700)..."
install_script "$tmp1" "$DEST_MERAKI"

echo "Ensuring server admin dir exists: $SERVER_ADMIN_DIR"
mkdir -p "$SERVER_ADMIN_DIR"

echo "Installing cmds_updater.sh into $SERVER_ADMIN_DIR (chmod 700)..."
install_script "$tmp2" "$DEST_UPDATER"

echo
echo "Done."
echo "  $(ls -al "$DEST_MERAKI")"
echo "  $(ls -al "$DEST_UPDATER")"