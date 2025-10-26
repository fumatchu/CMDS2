#!/bin/sh
# discovery_prompt.sh — targets + SSH creds (+ login test) + Meraki API key
# + DNS fallbacks + mandatory HTTP client SVI + firmware selection
# POSIX /bin/sh; dialog UI; writes ./meraki_discovery.env

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"
ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"       # scanner reads here
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}" # Cockpit opens here (symlink to FIRMWARE_DIR)
DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

log() { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need python3
need find
need ssh
need sshpass
need timeout

# ---------- Helpers ----------
trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

is_valid_ip()   { python3 -c 'import sys,ipaddress; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
is_valid_cidr() { python3 -c 'import sys,ipaddress; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }

ssh_login_ok() {
  sshpass -p "$3" ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=8 -o ServerAliveInterval=5 -o ServerAliveCountMax=1 \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 -tt "$2@$1" "exit" >/dev/null 2>&1
}

# human bytes
hbytes() {
  awk 'function hb(b){if(b<1024)printf "%d B",b;else if(b<1048576)printf "%.1f KB",b/1024;else if(b<1073741824)printf "%.1f MB",b/1048576;else printf "%.2f GB",b/1073741824}
       {hb($1)}' <<EOF
${1:-0}
EOF
}
# version x.y.z from filename
# Extract IOS XE version from filename safely (e.g., cat9k_iosxe.17.15.03.SPA.bin -> 17.15.03)
version_from_name() {
  b="$(basename -- "$1" 2>/dev/null || printf '%s' "$1")"
  # Prefer "iosxe.<ver>" if present
  v="$(printf '%s\n' "$b" | sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' | head -n1)"
  # Fallback: version preceded by a non-digit boundary (prevents eating the leading "1")
  [ -n "$v" ] || v="$(printf '%s\n' "$b" | sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,3}).*/\1/p' | head -n1)"
  printf '%s\n' "$v"
}
HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

# Ensure Cockpit upload path exists (and points to the scanner dir if missing)
ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    # If parent exists, create a symlink so uploads land in the scanner dir
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

# dialog wrapper
dlg() { _tmp="$(mktemp)"; dialog "$@" 2>"$_tmp"; _rc=$?; DOUT=""; [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"; rm -f "$_tmp"; return $_rc; }

# Clickable link helper (OSC-8). Safe even if terminal doesn’t support it.
osc8_link() { # usage: osc8_link URL [TEXT]
  url="$1"; txt="${2:-$1}"
  # OSC-8 begin + text + OSC-8 end
  printf '\033]8;;%s\033\\%s\033]8;;\033\\\n' "$url" "$txt"
}

print_cockpit_link_and_wait() {
  # Encode the friendly path for Cockpit's file browser
  HOST_SHOW="${HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
  ENC_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$COCKPIT_UPLOAD_DIR")"

  # Two URL forms Cockpit understands
  URL_A="https://${HOST_SHOW}:9090/files#/?path=${ENC_PATH}"
  URL_B="https://${HOST_SHOW}:9090/=${HOST_SHOW}/files#/?path=${ENC_PATH}"

  clear
  echo "=== Upload firmware via Cockpit ==="
  echo
  echo "Click one of these links in your local terminal (Ctrl/Cmd+Click):"
  echo "  $URL_A"
  echo "  $URL_B"
  echo
  echo "Clickable (OSC-8) variants:"
  osc8_link "$URL_A" "Open Cockpit Files at /root/IOS-XE_images"
  osc8_link "$URL_B"
  echo
  echo "Upload your images into: $COCKPIT_UPLOAD_DIR"
  [ -L "$COCKPIT_UPLOAD_DIR" ] && echo "(This path symlinks to: $FIRMWARE_DIR)"
  printf "Press Enter when done to return… "
  IFS= read -r _junk
  stty sane 2>/dev/null || true
}

# -------- Box widths --------
TERM_COLS="$(tput cols 2>/dev/null)"; [ -z "$TERM_COLS" ] && TERM_COLS=140
BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200    # max wide
W_WIDE="$BOX_W"                                                                                  # for API key & long lists
W_MODE="${W_MODE:-68}"; [ "$W_MODE" -lt 60 ] && W_MODE=60; [ "$W_MODE" -gt 90 ] && W_MODE=90     # width you liked on MODE
# Global/default width = MODE width (your request)
W_DEF="$W_MODE"
# Editors for IP/CIDR: also use MODE width (to match)
W_EDIT="$W_MODE"

###############################################################################
# 1) MODE (Provide targets)
###############################################################################
log "Prompt: mode"
dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
    --menu "How do you want to provide targets?" 12 "$W_MODE" 2 \
    scan "Discover live hosts by scanning CIDR networks" \
    list "Use a manual list of IPs (one per line)"
rc=$?; MODE="$(trim "${DOUT:-}")"; log "Mode rc=$rc val='$MODE'"
[ $rc -eq 0 ] || { clear; exit 1; }

###############################################################################
# 2) TARGETS  (loop until valid or user cancels)
###############################################################################
DISCOVERY_NETWORKS=""; DISCOVERY_IPS=""

if [ "$MODE" = "scan" ]; then
  NETS_PREV="$(cat <<'EOF'
# Paste or type CIDR networks (one per line).
# Lines starting with '#' and blank lines are ignored.
10.0.0.0/24
EOF
)"
  while :; do
    tmpnets="$(mktemp)"; printf '%s\n' "$NETS_PREV" >"$tmpnets"
    dlg --clear --backtitle "$BACKTITLE" --title "Networks to Scan (one per line)" \
        --editbox "$tmpnets" 14 "$W_EDIT"
    rc=$?; NETS_RAW="${DOUT:-}"; rm -f "$tmpnets"
    [ $rc -eq 0 ] || { clear; exit 1; }

    NETS_PREV="$NETS_RAW"
    tmpin_nets="$(mktemp)"; printf '%s\n' "$NETS_RAW" >"$tmpin_nets"

    DISCOVERY_NETWORKS=""; invalid_line=""
    while IFS= read -r raw; do
      line="$(trim "$raw")"; [ -z "$line" ] && continue
      case "$line" in \#*) continue;; esac
      if ! is_valid_cidr "$line"; then invalid_line="$line"; break; fi
      [ -z "$DISCOVERY_NETWORKS" ] && DISCOVERY_NETWORKS="$line" || DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS,$line"
    done <"$tmpin_nets"
    rm -f "$tmpin_nets"

    [ -z "$invalid_line" ] || { dlg --title "Invalid Network" --msgbox "Invalid: '$invalid_line'\nUse CIDR like 10.0.0.0/24." 8 "$W_DEF"; continue; }
    [ -n "$DISCOVERY_NETWORKS" ] || { dlg --title "No Networks" --msgbox "Provide at least one valid CIDR." 7 "$W_DEF"; continue; }
    break
  done

else
  IPS_PREV="$(cat <<'EOF'
# Paste or type one IP per line.
# Lines starting with '#' and blank lines are ignored.
192.168.1.10
192.168.1.11
EOF
)"
  while :; do
    tmpips="$(mktemp)"; printf '%s\n' "$IPS_PREV" >"$tmpips"
    dlg --clear --backtitle "$BACKTITLE" --title "Manual IP List (one per line)" \
        --editbox "$tmpips" 16 "$W_EDIT"
    rc=$?; IPS_RAW="${DOUT:-}"; rm -f "$tmpips"
    [ $rc -eq 0 ] || { clear; exit 1; }

    IPS_PREV="$IPS_RAW"
    ips_file="$(mktemp)"; printf '%s\n' "$IPS_RAW" >"$ips_file"

    DISCOVERY_IPS=""; invalid_ip=""; SEEN_TMP="$(mktemp)"; : >"$SEEN_TMP"
    while IFS= read -r raw; do
      ip="$(trim "$raw")"; [ -z "$ip" ] && continue
      case "$ip" in \#*) continue;; esac
      if ! is_valid_ip "$ip"; then invalid_ip="$ip"; break; fi
      if ! grep -qx -- "$ip" "$SEEN_TMP" 2>/dev/null; then
        printf '%s\n' "$ip" >>"$SEEN_TMP"
        [ -z "$DISCOVERY_IPS" ] && DISCOVERY_IPS="$ip" || DISCOVERY_IPS="$DISCOVERY_IPS $ip"
      fi
    done <"$ips_file"
    rm -f "$ips_file"

    [ -z "$invalid_ip" ] || { rm -f "$SEEN_TMP"; dlg --title "Invalid IP" --msgbox "Invalid IP: '$invalid_ip'." 7 "$W_DEF"; continue; }
    [ -n "$DISCOVERY_IPS" ] || { rm -f "$SEEN_TMP"; dlg --title "No IPs" --msgbox "Provide at least one valid IP." 7 "$W_DEF"; continue; }
    rm -f "$SEEN_TMP"; break
  done
fi

###############################################################################
# 3) SSH CREDS (require non-empty) + TEST
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
done

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_PASSWORD="$(trim "${DOUT:-}")"
  [ -n "$SSH_PASSWORD" ] && break
  dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
done

SSH_TEST_IP=""
if [ -n "$DISCOVERY_IPS" ]; then
  MENU_ARGS=""; for ip in $DISCOVERY_IPS; do MENU_ARGS="$MENU_ARGS $ip -"; done
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Test Device" \
      --menu "We'll verify your SSH credentials on one device.\nSelect an IP:" 16 "$W_DEF" 12 $MENU_ARGS
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_TEST_IP="$(trim "${DOUT:-}")"
else
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "Test Device IP" \
        --inputbox "Enter an IP address to test the SSH login:" 9 "$W_DEF" "$SSH_TEST_IP"
    rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
    val="$(trim "${DOUT:-}")"
    [ -n "$val" ] && is_valid_ip "$val" && SSH_TEST_IP="$val" && break
    dlg --title "Invalid IP" --msgbox "Please enter a valid IPv4/IPv6 address." 7 "$W_DEF"
  done
fi

while :; do
  dlg --backtitle "$BACKTITLE" --title "Testing SSH" --infobox "Testing SSH login to ${SSH_TEST_IP} as ${SSH_USERNAME}…" 6 "$W_DEF"
  sleep 1
  if ssh_login_ok "$SSH_TEST_IP" "$SSH_USERNAME" "$SSH_PASSWORD"; then
    dlg --backtitle "$BACKTITLE" --title "SSH Test" --infobox "Login OK to ${SSH_TEST_IP}." 5 "$W_DEF"; sleep 1; break
  fi
  dlg --backtitle "$BACKTITLE" --title "Login Failed" --yesno \
      "Could not log in to ${SSH_TEST_IP} as ${SSH_USERNAME}.\n\nRe-enter username and password?" 9 "$W_DEF"
  [ $? -eq 0 ] || { clear; exit 1; }

  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 "$W_DEF" "$SSH_USERNAME"
    [ $? -eq 0 ] || { clear; exit 1; }
    SSH_USERNAME="$(trim "${DOUT:-}")"
    [ -n "$SSH_USERNAME" ] && break
    dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 "$W_DEF"
  done
  while :; do
    dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
        --insecure --passwordbox "Enter SSH password (masked with *):" 9 "$W_DEF"
    [ $? -eq 0 ] || { clear; exit 1; }
    SSH_PASSWORD="$(trim "${DOUT:-}")"
    [ -n "$SSH_PASSWORD" ] && break
    dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 "$W_DEF"
  done
done

###############################################################################
# 3b) MERAKI API KEY (keep WIDE)
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Meraki API Key" \
      --insecure --passwordbox "Paste your Meraki Dashboard API key:\n(Asterisks shown while typing; last 4 shown in summary.)" 10 "$W_WIDE"
  rc=$?; [ $rc -eq 1 ] && { clear; exit 1; }
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 "$W_DEF"; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 "$W_DEF"
  [ $? -eq 0 ] && break
done

###############################################################################
# 3c) DNS (compact = MODE width)
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "Optional DNS Servers" --msgbox \
"We will NOT overwrite existing DNS on switches.\nIf a switch cannot resolve DNS, we will apply these fallback entries.\n\nLeave fields blank to skip." 10 "$W_DEF"

DNS_PRIMARY=""; DNS_SECONDARY=""
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "DNS Fallback — Primary" --inputbox "Primary DNS server (optional):" 8 "$W_DEF" "$DNS_PRIMARY"
  rc=$?; val="$(trim "${DOUT:-}")"; [ $rc -ne 0 ] && val=""
  [ -z "$val" ] && { DNS_PRIMARY=""; break; }
  is_valid_ip "$val" && DNS_PRIMARY="$val" && break
  dlg --msgbox "Invalid IP address: '$val'." 7 "$W_DEF"
done
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "DNS Fallback — Secondary" --inputbox "Secondary DNS server (optional):" 8 "$W_DEF" "$DNS_SECONDARY"
  rc=$?; val="$(trim "${DOUT:-}")"; [ $rc -ne 0 ] && val=""
  [ -z "$val" ] && { DNS_SECONDARY=""; break; }
  is_valid_ip "$val" && DNS_SECONDARY="$val" && break
  dlg --msgbox "Invalid IP address: '$val'." 7 "$W_DEF"
done

###############################################################################
# 3d) VLAN SVI — MANDATORY
###############################################################################
HTTP_CLIENT_VLAN_ID=""; HTTP_CLIENT_SOURCE_IFACE=""
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "HTTP Client Source SVI (required)" \
      --inputbox "Enter the VLAN SVI number to use with:\n  ip http client source-interface Vlan<N>\n\nExamples: 10, 20, 4094" 12 "$W_DEF" "$HTTP_CLIENT_VLAN_ID"
  rc=$?; [ $rc -eq 0 ] || { clear; exit 1; }
  val="$(trim "${DOUT:-}")"
  python3 - "$val" <<'PY'
import sys
s=sys.argv[1]
ok = s.isdigit() and 1 <= int(s) <= 4094
sys.exit(0 if ok else 1)
PY
  if [ $? -eq 0 ]; then
    HTTP_CLIENT_VLAN_ID="$val"; HTTP_CLIENT_SOURCE_IFACE="Vlan${HTTP_CLIENT_VLAN_ID}"; break
  fi
  dlg --msgbox "Invalid VLAN ID: '${val:-<empty>}'\nEnter a number 1–4094." 9 "$W_DEF"
done

###############################################################################
# 4) FIRMWARE PICK (WIDE to show long filenames)
###############################################################################
mkdir -p "$FIRMWARE_DIR"
command -v restorecon >/dev/null 2>/dev/null && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%T@|%s|%f\n' 2>/dev/null | sort -nr
}

while :; do
  tmp_lines="$(mktemp)"; list_files >"$tmp_lines"
  if [ ! -s "$tmp_lines" ]; then
    CH=$(
      dialog --clear --backtitle "$BACKTITLE" --title "Firmware Upload Needed" \
        --menu "No firmware images were found in:\n  $FIRMWARE_DIR\n\nUpload in Cockpit, then choose Rescan." 14 "$W_DEF" 6 \
          1 "Show clickable Cockpit link (opens /root/IOS-XE_images)" \
          2 "Rescan directory" \
          0 "Exit setup" \
        3>&1 1>&2 2>&3
    ) || { clear; rm -f "$tmp_lines"; exit 1; }

    case "$CH" in
      1) print_cockpit_link_and_wait; rm -f "$tmp_lines"; continue ;;
      2) rm -f "$tmp_lines"; continue ;;
      0) clear; rm -f "$tmp_lines"; exit 1 ;;
    esac
  fi
  break
done

build_menu_file() {
  fam="$1"; infile="$2"
  while IFS='|' read -r _mt _sz nm; do
    [ -z "$nm" ] && continue
    lower="$(printf '%s' "$nm" | tr '[:upper:]' '[:lower:]')"
    case "$fam" in
      universal) echo "$lower" | grep -Eq '^cat9k_iosxe.*\.bin$' || continue ;;
      lite)      echo "$lower" | grep -Eq '^cat9k_lite_iosxe.*\.bin$' || continue ;;
    esac
    printf '%s\n' "$nm"; printf '%s\n' "-"
  done <"$infile"
}

U_FILE="$(mktemp)"; build_menu_file universal "$tmp_lines" >"$U_FILE"
L_FILE="$(mktemp)"; build_menu_file lite "$tmp_lines" >"$L_FILE"
U_ARGS="$(tr '\n' ' ' <"$U_FILE")"; L_ARGS="$(tr '\n' ' ' <"$L_FILE")"
FW_CAT9K_FILE=""; FW_CAT9K_LITE_FILE=""

if [ -s "$U_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
      --menu "Choose a Cat9k (9300/9400/9500/9600) image:" 22 "$W_WIDE" 16 $U_ARGS
  [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
fi
if [ -s "$L_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
      --menu "Choose a Cat9k-Lite (9200) image:" 22 "$W_WIDE" 16 $L_ARGS
  [ $? -eq 0 ] && FW_CAT9K_LITE_FILE="${DOUT:-}"
fi

if [ -z "$FW_CAT9K_FILE$FW_CAT9K_LITE_FILE" ]; then
  G_TMP="$(mktemp)"; while IFS='|' read -r _mt _sz nm; do [ -z "$nm" ] || printf '%s\n%s\n' "$nm" "-" >>"$G_TMP"; done <"$tmp_lines"
  if [ -s "$G_TMP" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Generic" \
        --menu "Pick an image to proceed:" 22 "$W_WIDE" 16 $(tr '\n' ' ' <"$G_TMP")
    [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
  fi
  rm -f "$G_TMP"
fi

resolve_meta() {
  name="$1"; infile="$2"
  while IFS='|' read -r mt sz nm; do [ "$nm" = "$name" ] && { printf '%s|%s\n' "$sz" "$FIRMWARE_DIR/$nm"; return; }; done <"$infile"
  printf '|\n'
}

FW_CAT9K_PATH=""; FW_CAT9K_SIZE_BYTES=""; FW_CAT9K_SIZE_H=""; FW_CAT9K_VERSION=""
FW_CAT9K_LITE_PATH=""; FW_CAT9K_LITE_SIZE_BYTES=""; FW_CAT9K_LITE_SIZE_H=""; FW_CAT9K_LITE_VERSION=""
if [ -n "$FW_CAT9K_FILE" ]; then
  out="$(resolve_meta "$FW_CAT9K_FILE" "$tmp_lines")"
  FW_CAT9K_SIZE_BYTES="$(printf '%s' "$out" | cut -d'|' -f1)"
  FW_CAT9K_PATH="$(printf '%s' "$out" | cut -d'|' -f2)"
  FW_CAT9K_SIZE_H="$(hbytes "${FW_CAT9K_SIZE_BYTES:-0}")"
  FW_CAT9K_VERSION="$(version_from_name "$FW_CAT9K_FILE")"
fi
if [ -n "$FW_CAT9K_LITE_FILE" ]; then
  out="$(resolve_meta "$FW_CAT9K_LITE_FILE" "$tmp_lines")"
  FW_CAT9K_LITE_SIZE_BYTES="$(printf '%s' "$out" | cut -d'|' -f1)"
  FW_CAT9K_LITE_PATH="$(printf '%s' "$out" | cut -d'|' -f2)"
  FW_CAT9K_LITE_SIZE_H="$(hbytes "${FW_CAT9K_LITE_SIZE_BYTES:-0}")"
  FW_CAT9K_LITE_VERSION="$(version_from_name "$FW_CAT9K_LITE_FILE")"
fi

rm -f "$tmp_lines" "$U_FILE" "$L_FILE" 2>/dev/null

###############################################################################
# 5) EXPORT + PERSIST
###############################################################################
export DISCOVERY_MODE="$MODE"
export DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS"
export DISCOVERY_IPS="$DISCOVERY_IPS"
export SSH_USERNAME SSH_PASSWORD SSH_TEST_IP
export MERAKI_API_KEY
export DNS_PRIMARY DNS_SECONDARY
export HTTP_CLIENT_VLAN_ID HTTP_CLIENT_SOURCE_IFACE
export FW_CAT9K_FILE FW_CAT9K_PATH FW_CAT9K_SIZE_BYTES FW_CAT9K_SIZE_H FW_CAT9K_VERSION
export FW_CAT9K_LITE_FILE FW_CAT9K_LITE_PATH FW_CAT9K_LITE_SIZE_BYTES FW_CAT9K_LITE_SIZE_H FW_CAT9K_LITE_VERSION

{
  echo "# Generated $(date -u '+%F %T') UTC"
  printf 'export DISCOVERY_MODE=%q\n' "$DISCOVERY_MODE"
  printf 'export DISCOVERY_NETWORKS=%q\n' "$DISCOVERY_NETWORKS"
  printf 'export DISCOVERY_IPS=%q\n' "$DISCOVERY_IPS"
  printf 'export SSH_USERNAME=%q\n' "$SSH_USERNAME"
  printf 'export SSH_PASSWORD=%q\n' "$SSH_PASSWORD"
  printf 'export SSH_TEST_IP=%q\n' "$SSH_TEST_IP"
  printf 'export MERAKI_API_KEY=%q\n' "$MERAKI_API_KEY"
  printf 'export DNS_PRIMARY=%q\n' "$DNS_PRIMARY"
  printf 'export DNS_SECONDARY=%q\n' "$DNS_SECONDARY"
  printf 'export HTTP_CLIENT_VLAN_ID=%q\n' "$HTTP_CLIENT_VLAN_ID"
  printf 'export HTTP_CLIENT_SOURCE_IFACE=%q\n' "$HTTP_CLIENT_SOURCE_IFACE"
  [ -n "$FW_CAT9K_FILE" ] && {
    printf 'export FW_CAT9K_FILE=%q\n' "$FW_CAT9K_FILE"
    printf 'export FW_CAT9K_PATH=%q\n' "$FW_CAT9K_PATH"
    printf 'export FW_CAT9K_SIZE_BYTES=%q\n' "$FW_CAT9K_SIZE_BYTES"
    printf 'export FW_CAT9K_SIZE_H=%q\n' "$FW_CAT9K_SIZE_H"
    printf 'export FW_CAT9K_VERSION=%q\n' "$FW_CAT9K_VERSION"
  }
  [ -n "$FW_CAT9K_LITE_FILE" ] && {
    printf 'export FW_CAT9K_LITE_FILE=%q\n' "$FW_CAT9K_LITE_FILE"
    printf 'export FW_CAT9K_LITE_PATH=%q\n' "$FW_CAT9K_LITE_PATH"
    printf 'export FW_CAT9K_LITE_SIZE_BYTES=%q\n' "$FW_CAT9K_LITE_SIZE_BYTES"
    printf 'export FW_CAT9K_LITE_SIZE_H=%q\n' "$FW_CAT9K_LITE_SIZE_H"
    printf 'export FW_CAT9K_LITE_VERSION=%q\n' "$FW_CAT9K_LITE_VERSION"
  }
} >"$ENV_FILE"
chmod 600 "$ENV_FILE"

###############################################################################
# 6) SUMMARY (WIDE)
###############################################################################
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() {
  s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}')
  if [ "$n" -le 4 ]; then printf '****'; else
    printf "%0.s*" $(seq 1 $((n-4))); printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}
PW_MASK="$(mask "$SSH_PASSWORD")"
API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
SVI_SUMMARY="$( printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID" )"

summary="Saved: ${ENV_FILE}

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Meraki API Key: ${API_MASK}

DNS fallback (won't overwrite existing; only used if switch cannot resolve):
  Primary  : ${DNS_PRIMARY:-<none>}
  Secondary: ${DNS_SECONDARY:-<none>}

HTTP client source-interface (required):
  ${SVI_SUMMARY}
"
if [ -n "$FW_CAT9K_FILE" ]; then
  summary="${summary}
Cat9k (universal):
  ${FW_CAT9K_FILE}  [$(hbytes "${FW_CAT9K_SIZE_BYTES:-0}")${FW_CAT9K_VERSION:+, v${FW_CAT9K_VERSION}}]
  ${FW_CAT9K_PATH}
"
fi
if [ -n "$FW_CAT9K_LITE_FILE" ]; then
  summary="${summary}
Cat9k-Lite (9200):
  ${FW_CAT9K_LITE_FILE}  [$(hbytes "${FW_CAT9K_LITE_SIZE_BYTES:-0}")${FW_CAT9K_LITE_VERSION:+, v${FW_CAT9K_LITE_VERSION}}]
  ${FW_CAT9K_LITE_PATH}
"
fi

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 22 "$W_WIDE"
clear
