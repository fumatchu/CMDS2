#!/bin/sh
# discovery_prompt.sh — targets + SSH creds + Meraki API key + DNS fallbacks + HTTP client SVI + firmware selection
# POSIX /bin/sh; dialog UI; writes ./meraki_discovery.env

TITLE="CMDS Switch Discovery — Setup"
BACKTITLE="Meraki Migration Toolkit — Discovery"
ENV_FILE="${ENV_FILE:-./meraki_discovery.env}"
FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"
DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_discovery_prompt.log}"

log() { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need python3
need find

# ---------- Helpers ----------
# ---------- Helpers ----------
# Trim leading/trailing whitespace and strip CRs (already in your file)
trim() {
  printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Use python -c so argv handling is rock solid
is_valid_ip() {
  python3 -c 'import sys, ipaddress; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null
}

is_valid_cidr() {
  python3 -c 'import sys, ipaddress; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null
}
HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

dlg() { _tmp="$(mktemp)"; dialog "$@" 2>"$_tmp"; _rc=$?; DOUT=""; [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"; rm -f "$_tmp"; return $_rc; }

TERM_COLS="$(tput cols 2>/dev/null)"; [ -z "$TERM_COLS" ] && TERM_COLS=140
BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200

# Narrower width for multi-line edit boxes (scan/list). Clamp to 50–90 chars.
EDIT_W=${EDIT_W:-$(( TERM_COLS - 40 ))}
[ "$EDIT_W" -lt 50 ] && EDIT_W=50
[ "$EDIT_W" -gt 90 ] && EDIT_W=90

###############################################################################
# 1) MODE
###############################################################################
log "Prompt: mode"
dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" \
    --menu "How do you want to provide targets?" 12 "$EDIT_W" 2 \
    scan "Discover live hosts by scanning CIDR networks" \
    list "Use a manual list of IPs (one per line)"
rc=$?; MODE="$(trim "${DOUT:-}")"; log "Mode rc=$rc val='$MODE'"
[ $rc -eq 0 ] || { clear; exit 1; }

###############################################################################
# 2) TARGETS  (loop until valid or user cancels)
###############################################################################
DISCOVERY_NETWORKS=""
DISCOVERY_IPS=""

if [ "$MODE" = "scan" ]; then
  log "Mode=scan"

  NETS_PREV="$(cat <<'EOF'
# Paste or type CIDR networks (one per line).
# Tips: Ctrl+Shift+V (most terminals), Shift+Insert, or right-click Paste.
# Lines starting with '#' and blank lines are ignored.
10.0.0.0/24
EOF
)"

  while :; do
    tmpnets="$(mktemp)"; printf '%s\n' "$NETS_PREV" >"$tmpnets"
    dlg --clear --backtitle "$BACKTITLE" --title "Networks to Scan (one per line)" \
        --editbox "$tmpnets" 14 "$EDIT_W"
    rc=$?; NETS_RAW="${DOUT:-}"; rm -f "$tmpnets"; log "scan editbox rc=$rc"
    [ $rc -eq 0 ] || { clear; exit 1; }

    NETS_PREV="$NETS_RAW"
    tmpin_nets="$(mktemp)"; printf '%s\n' "$NETS_RAW" >"$tmpin_nets"

    DISCOVERY_NETWORKS=""
    invalid_line=""
    while IFS= read -r raw; do
      line="$(trim "$raw")"
      [ -z "$line" ] && continue
      case "$line" in \#*) continue;; esac
      if ! is_valid_cidr "$line"; then invalid_line="$line"; break; fi
      [ -z "$DISCOVERY_NETWORKS" ] && DISCOVERY_NETWORKS="$line" || DISCOVERY_NETWORKS="$DISCOVERY_NETWORKS,$line"
    done <"$tmpin_nets"
    rm -f "$tmpin_nets"

    if [ -n "$invalid_line" ]; then
      dlg --title "Invalid Network" --msgbox "Invalid: '$invalid_line'\nUse proper CIDR (e.g., 10.0.0.0/24), one per line." 8 64
      continue
    fi
    if [ -z "$DISCOVERY_NETWORKS" ]; then
      dlg --title "No Networks" --msgbox "Provide at least one valid CIDR." 7 "$BOX_W"
      continue
    fi
    break
  done

else
  log "Mode=list"

  IPS_PREV="$(cat <<'EOF'
# Paste or type one IP per line.
# Tips: Ctrl+Shift+V (most terminals), Shift+Insert, or right-click Paste.
# Lines starting with '#' and blank lines are ignored.
192.168.1.10
192.168.1.11
EOF
)"

  while :; do
    tmpips="$(mktemp)"; printf '%s\n' "$IPS_PREV" >"$tmpips"
    dlg --clear --backtitle "$BACKTITLE" --title "Manual IP List (one per line)" \
        --editbox "$tmpips" 16 "$EDIT_W"
    rc=$?; IPS_RAW="${DOUT:-}"; rm -f "$tmpips"; log "list editbox rc=$rc"
    [ $rc -eq 0 ] || { clear; exit 1; }

    IPS_PREV="$IPS_RAW"
    ips_file="$(mktemp)"; printf '%s\n' "$IPS_RAW" >"$ips_file"

    DISCOVERY_IPS=""
    invalid_ip=""
    SEEN_TMP="$(mktemp)"; : >"$SEEN_TMP"

    while IFS= read -r raw; do
      ip="$(trim "$raw")"
      [ -z "$ip" ] && continue
      case "$ip" in \#*) continue;; esac
      if ! is_valid_ip "$ip"; then invalid_ip="$ip"; break; fi
      if ! grep -qx -- "$ip" "$SEEN_TMP" 2>/dev/null; then
        printf '%s\n' "$ip" >>"$SEEN_TMP"
        [ -z "$DISCOVERY_IPS" ] && DISCOVERY_IPS="$ip" || DISCOVERY_IPS="$DISCOVERY_IPS $ip"
      fi
    done <"$ips_file"
    rm -f "$ips_file"

    if [ -n "$invalid_ip" ]; then
      rm -f "$SEEN_TMP"
      dlg --title "Invalid IP" --msgbox "Invalid IP: '$invalid_ip'\nEnter IPv4/IPv6 literal, one per line." 8 64
      continue
    fi
    if [ -z "$DISCOVERY_IPS" ]; then
      rm -f "$SEEN_TMP"
      dlg --title "No IPs" --msgbox "Provide at least one valid IP." 7 "$BOX_W"
      continue
    fi
    rm -f "$SEEN_TMP"
    break
  done
fi

###############################################################################
# 3) SSH CREDS (require non-empty)
###############################################################################
log "Prompt: username"
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Username" --inputbox "Enter SSH username:" 8 50
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_USERNAME="$(trim "${DOUT:-}")"
  [ -n "$SSH_USERNAME" ] && break
  dlg --title "Missing Username" --msgbox "Username cannot be empty." 7 44
done

log "Prompt: password"
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "SSH Password" \
      --insecure --passwordbox "Enter SSH password (masked with *):" 9 60
  [ $? -eq 0 ] || { clear; exit 1; }
  SSH_PASSWORD="$(trim "${DOUT:-}")"
  [ -n "$SSH_PASSWORD" ] && break
  dlg --title "Missing Password" --msgbox "Password cannot be empty." 7 44
done

###############################################################################
# 3b) MERAKI API KEY
###############################################################################
while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "Meraki API Key" \
      --insecure --passwordbox "Paste your Meraki Dashboard API key:\n(Asterisks shown while typing; last 4 shown in summary.)" 10 "$BOX_W"
  rc=$?; [ $rc -eq 1 ] && { clear; exit 1; }
  MERAKI_API_KEY="$(trim "${DOUT:-}")"
  [ -n "$MERAKI_API_KEY" ] || { dlg --msgbox "API key cannot be empty." 7 40; continue; }
  printf '%s' "$MERAKI_API_KEY" | grep -Eq '^[A-Za-z0-9]{28,64}$' >/dev/null 2>&1 && break
  dlg --yesno "The key format looks unusual.\nUse it anyway?" 9 50
  [ $? -eq 0 ] && break
done

###############################################################################
# 3c) OPTIONAL DNS SERVERS (up to 2)
###############################################################################
dlg --clear --backtitle "$BACKTITLE" --title "Optional DNS Servers" --msgbox \
"We will NOT overwrite existing DNS on switches.\nIf a switch cannot resolve DNS, we will apply these fallback entries.\n\nLeave fields blank to skip." 10 "$BOX_W"

DNS_PRIMARY=""
DNS_SECONDARY=""

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "DNS Fallback — Primary" --inputbox "Primary DNS server (optional):" 8 60 "$DNS_PRIMARY"
  rc=$?; val="$(trim "${DOUT:-}")"; [ $rc -ne 0 ] && val=""
  [ -z "$val" ] && { DNS_PRIMARY=""; break; }
  if is_valid_ip "$val"; then DNS_PRIMARY="$val"; break; fi
  dlg --msgbox "Invalid IP address: '$val'." 7 50
done

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "DNS Fallback — Secondary" --inputbox "Secondary DNS server (optional):" 8 60 "$DNS_SECONDARY"
  rc=$?; val="$(trim "${DOUT:-}")"; [ $rc -ne 0 ] && val=""
  [ -z "$val" ] && { DNS_SECONDARY=""; break; }
  if is_valid_ip "$val"; then DNS_SECONDARY="$val"; break; fi
  dlg --msgbox "Invalid IP address: '$val'." 7 50
done

###############################################################################
# 3d) VLAN SVI for 'ip http client source-interface' (optional)
###############################################################################
HTTP_CLIENT_VLAN_ID=""
HTTP_CLIENT_SOURCE_IFACE=""

while :; do
  dlg --clear --backtitle "$BACKTITLE" --title "HTTP Client Source SVI (optional)" \
      --inputbox "Enter the VLAN SVI number to use with:\n  ip http client source-interface Vlan<N>\n\nExamples: 10, 20, 4094\nLeave blank to skip." 12 70 "$HTTP_CLIENT_VLAN_ID"
  rc=$?; val="$(trim "${DOUT:-}")"
  [ $rc -ne 0 ] && val=""
  [ -z "$val" ] && break
  python3 - "$val" <<'PY' || ok=1
import sys
s=sys.argv[1]
ok = s.isdigit() and 1 <= int(s) <= 4094
sys.exit(0 if ok else 1)
PY
  if [ $? -eq 0 ]; then
    HTTP_CLIENT_VLAN_ID="$val"
    HTTP_CLIENT_SOURCE_IFACE="Vlan${HTTP_CLIENT_VLAN_ID}"
    break
  else
    dlg --msgbox "Invalid VLAN ID: '$val'\nEnter a number 1–4094, or leave blank to skip." 9 60
  fi
done

###############################################################################
# 4) FIRMWARE PICK (Cat9k universal + Cat9k-Lite)
###############################################################################
mkdir -p "$FIRMWARE_DIR"
command -v restorecon >/dev/null 2>/dev/null && restorecon -R "$FIRMWARE_DIR" >/dev/null 2>&1

list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%T@|%s|%f\n' 2>/dev/null | sort -nr
}

while :; do
  log "Scan firmware dir"
  tmp_lines="$(mktemp)"; list_files >"$tmp_lines"
  if [ ! -s "$tmp_lines" ]; then
    dlg --clear --backtitle "$BACKTITLE" --title "Firmware Upload" --msgbox \
"No firmware files were found in:
  $FIRMWARE_DIR

Upload images via Cockpit, then return here.

Clickable links:
  https://${HOST_FQDN}:9090
  https://${HOST_IP}:9090
" 14 "$BOX_W" || { clear; rm -f "$tmp_lines"; exit 1; }
    clear
    echo "Cockpit (hostname): https://${HOST_FQDN}:9090"
    echo "Cockpit (IP)      : https://${HOST_IP}:9090"
    echo
    dlg --clear --backtitle "$BACKTITLE" --title "Firmware Upload" --yesno "Rescan now?" 7 "$BOX_W"
    [ $? -eq 0 ] && { clear; rm -f "$tmp_lines"; continue; } || { clear; rm -f "$tmp_lines"; exit 1; }
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
    printf '%s\n' "$nm"
    printf '%s\n' "-"
  done <"$infile"
}

U_FILE="$(mktemp)"; build_menu_file universal "$tmp_lines" >"$U_FILE"
L_FILE="$(mktemp)"; build_menu_file lite "$tmp_lines" >"$L_FILE"

U_ARGS="$(tr '\n' ' ' <"$U_FILE")"
L_ARGS="$(tr '\n' ' ' <"$L_FILE")"

FW_CAT9K_FILE=""
FW_CAT9K_LITE_FILE=""

if [ -s "$U_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k (universal)" \
      --menu "Choose a Cat9k (9300/9400/9500/9600) image:" 22 "$BOX_W" 16 $U_ARGS
  [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
fi
if [ -s "$L_FILE" ]; then
  # shellcheck disable=SC2086
  dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Cat9k-Lite (9200)" \
      --menu "Choose a Cat9k-Lite (9200) image:" 22 "$BOX_W" 16 $L_ARGS
  [ $? -eq 0 ] && FW_CAT9K_LITE_FILE="${DOUT:-}"
fi

if [ -z "$FW_CAT9K_FILE$FW_CAT9K_LITE_FILE" ]; then
  G_TMP="$(mktemp)"
  while IFS='|' read -r _mt _sz nm; do [ -z "$nm" ] || printf '%s\n%s\n' "$nm" "-" >>"$G_TMP"; done <"$tmp_lines"
  if [ -s "$G_TMP" ]; then
    # shellcheck disable=SC2086
    dlg --clear --backtitle "$BACKTITLE" --title "Select Firmware — Generic" \
        --menu "Pick an image to proceed:" 22 "$BOX_W" 16 $(tr '\n' ' ' <"$G_TMP")
    [ $? -eq 0 ] && FW_CAT9K_FILE="${DOUT:-}"
  fi
  rm -f "$G_TMP"
fi

resolve_meta() {
  name="$1"; infile="$2"
  while IFS='|' read -r mt sz nm; do
    [ "$nm" = "$name" ] && { printf '%s|%s\n' "$sz" "$FIRMWARE_DIR/$nm"; return; }
  done <"$infile"
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
export SSH_USERNAME
export SSH_PASSWORD
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
# 6) SUMMARY
###############################################################################
mask() { n=$(printf '%s' "$1" | wc -c | awk '{print $1}'); [ "$n" -gt 0 ] && { printf "%0.s*" $(seq 1 "$n"); } || printf "(empty)"; }
mask_last4() {
  s="$1"; n=$(printf '%s' "$s" | wc -c | awk '{print $1}')
  if [ "$n" -le 4 ]; then printf '****'; else
    printf "%0.s*" $(seq 1 $((n-4)))
    printf '%s' "$(printf '%s' "$s" | sed -n 's/.*\(....\)$/\1/p')"
  fi
}
PW_MASK="$(mask "$SSH_PASSWORD")"
API_MASK="$(mask_last4 "$MERAKI_API_KEY")"
SVI_SUMMARY="$( [ -n "$HTTP_CLIENT_VLAN_ID" ] && printf '%s (%s)' "$HTTP_CLIENT_SOURCE_IFACE" "$HTTP_CLIENT_VLAN_ID" || printf '<none>' )"

summary="Saved: ${ENV_FILE}

SSH Username: ${SSH_USERNAME}
SSH Password: ${PW_MASK}
Meraki API Key: ${API_MASK}

DNS fallback (won't overwrite existing; only used if switch cannot resolve):
  Primary  : ${DNS_PRIMARY:-<none>}
  Secondary: ${DNS_SECONDARY:-<none>}

HTTP client source-interface (for later):
  ${SVI_SUMMARY}
"
if [ -n "$FW_CAT9K_FILE" ]; then
  summary="${summary}
Cat9k (universal):
  ${FW_CAT9K_FILE}  [${FW_CAT9K_SIZE_H}${FW_CAT9K_VERSION:+, v${FW_CAT9K_VERSION}}]
  ${FW_CAT9K_PATH}
"
fi
if [ -n "$FW_CAT9K_LITE_FILE" ]; then
  summary="${summary}
Cat9k-Lite (9200):
  ${FW_CAT9K_LITE_FILE}  [${FW_CAT9K_LITE_SIZE_H}${FW_CAT9K_LITE_VERSION:+, v${FW_CAT9K_LITE_VERSION}}]
  ${FW_CAT9K_LITE_PATH}
"
fi

dlg --clear --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$summary" 22 "$BOX_W"
clear
