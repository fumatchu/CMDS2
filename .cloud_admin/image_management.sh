#!/bin/sh
# manage_firmware_images.sh
# Simple dialog-based helper to:
#   - Open Cockpit at the firmware upload path
#   - Rescan /var/lib/tftpboot/images (or $FIRMWARE_DIR)
#   - Show a categorized list of IOS-XE images (universal / lite / other)
#
# This does NOT modify meraki_discovery.env — it only helps manage the images dir.

TITLE="IOS-XE Firmware Image Manager"
BACKTITLE="Meraki Migration Toolkit — Firmware Images"

FIRMWARE_DIR="${FIRMWARE_DIR:-/var/lib/tftpboot/images}"        # Same default as discovery_prompt.sh
COCKPIT_UPLOAD_DIR="${COCKPIT_UPLOAD_DIR:-/root/IOS-XE_images}" # Cockpit opens here (symlink to FIRMWARE_DIR)
DEBUG_LOG="${DEBUG_LOG:-/tmp/cmds_fw_manager.log}"

log() { [ "${DEBUG:-0}" = "1" ] && printf '[%s] %s\n' "$(date -u '+%F %T')" "$*" >>"$DEBUG_LOG"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }

need dialog
need find
need python3

trim() { printf '%s' "$1" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# ----- Byte formatting + version extraction -----
hbytes() {
  awk 'function hb(b){
    if(b<1024)printf "%d B",b;
    else if(b<1048576)printf "%.1f KB",b/1024;
    else if(b<1073741824)printf "%.1f MB",b/1048576;
    else printf "%.2f GB",b/1073741824
  } {hb($1)}' <<EOF
${1:-0}
EOF
}

version_from_name() {
  b="$(basename -- "$1" 2>/dev/null || printf '%s' "$1")"
  v="$(printf '%s\n' "$b" | sed -nE 's/.*iosxe\.([0-9]+(\.[0-9]+){1,4}).*/\1/p' | head -n1)"
  [ -n "$v" ] || v="$(printf '%s\n' "$b" | sed -nE 's/.*[^0-9]([0-9]{1,2}(\.[0-9]+){1,3}).*/\1/p' | head -n1)"
  printf '%s\n' "${v:-0}"
}

# ----- Cockpit upload dir + OSC-8 clickable link logic -----
HOST_FQDN="$(hostname -f 2>/dev/null || hostname)"
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

ensure_cockpit_upload_dir() {
  if [ ! -e "$COCKPIT_UPLOAD_DIR" ]; then
    ln -s "$FIRMWARE_DIR" "$COCKPIT_UPLOAD_DIR" 2>/dev/null || mkdir -p "$COCKPIT_UPLOAD_DIR"
  fi
}
ensure_cockpit_upload_dir

dlg() {
  _tmp="$(mktemp)"
  dialog "$@" 2>"$_tmp"
  _rc=$?
  DOUT=""
  [ -s "$_tmp" ] && DOUT="$(cat "$_tmp")"
  rm -f "$_tmp"
  return $_rc
}

osc8_link() {
  url="$1"
  txt="${2:-$1}"
  printf '\033]8;;%s\033\\%s\033]8;;\033\\\n' "$url" "$txt"
}

print_cockpit_link_and_wait() {
  HOST_SHOW="${HOST_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
  ENC_PATH="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$COCKPIT_UPLOAD_DIR")"
  URL_B="https://${HOST_SHOW}:9090/=${HOST_SHOW}/files#/?path=${ENC_PATH}"

  clear
  echo "=== Upload IOS-XE firmware via Cockpit ==="
  echo
  echo "  URL:"
  echo "    $URL_B"
  echo
  echo "Clickable (if your terminal supports it):"
  osc8_link "$URL_B" "Open Cockpit Files at ${COCKPIT_UPLOAD_DIR}"
  echo
  echo "Upload directory in Cockpit:"
  echo "  $COCKPIT_UPLOAD_DIR"
  [ -L "$COCKPIT_UPLOAD_DIR" ] && echo "  (symlink to: $FIRMWARE_DIR)"
  echo
  printf "Press Enter when you are done uploading or cleaning up images... "
  IFS= read -r _junk
  stty sane 2>/dev/null || true
}

# ----- Firmware listing helpers -----
list_files() {
  find "$FIRMWARE_DIR" -maxdepth 1 -type f -regextype posix-extended \
    -iregex '.*\.(bin|tar|pkg|cop|spk|img)$' -printf '%f|%s\n' 2>/dev/null
}

family_for_name() {
  nm_lc="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$nm_lc" in
    cat9k_iosxe*\.bin)      echo "universal" ;;
    cat9k_lite_iosxe*\.bin) echo "lite" ;;
    *)                      echo "other" ;;
  esac
}

build_summary_text() {
  tmp_all="$1"

  U_TMP="$(mktemp)"
  L_TMP="$(mktemp)"
  O_TMP="$(mktemp)"

  while IFS='|' read -r nm sz; do
    [ -n "$nm" ] || continue
    fam="$(family_for_name "$nm")"
    ver="$(version_from_name "$nm")"
    hsz="$(hbytes "$sz")"
    line="  - ${nm}  [${hsz}${ver:+, v${ver}}]"
    case "$fam" in
      universal) echo "$line" >>"$U_TMP" ;;
      lite)      echo "$line" >>"$L_TMP" ;;
      other)     echo "$line" >>"$O_TMP" ;;
    esac
  done <"$tmp_all"

  {
    echo "Firmware directory:"
    echo "  $FIRMWARE_DIR"
    echo
    if [ -s "$U_TMP" ]; then
      echo "Cat9k (universal) images:"
      sort "$U_TMP"
      echo
    fi
    if [ -s "$L_TMP" ]; then
      echo "Cat9k-Lite (9200) images:"
      sort "$L_TMP"
      echo
    fi
    if [ -s "$O_TMP" ]; then
      echo "Other images:"
      sort "$O_TMP"
      echo
    fi
    if [ ! -s "$U_TMP" ] && [ ! -s "$L_TMP" ] && [ ! -s "$O_TMP" ]; then
      echo "No firmware images found."
    fi
  } >"$SUMMARY_OUT"

  rm -f "$U_TMP" "$L_TMP" "$O_TMP"
}

# ----- Terminal sizing for dialog -----
TERM_LINES="$(tput lines 2>/dev/null)"; [ -z "$TERM_LINES" ] && TERM_LINES=40
TERM_COLS="$(tput cols 2>/dev/null)";  [ -z "$TERM_COLS" ] && TERM_COLS=120

BOX_W=$((TERM_COLS - 4)); [ "$BOX_W" -lt 80 ] && BOX_W=80; [ "$BOX_W" -gt 200 ] && BOX_W=200

# Overall generic box height (not strictly needed, but kept for consistency)
BOX_H=$((TERM_LINES - 4)); [ "$BOX_H" -lt 10 ] && BOX_H=10

# Textbox height for the firmware list — make it smaller than full screen
TEXTBOX_H=$((TERM_LINES - 10))
[ "$TEXTBOX_H" -lt 12 ] && TEXTBOX_H=12      # minimum readable height
[ "$TEXTBOX_H" -gt "$BOX_H" ] && TEXTBOX_H="$BOX_H"

W_DEF="$BOX_W"

# ----- Main loop -----
while :; do
  CH=$(dialog --clear --backtitle "$BACKTITLE" --title "$TITLE" \
        --menu "Manage IOS-XE firmware images.\n\nFirmware directory:\n  $FIRMWARE_DIR\n\nCockpit upload path:\n  $COCKPIT_UPLOAD_DIR" \
        16 "$W_DEF" 6 \
        1 "Show Cockpit upload URL / instructions" \
        2 "Rescan + show firmware images (categorized)" \
        0 "Exit" \
        3>&1 1>&2 2>&3) || { clear; exit 0; }

  case "$CH" in
    1)
      print_cockpit_link_and_wait
      ;;

    2)
      mkdir -p "$FIRMWARE_DIR"
      tmp_all="$(mktemp)"
      list_files >"$tmp_all"
      if [ ! -s "$tmp_all" ]; then
        rm -f "$tmp_all"
        dlg --clear --backtitle "$BACKTITLE" --title "No Images Found" \
            --msgbox "No firmware images were found in:\n  $FIRMWARE_DIR\n\nUse Cockpit to upload images, then rescan." \
            10 "$W_DEF"
        continue
      fi

      SUMMARY_OUT="$(mktemp)"
      build_summary_text "$tmp_all"
      rm -f "$tmp_all"

      dialog --clear --backtitle "$BACKTITLE" --title "Firmware Images" \
             --textbox "$SUMMARY_OUT" "$TEXTBOX_H" "$BOX_W"
      rm -f "$SUMMARY_OUT"
      ;;

    0)
      clear
      exit 0
      ;;
  esac
done