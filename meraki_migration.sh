#!/usr/bin/env bash
# Main Dialog Menu for CMDS-Deployment Server

set -Eeuo pipefail

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog

BACKTITLE="CMDS-Deployment Server"
TITLE="Main Menu"
HYBRID_MENU="/root/.hybrid_admin/menu.sh"

# Colors for bottom status/help line (dialog --colors)
HELP_COLOR_PREFIX="${HELP_COLOR_PREFIX:-\Zb\Z3}"  # bold yellow
HELP_COLOR_RESET="${HELP_COLOR_RESET:-\Zn}"

cleanup(){ clear; }
trap cleanup EXIT

while true; do
  CHOICE=$(
    dialog --no-shadow --colors --item-help \
      --backtitle "$BACKTITLE" \
      --title "$TITLE" \
      --menu "Select an option:" 18 110 8 \
        1 "Catalyst to Meraki (hybrid) (Device Local)" \
          "${HELP_COLOR_PREFIX}Device-local workflow that uses Cloud CLI (R/W) to migrate Catalyst to Meraki while retaining IOS-XE; opens the hybrid tools menu.${HELP_COLOR_RESET}" \
        0 "Exit" \
          "${HELP_COLOR_PREFIX}Quit the deployment server menu.${HELP_COLOR_RESET}" \
      3>&1 1>&2 2>&3
  )
  rc=$?

  # ESC or Cancel -> exit
  if [[ $rc -ne 0 ]]; then clear; exit 0; fi

  case "$CHOICE" in
    1)
      if [[ -x "$HYBRID_MENU" ]]; then
        clear
        bash "$HYBRID_MENU" || {
          dialog --no-shadow --backtitle "$BACKTITLE" --title "Hybrid Menu" \
                 --msgbox "The script returned a non-zero status.\n\nPath: $HYBRID_MENU" 9 70
        }
      elif [[ -f "$HYBRID_MENU" ]]; then
        clear
        bash "$HYBRID_MENU" || true
      else
        dialog --no-shadow --backtitle "$BACKTITLE" --title "Not Found" \
               --msgbox "Cannot find:\n$HYBRID_MENU" 7 60
      fi
      ;;
    0)
      clear; exit 0 ;;
  esac
done
