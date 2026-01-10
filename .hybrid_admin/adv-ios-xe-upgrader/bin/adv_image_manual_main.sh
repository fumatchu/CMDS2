#!/usr/bin/env bash

set -e

BASE_DIR="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 && pwd -P)"

BACKTITLE="Advanced IOS-XE Image Deployment Module"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1"
    exit 1
  }
}

need dialog

intro_text="Advanced IOS-XE Image Deployment Module

This is an advanced deployment workflow that allows you to install
ANY version of IOS-XE onto supported devices.

⚠ IMPORTANT ⚠

This module does NOT enforce guardrails.

You are fully responsible for:
  • The IOS-XE version you select
  • The target hardware you deploy it to
  • Compatibility with Meraki interoperation requirements

This tool is intended ONLY for users who understand
Cisco IOS-XE, Catalyst platforms, and Meraki integration behavior.

If you are unsure — STOP now.

Do you want to continue?"

dialog \
  --no-shadow \
  --backtitle "$BACKTITLE" \
  --title "⚠ Warning" \
  --yesno "$intro_text" 20 80

if [[ $? -ne 0 ]]; then
  clear
  exit 0
fi

run_step() {
  local title="$1"
  local script="$2"

  dialog \
    --no-shadow \
    --backtitle "$BACKTITLE" \
    --title "$title" \
    --infobox "Starting..." 5 50

  sleep 1

  clear

  if [[ ! -x "$script" ]]; then
    dialog \
      --no-shadow \
      --backtitle "$BACKTITLE" \
      --title "Error" \
      --msgbox "Missing or not executable:\n\n$script" 8 60
    exit 1
  fi

  "$script"
}

run_step "Setup Wizard"       "$BASE_DIR/setupwizard.sh"
run_step "Device Discovery"  "$BASE_DIR/discoverswitches.sh"
run_step "Image Deployment"  "$BASE_DIR/image_upgrade.sh"

dialog \
  --no-shadow \
  --backtitle "$BACKTITLE" \
  --title "Complete" \
  --msgbox "All stages completed." 6 40

clear