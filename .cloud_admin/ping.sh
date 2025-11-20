#!/usr/bin/env bash
# Simple switch reachability check using dialog + colors
# Reads IPs from upgrade_plan.json (created by discoverswitches.sh)

set -Eeuo pipefail

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }

need dialog
need jq
need ping

BACKTITLE="CMDS-Deployment Server"
TITLE="Switch Connectivity Monitor"

# Path to upgrade plan JSON (override with UPGRADE_PLAN env if needed)
UPGRADE_PLAN="${UPGRADE_PLAN:-/root/.hybrid_admin/upgrade_plan.json}"

if [[ ! -s "$UPGRADE_PLAN" ]]; then
  dialog --no-shadow --backtitle "$BACKTITLE" --title "$TITLE" \
         --msgbox "No upgrade plan found or file is empty:\n\n$UPGRADE_PLAN" 9 70
  exit 1
fi

# Get unique IP list from upgrade_plan.json
mapfile -t IPS < <(jq -r '.[].ip' "$UPGRADE_PLAN" 2>/dev/null | awk 'NF' | sort -u)

if (( ${#IPS[@]} == 0 )); then
  dialog --no-shadow --backtitle "$BACKTITLE" --title "$TITLE" \
         --msgbox "No IP addresses found in:\n\n$UPGRADE_PLAN" 9 70
  exit 0
fi

# Build colored status output for dialog --colors
OUT="Monitoring connectivity to switches (Catalyst Migration)\n\n"

for IP in "${IPS[@]}"; do
  if ping -c 1 -W 1 "$IP" >/dev/null 2>&1; then
    OUT+="$IP is \Z2UP\Zn\n"      # green
  else
    OUT+="$IP is \Z1DOWN\Zn\n"    # red
  fi
done

dialog --no-shadow --colors \
       --backtitle "$BACKTITLE" \
       --title "$TITLE" \
       --msgbox "$OUT" 0 0
