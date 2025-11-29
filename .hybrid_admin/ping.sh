#!/usr/bin/env bash
# Continuous switch reachability monitor (auto-refresh + Q to quit + counter)
# Uses dialog --infobox and refreshes every 5 seconds

# Be a bit less strict so the loop doesn't die on a non-zero command
set -Euo pipefail

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

COUNTER=0

while true; do
  ((COUNTER++))

  OUT="Monitoring connectivity to switches (Catalyst Migration)\n"
  OUT+="Updated: $(date '+%Y-%m-%d %H:%M:%S')\n"
  OUT+="Refresh Count: $COUNTER\n"
  OUT+="Press \Z1Q\Zn to quit.\n\n"

  # Don't let a single bad ping kill the loop
  for IP in "${IPS[@]}"; do
    if ping -c 1 -W 1 "$IP" >/dev/null 2>&1; then
      OUT+="$IP  \Z2UP\Zn\n"      # green
    else
      OUT+="$IP  \Z1DOWN\Zn\n"    # red
    fi
  done

  # dialog may return non-zero if user resizes/ESC/etc — ignore that
  dialog --no-shadow --colors \
         --backtitle "$BACKTITLE" \
         --title "$TITLE" \
         --infobox "$OUT" 0 0 || true

  # Wait up to 5 seconds for a keypress from the TTY; Q/q exits
  if read -t 5 -n1 key < /dev/tty 2>/dev/null; then
    if [[ "$key" == "q" || "$key" == "Q" ]]; then
      clear
      exit 0
    fi
  fi
done