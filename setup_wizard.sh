#!/bin/bash

# ========== Constants ========== 
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
RESET="\033[0m"

IOS_VERSIONS_FILE="$(dirname "$0")/ios_versions.txt"
NETMIKO_SCRIPT="$(dirname "$0")/../scripts/netmiko_check.py"
NETMIKO_UPGRADE_SCRIPT="$(dirname "$0")/../scripts/netmiko_upgrade.py"
NETMIKO_FIX_SCRIPT="$(dirname "$0")/../scripts/netmiko_remediate.py"
LOG_FILE="$(dirname "$0")/../logs/wizard.log"
SCAN_RESULTS="/tmp/scan_results.txt"
CSV_REPORT="$(dirname "$0")/../results.csv"

mkdir -p "$(dirname "$LOG_FILE")"
echo "IP,IOS Version,Upgraded,DNS OK,NTP OK,AAA OK,Remediated" > "$CSV_REPORT"

# Summary counters
count_total=0
count_upgraded=0
count_remediated=0
count_failed=0

log() {
  echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

prompt_credentials() {
  echo -e "${CYAN}==> Enter administrator and SCP credentials ${RESET}"
  read -p "Username: " USER
  read -s -p "Password: " PASS
  echo

  read -p "SCP Server IP/Hostname: " SCP_SERVER
  read -p "SCP Username: " SCP_USER
  read -s -p "SCP Password: " SCP_PASS
  echo
  read -p "IOS File Path on SCP Server (e.g., /var/ftp/ios.bin): " IOS_FILE

  read -p "Expected DNS Server IP (for validation): " EXPECTED_DNS
  read -p "Expected NTP Server IP (for validation): " EXPECTED_NTP
}

scan_network() {
  local network_range="$1"

  echo -e "${CYAN}==> Scanning network $network_range...${RESET}"
  nmap -sn "$network_range" -oG - | awk '/Up$/{print $2}' > "$SCAN_RESULTS"

  echo -e "${GREEN}[INFO]${RESET} Scan complete. Devices found:"
  cat "$SCAN_RESULTS"
}

check_ios_version() {
  local ip="$1"
  ((count_total++))
  echo -e "${CYAN}==> Validating system on $ip...${RESET}"
  json=$(python3 "$NETMIKO_SCRIPT" "$ip" "$USER" "$PASS")

  if [[ $? -ne 0 ]]; then
    log "${RED}[ERROR]${RESET} Failed to retrieve data from $ip."
    echo "$json"
    ((count_failed++))
    echo "$ip,ERROR,N/A,N/A,N/A,N/A,N/A" >> "$CSV_REPORT"
    return
  fi

  ios_version=$(echo "$json" | jq -r '.ios_version')
  dns_ok=$(echo "$json" | jq -r '.dns_configured')
  ntp_ok=$(echo "$json" | jq -r '.ntp_synced')
  aaa_ok=$(echo "$json" | jq -r '.aaa_enabled')

  target_version=$(head -n 1 "$IOS_VERSIONS_FILE")
  upgraded="no"

  if [[ "$ios_version" == "$target_version" ]]; then
    log "${GREEN}[INFO]${RESET} $ip is running target IOS version: $ios_version"
  else
    log "${YELLOW}[WARN]${RESET} $ip is running outdated IOS version: $ios_version"
    upgrade_ios "$ip" "$target_version"
    ((count_upgraded++))
    upgraded="yes"
  fi

  remediated=false
  if [[ "$dns_ok" != "true" ]]; then
    log "${YELLOW}[WARN]${RESET} $ip is missing DNS config. Attempting remediation..."
    remediate "$ip" dns
    remediated=true
    dns_ok="fixed"
  fi

  if [[ "$ntp_ok" != "true" ]]; then
    log "${YELLOW}[WARN]${RESET} $ip is not NTP synchronized. Attempting remediation..."
    remediate "$ip" ntp
    remediated=true
    ntp_ok="fixed"
  fi

  if [[ "$aaa_ok" != "true" ]]; then
    log "${YELLOW}[WARN]${RESET} $ip does not have AAA enabled. Attempting remediation..."
    remediate "$ip" aaa
    remediated=true
    aaa_ok="fixed"
  fi

  [[ "$remediated" == true ]] && ((count_remediated++))

  echo "$ip,$ios_version,$upgraded,$dns_ok,$ntp_ok,$aaa_ok,$remediated" >> "$CSV_REPORT"
}

upgrade_ios() {
  local ip="$1"
  local target_version="$2"
  echo -e "${CYAN}==> Initiating IOS upgrade on $ip...${RESET}"
  python3 "$NETMIKO_UPGRADE_SCRIPT" \
    "$ip" "$USER" "$PASS" \
    "$SCP_SERVER" "$SCP_USER" "$SCP_PASS" "$IOS_FILE"

  if [[ $? -eq 0 ]]; then
    log "${GREEN}[SUCCESS]${RESET} IOS upgrade command sent to $ip"
  else
    log "${RED}[ERROR]${RESET} Failed to initiate upgrade on $ip"
  fi
}

remediate() {
  local ip="$1"
  local what="$2"
  echo -e "${CYAN}==> Remediating $what on $ip...${RESET}"
  result=$(python3 "$NETMIKO_FIX_SCRIPT" "$ip" "$USER" "$PASS" "$what" "$EXPECTED_DNS" "$EXPECTED_NTP")
  echo "$result"
  log "[REMEDIATION] $ip → $what result: $result"
}

# Main
prompt_credentials
scan_network "192.168.1.0/24"
while read -r ip; do
  check_ios_version "$ip"
done < "$SCAN_RESULTS"

echo -e "\n${CYAN}========== SUMMARY ==========${RESET}" | tee -a "$LOG_FILE"
echo -e "${GREEN}[INFO]${RESET} Total switches scanned: $count_total" | tee -a "$LOG_FILE"
echo -e "${YELLOW}[INFO]${RESET} IOS upgrades performed: $count_upgraded" | tee -a "$LOG_FILE"
echo -e "${BLUE}[INFO]${RESET} Switches remediated: $count_remediated" | tee -a "$LOG_FILE"
echo -e "${RED}[FAIL]${RESET} Failed connections: $count_failed" | tee -a "$LOG_FILE"
echo -e "${CYAN}==> Results saved to $CSV_REPORT${RESET}" | tee -a "$LOG_FILE"
