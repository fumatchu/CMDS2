#!/bin/bash
#Bootstrap to GIT REPO

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"

USER=$(whoami)

clear
echo -e "${CYAN}CMDS2${TEXTRESET} ${YELLOW}Bootstrap${TEXTRESET}"

# Checking for user permissions
if [ "$USER" = "root" ]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Exiting..."
  exit 1
fi

# =========================
# Checking for version information (Rocky 10.1 or newer)
# =========================
OSVER_RAW=""
if [[ -f /etc/os-release ]]; then
  # VERSION_ID is typically like: "10.1"
  OSVER_RAW=$(grep -oP '(?<=^VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null)
elif [[ -f /etc/redhat-release ]]; then
  # Fallback: try to capture something like 10.1, else just 10
  OSVER_RAW=$(grep -oE '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
fi

# Sanity check
if [[ -z "$OSVER_RAW" ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to detect a valid Rocky Linux version."
  echo "Exiting..."
  exit 1
fi

# Split into major/minor (minor defaults to 0 if absent)
OSVER_MAJOR=$(echo "$OSVER_RAW" | awk -F. '{print $1}')
OSVER_MINOR=$(echo "$OSVER_RAW" | awk -F. '{print ($2==""?0:$2)}')

# Validate numeric
if ! [[ "$OSVER_MAJOR" =~ ^[0-9]+$ && "$OSVER_MINOR" =~ ^[0-9]+$ ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to parse Rocky Linux version from: ${OSVER_RAW}"
  echo "Exiting..."
  exit 1
fi

# Require >= 10.1
if (( OSVER_MAJOR > 10 || (OSVER_MAJOR == 10 && OSVER_MINOR >= 1) )); then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky ${OSVER_MAJOR}.${OSVER_MINOR} or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, this installer only supports Rocky 10.1 or newer."
  echo -e "Detected: Rocky ${OSVER_MAJOR}.${OSVER_MINOR} — Please upgrade to ${GREEN}Rocky 10.1${TEXTRESET} or later."
  echo "Exiting..."
  exit 1
fi

# =========================
# Checking root filesystem size (minimum 8GB required)
# =========================

# Get available space on / in GB (integer)
ROOT_FREE_GB=$(df -BG / | awk 'NR==2 {gsub(/G/, "", $4); print $4}')

# Sanity check
if ! [[ "$ROOT_FREE_GB" =~ ^[0-9]+$ ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine available disk space on root filesystem."
  echo "Exiting..."
  exit 1
fi

# Enforce minimum space
if (( ROOT_FREE_GB >= 8 )); then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Root filesystem has ${ROOT_FREE_GB}GB available (minimum 8GB required)."
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Insufficient disk space on root filesystem."
  echo -e "Detected: ${ROOT_FREE_GB}GB available — ${GREEN}8GB or more${TEXTRESET} is required."
  echo "Exiting..."
  exit 1
fi

echo -e "${CYAN}==>Retrieving requirements for the installer...${TEXTRESET}"

# Function to show an animated spinner
spinner() {
  local pid=$1
  local delay=0.1
  local spinstr='|/-\'

  while ps -p "$pid" > /dev/null 2>&1; do
    for i in $(seq 0 3); do
      printf "\r[${YELLOW}INFO${TEXTRESET}] Installing... ${spinstr:$i:1}"
      sleep $delay
    done
  done
  printf "\r[${GREEN}SUCCESS${TEXTRESET}] Installation complete!  \n"
}

# Run dnf in the background
dnf -y install wget git ipcalc dialog >/dev/null 2>&1 &

# Get the PID of the last background process
dnf_pid=$!

# Start the spinner while waiting for dnf to complete
spinner "$dnf_pid"

echo -e "${CYAN}==>Retrieving files from Github...${TEXTRESET}"
sleep 1

# Clone CMDS
rm -rf /root/CMDS2Installer
mkdir -p /root/CMDS2Installer
git clone https://github.com/fumatchu/CMDS2.git /root/CMDS2Installer

chmod 700 /root/CMDS2Installer/*

echo -e "[${YELLOW}INFO${TEXTRESET}] Removing Git"
dnf -y remove git >/dev/null 2>&1

clear
echo -e "${CYAN}CMDS${RESET} ${YELLOW}Builder${TEXTRESET}"
sleep 2
echo " "

items=(1 "Install CMDS Server")

while choice=$(dialog --title "$TITLE" \
  --backtitle "Server Installer" \
  --menu "Please select the install type" 15 65 3 "${items[@]}" \
  2>&1 >/dev/tty); do
  case $choice in
    1) /root/CMDS2Installer/CMDS2Install.sh ;;
  esac
done

clear