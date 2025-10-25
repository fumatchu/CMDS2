#!/usr/bin/env bash
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"
clear
echo -e "${CYAN}CMDS${TEXTRESET} Builder ${YELLOW}Installation${TEXTRESET}"

# =========================
# Checking for root privileges
# =========================
USER=$(whoami 2>/dev/null || echo "")
if [[ $EUID -eq 0 || "$USER" == "root" ]]; then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Running as root user"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] This program must be run as root."
  echo "Please run using: ${GREEN}sudo $0${TEXTRESET}"
  echo "Exiting..."
  exit 1
fi

# =========================
# Checking for version information (Rocky 9 or newer)
# =========================
if [[ -f /etc/os-release ]]; then
  # Extract only the numeric part of VERSION_ID (e.g., "9", "10", "11")
  OSVER=$(grep -oP '(?<=VERSION_ID=")[0-9]+' /etc/os-release 2>/dev/null)
elif [[ -f /etc/redhat-release ]]; then
  OSVER=$(grep -oE '[0-9]+' /etc/redhat-release | head -1)
else
  OSVER=0
fi

# Sanity check
if ! [[ "$OSVER" =~ ^[0-9]+$ ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to detect a valid Rocky Linux version."
  echo "Exiting..."
  exit 1
fi

# Compare numerically (works for 9, 10, 11, etc.)
if (( OSVER >= 9 )); then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Detected compatible OS version: Rocky ${OSVER}.x or greater"
  sleep 2
else
  echo -e "[${RED}ERROR${TEXTRESET}] Sorry, this installer only supports Rocky 9.x or newer."
  echo -e "Please upgrade to ${GREEN}Rocky 9.x${TEXTRESET} or later."
  echo "Exiting..."
  exit 1
fi

# ========= REMOVE BRACKETED PASTING =========
sed -i '8i set enable-bracketed-paste off' /etc/inputrc


# ========= INSERT INSTALLER INTO .bash_profile =========
PROFILE="/root/.bash_profile"
BACKUP="/root/.bash_profile.bak.$(date +%Y%m%d%H%M%S)"
INSTALLER="/root/CMDS2Installer/CMDS2Install.sh"

cat << 'EOF' >> "$PROFILE"

## Run CMDS installer on every interactive login ##
if [[ $- == *i* ]]; then
  /root/CMDS2Installer/CMDS2Install.sh
fi
EOF
if [[ -f "$INSTALLER" ]]; then
  chmod +x "$INSTALLER"
else
  echo "WARNING: Installer not found at $INSTALLER"
fi

# ========= VALIDATION HELPERS =========
validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }
validate_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
validate_fqdn() { [[ "$1" =~ ^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$ ]]; }

is_host_ip() {
  local cidr="$1"
  local ip_part="${cidr%/*}"
  local mask="${cidr#*/}"

  IFS='.' read -r o1 o2 o3 o4 <<< "$ip_part"
  ip_dec=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))

  netmask=$(( 0xFFFFFFFF << (32 - mask) & 0xFFFFFFFF ))
  network=$(( ip_dec & netmask ))
  broadcast=$(( network | ~netmask & 0xFFFFFFFF ))

  [[ "$ip_dec" -eq "$network" || "$ip_dec" -eq "$broadcast" ]] && return 1 || return 0
}

check_hostname_in_domain() {
  local fqdn="$1"
  local hostname="${fqdn%%.*}"
  local domain="${fqdn#*.}"
  [[ ! "$domain" =~ (^|\.)"$hostname"(\.|$) ]]
}
isValidIP() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r o1 o2 o3 o4 <<< "$1"
  (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) || return 1
  return 0
}

isValidNetmask() {
  local valid=(
    255.255.255.0 255.255.0.0 255.0.0.0
    255.255.254.0 255.255.252.0 255.255.248.0 255.255.240.0
    255.255.224.0 255.255.192.0 255.255.128.0
  )
  [[ " ${valid[*]} " =~ " $1 " ]]
}

isIPInRange() {
  local ip=$1
  local ipnum=$(ipToNumber "$ip")
  local netnum=$(ipToNumber "$NETWORK")
  local broadnum=$(ipToNumber "$BROADCAST")
  [[ $ipnum -ge $netnum && $ipnum -le $broadnum ]]
}

# ========= SYSTEM CHECKS =========
check_root_and_os() {
  if [[ "$EUID" -ne 0 ]]; then
    dialog --aspect 9 --title "Permission Denied" --msgbox "This script must be run as root." 7 50
    clear; exit 1
  fi

  if [[ -f /etc/redhat-release ]]; then
    MAJOROS=$(grep -oP '\d+' /etc/redhat-release | head -1)
  else
    dialog --title "OS Check Failed" --msgbox "/etc/redhat-release not found. Cannot detect OS." 7 50
    exit 1
  fi

  if [[ "$MAJOROS" -lt 9 ]]; then
    dialog --title "Unsupported OS" --msgbox "This installer requires Rocky Linux 9.x or later." 7 50
    exit 1
  fi
}

# ========= SELINUX CHECK =========
check_and_enable_selinux() {
  local current_status=$(getenforce)

  if [[ "$current_status" == "Enforcing" ]]; then
    dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Status" --infobox "SELinux is already enabled and enforcing." 6 50
    sleep 4
  else
    dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Disabled" --msgbox "SELinux is not enabled. Enabling SELinux now..." 6 50
    sed -i 's/SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config
    setenforce 1

    if [[ "$(getenforce)" == "Enforcing" ]]; then
      dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Enabled" --msgbox "SELinux has been successfully enabled and is now enforcing." 6 50
    else
      dialog --backtitle "Checking and Enabling SELinux" --title "SELinux Error" --msgbox "Failed to enable SELinux. Please check the configuration manually." 6 50
      exit 1
    fi
  fi
}

# ========= NETWORK DETECTION =========
detect_active_interface() {
  dialog --backtitle "Network Setup" --title "Interface Check" --infobox "Checking active network interface..." 5 50
  sleep 3

  # Attempt 1: Use nmcli to find connected Ethernet
  INTERFACE=$(nmcli -t -f DEVICE,TYPE,STATE device | grep "ethernet:connected" | cut -d: -f1 | head -n1)

  # Attempt 2: Fallback to any interface with an IP if nmcli fails
  if [[ -z "$INTERFACE" ]]; then
    INTERFACE=$(ip -o -4 addr show up | grep -v ' lo ' | awk '{print $2}' | head -n1)
  fi

  # Get the matching connection profile name
  if [[ -n "$INTERFACE" ]]; then
    CONNECTION=$(nmcli -t -f NAME,DEVICE connection show | grep ":$INTERFACE" | cut -d: -f1)
  fi

  # Log to /tmp in case of failure
  echo "DEBUG: INTERFACE=$INTERFACE" >> /tmp/kvm_debug.log
  echo "DEBUG: CONNECTION=$CONNECTION" >> /tmp/kvm_debug.log

  if [[ -z "$INTERFACE" || -z "$CONNECTION" ]]; then
    dialog --clear  --no-ok --backtitle "Network Setup"  --title "Interface Error" --aspect 9 --msgbox "No active network interface with IP found. Check /tmp/kvm_debug.log for d
etails." 5 70
    exit 1
  fi

  export INTERFACE CONNECTION
}

# ========= STATIC IP CONFIG =========
prompt_static_ip_if_dhcp() {
  IP_METHOD=$(nmcli -g ipv4.method connection show "$CONNECTION" | tr -d '' | xargs)

  if [[ "$IP_METHOD" == "manual" ]]; then
  dialog --title "Static IP Detected" --infobox "Interface '$INTERFACE' is already using a static IP" 6 70
  sleep 3
  return
elif [[ "$IP_METHOD" == "auto" ]]; then
    while true; do
      while true; do
        IPADDR=$(dialog --backtitle "Interface Setup" --title "Static IP Address Required" --inputbox "***DHCP DETECTED on '$INTERFACE'***\n\nEnter static IP in CIDR format (e.g., 192.168.1.100/24):" 8 80 3>&1 1>&2 2>&3)
        validate_cidr "$IPADDR" && break || dialog --msgbox "Invalid CIDR format. Try again." 6 40
      done

      while true; do
        GW=$(dialog --backtitle "Interface Setup" --title "Gateway" --inputbox "Enter default gateway:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$GW" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        DNSSERVER=$(dialog --backtitle "Interface Setup" --title "DNS Server" --inputbox "Enter Upstream DNS server IP:" 8 60 3>&1 1>&2 2>&3)
        validate_ip "$DNSSERVER" && break || dialog --msgbox "Invalid IP address. Try again." 6 40
      done

      while true; do
        HOSTNAME=$(dialog --backtitle "Interface Setup" --title "FQDN" --inputbox "Enter FQDN (e.g., host.domain.com):" 8 60 3>&1 1>&2 2>&3)
        if validate_fqdn "$HOSTNAME" && check_hostname_in_domain "$HOSTNAME"; then break
        else dialog --msgbox "Invalid FQDN or hostname repeated in domain. Try again." 7 60
        fi
      done

      while true; do
        DNSSEARCH=$(dialog --backtitle "Interface Setup" --title "DNS Search" --inputbox "Enter domain search suffix (e.g., localdomain):" 8 60 3>&1 1>&2 2>&3)
        [[ -n "$DNSSEARCH" ]] && break || dialog --msgbox "Search domain cannot be blank." 6 40
      done

      dialog --backtitle "Interface Setup" --title "Confirm Settings" --yesno "Apply these settings?\n\nInterface: $INTERFACE\nIP: $IPADDR\nGW: $GW\nFQDN: $HOSTNAME\nDNS: $DNSSERVER\nSearch: $DNSSEARCH" 12 60

      if [[ $? -eq 0 ]]; then
        nmcli con mod "$CONNECTION" ipv4.address "$IPADDR"
        nmcli con mod "$CONNECTION" ipv4.gateway "$GW"
        nmcli con mod "$CONNECTION" ipv4.method manual
        nmcli con mod "$CONNECTION" ipv4.dns "$DNSSERVER"
        nmcli con mod "$CONNECTION" ipv4.dns-search "$DNSSEARCH"
        hostnamectl set-hostname "$HOSTNAME"


        dialog --clear --no-shadow --no-ok --backtitle "REBOOT REQUIRED" --title "Reboot Required" --aspect 9 --msgbox "Network stack set. The System will reboot. Reconnect at: ${IPADDR%%/*}" 5 95
        reboot
      fi
    done
  fi
}
# ========= INTERNET CONNECTIVITY CHECK =========
check_internet_connectivity() {
  dialog --backtitle "Checking Internet Connectivity" --title "Network Test" --infobox "Checking internet connectivity..." 5 50
  sleep 2

  local dns_test="FAILED"
  local ip_test="FAILED"

  if ping -c 1 -W 2 google.com &>/dev/null; then
    dns_test="SUCCESS"
  fi

  if ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    ip_test="SUCCESS"
  fi

  dialog --backtitle "Checking Internet Connectivity" --title "Connectivity Test Results" --infobox "DNS Resolution: $dns_test
Direct IP (8.8.8.8): $ip_test " 7 50
  sleep 4

  if [[ "$dns_test" == "FAILED" || "$ip_test" == "FAILED" ]]; then
    dialog --backtitle "Checking Internet Connectivity" --title "Network Warning" --yesno "Internet connectivity issues detected. Do you want to continue?" 7 50
    if [[ $? -ne 0 ]]; then
      exit 1
    fi
  fi
}

# ========= HOSTNAME VALIDATION =========
validate_and_set_hostname() {
  local current_hostname
  current_hostname=$(hostname)

  if [[ "$current_hostname" == "localhost.localdomain" ]]; then
    while true; do
      NEW_HOSTNAME=$(dialog --backtitle "Configure Hostname" --title "Hostname Configuration" --inputbox \
        "Current hostname is '$current_hostname'. Please enter a new FQDN (e.g., server.example.com):" \
        8 60 3>&1 1>&2 2>&3)

      if validate_fqdn "$NEW_HOSTNAME" && check_hostname_in_domain "$NEW_HOSTNAME"; then
        hostnamectl set-hostname "$NEW_HOSTNAME"
        dialog --backtitle "Configure Hostname" --title "Hostname Set" --msgbox "Hostname updated to: $NEW_HOSTNAME" 6 50
        break
      else
        dialog --backtitle "Configure Hostname" --title "Invalid Hostname" --msgbox "Invalid hostname. Please try again." 6 50
      fi
    done
  else
    # Show a temporary info box with current hostname, no OK button
    dialog --backtitle "Configure Hostname" --title "Hostname Check" --infobox \
      "Hostname set to: $current_hostname" 6 60
    sleep 3
  fi
}

# ========= SHOW CHECKLIST TO USER =========

show_server_checklist() {
  dialog --backtitle "Welcome to the CMDS Installer" --title "CMDS Server Installation Checklist" --msgbox "\
*********************************************

This will Install the Server and all the requirements

Checklist:
Before the Installer starts, please make sure you have the following information:
  1. An NTP Subnet for your clients. This server will provide synchronized time
  2. The beginning and ending lease range for DHCP (optional)
  3. The client default gateway IP Address for the DHCP Scope (optional)
  4. A Friendly name as a description to the DHCP scope created (optional)

*********************************************" 20 100
}
# ========= CONFIGURE CHRONY =========
declare -a ADDR
LOG_NTP="/tmp/chrony_ntp_configure.log"
touch "$LOG_NTP"

log_ntp() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_NTP"
}

validate_cidr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]
}

prompt_ntp_servers() {
    while true; do
        NTP_SERVERS=$(dialog --title "Chrony NTP Configuration" \
            --backtitle "Configure NTP" --inputbox "Enter up to 3 comma-separated NTP server IPs or FQDNs:" 8 60 \
            3>&1 1>&2 2>&3)
        exit_status=$?
        if [ $exit_status -eq 1 ] || [ $exit_status -eq 255 ]; then
            return 1
        fi

        if [[ -n "$NTP_SERVERS" ]]; then
            IFS=',' read -ra ADDR <<< "$NTP_SERVERS"
            if (( ${#ADDR[@]} > 3 )); then
                dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "You may only enter up to 3 servers." 6 50
                continue
            fi
            return 0
        else
            dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "The input cannot be blank. Please try again." 6 50
        fi
    done
}

prompt_allow_networks() {
    while true; do
        ALLOW_NET=$(dialog --title "Allow NTP Access" \
            --backtitle "Configure NTP" --inputbox "Enter the CIDR range to allow NTP access (e.g., 192.168.1.0/24):" 8 80 \
            3>&1 1>&2 2>&3)
        exit_status=$?
        if [ $exit_status -ne 0 ]; then
            return 1
        fi

        if validate_cidr "$ALLOW_NET"; then
            return 0
        else
            dialog --backtitle "Configure NTP" --msgbox "Invalid CIDR format. Please try again." 6 40
        fi
    done
}

update_chrony_config() {
    cp /etc/chrony.conf /etc/chrony.conf.bak
    sed -i '/^\(server\|pool\|allow\)[[:space:]]/d' /etc/chrony.conf

    for srv in "${ADDR[@]}"; do
        echo "server ${srv} iburst" >> /etc/chrony.conf
        log_ntp "Added server ${srv} to chrony.conf"
    done

    if [[ -n "$ALLOW_NET" ]]; then
        echo "allow $ALLOW_NET" >> /etc/chrony.conf
        log_ntp "Added allow $ALLOW_NET to chrony.conf"
    fi

    systemctl restart chronyd
    sleep 2
}

validate_time_sync() {
    local attempt=1
    local success=0

    while (( attempt <= 3 )); do
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Validating time sync... Attempt $attempt/3" 4 50
        sleep 5

        TRACKING=$(chronyc tracking 2>&1)
        echo "$TRACKING" >> "$LOG_NTP"

        if echo "$TRACKING" | grep -q "Leap status[[:space:]]*:[[:space:]]*Normal"; then
            success=1
            break
        fi
        ((attempt++))
    done

    if [[ "$success" -eq 1 ]]; then
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Time synchronized successfully:\n\n$TRACKING" 15 100
        sleep 3
    else
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --yesno "Time sync failed after 3 attempts.\nDo you want to proceed anyway?" 8 100
        [[ $? -eq 0 ]] || return 1
    fi
    return 0
}

# ========= SYSTEM UPDATE & PACKAGE INSTALL =========
# ========= SYSTEM UPDATE & PACKAGE INSTALL (per-package with gauge text) =========
update_and_install_packages() {
  local BACK="Base Package Update"
  local LOGDIR="/var/log/installer"
  local REPLOG="$LOGDIR/repo-setup.log"
  local UPDLOG="$LOGDIR/system-upgrade.log"
  local REQLOG="$LOGDIR/required-packages.log"
  mkdir -p "$LOGDIR"

  export DNF_COLOR=0
  export LC_ALL=C LANG=C

  # ------------------ Enable/refresh repos (quiet) with gauge -------------------
  : >"$REPLOG"
  dialog --backtitle "$BACK" --title "Repository Setup" --gauge "Enabling EPEL and CRB repositories..." 10 70 0 < <(
    (
      {
        dnf -y -q install epel-release                 --setopt=install_weak_deps=False   --color=never >>"$REPLOG" 2>&1
        dnf -y -q install dnf-plugins-core             --setopt=install_weak_deps=False   --color=never >>"$REPLOG" 2>&1 || true
        dnf -q config-manager --set-enabled crb                                           --color=never >>"$REPLOG" 2>&1 || true
        dnf -y -q makecache --refresh                   --setopt=metadata_timer_sync=0     --color=never >>"$REPLOG" 2>&1
      } &
      PID=$!
      PROGRESS=0
      while kill -0 "$PID" 2>/dev/null; do
        echo "$PROGRESS"
        echo "XXX"
        echo -e "Enabling EPEL and CRB...\n\nLog: $REPLOG"
        echo "XXX"
        ((PROGRESS+=5)); ((PROGRESS>=95)) && PROGRESS=5
        sleep 0.4
      done
      wait "$PID"
      echo "100"; echo "XXX"; echo -e "Repositories enabled.\n\nLog: $REPLOG"; echo "XXX"
    )
  )

  # ----------------------- Build list of upgradable packages --------------------
  # Use repoquery for reliable parsing (needs dnf-plugins-core, ensured above)
  mapfile -t PACKAGE_LIST < <(dnf -q repoquery --upgrades --qf '%{name}' 2>/dev/null | sort -u)

  TOTAL_PACKAGES=${#PACKAGE_LIST[@]}
  if [[ "$TOTAL_PACKAGES" -eq 0 ]]; then
    dialog --backtitle "$BACK" --title "System Update" --infobox "No updates available." 6 40
    sleep 2
  else
    : >"$UPDLOG"
    PIPE=$(mktemp -u); mkfifo "$PIPE"
    dialog --backtitle "$BACK" --title "System Update" --gauge "Installing updates..." 10 70 0 < "$PIPE" &
    COUNT=0
    {
      for PACKAGE in "${PACKAGE_LIST[@]}"; do
        ((COUNT++))
        PERCENT=$(( COUNT * 100 / TOTAL_PACKAGES ))
        echo "$PERCENT"
        echo "XXX"
        echo "Updating: $PACKAGE"
        echo "XXX"
        # Per-package upgrade (quiet, no ANSI), log output
        dnf -y -q upgrade --color=never --best --allowerasing "$PACKAGE" >>"$UPDLOG" 2>&1
      done
      echo "100"; echo "XXX"; echo -e "Base packages updated.\n\nLog: $UPDLOG"; echo "XXX"
    } > "$PIPE"
    wait
    rm -f "$PIPE"
  fi

  # ---------------------- Install required packages (per-package) ---------------
  dialog --backtitle "Required Package Install" --title "Package Installation" \
         --infobox "Installing required packages..." 5 60
  sleep 1

  : >"$REQLOG"
  local REQUIRED_PKGS=(
    ntsysv iptraf expect gcc tar nmap openssl-devel make at bc bzip2-devel
    libffi-devel zlib-devel nano rsync sshpass openldap-clients fail2ban tuned
    cockpit tftp-server cockpit-storaged cockpit-files net-tools dmidecode ipcalc
    bind-utils iotop zip yum-utils curl wget git dnf-automatic dnf-plugins-core
    util-linux htop iptraf-ng mc httpd
  )

  local TOTAL_REQ=${#REQUIRED_PKGS[@]}
  local COUNT=0
  PIPE=$(mktemp -u); mkfifo "$PIPE"
  dialog --backtitle "Required Package Install" --title "Installing Required Packages" \
         --gauge "Preparing to install packages..." 10 70 0 < "$PIPE" &
  {
    for PACKAGE in "${REQUIRED_PKGS[@]}"; do
      ((COUNT++))
      PERCENT=$(( COUNT * 100 / TOTAL_REQ ))
      echo "$PERCENT"
      echo "XXX"
      echo "Installing: $PACKAGE"
      echo "XXX"
      dnf -y -q install --color=never --setopt=tsflags=nodocs "$PACKAGE" >>"$REQLOG" 2>&1
    done
    echo "100"; echo "XXX"; echo -e "All required packages processed.\n\nLog: $REQLOG"; echo "XXX"
  } > "$PIPE"
  wait
  rm -f "$PIPE"

  dialog --backtitle "Required Package Install" --title "Installation Complete" \
         --infobox "Required package installation complete.\nSee logs in $LOGDIR" 7 70
  sleep 2
}
#===========DETECT VIRT and INSTALL GUEST=============
# Function to show a dialog infobox
vm_detection() {
show_info() {
    dialog --backtitle "Guest VM Detection and Installation" --title "$1" --infobox "$2" 5 60
    sleep 2
}

# Function to show a progress bar during installation
show_progress() {
    (
        echo "10"; sleep 1
        echo "40"; sleep 1
        echo "70"; sleep 1
        echo "100"
    ) | dialog --backtitle "Guest VM Detection and Installation" --title "$1" --gauge "$2" 7 60 0
}

# Detect virtualization platform
HWKVM=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep KVM | cut -c16-)
HWVMWARE=$(dmidecode | grep -i -e manufacturer -e product -e vendor | grep Manufacturer | grep "VMware, Inc." | cut -c16- | cut -d , -f1)

show_info "Virtualization Check" "Checking for virtualization platform..."

# Install guest agent for KVM
if [ "$HWKVM" = "KVM" ]; then
    show_info "Platform Detected" "KVM platform detected.\nInstalling qemu-guest-agent..."
    show_progress "Installing qemu-guest-agent" "Installing guest tools for KVM..."
    dnf -y install qemu-guest-agent &>/dev/null
fi

# Install guest agent for VMware
if [ "$HWVMWARE" = "VMware" ]; then
    show_info "Platform Detected" "VMware platform detected.\nInstalling open-vm-tools..."
    show_progress "Installing open-vm-tools" "Installing guest tools for VMware..."
    dnf -y install open-vm-tools &>/dev/null
fi
}
#===========OPTIONAL DHCP INSTALL=============
configure_dhcp_server() {
  local DIALOG="${DIALOG_BIN:-dialog}"
  local BACKTITLE="DHCP Server Install"
  local CHOSEN_BACKEND=""

  # ────────────────────────────── UI helpers ──────────────────────────────
  msgbox() { $DIALOG --backtitle "$BACKTITLE" --title "$1" --msgbox "$2" "${3:-8}" "${4:-72}"; }
  infobox(){ $DIALOG --backtitle "$BACKTITLE" --title "$1" --infobox "$2" "${3:-6}" "${4:-60}"; }

  # Require root + Rocky 9+
  require_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root." >&2; return 1; }; }
  require_rocky9plus(){
    . /etc/os-release 2>/dev/null || true
    if [[ "${ID:-}" != "rocky" ]]; then
      msgbox "Unsupported OS" "This installer is limited to Rocky Linux 9+."; return 1
    fi
    local maj="${VERSION_ID%%.*}"
    if [[ -z "$maj" || "$maj" -lt 9 ]]; then
      msgbox "Unsupported Version" "Detected Rocky Linux ${VERSION_ID:-unknown}. This script supports Rocky Linux 9+ only."
      return 1
    fi
    return 0
  }

  # ─────────────────────── detection of installed backends ─────────────────────
  detect_isc_dhcp(){ [[ -f /etc/dhcp/dhcpd.conf ]] || rpm -q dhcp-server >/dev/null 2>&1; }
  detect_kea()     { [[ -f /etc/kea/kea-dhcp4.conf ]] || rpm -q kea >/dev/null 2>&1; }

  # ───────────────────────── repo enable (Rocky 9+) ───────────────────────────
  enable_repos_with_gauge() {
    # Rocky 9+: enable EPEL + CRB, then refresh metadata
    local log="/tmp/repo-setup.$(date +%s).log"
    local status="/tmp/repo-setup-status.$$"
    local msg="/tmp/repo-setup-phase.$$"
    : >"$log"; : >"$msg"
    trap 'rm -f "$status" "$msg"' RETURN

    (
      rc=0
      {
        echo "Installing dnf-plugins-core..." >"$msg"
        dnf -y install dnf-plugins-core >>"$log" 2>&1 || rc=1

        echo "Installing epel-release..." >"$msg"
        dnf -y install epel-release >>"$log" 2>&1 || rc=1

        echo "Enabling CRB repository..." >"$msg"
        dnf config-manager --set-enabled crb >>"$log" 2>&1 || rc=1

        echo "Refreshing repository metadata (makecache --refresh)..." >"$msg"
        dnf -y makecache --refresh >>"$log" 2>&1 || rc=1
      } || rc=1
      echo "$rc" >"$status"
    ) &

    local pid=$!
    (
      local PROGRESS=0
      while kill -0 "$pid" 2>/dev/null; do
        (( PROGRESS < 95 )) && PROGRESS=$(( PROGRESS + 5 ))
        echo "$PROGRESS"
        echo "XXX"
        echo -e "Enabling EPEL and CRB...\n$(cat "$msg" 2>/dev/null || echo "Working...")\n\nLog: $log"
        echo "XXX"
        sleep 0.5
      done
      echo "100"
      echo "XXX"
      echo -e "Repositories enabled and metadata refreshed.\n\nLog: $log"
      echo "XXX"
    ) | $DIALOG --backtitle "$BACKTITLE" --title "Repository Setup" --gauge "Preparing..." 10 70 0

    local rc=1
    [[ -f "$status" ]] && rc="$(cat "$status" 2>/dev/null || echo 1)"
    if [[ "$rc" -ne 0 ]]; then
      msgbox "Repository Setup Failed" "There was a problem enabling repositories.\n\nYou'll see the log next." 9 70
      $DIALOG --backtitle "$BACKTITLE" --title "Repo Setup Log" --textbox "$log" 22 100
      return 1
    fi
    return 0
  }

  # ────────────────────────── generic gauge runner ────────────────────────────
  run_gauge_cmd() {
    local title="$1"; shift
    local log="/tmp/$(basename "$1")-install.$(date +%s).log"
    local status="/tmp/$(basename "$1")-status.$$"
    : > "$log"
    ( "$@" &> "$log"; echo $? > "$status" ) & local pid=$!
    set +e
    (
      local pct=0
      while kill -0 "$pid" 2>/dev/null; do
        echo "$pct"
        echo "XXX"
        echo -e "Installing... Please wait.\nLog: $log"
        echo "XXX"
        sleep 0.3
        pct=$(( (pct + 2) % 97 ))
      done
      echo 100; echo "XXX"; echo "Finishing up..."; echo "XXX"
    ) | $DIALOG --backtitle "$BACKTITLE" --title "$title" --gauge "Preparing..." 10 70 0

    local rc=1
    [[ -f "$status" ]] && { rc="$(cat "$status" 2>/dev/null || echo 1)"; rm -f "$status"; }
    if [[ "$rc" -ne 0 ]]; then
      msgbox "Error" "$title failed.\n\nSee the next screen for details.\n\nLog: $log" 10 72
      $DIALOG --backtitle "$BACKTITLE" --title "Install log: $title" --textbox "$log" 22 100
      return "$rc"
    else
      infobox "Success" "$title completed.\n\nLog: $log" 8 70
      sleep 1
    fi
  }

  # ───────────────────────────── dnf installers ────────────────────────────────
  install_isc_dhcp() {
    enable_repos_with_gauge || return 1
    run_gauge_cmd "Installing ISC DHCP (dhcp-server)" dnf -y install dhcp-server
  }
  install_kea() {
    enable_repos_with_gauge || return 1
    run_gauge_cmd "Installing Kea DHCP (kea)" dnf -y install kea
  }

  # ───────────────────── shared IP/CIDR + domain helpers ──────────────────────
  is_valid_ip(){
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.; local o; for o in $1; do [[ $o -ge 0 && $o -le 255 ]] || return 1; done
  }
  ip_to_int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
  int_to_ip(){ local i=$1; printf "%d.%d.%d.%d" $(( (i>>24)&255 )) $(( (i>>16)&255 )) $(( (i>>8)&255 )) $(( i&255 )); }
  cidr_to_netmask(){ local c=$1; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip "$m"; }
  netmask_to_cidr(){
    local ip=$1; is_valid_ip "$ip" || { echo -1; return; }
    local n=$(ip_to_int "$ip") c=0 saw_zero=0
    for ((i=31;i>=0;i--)); do
      if (( (n>>i)&1 )); then (( saw_zero )) && { echo -1; return; }; ((c++))
      else saw_zero=1
      fi
    done
    echo "$c"
  }
  network_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip $(( $(ip_to_int "$ip") & m )); }
  broadcast_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); int_to_ip $(( $(ip_to_int "$ip") | (~m & 0xFFFFFFFF) )); }
  ip_in_cidr(){
    local ip=$1 net=$2 c=$3
    local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF ))
    (( ( $(ip_to_int "$ip") & m ) == ( $(ip_to_int "$net") & m ) ))
  }
  is_valid_domain(){
    local d="$1"
    [[ -n "$d" ]] || return 1
    [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
  }

  # ───────────────────────────── dhcpd setup flow ─────────────────────────────
  dhcpd_setup() {
    local iface inet4_line INET4 DHCPCIDR NET_DETECTED NETMASK_DETECTED
    iface=$(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1; exit}')
    [[ -z "$iface" ]] && { msgbox "DHCPD Setup" "No active interface found."; return 1; }
    inet4_line=$(nmcli -g IP4.ADDRESS device show "$iface" | head -n 1)
    [[ -z "$inet4_line" ]] && { msgbox "DHCPD Setup" "No IPv4 address found on $iface."; return 1; }

    INET4=${inet4_line%/*}
    DHCPCIDR=${inet4_line#*/}
    NET_DETECTED=$(network_from_ip_cidr "$INET4" "$DHCPCIDR")
    NETMASK_DETECTED=$(cidr_to_netmask "$DHCPCIDR")

    local DHCPBEGIP DHCPENDIP DHCPNETMASK DHCPDEFGW SUBNETDESC DOM_SUFFIX SEARCH_DOMAIN
    local DEF_SUFFIX="$(hostname -d 2>/dev/null || true)"
    local DEF_SEARCH="${DEF_SUFFIX}"

    while true; do
      # Range start
      while true; do
        DHCPBEGIP=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter beginning IP of DHCP lease range (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPBEGIP" ]] && is_valid_ip "$DHCPBEGIP" && ip_in_cidr "$DHCPBEGIP" "$NET_DETECTED" "$DHCPCIDR" && break
        msgbox "Invalid Input" "Start IP must be a valid IPv4 within $NET_DETECTED/$DHCPCIDR."
      done
      # Range end
      while true; do
        DHCPENDIP=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter ending IP of DHCP lease range (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPENDIP" ]] && is_valid_ip "$DHCPENDIP" && ip_in_cidr "$DHCPENDIP" "$NET_DETECTED" "$DHCPCIDR" && \
          (( $(ip_to_int "$DHCPBEGIP") <= $(ip_to_int "$DHCPENDIP") )) && break
        msgbox "Invalid Input" "End IP must be valid, in $NET_DETECTED/$DHCPCIDR, and ≥ start IP."
      done
      # Netmask (must match detected)
      while true; do
        DHCPNETMASK=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter netmask for clients (must match detected $NETMASK_DETECTED):" 8 78 "$NETMASK_DETECTED")
        local nm_cidr; nm_cidr=$(netmask_to_cidr "$DHCPNETMASK")
        [[ "$nm_cidr" -eq "$DHCPCIDR" ]] && break
        msgbox "Invalid Netmask" "Netmask must be contiguous and equal to $NETMASK_DETECTED."
      done
      # Default gateway
      while true; do
        DHCPDEFGW=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter default gateway for clients (in $NET_DETECTED/$DHCPCIDR):" 8 78)
        [[ -n "$DHCPDEFGW" ]] && is_valid_ip "$DHCPDEFGW" && ip_in_cidr "$DHCPDEFGW" "$NET_DETECTED" "$DHCPCIDR" && break
        msgbox "Invalid Gateway" "Gateway must be a valid IPv4 within $NET_DETECTED/$DHCPCIDR."
      done
      # Domain suffix (option 15)
      while true; do
        DOM_SUFFIX=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter domain suffix (for 'option domain-name'):" 8 78 "${DEF_SUFFIX}")
        is_valid_domain "$DOM_SUFFIX" && break
        msgbox "Invalid Domain" "Please enter a valid domain suffix like 'ad.example.com'."
      done
      # Search domain(s) (option 119)
      while true; do
        SEARCH_DOMAIN=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter search domain(s) for clients (comma-separated if multiple):" 9 78 "${DEF_SEARCH}")
        local ok=1 IFS=, item
        for item in $SEARCH_DOMAIN; do
          item="${item// /}" ; is_valid_domain "$item" || { ok=0; break; }
        done
        [[ $ok -eq 1 ]] && break
        msgbox "Invalid Search Domain" "One or more domains are invalid. Use comma-separated FQDNs."
      done

      SUBNETDESC=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter a friendly name/description for this subnet:" 8 78)

      $DIALOG --backtitle "$BACKTITLE" --title "DHCP Configuration Summary" --yesno \
"Interface:     $iface
Interface IP:  $INET4/$DHCPCIDR
Subnet:        $NET_DETECTED
Netmask:       $DHCPNETMASK
Range:         $DHCPBEGIP  →  $DHCPENDIP
Gateway:       $DHCPDEFGW
Domain:        $DOM_SUFFIX
Search:        $SEARCH_DOMAIN
Description:   $SUBNETDESC

Are these settings correct?" 18 72 && break
    done

    infobox "DHCPD Setup" "Creating /etc/dhcp/dhcpd.conf..."
    mkdir -p /etc/dhcp
    mv /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.orig 2>/dev/null || true
    cat <<EOF >/etc/dhcp/dhcpd.conf
authoritative;
allow unknown-clients;
default-lease-time 600;
max-lease-time 7200;

option ntp-servers ${INET4};
option time-servers ${INET4};
option domain-name-servers ${INET4};
option domain-name "${DOM_SUFFIX}";
option domain-search "${SEARCH_DOMAIN}";

# ${SUBNETDESC}
subnet ${NET_DETECTED} netmask ${DHCPNETMASK} {
  range ${DHCPBEGIP} ${DHCPENDIP};
  option subnet-mask ${DHCPNETMASK};
  option routers ${DHCPDEFGW};
}
EOF
  }

  # ───────────────────────────── Kea setup flow ───────────────────────────────
  kea_dhcp_setup() {
    local KEA_CONF="/etc/kea/kea-dhcp4.conf"
    mkdir -p /etc/kea; touch "$KEA_CONF"

    local iface inet4_line INET4 CIDR NETMASK NETWORK BROADCAST
    iface=$(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1; exit}')
    [[ -z "$iface" ]] && { msgbox "KEA DHCP Setup" "No active interface found."; return 1; }
    inet4_line=$(nmcli -g IP4.ADDRESS device show "$iface" | head -n 1)
    [[ -z "$inet4_line" ]] && { msgbox "KEA DHCP Setup" "No IPv4 address found on $iface."; return 1; }

    INET4=${inet4_line%/*}
    CIDR=${inet4_line#*/}
    NETWORK=$(network_from_ip_cidr "$INET4" "$CIDR")
    NETMASK=$(cidr_to_netmask "$CIDR")
    BROADCAST=$(broadcast_from_ip_cidr "$INET4" "$CIDR")

    local POOL_START POOL_END ROUTER DOM_SUFFIX SEARCH_DOMAIN DNS_SERVERS SUBNET_DESC
    local DEF_SUFFIX="$(hostname -d 2>/dev/null || true)"
    local DEF_SEARCH="${DEF_SUFFIX}"

    while true; do
      # pool start
      while true; do
        POOL_START=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter beginning IP of DHCP lease range (in $NETWORK/$CIDR):" 8 78)
        [[ -n "$POOL_START" ]] && is_valid_ip "$POOL_START" && ip_in_cidr "$POOL_START" "$NETWORK" "$CIDR" && break
        msgbox "Invalid Input" "Start IP must be a valid IPv4 within $NETWORK/$CIDR."
      done
      # pool end
      while true; do
        POOL_END=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter ending IP of DHCP lease range:" 8 78)
        [[ -n "$POOL_END" ]] && is_valid_ip "$POOL_END" && ip_in_cidr "$POOL_END" "$NETWORK" "$CIDR" && \
          (( $(ip_to_int "$POOL_START") <= $(ip_to_int "$POOL_END") )) && break
        msgbox "Invalid Input" "End IP must be valid, in $NETWORK/$CIDR, and ≥ start IP."
      done
      # gateway
      while true; do
        ROUTER=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter default gateway for clients (in $NETWORK/$CIDR):" 8 78)
        [[ -n "$ROUTER" ]] && is_valid_ip "$ROUTER" && ip_in_cidr "$ROUTER" "$NETWORK" "$CIDR" && break
        msgbox "Invalid Gateway" "Gateway must be a valid IPv4 within $NETWORK/$CIDR."
      done
      # domains
      while true; do
        DOM_SUFFIX=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter domain suffix (for 'domain-name'):" 8 78 "${DEF_SUFFIX}")
        is_valid_domain "$DOM_SUFFIX" && break
        msgbox "Invalid Domain" "Please enter a valid domain suffix like 'ad.example.com'."
      done
      while true; do
        SEARCH_DOMAIN=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
          "Enter search domain(s) for clients (comma-separated if multiple):" 9 78 "${DEF_SEARCH}")
        local ok=1 IFS=, item
        for item in $SEARCH_DOMAIN; do
          item="${item// /}" ; is_valid_domain "$item" || { ok=0; break; }
        done
        [[ $ok -eq 1 ]] && break
        msgbox "Invalid Search Domain" "One or more domains are invalid. Use comma-separated FQDNs."
      done
      DNS_SERVERS=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter DNS servers (comma separated, or leave blank to use $INET4):" 8 78 "$INET4")
      SUBNET_DESC=$($DIALOG --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter a friendly name/description for this subnet:" 8 78)

      $DIALOG --backtitle "$BACKTITLE" --title "KEA DHCP Settings Review" --yesno \
"Interface:     $iface
Interface IP:  $INET4/$CIDR
Subnet:        $NETWORK/$CIDR
Broadcast:     $BROADCAST
Range:         $POOL_START  →  $POOL_END
Gateway:       $ROUTER
DNS:           $DNS_SERVERS
Domain:        $DOM_SUFFIX
Search:        $SEARCH_DOMAIN
Description:   $SUBNET_DESC

Are these settings correct?" 20 72 && break
    done

    infobox "KEA DHCP Setup" "Creating /etc/kea/kea-dhcp4.conf..."
    cat <<EOF > "$KEA_CONF"
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$iface" ]
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/lib/kea/kea-leases4.csv"
    },
    "subnet4": [
      {
        "id": 1,
        "subnet": "$NETWORK/$CIDR",
        "interface": "$iface",
        "comment": "$SUBNET_DESC",
        "pools": [ { "pool": "$POOL_START - $POOL_END" } ],
        "option-data": [
          { "name": "routers",               "data": "$ROUTER" },
          { "name": "domain-name-servers",   "data": "$DNS_SERVERS" },
          { "name": "ntp-servers",           "data": "$DNS_SERVERS" },
          { "name": "domain-name",           "data": "$DOM_SUFFIX" },
          { "name": "domain-search",         "data": "$SEARCH_DOMAIN" }
        ]
      }
    ],
    "authoritative": true
  }
}
EOF
    chown root:kea "$KEA_CONF"
    chmod 640 "$KEA_CONF"
    restorecon "$KEA_CONF" 2>/dev/null || true
  }

  # ────────────────────────────── preflight checks ─────────────────────────────
  require_root || return 1
  require_rocky9plus || return 1
  command -v "$DIALOG" >/dev/null 2>&1 || { echo "dialog not found. dnf -y install dialog" >&2; return 1; }
  command -v nmcli   >/dev/null 2>&1 || { echo "nmcli not found. dnf -y install NetworkManager" >&2; return 1; }

  # ────────────────────────────── user selection ───────────────────────────────
  $DIALOG --backtitle "$BACKTITLE" --title "DHCP Installation" --yesno \
"Would you like to install a DHCP service on this system?

You will be able to choose between ISC DHCP or Kea DHCP in the next step." 9 80 || { clear; return 0; }

  local isc_installed="not installed" kea_installed="not installed"
  detect_isc_dhcp && isc_installed="installed"
  detect_kea && kea_installed="installed"

  local default="kea"
  detect_kea && default="kea"
  { detect_isc_dhcp && ! detect_kea; } && default="isc"

  local kea_desc="Install/upgrade Kea DHCP (recommended)"
  [[ $kea_installed == "installed" ]] && kea_desc+=" [installed]"
  local isc_desc="Install/upgrade ISC DHCP (dhcp-server)"
  [[ $isc_installed == "installed" ]] && isc_desc+=" [installed]"

  local KEA_ON="OFF" ISC_ON="OFF"
  [[ $default == "kea" ]] && KEA_ON="ON" || ISC_ON="ON"

  local choice
  choice=$($DIALOG --backtitle "$BACKTITLE" --stdout --title "DHCP Installer" --radiolist \
"Select which DHCP server to install or upgrade.

Detected:
- ISC DHCP: $isc_installed
- Kea DHCP: $kea_installed" \
    14 76 2 \
    kea "$kea_desc" $KEA_ON \
    isc "$isc_desc" $ISC_ON)

  case "${choice:-}" in
    kea) install_kea && CHOSEN_BACKEND="kea" ;;
    isc) install_isc_dhcp && CHOSEN_BACKEND="isc" ;;
    *)   clear; return 0 ;;
  esac

  # ────────────────── run setup, enable service, open firewall ────────────────
  local CONF SVC
  if [[ "$CHOSEN_BACKEND" == "kea" ]]; then
    kea_dhcp_setup
    systemctl enable --now kea-dhcp4 >/dev/null 2>&1 || true
    CONF="/etc/kea/kea-dhcp4.conf"; SVC="kea-dhcp4"
  else
    dhcpd_setup
    systemctl enable --now dhcpd >/dev/null 2>&1 || true
    CONF="/etc/dhcp/dhcpd.conf"; SVC="dhcpd"
  fi

  firewall-cmd --zone=public --add-service=dhcp --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true

  # ────────────────────────────── final validation ─────────────────────────────
  local ok_conf=0 ok_svc=0
  [[ -s "$CONF" ]] && ok_conf=1
  if systemctl is-active --quiet "$SVC"; then ok_svc=1; fi

  if [[ $ok_conf -eq 1 && $ok_svc -eq 1 ]]; then
    msgbox "Success" "$SVC is running and $CONF configured successfully."
    clear; return 0
  fi

  # Syntax hint on failure
  local syntax=""
  if [[ "$SVC" == "kea-dhcp4" && -f "$CONF" ]]; then
    syntax="$(kea-dhcp4 -t "$CONF" 2>&1 || true)"
  elif [[ "$SVC" == "dhcpd" && -f "$CONF" ]]; then
    syntax="$(dhcpd -t -cf "$CONF" 2>&1 || true)"
  fi

  local err="Validation failed:
- Config file present: $( [[ $ok_conf -eq 1 ]] && echo YES || echo NO )
- Service active:      $( [[ $ok_svc -eq 1 ]] && echo YES || echo NO )

$( [[ -n "$syntax" ]] && echo -e "Syntax check output:\n\n$syntax" || echo "No syntax details available.")"

  msgbox "DHCP Validation" "$err" 18 90
  clear
  return 1
}
#===========CONFGIURE FIREWALL=============
configure_firewall() {
  dialog --backtitle "Firewall Services Configuration" --title "Firewall Configuration" --infobox "Applying firewall rules for services..." 5 60
  firewall-cmd --permanent --add-service=tftp >/dev/null
  firewall-cmd --permanent --add-service=ntp >/dev/null
  firewall-cmd --permanent --add-service=http >/dev/null

  firewall-cmd --reload >/dev/null
  systemctl restart firewalld
  sleep 2
  # Extract enabled services
  FIREWALL_SERVICES=$(firewall-cmd --list-services 2>/dev/null)

  dialog --backtitle "Firewall Services Configuration" --title "Firewall Status" --infobox "These services are now open on the server:\n\n$FIREWALL_SERVICES\n\n" 12 60
  sleep 4
}
#===========UPDATE ISSUE FILE============
update_issue_file() {
  rm -rf /etc/issue
  touch /etc/issue
  cat <<EOF >/etc/issue
\S
Kernel \r on an \m
Hostname: \n
IP Address: \4
EOF
}

#===========CONFIGURE FAIL2BAN=============
configure_fail2ban() {
  LOG_FILE="/var/log/fail2ban-setup.log"
  ORIGINAL_FILE="/etc/fail2ban/jail.conf"
  JAIL_LOCAL_FILE="/etc/fail2ban/jail.local"
  SSHD_LOCAL_FILE="/etc/fail2ban/jail.d/sshd.local"

  {
    echo "10"
    echo "# Copying jail.conf to jail.local..."
    if cp -v "$ORIGINAL_FILE" "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
      echo "Copied jail.conf to jail.local" >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "Error" --msgbox "Failed to copy $ORIGINAL_FILE to $JAIL_LOCAL_FILE" 6 60
      echo "Failed to copy jail.conf" >> "$LOG_FILE"
      return 1
    fi

    echo "30"
    echo "# Enabling SSHD in jail.local..."
    if sed -i '/^\[sshd\]/,/^$/ s/#mode.*normal/&\nenabled = true/' "$JAIL_LOCAL_FILE" >> "$LOG_FILE" 2>&1; then
      echo "Modified jail.local to enable SSHD" >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "Error" --msgbox "Failed to enable SSHD in jail.local" 6 60
      return 1
    fi

    echo "50"
    echo "# Writing SSHD jail configuration..."
    cat <<EOL > "$SSHD_LOCAL_FILE"
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
bantime.increment = true
bantime.factor = 2
EOL
    echo "Created sshd.local config" >> "$LOG_FILE"

    echo "60"
    echo "# Enabling and starting Fail2Ban..."
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1
    sleep 2

    echo "75"
    echo "# Checking Fail2Ban status..."
    if systemctl is-active --quiet fail2ban; then
      echo "Fail2Ban is running." >> "$LOG_FILE"
    else
      echo "Fail2Ban failed to start. Attempting SELinux recovery..." >> "$LOG_FILE"

      selinux_status=$(sestatus | grep "SELinux status" | awk '{print $3}')
      if [[ "$selinux_status" == "enabled" ]]; then
        restorecon -v /etc/fail2ban/jail.local >> "$LOG_FILE" 2>&1
        denials=$(ausearch -m avc -ts recent | grep "fail2ban-server" | wc -l)
        if (( denials > 0 )); then
          ausearch -c 'fail2ban-server' --raw | audit2allow -M my-fail2banserver >> "$LOG_FILE" 2>&1
          semodule -X 300 -i my-fail2banserver.pp >> "$LOG_FILE" 2>&1
          echo "Custom SELinux policy applied." >> "$LOG_FILE"
        fi
      fi

      systemctl restart fail2ban >> "$LOG_FILE" 2>&1
      if systemctl is-active --quiet fail2ban; then
        echo "Fail2Ban restarted successfully after SELinux fix." >> "$LOG_FILE"
      else
        dialog --title "Fail2Ban Error" --msgbox "Fail2Ban failed to start even after SELinux policy fix. Please investigate manually." 8 70
        echo "Fail2Ban still failed after SELinux fix." >> "$LOG_FILE"
        return 1
      fi
    fi

    echo "90"
    echo "# Verifying SSHD jail status..."
    sshd_status=$(fail2ban-client status sshd 2>&1)
    if echo "$sshd_status" | grep -q "ERROR   NOK: ('sshd',)"; then
      dialog --backtitle "Configure Fail2ban for SSH" --title "SSHD Jail Error" --msgbox "SSHD jail failed to start. Check configuration:\n\n$sshd_status" 10 70
      echo "SSHD jail failed to start." >> "$LOG_FILE"
    elif echo "$sshd_status" | grep -q "Banned IP list:"; then
      echo "SSHD jail is active and functional." >> "$LOG_FILE"
    else
      dialog --backtitle "Configure Fail2ban for SSH" --title "SSHD Jail Warning" --msgbox "SSHD jail may not be functional. Check manually:\n\n$sshd_status" 10 70
      echo "SSHD jail might be non-functional." >> "$LOG_FILE"
    fi

    echo "100"
  } | dialog --backtitle "Configure Fail2ban for SSH" --title "Fail2Ban Setup" --gauge "Installing and configuring Fail2Ban..." 10 60 0

  dialog --backtitle "Configure Fail2ban for SSH" --title "Success" --infobox "Fail2Ban has been configured and started successfully." 6 60
  sleep 3
}
#===========Install Python and Dependencies==========
python310_setup_module() {
  local TITLE="Python 3.10 Setup"
  local BACKTITLE="Python 3.10 Setup"
  local LOGFILE="/var/log/python310-setup.log"
  local PYVER="3.10.5"
  local PYTGZ="Python-${PYVER}.tgz"
  local PYSRC="Python-${PYVER}"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  # ---- Preflight (auto-close errors) ----
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"ERROR: This function must be run as root (sudo)." 7 60
    sleep 2; return 1
  fi
  local OSMAJOR=""
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release; OSMAJOR="${VERSION_ID%%.*}"
  elif [[ -r /etc/redhat-release ]]; then
    OSMAJOR="$(grep -oE '[0-9]+' /etc/redhat-release | head -1 || true)"
  fi
  if ! [[ "$OSMAJOR" =~ ^[0-9]+$ && $OSMAJOR -ge 9 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"ERROR: This installer supports Rocky Linux 9 or newer." 7 60
    sleep 2; return 1
  fi

  # ---- Gauge helpers ----
  _gauge_update() {  # usage: _gauge_update <pct> <message...>
    local pct="$1"; shift
    echo "XXX"; echo "$pct"; echo -e "$*"; echo "XXX"
  }

  _run_step() {      # usage: _run_step <target_pct> <label> <cmd...>
    local target_pct="$1"; shift
    local label="$1"; shift
    _gauge_update "$((target_pct-1))" "$label..."
    { "$@" >>"$LOGFILE" 2>&1; } || return 1
    _gauge_update "$target_pct" "$label...done"; sleep 0.3
  }

  # Dynamic pacing: faster early, slower near target
  _run_long_step() { # usage: _run_long_step <start_pct> <target_pct> <label> <cmd...>
    local start_pct="$1"; local target_pct="$2"; shift 2
    local label="$1"; shift
    _gauge_update "$start_pct" "$label (running)..."

    { "$@" >>"$LOGFILE" 2>&1 & }
    local pid=$!
    local pct="$start_pct"

    while kill -0 "$pid" >/dev/null 2>&1; do
      # Increment toward target-1, never reaching it until the command finishes
      pct=$((pct + 1))
      if (( pct >= target_pct )); then pct=$((target_pct-1)); fi

      # Dynamic pacing: slow down as we get closer to the target
      #   <= 60%  : snappy updates
      #   61–70%  : moderate
      #   71–(target-1): slower (feels realistic near the end)
      if   (( pct <= 60 )); then sleep 1
      elif (( pct <= 70 )); then sleep 5
      else                       sleep 2
      fi

      _gauge_update "$pct" "$label (running)..."
    done

    wait "$pid" || return 1
    _gauge_update "$target_pct" "$label...done"; sleep 0.3
  }

  # ---- Run the build with a single gauge ----
  {
    _gauge_update 1 "Starting Python ${PYVER} setup (Rocky ${OSMAJOR})..."; sleep 0.4

    _run_step 5  "Preparing /root working directory" bash -lc 'cd /root' || exit 1
    _run_step 10 "Downloading ${PYTGZ}"             bash -lc "cd /root && wget -q https://www.python.org/ftp/python/${PYVER}/${PYTGZ}" || exit 1
    _run_step 15 "Extracting ${PYTGZ}"              bash -lc "cd /root && tar xzf ${PYTGZ}" || exit 1
    _run_step 25 "Configuring (enable optimizations)" bash -lc "cd /root/${PYSRC} && ./configure --enable-optimizations" || exit 1

    local JOBS; JOBS="$(nproc 2>/dev/null || echo 4)"
    _run_long_step 25 80 "Compiling (make -j ${JOBS})" bash -lc "cd /root/${PYSRC} && make -j ${JOBS}" || exit 1

    _run_step 85 "Installing (make altinstall)"     bash -lc "cd /root/${PYSRC} && make altinstall" || exit 1
    _run_step 88 "Bootstrapping pip (ensurepip)"    /usr/local/bin/python3.10 -m ensurepip --upgrade || true
    _run_long_step 90 93 "Upgrading pip/setuptools/wheel" /usr/local/bin/python3.10 -m pip install --upgrade pip setuptools wheel || exit 1
    _run_long_step 93 96 "Installing meraki & requests"  /usr/local/bin/python3.10 -m pip install -U meraki requests || exit 1
    _run_step 97 "Relocating sources to /opt/${PYSRC}" bash -lc "mv -f /root/${PYSRC}/ /opt/" || exit 1
    _run_step 99 "Cleaning /root artifacts"         bash -lc "rm -f /root/Python* 2>/dev/null || true" || exit 1
    _gauge_update 100 "Finalizing..."; sleep 0.5
  } | dialog --backtitle "$BACKTITLE" --title "Building Python ${PYVER}" \
             --gauge "Initializing..." 18 90 0

  # ---- Post-check & summary ----
  if ! command -v /usr/local/bin/python3.10 >/dev/null 2>&1; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"Python 3.10 installation appears to have failed.
See log: $LOGFILE" 8 70
    sleep 2; return 1
  fi

  local PYBIN="/usr/local/bin/python3.10"
  local PYV="$("$PYBIN" -V 2>&1 || true)"
  local PIPV="$("$PYBIN" -m pip --version 2>&1 || true)"
  local MERAKI_V="$("$PYBIN" -m pip show meraki 2>/dev/null | awk -F': ' '/^Version/{print $2}')"
  local REQ_V="$("$PYBIN" -m pip show requests 2>/dev/null | awk -F': ' '/^Version/{print $2}')"

  local REPORT="Python setup complete.

${PYV}
${PIPV}
meraki:  ${MERAKI_V:-not installed}
requests: ${REQ_V:-not installed}

Binary: /usr/local/bin/python3.10
Sources: /opt/${PYSRC}
Log: ${LOGFILE}

Continuing..."
  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "$REPORT" 14 78
  sleep 2
  return 0
}
#===========TFTP Server Setup=============
tftp_setup_module() {
  local TITLE="TFTP Server Configuration"
  local BACKTITLE="TFTP Server Setup"
  local LOGFILE="/var/log/tftp-setup.log"
  local TFTP_ROOT="/var/lib/tftpboot"
  local SVC="/etc/systemd/system/tftp-server.service"
  local SOCK="/etc/systemd/system/tftp-server.socket"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  if [[ $EUID -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --msgbox "This function must be run as root." 7 50
    return 1
  fi

  local total=13 step=0
  _gauge_step() {
    step=$((step + 1))
    local pct=$(( step * 100 / total ))
    echo "XXX"; echo "$pct"; echo -e "$1"; echo "XXX"
    sleep 0.35
  }

  {
    _gauge_step "Copying systemd unit files..."
    \cp -f /usr/lib/systemd/system/tftp.service "$SVC"  >>"$LOGFILE" 2>&1
    \cp -f /usr/lib/systemd/system/tftp.socket  "$SOCK" >>"$LOGFILE" 2>&1

    _gauge_step "Pointing socket to tftp-server.service..."
    if grep -q '^Service=' "$SOCK"; then
      sed -i 's/^Service=.*/Service=tftp-server.service/' "$SOCK" >>"$LOGFILE" 2>&1
    else
      echo 'Service=tftp-server.service' >>"$SOCK"
    fi

    _gauge_step "Updating Requires= in service..."
    sed -i '/^Requires=/c\Requires=tftp-server.socket' "$SVC" >>"$LOGFILE" 2>&1 || true

    _gauge_step "Setting ExecStart with create (-c), chroot (-s)..."
    sed -i '/^ExecStart=/c\ExecStart=/usr/sbin/in.tftpd -c -p -s /var/lib/tftpboot' "$SVC" >>"$LOGFILE" 2>&1

    _gauge_step "Creating TFTP root and subdirectories..."
    mkdir -p "$TFTP_ROOT/images" "$TFTP_ROOT/hybrid" "$TFTP_ROOT/wlc" "$TFTP_ROOT/mig" >>"$LOGFILE" 2>&1

    _gauge_step "Applying permissive POSIX perms (R/W for uploads)…"
    chmod 777 -R "$TFTP_ROOT" >>"$LOGFILE" 2>&1

    _gauge_step "Restoring SELinux contexts on the tree…"
    restorecon -RFv "$TFTP_ROOT" >>"$LOGFILE" 2>&1 || true

    _gauge_step "Allowing anonymous TFTP writes (SELinux)…"
    if command -v setsebool >/dev/null 2>&1; then
      setsebool -P tftp_anon_write on >>"$LOGFILE" 2>&1 || true
    fi

    _gauge_step "Reloading systemd daemon..."
    systemctl daemon-reload >>"$LOGFILE" 2>&1

    _gauge_step "Disabling stock tftp.socket to avoid conflicts…"
    systemctl disable --now tftp.socket >>"$LOGFILE" 2>&1 || true

    _gauge_step "Enabling and starting tftp-server.socket..."
    systemctl enable --now tftp-server.socket >>"$LOGFILE" 2>&1

    _gauge_step "Finalizing..."
    sleep 0.3
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" \
             --gauge "Configuring TFTP server...\n(Logging to $LOGFILE)" 12 74 0

  local status="inactive"
  systemctl is-active tftp-server.socket >/dev/null 2>&1 && status="active"

  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"TFTP setup complete.

• Socket status: ${status}
• Root: $TFTP_ROOT
• Subdirs (TFTP R/W): images, hybrid, wlc, mig
• SELinux:
    - restorecon applied to tree
    - tftp_anon_write=on
• Units:
    - $SVC
    - $SOCK (Service=tftp-server.service)
• Log: ${LOGFILE}" 15 78
  sleep 3
}
#===========HTTP Repo Setup (images via HTTP; ALL dirs writable via TFTP)=============
http_repo_setup_module() {
  local TITLE="HTTP Repository Configuration"
  local BACKTITLE="HTTP Repo Setup"
  local LOGFILE="/var/log/http-repo-setup.log"

  local TFTP_ROOT="/var/lib/tftpboot"
  local IMAGES_DIR="$TFTP_ROOT/images"
  local HYBRID_DIR="$TFTP_ROOT/hybrid"
  local WLC_DIR="$TFTP_ROOT/wlc"
  local MIG_DIR="$TFTP_ROOT/mig"

  local SITE_CONF="/etc/httpd/conf.d/tftp-images.conf"
  local SEND_FILE_CONF="/etc/httpd/conf.d/00-sendfile.conf"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  if [[ $EUID -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --msgbox "This function must be run as root." 7 50
    return 1
  fi

  _server_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' \
      || hostname -I 2>/dev/null | awk '{print $1}' \
      || echo "127.0.0.1"
  }

  local total=12 step=0
  _gauge_step() {
    step=$((step + 1))
    local pct=$(( step * 100 / total ))
    echo "XXX"; echo "$pct"; echo -e "$1"; echo "XXX"
    sleep 0.35
  }

  local selinux_persist="applied"
  {
    _gauge_step "Ensuring directories exist (images, hybrid, wlc, mig)…"
    mkdir -p "$IMAGES_DIR" "$HYBRID_DIR" "$WLC_DIR" "$MIG_DIR" >>"$LOGFILE" 2>&1
    # NOTE: Do NOT chmod 755 here; keep your TFTP module's 777 so TFTP can write everywhere.

    _gauge_step "Writing Apache alias for /images → $IMAGES_DIR…"
    cat > "$SITE_CONF" <<CONF
# Serve firmware from TFTP images over HTTP at /images
Alias /images $IMAGES_DIR
<Directory "$IMAGES_DIR">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
# NOTE: hybrid/, wlc/, mig/ are NOT exposed over HTTP
CONF

    _gauge_step "Disabling sendfile globally…"
    cat > "$SEND_FILE_CONF" <<'CONF'
EnableSendfile Off
CONF

    _gauge_step "Remove any old broad fcontext rules on /var/lib/tftpboot…"
    if command -v semanage >/dev/null 2>&1; then
      semanage fcontext -d "$TFTP_ROOT(/.*)?" >>"$LOGFILE" 2>&1 || true
    fi

    _gauge_step "Label ONLY images/ as public_content_rw_t (Apache-readable, still TFTP-writable)…"
    if command -v semanage >/dev/null 2>&1; then
      semanage fcontext -a -t public_content_rw_t "$IMAGES_DIR(/.*)?" >>"$LOGFILE" 2>&1 \
        || semanage fcontext -m -t public_content_rw_t "$IMAGES_DIR(/.*)?" >>"$LOGFILE" 2>&1
      selinux_persist="applied"
    else
      selinux_persist="skipped (no semanage)"
    fi

    _gauge_step "Restore SELinux contexts (hybrid/wlc/mig stay tftpdir_rw_t)…"
    restorecon -RFv "$TFTP_ROOT" >>"$LOGFILE" 2>&1 || true

    _gauge_step "Allow TFTP to write into public_content_rw_t (boolean)…"
    if command -v setsebool >/dev/null 2>&1; then
      setsebool -P tftp_anon_write on >>"$LOGFILE" 2>&1 || true
    fi

    _gauge_step "Ensure Apache can read/traverse images/ without reducing write bits…"
    chmod -R a+rX "$IMAGES_DIR" >>"$LOGFILE" 2>&1 || true   # adds r/X; doesn't remove existing write

    _gauge_step "Ensure autoindex (remove stale index.html)…"
    rm -f "$IMAGES_DIR/index.html" >>"$LOGFILE" 2>&1 || true

    _gauge_step "Finalizing…"
    sleep 0.3
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" \
             --gauge "Configuring HTTP repo (images via HTTP; ALL TFTP R/W)…\n(Logging to $LOGFILE)" 12 74 0

  local IP=$(_server_ip)
  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"HTTP repo setup complete.

• Served via HTTP:
    /images  →  $IMAGES_DIR  (SELinux: public_content_rw_t)
• TFTP R/W (all four dirs, writable by design):
    $IMAGES_DIR, $HYBRID_DIR, $WLC_DIR, $MIG_DIR
    (POSIX perms left as set by TFTP module; SELinux:
      images/* public_content_rw_t, others tftpdir_rw_t)
• SELinux:
    fcontext images/* → public_content_rw_t   (persist: $selinux_persist)
    boolean tftp_anon_write=on
• Configs:
    $SITE_CONF
    $SEND_FILE_CONF
• Log: $LOGFILE

URL after reboot:
  http://$IP/images/" 20 84
  sleep 3
}
#===========IOS-XE Images Symlink Setup=============
create_iosxe_symlink_module() {
  # Optional overrides:
  # create_iosxe_symlink_module "/root/IOS-XE_images" "/var/lib/tftpboot/images"
  local LINK_PATH="${1:-/root/IOS-XE_images}"
  local TARGET_PATH="${2:-/var/lib/tftpboot/images}"

  local TITLE="IOS-XE Images Symlink Configuration"
  local BACKTITLE="Server Prep"
  local LOGFILE="/var/log/iosxe-images-symlink.log"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  if [[ $EUID -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --msgbox "This function must be run as root." 7 50
    return 1
  fi

  local total=5
  local step=0
  _gauge_step() {
    step=$((step + 1))
    local pct=$(( step * 100 / total ))
    echo "XXX"
    echo "$pct"
    echo -e "$1"
    echo "XXX"
    sleep 0.3
  }

  _link_current_target() { [[ -L "$LINK_PATH" ]] && readlink -f "$LINK_PATH" || true; }

  local replaced="no"
  local status_msg=""

  {
    _gauge_step "Ensuring target directory exists: $TARGET_PATH ..."
    mkdir -p "$TARGET_PATH" >>"$LOGFILE" 2>&1
    chmod 755 "$TARGET_PATH" >>"$LOGFILE" 2>&1

    _gauge_step "Checking existing link/path at: $LINK_PATH ..."
    if [[ -e "$LINK_PATH" || -L "$LINK_PATH" ]]; then
      local cur="$(_link_current_target)"
      if [[ -L "$LINK_PATH" && "$cur" == "$(readlink -f "$TARGET_PATH")" ]]; then
        echo "Link already correct ($LINK_PATH -> $cur)" >>"$LOGFILE"
      else
        echo "Existing path at $LINK_PATH (type: $(stat -c %F "$LINK_PATH" 2>/dev/null || echo 'unknown'))" >>"$LOGFILE"
        echo "REPLACE_PROMPT" >>"$LOGFILE"
      fi
    fi
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" \
             --gauge "Preparing symlink...\n(Logging to $LOGFILE)" 10 70 0

  if [[ -e "$LINK_PATH" || -L "$LINK_PATH" ]]; then
    local cur="$(_link_current_target)"
    if [[ ! ( -L "$LINK_PATH" && "$cur" == "$(readlink -f "$TARGET_PATH")" ) ]]; then
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --yesno \
"Path exists at:
  $LINK_PATH
$( [[ -n "$cur" ]] && echo "Currently points to: $cur" || echo "Not a matching symlink.")

Replace it with a new symlink to:
  $TARGET_PATH ?" 12 70
      local rc=$?
      if (( rc != 0 )); then
        dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"Aborted. Existing path was left untouched:

$LINK_PATH" 8 70
        sleep 2
        return 2
      fi
      replaced="yes"
      rm -rf -- "$LINK_PATH" >>"$LOGFILE" 2>&1 || true
    fi
  fi

  {
    _gauge_step "Creating symlink: $LINK_PATH -> $TARGET_PATH ..."
    ln -sfn "$TARGET_PATH" "$LINK_PATH" >>"$LOGFILE" 2>&1

    _gauge_step "Verifying symlink..."
    local final_target=""
    [[ -L "$LINK_PATH" ]] && final_target="$(readlink -f "$LINK_PATH" || true)"
    if [[ "$final_target" == "$(readlink -f "$TARGET_PATH")" ]]; then
      status_msg="Symlink OK"
      echo "Verified: $LINK_PATH -> $final_target" >>"$LOGFILE"
    else
      status_msg="Verification failed"
      echo "Verification failed: $LINK_PATH" >>"$LOGFILE"
    fi

    _gauge_step "Finalizing..."
    sleep 0.3
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" \
             --gauge "Creating symlink...\n(Logging to $LOGFILE)" 10 70 0

  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"IOS-XE images symlink setup complete.

• Link:   $LINK_PATH
• Target: $TARGET_PATH
• Replaced existing path: $replaced
• Status: $status_msg
• Log:    $LOGFILE

Tip: copy files into $LINK_PATH (the link), e.g.:
  cp -av /root/IOS-XE_images/*.bin $LINK_PATH/
" 14 78
  sleep 3
}
#===========Images Auto-Fix (HTTP/TFTP images dir)=============
images_autofix_module() {
  local TITLE="Images Auto-Fix Configuration"
  local BACKTITLE="Server Prep"
  local LOGFILE="/var/log/images-autofix-setup.log"

  # Paths (same as your latest script)
  local IMAGES_DIR="/var/lib/tftpboot/images"
  local FIX_SCRIPT="/usr/local/sbin/tftp-images-autofix.sh"
  local SVC="/etc/systemd/system/tftp-images-autofix.service"
  local PATHU="/etc/systemd/system/tftp-images-autofix.path"
  local TIMER="/etc/systemd/system/tftp-images-autofix.timer"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  if [[ $EUID -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --msgbox "This function must be run as root." 7 54
    return 1
  fi

  local total=10 step=0
  _gauge_step() {
    step=$((step + 1))
    local pct=$(( step * 100 / total ))
    echo "XXX"; echo "$pct"; echo -e "$1"; echo "XXX"
    sleep 0.3
  }

  {
    _gauge_step "Ensuring images directory exists..."
    mkdir -p "$IMAGES_DIR" >>"$LOGFILE" 2>&1

    _gauge_step "Installing fix script..."
    cat > "$FIX_SCRIPT" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
IMAGES_DIR="/var/lib/tftpboot/images"
[[ -d "$IMAGES_DIR" ]] || exit 0

# Prevent overlapping runs
exec 9>/run/tftp-images-autofix.lock
flock -n 9 || exit 0

export LANG=C LC_ALL=C

STATE="/run/tftp-images-autofix.state"
now=$(date +%s)
last=0
[[ -f "$STATE" ]] && last=$(<"$STATE" || echo 0)

# Self-throttle: if we ran within the last 2s, skip
if (( last > 0 && now - last < 2 )); then
  exit 0
fi

# If nothing newer than last successful run, skip heavy work
if [[ -f "$STATE" ]]; then
  if ! find "$IMAGES_DIR" -type f -newer "$STATE" -print -quit | grep -q . ; then
    exit 0
  fi
fi

# Persistent SELinux label rule
if command -v semanage >/dev/null 2>&1; then
  semanage fcontext -m -t public_content_rw_t "$IMAGES_DIR(/.*)?" >/dev/null 2>&1 \
    || semanage fcontext -a -t public_content_rw_t "$IMAGES_DIR(/.*)?" >/dev/null 2>&1
fi

RESTORECON_BIN="$(command -v restorecon || true)"
CHMOD_BIN="$(command -v chmod || true)"
LOGGER_BIN="$(command -v logger || true)"

# Quiet repairs
"$RESTORECON_BIN" -RF "$IMAGES_DIR" >/dev/null 2>&1 || true
"$CHMOD_BIN"    -R a+rX "$IMAGES_DIR" >/dev/null 2>&1 || true

# Mark successful run
echo "$now" > "$STATE"

# Light log
[[ -n "$LOGGER_BIN" ]] && "$LOGGER_BIN" -t tftp-images-autofix "Repaired labels/perms under $IMAGES_DIR" || true
exit 0
SH
    chmod 755 "$FIX_SCRIPT" >>"$LOGFILE" 2>&1

    _gauge_step "Writing systemd service..."
    cat > "$SVC" <<SERVICE
[Unit]
Description=Auto-fix SELinux labels/permissions under $IMAGES_DIR
ConditionPathExists=$IMAGES_DIR
# Disable rate limiting to avoid 'start-limit-hit'
StartLimitIntervalSec=0

[Service]
Type=oneshot
ExecStart=$FIX_SCRIPT
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
SERVICE

    _gauge_step "Writing systemd path unit (PathModified)..."
    cat > "$PATHU" <<PATHUNIT
[Unit]
Description=Watch $IMAGES_DIR for changes and run auto-fix

[Path]
Unit=tftp-images-autofix.service
MakeDirectory=true
PathModified=$IMAGES_DIR

[Install]
WantedBy=paths.target
PATHUNIT

    _gauge_step "Writing 30s safety timer..."
    cat > "$TIMER" <<TIMER
[Unit]
Description=Periodic auto-fix for $IMAGES_DIR (every 30s)

[Timer]
OnBootSec=15s
OnUnitActiveSec=30s
AccuracySec=1s
RandomizedDelaySec=0
Unit=tftp-images-autofix.service

[Install]
WantedBy=timers.target
TIMER

    _gauge_step "Reloading systemd & clearing old failures..."
    systemctl daemon-reload >>"$LOGFILE" 2>&1
    systemctl reset-failed tftp-images-autofix.service 2>/dev/null || true
    systemctl reset-failed tftp-images-autofix.path 2>/dev/null || true
    systemctl reset-failed tftp-images-autofix.timer 2>/dev/null || true

    _gauge_step "Enabling path trigger + safety timer..."
    systemctl enable --now tftp-images-autofix.path  >>"$LOGFILE" 2>&1
    systemctl enable --now tftp-images-autofix.timer >>"$LOGFILE" 2>&1

    _gauge_step "Initial run (oneshot; quiet)..."
    systemctl start tftp-images-autofix.service >>"$LOGFILE" 2>&1 || true

    _gauge_step "Quick self-test (touch → path trigger)..."
    date > "$IMAGES_DIR/.autofix-test" 2>>"$LOGFILE"
    sleep 2
    rm -f "$IMAGES_DIR/.autofix-test" 2>>"$LOGFILE"

    _gauge_step "Finalizing..."
    sleep 0.2
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" \
             --gauge "Setting up Images Auto-Fix...\n(Logging to $LOGFILE)" 12 74 0

  # Summarize states (quiet)
  local path_state="inactive" timer_state="inactive"
  systemctl is-active tftp-images-autofix.path  >/dev/null 2>&1 && path_state="active"
  systemctl is-active tftp-images-autofix.timer >/dev/null 2>&1 && timer_state="active"

  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"Images Auto-Fix ready.

• Watch path: ${IMAGES_DIR}
• Units:
    - tftp-images-autofix.path  : ${path_state}
    - tftp-images-autofix.timer : ${timer_state}
    - tftp-images-autofix.service (oneshot)
• Fix script:
    ${FIX_SCRIPT}
• Log:
    ${LOGFILE}

Behavior:
  - Runs on changes to ${IMAGES_DIR}
  - Also runs every 30s as a safety net
  - Idempotent; quiet; no rate-limit issues" 17 78
  sleep 3
}

#===========SERVICE CHECK & ENABLE PROGRESS=============
check_and_enable_services() {
  TMP_LOG=$(mktemp)
  TMP_BAR=$(mktemp)

  # List the services you want to manage
  SERVICES=("fail2ban" "tftp-server.socket" "cockpit.socket" "httpd")  # <-- add or remove services as needed

  total=${#SERVICES[@]}
  count=0

  {
    for service in "${SERVICES[@]}"; do
      echo "Checking $service..." >> "$TMP_LOG"

      systemctl is-enabled --quiet "$service"
      if [[ $? -ne 0 ]]; then
        echo "$service is not enabled. Enabling..." >> "$TMP_LOG"
        systemctl enable "$service" >> "$TMP_LOG" 2>&1
      fi

      systemctl is-active --quiet "$service"
      if [[ $? -ne 0 ]]; then
        echo "$service is not running. Starting..." >> "$TMP_LOG"
        systemctl start "$service" >> "$TMP_LOG" 2>&1
      fi

      systemctl is-active --quiet "$service"
      if [[ $? -eq 0 ]]; then
        echo "$service is active." >> "$TMP_LOG"
      else
        echo "$service failed to start." >> "$TMP_LOG"
      fi

      # Progress bar update
      count=$((count + 1))
      percent=$(( (count * 100) / total ))
      echo $percent
      sleep 1
    done
  } | dialog --backtitle "Enabling and Starting Services" --title "Service Check & Startup" --gauge "Checking services and starting them if needed..." 10 70 0

  # Final report
  if grep -q "failed to start" "$TMP_LOG"; then
    dialog --backtitle "Enabling and Starting Services" --title "Service Status" --textbox "$TMP_LOG" 20 70
  else
    dialog --backtitle "Enabling and Starting Services" --title "All Services Running" --infobox "All services have been enabled and are running." 7 60
   sleep 3
  fi

  rm -f "$TMP_LOG" "$TMP_BAR"
}
# ========= RECLAIM SPACE FROM HOME MAPPER (LVM) — QUIET NO-OP =========
remove_home_mapper() {
    # deps (quietly require essentials)
    need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
    need findmnt; need rsync; need lvs; need lvremove; need lvextend; need df; need awk
    command -v xfs_growfs >/dev/null 2>&1 || true
    command -v resize2fs  >/dev/null 2>&1 || true

    # no-op banner toggle (optional): export HOME_MAPPER_NOOP_INFO=1 to show brief notice
    NOOP_INFO="${HOME_MAPPER_NOOP_INFO:-0}"

    # dialog fallback if absent
    if ! command -v dialog >/dev/null 2>&1; then
        dialog() { :; }  # swallow messages when dialog isn't present
    fi

    # detect mounts/devices
    HOME_DEV="$(findmnt -n -o SOURCE /home 2>/dev/null || true)"
    ROOT_DEV="$(findmnt -n -o SOURCE /      2>/dev/null || true)"
    ROOT_FSTYPE="$(findmnt -n -o FSTYPE /   2>/dev/null || true)"

    # If /home is not a separate mount or not an LVM LV → quiet no-op
    if [[ -z "$HOME_DEV" ]] || [[ "$HOME_DEV" == "$ROOT_DEV" ]]; then
        if [[ "$NOOP_INFO" == "1" ]]; then dialog --infobox "No separate /home detected. Skipping…" 3 60; sleep 2; fi
        return 0
    fi
    # Confirm it's actually an LVM LV; if not, also treat as no-op
    if ! lvs --noheadings "$HOME_DEV" >/dev/null 2>&1; then
        if [[ "$NOOP_INFO" == "1" ]]; then dialog --infobox "/home is not an LVM LV. Skipping…" 3 60; sleep 2; fi
        return 0
    fi

    BACKUP_DIR="/root/home-backup"

    dialog --infobox "Backing up /home to $BACKUP_DIR …" 3 60
    mkdir -p "$BACKUP_DIR"
    if ! rsync -aHAX --numeric-ids --delete --exclude '/lost+found' /home/ "$BACKUP_DIR"/; then
        dialog --msgbox "Backup of /home failed. Aborting; nothing changed." 6 70
        return 1
    fi

    dialog --infobox "Unmounting /home …" 3 40
    if ! umount /home 2>/dev/null; then
        command -v fuser >/dev/null 2>&1 && fuser -km /home || true
        sleep 1
        umount -l /home || { dialog --msgbox "Could not unmount /home. Aborting." 6 60; return 1; }
    fi

    dialog --infobox "Removing logical volume $HOME_DEV …" 3 70
    if ! lvremove -y "$HOME_DEV" >/dev/null 2>&1; then
        dialog --msgbox "lvremove failed for $HOME_DEV. Backup left at $BACKUP_DIR; /home is unmounted." 7 70
        return 1
    fi

    # Fallback if ROOT_DEV wasn't detected cleanly
    [[ -n "$ROOT_DEV" ]] || ROOT_DEV="/dev/mapper/rl-root"

    dialog --infobox "Extending root LV to use all free space …" 3 70
    if ! lvextend -y -l +100%FREE "$ROOT_DEV" >/dev/null 2>&1; then
        dialog --msgbox "lvextend failed. Free space remains in the VG; please investigate." 6 70
    fi

    dialog --infobox "Growing root filesystem ($ROOT_FSTYPE) …" 3 60
    case "$ROOT_FSTYPE" in
      xfs)  xfs_growfs / >/dev/null 2>&1 || dialog --msgbox "xfs_growfs failed; grow root FS manually." 6 70 ;;
      ext4|ext3) resize2fs "$ROOT_DEV" >/dev/null 2>&1 || dialog --msgbox "resize2fs failed; grow root FS manually." 6 70 ;;
      *)    dialog --msgbox "Unknown root FS '$ROOT_FSTYPE'. Could not auto-grow." 6 70 ;;
    esac

    # Recreate /home and restore user data
    mkdir -p /home && chmod 755 /home
    if ! rsync -aHAX --numeric-ids "$BACKUP_DIR"/ /home/; then
        dialog --msgbox "Restore to /home failed. Data preserved in $BACKUP_DIR." 6 70
        return 1
    fi
    command -v restorecon >/dev/null 2>&1 && restorecon -R /home || true
    rm -rf "$BACKUP_DIR" || true

    # Remove /home from fstab if present
    if grep -Eq '^[^#].*[[:space:]]/home[[:space:]]' /etc/fstab; then
        cp -a /etc/fstab "/etc/fstab.bak.$(date +%s)"
        sed -i '/^[[:space:]]*[^#].*[[:space:]]\/home[[:space:]]/d' /etc/fstab
    fi

    dialog --infobox "Reclaimed /home space and merged into root. Done." 3 60
    sleep 1
}
#===========CLEANUP INSTALLATION FILES=============
cleanup_installer_files() {
  LOG_FILE="/var/log/rads-cleanup.log"
  TMP_PROGRESS=$(mktemp)

  {
    echo "10"; sleep 0.5
    echo "# Starting cleanup..." >> "$TMP_PROGRESS"

    # Remove DCInstall.sh launch block
    sed -i '/## Run CMDS installer on every interactive login ##/,/fi/d' /root/.bash_profile
    echo "[INFO] Removed CMDS installer launch block" >> "$LOG_FILE"
    echo "30"; sleep 0.5

    # Also remove any straggling DCInstall.sh lines
    sed -i '/CMDS2Install.sh/d' /root/.bash_profile
    echo "[INFO] Removed any additional CMDS2Install.sh entries" >> "$LOG_FILE"
    echo "50"; sleep 0.5

    # Delete installer-related files
    rm -rf /root/CMDS2-Installer.sh /root/CMDS2Installer >> "$LOG_FILE" 2>&1
    echo "[INFO] Removed installer files" >> "$LOG_FILE"
    echo "90"; sleep 0.5

    echo "100"
  } | dialog --backtitle "Installer Cleanup" --title "Cleanup Progress" --gauge "Cleaning up installer files..." 10 60 0

  rm -f "$TMP_PROGRESS"

  dialog --backtitle "Installer Cleanup" --title "Cleanup Complete" --infobox "Installer files have been successfully removed from the system." 6 80
  sleep 3
}
configure_dnf_automatic() {
    local CONFIG="/etc/dnf/automatic.conf"
    local BACKUP="/etc/dnf/automatic.conf.bak"
    local LOG="/tmp/dnf_automatic_setup.log"
    : > "$LOG"

    # 1. Inform the user
    dialog --backtitle "DNF Automatic Setup" --title "Configure Security Updates" \
        --infobox "This will enable SECURITY-ONLY updates.\n\nIt will also disable major OS upgrades.\n\nUpdate time will be left to system default" 10 60
        sleep 4

    # 2. Backup current config
    sudo cp -f "$CONFIG" "$BACKUP"
    echo "[INFO] Backed up $CONFIG to $BACKUP" >> "$LOG"

    # 3. Apply dnf-automatic settings
    sudo sed -i 's/^upgrade_type.*/upgrade_type = security/' "$CONFIG"
    sudo sed -i 's/^apply_updates.*/apply_updates = yes/' "$CONFIG"

    # 4. Remove any [timer] section from the config (let systemd handle it)
    sudo sed -i '/^\[timer\]/,/^$/d' "$CONFIG"

    # 5. Remove any old systemd override (Cockpit workaround)
    sudo rm -f /etc/systemd/system/dnf-automatic.timer.d/override.conf

    # 6. Reload systemd and restart timer
    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
    sudo systemctl enable --now dnf-automatic.timer

    # 7. Validate setup
    local STATUS_MSG=""
    local VALIDATE_OUTPUT
    VALIDATE_OUTPUT=$(grep -E 'upgrade_type|apply_updates' "$CONFIG")
    echo "$VALIDATE_OUTPUT" >> "$LOG"

    if echo "$VALIDATE_OUTPUT" | grep -q "apply_updates = yes"; then
        STATUS_MSG="Security updates enabled.\n"
    else
        dialog --title "Error" --msgbox "Configuration failed.\nCheck $CONFIG or $LOG." 7 50
        return 1
    fi

    if systemctl is-active --quiet dnf-automatic.timer; then
        STATUS_MSG+="Timer is active.\n"
    else
        STATUS_MSG+="⚠Timer is not running!\nCheck: journalctl -u dnf-automatic.timer\n"
    fi

    NEXT_RUN=$(systemctl list-timers --all | grep dnf-automatic.timer | awk '{print $1, $2}')
    STATUS_MSG+="\nNext scheduled run: $NEXT_RUN"

    dialog --backtitle "DNF Automatic Setup" --title "Setup Complete" --infobox "$STATUS_MSG" 12 60
    sleep 3
}
#===========FINAL INSTALLATION COMPLETE PROMPT=============
prompt_reboot_now() {
  dialog --backtitle "Installation Complete" --title "Installation Complete" \
    --yesno "Server Installation Complete!\n\nWould you like to reboot the system now?" 8 50

  if [[ $? -eq 0 ]]; then
    reboot
  fi
}
# ============================================================
# Service Installer Checklist
#  - Bind DNS (caching-only)  ✅
#  - NTP (Chrony)             ✅
#  - DHCP (Kea)               ✅ (new integration)
#  - NONE (continue)          ✅
#  All popups auto-close (no OK buttons) except where inputs/yes-no are needed.
# ============================================================

service_menu_checklist() {
  local BACKTITLE="Service Installer"
  local TITLE="Install/Configure Services"

  # Single-shot checklist (no loop-back)
  local selection
  selection=$(dialog --backtitle "$BACKTITLE" --title "$TITLE" --checklist \
"Space = toggle; Enter = continue. You can pick more than one.
Select \"Do not install any services (continue)\" to skip and move on." 19 80 8 \
    BIND "Bind DNS (caching-only)"                   OFF \
    KEA  "DHCP (Kea)"                                OFF \
    NTP  "NTP (Chrony)"                              OFF \
    NONE "Do not install any services (continue)"    OFF \
    3>&1 1>&2 2>&3)

  local rc=$?
  [[ $rc -ne 0 ]] && return 0  # ESC/Cancel → continue main installer

  # shellcheck disable=SC2206
  local choices=($selection)

  if [[ ${#choices[@]} -eq 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"No services selected. Continuing..." 6 60; sleep 2
    return 0
  fi

  local tag
  for tag in "${choices[@]}"; do
    tag="${tag%\"}"; tag="${tag#\"}"
    if [[ "$tag" == "NONE" ]]; then
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"No services will be installed. Continuing..." 6 60; sleep 2
      return 0
    fi
  done

  # Run selected installers in sequence, then return to caller
  for tag in "${choices[@]}"; do
    tag="${tag%\"}"; tag="${tag#\"}"
    case "$tag" in
      BIND) bind_caching_setup ;;
      KEA)  kea_dhcp_setup ;;
      NTP)  chrony_setup ;;
    esac
  done

  return 0
}

# -----------------------------
# Bind (caching-only) installer
# -----------------------------
bind_caching_setup() {
  local BACKTITLE="Service Installer"
  local TITLE="Bind (Caching-Only) Setup"
  local LOGFILE="/var/log/bind-caching-setup.log"
  local NAMED_CONF="/etc/named.conf"
  local NAMED_BAK="/etc/named.conf.bak.$(date +%Y%m%d-%H%M%S)"

  mkdir -p "$(dirname "$LOGFILE")" >/dev/null 2>&1
  : > "$LOGFILE"

  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --infobox "ERROR: This must be run as root (sudo)." 7 55
    sleep 2; return 1
  fi
  local OSMAJOR=""
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release; OSMAJOR="${VERSION_ID%%.*}"
  elif [[ -r /etc/redhat-release ]]; then
    OSMAJOR="$(grep -oE '[0-9]+' /etc/redhat-release | head -1 || true)"
  fi
  if ! [[ "$OSMAJOR" =~ ^[0-9]+$ && $OSMAJOR -ge 9 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" \
           --infobox "ERROR: Rocky Linux 9 or newer is required." 7 55
    sleep 2; return 1
  fi

  _gauge_update() { echo "XXX"; echo "$1"; shift; echo -e "$*"; echo "XXX"; }
  _run_step() { local pct="$1"; shift; local label="$1"; shift
    _gauge_update "$((pct-1))" "$label..."
    { "$@" >>"$LOGFILE" 2>&1; } || return 1
    _gauge_update "$pct" "$label...done"; sleep 0.3
  }

  {
    _gauge_update 1  "Starting Bind (caching-only) setup..."
    sleep 0.4
    _run_step 8  "Installing bind & bind-utils"    dnf -y -q install bind bind-utils || exit 1
    _run_step 15 "Enabling DNS service in firewall" firewall-cmd --zone=public --add-service=dns --permanent || exit 1
    _run_step 20 "Reloading firewall"               firewall-cmd --complete-reload || exit 1
    _run_step 30 "Backing up named.conf"            cp -f "$NAMED_CONF" "$NAMED_BAK" || exit 1

    _gauge_update 50 "Updating named.conf for caching-only..."
    {
      awk '
        BEGIN { inopt=0 }
        /^[[:space:]]*options[[:space:]]*\{/ {
          inopt=1
          print
          print "        listen-on port 53 { any; };"
          print "        listen-on-v6 { any; };"
          print "        allow-query { any; };"
          print "        recursion yes;"
          next
        }
        inopt && /^[[:space:]]*\}/ { inopt=0; print; next }
        inopt {
          if ($0 ~ /^[[:space:]]*listen-on([[:space:]]+port[[:space:]]+53)?[[:space:]]*\{/) next
          if ($0 ~ /^[[:space:]]*listen-on-v6([[:space:]]+port[[:space:]]+53)?[[:space:]]*\{/) next
          if ($0 ~ /^[[:space:]]*allow-query[[:space:]]*\{/) next
          if ($0 ~ /^[[:space:]]*recursion[[:space:]]+/) next
          print; next
        }
        { print }
      ' "$NAMED_CONF" > "${NAMED_CONF}.tmp" && mv -f "${NAMED_CONF}.tmp" "$NAMED_CONF"
    } >>"$LOGFILE" 2>&1 || exit 1
    _gauge_update 60 "Updating named.conf for caching-only...done"; sleep 0.3
    _run_step 70 "Validating named.conf"            named-checkconf -z || exit 1
    _run_step 85 "Enabling named (systemd)"         systemctl enable named || exit 1
    _run_step 95 "Starting named"                   systemctl restart named || exit 1
    _gauge_update 100 "Finalizing..."; sleep 0.5
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Initializing..." 18 90 0

  local NAMED_STATUS="unknown"
  systemctl is-active named >/dev/null 2>&1 && NAMED_STATUS="active" || NAMED_STATUS="inactive"

  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"Bind (caching-only) setup complete.

• named service: ${NAMED_STATUS}
• Config: /etc/named.conf (backup: ${NAMED_BAK})
• Log: ${LOGFILE}

Continuing..." 12 70
  sleep 2
  return 0
}

# -----------------------------
# Chrony NTP installer (from earlier)
# -----------------------------
chrony_setup() {
  local BACKTITLE="Service Installer"
  local TITLE="Chrony NTP Configuration"
  local LOG_NTP="/tmp/chrony_ntp_configure.log"
  local OSMAJOR=""

  touch "$LOG_NTP"
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "ERROR: This must be run as root (sudo)." 7 55
    sleep 2; return 1
  fi
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release; OSMAJOR="${VERSION_ID%%.*}"
  elif [[ -r /etc/redhat-release ]]; then
    OSMAJOR="$(grep -oE '[0-9]+' /etc/redhat-release | head -1 || true)"
  fi
  if ! [[ "$OSMAJOR" =~ ^[0-9]+$ && $OSMAJOR -ge 9 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "ERROR: Rocky Linux 9 or newer is required." 7 55
    sleep 2; return 1
  fi

  _gauge_update() { echo "XXX"; echo "$1"; shift; echo -e "$*"; echo "XXX"; }
  {
    _gauge_update 10 "Installing chrony..."
    dnf -y -q install chrony >>"$LOG_NTP" 2>&1 || exit 1
    _gauge_update 60 "Enabling and starting chronyd..."
    systemctl enable --now chronyd >>"$LOG_NTP" 2>&1 || exit 1
    _gauge_update 100 "Chrony base installed."
    sleep 0.4
  } | dialog --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Preparing..." 10 70 0

  declare -a ADDR

  log_ntp() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" >> "$LOG_NTP"; }
  validate_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }

  prompt_ntp_servers() {
    while true; do
      NTP_SERVERS=$(dialog --title "Chrony NTP Configuration" --backtitle "Configure NTP" \
        --inputbox "Enter up to 3 comma-separated NTP server IPs or FQDNs:" 8 70 3>&1 1>&2 2>&3)
      local exit_status=$?
      [[ $exit_status -ne 0 ]] && return 1
      if [[ -n "$NTP_SERVERS" ]]; then
        IFS=',' read -ra ADDR <<< "$NTP_SERVERS"
        if (( ${#ADDR[@]} > 3 )); then
          dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "You may only enter up to 3 servers." 6 60
          sleep 2; continue
        fi
        return 0
      else
        dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "The input cannot be blank. Please try again." 6 60
        sleep 2
      fi
    done
  }

  prompt_allow_networks() {
    while true; do
      ALLOW_NET=$(dialog --title "Allow NTP Access" --backtitle "Configure NTP" \
        --inputbox "Enter the CIDR range to allow NTP access (e.g., 192.168.1.0/24):" 8 80 3>&1 1>&2 2>&3)
      local exit_status=$?
      [[ $exit_status -ne 0 ]] && return 1
      if validate_cidr "$ALLOW_NET"; then
        return 0
      else
        dialog --backtitle "Configure NTP" --infobox "Invalid CIDR format. Please try again." 6 60
        sleep 2
      fi
    done
  }

  update_chrony_config() {
    cp /etc/chrony.conf /etc/chrony.conf.bak
    sed -i '/^\(server\|pool\|allow\)[[:space:]]/d' /etc/chrony.conf
    for srv in "${ADDR[@]}"; do
      echo "server ${srv} iburst" >> /etc/chrony.conf
      log_ntp "Added server ${srv} to chrony.conf"
    done
    if [[ -n "$ALLOW_NET" ]]; then
      echo "allow $ALLOW_NET" >> /etc/chrony.conf
      log_ntp "Added allow $ALLOW_NET to chrony.conf"
    fi
    systemctl restart chronyd
    sleep 1
  }

  validate_time_sync() {
    local attempt=1 success=0 TRACKING=""
    while (( attempt <= 3 )); do
      dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Validating time sync... Attempt $attempt/3" 5 60
      sleep 5
      TRACKING=$(chronyc tracking 2>&1)
      echo "$TRACKING" >> "$LOG_NTP"
      if echo "$TRACKING" | grep -q "Leap status[[:space:]]*:[[:space:]]*Normal"; then success=1; break; fi
      ((attempt++))
    done
    if [[ "$success" -eq 1 ]]; then
      dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Time synchronized successfully:\n\n$TRACKING" 15 100
      sleep 2; return 0
    else
      dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --yesno "Time sync failed after 3 attempts.\nDo you want to proceed anyway?" 8 80
      [[ $? -eq 0 ]] || return 1
      return 0
    fi
  }

  if ! prompt_ntp_servers; then
    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "NTP configuration cancelled." 6 50
    sleep 2; return 1
  fi
  if ! prompt_allow_networks; then
    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "No network was allowed. Configuration cancelled." 6 60
    sleep 2; return 1
  fi
  update_chrony_config
  if ! validate_time_sync; then
    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "Chrony configuration aborted." 6 50
    sleep 2; return 1
  fi
  dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "NTP configuration completed successfully.\nLog: $LOG_NTP" 7 80
  sleep 2; return 0
}

# -----------------------------
# Kea DHCP installer (NEW)
# -----------------------------
# Helpers used by Kea flow
_kea_infobox() { dialog --backtitle "Service Installer" --title "$1" --infobox "$2" "${3:-7}" "${4:-70}"; }
_enable_repos_with_gauge() {
  local log="/tmp/repo-setup.$(date +%s).log"; : >"$log"
  (
    dnf -y install dnf-plugins-core >>"$log" 2>&1 || exit 1
    dnf -y install epel-release     >>"$log" 2>&1 || exit 1
    dnf config-manager --set-enabled crb >>"$log" 2>&1 || exit 1
    dnf -y makecache --refresh      >>"$log" 2>&1 || exit 1
  ) &
  local pid=$!
  (
    local pct=0 msg="Enabling EPEL and CRB..."
    while kill -0 "$pid" 2>/dev/null; do
      (( pct < 95 )) && pct=$((pct+5))
      echo "$pct"; echo "XXX"; echo -e "$msg\n\nLog: $log"; echo "XXX"; sleep 0.5
    done
    echo 100; echo "XXX"; echo -e "Repositories enabled and metadata refreshed.\n\nLog: $log"; echo "XXX"
  ) | dialog --backtitle "Service Installer" --title "Repository Setup" --gauge "Preparing..." 10 70 0
  wait "$pid" || { _kea_infobox "Repository Setup Failed" "There was a problem enabling repositories.\n\nLog: $log"; sleep 2; return 1; }
  return 0
}
_run_gauge_cmd() {
  local title="$1"; shift
  local log="/tmp/$(basename "$1")-install.$(date +%s).log"; : >"$log"
  ( "$@" &> "$log"; echo $? >/tmp/.cmd_rc.$$ ) & local pid=$!
  (
    local pct=0
    while kill -0 "$pid" 2>/dev/null; do
      echo "$pct"; echo "XXX"; echo -e "Installing... Please wait.\nLog: $log"; echo "XXX"
      sleep 0.3; pct=$(( (pct + 2) % 97 ))
    done
    echo 100; echo "XXX"; echo "Finishing up..."; echo "XXX"
  ) | dialog --backtitle "Service Installer" --title "$title" --gauge "Preparing..." 10 70 0
  local rc=1
  [[ -f /tmp/.cmd_rc.$$ ]] && { rc="$(cat /tmp/.cmd_rc.$$)"; rm -f /tmp/.cmd_rc.$$; }
  if [[ "$rc" -ne 0 ]]; then
    _kea_infobox "Error" "$title failed.\n\nLog: $log"; sleep 2; return "$rc"
  else
    _kea_infobox "Success" "$title completed.\n\nLog: $log"; sleep 2; return 0
  fi
}
# IP / CIDR helpers
_is_valid_ip(){ [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { IFS=.; read -r a b c d <<<"$1"; [[ $a -le 255 && $b -le 255 && $c -le 255 && $d -le 255 ]]; }; }
_ip_to_int(){ local IFS=.; read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
_int_to_ip(){ local i=$1; printf "%d.%d.%d.%d" $(( (i>>24)&255 )) $(( (i>>16)&255 )) $(( (i>>8)&255 )) $(( i&255 )); }
_cidr_to_netmask(){ local c=$1; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); _int_to_ip "$m"; }
_netmask_to_cidr(){
  local ip=$1; $_is_valid_ip "$ip" || { echo -1; return; }
  local n=$(_ip_to_int "$ip") c=0 saw_zero=0
  for ((i=31;i>=0;i--)); do
    if (( (n>>i)&1 )); then (( saw_zero )) && { echo -1; return; }; ((c++))
    else saw_zero=1; fi
  done; echo "$c"
}
_network_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); _int_to_ip $(( $(_ip_to_int "$ip") & m )); }
_broadcast_from_ip_cidr(){ local ip=$1 c=$2; local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF )); _int_to_ip $(( $(_ip_to_int "$ip") | (~m & 0xFFFFFFFF) )); }
_ip_in_cidr(){
  local ip=$1 net=$2 c=$3
  local m=$(( 0xFFFFFFFF << (32-c) & 0xFFFFFFFF ))
  (( ( $(_ip_to_int "$ip") & m ) == ( $(_ip_to_int "$net") & m ) ))
}
_is_valid_domain(){
  local d="$1"
  [[ -n "$d" ]] || return 1
  [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}

kea_dhcp_setup() {
  local BACKTITLE="Service Installer"
  local TITLE="Kea DHCP Setup"
  local KEA_CONF="/etc/kea/kea-dhcp4.conf"

  # Root & OS checks
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "ERROR: Must be run as root (sudo)." 7 60
    sleep 2; return 1
  fi
  local OSMAJOR=""
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release; OSMAJOR="${VERSION_ID%%.*}"
  elif [[ -r /etc/redhat-release ]]; then
    OSMAJOR="$(grep -oE '[0-9]+' /etc/redhat-release | head -1 || true)"
  fi
  if ! [[ "$OSMAJOR" =~ ^[0-9]+$ && $OSMAJOR -ge 9 ]]; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "ERROR: Rocky Linux 9 or newer is required." 7 60
    sleep 2; return 1
  fi
  command -v nmcli >/dev/null 2>&1 || { dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "ERROR: nmcli not found. Install NetworkManager." 7 70; sleep 2; return 1; }

  # Enable repos + install kea
  _enable_repos_with_gauge || return 1
  _run_gauge_cmd "Installing Kea DHCP (kea)" dnf -y install kea || return 1

  # Detect interface and addressing
  local iface inet4_line INET4 CIDR NETWORK NETMASK BROADCAST
  iface=$(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1; exit}')
  if [[ -z "$iface" ]]; then dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "No active interface found." 6 50; sleep 2; return 1; fi
  inet4_line=$(nmcli -g IP4.ADDRESS device show "$iface" | head -n 1)
  if [[ -z "$inet4_line" ]]; then dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "No IPv4 address found on $iface." 6 60; sleep 2; return 1; fi

  INET4=${inet4_line%/*}
  CIDR=${inet4_line#*/}
  NETWORK=$(_network_from_ip_cidr "$INET4" "$CIDR")
  NETMASK=$(_cidr_to_netmask "$CIDR")
  BROADCAST=$(_broadcast_from_ip_cidr "$INET4" "$CIDR")

  # Gather settings
  local POOL_START POOL_END ROUTER DOM_SUFFIX SEARCH_DOMAIN DNS_SERVERS SUBNET_DESC
  local DEF_SUFFIX="$(hostname -d 2>/dev/null || true)"
  local DEF_SEARCH="${DEF_SUFFIX}"

  while true; do
    while true; do
      POOL_START=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter beginning IP of DHCP lease range (in $NETWORK/$CIDR):" 8 78)
      [[ -n "$POOL_START" ]] && _is_valid_ip "$POOL_START" && _ip_in_cidr "$POOL_START" "$NETWORK" "$CIDR" && break
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Start IP must be a valid IPv4 within $NETWORK/$CIDR." 6 78; sleep 2
    done
    while true; do
      POOL_END=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter ending IP of DHCP lease range:" 8 78)
      [[ -n "$POOL_END" ]] && _is_valid_ip "$POOL_END" && _ip_in_cidr "$POOL_END" "$NETWORK" "$CIDR" && \
        (( $(_ip_to_int "$POOL_START") <= $(_ip_to_int "$POOL_END") )) && break
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "End IP must be valid, in $NETWORK/$CIDR, and ≥ start IP." 6 78; sleep 2
    done
    while true; do
      ROUTER=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter default gateway for clients (in $NETWORK/$CIDR):" 8 78)
      [[ -n "$ROUTER" ]] && _is_valid_ip "$ROUTER" && _ip_in_cidr "$ROUTER" "$NETWORK" "$CIDR" && break
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Gateway must be a valid IPv4 within $NETWORK/$CIDR." 6 78; sleep 2
    done
    while true; do
      DOM_SUFFIX=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter domain suffix (for 'domain-name'):" 8 78 "${DEF_SUFFIX}")
      _is_valid_domain "$DOM_SUFFIX" && break
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Please enter a valid domain suffix like 'ad.example.com'." 6 78; sleep 2
    done
    while true; do
      SEARCH_DOMAIN=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
        "Enter search domain(s) for clients (comma-separated if multiple):" 9 78 "${DEF_SEARCH}")
      local ok=1 IFS=, item
      for item in $SEARCH_DOMAIN; do item="${item// /}"; _is_valid_domain "$item" || { ok=0; break; }; done
      [[ $ok -eq 1 ]] && break
      dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "One or more domains are invalid. Use comma-separated FQDNs." 6 78; sleep 2
    done
    DNS_SERVERS=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
      "Enter DNS servers (comma separated, or leave default to use $INET4):" 8 78 "$INET4")
    SUBNET_DESC=$(dialog --backtitle "$BACKTITLE" --stdout --inputbox \
      "Enter a friendly name/description for this subnet:" 8 78)

    dialog --backtitle "$BACKTITLE" --title "Kea DHCP Settings Review" --yesno \
"Interface:     $iface
Interface IP:  $INET4/$CIDR
Subnet:        $NETWORK/$CIDR
Broadcast:     $BROADCAST
Range:         $POOL_START  →  $POOL_END
Gateway:       $ROUTER
DNS:           $DNS_SERVERS
Domain:        $DOM_SUFFIX
Search:        $SEARCH_DOMAIN
Description:   $SUBNET_DESC

Are these settings correct?" 20 72 && break
  done

  # Write config
  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Creating $KEA_CONF ..." 6 60; sleep 1
  mkdir -p /etc/kea; touch "$KEA_CONF"
  cat <<EOF > "$KEA_CONF"
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": [ "$iface" ]
    },
    "lease-database": {
      "type": "memfile",
      "persist": true,
      "name": "/var/lib/kea/kea-leases4.csv"
    },
    "subnet4": [
      {
        "id": 1,
        "subnet": "$NETWORK/$CIDR",
        "interface": "$iface",
        "comment": "$SUBNET_DESC",
        "pools": [ { "pool": "$POOL_START - $POOL_END" } ],
        "option-data": [
          { "name": "routers",               "data": "$ROUTER" },
          { "name": "domain-name-servers",   "data": "$DNS_SERVERS" },
          { "name": "ntp-servers",           "data": "$DNS_SERVERS" },
          { "name": "domain-name",           "data": "$DOM_SUFFIX" },
          { "name": "domain-search",         "data": "$SEARCH_DOMAIN" }
        ]
      }
    ],
    "authoritative": true
  }
}
EOF
  chown root:kea "$KEA_CONF"
  chmod 640 "$KEA_CONF"
  restorecon "$KEA_CONF" 2>/dev/null || true

  # Syntax check, enable, start, firewall
  local syntax=""
  if ! syntax="$(kea-dhcp4 -t "$KEA_CONF" 2>&1)"; then
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Kea config test failed:\n\n$syntax" 12 100
    sleep 3; return 1
  fi

  systemctl enable --now kea-dhcp4 >/dev/null 2>&1 || {
    dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox "Failed to start kea-dhcp4. Check: systemctl status kea-dhcp4" 7 80
    sleep 2; return 1
  }

  firewall-cmd --zone=public --add-service=dhcp --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true

  # Final status
  local SVC="kea-dhcp4" ok_svc=0
  systemctl is-active --quiet "$SVC" && ok_svc=1
  dialog --backtitle "$BACKTITLE" --title "$TITLE" --infobox \
"Kea DHCP setup complete.

• Service:      $SVC ($( [[ $ok_svc -eq 1 ]] && echo active || echo inactive ))
• Config file:  $KEA_CONF

Tip:
  journalctl -u $SVC -b --no-pager | tail -n 50

Continuing..." 14 80
  sleep 2
  return 0
}
# ========= MAIN =========
detect_active_interface
prompt_static_ip_if_dhcp
check_root_and_os
check_and_enable_selinux
check_internet_connectivity
validate_and_set_hostname
show_server_checklist
service_menu_checklist
#configure_dhcp_server
# === Set Time ===
#if ! prompt_ntp_servers; then
#    dialog --title "Chrony NTP Configuration" --msgbox "NTP configuration was cancelled." 6 40
#    exit 1
#fi

#if ! prompt_allow_networks; then
#    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "No network was allowed. Configuration cancelled." 6 50
#    exit 1
#fi

#update_chrony_config

#if ! validate_time_sync; then
#    dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --msgbox "Chrony configuration aborted." 6 40
#    exit 1
#fi

#dialog --backtitle "Configure NTP" --title "Chrony NTP Configuration" --infobox "NTP configuration completed successfully." 4 60
#sleep 3
#=== End Set time ===
update_and_install_packages
vm_detection
configure_firewall
update_issue_file
python310_setup_module
tftp_setup_module
http_repo_setup_module
create_iosxe_symlink_module
images_autofix_module
configure_fail2ban
configure_dnf_automatic
check_and_enable_services
cleanup_installer_files
prompt_reboot_now
