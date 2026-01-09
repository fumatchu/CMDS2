#!/bin/bash
#Bootstrap to GIT REPO

GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
TEXTRESET="\033[0m"
CYAN="\e[36m"
RESET="\e[0m"

# Set FORCE_PLATFORM=rpi4 or rpi5 (or esxi/kvm) to simulate detection in a VM
FORCE_PLATFORM="${FORCE_PLATFORM:-}"

USER=$(whoami)

clear
echo -e "${CYAN}CMDS2${TEXTRESET} ${YELLOW}Bootstrap${TEXTRESET}"

# =========================
# Platform detection (ESXi / KVM / Raspberry Pi 4/5)
# =========================
detect_platform() {
  # --- Test override ---
  if [[ -n "$FORCE_PLATFORM" ]]; then
    case "$FORCE_PLATFORM" in
      rpi4)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: Raspberry Pi (Raspberry Pi 4) [FORCED]"
        DETECTED_PLATFORM="rpi"
        DETECTED_PLATFORM_DETAIL="Raspberry Pi 4 [FORCED]"
        return 0
        ;;
      rpi5)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: Raspberry Pi (Raspberry Pi 5) [FORCED]"
        DETECTED_PLATFORM="rpi"
        DETECTED_PLATFORM_DETAIL="Raspberry Pi 5 [FORCED]"
        return 0
        ;;
      rpi2|rpi3|rpi)
        echo -e "[${RED}ERROR${TEXTRESET}] Unsupported Raspberry Pi platform forced: ${FORCE_PLATFORM}"
        echo -e "Rocky Linux 10.1 requires ${GREEN}Raspberry Pi 4 or newer${TEXTRESET}."
        echo "Exiting..."
        exit 1
        ;;
      esxi)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: ESXi/VMware (VMware Virtual Platform) [FORCED]"
        DETECTED_PLATFORM="vmware"
        DETECTED_PLATFORM_DETAIL="VMware Virtual Platform [FORCED]"
        return 0
        ;;
      kvm)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: KVM/QEMU (KVM) [FORCED]"
        DETECTED_PLATFORM="kvm"
        DETECTED_PLATFORM_DETAIL="KVM [FORCED]"
        return 0
        ;;
      *)
        echo -e "[${RED}ERROR${TEXTRESET}] Unknown FORCE_PLATFORM value: ${FORCE_PLATFORM}"
        echo -e "Valid values: ${GREEN}rpi4, rpi5, esxi, kvm${TEXTRESET}"
        echo "Exiting..."
        exit 1
        ;;
    esac
  fi

  DETECTED_PLATFORM="physical"
  DETECTED_PLATFORM_DETAIL="Unknown/Physical"

  # --- Raspberry Pi detection (most reliable on ARM SBCs) ---
  if [[ -f /proc/device-tree/model ]]; then
    local model
    model=$(tr -d '\0' </proc/device-tree/model)

    case "$model" in
      *"Raspberry Pi 4"*)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: Raspberry Pi (Raspberry Pi 4)"
        DETECTED_PLATFORM="rpi"
        DETECTED_PLATFORM_DETAIL="Raspberry Pi 4"
        return 0
        ;;
      *"Raspberry Pi 5"*)
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: Raspberry Pi (Raspberry Pi 5)"
        DETECTED_PLATFORM="rpi"
        DETECTED_PLATFORM_DETAIL="Raspberry Pi 5"
        return 0
        ;;
      *"Raspberry Pi"*)
        echo -e "[${RED}ERROR${TEXTRESET}] Unsupported Raspberry Pi hardware detected."
        echo -e "Detected model: ${model}"
        echo -e "Rocky Linux 10.1 requires ${GREEN}Raspberry Pi 4 or newer${TEXTRESET}."
        echo "Exiting..."
        exit 1
        ;;
    esac
  fi

  # --- Virtualization detection ---
  local virt=""
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt=$(systemd-detect-virt 2>/dev/null || true)
  fi

  # DMI hints (works on most VMs / x86)
  local dmi_product="" dmi_vendor=""
  [[ -r /sys/class/dmi/id/product_name ]] && dmi_product=$(tr -d '\0' </sys/class/dmi/id/product_name)
  [[ -r /sys/class/dmi/id/sys_vendor   ]] && dmi_vendor=$(tr -d '\0' </sys/class/dmi/id/sys_vendor)

  # ESXi / VMware
  if [[ "$virt" == "vmware" ]] || [[ "$dmi_vendor" =~ VMware|VMware,\ Inc\. ]] || [[ "$dmi_product" =~ VMware|VMware\ Virtual\ Platform ]]; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: ESXi/VMware (${dmi_product:-vmware})"
    DETECTED_PLATFORM="vmware"
    DETECTED_PLATFORM_DETAIL="${dmi_product:-vmware}"
    return 0
  fi

  # KVM / QEMU
  if [[ "$virt" == "kvm" || "$virt" == "qemu" ]] || [[ "$dmi_product" =~ KVM|QEMU|Virtual\ Machine ]] || [[ "$dmi_vendor" =~ QEMU|Red\ Hat|oVirt ]]; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Platform detected: KVM/QEMU (${dmi_product:-$virt})"
    DETECTED_PLATFORM="kvm"
    DETECTED_PLATFORM_DETAIL="${dmi_product:-$virt}"
    return 0
  fi

  # Some other virtualization
  if [[ -n "$virt" && "$virt" != "none" ]]; then
    echo -e "[${YELLOW}INFO${TEXTRESET}] Platform detected: Virtual Machine (${virt})"
    DETECTED_PLATFORM="vm"
    DETECTED_PLATFORM_DETAIL="$virt"
    return 0
  fi

  # Otherwise likely bare metal
  echo -e "[${YELLOW}INFO${TEXTRESET}] Platform detected: Unknown/Physical"
  return 0
}

# =========================
# Helper: get free GB on /
# =========================
get_root_free_gb() {
  local gb
  gb=$(df -BG / | awk 'NR==2 {gsub(/G/, "", $4); print $4}')
  if ! [[ "$gb" =~ ^[0-9]+$ ]]; then
    echo ""
    return 1
  fi
  echo "$gb"
  return 0
}

# =========================
# Raspberry Pi rootfs expand (ROOT RUN ONLY)
# =========================
pi_maybe_expand_rootfs() {
  # Only for Raspberry Pi, and only when running as root
  [[ "${DETECTED_PLATFORM}" == "rpi" ]] || return 0
  [[ "$(id -un)" == "root" ]] || return 0

  local free_gb
  free_gb="$(get_root_free_gb)" || free_gb=""

  if [[ -z "$free_gb" ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine available disk space on root filesystem."
    echo "Exiting..."
    exit 1
  fi

  # Already good
  if (( free_gb >= 8 )); then
    return 0
  fi

  echo
  echo -e "[${RED}ERROR${TEXTRESET}] Insufficient disk space on root filesystem."
  echo -e "[${YELLOW}INFO${TEXTRESET}] Detected: ${free_gb}GB available on / — ${GREEN}8GB+ required${TEXTRESET}."
  echo -e "[${YELLOW}INFO${TEXTRESET}] On Raspberry Pi images, it's common for the root partition to be left small until expanded."
  echo

  if ! command -v rootfs-expand >/dev/null 2>&1; then
    echo -e "[${RED}ERROR${TEXTRESET}] 'rootfs-expand' was not found on this system."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Please expand the root filesystem manually, then re-run this installer."
    echo "Exiting..."
    exit 1
  fi

  echo -e "[${YELLOW}INFO${TEXTRESET}] Current storage summary:"
  df -h / || true
  echo

  read -r -p "Run rootfs-expand now to grow / to the maximum available size? [y/N]: " ans
  case "$ans" in
    y|Y|yes|YES)
      echo -e "[${YELLOW}INFO${TEXTRESET}] Running: rootfs-expand"
      if rootfs-expand; then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] rootfs-expand completed."
      else
        echo -e "[${RED}ERROR${TEXTRESET}] rootfs-expand failed."
        echo -e "[${YELLOW}INFO${TEXTRESET}] Please expand the root filesystem manually, then re-run this installer."
        echo "Exiting..."
        exit 1
      fi

      echo
      echo -e "[${YELLOW}INFO${TEXTRESET}] Re-checking available space on / ..."
      free_gb="$(get_root_free_gb)" || free_gb=""
      if [[ -z "$free_gb" ]]; then
        echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine available disk space after expansion."
        echo "Exiting..."
        exit 1
      fi

      if (( free_gb >= 8 )); then
        echo -e "[${GREEN}SUCCESS${TEXTRESET}] Root filesystem now has ${free_gb}GB available (meets 8GB requirement)."
        echo
        return 0
      fi

      echo -e "[${RED}ERROR${TEXTRESET}] Root filesystem still does not meet requirements after expansion."
      echo -e "[${YELLOW}INFO${TEXTRESET}] Detected: ${free_gb}GB available — ${GREEN}8GB or more${TEXTRESET} is required."
      echo -e "[${YELLOW}INFO${TEXTRESET}] This typically means the SD card / disk itself is too small, or the image/partition layout limits growth."
      echo "Exiting..."
      exit 1
      ;;
    *)
      echo -e "[${RED}ERROR${TEXTRESET}] Cannot proceed without at least 8GB available on /."
      echo -e "[${YELLOW}INFO${TEXTRESET}] Re-run this installer after expanding the root filesystem."
      echo "Exiting..."
      exit 1
      ;;
  esac
}

# =========================
# Raspberry Pi precheck:
# 1) If NOT root, prompt to set root password (sudo passwd root)
# 2) Ensure sshd allows root PASSWORD login and restart sshd if needed
# Must run BEFORE the later "must be root" check.
# =========================
pi_root_setup_and_ssh() {
  [[ "${DETECTED_PLATFORM}" == "rpi" ]] || return 0

  local effective_user logged_in_user
  effective_user="$(id -un)"
  logged_in_user="${SUDO_USER:-}"
  if [[ -z "$logged_in_user" ]]; then
    logged_in_user="$(logname 2>/dev/null || true)"
  fi
  [[ -z "$logged_in_user" ]] && logged_in_user="$effective_user"

  echo -e "[${YELLOW}INFO${TEXTRESET}] Raspberry Pi detected (${DETECTED_PLATFORM_DETAIL})."
  echo -e "[${YELLOW}INFO${TEXTRESET}] Logged-in user: ${logged_in_user} (effective user: ${effective_user})"

  # Ensure sudo is present
  if ! command -v sudo >/dev/null 2>&1; then
    echo -e "[${RED}ERROR${TEXTRESET}] sudo is not available. Cannot proceed with Raspberry Pi setup."
    echo "Exiting..."
    exit 1
  fi

  echo -e "[${YELLOW}INFO${TEXTRESET}] Verifying sudo access..."
  if sudo -n true 2>/dev/null; then
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] sudo access verified (non-interactive)."
  else
    # KEEP THIS LINE (per your request)
    echo -e "[${YELLOW}INFO${TEXTRESET}] You will now be prompted for your current user's sudo password (${logged_in_user}) if required."
    if sudo -k true; then
      echo -e "[${GREEN}SUCCESS${TEXTRESET}] sudo access verified."
    else
      echo -e "[${RED}ERROR${TEXTRESET}] sudo authentication failed or user not permitted to run sudo."
      echo "Exiting..."
      exit 1
    fi
  fi

  local root_password_set=0
  local ssh_changed=0

  # Step 1: If not root, set root password (interactive)
  if [[ "$effective_user" != "root" ]]; then
    echo
    echo -e "[${YELLOW}INFO${TEXTRESET}] Next step: set the password for the ${GREEN}root${TEXTRESET} account."
    echo -e "[${YELLOW}INFO${TEXTRESET}] You may see a sudo prompt first (this is the password for user ${logged_in_user})."
    echo -e "[${YELLOW}INFO${TEXTRESET}] After that, the prompts are for the ROOT password (New password / Retype)."
    echo

    if sudo passwd root; then
      echo -e "[${GREEN}SUCCESS${TEXTRESET}] Root password has been set."
      root_password_set=1
    else
      echo -e "[${RED}ERROR${TEXTRESET}] Failed to set the root password."
      echo "Exiting..."
      exit 1
    fi
  else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Already running as root on Raspberry Pi."
  fi

  # Step 2: Check effective sshd values and enable root PASSWORD login if needed
  local eff_prl eff_pwa
  eff_prl="$(sudo sshd -T 2>/dev/null | awk '/^permitrootlogin /{print $2; exit}')"
  eff_pwa="$(sudo sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2; exit}')"

  if [[ -z "$eff_prl" || -z "$eff_pwa" ]]; then
    echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine effective sshd settings via 'sshd -T'."
    echo "Exiting..."
    exit 1
  fi

  if [[ "$eff_prl" != "yes" || "$eff_pwa" != "yes" ]]; then
    echo
    echo -e "[${YELLOW}INFO${TEXTRESET}] We must verify SSH privileges for the root account."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Current effective SSH settings:"
    echo -e "  - permitrootlogin: ${eff_prl}"
    echo -e "  - passwordauthentication: ${eff_pwa}"
    echo

    read -r -p "Enable root SSH login with PASSWORD and restart sshd now? [y/N]: " ans
    case "$ans" in
      y|Y|yes|YES)
        local sshd_cfg="/etc/ssh/sshd_config"

        echo -e "[${YELLOW}INFO${TEXTRESET}] Updating ${sshd_cfg}..."

        sudo sed -ri 's/^[[:space:]]*(PermitRootLogin[[:space:]]+.*)$/#\1/g' "$sshd_cfg"
        sudo sed -ri 's/^[[:space:]]*(PasswordAuthentication[[:space:]]+.*)$/#\1/g' "$sshd_cfg"

        {
          echo ""
          echo "# Added by CMDS2 bootstrap for Raspberry Pi root SSH access"
          echo "PermitRootLogin yes"
          echo "PasswordAuthentication yes"
        } | sudo tee -a "$sshd_cfg" >/dev/null

        echo -e "[${YELLOW}INFO${TEXTRESET}] Restarting sshd (sudo systemctl restart sshd)..."
        if sudo systemctl restart sshd; then
          echo -e "[${GREEN}SUCCESS${TEXTRESET}] sshd restarted. Root SSH password login should now be allowed."
          ssh_changed=1
        else
          echo -e "[${RED}ERROR${TEXTRESET}] Failed to restart sshd."
          echo "Exiting..."
          exit 1
        fi
        ;;
      *)
        echo -e "[${RED}ERROR${TEXTRESET}] Root SSH password access not enabled. Cannot proceed on Raspberry Pi."
        echo "Exiting..."
        exit 1
        ;;
    esac
  else
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] SSH already allows root password login (PermitRootLogin yes, PasswordAuthentication yes)."
  fi

  # Final instruction to user (logout/relogin as root)
  if (( root_password_set == 1 || ssh_changed == 1 )); then
    echo
    echo -e "[${GREEN}SUCCESS${TEXTRESET}] Raspberry Pi bootstrap prerequisites completed."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Please log out of your current SSH session (${logged_in_user}) and log back in as ${GREEN}root${TEXTRESET} using the new root password you just set."
    echo -e "[${YELLOW}INFO${TEXTRESET}] Then re-run this installer as root."
    echo
  fi
}

# Call platform detection early, then Pi setup (before enforcing "must be root")
detect_platform
pi_root_setup_and_ssh

# Friendlier guidance on Pi before the root gate
if [[ "${DETECTED_PLATFORM}" == "rpi" && "$(id -un)" != "root" ]]; then
  echo -e "[${YELLOW}INFO${TEXTRESET}] Raspberry Pi detected: please SSH back in as ${GREEN}root${TEXTRESET}, then re-run this installer."
fi

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
  OSVER_RAW=$(grep -oP '(?<=^VERSION_ID=")[^"]+' /etc/os-release 2>/dev/null)
elif [[ -f /etc/redhat-release ]]; then
  OSVER_RAW=$(grep -oE '[0-9]+(\.[0-9]+)?' /etc/redhat-release | head -1)
fi

if [[ -z "$OSVER_RAW" ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to detect a valid Rocky Linux version."
  echo "Exiting..."
  exit 1
fi

OSVER_MAJOR=$(echo "$OSVER_RAW" | awk -F. '{print $1}')
OSVER_MINOR=$(echo "$OSVER_RAW" | awk -F. '{print ($2==""?0:$2)}')

if ! [[ "$OSVER_MAJOR" =~ ^[0-9]+$ && "$OSVER_MINOR" =~ ^[0-9]+$ ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to parse Rocky Linux version from: ${OSVER_RAW}"
  echo "Exiting..."
  exit 1
fi

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
# If Raspberry Pi and too small, offer rootfs-expand (ROOT ONLY)
# =========================
ROOT_FREE_GB="$(get_root_free_gb)" || ROOT_FREE_GB=""

if [[ -z "$ROOT_FREE_GB" ]]; then
  echo -e "[${RED}ERROR${TEXTRESET}] Unable to determine available disk space on root filesystem."
  echo "Exiting..."
  exit 1
fi

if (( ROOT_FREE_GB >= 8 )); then
  echo -e "[${GREEN}SUCCESS${TEXTRESET}] Root filesystem has ${ROOT_FREE_GB}GB available (minimum 8GB required)."
  sleep 2
else
  # If Pi, try to expand; otherwise fail immediately.
  if [[ "${DETECTED_PLATFORM}" == "rpi" ]]; then
    pi_maybe_expand_rootfs
  else
    echo -e "[${RED}ERROR${TEXTRESET}] Insufficient disk space on root filesystem."
    echo -e "Detected: ${ROOT_FREE_GB}GB available — ${GREEN}8GB or more${TEXTRESET} is required."
    echo "Exiting..."
    exit 1
  fi
fi

echo -e "${CYAN}==>Retrieving requirements for the installer...${TEXTRESET}"

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

dnf -y install wget git ipcalc dialog >/dev/null 2>&1 &
dnf_pid=$!
spinner "$dnf_pid"

echo -e "${CYAN}==>Retrieving files from Github...${TEXTRESET}"
sleep 1

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