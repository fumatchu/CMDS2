# CMDS2 – Meraki / Catalyst Migration Platform

With the changes to the Meraki platform and Catalyst integration, this is **Version 2 of CMDS**, designed to migrate switches leveraging **Service Meraki Connect** within IOS-XE packaging.

CMDS2 enables automated onboarding of:

- C9200
- C9300
- C9500

Supports:

- Single switch deployments
- Stack deployments
- Keeping IOS-XE intact (device local mode)
- Replacing IOS-XE with Meraki CS code (cloud mode)

---

## Installation & Requirements

### Base OS Requirement

A base installation of **Rocky Linux 10.1** is required.

Download:
https://rockylinux.org/download

### Supported Architectures (Rocky Linux 10)

- `x86_64-v3` (Intel/AMD 64-bit CPUs with Haswell or newer AVX support)
- `aarch64` (ARMv8-A 64-bit)
- `ppc64le` (IBM Power, Little Endian)
- `s390x` (IBM Z mainframes)
- `riscv64` (RISC-V 64-bit)

### CPU Feature Requirements

`x86_64-v3` requires:

- AVX
- AVX2
- BMI1
- BMI2
- FMA

Equivalent to:

- Intel Haswell or newer
- AMD Excavator or newer

Older x86_64 revisions (v1/v2) are not supported unless rebuilt by community SIGs.

---

## System Requirements

Before installing CMDS2:

- Enable root access during Rocky installation
- Enable SSH access for root
- Configure a static IP address
- Ensure internet connectivity

---

## Installation

After Rocky OS installation, run:

```bash
sudo dnf -y install wget && cd "$HOME" && bash <(wget -qO- https://raw.githubusercontent.com/fumatchu/CMDS2/main/CMDS2-Installer.sh)
