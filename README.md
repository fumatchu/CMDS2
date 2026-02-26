With the changes of Meraki platform/Catalyst integration, this is version 2 of CMDS that allows an individual to migrate 
switches leveraging service meraki connect in the IOS-XE packaging 

This allows automated onboarding of the C92/93/95 series switches in single or stack scenarios, Keeping IOS-XE intact (device local), or replacing IOS-XE with Meraki CS code. 





Installing and requirements 

A Base install of Rocky Linx is required (10.1)
https://rockylinux.org/download

Rocky Linux 10 officially supports the following architectures:

x86_64-v3 (Intel/AMD 64-bit CPUs with at least Haswell or equivalent AVX support)
aarch64 (ARMv8-A 64-bit)
ppc64le (IBM Power, Little Endian)
s390x (IBM Z mainframes)
riscv64 (RISC‑V 64-bit)
⚠️ CPU Feature Requirements¶
x86_64-v3 requires AVX, AVX2, BMI1/2, and FMA, corresponding to Intel Haswell or later, or AMD Excavator or newer.
Older x86_64 revisions (v1/v2) are not supported unless rebuilt by community SIGs.

Before installing CMDS it's required to enable root access and SSH access for the root account during the Rocky install process.
A Static IP address is required and Internet access is also required. 

After Rocky OS installation, within this REPO, 
