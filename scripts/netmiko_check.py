#!/usr/bin/env python3
import sys
import json
from netmiko import ConnectHandler

if len(sys.argv) != 4:
    print("Usage: netmiko_check.py <ip> <username> <password>")
    sys.exit(1)

ip, username, password = sys.argv[1:]

device = {
    "device_type": "cisco_ios",
    "host": ip,
    "username": username,
    "password": password,
}

try:
    net_connect = ConnectHandler(**device)

    version_raw = net_connect.send_command("show version | include IOS XE")
    ios_version = None
    for line in version_raw.splitlines():
        if "IOS XE Software" in line:
            ios_version = line.split()[-1]
            break

    dns_config = net_connect.send_command("show run | include ip name-server")
    dns_ok = bool(dns_config.strip())

    ntp_status = net_connect.send_command("show ntp status")
    ntp_ok = "synchronized" in ntp_status.lower()

    aaa_check = net_connect.send_command("show run | include aaa new-model")
    aaa_ok = "aaa new-model" in aaa_check

    output = {
        "ios_version": ios_version or "unknown",
        "dns_configured": dns_ok,
        "ntp_synced": ntp_ok,
        "aaa_enabled": aaa_ok,
    }

    print(json.dumps(output))
    net_connect.disconnect()

except Exception as e:
    print(f"[ERROR] {e}")
    sys.exit(1)
