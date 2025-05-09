#!/usr/bin/env python3
import sys
from netmiko import ConnectHandler

if len(sys.argv) != 7:
    print("Usage: netmiko_remediate.py <ip> <username> <password> <what> <dns_ip> <ntp_ip>")
    sys.exit(1)

ip, username, password, what, dns_ip, ntp_ip = sys.argv[1:]

device = {
    "device_type": "cisco_ios",
    "host": ip,
    "username": username,
    "password": password,
}

try:
    net_connect = ConnectHandler(**device)

    if what == "dns":
        net_connect.send_config_set([f"ip name-server {dns_ip}"])
        ping = net_connect.send_command("ping google.com")
        print("[SUCCESS] DNS appears to be working" if "!!!!" in ping else "[WARN] DNS ping failed")

    elif what == "ntp":
        net_connect.send_config_set([f"ntp server {ntp_ip}"])
        ntp_status = net_connect.send_command("show ntp status")
        print("[SUCCESS] NTP is synchronized" if "synchronized" in ntp_status.lower() else "[WARN] NTP is NOT synchronized")

    elif what == "aaa":
        net_connect.send_config_set(["aaa new-model"])
        result = net_connect.send_command("show run | include aaa new-model")
        print("[SUCCESS] AAA new-model enabled" if "aaa new-model" in result else "[ERROR] Failed to enable AAA new-model")

    else:
        print(f"[ERROR] Unknown remediation type: {what}")
        sys.exit(1)

    net_connect.save_config()
    net_connect.disconnect()

except Exception as e:
    print(f"[ERROR] {e}")
    sys.exit(1)
