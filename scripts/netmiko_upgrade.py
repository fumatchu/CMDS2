#!/usr/bin/env python3
from netmiko import ConnectHandler
import sys

if len(sys.argv) != 8:
    print("Usage: netmiko_upgrade.py <switch_ip> <username> <password> <scp_server> <scp_user> <scp_pass> <ios_path>")
    sys.exit(1)

switch_ip, username, password, scp_server, scp_user, scp_pass, ios_path = sys.argv[1:]

device = {
    "device_type": "cisco_ios",
    "ip": switch_ip,
    "username": username,
    "password": password,
}

try:
    net_connect = ConnectHandler(**device)

    net_connect.send_config_set(["ip scp server enable"])
    ios_filename = ios_path.split("/")[-1]
    dest_path = f"flash:/{ios_filename}"
    copy_cmd = f"copy scp://{scp_user}@{scp_server}{ios_path} {dest_path}"

    output = net_connect.send_command_timing(copy_cmd)
    if "Password:" in output:
        output += net_connect.send_command_timing(scp_pass, strip_prompt=False, strip_command=False)

    if "Destination filename" in output:
        output += net_connect.send_command_timing("\n", strip_prompt=False, strip_command=False)

    print("[INFO] IOS image copy initiated.")
    print(output)

    net_connect.send_config_set([
        f"boot system flash:{ios_filename}",
        "end"
    ])
    net_connect.save_config()
    print("[SUCCESS] Boot system set and config saved.")

    net_connect.disconnect()

except Exception as e:
    print(f"[ERROR] {e}")
    sys.exit(1)
