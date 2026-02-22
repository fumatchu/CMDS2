#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Cloud Admin – Mgmt IP Migration (IOS-XE cfg -> Meraki Dashboard)
#
# What it does (per your requirements):
#   - Builds a selectable list of candidate switches (blacklisted hidden)
#   - User can CHECK/UNCHECK multiple switches (checklist)
#   - For each selected switch:
#       * Find latest IOS-XE cfg in /var/lib/tftpboot/mig based on hostname/stack/device_name/pid prefix
#       * Read mgmt VLAN from meraki_discovery.env (HTTP_CLIENT_VLAN_ID)
#       * If mgmt VLAN has static "ip address A.B.C.D M.M.M.M":
#           - Collect DNS (ip name-server) else use DNS_PRIMARY/SECONDARY from env
#           - Collect GW (ip default-gateway) else default-route next-hop (validated in subnet)
#           - Update Meraki device managementInterface using cloud_id as "serial"
#           - If Meraki already has the same static settings => SKIPPED (not error)
#       * If DHCP / no static => DHCP_NO_CHANGE (not error)
#   - Logs to /root/.cloud_admin/runs/mgmt_ip/<run_id>/actions.log
#   - latest symlink points to the most recent run dir
#   - Dialog:
#       * Checklist selection screen (shows cloud_id + hostname + mgmt VLAN)
#       * Gauge progress while processing
#       * Final summary shows counts only (NO file paths)
# ============================================================

CLOUD_ADMIN_ROOT="/root/.cloud_admin"
IOS_CFG_DIR="/var/lib/tftpboot/mig"
DISC_ENV="${CLOUD_ADMIN_ROOT}/meraki_discovery.env"
MEM_DIR="${CLOUD_ADMIN_ROOT}/meraki_memory"
DISCOVERY_JSON="${CLOUD_ADMIN_ROOT}/discovery_results.json"
UPGRADE_PLAN_JSON="${CLOUD_ADMIN_ROOT}/upgrade_plan.json"

: "${DIALOG:=dialog}"
: "${BACKTITLE:=Cloud Admin – Mgmt IP Migration}"
: "${TITLE:=Mgmt IP Migration}"

RUNS_ROOT="${CLOUD_ADMIN_ROOT}/runs/mgmt_ip"
RUN_ID="mgmtip-$(date +%Y%m%d%H%M%S)"
RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
LOG_FILE="${RUN_DIR}/actions.log"
REPORT_JSON="${RUN_DIR}/report.json"
LATEST_LINK="${RUNS_ROOT}/latest"
SWITCH_INDEX_TSV="${RUN_DIR}/switch_index.tsv"

# ----------------------------
# dialog helpers
# ----------------------------
DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi

dlg() {
  local common=(--backtitle "$BACKTITLE" --title "$TITLE")
  if [[ $DIALOG_HAS_STDOUT -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --stdout "$@"
  else
    local out
    out="$(mktemp)"
    if "$DIALOG" "${common[@]}" "$@" 2>"$out"; then
      cat "$out"
      rm -f "$out"
      return 0
    else
      rm -f "$out"
      return 1
    fi
  fi
}

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing command: $1" >&2; exit 1; }; }

# No log paths in dialog popups
die() {
  log "FATAL: $*"
  "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "ERROR:\n\n$*\n" 12 70 || true
  exit 1
}

log() {
  mkdir -p "$RUN_DIR" >/dev/null 2>&1 || true
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  # Always append to file; avoid any dialog spam
  echo "[$ts] $*" >>"$LOG_FILE"
}

trim() { sed -e 's/^[[:space:]]\+//' -e 's/[[:space:]]\+$//'; }

ip_is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  local -a o
  read -r -a o <<<"$ip"
  (( o[0] <= 255 && o[1] <= 255 && o[2] <= 255 && o[3] <= 255 )) || return 1
  return 0
}

ip_in_same_subnet() {
  local ip="$1" mask="$2" gw="$3"
  python3 - "$ip" "$mask" "$gw" <<'PY'
import sys, ipaddress
ip,mask,gw=sys.argv[1:4]
try:
  net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
  ok = ipaddress.IPv4Address(gw) in net
  sys.exit(0 if ok else 1)
except Exception:
  sys.exit(1)
PY
}

# ----------------------------
# load env
# ----------------------------
load_discovery_env() {
  [[ -f "$DISC_ENV" ]] || die "Missing ${DISC_ENV}"
  # shellcheck disable=SC1090
  source "$DISC_ENV"

  : "${MERAKI_API_KEY:=}"
  : "${DNS_PRIMARY:=}"
  : "${DNS_SECONDARY:=}"
  : "${HTTP_CLIENT_VLAN_ID:=}"

  [[ -n "$MERAKI_API_KEY" ]] || die "MERAKI_API_KEY missing in meraki_discovery.env"
  [[ -n "$HTTP_CLIENT_VLAN_ID" ]] || die "HTTP_CLIENT_VLAN_ID missing in meraki_discovery.env"
  [[ "$HTTP_CLIENT_VLAN_ID" =~ ^[0-9]+$ ]] || die "HTTP_CLIENT_VLAN_ID is not numeric: $HTTP_CLIENT_VLAN_ID"
}

# ----------------------------
# parsing from IOS cfg
# ----------------------------

# returns:
#   STATIC: "A.B.C.D M.M.M.M"
#   DHCP:   "DHCP"
#   NONE:   "" (no mgmt ip config detected under vlan)
parse_vlan_mgmt_mode_from_cfg() {
  local cfg="$1" vid="$2"
  awk -v vid="$vid" '
    BEGIN { in_if=0; mode=""; ip=""; mask="" }
    $0 ~ ("^interface[[:space:]]+Vlan" vid "$") { in_if=1; next }
    in_if && $0 ~ "^!" { in_if=0 }
    in_if && $1=="ip" && $2=="address" {
      if ($3=="dhcp") { mode="DHCP"; next }
      if ($3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
        mode="STATIC"; ip=$3; mask=$4; next
      }
    }
    in_if && $1=="ip" && $2=="dhcp" && $3=="client" {
      if (mode=="") mode="DHCP"
      next
    }
    END {
      if (mode=="STATIC") print ip" "mask
      else if (mode=="DHCP") print "DHCP"
      else print ""
    }
  ' "$cfg"
}

parse_dns_from_cfg() {
  local cfg="$1"
  awk '
    $1=="ip" && $2=="name-server" {
      for (i=3;i<=NF;i++) {
        if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
          if (!seen[$i]++) {
            dns[++n]=$i
            if (n==2) { print dns[1]" "dns[2]; exit }
          }
        }
      }
    }
    END {
      if (n==1) print dns[1]
      else if (n==2) print dns[1]" "dns[2]
    }
  ' "$cfg"
}

parse_default_gateway_from_cfg() {
  local cfg="$1"
  awk '
    $1=="ip" && $2=="default-gateway" && $3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $3; exit }
  ' "$cfg"
}

parse_default_route_nexthop_from_cfg() {
  local cfg="$1"
  awk '
    $1=="ip" && $2=="route" && $3=="0.0.0.0" && $4=="0.0.0.0" && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $5; exit }
  ' "$cfg"
}

# ----------------------------
# meraki memory: map selected switch IP -> cloud_id (used as Meraki "serial")
# ----------------------------
cloud_id_for_ip() {
  local ip="$1"
  python3 - "$MEM_DIR" "$ip" <<'PY'
import os,sys,json
mem, target_ip = sys.argv[1], sys.argv[2]
if not os.path.isdir(mem):
  sys.exit(1)

best=None
best_ts=""
for fn in os.listdir(mem):
  if not fn.endswith(".json"):
    continue
  path=os.path.join(mem,fn)
  try:
    with open(path,"r") as f:
      d=json.load(f)
  except Exception:
    continue
  if str(d.get("ip","")) != target_ip:
    continue
  ts=str(d.get("timestamp",""))
  if best is None or ts > best_ts:
    best=d
    best_ts=ts

if not best:
  sys.exit(1)

cid=best.get("cloud_id","")
if not cid:
  sys.exit(1)
print(cid)
PY
}

# ----------------------------
# Build selectable list (blacklisted hidden)
# Adds cloud_id column by reading meraki_memory.
# TSV columns:
#   ip \t hostname \t device_name \t pid \t stack_base_name \t cloud_id
# ----------------------------
build_switch_index_tsv() {
  python3 - "$UPGRADE_PLAN_JSON" "$DISCOVERY_JSON" "$MEM_DIR" "$SWITCH_INDEX_TSV" <<'PY'
import json, os, sys

plan_path, disc_path, mem_dir, out_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def load_list(p):
  if p and os.path.isfile(p):
    try:
      with open(p,"r") as f:
        d=json.load(f)
      if isinstance(d,list):
        return d
    except Exception:
      return []
  return []

def cloud_id_for_ip(ip):
  if not os.path.isdir(mem_dir):
    return ""
  best=None
  best_ts=""
  try:
    for fn in os.listdir(mem_dir):
      if not fn.endswith(".json"):
        continue
      p=os.path.join(mem_dir, fn)
      try:
        with open(p,"r") as f:
          d=json.load(f)
      except Exception:
        continue
      if str(d.get("ip","")).strip() != ip:
        continue
      ts=str(d.get("timestamp",""))
      if best is None or ts > best_ts:
        best=d
        best_ts=ts
  except Exception:
    return ""
  if not best:
    return ""
  return str(best.get("cloud_id","") or "").strip()

plan = load_list(plan_path)
disc = load_list(disc_path)
data = plan if plan else disc

rows=[]
seen=set()
for d in data:
  ip = str(d.get("ip","")).strip()
  if not ip or ip in seen:
    continue
  seen.add(ip)

  if bool(d.get("blacklisted", False)):
    continue

  hostname = str(d.get("hostname","")).strip()
  device_name = str(d.get("device_name","")).strip()
  pid = str(d.get("pid","UNKNOWN")).strip() or "UNKNOWN"

  stack_base = ""
  stack = d.get("stack") or {}
  if isinstance(stack, dict):
    stack_base = str(stack.get("stack_base_name","")).strip()

  cid = cloud_id_for_ip(ip)

  rows.append((ip, hostname, device_name, pid, stack_base, cid))

def ipkey(ip):
  try:
    return tuple(int(x) for x in ip.split("."))
  except:
    return (999,999,999,999)

rows.sort(key=lambda r: ipkey(r[0]))

with open(out_path,"w") as f:
  for r in rows:
    f.write("\t".join(r) + "\n")

print(out_path)
PY
}

lookup_index_row_for_ip() {
  local ip="$1"
  awk -F'\t' -v ip="$ip" '$1==ip {print; exit}' "$SWITCH_INDEX_TSV" 2>/dev/null || true
}

# ----------------------------
# checklist selection (multi)
# Shows: IP, hostname, pid, cloud_id, mgmt VLAN
# ----------------------------
select_switches_dialog_checklist() {
  local vid="Vlan${HTTP_CLIENT_VLAN_ID}"
  local prompt="Select switch(es) to process (blacklisted hidden)\nMgmt VLAN: ${vid}\n\nUse SPACE to toggle selection."

  local -a menu=()
  while IFS=$'\t' read -r ip hn dn pid sb cid; do
    [[ -n "$ip" ]] || continue
    local label
    label="$(echo "${hn:-${dn:-UNKNOWN}}" | trim)"
local desc
if [[ -n "${sb:-}" ]]; then
  desc="${label} (${pid}, stack:${sb})  ${vid}"
else
  desc="${label} (${pid})  ${vid}"
fi
    # default OFF
    menu+=("$ip" "$desc" "on")
  done <"$SWITCH_INDEX_TSV"

  [[ ${#menu[@]} -gt 0 ]] || die "No eligible (non-blacklisted) switches found."

  # --separate-output => one tag per line
  dlg --separate-output --checklist "$prompt" 22 110 14 "${menu[@]}"
}

# ----------------------------
# cfg selection by hostname/device_name/stack base
# ----------------------------
normalize_name_for_cfg_prefix() {
  local s="$1"
  s="$(sed -E 's/\[[0-9]+\]$//' <<<"$s" | trim)"
  echo "$s"
}

find_latest_cfg_by_prefix() {
  local prefix="$1"
  [[ -n "$prefix" ]] || return 1
  [[ -d "$IOS_CFG_DIR" ]] || return 1

  local best=""
  best="$(find "$IOS_CFG_DIR" -maxdepth 1 -type f -name "${prefix}_-*.cfg" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}')"
  if [[ -z "$best" ]]; then
    best="$(find "$IOS_CFG_DIR" -maxdepth 1 -type f -iname "${prefix}_-*.cfg" -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}')"
  fi
  [[ -n "$best" ]] || return 1
  echo "$best"
}

find_cfg_for_ip_from_index() {
  local ip="$1"
  local row
  row="$(lookup_index_row_for_ip "$ip")"
  [[ -n "$row" ]] || return 1

  local hn dn pid sb
  hn="$(awk -F'\t' '{print $2}' <<<"$row")"
  dn="$(awk -F'\t' '{print $3}' <<<"$row")"
  pid="$(awk -F'\t' '{print $4}' <<<"$row")"
  sb="$(awk -F'\t' '{print $5}' <<<"$row")"

  hn="$(normalize_name_for_cfg_prefix "$hn")"
  dn="$(normalize_name_for_cfg_prefix "$dn")"
  sb="$(normalize_name_for_cfg_prefix "$sb")"

  local cfg=""
  cfg="$(find_latest_cfg_by_prefix "$hn" || true)"
  if [[ -z "$cfg" && -n "$sb" ]]; then
    cfg="$(find_latest_cfg_by_prefix "$sb" || true)"
  fi
  if [[ -z "$cfg" ]]; then
    cfg="$(find_latest_cfg_by_prefix "$dn" || true)"
  fi
  if [[ -z "$cfg" ]]; then
    cfg="$(find_latest_cfg_by_prefix "$pid" || true)"
  fi

  [[ -n "$cfg" ]] || return 1
  echo "$cfg"
}

# ----------------------------
# Meraki Dashboard API
# serial == cloud_id (your rule)
# ----------------------------
meraki_get_mgmt_interface() {
  local cloud_id="$1"
  local url="https://api.meraki.com/api/v1/devices/${cloud_id}/managementInterface"
  curl -sS \
    -H "Accept: application/json" \
    -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
    "$url" || true
}

meraki_update_mgmt_static() {
  local cloud_id="$1"
  local ip="$2"
  local mask="$3"
  local gw="$4"
  local dns1="$5"
  local dns2="$6"

  local body
  body="$(python3 - "$ip" "$mask" "$gw" "$dns1" "$dns2" <<'PY'
import json, sys
ip,mask,gw,d1,d2 = sys.argv[1:6]
dns=[]
if d1: dns.append(d1)
if d2 and d2 != d1: dns.append(d2)
payload={
  "wan1":{
    "usingStaticIp": True,
    "staticIp": ip,
    "staticSubnetMask": mask,
    "staticGatewayIp": gw,
    "staticDns": dns
  }
}
print(json.dumps(payload))
PY
)"

  local url="https://api.meraki.com/api/v1/devices/${cloud_id}/managementInterface"

  local http_code
  http_code="$(curl -sS -o "${RUN_DIR}/curl_${cloud_id}.out" -w "%{http_code}" \
    -X PUT "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "X-Cisco-Meraki-API-Key: ${MERAKI_API_KEY}" \
    --data "$body" || true)"

  echo "$http_code"
}

meraki_already_has_static() {
  # returns 0 if matches exactly (best-effort), else 1
  local json="$1" ip="$2" mask="$3" gw="$4" dns1="$5" dns2="$6"
  python3 - "$json" "$ip" "$mask" "$gw" "$dns1" "$dns2" <<'PY'
import sys, json
raw, ip, mask, gw, d1, d2 = sys.argv[1:7]
try:
  d=json.loads(raw)
except Exception:
  sys.exit(1)

wan=d.get("wan1") or {}
if not isinstance(wan, dict):
  sys.exit(1)

if wan.get("usingStaticIp") is not True:
  sys.exit(1)

if str(wan.get("staticIp","")) != ip: sys.exit(1)
if str(wan.get("staticSubnetMask","")) != mask: sys.exit(1)
if str(wan.get("staticGatewayIp","")) != gw: sys.exit(1)

dns=wan.get("staticDns") or []
if not isinstance(dns, list):
  dns=[]

want=[]
if d1: want.append(d1)
if d2 and d2 != d1: want.append(d2)

# Compare as sets (Meraki may reorder)
if set(dns) != set(want):
  sys.exit(1)

sys.exit(0)
PY
}

# ----------------------------
# Process selected switches with ONE overall gauge
# ----------------------------
process_selected_with_gauge() {
  local -a ips=("$@")
  local total="${#ips[@]}"
  [[ "$total" -ge 1 ]] || return 0

  local stats_file="${RUN_DIR}/stats.env"
  : >"$stats_file"
  printf "UPDATED=0\nDHCP=0\nSKIPPED=0\nERRORS=0\n" >"$stats_file"

  local items_json="${RUN_DIR}/items.jsonl"
  : >"$items_json"

  (
    local idx=0
    for ip in "${ips[@]}"; do
      idx=$((idx+1))

      # coarse percent per device, plus step offsets
      local base=$(( (idx-1) * 100 / total ))
      local next=$(( idx * 100 / total ))
      local span=$(( next - base ))
      [[ $span -lt 1 ]] && span=1

      echo "XXX"; echo "$((base+1))"; echo "[$idx/$total] Preparing $ip"; echo "XXX"

      log "----"
      log "Processing selected IP: $ip"

      if ! ip_is_ipv4 "$ip"; then
        log "SKIP: invalid IPv4 selected IP: $ip"
        python3 - "$ip" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"action":"SKIPPED_INVALID_IP"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      echo "XXX"; echo "$((base + span*15/100 + 1))"; echo "[$idx/$total] Finding latest IOS-XE cfg"; echo "XXX"
      local cfg=""
      cfg="$(find_cfg_for_ip_from_index "$ip" || true)"
      if [[ -z "$cfg" ]]; then
        log "SKIP: could not find cfg for $ip by hostname/stack/device_name/pid prefixes"
        python3 - "$ip" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"action":"SKIPPED_NO_CFG"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi
      log "CFG: $cfg"

      echo "XXX"; echo "$((base + span*30/100 + 1))"; echo "[$idx/$total] Mapping Meraki cloud ID"; echo "XXX"
      local cloud_id=""
      cloud_id="$(cloud_id_for_ip "$ip" || true)"
      if [[ -z "$cloud_id" ]]; then
        log "SKIP: no meraki_memory mapping found for IP $ip (cloud_id unknown)"
        python3 - "$ip" "$cfg" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"action":"SKIPPED_NO_CLOUD_ID"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi
      log "CLOUD_ID (used as Meraki serial): $cloud_id"

      echo "XXX"; echo "$((base + span*45/100 + 1))"; echo "[$idx/$total] Parsing mgmt VLAN Vlan${HTTP_CLIENT_VLAN_ID}"; echo "XXX"
      local mgmt_mode
      mgmt_mode="$(parse_vlan_mgmt_mode_from_cfg "$cfg" "$HTTP_CLIENT_VLAN_ID" | tr -s ' ' | trim || true)"

      if [[ -z "$mgmt_mode" || "$mgmt_mode" == "DHCP" ]]; then
        # DHCP/no-change is NOT an error
        log "DHCP: no static mgmt IP for Vlan${HTTP_CLIENT_VLAN_ID} (no change)"
        python3 - "$ip" "$cloud_id" "$cfg" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg=sys.argv[1:4]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"DHCP_NO_CHANGE"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["DHCP"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      local mgmt_ip mgmt_mask
      mgmt_ip="$(awk '{print $1}' <<<"$mgmt_mode")"
      mgmt_mask="$(awk '{print $2}' <<<"$mgmt_mode")"

      if ! ip_is_ipv4 "$mgmt_ip" || ! ip_is_ipv4 "$mgmt_mask"; then
        log "SKIP: parsed mgmt ip/mask invalid: $mgmt_ip $mgmt_mask"
        python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_mode" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cloud_id":sys.argv[2],"cfg":sys.argv[3],"raw":sys.argv[4],"action":"SKIPPED_BAD_MGMT_PARSE"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      echo "XXX"; echo "$((base + span*60/100 + 1))"; echo "[$idx/$total] Parsing DNS + gateway"; echo "XXX"
      local dns_line dns1 dns2
      dns_line="$(parse_dns_from_cfg "$cfg" | tr -s ' ' | trim || true)"
      dns1=""; dns2=""
      if [[ -n "$dns_line" ]]; then
        dns1="$(awk '{print $1}' <<<"$dns_line")"
        dns2="$(awk '{print $2}' <<<"$dns_line")"
      fi
      [[ -n "$dns1" ]] || dns1="${DNS_PRIMARY:-}"
      [[ -n "$dns2" ]] || dns2="${DNS_SECONDARY:-}"
      if [[ -n "$dns1" ]] && ! ip_is_ipv4 "$dns1"; then log "WARN: dns1 invalid: $dns1 (clearing)"; dns1=""; fi
      if [[ -n "$dns2" ]] && ! ip_is_ipv4 "$dns2"; then log "WARN: dns2 invalid: $dns2 (clearing)"; dns2=""; fi

      local gw=""
      gw="$(parse_default_gateway_from_cfg "$cfg" || true)"
      if [[ -z "$gw" ]]; then
        local nh=""
        nh="$(parse_default_route_nexthop_from_cfg "$cfg" || true)"
        if [[ -n "$nh" ]]; then
          if ip_in_same_subnet "$mgmt_ip" "$mgmt_mask" "$nh"; then
            gw="$nh"
            log "GW: using default-route next-hop $gw (validated in subnet)"
          else
            log "SKIP: default-route next-hop $nh NOT in subnet of $mgmt_ip/$mgmt_mask"
            python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" "$nh" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cloud_id":sys.argv[2],"cfg":sys.argv[3],"mgmt_ip":sys.argv[4],"mask":sys.argv[5],"nexthop":sys.argv[6],"action":"SKIPPED_GW_NOT_IN_SUBNET"}))
PY
            python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
            continue
          fi
        else
          log "SKIP: no ip default-gateway and no default route found"
          python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cloud_id":sys.argv[2],"cfg":sys.argv[3],"mgmt_ip":sys.argv[4],"mask":sys.argv[5],"action":"SKIPPED_NO_GATEWAY"}))
PY
          python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
          continue
        fi
      fi

      if ! ip_is_ipv4 "$gw"; then
        log "SKIP: gateway invalid IPv4: $gw"
        python3 - "$ip" "$cloud_id" "$cfg" "$gw" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cloud_id":sys.argv[2],"cfg":sys.argv[3],"gateway":sys.argv[4],"action":"SKIPPED_BAD_GATEWAY"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi
      if ! ip_in_same_subnet "$mgmt_ip" "$mgmt_mask" "$gw"; then
        log "SKIP: gateway $gw not in same subnet as $mgmt_ip/$mgmt_mask"
        python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cloud_id":sys.argv[2],"cfg":sys.argv[3],"mgmt_ip":sys.argv[4],"mask":sys.argv[5],"gateway":sys.argv[6],"action":"SKIPPED_GW_NOT_IN_SUBNET"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      log "STATIC: mgmt_ip=$mgmt_ip mask=$mgmt_mask gw=$gw dns1=$dns1 dns2=$dns2"

      echo "XXX"; echo "$((base + span*75/100 + 1))"; echo "[$idx/$total] Checking if Meraki already matches"; echo "XXX"
      local cur_json=""
      cur_json="$(meraki_get_mgmt_interface "$cloud_id")"
      if [[ -n "$cur_json" ]] && meraki_already_has_static "$cur_json" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2"; then
        log "SKIP: Meraki already set to same STATIC settings (no change)"
        python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2=sys.argv[1:10]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"SKIPPED_ALREADY_SET",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x]}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      echo "XXX"; echo "$((base + span*90/100 + 1))"; echo "[$idx/$total] Updating Meraki management interface"; echo "XXX"
      local http_code
      http_code="$(meraki_update_mgmt_static "$cloud_id" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2")"
      if [[ "$http_code" == "200" ]]; then
        log "OK: Meraki updated managementInterface to STATIC for $cloud_id ($ip -> $mgmt_ip)"
        python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" "$http_code" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2,code=sys.argv[1:10]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"UPDATED_STATIC",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x],
                  "http_code":int(code)}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["UPDATED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
      else
        log "ERROR: Meraki update failed for $cloud_id (HTTP $http_code). Response saved to curl_${cloud_id}.out"
        python3 - "$ip" "$cloud_id" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" "$http_code" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2,code=sys.argv[1:10]
def to_int(x):
  try: return int(x)
  except: return x
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"ERROR_MERAKI_UPDATE",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x],
                  "http_code":to_int(code)}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]
d={}
for line in open(p):
  k,v=line.strip().split("=",1)
  d[k]=int(v)
d["ERRORS"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
      fi

    done

    echo "XXX"; echo "100"; echo "Finalizing report"; echo "XXX"
  ) | "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Starting..." 10 90 0

  # Build report.json
  python3 - "$RUN_ID" "$items_json" "$stats_file" "$REPORT_JSON" <<'PY'
import json,sys
run_id, items_path, stats_path, out_path = sys.argv[1:5]
items=[]
with open(items_path,"r") as f:
  for line in f:
    line=line.strip()
    if not line: continue
    try: items.append(json.loads(line))
    except: pass

stats={}
with open(stats_path,"r") as f:
  for line in f:
    line=line.strip()
    if not line or "=" not in line: continue
    k,v=line.split("=",1)
    try: stats[k]=int(v)
    except: stats[k]=v

doc={
  "run_id": run_id,
  "updated_static": int(stats.get("UPDATED",0)),
  "dhcp_no_change": int(stats.get("DHCP",0)),
  "skipped": int(stats.get("SKIPPED",0)),
  "errors": int(stats.get("ERRORS",0)),
  "items": items
}
with open(out_path,"w") as f:
  json.dump(doc,f,indent=2)
PY

  local updated dhcp skipped errors
  updated="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['updated_static'])" 2>/dev/null || echo 0)"
  dhcp="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['dhcp_no_change'])" 2>/dev/null || echo 0)"
  skipped="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['skipped'])" 2>/dev/null || echo 0)"
  errors="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['errors'])" 2>/dev/null || echo 0)"

  # Final summary WITHOUT paths
  "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --msgbox \
"Completed: ${RUN_ID}\n\nUpdated to STATIC in Meraki: ${updated}\nDHCP (no change): ${dhcp}\nSkipped: ${skipped}\nErrors: ${errors}\n\nPlease use the log viewer (Main Menu --> Logging) to review any results." \
14 80 || true
}

main() {
  need_cmd "$DIALOG"
  need_cmd awk
  need_cmd find
  need_cmd sort
  need_cmd head
  need_cmd curl
  need_cmd python3
  need_cmd date

  mkdir -p "$RUN_DIR" "$RUNS_ROOT"
  : >"$LOG_FILE"
  ln -sfn "$RUN_DIR" "$LATEST_LINK" || true

  load_discovery_env

  build_switch_index_tsv >/dev/null 2>&1 || true
  [[ -s "$SWITCH_INDEX_TSV" ]] || die "No eligible switches found (or could not build index)."

    # Auto-process ALL eligible switches from the index (blacklisted already hidden)
  local -a ips=()
  while IFS=$'\t' read -r ip _rest; do
    ip="$(echo "$ip" | trim)"
    [[ -n "$ip" ]] || continue
    ips+=("$ip")
  done <"$SWITCH_INDEX_TSV"

  [[ ${#ips[@]} -ge 1 ]] || die "No eligible switches found."

    # One-second info box so the customer knows what this module is doing
  "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" \
    --infobox "Processing Management IP address (if applicable)..." 5 60
  sleep 1

  process_selected_with_gauge "${ips[@]}"
}

main "$@"