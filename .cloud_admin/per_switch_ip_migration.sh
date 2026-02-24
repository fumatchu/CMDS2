#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================
# Cloud Admin – Mgmt IP Migration (IOS-XE cfg -> Meraki Dashboard)
#
# What it does (per your requirements):
#   - Builds a selectable list of candidate switches (blacklisted hidden)
#   - User can CHECK/UNCHECK multiple switches (checklist)
#   - Filters the list to ONLY IPs in selected_upgrade.env (UPGRADE_SELECTED_IPS)
#   - For each selected management IP:
#       * Find latest IOS-XE cfg in /var/lib/tftpboot/mig based on hostname/stack/device_name/pid prefix
#       * Read mgmt VLAN from meraki_discovery.env (HTTP_CLIENT_VLAN_ID)
#       * If mgmt VLAN has static "ip address A.B.C.D M.M.M.M":
#           - Collect DNS (ip name-server) else use DNS_PRIMARY/SECONDARY from env
#           - Collect GW (ip default-gateway) else default-route next-hop (validated in subnet)
#           - Update Meraki device managementInterface using cloud_id(s) from meraki_memory
#             (stack-safe: multiple cloud IDs may exist for one mgmt IP)
#           - If Meraki already has the same static settings => SKIPPED (not error)
#       * If DHCP / no static => DHCP_NO_CHANGE (not error)
#   - Logs to /root/.cloud_admin/runs/mgmt_ip/<run_id>/actions.log
#   - latest symlink points to the most recent run dir
#   - Dialog:
#       * Checklist selection screen (hostname/device_name + pid + cloud_ids + mgmt VLAN)
#       * Gauge progress while processing
#       * Final summary shows counts only (NO file paths)
#
# Key fixes in this revision:
#   - Robust parsing of selected_upgrade.env UPGRADE_SELECTED_IPS (handles '\ ' escapes)
#   - Switch index is filtered to the selected IP set (removes wrong entries)
#   - cloud IDs come directly from meraki_memory JSONs by matching "ip"
#   - Stack-safe: one mgmt IP can map to multiple cloud IDs; UI shows all, updates all
# ============================================================

CLOUD_ADMIN_ROOT="/root/.cloud_admin"
IOS_CFG_DIR="/var/lib/tftpboot/mig"
DISC_ENV="${CLOUD_ADMIN_ROOT}/meraki_discovery.env"
MEM_DIR="${CLOUD_ADMIN_ROOT}/meraki_memory"
DISCOVERY_JSON="${CLOUD_ADMIN_ROOT}/discovery_results.json"
UPGRADE_PLAN_JSON="${CLOUD_ADMIN_ROOT}/upgrade_plan.json"
SELECTED_UPGRADE_ENV="${CLOUD_ADMIN_ROOT}/selected_upgrade.env"

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

die() {
  log "FATAL: $*"
  "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "ERROR:\n\n$*\n" 12 70 || true
  exit 1
}

log() {
  mkdir -p "$RUN_DIR" >/dev/null 2>&1 || true
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
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
# selected_upgrade.env parsing (robust)
# ----------------------------
selected_ips_from_env() {
  [[ -f "$SELECTED_UPGRADE_ENV" ]] || return 1
  python3 - "$SELECTED_UPGRADE_ENV" <<'PY'
import os,sys
p=sys.argv[1]
val=None
for raw in open(p,"r"):
  s=raw.strip()
  if not s or s.startswith("#"): continue
  if s.startswith("export "): s=s[len("export "):].strip()
  if s.startswith("UPGRADE_SELECTED_IPS="):
    val=s.split("=",1)[1].strip()
    break
if not val:
  sys.exit(2)

# handle: 192.168.245.9\ 192.168.245.10
val = val.replace("\\ ", " ")
val = val.strip().strip('"').strip("'")
ips=[x for x in val.split() if x]
for ip in ips:
  print(ip)
PY
}

# ----------------------------
# parsing from IOS cfg
# ----------------------------
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
  awk '$1=="ip" && $2=="default-gateway" && $3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $3; exit }' "$cfg"
}

parse_default_route_nexthop_from_cfg() {
  local cfg="$1"
  awk '$1=="ip" && $2=="route" && $3=="0.0.0.0" && $4=="0.0.0.0" && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $5; exit }' "$cfg"
}

# ----------------------------
# meraki memory: map mgmt IP -> cloud_id(s)
#   - for stacks: multiple cloud IDs can share same mgmt IP
# ----------------------------
cloud_ids_for_ip() {
  local ip="$1"
  python3 - "$MEM_DIR" "$ip" <<'PY'
import os,sys,json
mem, target_ip = sys.argv[1], sys.argv[2]
if not os.path.isdir(mem):
  sys.exit(1)

hits=[]
for fn in os.listdir(mem):
  if not fn.endswith(".json"):
    continue
  p=os.path.join(mem,fn)
  try:
    d=json.load(open(p,"r"))
  except Exception:
    continue
  if str(d.get("ip","")).strip() != target_ip:
    continue
  cid=str(d.get("cloud_id","") or "").strip()
  if not cid:
    continue
  stack=d.get("stack") or {}
  mi=None
  if isinstance(stack, dict):
    try:
      mi=int(stack.get("member_index"))
    except Exception:
      mi=None
  hits.append((mi if mi is not None else 9999, cid))

if not hits:
  sys.exit(1)

# sort by member_index then cid, unique preserve order
hits.sort(key=lambda x: (x[0], x[1]))
seen=set()
for _,cid in hits:
  if cid in seen:
    continue
  seen.add(cid)
  print(cid)
PY
}

cloud_ids_csv_for_ip() {
  local ip="$1"
  cloud_ids_for_ip "$ip" 2>/dev/null | paste -sd, - || true
}

# Backwards compatibility: "primary" cloud id (first)
cloud_id_for_ip() {
  local ip="$1"
  cloud_ids_for_ip "$ip" 2>/dev/null | head -n1 || true
}

# ----------------------------
# Build selectable list (blacklisted hidden)
# Filtered to selected_upgrade.env IPs
# TSV columns:
#   ip \t hostname \t device_name \t pid \t stack_base_name \t cloud_ids_csv
# ----------------------------
build_switch_index_tsv() {
  python3 - "$UPGRADE_PLAN_JSON" "$DISCOVERY_JSON" "$MEM_DIR" "$SELECTED_UPGRADE_ENV" "$SWITCH_INDEX_TSV" <<'PY'
import json, os, sys

plan_path, disc_path, mem_dir, sel_env, out_path = sys.argv[1:6]

def load_list(p):
  if p and os.path.isfile(p):
    try:
      d=json.load(open(p,"r"))
      return d if isinstance(d,list) else []
    except Exception:
      return []
  return []

def read_selected_ips(p):
  if not os.path.isfile(p):
    return []
  val=None
  for raw in open(p,"r"):
    s=raw.strip()
    if not s or s.startswith("#"):
      continue
    if s.startswith("export "):
      s=s[len("export "):].strip()
    if s.startswith("UPGRADE_SELECTED_IPS="):
      val=s.split("=",1)[1].strip()
      break
  if not val:
    return []
  val = val.replace("\\ ", " ")
  val = val.strip().strip('"').strip("'")
  return [x for x in val.split() if x]

def mem_primary_cloud_and_stackcount(ip):
  """
  Returns (primary_cloud_id, stack_count)
  - primary cloud id: lowest member_index, then stable by cid
  - stack_count: max observed stack_count for this IP, else 1 if any hit, else 0
  """
  if not os.path.isdir(mem_dir):
    return ("", 0)

  hits=[]
  max_stack=0
  any_hit=False

  for fn in os.listdir(mem_dir):
    if not fn.endswith(".json"):
      continue
    p=os.path.join(mem_dir,fn)
    try:
      d=json.load(open(p,"r"))
    except Exception:
      continue

    if str(d.get("ip","")).strip() != ip:
      continue

    any_hit=True
    cid=str(d.get("cloud_id","") or "").strip()
    stack=d.get("stack") or {}
    mi=9999
    sc=0
    if isinstance(stack, dict):
      try:
        mi=int(stack.get("member_index"))
      except Exception:
        mi=9999
      try:
        sc=int(stack.get("stack_count") or 0)
      except Exception:
        sc=0
    if sc > max_stack:
      max_stack = sc

    if cid:
      hits.append((mi, cid))

  if any_hit and max_stack <= 0:
    max_stack = 1

  if not hits:
    return ("", max_stack)

  hits.sort(key=lambda x:(x[0], x[1]))
  return (hits[0][1], max_stack)

def ipkey(ip):
  try:
    return tuple(int(x) for x in ip.split("."))
  except:
    return (999,999,999,999)

plan = load_list(plan_path)
disc = load_list(disc_path)
data = plan if plan else disc

selected = read_selected_ips(sel_env)
selset = set(selected)

by_ip={}
for d in data:
  ip=str(d.get("ip","")).strip()
  if not ip or ip not in selset:
    continue
  if ip not in by_ip:
    by_ip[ip]=d

for ip in selected:
  if ip not in by_ip:
    by_ip[ip]={"ip":ip}

rows=[]
for ip in selected:
  d=by_ip.get(ip, {"ip":ip})
  if bool(d.get("blacklisted", False)):
    continue

  hostname=str(d.get("hostname","")).strip()
  device_name=str(d.get("device_name","")).strip()
  pid=str(d.get("pid","UNKNOWN")).strip() or "UNKNOWN"

  primary_cid, stack_count = mem_primary_cloud_and_stackcount(ip)

  rows.append((ip, hostname, device_name, pid, primary_cid, str(stack_count)))

rows.sort(key=lambda r: ipkey(r[0]))

# TSV columns now:
# ip \t hostname \t device_name \t pid \t primary_cloud_id \t stack_count
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
# Keeps your original "look" but adds cloud IDs cleanly + IP
# ----------------------------
select_switches_dialog_checklist() {
  local vid="Vlan${HTTP_CLIENT_VLAN_ID}"
  local prompt="Select switch(es) to process (blacklisted hidden)\nMgmt VLAN: ${vid}\n\nUse SPACE to toggle selection."

  local -a menu=()
  while IFS=$'\t' read -r ip hn dn pid primary_cid stack_count; do
    [[ -n "$ip" ]] || continue

    local label
    label="$(echo "${hn:-${dn:-UNKNOWN}}" | trim)"
    [[ -n "$label" ]] || label="UNKNOWN"

    # Build "serial-ish" display: primary cloud id + +N for stack
    local cid_part=""
    if [[ -n "${primary_cid:-}" ]]; then
      local sc="${stack_count:-0}"
      local plus=""
      if [[ "$sc" =~ ^[0-9]+$ ]] && (( sc > 1 )); then
        plus="+$((sc-1))"
      fi
      cid_part=", ${primary_cid}${plus}"
    fi

    local qty_part=""
if [[ "${stack_count:-}" =~ ^[0-9]+$ ]] && (( stack_count > 0 )); then
  qty_part=", Switch QTY:${stack_count}"
fi

local cid_part=""
if [[ -n "${primary_cid:-}" ]]; then
  cid_part="${primary_cid}${qty_part}"
else
  cid_part="Switch QTY:${stack_count}"
fi

local desc="${label} (${cid_part})  IP:${ip}  ${vid}"

    # default ON
    menu+=("$ip" "$desc" "on")
  done <"$SWITCH_INDEX_TSV"

  [[ ${#menu[@]} -gt 0 ]] || die "No eligible (non-blacklisted) switches found."

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

if set(dns) != set(want):
  sys.exit(1)

sys.exit(0)
PY
}

# ----------------------------
# Process selected switches with ONE overall gauge
# (stack-safe: updates all cloud IDs for a mgmt IP)
# ----------------------------
process_selected_with_gauge() {
  local -a ips=("$@")
  local total="${#ips[@]}"
  [[ "$total" -ge 1 ]] || return 0

  local stats_file="${RUN_DIR}/stats.env"
  printf "UPDATED=0\nDHCP=0\nSKIPPED=0\nERRORS=0\n" >"$stats_file"

  local items_json="${RUN_DIR}/items.jsonl"
  : >"$items_json"

  (
    local idx=0
    for ip in "${ips[@]}"; do
      idx=$((idx+1))

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
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
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
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi
      log "CFG: $cfg"

      echo "XXX"; echo "$((base + span*30/100 + 1))"; echo "[$idx/$total] Mapping Meraki cloud ID(s)"; echo "XXX"
      local cloud_list=""
      cloud_list="$(cloud_ids_for_ip "$ip" 2>/dev/null || true)"
      if [[ -z "$cloud_list" ]]; then
        log "SKIP: no meraki_memory mapping found for IP $ip (cloud_id unknown)"
        python3 - "$ip" "$cfg" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"action":"SKIPPED_NO_CLOUD_ID"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      log "CLOUD_ID(s) for IP $ip:"
      while IFS= read -r cid; do
        [[ -n "$cid" ]] && log "  - $cid"
      done <<<"$cloud_list"

      echo "XXX"; echo "$((base + span*45/100 + 1))"; echo "[$idx/$total] Parsing mgmt VLAN Vlan${HTTP_CLIENT_VLAN_ID}"; echo "XXX"
      local mgmt_mode
      mgmt_mode="$(parse_vlan_mgmt_mode_from_cfg "$cfg" "$HTTP_CLIENT_VLAN_ID" | tr -s ' ' | trim || true)"

      if [[ -z "$mgmt_mode" || "$mgmt_mode" == "DHCP" ]]; then
        log "DHCP: no static mgmt IP for Vlan${HTTP_CLIENT_VLAN_ID} (no change)"
        while IFS= read -r cid; do
          [[ -n "$cid" ]] || continue
          python3 - "$ip" "$cid" "$cfg" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg=sys.argv[1:4]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"DHCP_NO_CHANGE"}))
PY
        done <<<"$cloud_list"
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
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
        python3 - "$ip" "$cfg" "$mgmt_mode" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"raw":sys.argv[3],"action":"SKIPPED_BAD_MGMT_PARSE"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
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
            python3 - "$ip" "$cfg" "$mgmt_ip" "$mgmt_mask" "$nh" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"mgmt_ip":sys.argv[3],"mask":sys.argv[4],"nexthop":sys.argv[5],"action":"SKIPPED_GW_NOT_IN_SUBNET"}))
PY
            python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
            continue
          fi
        else
          log "SKIP: no ip default-gateway and no default route found"
          python3 - "$ip" "$cfg" "$mgmt_ip" "$mgmt_mask" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"mgmt_ip":sys.argv[3],"mask":sys.argv[4],"action":"SKIPPED_NO_GATEWAY"}))
PY
          python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
          continue
        fi
      fi

      if ! ip_is_ipv4 "$gw"; then
        log "SKIP: gateway invalid IPv4: $gw"
        python3 - "$ip" "$cfg" "$gw" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"gateway":sys.argv[3],"action":"SKIPPED_BAD_GATEWAY"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi
      if ! ip_in_same_subnet "$mgmt_ip" "$mgmt_mask" "$gw"; then
        log "SKIP: gateway $gw not in same subnet as $mgmt_ip/$mgmt_mask"
        python3 - "$ip" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" <<'PY' >>"$items_json"
import json,sys
print(json.dumps({"ip":sys.argv[1],"cfg":sys.argv[2],"mgmt_ip":sys.argv[3],"mask":sys.argv[4],"gateway":sys.argv[5],"action":"SKIPPED_GW_NOT_IN_SUBNET"}))
PY
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
        continue
      fi

      log "STATIC: mgmt_ip=$mgmt_ip mask=$mgmt_mask gw=$gw dns1=$dns1 dns2=$dns2"

      echo "XXX"; echo "$((base + span*75/100 + 1))"; echo "[$idx/$total] Checking if Meraki already matches"; echo "XXX"

      # apply to ALL cloud IDs for this mgmt IP
      local any_updated=0 any_error=0 any_skipped=0
      while IFS= read -r cid; do
        [[ -n "$cid" ]] || continue

        local cur_json=""
        cur_json="$(meraki_get_mgmt_interface "$cid")"
        if [[ -n "$cur_json" ]] && meraki_already_has_static "$cur_json" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2"; then
          log "SKIP: Meraki already set (no change) for $cid"
          any_skipped=1
          python3 - "$ip" "$cid" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2=sys.argv[1:9]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"SKIPPED_ALREADY_SET",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x]}))
PY
          continue
        fi

        echo "XXX"; echo "$((base + span*90/100 + 1))"; echo "[$idx/$total] Updating Meraki management interface"; echo "XXX"
        local http_code
        http_code="$(meraki_update_mgmt_static "$cid" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2")"
        if [[ "$http_code" == "200" ]]; then
          log "OK: Meraki updated managementInterface to STATIC for $cid ($ip -> $mgmt_ip)"
          any_updated=1
          python3 - "$ip" "$cid" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" "$http_code" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2,code=sys.argv[1:10]
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"UPDATED_STATIC",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x],
                  "http_code":int(code)}))
PY
        else
          log "ERROR: Meraki update failed for $cid (HTTP $http_code). Response saved to curl_${cid}.out"
          any_error=1
          python3 - "$ip" "$cid" "$cfg" "$mgmt_ip" "$mgmt_mask" "$gw" "$dns1" "$dns2" "$http_code" <<'PY' >>"$items_json"
import json,sys
ip,cid,cfg,mip,mask,gw,d1,d2,code=sys.argv[1:10]
def to_int(x):
  try: return int(x)
  except: return x
print(json.dumps({"ip":ip,"cloud_id":cid,"cfg":cfg,"action":"ERROR_MERAKI_UPDATE",
                  "mgmt_ip":mip,"mask":mask,"gateway":gw,"dns":[x for x in [d1,d2] if x],
                  "http_code":to_int(code)}))
PY
        fi
      done <<<"$cloud_list"

      # Update rollup counters ONCE per selected IP (keeps summary sane)
      if [[ $any_error -eq 1 ]]; then
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["ERRORS"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
      elif [[ $any_updated -eq 1 ]]; then
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["UPDATED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
      else
        # includes already-set cases
        python3 - "$stats_file" <<'PY'
import sys
p=sys.argv[1]; d={}
for line in open(p): k,v=line.strip().split("=",1); d[k]=int(v)
d["SKIPPED"]+=1
open(p,"w").write("\n".join(f"{k}={d[k]}" for k in ["UPDATED","DHCP","SKIPPED","ERRORS"])+"\n")
PY
      fi

    done

    echo "XXX"; echo "100"; echo "Finalizing report"; echo "XXX"
  ) | "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --gauge "Starting..." 10 90 0

  python3 - "$RUN_ID" "${RUN_DIR}/items.jsonl" "${RUN_DIR}/stats.env" "$REPORT_JSON" <<'PY'
import json,sys
run_id, items_path, stats_path, out_path = sys.argv[1:5]
items=[]
for line in open(items_path,"r"):
  line=line.strip()
  if not line: continue
  try: items.append(json.loads(line))
  except: pass

stats={}
for line in open(stats_path,"r"):
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
json.dump(doc, open(out_path,"w"), indent=2)
PY

  local updated dhcp skipped errors
  updated="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['updated_static'])" 2>/dev/null || echo 0)"
  dhcp="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['dhcp_no_change'])" 2>/dev/null || echo 0)"
  skipped="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['skipped'])" 2>/dev/null || echo 0)"
  errors="$(python3 -c "import json;print(json.load(open('$REPORT_JSON'))['errors'])" 2>/dev/null || echo 0)"

  "$DIALOG" --backtitle "$BACKTITLE" --title "$TITLE" --msgbox \
"Completed: ${RUN_ID}\n\nUpdated to STATIC in Meraki: ${updated}\nDHCP (no change): ${dhcp}\nSkipped: ${skipped}\nErrors: ${errors}" \
12 70 || true
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
  need_cmd paste

  mkdir -p "$RUN_DIR" "$RUNS_ROOT"
  : >"$LOG_FILE"
  ln -sfn "$RUN_DIR" "$LATEST_LINK" || true

  load_discovery_env

  # Require selected_upgrade.env and a non-empty selection set (this is how we avoid wrong entries)
  [[ -f "$SELECTED_UPGRADE_ENV" ]] || die "Missing ${SELECTED_UPGRADE_ENV} (run the upgrade selection step first)."
  local sel_count
  sel_count="$(selected_ips_from_env 2>/dev/null | wc -l | tr -d ' ' || true)"
  [[ "${sel_count:-0}" -ge 1 ]] || die "UPGRADE_SELECTED_IPS is empty or not parseable in selected_upgrade.env"

  build_switch_index_tsv >/dev/null 2>&1 || die "Could not build index (check selected_upgrade.env + plan/discovery files)."
  [[ -s "$SWITCH_INDEX_TSV" ]] || die "No eligible switches found after filtering to selected_upgrade.env."

  local selected
  selected="$(select_switches_dialog_checklist)" || { log "User cancelled."; exit 0; }
  [[ -n "${selected//[[:space:]]/}" ]] || { log "No selection."; exit 0; }

  local -a ips=()
  while IFS= read -r line; do
    line="$(echo "$line" | trim)"
    [[ -n "$line" ]] || continue
    ips+=("$line")
  done <<<"$selected"

  [[ ${#ips[@]} -ge 1 ]] || { log "No valid selections."; exit 0; }

  process_selected_with_gauge "${ips[@]}"
}

main "$@"