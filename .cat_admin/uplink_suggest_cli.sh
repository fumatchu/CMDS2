#!/usr/bin/env bash
set -Euo pipefail

BASE_DIR="/root/.cat_admin"
MERAKI_ENV_FILE="${BASE_DIR}/meraki_discovery.env"
MAPPING_JSON_FILE="${BASE_DIR}/runs/mappings/latest/mapping.json"
SELECTED_JSON_FILE="${BASE_DIR}/selected_upgrade.json"
BACKUP_LOCAL_BASE_DIR="/var/lib/tftpboot/cat"

RUNS_BASE="${BASE_DIR}/runs/uplink_suggest"
RUN_TS="$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="${RUNS_BASE}/run-${RUN_TS}"
LATEST_LINK="${RUNS_BASE}/latest"
TMP_DIR="${BASE_DIR}/.tmp_uplink_suggest_cli"

mkdir -p "$RUN_DIR"
mkdir -p "$TMP_DIR"
ln -sfn "$RUN_DIR" "$LATEST_LINK"

TARGET_FAMILY_OVERRIDE=""
SOURCE_IP_FILTER=""
MANUAL_PAIRS_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-family)
      TARGET_FAMILY_OVERRIDE="${2:-}"
      shift 2
      ;;
    --ip)
      SOURCE_IP_FILTER="${2:-}"
      shift 2
      ;;
    --pairs-file)
      MANUAL_PAIRS_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage:
  uplink_suggest_cli.sh [--ip <source-ip>] [--target-family <family>] [--pairs-file <json>]

Examples:
  ./uplink_suggest_cli.sh
  ./uplink_suggest_cli.sh --ip 192.168.245.225
  ./uplink_suggest_cli.sh --ip 192.168.245.225 --target-family TenGigabitEthernet
  ./uplink_suggest_cli.sh --ip 192.168.245.225 --pairs-file /root/.cat_admin/manual_pairs.json

Notes:
- Supports 3-part source interfaces like Gi1/1/1 and Te1/1/1
- Supports older 2-part source interfaces like Fa0/1, Gi0/1, Gi1/1
- Detects likely uplink numbering mode on older switches
- Empty placeholder blocks are ignored for remap decisions
- Meraki target side only considers module-backed ports
- Does NOT overwrite original configs
- Writes artifacts under runs/uplink_suggest/run-<timestamp>/
- Writes normalized_manifest.json for handoff to downstream migration
- Supports manual pair injection via --pairs-file
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing required command: $1" >&2
    exit 1
  }
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need jq
need curl
need python3
need grep
need sed
need awk
need sort

[[ -f "$MERAKI_ENV_FILE" ]] || die "Missing env file: $MERAKI_ENV_FILE"
[[ -f "$MAPPING_JSON_FILE" ]] || die "Missing mapping file: $MAPPING_JSON_FILE"
[[ -f "$SELECTED_JSON_FILE" ]] || die "Missing selected upgrade file: $SELECTED_JSON_FILE"
[[ -d "$BACKUP_LOCAL_BASE_DIR" ]] || die "Missing backup config dir: $BACKUP_LOCAL_BASE_DIR"

if [[ -n "$MANUAL_PAIRS_FILE" && ! -f "$MANUAL_PAIRS_FILE" ]]; then
  die "Manual pairs file not found: $MANUAL_PAIRS_FILE"
fi

trim() {
  local s="${1:-}"
  s="$(printf '%s' "$s" | tr -d '\r')"
  s="$(printf '%s' "$s" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  printf '%s' "$s"
}

safe_name() {
  printf '%s' "$1" | tr ' /:' '---' | tr -cd 'A-Za-z0-9_.-'
}

# shellcheck disable=SC1090
source "$MERAKI_ENV_FILE"

MERAKI_API_KEY="${MERAKI_API_KEY:-}"
[[ -n "$MERAKI_API_KEY" ]] || die "MERAKI_API_KEY is empty in $MERAKI_ENV_FILE"

api_get() {
  local path="$1"
  curl -fsS \
    -H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY" \
    -H "Content-Type: application/json" \
    "https://api.meraki.com/api/v1${path}"
}

get_backup_filename_for_ip() {
  local ip="$1"
  jq -r --arg ip "$ip" '
    first(.[] | select(.ip == $ip) | .backup_filename) // ""
  ' "$SELECTED_JSON_FILE"
}

get_all_mapped_ip_members() {
  jq -r '
    .[]?
    | select((.source.ip // "") != "")
    | [
        (.source.key // (((.source.ip // "")|tostring) + "|" + (((.source.member_index // 1)|tostring)))),
        (.source.ip // ""),
        ((.source.member_index // 1)|tostring),
        (.target.cloud_id // ""),
        (.source.hostname // "UNKNOWN"),
        (.target.model // "UNKNOWN")
      ] | @tsv
  ' "$MAPPING_JSON_FILE"
}

detect_source_configured_uplinks_json() {
  local cfg="$1"
  local member="$2"

  python3 - "$cfg" "$member" <<'PY'
import json
import re
import sys
from pathlib import Path

cfg = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
mapped_member = int(sys.argv[2])

blocks = []
name = None
buf = []

for line in cfg.splitlines():
    if line.startswith("interface "):
        if name is not None:
            blocks.append((name, buf))
        name = line.split(None, 1)[1].strip()
        buf = [line]
    else:
        if name is not None:
            buf.append(line)

if name is not None:
    blocks.append((name, buf))

pat3 = re.compile(r'^([A-Za-z]+(?:Ethernet|GigE))(\d+)/(\d+)/(\d+)$')
pat2 = re.compile(r'^([A-Za-z]+(?:Ethernet|GigE))(\d+)/(\d+)$')

physical = []
nonphysical = []

def meaningful_lines(lines):
    out = []
    for ln in lines[1:]:
        s = ln.strip()
        if not s:
            continue
        if s == "!":
            continue
        out.append(s)
    return out

def config_score(lines):
    score = 0
    joined = "\n".join(lines).lower()

    for s in lines:
        sl = s.lower()
        if sl.startswith("description ") and any(x in sl for x in (
            "uplink", "up-link", "core", "dist", "distribution", "idf", "mdf",
            "trunk", "agg", "aggregation", "server", "router", "firewall", "wan"
        )):
            score += 4
        if sl == "switchport mode trunk":
            score += 8
        if sl.startswith("switchport trunk "):
            score += 4
        if sl.startswith("channel-group "):
            score += 7
        if sl == "no switchport":
            score += 4
        if sl.startswith("ip address "):
            score += 4
        if sl.startswith("media-type "):
            score += 2
        if sl == "speed nonegotiate":
            score += 2
        if sl.startswith("spanning-tree guard root"):
            score += 2
        if sl.startswith("service-policy "):
            score += 1

    if "switchport access vlan" in joined:
        score -= 2
    if "spanning-tree portfast" in joined:
        score -= 2
    if "authentication port-control auto" in joined:
        score -= 2
    if "mab" in joined:
        score -= 1
    if "dot1x" in joined:
        score -= 1

    return score

def parse_iface(ifname):
    m3 = pat3.match(ifname)
    if m3:
        return {
            "family": m3.group(1),
            "first": int(m3.group(2)),
            "second": int(m3.group(3)),
            "third": int(m3.group(4)),
            "syntax": "three-part",
        }
    m2 = pat2.match(ifname)
    if m2:
        return {
            "family": m2.group(1),
            "first": int(m2.group(2)),
            "second": int(m2.group(3)),
            "syntax": "two-part",
        }
    return None

for ifname, lines in blocks:
    body = meaningful_lines(lines)
    parsed = parse_iface(ifname)
    if not parsed:
        nonphysical.append({
            "name": ifname,
            "configCount": len(body),
        })
        continue

    entry = {
        "name": ifname,
        "family": parsed["family"],
        "rawConfigLines": body,
        "configLines": body,
        "configCount": len(body),
        "candidateScore": config_score(body),
        "sourceSyntax": parsed["syntax"],
    }

    if parsed["syntax"] == "three-part":
        entry["first"] = parsed["first"]
        entry["member"] = parsed["first"]
        entry["slot"] = parsed["second"]
        entry["port"] = parsed["third"]
        entry["rawFirstNumber"] = parsed["first"]
    else:
        entry["first"] = parsed["first"]
        entry["rawFirstNumber"] = parsed["first"]
        entry["rawSecondNumber"] = parsed["second"]
        entry["member"] = mapped_member
        entry["slot"] = 1
        entry["port"] = parsed["second"]

    physical.append(entry)

family_totals = {}
family_configured_totals = {}
firstnum_totals = {}
firstnum_configured_totals = {}

for e in physical:
    fam = e["family"]
    family_totals[fam] = family_totals.get(fam, 0) + 1
    firstn = str(e.get("first", -1))
    firstnum_totals[firstn] = firstnum_totals.get(firstn, 0) + 1

    if e["configCount"] > 0:
        family_configured_totals[fam] = family_configured_totals.get(fam, 0) + 1
        firstnum_configured_totals[firstn] = firstnum_configured_totals.get(firstn, 0) + 1

has_three_part = any(e["sourceSyntax"] == "three-part" for e in physical)
has_fast = family_totals.get("FastEthernet", 0) > 0

source_numbering_mode = "unknown"
numbering_reason = ""

if has_three_part:
    source_numbering_mode = "three-part-modular"
    numbering_reason = "Detected source interfaces using member/slot/port format such as Gi1/1/1 or Te1/1/1."
elif has_fast and family_totals.get("GigabitEthernet", 0) > 0:
    source_numbering_mode = "fastethernet-access-gig-uplink"
    numbering_reason = "Detected FastEthernet access-style ports with GigabitEthernet uplink-style ports."
elif family_totals.get("GigabitEthernet", 0) > 0 and firstnum_totals.get("0", 0) > 0 and firstnum_totals.get("1", 0) > 0:
    source_numbering_mode = "gigabit-access-separate-uplink-bank"
    numbering_reason = "Detected two-part GigabitEthernet numbering with multiple first-number banks such as Gi0/x and Gi1/x."
else:
    source_numbering_mode = "two-part-flat"
    numbering_reason = "Detected only two-part interface numbering; using config-role clues to identify uplinks."

configured = []
empty = []

for e in physical:
    include = False
    candidate_reason = []

    if e["sourceSyntax"] == "three-part":
        if e["member"] != mapped_member:
            continue
        if e["slot"] != 1:
            continue

        include = True
        candidate_reason.append("three-part slot-1 uplink candidate")
    else:
        fam = e["family"]
        firstn = e.get("first", -1)
        score = e.get("candidateScore", 0)

        if source_numbering_mode == "fastethernet-access-gig-uplink":
            if fam == "GigabitEthernet":
                include = True
                candidate_reason.append("gigabit family selected because switch has FastEthernet access ports")

        elif source_numbering_mode == "gigabit-access-separate-uplink-bank":
            if fam in ("GigabitEthernet", "TenGigabitEthernet") and firstn >= 1:
                include = True
                candidate_reason.append("higher first-number bank treated as uplink bank on two-part gigabit switch")
            elif score >= 8:
                include = True
                candidate_reason.append("two-part interface included due to strong uplink config score")

        elif source_numbering_mode == "two-part-flat":
            if fam in ("GigabitEthernet", "TenGigabitEthernet") and score >= 1:
                include = True
                candidate_reason.append("two-part gigabit interface included due to positive uplink score")
            elif fam in ("GigabitEthernet", "TenGigabitEthernet") and e["configCount"] > 0:
                include = True
                candidate_reason.append("two-part gigabit interface included because it has real config")
            elif score >= 8:
                include = True
                candidate_reason.append("non-gigabit interface included due to strong uplink config score")

        else:
            if fam in ("GigabitEthernet", "TenGigabitEthernet") and e["configCount"] > 0:
                include = True
                candidate_reason.append("fallback inclusion of configured gigabit/ten-gigabit two-part interface")
            elif score >= 8:
                include = True
                candidate_reason.append("fallback inclusion due to strong uplink config score")

    if not include:
        continue

    entry = dict(e)
    entry["candidateReason"] = "; ".join(candidate_reason) if candidate_reason else ""
    entry["normalizedInterface"] = f'{entry["family"]}{entry["member"]}/{entry["slot"]}/{entry["port"]}'

    if entry["configCount"] > 0:
        configured.append(entry)
    else:
        empty.append(entry)

family_counts = {}
for e in configured:
    fam = e["family"]
    family_counts[fam] = family_counts.get(fam, 0) + 1

preferred_family = None
if family_counts:
    preferred_family = sorted(family_counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

configured.sort(key=lambda x: (x["member"], x["slot"], x["port"], x["name"]))
empty.sort(key=lambda x: (x["member"], x["slot"], x["port"], x["name"]))

print(json.dumps({
    "configuredSourceUplinks": configured,
    "emptySourceUplinks": empty,
    "configuredSourceFamilies": family_counts,
    "preferredSourceFamily": preferred_family,
    "sourceNumberingMode": source_numbering_mode,
    "sourceNumberingReason": numbering_reason,
    "sourceFamilyTotals": family_totals,
    "sourceConfiguredFamilyTotals": family_configured_totals,
    "sourceFirstNumberTotals": firstnum_totals,
    "sourceConfiguredFirstNumberTotals": firstnum_configured_totals
}, indent=2))
PY
}

build_valid_target_module_candidates() {
  local raw_ports_json="$1"
  local out_json="$2"

  python3 - "$raw_ports_json" "$out_json" <<'PY'
import json
import re
import sys
from pathlib import Path

raw = json.loads(Path(sys.argv[1]).read_text())
out_json = Path(sys.argv[2])

rows = []

for p in raw:
    port_id = p.get("portId") or ""
    port_name = p.get("name") or ""
    port_type = p.get("type") or ""
    enabled = bool(p.get("enabled", False))
    module_model = ((p.get("module") or {}).get("model")) or ""

    if port_type == "stack":
        continue
    if not module_model:
        continue

    family = ""
    named_port = False
    iface = ""

    if port_name and re.match(r'^[A-Za-z]+(?:Ethernet|GigE)\d+/1/\d+$', port_name):
        iface = port_name
        named_port = True
        m = re.match(r'^([A-Za-z]+(?:Ethernet|GigE))', port_name)
        if m:
            family = m.group(1)

    rows.append({
        "portId": port_id,
        "name": port_name,
        "moduleModel": module_model,
        "type": port_type,
        "enabled": enabled,
        "namedPort": named_port,
        "interface": iface,
        "family": family
    })

rows.sort(key=lambda x: (x["moduleModel"], x["portId"]))

out_json.write_text(json.dumps({
    "targetModuleCandidates": rows,
    "availableTargetFamilies": {},
    "namedTargetFamilies": {}
}, indent=2), encoding="utf-8")
PY
}

enrich_target_module_candidates_with_family() {
  local in_json="$1"
  local out_json="$2"

  python3 - "$in_json" "$out_json" <<'PY'
import json
import re
import sys
from pathlib import Path

src = json.loads(Path(sys.argv[1]).read_text())
dst = Path(sys.argv[2])

def infer_family_from_portid(port_id: str) -> str:
    mod = ""
    m = re.match(r'^[0-9]+_([^_]+)_[0-9]+$', port_id or "")
    if m:
        mod = m.group(1)

    if any(x in mod for x in ("NM-2Q", "NM-2-40G", "MA-MOD-2X40G")):
        return "FortyGigabitEthernet"
    if any(x in mod for x in ("NM-2Y", "NM-8Y", "MA-MOD-2X25G")):
        return "TwentyFiveGigE"
    if any(x in mod for x in ("NM-8X", "NM-4M", "MA-MOD-4X10G", "MA-MOD-8X10G", "C3850-NM-4-10G", "C3850-NM-8-10G")):
        return "TenGigabitEthernet"
    if "NM-4G" in mod:
        return "GigabitEthernet"
    return ""

rows = []
all_families = {}
named_families = {}
installed_named_modules = {}
installed_all_modules = {}

for row in src.get("targetModuleCandidates", []):
    port_id = row.get("portId", "") or ""
    name = row.get("name", "") or ""
    module_model = row.get("moduleModel", "") or ""
    port_type = row.get("type", "") or ""
    enabled = bool(row.get("enabled", False))
    named_port = bool(row.get("namedPort", False))
    iface = row.get("interface", "") or ""
    family = row.get("family", "") or ""

    if not family:
        family = infer_family_from_portid(port_id)

    if not family and module_model:
        if any(x in module_model for x in ("NM-8X", "NM-4M", "MA-MOD-4X10G", "MA-MOD-8X10G", "C3850-NM-4-10G", "C3850-NM-8-10G")):
            family = "TenGigabitEthernet"
        elif any(x in module_model for x in ("NM-2Q", "NM-2-40G", "MA-MOD-2X40G")):
            family = "FortyGigabitEthernet"
        elif any(x in module_model for x in ("NM-2Y", "NM-8Y", "MA-MOD-2X25G")):
            family = "TwentyFiveGigE"
        elif "NM-4G" in module_model:
            family = "GigabitEthernet"

    if family:
        all_families[family] = all_families.get(family, 0) + 1
        installed_all_modules.setdefault(family, {})
        installed_all_modules[family][module_model] = installed_all_modules[family].get(module_model, 0) + 1

        if named_port:
            named_families[family] = named_families.get(family, 0) + 1
            installed_named_modules.setdefault(family, {})
            installed_named_modules[family][module_model] = installed_named_modules[family].get(module_model, 0) + 1

    nums = [int(n) for n in re.findall(r'\d+', iface or port_id)]

    score = 0
    if named_port:
        score += 10
    if enabled:
        score += 1
    if family:
        score += 2

    rows.append({
        "portId": port_id,
        "name": name,
        "moduleModel": module_model,
        "portType": port_type,
        "enabled": enabled,
        "namedPort": named_port,
        "interface": iface,
        "family": family,
        "score": score,
        "sortNums": nums
    })

rows.sort(key=lambda x: (-x["score"], x["sortNums"], x["portId"]))
for r in rows:
    r.pop("sortNums", None)

dst.write_text(json.dumps({
    "targetModuleCandidates": rows,
    "availableTargetFamilies": all_families,
    "namedTargetFamilies": named_families,
    "installedNamedModulesByFamily": installed_named_modules,
    "installedAllModulesByFamily": installed_all_modules
}, indent=2), encoding="utf-8")
PY
}

build_suggestions_and_preview() {
  local cfg="$1"
  local source_json="$2"
  local target_json="$3"
  local suggest_json="$4"
  local preview_cfg="$5"
  local target_family_override="$6"
  local manual_pairs_file="$7"

  python3 - "$cfg" "$source_json" "$target_json" "$suggest_json" "$preview_cfg" "$target_family_override" "$manual_pairs_file" <<'PY'
import json
import re
import sys
from pathlib import Path

cfg_path = Path(sys.argv[1])
source = json.loads(Path(sys.argv[2]).read_text())
target = json.loads(Path(sys.argv[3]).read_text())
suggest_out = Path(sys.argv[4])
preview_out = Path(sys.argv[5])
target_family_override = sys.argv[6].strip()
manual_pairs_file = sys.argv[7].strip()

cfg_text = cfg_path.read_text(encoding="utf-8", errors="replace")

src = source.get("configuredSourceUplinks", [])
preferred_source_family = source.get("preferredSourceFamily")
source_families = source.get("configuredSourceFamilies", {})
source_numbering_mode = source.get("sourceNumberingMode", "")
source_numbering_reason = source.get("sourceNumberingReason", "")

tgt = target.get("targetModuleCandidates", [])
all_target_families = target.get("availableTargetFamilies", {})
named_target_families = target.get("namedTargetFamilies", {})
installed_named_modules = target.get("installedNamedModulesByFamily", {})
installed_all_modules = target.get("installedAllModulesByFamily", {})

def parse_ios_iface(name: str):
    m3 = re.match(r'^([A-Za-z]+(?:Ethernet|GigE))(\d+)/(\d+)/(\d+)$', name or "")
    if m3:
        return {
            "family": m3.group(1),
            "member": int(m3.group(2)),
            "slot": int(m3.group(3)),
            "port": int(m3.group(4)),
            "syntax": "three-part",
        }

    m2 = re.match(r'^([A-Za-z]+(?:Ethernet|GigE))(\d+)/(\d+)$', name or "")
    if m2:
        return {
            "family": m2.group(1),
            "member": 0,
            "slot": int(m2.group(2)),
            "port": int(m2.group(3)),
            "syntax": "two-part",
        }

    return None

def parse_portid(portid: str):
    m = re.match(r'^(\d+)_([^_]+)_(\d+)$', portid or "")
    if not m:
        return None
    return {
        "member": int(m.group(1)),
        "module": m.group(2),
        "port": int(m.group(3)),
    }

def synthesize_iface_name(family: str, member: int, slot: int, port: int):
    return f"{family}{member}/{slot}/{port}"

def source_coords(row):
    fam = row.get("family", "") or ""
    member = row.get("member")
    slot = row.get("slot")
    port = row.get("port")

    if fam and member is not None and slot is not None and port is not None:
        try:
            return {
                "family": fam,
                "member": int(member),
                "slot": int(slot),
                "port": int(port),
            }
        except Exception:
            return None

    parsed = parse_ios_iface(row.get("name", ""))
    if parsed:
        return {
            "family": parsed.get("family", ""),
            "member": int(parsed.get("member", 0)),
            "slot": int(parsed.get("slot", 0)),
            "port": int(parsed.get("port", 0)),
        }

    return None

preferred_target_family = None
reason = ""

if not src:
    reason = "No configured source uplinks detected; nothing to remap"
elif target_family_override:
    preferred_target_family = target_family_override
    reason = f"User override requested target family {target_family_override}"
elif preferred_source_family and preferred_source_family in named_target_families:
    preferred_target_family = preferred_source_family
    reason = f"Source family exists as named target ports: {preferred_source_family}"
elif len(named_target_families) == 1:
    preferred_target_family = sorted(named_target_families.keys())[0]
    reason = f"Source family does not exist as named target ports; only one named target family exists: {preferred_target_family}"
elif not named_target_families and preferred_source_family and preferred_source_family in all_target_families:
    preferred_target_family = preferred_source_family
    reason = f"No named target families exist; falling back to source-family match in all target families: {preferred_source_family}"
else:
    reason = "Multiple valid target families exist; no automatic family selected"

usable_targets = tgt
if preferred_target_family:
    usable_targets = [t for t in usable_targets if t.get("family") == preferred_target_family]

enriched_targets = []
for t in usable_targets:
    iface = (t.get("interface") or "").strip()
    portid = (t.get("portId") or "").strip()
    family = (t.get("family") or "").strip()

    coords = None
    effective_iface = iface
    interface_origin = "unknown"

    parsed_named = parse_ios_iface(iface) if iface else None
    if parsed_named and parsed_named.get("syntax") == "three-part":
        coords = parsed_named
        interface_origin = "named"
    else:
        parsed_pid = parse_portid(portid)
        if parsed_pid and family:
            coords = {
                "family": family,
                "member": parsed_pid["member"],
                "slot": 1,
                "port": parsed_pid["port"],
            }
            effective_iface = synthesize_iface_name(family, parsed_pid["member"], 1, parsed_pid["port"])
            interface_origin = "synthesized"

    enriched = dict(t)
    enriched["effectiveInterface"] = effective_iface
    enriched["coords"] = coords
    enriched["isActuallyNamed"] = bool(t.get("namedPort", False))
    enriched["interfaceOrigin"] = interface_origin
    enriched_targets.append(enriched)

parsed_src = []
for s in src:
    row = dict(s)
    row["coords"] = source_coords(s)
    parsed_src.append(row)

parsed_src.sort(key=lambda x: (
    x["coords"]["member"] if x.get("coords") else 9999,
    x["coords"]["slot"] if x.get("coords") else 9999,
    x["coords"]["port"] if x.get("coords") else 9999,
    x.get("name", "")
))

target_by_portid = {}
target_by_interface = {}
exact_named = {}
exact_any = {}

for t in enriched_targets:
    if t.get("portId"):
        target_by_portid[t["portId"]] = t
    if t.get("effectiveInterface"):
        target_by_interface[t["effectiveInterface"]] = t

    c = t.get("coords")
    if not c:
        continue
    key = (c["family"], c["member"], c["slot"], c["port"])
    exact_any[key] = t
    if t.get("isActuallyNamed"):
        exact_named[key] = t

family_targets_named = {}
family_targets_any = {}

for t in enriched_targets:
    fam = t.get("family") or ""
    if not fam:
        continue
    family_targets_any.setdefault(fam, []).append(t)
    if t.get("isActuallyNamed"):
        family_targets_named.setdefault(fam, []).append(t)

def sort_key_target(t):
    c = t.get("coords") or {}
    return (
        c.get("member", 9999),
        c.get("slot", 9999),
        c.get("port", 9999),
        t.get("portId", "")
    )

for fam in family_targets_named:
    family_targets_named[fam].sort(key=sort_key_target)
for fam in family_targets_any:
    family_targets_any[fam].sort(key=sort_key_target)

pairs = []
decision_mode = "automatic"
match_confidence = "low"
operator_review_required = False

if manual_pairs_file:
    decision_mode = "manual"
    manual_pairs = json.loads(Path(manual_pairs_file).read_text(encoding="utf-8"))
    if not isinstance(manual_pairs, list):
        raise SystemExit("manual pairs file must be a JSON array")

    used_portids = set()
    source_names = {s["name"] for s in parsed_src}
    src_by_name = {s["name"]: s for s in parsed_src}

    for mp in manual_pairs:
        if not isinstance(mp, dict):
            continue

        source_name = (mp.get("source") or "").strip()
        target_iface = (mp.get("targetInterface") or "").strip()
        target_portid = (mp.get("targetPortId") or "").strip()

        if not source_name:
            continue
        if source_name not in source_names:
            raise SystemExit(f"manual pair source not found in source uplinks: {source_name}")

        candidate = None
        if target_portid and target_portid in target_by_portid:
            candidate = target_by_portid[target_portid]
        elif target_iface and target_iface in target_by_interface:
            candidate = target_by_interface[target_iface]

        if candidate is None:
            src_row = src_by_name.get(source_name, {})
            sc = src_row.get("coords") or parse_ios_iface(source_name)
            fallback_family = mp.get("targetFamily") or preferred_target_family or (sc["family"] if sc else "")
            fallback_module = mp.get("targetModuleModel") or ""
            candidate = {
                "portId": target_portid,
                "moduleModel": fallback_module,
                "family": fallback_family,
                "effectiveInterface": target_iface,
                "score": 0,
                "interfaceOrigin": "manual-raw",
                "isActuallyNamed": False,
            }

        if candidate.get("portId") and candidate["portId"] in used_portids:
            raise SystemExit(f"manual pair reuses target portId: {candidate['portId']}")

        if candidate.get("portId"):
            used_portids.add(candidate["portId"])

        src_row = src_by_name.get(source_name, {})
        sc = src_row.get("coords") or parse_ios_iface(source_name) or {}

        pairs.append({
            "source": source_name,
            "sourceFamily": mp.get("sourceFamily") or sc.get("family", ""),
            "targetPortId": candidate.get("portId", ""),
            "targetModuleModel": candidate.get("moduleModel", ""),
            "targetFamily": candidate.get("family", ""),
            "targetInterface": target_iface or candidate.get("effectiveInterface", ""),
            "targetScore": candidate.get("score", 0),
            "matchType": "manual",
            "targetNamed": bool(candidate.get("isActuallyNamed", False)),
            "targetInterfaceOrigin": candidate.get("interfaceOrigin", "manual-raw"),
        })

    pairs.sort(key=lambda p: (
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("member", 9999),
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("slot", 9999),
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("port", 9999),
        p["source"]
    ))
    match_confidence = "medium"
else:
    used_portids = set()

    for s in parsed_src:
        sc = s.get("coords")
        if not sc:
            continue

        key = (sc["family"], sc["member"], sc["slot"], sc["port"])

        candidate = exact_named.get(key)
        if candidate is None:
            candidate = exact_any.get(key)

        if candidate is None:
            continue
        if candidate.get("portId") in used_portids:
            continue

        used_portids.add(candidate.get("portId"))

        if candidate.get("isActuallyNamed"):
            match_type = "exact-port-match-named"
        else:
            match_type = "exact-port-match-synthesized"

        pairs.append({
            "source": s["name"],
            "sourceFamily": s.get("family", ""),
            "targetPortId": candidate.get("portId", ""),
            "targetModuleModel": candidate.get("moduleModel", ""),
            "targetFamily": candidate.get("family", ""),
            "targetInterface": candidate.get("effectiveInterface", ""),
            "targetScore": candidate.get("score", 0),
            "matchType": match_type,
            "targetNamed": bool(candidate.get("isActuallyNamed", False)),
            "targetInterfaceOrigin": candidate.get("interfaceOrigin", "unknown"),
        })

    paired_sources = {p["source"] for p in pairs}
    fallback_family = preferred_target_family or preferred_source_family or ""

    fallback_pool = [
        t for t in family_targets_named.get(fallback_family, [])
        if t.get("portId") not in used_portids
    ]
    if not fallback_pool:
        fallback_pool = [
            t for t in family_targets_any.get(fallback_family, [])
            if t.get("portId") not in used_portids
        ]

    unmatched_sources = [s for s in parsed_src if s["name"] not in paired_sources]

    for s, t in zip(unmatched_sources, fallback_pool):
        used_portids.add(t.get("portId"))
        pairs.append({
            "source": s["name"],
            "sourceFamily": s.get("family", ""),
            "targetPortId": t.get("portId", ""),
            "targetModuleModel": t.get("moduleModel", ""),
            "targetFamily": t.get("family", ""),
            "targetInterface": t.get("effectiveInterface", ""),
            "targetScore": t.get("score", 0),
            "matchType": "ordered-fallback",
            "targetNamed": bool(t.get("isActuallyNamed", False)),
            "targetInterfaceOrigin": t.get("interfaceOrigin", "unknown"),
        })

    src_by_name = {s["name"]: s for s in parsed_src}
    pairs.sort(key=lambda p: (
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("member", 9999),
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("slot", 9999),
        (src_by_name.get(p["source"], {}).get("coords") or {}).get("port", 9999),
        p["source"]
    ))

    pair_types = {p.get("matchType") for p in pairs}
    named_pair_count = sum(1 for p in pairs if p.get("matchType") == "exact-port-match-named")
    synth_pair_count = sum(1 for p in pairs if p.get("matchType") == "exact-port-match-synthesized")
    fallback_pair_count = sum(1 for p in pairs if p.get("matchType") == "ordered-fallback")

    has_named_family_evidence = bool(named_target_families) and bool(preferred_target_family) and preferred_target_family in named_target_families

    if pairs and pair_types == {"exact-port-match-named"}:
        match_confidence = "high"
    elif (
        pairs
        and fallback_pair_count == 0
        and named_pair_count > 0
        and synth_pair_count > 0
        and pair_types.issubset({"exact-port-match-named", "exact-port-match-synthesized"})
        and has_named_family_evidence
    ):
        match_confidence = "medium-high"
    elif pairs and pair_types.issubset({"exact-port-match-named", "exact-port-match-synthesized"}):
        match_confidence = "medium"
    elif pairs:
        match_confidence = "medium"
    else:
        match_confidence = "low"

new_text = cfg_text
mapping = {p["source"]: p["targetInterface"] for p in pairs if p.get("targetInterface")}

for old_name in sorted(mapping.keys(), key=len, reverse=True):
    new_name = mapping[old_name]
    pattern = rf'(?<![A-Za-z0-9]){re.escape(old_name)}(?![A-Za-z0-9])'
    new_text = re.sub(pattern, new_name, new_text)

preview_out.write_text(new_text, encoding="utf-8")

changed = any(p["source"] != p["targetInterface"] for p in pairs)

source_count = len(parsed_src)
pair_count = len(pairs)

if source_count == 0:
    status = "unchanged"
    changed = False
    match_confidence = "high"
    operator_review_required = False
    preferred_target_family = preferred_target_family or ""
    reason = "No configured source uplinks detected; nothing to remap"
elif pair_count == 0:
    status = "needs_review"
elif pair_count < source_count:
    status = "needs_review"
elif decision_mode == "manual":
    status = "ready"
elif changed:
    status = "ready"
else:
    status = "unchanged"

if source_count == 0:
    operator_review_required = False
elif status == "needs_review":
    operator_review_required = True
elif match_confidence in ("medium", "low"):
    operator_review_required = True
elif decision_mode == "manual":
    operator_review_required = False
else:
    operator_review_required = False

suggest_out.write_text(json.dumps({
    "configuredSourceFamilies": source_families,
    "preferredSourceFamily": preferred_source_family,
    "sourceNumberingMode": source_numbering_mode,
    "sourceNumberingReason": source_numbering_reason,
    "availableTargetFamilies": all_target_families,
    "namedTargetFamilies": named_target_families,
    "installedNamedModulesByFamily": installed_named_modules,
    "installedAllModulesByFamily": installed_all_modules,
    "preferredTargetFamily": preferred_target_family,
    "reason": reason,
    "pairs": pairs,
    "finalPairs": pairs,
    "changed": changed,
    "status": status,
    "sourceConfiguredCount": source_count,
    "pairCount": pair_count,
    "decisionMode": decision_mode,
    "matchConfidence": match_confidence,
    "operatorReviewRequired": operator_review_required
}, indent=2), encoding="utf-8")
PY
}

write_report() {
  local report_file="$1"
  local ip="$2"
  local member="$3"
  local host="$4"
  local model="$5"
  local cloud_id="$6"
  local cfg="$7"
  local source_json="$8"
  local target_json="$9"
  local suggest_json="${10}"
  local preview_cfg="${11}"

  {
    echo "================================================================"
    echo "Source host/IP:    ${host} (${ip})"
    echo "Source member:     ${member}"
    echo "Target model:      ${model}"
    echo "Target cloud_id:   ${cloud_id}"
    echo "Config:            ${cfg}"
    echo

    echo "Detected source numbering mode:"
    jq -r '
      "  mode: " + ((.sourceNumberingMode // "unknown")|tostring),
      "  reason: " + ((.sourceNumberingReason // "unknown")|tostring)
    ' "$source_json"
    echo

    echo "All source family totals:"
    jq -r '
      if (.sourceFamilyTotals | length) == 0 then
        "  (none)"
      else
        .sourceFamilyTotals
        | to_entries[]
        | "  " + .key + "  count=" + (.value|tostring)
      end
    ' "$source_json"
    echo

    echo "All source first-number totals:"
    jq -r '
      if (.sourceFirstNumberTotals | length) == 0 then
        "  (none)"
      else
        .sourceFirstNumberTotals
        | to_entries[]
        | "  first=" + .key + "  count=" + (.value|tostring)
      end
    ' "$source_json"
    echo

    echo "Configured source uplink candidates:"
    jq -r '
      if (.configuredSourceUplinks | length) == 0 then
        "  (none)"
      else
        .configuredSourceUplinks[]
        | "  " + .name
          + "  [normalized=" + (.normalizedInterface // "")
          + ", family=" + .family
          + ", syntax=" + (.sourceSyntax // "")
          + ", configCount=" + (.configCount|tostring)
          + ", candidateScore=" + ((.candidateScore // 0)|tostring)
          + ", reason=" + (.candidateReason // "")
          + "]"
      end
    ' "$source_json"
    echo

    echo "Empty source uplink candidates:"
    jq -r '
      if (.emptySourceUplinks | length) == 0 then
        "  (none)"
      else
        .emptySourceUplinks[]
        | "  " + .name
          + "  [normalized=" + (.normalizedInterface // "")
          + ", family=" + .family
          + ", syntax=" + (.sourceSyntax // "")
          + ", candidateScore=" + ((.candidateScore // 0)|tostring)
          + ", reason=" + (.candidateReason // "")
          + "]"
      end
    ' "$source_json"
    echo

    echo "Configured source families:"
    jq -r '
      if (.configuredSourceFamilies | length) == 0 then
        "  (none)"
      else
        .configuredSourceFamilies
        | to_entries[]
        | "  " + .key + "  count=" + (.value|tostring)
      end
    ' "$source_json"
    echo

    echo "Preferred source family in use:"
    jq -r '"  " + ((.preferredSourceFamily // "NONE")|tostring)' "$source_json"
    echo

    echo "Valid target Meraki module candidates:"
    jq -r '
      if (.targetModuleCandidates | length) == 0 then
        "  (none)"
      else
        .targetModuleCandidates[]
        | "  " + (if .interface != "" then .interface else "(unnamed)" end)
          + "  [portId=" + .portId
          + ", module=" + .moduleModel
          + ", family=" + (.family // "")
          + ", named=" + (.namedPort|tostring)
          + ", score=" + (.score|tostring)
          + "]"
      end
    ' "$target_json"
    echo

    echo "Available valid target families (all):"
    jq -r '
      if (.availableTargetFamilies | length) == 0 then
        "  (none)"
      else
        .availableTargetFamilies
        | to_entries[]
        | "  " + .key + "  count=" + (.value|tostring)
      end
    ' "$target_json"
    echo

    echo "Available named target families (preferred):"
    jq -r '
      if (.namedTargetFamilies | length) == 0 then
        "  (none)"
      else
        .namedTargetFamilies
        | to_entries[]
        | "  " + .key + "  count=" + (.value|tostring)
      end
    ' "$target_json"
    echo

    echo "Detected installed target modules by family (named only):"
    jq -r '
      if (.installedNamedModulesByFamily | length) == 0 then
        "  (none)"
      else
        .installedNamedModulesByFamily
        | to_entries[]
        | .key as $fam
        | .value
        | to_entries[]
        | "  " + $fam + "  module=" + .key + "  count=" + (.value|tostring)
      end
    ' "$target_json"
    echo

    echo "All module-backed target possibilities exposed by API:"
    jq -r '
      if (.installedAllModulesByFamily | length) == 0 then
        "  (none)"
      else
        .installedAllModulesByFamily
        | to_entries[]
        | .key as $fam
        | .value
        | to_entries[]
        | "  " + $fam + "  module=" + .key + "  count=" + (.value|tostring)
      end
    ' "$target_json"
    echo

    echo "Suggestion decision:"
    jq -r '
      "  preferred source family: " + ((.preferredSourceFamily // "NONE")|tostring),
      "  source numbering mode: " + ((.sourceNumberingMode // "unknown")|tostring),
      "  preferred target family: " + ((.preferredTargetFamily // "NONE")|tostring),
      "  reason: " + (.reason // "unknown"),
      "  status: " + ((.status // "unknown")|tostring),
      "  changed: " + ((.changed // false)|tostring),
      "  decisionMode: " + ((.decisionMode // "automatic")|tostring),
      "  matchConfidence: " + ((.matchConfidence // "low")|tostring),
      "  operatorReviewRequired: " + ((.operatorReviewRequired // false)|tostring)
    ' "$suggest_json"
    echo

    echo "Suggested remap:"
    jq -r '
      if (.pairs | length) == 0 then
        "  (no automatic remap generated)"
      else
        .pairs[]
        | "  " + .source + "  ->  " + .targetInterface
          + "  [module=" + .targetModuleModel
          + ", family=" + .targetFamily
          + ", targetScore=" + (.targetScore|tostring)
          + ", matchType=" + (.matchType // "unknown")
          + ", targetNamed=" + ((.targetNamed // false)|tostring)
          + ", targetInterfaceOrigin=" + (.targetInterfaceOrigin // "unknown")
          + "]"
      end
    ' "$suggest_json"
    echo

    echo "Preview config written to:"
    echo "  ${preview_cfg}"
    echo
  } > "$report_file"
}

append_manifest_entry() {
  local manifest_file="$1"
  local source_key="$2"
  local ip="$3"
  local member="$4"
  local host="$5"
  local cloud_id="$6"
  local model="$7"
  local original_cfg="$8"
  local working_cfg="$9"
  local source_json="${10}"
  local suggest_json="${11}"

  local tmp_manifest
  tmp_manifest="$(mktemp)"

  jq \
    --arg source_key "$source_key" \
    --arg ip "$ip" \
    --arg member "$member" \
    --arg host "$host" \
    --arg cloud_id "$cloud_id" \
    --arg model "$model" \
    --arg original_cfg "$original_cfg" \
    --arg working_cfg "$working_cfg" \
    --slurpfile src "$source_json" \
    --slurpfile sug "$suggest_json" \
    '
      . + [
        {
          source_key: $source_key,
          ip: $ip,
          member_index: ($member | tonumber),
          hostname: $host,
          target_cloud_id: $cloud_id,
          target_model: $model,
          original_config: $original_cfg,
          working_config: $working_cfg,
          effective_config: (
            if (($sug[0].status // "needs_review") == "ready" or ($sug[0].status // "needs_review") == "unchanged")
            then $working_cfg
            else ""
            end
          ),
          status: ($sug[0].status // "needs_review"),
          approved_for_migration: (
            (($sug[0].status // "needs_review") == "ready") or
            (($sug[0].status // "needs_review") == "unchanged")
          ),
          changed: ($sug[0].changed // false),
          decision_mode: ($sug[0].decisionMode // "automatic"),
          match_confidence: ($sug[0].matchConfidence // "low"),
          operator_review_required: (
            if ($sug[0] | has("operatorReviewRequired"))
            then $sug[0].operatorReviewRequired
            else true
            end
          ),
          preferred_source_family: ($src[0].preferredSourceFamily // ""),
          preferred_target_family: ($sug[0].preferredTargetFamily // ""),
          source_numbering_mode: ($src[0].sourceNumberingMode // ""),
          source_numbering_reason: ($src[0].sourceNumberingReason // ""),
          reason: ($sug[0].reason // ""),
          source_configured_count: ($sug[0].sourceConfiguredCount // 0),
          pair_count: ($sug[0].pairCount // 0),
          final_pairs: ($sug[0].finalPairs // [])
        }
      ]
    ' "$manifest_file" > "$tmp_manifest"

  mv "$tmp_manifest" "$manifest_file"
}

main() {
  local entry_count=0
  local run_summary="${RUN_DIR}/run_summary.txt"
  local manifest_file="${RUN_DIR}/normalized_manifest.json"

  printf '[]\n' > "$manifest_file"

  {
    echo "Uplink Suggest Run"
    echo "Run timestamp UTC: ${RUN_TS}"
    echo "Run dir: ${RUN_DIR}"
    echo "Target family override: ${TARGET_FAMILY_OVERRIDE:-<none>}"
    echo "Source IP filter: ${SOURCE_IP_FILTER:-<none>}"
    echo "Manual pairs file: ${MANUAL_PAIRS_FILE:-<none>}"
    echo "Manifest: ${manifest_file}"
    echo
  } > "$run_summary"

  while IFS=$'\t' read -r source_key ip member cloud_id host model; do
    source_key="$(trim "$source_key")"
    ip="$(trim "$ip")"
    member="$(trim "$member")"
    cloud_id="$(trim "$cloud_id")"
    host="$(trim "$host")"
    model="$(trim "$model")"

    [[ -n "$ip" && -n "$member" && -n "$cloud_id" ]] || continue
    if [[ -n "$SOURCE_IP_FILTER" && "$ip" != "$SOURCE_IP_FILTER" ]]; then
      continue
    fi

    entry_count=$((entry_count + 1))

    local backup_filename cfg base_name
    backup_filename="$(trim "$(get_backup_filename_for_ip "$ip")")"
    [[ -n "$backup_filename" ]] || {
      echo "Skipping ${ip}|${member}: no backup filename found in ${SELECTED_JSON_FILE}" >&2
      continue
    }

    cfg="${BACKUP_LOCAL_BASE_DIR}/${backup_filename}"
    [[ -f "$cfg" ]] || {
      echo "Skipping ${ip}|${member}: config not found: ${cfg}" >&2
      continue
    }

    base_name="$(safe_name "${host}_${ip}_member${member}")"

    local raw_ports_json source_json target_stage1_json target_json suggest_json preview_cfg report_file
    raw_ports_json="${RUN_DIR}/raw_ports_${base_name}.json"
    source_json="${RUN_DIR}/source_${base_name}.json"
    target_stage1_json="${RUN_DIR}/target_stage1_${base_name}.json"
    target_json="${RUN_DIR}/target_${base_name}.json"
    suggest_json="${RUN_DIR}/suggest_${base_name}.json"
    preview_cfg="${RUN_DIR}/preview_${base_name}.cfg"
    report_file="${RUN_DIR}/report_${base_name}.txt"

    echo "Querying target module ports for ${host} (${ip}) member ${member} ..."
    api_get "/devices/${cloud_id}/switch/ports" > "$raw_ports_json"

    detect_source_configured_uplinks_json "$cfg" "$member" > "$source_json"
    build_valid_target_module_candidates "$raw_ports_json" "$target_stage1_json"
    enrich_target_module_candidates_with_family "$target_stage1_json" "$target_json"
    build_suggestions_and_preview "$cfg" "$source_json" "$target_json" "$suggest_json" "$preview_cfg" "$TARGET_FAMILY_OVERRIDE" "$MANUAL_PAIRS_FILE"

    write_report "$report_file" "$ip" "$member" "$host" "$model" "$cloud_id" "$cfg" "$source_json" "$target_json" "$suggest_json" "$preview_cfg"

    append_manifest_entry "$manifest_file" "$source_key" "$ip" "$member" "$host" "$cloud_id" "$model" "$cfg" "$preview_cfg" "$source_json" "$suggest_json"

    cat "$report_file"

    {
      echo "Source key: ${source_key}"
      echo "Report: ${report_file}"
      echo "Preview: ${preview_cfg}"
      echo
    } >> "$run_summary"
  done < <(get_all_mapped_ip_members)

  if [[ "$entry_count" -eq 0 ]]; then
    die "No matching mapping entries found in ${MAPPING_JSON_FILE}"
  fi

  echo
  echo "Normalized manifest:"
  echo "  ${manifest_file}"
  echo
  echo "Artifacts written to: ${RUN_DIR}"
  echo "Latest symlink: ${LATEST_LINK}"
}

main "$@"