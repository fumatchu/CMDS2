#!/bin/bash
# KEA DHCP Manager Suite (dialog)
# Looks/feels like the ISC DHCP suite, but KEA-only.
#
# Tools:
#   1) Create DHCP Scope & Options (Kea JSON writer w/ Option15/119 + per-subnet interface)
#   2) Delete Subnet(s) from kea-dhcp4.conf
#   3) Edit kea-dhcp4.conf (validate, save, optional restart)
#   4) View Leases (raw/search/live)
#   5) MAC Reservations (add/delete)
#   6) Restart KEA service
#
# Usage:
#   sudo ./kea-suite.sh

set -euo pipefail

# --- Global UI/paths ---
BACKTITLE=${BACKTITLE:-"KEA DHCP Manager (kea-dhcp4)"}
export DIALOGOPTS="--backtitle $BACKTITLE"

DIALOG=${DIALOG:-dialog}
CONF="/etc/kea/kea-dhcp4.conf"
LEASES="/var/lib/kea/kea-leases4.csv"
LOG="/var/log/kea-manager-suite.log"
SERVICE="kea-dhcp4"

TMPROOT="$(mktemp -d)"; trap 'rm -rf "$TMPROOT"' EXIT

# ---------- Small helpers ----------
need_root(){ [[ $EUID -eq 0 ]] || { "$DIALOG" --msgbox "This tool must be run as root." 7 40; exit 1; }; }
cmd_exists(){ command -v "$1" &>/dev/null; }
die(){ "$DIALOG" --msgbox "Error:\n$*" 10 80; exit 1; }
trim(){ sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//' <<<"$1"; }

# ---------- Validators / IP math ----------
ip_ok(){
  local ip="$1"
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"
  for o in $a $b $c $d; do (( o>=0 && o<=255 )) || return 1; done
}
ip2int(){ IFS=. read -r a b c d <<<"$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
mask_ok(){
  ip_ok "$1" || return 1
  local m; m=$(ip2int "$1")
  (( m!=0 && m!=0xFFFFFFFF )) || return 1
  (( (m | (m-1)) == 0xFFFFFFFF ))
}
mask_to_prefix(){ # dotted->CIDR
  IFS=. read -r a b c d <<<"$1"
  local n=0 x
  for x in $a $b $c $d; do
    for ((i=7;i>=0;i--)); do
      if (( (x>>i)&1 )); then ((n++)); else break; fi
    done
  done
  echo "$n"
}
in_subnet_nm(){ # ip, network, mask
  (( ( $(ip2int "$1") & $(ip2int "$3") ) == ( $(ip2int "$2") & $(ip2int "$3") ) ))
}
not_net_or_bcast(){
  local ip="$1" net="$2" mask="$3"
  local ipi ni mi bcast
  ipi=$(ip2int "$ip"); ni=$(ip2int "$net"); mi=$(ip2int "$mask")
  bcast=$(( (ni & mi) | ((~mi) & 0xFFFFFFFF) ))
  (( ipi!=(ni&mi) && ipi!=bcast ))
}
valid_domain(){
  [[ $1 =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+\.?$ ]]
}

# ---------- KEA helpers ----------
kea_validate(){ local f="$1"; kea-dhcp4 -t "$f" >/dev/null 2>&1; }
restart_service(){
  {
    echo 20; systemctl daemon-reload >/dev/null 2>&1
    echo 60; systemctl restart "$SERVICE" >/dev/null 2>&1
    echo 90; sleep 0.25
    systemctl is-active "$SERVICE" >/dev/null 2>&1 && echo 100 || echo 0
  } | "$DIALOG" --gauge "Restarting $SERVICE..." 8 50 0
}

# ==========================================================
#                 LEASE VIEWER + SEARCH (KEA CSV)
# ==========================================================
leases_raw(){
  [[ -f "$LEASES" ]] || die "Leases file not found: $LEASES"
  "$DIALOG" --title "KEA leases (raw CSV)" --textbox "$LEASES" 0 0
}
leases_tail(){
  [[ -f "$LEASES" ]] || die "Leases file not found: $LEASES"
  "$DIALOG" --title "Live leases (tail -f)" --tailbox "$LEASES" 0 0
}

leases_search(){
  [[ -f "$LEASES" ]] || die "Leases file not found: $LEASES"

  local mode query include_expired inc_raw rc
  local tmp="$TMPROOT/leases_search.$RANDOM.txt"
  local tmpk="$TMPROOT/leases_search.$RANDOM.keyed"
  local now_epoch; now_epoch=$(date +%s)

  mode=$($DIALOG --menu "Search dataset" 10 60 2 \
           1 "Active leases (by expiry, sorted soonest first)" \
           2 "All lines (CSV filter)" 3>&1 1>&2 2>&3) || return 0

  if [[ "$mode" == "1" ]]; then
    # One screen: query + include-expired toggle
    local tmpf; tmpf=$(mktemp)
    if $DIALOG --help 2>&1 | grep -q -- '--output-fd'; then
      $DIALOG --output-fd 3 --form \
"Search (optional).
• Leave Query blank to list ALL.
• Text matches MAC/Hostname (case-insens.).
• Or CIDR 192.168.10.0/24 or dotted prefix 192.168.10.
• Include expired: y/n, on/off, true/false, 1/0." \
        13 80 2 \
        "Query:"            1 2  ""  1 18 54 0 \
        "Include expired?:" 2 2  "n" 2 18 10 0 3>"$tmpf"; rc=$?
    elif $DIALOG --help 2>&1 | grep -q -- '--stdout'; then
      $DIALOG --stdout --form \
"Search (optional).
• Leave Query blank to list ALL.
• Text matches MAC/Hostname (case-insens.).
• Or CIDR 192.168.10.0/24 or dotted prefix 192.168.10.
• Include expired: y/n, on/off, true/false, 1/0." \
        13 80 2 \
        "Query:"            1 2  ""  1 18 54 0 \
        "Include expired?:" 2 2  "n" 2 18 10 0 >"$tmpf"; rc=$?
    else
      $DIALOG --form \
"Search (optional).
• Leave Query blank to list ALL.
• Text matches MAC/Hostname (case-insens.).
• Or CIDR 192.168.10.0/24 or dotted prefix 192.168.10.
• Include expired: y/n, on/off, true/false, 1/0." \
        13 80 2 \
        "Query:"            1 2  ""  1 18 54 0 \
        "Include expired?:" 2 2  "n" 2 18 10 0 2>"$tmpf" >/dev/tty; rc=$?
    fi
    [[ $rc -ne 0 ]] && { rm -f "$tmpf"; return 0; }

    mapfile -t _F <"$tmpf"; rm -f "$tmpf"
    query="$(trim "${_F[0]}")"; inc_raw="$(trim "${_F[1]}")"
    case "${inc_raw,,}" in y|yes|on|true|1|x|"[x]") include_expired=1 ;; *) include_expired=0 ;; esac

    awk -F',' -v q="$query" -v now="$now_epoch" -v inc="$include_expired" '
      function ip2n(ip,   p){ n=split(ip,p,"."); return (((p[1]*256)+p[2])*256 + p[3])*256 + p[4] }
      function in_cidr(ip,c,   pp,net,pfx,blk){
        n=split(c,pp,"/"); if(n!=2) return 0
        net=ip2n(pp[1]); pfx=pp[2]+0; blk=2^(32-pfx)
        return (int(ip2n(ip)/blk)==int(net/blk))
      }
      function to_epoch(s,   a){
        gsub(/\r/,"",s)
        if (s ~ /^[0-9]+$/) return s+0
        if (match(s,/^([0-9]{4})-([0-9]{2})-([0-9]{2})[ T]([0-9]{2}):([0-9]{2}):([0-9]{2})/,a))
          return mktime(a[1]" "a[2]" "a[3]" "a[4]" "a[5]" "a[6])
        return 0
      }
      # portable locals
      function fmt_ttl(E, N) {
        diff = E - N
        neg  = (diff < 0)
        if (neg) diff = -diff
        d = int(diff/86400); diff%=86400
        h = int(diff/3600);  diff%=3600
        m = int(diff/60);    s=diff%60
        out=""
        if (d>0)      { out = d "d"; if(h>0) out = out " " h "h" }
        else if (h>0) { out = h "h"; if(m>0) out = out " " m "m" }
        else if (m>0) { out = m "m"; if(s>0) out = out " " s "s" }
        else          { out = s "s" }
        return out (neg ? " ago" : " left")
      }

      NR==1 {
        # Map field positions directly (no header array)
        ci_addr=ci_mac=ci_exp=ci_sid=ci_host=0
        for (i=1;i<=NF;i++) {
          f=$i; sub(/\r$/,"",f)
          if (f=="address")      ci_addr=i
          else if (f=="hwaddr")  ci_mac=i
          else if (f=="expire")  ci_exp=i
          else if (f=="subnet_id" || f=="subnet-id") ci_sid=i
          else if (f=="hostname") ci_host=i
        }
        q_lc=tolower(q)
        next
      }

      { sub(/\r$/,"") }

      {
        ip      = (ci_addr? $(ci_addr) : "")
        mac     = (ci_mac ? $(ci_mac)  : "")
        expires = (ci_exp ? $(ci_exp)  : "")
        sid     = (ci_sid ? $(ci_sid)  : "")
        host    = (ci_host? $(ci_host) : ""); gsub(/^ +| +$/,"",host)

        exp_epoch = to_epoch(expires)
        is_expired = (exp_epoch < now ? 1 : 0)
        if (!inc && is_expired) next

        ok = (q_lc=="")
        if (!ok) {
          if (index(tolower(host), q_lc) || index(tolower(mac), q_lc)) ok=1
          else if (q ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]+$/) ok=in_cidr(ip,q)
          else if (q ~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.$/) ok=(index(ip,q)==1)
        }
        if (ok) {
          status = (is_expired ? "EXPIRED" : "ACTIVE")
          hr  = (exp_epoch ? strftime("%Y-%m-%d %H:%M:%S", exp_epoch) : "-")
          ttl = (exp_epoch ? fmt_ttl(exp_epoch, now) : "-")
          # keys then pretty columns
          printf "%d\t%010d\t%-16s %-18s %-19s %-12s %-8s %-8s %-s\n",
                 is_expired, (exp_epoch?exp_epoch:9999999999),
                 ip, mac, hr, ttl, sid, status, host
        }
      }
    ' "$LEASES" > "$tmpk"

    if [[ ! -s "$tmpk" ]]; then
      $DIALOG --msgbox "$([[ $include_expired -eq 1 ]] && echo "No leases matched." || echo "No active leases matched.")" 6 44
      rm -f "$tmpk"; return 0
    fi

    {
      printf "%-16s %-18s %-19s %-12s %-8s %-8s %-s\n" "IP" "MAC" "EXPIRES (local)" "TTL" "SUBNET" "STATUS" "HOSTNAME"
      echo "-----------------------------------------------------------------------------------------------------------"
      sort -n -k1,1 -k2,2 "$tmpk" | cut -f3-
    } > "$tmp"
    rm -f "$tmpk"

  else
    # CSV filter (raw; active + expired); blank query = all
    query=$($DIALOG --inputbox "CSV filter (optional). Blank = show ALL." 8 70 "" 3>&1 1>&2 2>&3) || return 0
    query=$(trim "$query")
    awk -F',' -v q="$query" '
      NR==1 { print; next }
      { line=$0; sub(/\r$/,"",line)
        if (q=="") print line
        else if (index(tolower(line), tolower(q))) print line
      }
    ' "$LEASES" > "$tmp"
  fi

  if [[ ! -s "$tmp" ]]; then
    $DIALOG --msgbox "No results." 6 24
  else
    $DIALOG --title "Search results" --textbox "$tmp" 0 0
  fi
}


leases_menu(){
  while :; do
    CH=$("$DIALOG" --menu "KEA Lease Viewer\nLeases file: $LEASES" 16 78 8 \
      1 "Raw CSV (scroll)" \
      2 "Search (MAC / Host / Subnet)" \
      3 "Live view (tail -f)" \
      4 "Return to main menu" \
      3>&1 1>&2 2>&3) || break
    case "$CH" in
      1) leases_raw ;;
      2) leases_search ;;
      3) leases_tail ;;
      4) break ;;
    esac
  done
}


# ==========================================================
#                   CONFIG EDITOR (dialog)
# ==========================================================
config_editor(){
  [[ -f "$CONF" ]] || die "$CONF not found."
  local tmp="$TMPROOT/kea.$RANDOM.json" out="$TMPROOT/kea.$RANDOM.out"
  cp -f "$CONF" "$tmp"

  while :; do
    "$DIALOG" --title "Edit $CONF (Save & Continue to validate)" --editbox "$tmp" 0 0 2>"$out" || {
      "$DIALOG" --yesno "Cancel editing and discard changes?" 7 60 || continue
      return 0
    }
    mv -f "$out" "$tmp"

    # First: syntactic JSON check
    if ! jq . "$tmp" >/dev/null 2>&1; then
      "$DIALOG" --yesno "Invalid JSON. Re-edit?" 7 36 || return 1
      continue
    fi
    # Then: KEA semantic validation
    if kea_validate "$tmp"; then
      "$DIALOG" --msgbox "Validation PASSED." 6 28
      "$DIALOG" --yesno "Save changes to $CONF?\n(A backup will be created)" 8 60 || continue
      local ts; ts=$(date +%Y%m%d%H%M%S)
      cp -a "$CONF" "${CONF}.bak.${ts}" || die "Backup failed."
      cp -f "$tmp" "$CONF" || die "Write failed."
      chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
      "$DIALOG" --yesno "Restart $SERVICE now?" 7 40 && restart_service
      break
    else
      "$DIALOG" --yesno "KEA validation FAILED. Re-edit?" 7 44 || return 1
    fi
  done
}

# ==========================================================
#          SUBNET CREATOR (dialog)  — KEA JSON writer
# ==========================================================

pick_interface(){
  cmd_exists nmcli || { "$DIALOG" --msgbox "nmcli is required to select an interface." 7 60; return 1; }
  mapfile -t devs < <(nmcli -t -f DEVICE,STATE device status | awk -F: '$2=="connected"{print $1}')
  ((${#devs[@]})) || { "$DIALOG" --msgbox "No connected interfaces found." 6 50; return 1; }

  local ARGS=() d ip
  for d in "${devs[@]}"; do
    ip=$(nmcli -g IP4.ADDRESS device show "$d" | head -n1 | cut -d/ -f1)
    ARGS+=( "$d" "${d}${ip:+ ($ip)}" )
  done

  IFACE=$("$DIALOG" --menu "Select interface to bind this subnet to:" 14 60 8 "${ARGS[@]}" 3>&1 1>&2 2>&3) || return 1
  IFACE_IP=$(nmcli -g IP4.ADDRESS device show "$IFACE" | head -n1 | cut -d/ -f1)
  return 0
}

read_ip_list_csv(){
  local prompt="$1" value
  while :; do
    value=$("$DIALOG" --inputbox "$prompt\n(Comma-separated, e.g. 192.168.1.10, 192.168.1.11)" 10 72 "" 3>&1 1>&2 2>&3) || return 1
    value=$(trim "$value"); [[ -z $value ]] && { "$DIALOG" --msgbox "Please enter at least one IP." 6 44; continue; }
    local ok=1; IFS=, read -ra arr <<<"$value"; for x in "${arr[@]}"; do x=$(trim "$x"); ip_ok "$x" || { ok=0; break; }; done
    (( ok )) && { echo "$(IFS=, ; printf "%s" "${arr[*]// /}")"; return 0; }
    "$DIALOG" --msgbox "One or more IPs are invalid." 6 50
  done
}
read_domain_list_csv(){
  local v
  while :; do
    v=$("$DIALOG" --inputbox "Domain Search (Option 119)\nComma-separated FQDNs (e.g. corp.local, eng.corp.local)" 10 72 "" 3>&1 1>&2 2>&3) || return 1
    v=$(trim "$v"); [[ -z $v ]] && { "$DIALOG" --msgbox "Enter at least one domain." 6 48; continue; }
    local ok=1; IFS=, read -ra arr <<<"$v"; for d in "${arr[@]}"; do d=$(trim "$d"); valid_domain "$d" || { ok=0; break; }; done
    (( ok )) && { echo "$(IFS=,; echo "${arr[*]// /}")"; return 0; }
    "$DIALOG" --msgbox "One or more domains are invalid." 6 50
  done
}

next_subnet_id(){
  jq -r '.Dhcp4.subnet4[]?.id' "$CONF" 2>/dev/null | sort -n | awk '
    BEGIN{want=1}
    { if($1==want){want++} else if($1>want){print want; exit} }
    END{ print want }
  '
}

scope_creator_menu(){
  need_root; cmd_exists "$DIALOG" || die "dialog is not installed."
  cmd_exists jq || die "jq is required."
  cmd_exists kea-dhcp4 || die "kea-dhcp4 is not installed."
  [[ -f "$CONF" ]] || die "$CONF not found."
  : > "$LOG"

  while :; do
    SUBNETNETWORK=$("$DIALOG" --inputbox "Subnet network (e.g. 192.168.25.0)" 8 60 "" 3>&1 1>&2 2>&3) || return 0
    ip_ok "$SUBNETNETWORK" || { "$DIALOG" --msgbox "Invalid IPv4 address." 6 45; continue; }
    break
  done
  while :; do
    DHCPNETMASK=$("$DIALOG" --inputbox "Subnet mask (e.g. 255.255.255.0)" 8 60 "" 3>&1 1>&2 2>&3) || return 0
    mask_ok "$DHCPNETMASK" || { "$DIALOG" --msgbox "Invalid or non-contiguous mask." 6 55; continue; }
    (( ( $(ip2int "$SUBNETNETWORK") & $(ip2int "$DHCPNETMASK") ) == ( $(ip2int "$SUBNETNETWORK") ) )) || { "$DIALOG" --msgbox "Network is not aligned to this mask." 6 55; continue; }
    break
  done
  while :; do
    DHCPBEGIP=$("$DIALOG" --inputbox "Lease range START (e.g. 192.168.25.50)" 8 60 "" 3>&1 1>&2 2>&3) || return 0
    ip_ok "$DHCPBEGIP" && in_subnet_nm "$DHCPBEGIP" "$SUBNETNETWORK" "$DHCPNETMASK" && not_net_or_bcast "$DHCPBEGIP" "$SUBNETNETWORK" "$DHCPNETMASK" \
      || { "$DIALOG" --msgbox "Start IP must be a valid host in the subnet." 6 60; continue; }
    break
  done
  while :; do
    DHCPENDIP=$("$DIALOG" --inputbox "Lease range END (e.g. 192.168.25.200)" 8 60 "" 3>&1 1>&2 2>&3) || return 0
    ip_ok "$DHCPENDIP" && in_subnet_nm "$DHCPENDIP" "$SUBNETNETWORK" "$DHCPNETMASK" && not_net_or_bcast "$DHCPENDIP" "$SUBNETNETWORK" "$DHCPNETMASK" \
      || { "$DIALOG" --msgbox "End IP must be a valid host in the subnet." 6 60; continue; }
    (( $(ip2int "$DHCPBEGIP") <= $(ip2int "$DHCPENDIP") )) || { "$DIALOG" --msgbox "Start IP must be <= End IP." 6 45; continue; }
    break
  done
  while :; do
    DHCPDEFGW=$("$DIALOG" --inputbox "Default gateway (e.g. 192.168.25.1)" 8 60 "" 3>&1 1>&2 2>&3) || return 0
    ip_ok "$DHCPDEFGW" && in_subnet_nm "$DHCPDEFGW" "$SUBNETNETWORK" "$DHCPNETMASK" && not_net_or_bcast "$DHCPDEFGW" "$SUBNETNETWORK" "$DHCPNETMASK" \
      || { "$DIALOG" --msgbox "Gateway must be a valid host in the subnet." 6 60; continue; }
    break
  done
  SUBNETDESC=$("$DIALOG" --inputbox "Description (comment)" 8 60 "" 3>&1 1>&2 2>&3) || return 0

  if ! pick_interface; then
    "$DIALOG" --msgbox "Interface selection cancelled." 6 40
    return 0
  fi

  if [[ -z "${IFACE_IP:-}" ]]; then
    "$DIALOG" --yesno "Interface $IFACE has no IPv4 address.\nContinue anyway (e.g., relay case)?" 8 64 || return 0
  else
    if ! in_subnet_nm "$IFACE_IP" "$SUBNETNETWORK" "$DHCPNETMASK"; then
      "$DIALOG" --yesno "Interface $IFACE IP ($IFACE_IP) is not in ${SUBNETNETWORK}/$(mask_to_prefix "$DHCPNETMASK").\nContinue anyway (e.g., relay case)?" 9 72 || return 0
    fi
  fi

  local CIDR_PREFIX; CIDR_PREFIX=$(mask_to_prefix "$DHCPNETMASK")
  local SUBNET_CIDR="${SUBNETNETWORK}/${CIDR_PREFIX}"
  local SID; SID=$(next_subnet_id)

  # ---- Option builder (collect into a JSON array) ----
  local OPTS; OPTS=$(jq -n '[]')
  local HAS_DNS=0 HAS_ROUTERS=0 HAS_DN=0 HAS_SEARCH=0

  add_opt(){ # name value_string
    local n="$1" v="$2"
    case "$n" in
      domain-name-servers) HAS_DNS=1 ;;
      routers)             HAS_ROUTERS=1 ;;
      domain-name)         HAS_DN=1 ;;
      domain-search)       HAS_SEARCH=1 ;;
    esac
    OPTS=$(jq --arg name "$n" --arg data "$v" '. + [{name:$name, data:$data}]' <<<"$OPTS")
  }

  while :; do
    CH=$("$DIALOG" --menu "Add optional DHCP options (repeat as needed), or Done." 22 84 12 \
      DNS     "Option 6   - domain-name-servers (IP list)" \
      DN      "Option 15  - domain-name (FQDN)" \
      DOMSRCH "Option 119 - domain-search (list of FQDNs)" \
      NTP     "Option 42  - ntp-servers (IP list)" \
      TFTP66  "Option 66  - tftp-server-name (string)" \
      OPT150  "Option 150 - TFTP server IPs (list)" \
      USER    "Custom option (code/name/space/data)" \
      SHOW    "Show currently selected options" \
      DONE    "Finished adding options" \
      3>&1 1>&2 2>&3) || CH="DONE"

    case "$CH" in
      DNS)
        IPS=$(read_ip_list_csv "Domain Name Servers") || continue
        add_opt "domain-name-servers" "$IPS"
        ;;
      DN)
        while :; do
          DNVAL=$("$DIALOG" --inputbox "Domain name (e.g. example.local)" 8 60 "" 3>&1 1>&2 2>&3) || { DNVAL=""; break; }
          DNVAL=$(trim "$DNVAL")
          valid_domain "$DNVAL" || { "$DIALOG" --msgbox "Invalid FQDN." 6 40; continue; }
          add_opt "domain-name" "$DNVAL"
          break
        done
        ;;
      DOMSRCH)
        DOMS=$(read_domain_list_csv) || continue
        add_opt "domain-search" "$DOMS"
        ;;
      NTP)
        IPS=$(read_ip_list_csv "NTP servers") || continue
        add_opt "ntp-servers" "$IPS"
        ;;
      TFTP66)
        while :; do
          TFTP=$("$DIALOG" --inputbox "TFTP server name (FQDN/hostname)" 8 60 "" 3>&1 1>&2 2>&3) || { TFTP=""; break; }
          TFTP=$(trim "$TFTP"); [[ -n $TFTP ]] || { "$DIALOG" --msgbox "Enter a server name." 6 40; continue; }
          add_opt "tftp-server-name" "$TFTP"; break
        done
        ;;
      OPT150)
        IPS=$(read_ip_list_csv "TFTP server IP(s) for option 150") || true
        [[ -n ${IPS:-} ]] && OPTS=$(jq --arg code "150" --arg data "$IPS" '. + [{code: ($code|tonumber), space:"dhcp4", data:$data}]' <<<"$OPTS")
        ;;
      USER)
        exec 3>&1
        UCODE=$("$DIALOG" --inputbox "Custom option CODE (1–254)" 8 40 "" 2>&1 1>&3) || { exec 3>&-; continue; }
        UNAME=$("$DIALOG" --inputbox "Custom option NAME (optional)" 8 60 "" 2>&1 1>&3) || { exec 3>&-; continue; }
        USPACE=$("$DIALOG" --inputbox "Option space (default: dhcp4)" 8 60 "dhcp4" 2>&1 1>&3) || { exec 3>&-; continue; }
        UDATA=$("$DIALOG" --inputbox "Option value (string/IPs/hex as needed)" 9 70 "" 2>&1 1>&3) || { exec 3>&-; continue; }
        exec 3>&-
        UCODE=$(trim "$UCODE"); UNAME=$(trim "$UNAME"); USPACE=$(trim "$USPACE"); UDATA=$(trim "$UDATA")
        [[ $UCODE =~ ^[0-9]+$ && $UCODE -ge 1 && $UCODE -le 254 ]] || { "$DIALOG" --msgbox "CODE must be 1–254." 6 32; continue; }
        if [[ -n "$UNAME" ]]; then
          OPTS=$(jq --arg code "$UCODE" --arg name "$UNAME" --arg space "$USPACE" --arg data "$UDATA" '. + [{code: ($code|tonumber), name:$name, space:$space, data:$data}]' <<<"$OPTS")
        else
          OPTS=$(jq --arg code "$UCODE" --arg space "$USPACE" --arg data "$UDATA" '. + [{code: ($code|tonumber), space:$space, data:$data}]' <<<"$OPTS")
        fi
        ;;
      SHOW)
        tmp="$TMPROOT/opts.$RANDOM.json"; echo "$OPT S" | jq . > "$tmp"
        "$DIALOG" --title "Current option-data" --textbox "$tmp" 0 0
        ;;
      DONE) break ;;
    esac
  done

  # ---- Ensure essentials / prompt-if-missing (NO DUPES) ----
  if (( ! HAS_ROUTERS )); then
    OPTS=$(jq --arg name "routers" --arg data "$DHCPDEFGW" '. + [{name:$name, data:$data}]' <<<"$OPTS"); HAS_ROUTERS=1
  fi
  if (( ! HAS_DNS )); then
    OPTS=$(jq --arg name "domain-name-servers" --arg data "$DHCPDEFGW" '. + [{name:$name, data:$data}]' <<<"$OPTS"); HAS_DNS=1
  fi
  if (( ! HAS_DN )); then
    DNVAL=$("$DIALOG" --inputbox "Domain name (Option 15 – e.g. example.local)" 8 60 "" 3>&1 1>&2 2>&3) || DNVAL=""
    DNVAL=$(trim "$DNVAL")
    if [[ -n "$DNVAL" ]] && valid_domain "$DNVAL"; then
      OPTS=$(jq --arg n "domain-name" --arg d "$DNVAL" '. + [{name:$n,data:$d}]' <<<"$OPTS")
    fi
  fi
  if (( ! HAS_SEARCH )); then
    if DOMS=$(read_domain_list_csv); then
      OPTS=$(jq --arg n "domain-search" --arg d "$DOMS" '. + [{name:$n,data:$d}]' <<<"$OPTS")
    fi
  fi

  # ---- Human-readable preview for review page ----
  OPTIONS_PREVIEW=$(jq -r '
    def fmt(x): if (x|type)=="array" then (x|join(", ")) else (x|tostring) end;
    .[] |
    if has("name") then
      "- " + .name + " → " + fmt(.data)
    else
      "- code " + ( .code|tostring ) +
        (if has("name") then " (" + .name + ")" else "" end) +
        (if has("space") then " [" + .space + "]" else "" end) +
        " → " + fmt(.data)
    end
  ' <<<"$OPTS")
  [[ -z "$OPTIONS_PREVIEW" ]] && OPTIONS_PREVIEW="(none)"
  opt_lines=$(echo "$OPTIONS_PREVIEW" | sed '/^$/d' | wc -l)
  MAX_SHOWN=18
  if (( opt_lines > MAX_SHOWN )); then
    OPTIONS_PREVIEW="$(echo "$OPTIONS_PREVIEW" | head -n $MAX_SHOWN)
... ($(($opt_lines - $MAX_SHOWN)) more not shown)"
  fi

  REVIEW="About to add:

Subnet ID: $SID
Subnet:    $SUBNET_CIDR
Interface: $IFACE${IFACE_IP:+  (IP $IFACE_IP)}
Range:     $DHCPBEGIP  -  $DHCPENDIP
Gateway:   $DHCPDEFGW
Comment:   $SUBNETDESC

Option-data:
$OPTIONS_PREVIEW

Proceed?"

  H=$((20 + (opt_lines>MAX_SHOWN ? MAX_SHOWN : opt_lines) ))
  (( H > 32 )) && H=32
  "$DIALOG" --yesno "$REVIEW" "$H" 92 || return 0

  SUBNET_JSON=$(jq -n \
    --argjson id "$SID" \
    --arg subnet "$SUBNET_CIDR" \
    --arg desc "$SUBNETDESC" \
    --arg iface "$IFACE" \
    --arg pool "$DHCPBEGIP - $DHCPENDIP" \
    --argjson opts "$OPTS" \
    '{ id:$id, subnet:$subnet, interface:$iface, comment:$desc, pools:[{pool:$pool}], "option-data":$opts }')

  IFACE_ADD=1
  mapfile -t CUR_IFS < <(jq -r '.Dhcp4."interfaces-config".interfaces[]? // empty' "$CONF" 2>/dev/null || true)
  for x in "${CUR_IFS[@]:-}"; do
    if [[ "$x" == "$IFACE" || "$x" == "any" || "$x" == "*" || "$x" == "all" ]]; then
      IFACE_ADD=0; break
    fi
  done

  TMP_CONF="$TMPROOT/kea.new.$RANDOM.json"
  if (( IFACE_ADD )); then
    jq --argjson s "$SUBNET_JSON" --arg iface "$IFACE" '
      .Dhcp4.subnet4 = ((.Dhcp4.subnet4 // []) + [ $s ]) |
      .Dhcp4."interfaces-config".interfaces =
        (((.Dhcp4."interfaces-config".interfaces // []) + [ $iface ]) | unique)
    ' "$CONF" > "$TMP_CONF"
  else
    jq --argjson s "$SUBNET_JSON" '
      .Dhcp4.subnet4 = ((.Dhcp4.subnet4 // []) + [ $s ])
    ' "$CONF" > "$TMP_CONF"
  fi

  if kea_validate "$TMP_CONF"; then
    ts=$(date +%Y%m%d%H%M%S); cp -a "$CONF" "${CONF}.bak.${ts}" || die "Backup failed."
    cp -f "$TMP_CONF" "$CONF" || die "Write failed."
    chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
    "$DIALOG" --msgbox "Configuration validated and written.\nSubnet appended to $CONF" 8 72
  else
    "$DIALOG" --msgbox "KEA config test FAILED. No changes written." 7 70
    return 1
  fi

  "$DIALOG" --yesno "Restart $SERVICE now?" 7 40 && restart_service
}

# ==========================================================
#              SUBNET DELETE (dialog) — KEA JSON
# ==========================================================
subnet_delete_menu(){
  [[ -f "$CONF" ]] || die "$CONF not found."
  cmd_exists jq || die "jq is required."

  mapfile -t items < <(jq -r '
    .Dhcp4.subnet4[]? | "\(.id)|\(.subnet)|\(.comment // "(no comment)")|\(if .pools and (.pools|length>0) then (.pools[0].pool) else "" end)"
  ' "$CONF")

  (( ${#items[@]} )) || { "$DIALOG" --msgbox "No subnets found." 6 40; return 0; }

  local ARGS=() id subnet comment range label
  for line in "${items[@]}"; do
    IFS='|' read -r id subnet comment range <<<"$line"
    label="${subnet}  ${range:+[$range] }- ${comment}"
    ARGS+=( "$id" "$label" off )
  done

  picks=$("$DIALOG" --checklist "Select subnet ID(s) to DELETE:" 24 100 14 "${ARGS[@]}" 3>&1 1>&2 2>&3) || return 0
  picks=$(echo "$picks" | sed 's/"//g'); [[ -z "$picks" ]] && { "$DIALOG" --msgbox "No subnets selected." 6 40; return 0; }

  local TMP_CONF="$TMPROOT/kea.del.$RANDOM.json"
  jq --arg picks "$picks" '
    [($picks|split(" "))[] | tonumber] as $ids
    | .Dhcp4.subnet4 |= map(select((.id|IN($ids[]))|not))
  ' "$CONF" > "$TMP_CONF"

  if kea_validate "$TMP_CONF"; then
    local ts; ts=$(date +%Y%m%d%H%M%S); cp -a "$CONF" "${CONF}.bak.${ts}" || die "Backup failed."
    cp -f "$TMP_CONF" "$CONF" || die "Write failed."
    chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
    "$DIALOG" --yesno "Deletion applied. Restart $SERVICE now?" 8 60 && restart_service
  else
    "$DIALOG" --msgbox "KEA config validation FAILED. No changes written." 7 70
  fi
}

# ==========================================================
#           MAC RESERVATIONS (add / delete) — KEA
# ==========================================================
ip_to_int(){ IFS=. read -r a b c d <<< "$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }

add_mac_reservation(){
  cmd_exists jq || die "jq is required."
  [[ -f "$CONF" ]] || die "$CONF not found."

  exec 3>&1
  mac=$("$DIALOG" --inputbox "MAC address (e.g. 00:11:22:33:44:55)" 8 50 "" 2>&1 1>&3) || { exec 3>&-; return; }
  ip=$("$DIALOG" --inputbox "IPv4 address to reserve" 8 50 "" 2>&1 1>&3) || { exec 3>&-; return; }
  host=$("$DIALOG" --inputbox "Hostname (optional)" 8 50 "" 2>&1 1>&3)
  exec 3>&-

  mac=$(trim "$mac"); ip=$(trim "$ip"); host=$(trim "$host")
  [[ "$mac" =~ ^([A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}$ ]] || { "$DIALOG" --msgbox "Invalid MAC." 6 30; return; }
  ip_ok "$ip" || { "$DIALOG" --msgbox "Invalid IPv4." 6 30; return; }

  mapfile -t subs < <(jq -c '.Dhcp4.subnet4[]' "$CONF")
  target=""
  for i in "${!subs[@]}"; do
    cidr=$(jq -r '.subnet' <<<"${subs[$i]}")
    [[ "$cidr" == "null" ]] && continue
    base="${cidr%/*}"; pfx="${cidr#*/}"
    mask=$(( 0xFFFFFFFF << (32 - pfx) & 0xFFFFFFFF ))
    (( ( $(ip_to_int "$ip") & mask ) == ( $(ip_to_int "$base") & mask ) )) && { target="$i"; break; }
  done
  [[ -z "$target" ]] && { "$DIALOG" --msgbox "No matching subnet for $ip." 6 44; return; }

  if jq -e --arg mac "$mac" '.Dhcp4.subnet4[].reservations[]? | select(."hw-address" == $mac)' "$CONF" >/dev/null; then
    "$DIALOG" --msgbox "MAC $mac already reserved." 6 50; return
  fi
  if jq -e --arg ip "$ip" '.Dhcp4.subnet4[].reservations[]? | select(."ip-address" == $ip)' "$CONF" >/dev/null; then
    "$DIALOG" --msgbox "IP $ip already reserved." 6 50; return
  fi

  tmp=$(mktemp)
  jq --arg mac "$mac" --arg ip "$ip" --arg host "$host" --argjson idx "$target" '
    if (.Dhcp4.subnet4[$idx].reservations) then
      .Dhcp4.subnet4[$idx].reservations += [{"hw-address": $mac, "ip-address": $ip} + (if $host=="" then {} else {"hostname":$host} end)]
    else
      .Dhcp4.subnet4[$idx].reservations  = [{"hw-address": $mac, "ip-address": $ip} + (if $host=="" then {} else {"hostname":$host} end)]
    end
  ' "$CONF" > "$tmp"

  if kea_validate "$tmp"; then
    mv "$tmp" "$CONF"; chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
    systemctl restart "$SERVICE"
    "$DIALOG" --msgbox "Reservation added and $SERVICE restarted." 6 60
  else
    rm -f "$tmp"; "$DIALOG" --msgbox "Validation failed; no change written." 6 60
  fi
}

delete_mac_reservation(){
  cmd_exists jq || die "jq is required."
  cmd_exists python3 || die "python3 is required."
  [[ -f "$CONF" ]] || die "$CONF not found."

  # Build list (tag = "mac|sid")
  mapfile -t RES_LIST < <(
    jq -r '
      .Dhcp4.subnet4[] |
      .id as $sid | .comment as $desc |
      (.reservations // [])[]? |
      "\($sid)|\($desc // "(no comment)")|\(."hw-address")|\(."ip-address")|\(.hostname // "")"
    ' "$CONF"
  )
  if [[ ${#RES_LIST[@]} -eq 0 ]]; then
    "$DIALOG" --msgbox "No static reservations found." 6 50
    return
  fi

  MENU=()
  for entry in "${RES_LIST[@]}"; do
    IFS="|" read -r sid desc mac ip host <<< "$entry"
    label="$mac → $ip"
    [[ -n "$host" ]] && label+=" ($host)"
    [[ -n "$desc" ]] && label+="  -  $desc"
    MENU+=("${mac}|${sid}" "$label" off)
  done

  # ✅ Robust capture: stdout gets the values; stderr goes to the screen
  sel=$("$DIALOG" --separate-output --checklist "Select reservation(s) to delete:" 22 90 12 "${MENU[@]}" 3>&1 1>&2 2>&3) || return 0
  # Convert newline-separated tags to space-separated string
  sel=$(echo "$sel" | tr '\n' ' ' | sed 's/^ *//;s/ *$//')
  [[ -z "$sel" ]] && { "$DIALOG" --msgbox "No reservations selected." 6 40; return 0; }

  tmp_json=$(mktemp)
  tmp_cnt=$(mktemp)

  # Python: remove selected (mac|sid) pairs; write JSON to stdout and a deletion count to tmp_cnt
  if ! python3 - "$CONF" "$sel" "$tmp_cnt" > "$tmp_json" <<'PY'
import json, sys
conf_path, picks_raw, cnt_path = sys.argv[1], sys.argv[2], sys.argv[3]
targets=set()
for tok in (picks_raw or "").split():
    if "|" in tok:
        mac,sid = tok.split("|",1)
        try:
            targets.add((mac.strip().lower(), int(sid.strip())))
        except ValueError:
            pass

with open(conf_path,"r") as f:
    data=json.load(f)

removed=0
dhcp4 = data.get("Dhcp4", {})
for subnet in dhcp4.get("subnet4", []) or []:
    sid = subnet.get("id")
    res = subnet.get("reservations")
    if not res:
        continue
    keep=[]
    for r in res:
        mac=(r.get("hw-address") or "").lower()
        if (mac, sid) in targets:
            removed += 1
        else:
            keep.append(r)
    if keep:
        subnet["reservations"]=keep
    else:
        subnet.pop("reservations", None)

with open(cnt_path,"w") as cf:
    cf.write(str(removed))

json.dump(data, sys.stdout, indent=2)
PY
  then
    rm -f "$tmp_json" "$tmp_cnt"
    "$DIALOG" --msgbox "Failed to update configuration." 6 44
    return 1
  fi

  removed=$(cat "$tmp_cnt" 2>/dev/null || echo 0); rm -f "$tmp_cnt"
  if [[ "$removed" -eq 0 ]]; then
    "$DIALOG" --msgbox "No matching reservation(s) found to delete.\n\nSelected: $sel" 10 70
    rm -f "$tmp_json"
    return 0
  fi

  # Validate, back up, write, restart
  if kea_validate "$tmp_json"; then
    cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d%H%M%S)" || true
    mv -f "$tmp_json" "$CONF"
    chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
    systemctl restart "$SERVICE" >/dev/null 2>&1 || true
    "$DIALOG" --msgbox "Deleted $removed reservation(s) and restarted $SERVICE." 6 64
  else
    rm -f "$tmp_json"
    "$DIALOG" --msgbox "KEA config validation FAILED; no changes written." 7 64
  fi
}

browse_mac_reservations(){
  cmd_exists jq || die "jq is required."
  cmd_exists python3 || die "python3 is required."
  [[ -f "$CONF" ]] || die "$CONF not found."

  # ── collect subnets for menu
  mapfile -t SUBS < <(jq -r '.Dhcp4.subnet4[] | "\(.id)|\(.subnet)|\(.comment // "(no comment)")"' "$CONF")
  if [[ ${#SUBS[@]} -eq 0 ]]; then
    "$DIALOG" --msgbox "No subnets found in $CONF." 6 50
    return 0
  fi

  local MENU_ARGS=()
  MENU_ARGS+=( "ALL" "All subnets" )
  for line in "${SUBS[@]}"; do
    IFS="|" read -r sid cidr desc <<<"$line"
    MENU_ARGS+=( "$sid" "ID $sid  -  $cidr  -  ${desc}" )
  done

  local SUB_PICK
  SUB_PICK=$("$DIALOG" --menu "Choose subnet to browse" 18 80 10 "${MENU_ARGS[@]}" 3>&1 1>&2 2>&3) || return 0

  # ── optional query
  local query qlc
  query=$("$DIALOG" --inputbox "Search (optional)\n• Matches MAC / IP / Hostname (case-insensitive)\n• Leave blank to list all" 10 72 "" 3>&1 1>&2 2>&3) || return 0
  query=$(trim "$query"); qlc=${query,,}

  # ── pull reservations (as TSV): SID<TAB>SUBNET<TAB>DESC<TAB>MAC<TAB>IP<TAB>HOST
  local jq_prog jq_args=()
  if [[ "$SUB_PICK" == "ALL" ]]; then
    jq_prog='.Dhcp4.subnet4[]
      | .id as $sid | .subnet as $cidr | .comment as $desc
      | (.reservations // [])[]?
      | [$sid, $cidr, ($desc // "(no comment)"), ."hw-address", ."ip-address", (.hostname // "")]
      | @tsv'
  else
    jq_prog='
      .Dhcp4.subnet4[]
      | select(.id == $sid)
      | .id as $sid | .subnet as $cidr | .comment as $desc
      | (.reservations // [])[]?
      | [$sid, $cidr, ($desc // "(no comment)"), ."hw-address", ."ip-address", (.hostname // "")]
      | @tsv'
    jq_args=(--argjson sid "$SUB_PICK")
  fi

  mapfile -t RAW < <(jq -r "${jq_args[@]}" "$jq_prog" "$CONF")
  if [[ ${#RAW[@]} -eq 0 ]]; then
    "$DIALOG" --msgbox "No reservations found for the selected scope." 6 60
    return 0
  fi

  # ── apply query on MAC/IP/HOST (case-insensitive)
  local FILTERED=()
  if [[ -n "$qlc" ]]; then
    for row in "${RAW[@]}"; do
      IFS=$'\t' read -r sid cidr desc mac ip host <<<"$row"
      if [[ "${mac,,}" == *"$qlc"* || "${ip,,}" == *"$qlc"* || "${host,,}" == *"$qlc"* ]]; then
        FILTERED+=("$row")
      fi
    done
  else
    FILTERED=("${RAW[@]}")
  fi

  if [[ ${#FILTERED[@]} -eq 0 ]]; then
    "$DIALOG" --msgbox "No reservations match your search." 6 44
    return 0
  fi

  # ── pretty table + keys for checklist
  local tmp_table tmp_keys
  tmp_table=$(mktemp); tmp_keys=$(mktemp)
  {
    printf "%-6s %-18s %-22s %-18s %-16s %-s\n" "SID" "SUBNET" "DESC" "MAC" "IP" "HOSTNAME"
    echo   "---------------------------------------------------------------------------------------------------------------"
    for row in "${FILTERED[@]}"; do
      IFS=$'\t' read -r sid cidr desc mac ip host <<<"$row"
      printf "%-6s %-18s %-22s %-18s %-16s %-s\n" "$sid" "$cidr" "$desc" "$mac" "$ip" "$host"
      label="$mac → $ip"; [[ -n "$host" ]] && label+=" ($host)"; label+="  -  $desc [SID $sid]"
      # Write TAG<TAB>LABEL so TAG can contain a literal '|'
      printf "%s\t%s\n" "${mac}|${sid}" "$label" >>"$tmp_keys"
    done
  } >"$tmp_table"

  "$DIALOG" --title "Reservations (browse)" --textbox "$tmp_table" 0 0

  # ── ask to delete from this subset
  "$DIALOG" --yesno "Delete any reservation(s) from this result set?" 7 60 || { rm -f "$tmp_table" "$tmp_keys"; return 0; }

  # checklist built from subset (read TAG and LABEL separated by TAB)
  local CK_ARGS=() tag lbl
  while IFS=$'\t' read -r tag lbl; do
    CK_ARGS+=( "$tag" "$lbl" off )
  done <"$tmp_keys"
  rm -f "$tmp_table" "$tmp_keys"

  # Separate-output -> one TAG per line (each TAG is mac|sid)
  local sel
  sel=$("$DIALOG" --separate-output --checklist "Select reservation(s) to delete:" 22 100 14 "${CK_ARGS[@]}" 3>&1 1>&2 2>&3) || return 0
  sel=$(echo "$sel" | tr '\n' ' ' | sed 's/^ *//;s/ *$//')
  [[ -z "$sel" ]] && { "$DIALOG" --msgbox "No reservations selected." 6 40; return 0; }

  # ── perform deletion using the existing Python mutator
  local tmp_json tmp_cnt
  tmp_json=$(mktemp); tmp_cnt=$(mktemp)

  if ! python3 - "$CONF" "$sel" "$tmp_cnt" > "$tmp_json" <<'PY'
import json, sys
conf_path, picks_raw, cnt_path = sys.argv[1], sys.argv[2], sys.argv[3]
targets=set()
for tok in (picks_raw or "").split():
    if "|" in tok:
        mac,sid = tok.split("|",1)
        try:
            targets.add((mac.strip().lower(), int(sid.strip())))
        except ValueError:
            pass

with open(conf_path,"r") as f:
    data=json.load(f)

removed=0
dhcp4 = data.get("Dhcp4", {})
for subnet in dhcp4.get("subnet4", []) or []:
    sid = subnet.get("id")
    res = subnet.get("reservations")
    if not res:
        continue
    keep=[]
    for r in res:
        mac=(r.get("hw-address") or "").lower()
        if (mac, sid) in targets:
            removed += 1
        else:
            keep.append(r)
    if keep:
        subnet["reservations"]=keep
    else:
        subnet.pop("reservations", None)

with open(cnt_path,"w") as cf:
    cf.write(str(removed))

json.dump(data, sys.stdout, indent=2)
PY
  then
    rm -f "$tmp_json" "$tmp_cnt"
    "$DIALOG" --msgbox "Failed to update configuration." 6 44
    return 1
  fi

  local removed; removed=$(cat "$tmp_cnt" 2>/dev/null || echo 0); rm -f "$tmp_cnt"
  if [[ "$removed" -eq 0 ]]; then
    rm -f "$tmp_json"
    "$DIALOG" --msgbox "No matching reservation(s) found to delete.\n\nSelected: $sel" 10 70
    return 0
  fi

  if kea_validate "$tmp_json"; then
    cp -a "$CONF" "${CONF}.bak.$(date +%Y%m%d%H%M%S)" || true
    mv -f "$tmp_json" "$CONF"
    chown kea:kea "$CONF"; chmod 640 "$CONF"; restorecon "$CONF" 2>/dev/null || true
    systemctl restart "$SERVICE" >/dev/null 2>&1 || true
    "$DIALOG" --msgbox "Deleted $removed reservation(s) and restarted $SERVICE." 6 64
  else
    rm -f "$tmp_json"
    "$DIALOG" --msgbox "KEA config validation FAILED; no changes written." 7 64
  fi
}


reservations_menu(){
  while :; do
    CH=$("$DIALOG" --menu "MAC Reservations" 16 72 8 \
      1 "Add MAC reservation" \
      2 "Browse/search reservations (view + optional delete)" \
      3 "Delete MAC reservation(s) (classic)" \
      4 "Back to main menu" \
      3>&1 1>&2 2>&3) || break
    case "$CH" in
      1) add_mac_reservation ;;
      2) browse_mac_reservations ;;
      3) delete_mac_reservation ;;
      4) break ;;
    esac
  done
}

# ==========================================================
#                          MAIN MENU
# ==========================================================
main_menu(){
  need_root
  cmd_exists "$DIALOG" || die "dialog is not installed."
  cmd_exists jq || die "jq is required."
  cmd_exists kea-dhcp4 || die "kea-dhcp4 is not installed."

  while :; do
    CH=$("$DIALOG" --menu "KEA DHCP Manager\nConfig: $CONF\nService: $SERVICE" 18 76 10 \
      1 "Create DHCP Scope & Options" \
      2 "Delete Subnet(s) from kea-dhcp4.conf" \
      3 "Edit kea-dhcp4.conf (validate, save, restart)" \
      4 "View Leases (raw/search/live)" \
      5 "MAC Reservations (add/delete)" \
      6 "Restart Service" \
      7 "Service Control" \
      8 "Exit" \
      3>&1 1>&2 2>&3) || break
    case "$CH" in
      1)  scope_creator_menu ;;
      2)  subnet_delete_menu ;;
      3)  config_editor ;;
      4)  leases_menu ;;
      5)  reservations_menu ;;
      6)  restart_service ;;
      7) "$DIALOG" --clear; clear; /root/.servman/ServiceMan kea-dhcp4.service || true ;;
      8)  break ;;
      *)  break ;;
    esac
  done
}

main_menu "$@"
