#!/usr/bin/env bash
# meraki_hybrid_preflight.sh — Pre-flight + DNS/NTP/AAA/IP Routing fixes (dialog + parallel)
# Flow:
#   preflight   : select source -> select switches -> probe in parallel -> CSV summary
#   fix-dns     : read latest.csv -> fix DNS (name-server + ip domain lookup) -> verify resolution
#   fix-ntp     : ensure NTP servers; wait 5s; verify sync if possible
#   fix-aaa     : ensure Meraki-required AAA lines (new-model, login default local, authorization exec default local)
#   fix-routing : ensure ip routing + default route (dhcp or static) + ping 8.8.8.8
#
# Exports after preflight:
#   PRE_FLIGHT_RUN_ID, PRE_FLIGHT_RUN_DIR, PRE_FLIGHT_SUMMARY
#   Also writes: runs/preflight/latest.env, runs/preflight/latest, runs/preflight/latest.csv
#
# Usage:
#   ./script                # same as "all"
#   ./script all            # run preflight, then DNS+NTP+AAA+Routing fixes for switches that need it
#   ./script preflight      # just preflight
#   ./script fix-dns        # just DNS fixes (reads runs/preflight/latest.csv)
#   ./script fix-ntp        # just NTP fixes (reads runs/preflight/latest.csv)
#   ./script fix-aaa        # just AAA fixes (reads runs/preflight/latest.csv)
#   ./script fix-routing    # just IP routing / default route fixes (reads runs/preflight/latest.csv)

set -uo pipefail

# ---------- prerequisites ----------
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog; need jq; need awk; need sed; need grep; need ssh; need timeout; need flock
command -v sshpass >/dev/null 2>&1 || true

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPT_DIR"

DISC_ENV="$SCRIPT_DIR/meraki_discovery.env"
SEL_ENV="$SCRIPT_DIR/selected_upgrade.env"
DISC_JSON="$SCRIPT_DIR/discovery_results.json"
SEL_JSON="$SCRIPT_DIR/selected_upgrade.json"
DISC_CSV="$SCRIPT_DIR/discovery_results.csv"

# ---------- tiny utils ----------
__deq(){ local s="${1-}"; s="${s//\\!/!}"; s="${s//\\;/;}"; s="${s//\\ / }"; s="${s//\\\\/\\}"; printf '%s' "$s"; }
trim(){ sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }
now(){ date +%H:%M:%S; }

# CSV append with flock (safe for parallel writers)
append_csv(){
  # Usage: append_csv "/path/to/file.csv" "row,comma,separated"
  local csv="$1"; shift
  local line="$*"
  { flock -x 9
    printf '%s\n' "$line" >&9
  } 9>>"$csv"
}

# ---------- IOS-XE minimum version check ----------
MIN_IOS_VERSION="17.15.03"

ios_meets_min(){
  # returns 0 if $1 >= MIN_IOS_VERSION, else 1
  local v_raw="${1:-}"
  [[ -z "$v_raw" ]] && return 1

  local v nv
  v="${v_raw%% *}"
  v="${v//,/}"
  nv="$(sed 's/[^0-9.].*$//' <<<"$v")"
  [[ -z "$nv" ]] && return 1

  local a b c ma mb mc
  local IFS='.'
  read -r a b c  <<<"$nv"
  read -r ma mb mc <<<"$MIN_IOS_VERSION"

  a=${a:-0};  b=${b:-0};  c=${c:-0}
  ma=${ma:-0}; mb=${mb:-0}; mc=${mc:-0}

  if   (( a > ma )); then return 0
  elif (( a < ma )); then return 1
  fi
  if   (( b > mb )); then return 0
  elif (( b < mb )); then return 1
  fi
  if   (( c >= mc )); then return 0
  else                    return 1
  fi
}

enforce_min_ios_or_abort(){
  # $1 = path to preflight summary CSV (PRE_FLIGHT_SUMMARY)
  local sum="$1"
  local CHECK_ROOT="$SCRIPT_DIR/runs/ioscheck"
  mkdir -p "$CHECK_ROOT"

  local RUN_ID="ioschk-$(date -u +%Y%m%d%H%M%S)"
  local LOG="$CHECK_ROOT/$RUN_ID.csv"
  ln -sfn "$LOG" "$CHECK_ROOT/latest.csv"

  echo "ip,hostname,ios_ver,meets_min_${MIN_IOS_VERSION}" > "$LOG"

  local bad=0
  local -a BAD_LINES=()

  local first=1
  local ip host ios_ver rest
  while IFS=, read -r ip host ios_ver rest; do
    if (( first )); then
      first=0
      continue
    fi
    [[ -z "$ip" ]] && continue

    ios_ver="${ios_ver:-unknown}"

    if ios_meets_min "$ios_ver"; then
      echo "$ip,$host,$ios_ver,yes" >> "$LOG"
    else
      echo "$ip,$host,$ios_ver,no" >> "$LOG"
      ((bad++))
      BAD_LINES+=( "$(printf '%-16s %-25s %s' "$ip" "${host:-<none>}" "${ios_ver:-<unknown>}")" )
    fi
  done < "$sum"

  if (( bad > 0 )); then
    local tmp
    tmp="$(mktemp)"
    {
      echo "The following switches do NOT meet the minimum IOS-XE version ${MIN_IOS_VERSION}:"
      echo
      printf "%-16s %-25s %s\n" "IP" "Hostname" "IOS Version"
      printf "%-16s %-25s %s\n" "----------------" "------------------------" "-----------"
      for line in "${BAD_LINES[@]}"; do
        echo "$line"
      done
      echo
      echo "No DNS/NTP/AAA/IP routing changes were made."
      echo
      echo "A detailed CSV log has been saved to:"
      echo "  $LOG"
    } > "$tmp"

    dlg --title "IOS-XE Minimum Version Check FAILED" --textbox "$tmp" 20 90
    rm -f "$tmp"
    clear
    return 1
  fi

  return 0
}

# ---------- dialog helpers ----------
BACKTITLE="${BACKTITLE:-Meraki Migration Toolkit}"
DOPTS=(--no-shadow --backtitle "$BACKTITLE")
DOUT=""
set_backtitle(){ BACKTITLE="$1"; DOPTS=(--no-shadow --backtitle "$BACKTITLE"); }
dlg(){ local t; t="$(mktemp)"; dialog "${DOPTS[@]}" "$@" 2>"$t"; local rc=$?; DOUT=""; [[ -s "$t" ]] && DOUT="$(<"$t")"; rm -f "$t"; return $rc; }

# ---------- UI (tailbox + gauge) ----------
DIALOG=0; command -v dialog >/dev/null 2>&1 && DIALOG=1
STATUS_FILE=""; GAUGE_PIPE=""; GAUGE_FD=""; DPID=""; MAIN=$$
DIALOG=0; command -v dialog >/dev/null 2>&1 && DIALOG=1
STATUS_FILE=""; GAUGE_PIPE=""; GAUGE_FD=""; DPID=""; MAIN=$$

ui_calc(){
  local L=24 C=80
  read -r L C < <(stty size 2>/dev/null || echo "24 80")
  ((L<20)) && L=20
  ((C<80)) && C=80

  local TOP_PAD=2
  local BOT_PAD=2
  local SIDE_PAD=2
  local SPACE=1

  GAUGE_H=6
  TAIL_W=$(( C - SIDE_PAD*2 ))
  GAUGE_W=$TAIL_W

  TAIL_H=$(( L - TOP_PAD - BOT_PAD - GAUGE_H - SPACE - 2 ))
  (( TAIL_H < 8 )) && TAIL_H=8

  TAIL_ROW=$TOP_PAD
  GAUGE_ROW=$(( TOP_PAD + TAIL_H + SPACE ))
  GAUGE_COL=$SIDE_PAD
}

log(){ printf '%s %s\n' "$(now)" "$1" | tee -a "$STATUS_FILE" >/dev/null; }
gauge(){ local p="${1:-0}" m="${2:-Working…}"; if ((DIALOG)) && [[ -n "${GAUGE_FD:-}" ]] && [[ -e "/proc/$MAIN/fd/$GAUGE_FD" ]]; then printf 'XXX\n%s\n%s\nXXX\n' "$p" "$m" >&"$GAUGE_FD" 2>/dev/null || true; else echo "[progress] $p%% - $m"; fi; }

ui_start(){
  STATUS_FILE="$RUN_DIR/ui.status"; : > "$STATUS_FILE"
  if (( !DIALOG )); then return; fi
  ui_calc
  GAUGE_PIPE="$(mktemp -u)"; mkfifo "$GAUGE_PIPE"; exec {GAUGE_FD}<>"$GAUGE_PIPE"

  ( dialog --no-shadow --backtitle "$BACKTITLE" \
           --begin "$TAIL_ROW" "$GAUGE_COL" \
           --title "$UI_TITLE (run: $RUN_ID)" \
           --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
           --and-widget \
           --begin "$GAUGE_ROW" "$GAUGE_COL" --title "Progress" \
           --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 < "$GAUGE_PIPE" ) & DPID=$!

  sleep 0.15
  printf 'XXX\n1\nStarting…\nXXX\n' >&"$GAUGE_FD" 2>/dev/null || true
}

ui_stop(){
  [[ $$ -ne $MAIN ]] && return
  if ((DIALOG)); then
    printf 'XXX\n100\nDone.\nXXX\n' >&"$GAUGE_FD" 2>/dev/null || true
    exec {GAUGE_FD}>&- 2>/dev/null || true
    rm -f "$GAUGE_PIPE" 2>/dev/null || true
    kill "$DPID" 2>/dev/null || true
  fi
}

# ---------- SSH helpers ----------
build_ssh_arr(){
  local ip="$1"
  SSH_CMD=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=40 \
            -o ServerAliveInterval=10 -o ServerAliveCountMax=6 \
            -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group14-sha1 \
            -tt "${SSH_USERNAME}@${ip}")
  if [[ -n "${SSH_KEY_PATH-}" && -r "$SSH_KEY_PATH" ]]; then
    SSH_CMD+=(-i "$SSH_KEY_PATH" -o BatchMode=yes)
  else
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" "${SSH_CMD[@]}" -o PreferredAuthentications=password,keyboard-interactive \
             -o KbdInteractiveAuthentication=yes -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1)
  fi
}
is_priv15_for_ip(){
  local ip="$1" raw out ok=1
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    printf 'show privilege\r\n'; printf 'exit\r\n'
  } | timeout -k 5s 25s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"
  grep -Eiq 'Current privilege level is[[:space:]]*15' "$out" && ok=0
  rm -f "$raw" "$out"; return $ok
}
emit_enable(){
  printf 'enable\r\n'; sleep 0.2
  if [[ -n "${ENABLE_PASSWORD-}" ]]; then printf '%s\r\n' "$ENABLE_PASSWORD"; else printf '\r\n'; fi
  printf 'show privilege\r\n'; sleep 0.2
}

# =====================================================================
# PRE-FLIGHT
# =====================================================================
probe_one(){
  set +e
  local ip="$1" need_en=0 raw out
  local host ios install_mode meraki_mode
  local dns_ok="no" ntp_ok="no"
  local iprt="unknown" defrt="no" domlkp="enabled"
  local aaa_nm="off" aaa_login="no" aaa_exec="no"
  local tunnel="down" reg="not_registered"
  local ready="no" notes=""

  log "[${ip}] CONNECT…"
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"
  is_priv15_for_ip "$ip" || need_en=1

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show version\r\n'
    printf 'show install summary\r\n'
    printf 'show running-config | include ^ip name-server\r\n'
    printf 'show running-config | include ^ntp server\r\n'
    # routing / default route / domain lookup / aaa
    printf 'show running-config | include ^ip routing\r\n'
    printf 'show running-config | include ^no ip routing\r\n'
    printf 'show running-config | include ^ip route 0.0.0.0 0.0.0.0\r\n'
    printf 'show running-config | include ^ip default-gateway\r\n'
    printf 'show running-config | include ^no ip domain lookup\r\n'
    printf 'show running-config | include ^ip domain lookup\r\n'
    printf 'show running-config | include ^aaa new-model\r\n'
    printf 'show running-config | include ^aaa authentication login default\r\n'
    printf 'show running-config | include ^aaa authorization exec default\r\n'
    # Meraki state
    printf 'show meraki migration\r\n'
    printf 'show meraki connect\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 150s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.session.log"; rm -f "$raw"

  # hostname
  host="$(awk 'match($0,/^([[:alnum:]_.:-]+)[>#][[:space:]]*$/,m){print m[1]; exit}' "$out")"
  [[ -z "$host" ]] && host="$(awk '/^hostname[[:space:]]+/{print $2; exit}' "$out")"
  [[ -z "$host" ]] && host="$ip"

  # IOS-XE version
  ios="$(awk '
    match($0,/Cisco IOS XE Software, Version[[:space:]]+([^ ,]+)/,m){print m[1]; exit}
    match($0,/Version[[:space:]]+([0-9]+\.[0-9]+(\.[0-9A-Za-z]+)?)/,m){print m[1]; exit}
  ' "$out")"

  # INSTALL/BUNDLE
  install_mode="$(awk -F: 'BEGIN{IGNORECASE=1}/Running[[:space:]]+mode/ {gsub(/^[ \t]+/,"",$2); print toupper($2); exit}' "$out")"
  [[ -z "$install_mode" ]] && install_mode="$(grep -Eio '(INSTALL|BUNDLE)' "$out" | head -n1 | tr '[:lower:]' '[:upper:]')"

  # Meraki booted mode
  meraki_mode="$(awk -F: 'BEGIN{IGNORECASE=1}
    /^Meraki Mode Migration Status/ {seen=1}
    seen && /Current Booted Mode/ {gsub(/^[ \t]+/,"",$2); print $2; exit}
  ' "$out")"

  # DNS/NTP presence (or planned via env)
  grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$out" && dns_ok="yes" || { [[ -n "${DNS_PRIMARY:-}" ]] && dns_ok="planned"; }
  grep -Eq '^[[:space:]]*ntp[[:space:]]+server'     "$out" && ntp_ok="yes"  || { [[ -n "${NTP_PRIMARY:-}" ]] && ntp_ok="planned"; }

  # ip routing
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+routing' "$out"; then iprt="no"
  elif grep -Eq '^ip[[:space:]]+routing' "$out"; then iprt="yes"
  else iprt="unknown"; fi

  # default route
  if grep -Eq '^ip[[:space:]]+route[[:space:]]+0\.0\.0\.0[[:space:]]+0\.0\.0\.0[[:space:]]+' "$out"; then
    defrt="yes"
  elif grep -Eq '^ip[[:space:]]+default-gateway[[:space:]]+' "$out"; then
    defrt="legacy"; notes+="default_gateway_unsupported;"
  else
    defrt="no"
  fi

  # domain lookup
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$out"; then domlkp="disabled"; else domlkp="enabled"; fi

  # AAA checks
  grep -Eq '^aaa[[:space:]]+new-model(\s|$)' "$out" && aaa_nm="on" || aaa_nm="off"
  grep -Eq '^aaa[[:space:]]+authentication[[:space:]]+login[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && aaa_login="yes" || aaa_login="no"
  grep -Eq '^aaa[[:space:]]+authorization[[:space:]]+exec[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && aaa_exec="yes" || aaa_exec="no"

  # Meraki registration/tunnel (best-effort)
  if awk 'BEGIN{IGNORECASE=1} /^Meraki Device Registration/{s=1} s && /Status:[[:space:]]+Registered/ {print "1"; exit}' "$out" | grep -q 1; then reg="registered"; fi
  if awk 'BEGIN{IGNORECASE=1} /^Meraki Tunnel State/{s=1} s && /Primary:[[:space:]]+Up/ {print "1"; exit}' "$out" | grep -q 1; then
    tunnel="up"
  elif [[ "$reg" == "registered" ]]; then
    tunnel="registered"
  fi
  if [[ "$meraki_mode" == *"C9K-C"* && ( "$tunnel" == "registered" || "$tunnel" == "up" ) ]]; then
    notes+="already_onboarded;"
  fi

  # gating + notes
  [[ "$install_mode" == "INSTALL" ]] || notes+="mode_${install_mode:-?};"
  [[ "$dns_ok" == "yes" || "$dns_ok" == "planned" ]] || notes+="dns_missing;"
  [[ "$ntp_ok" == "yes" || "$ntp_ok" == "planned" ]] || notes+="ntp_missing;"
  [[ "$iprt" == "yes" ]] || notes+="ip_routing_off;"
  [[ "$defrt" == "yes" ]] || notes+="default_route_missing;"
  [[ "$domlkp" == "enabled" ]] || notes+="domain_lookup_disabled;"
  [[ "$aaa_nm" == "on" ]] || notes+="aaa_new_model_missing;"
  [[ "$aaa_login" == "yes" ]] || notes+="aaa_login_missing;"
  [[ "$aaa_exec" == "yes"  ]] || notes+="aaa_exec_missing;"

  ready="yes"
  for gate in "mode_" "dns_missing" "ntp_missing" "ip_routing_off" "default_route_missing" "domain_lookup_disabled" "aaa_new_model_missing" "aaa_login_missing" "aaa_exec_missing"; do
    [[ "$notes" == *"$gate"* ]] && { ready="no"; break; }
  done

  log "[${ip}] HOST=${host} IOS=${ios:-?} INSTALL_MODE=${install_mode:-?} MERAKI_MODE=${meraki_mode:-} DNS=${dns_ok} NTP=${ntp_ok} IPRT=${iprt} DEFRT=${defrt} DOMLKP=${domlkp} AAA_NM=${aaa_nm} AAA_LOGIN=${aaa_login} AAA_EXEC=${aaa_exec} TUNNEL=${tunnel} READY=${ready}"
  echo "${ip},${host},${ios:-},${install_mode:-},${meraki_mode:-},${dns_ok},${ntp_ok},${iprt},${defrt},${domlkp},${tunnel},${ready},${notes}" >> "$SUMMARY_CSV"
  rm -f "$out"
}

meraki_preflight(){
  trap 'ui_stop' EXIT
  set_backtitle "Meraki Preflight"

  # env
  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  DNS_PRIMARY="$(__deq "${DNS_PRIMARY-}")"
  DNS_SECONDARY="$(__deq "${DNS_SECONDARY-}")"
  NTP_PRIMARY="$(__deq "${NTP_PRIMARY-}")"
  NTP_SECONDARY="$(__deq "${NTP_SECONDARY-}")"

  if [[ -z "${SSH_KEY_PATH-}" && -n "$SSH_PASSWORD" ]] && ! command -v sshpass >/dev/null 2>&1; then
    dlg --title "Missing requirement" --msgbox "sshpass is required when SSH_PASSWORD is used.\n\nInstall it or set SSH_KEY_PATH to a readable private key." 11 70
    clear; trap - EXIT; return 1
  fi
  [[ -n "$SSH_USERNAME" ]] || { dlg --title "Missing" --msgbox "SSH_USERNAME is empty in meraki_discovery.env" 7 60; clear; trap - EXIT; return 1; }

  # determine source automatically – prefer selected over discovery
  local SRC=""
  local have_disc="" have_sel_json="" have_sel_ips=""

  # selected_upgrade.json
  [[ -s "$SEL_JSON" && "$(jq 'length' "$SEL_JSON" 2>/dev/null || echo 0)" -gt 0 ]] && have_sel_json=1

  # selected_upgrade.env (UPGRADE_SELECTED_IPS)
  if [[ -f "$SEL_ENV" ]]; then
    source "$SEL_ENV"
    UPGRADE_SELECTED_IPS="$(__deq "${UPGRADE_SELECTED_IPS-}")"
    [[ -n "$UPGRADE_SELECTED_IPS" ]] && have_sel_ips=1
  fi

  # discovery_results.json as a fallback
  [[ -s "$DISC_JSON" ]] && have_disc=1

  if [[ -n "$have_sel_json" ]]; then
    SRC="seljson"
  elif [[ -n "$have_sel_ips" ]]; then
    SRC="selips"
  elif [[ -n "$have_disc" ]]; then
    SRC="disc"
  else
    dlg --title "Nothing to pick" --msgbox "No selected_upgrade.json, selected_upgrade.env, or discovery_results.json found.\nRun the IOS-XE upgrader or Discovery first." 10 75
    clear; trap - EXIT; return 1
  fi

  # checklist
  declare -a IPS HOSTS PIDS VERS SER
  if [[ "$SRC" == "disc" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$DISC_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$DISC_JSON" 2>/dev/null)
    mapfile -t PIDS  < <(jq -r '.[].pid // ""' "$DISC_JSON" 2>/dev/null)
    mapfile -t VERS  < <(jq -r '.[].version // ""' "$DISC_JSON" 2>/dev/null)
    mapfile -t SER   < <(jq -r '.[].serial // ""' "$DISC_JSON" 2>/dev/null)
  elif [[ "$SRC" == "seljson" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$SEL_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$SEL_JSON" 2>/dev/null)
    mapfile -t PIDS  < <(jq -r '.[].pid // ""' "$SEL_JSON" 2>/dev/null)
    mapfile -t VERS  < <(jq -r '.[].installed_version // ""' "$SEL_JSON" 2>/dev/null)
    mapfile -t SER   < <(jq -r '.[].serial // ""' "$SEL_JSON" 2>/dev/null)
  else
    # SRC = "selips" — only have UPGRADE_SELECTED_IPS. Enrich from
    # discovery_results.json (preferred) or discovery_results.csv (fallback).
    read -r -a IPS <<<"${UPGRADE_SELECTED_IPS:-}"

    HOSTS=(); PIDS=(); VERS=(); SER=()

    if [[ -s "$DISC_JSON" ]]; then
      # Build maps: ip -> hostname/version/pid/serial from discovery_results.json
      declare -A HMAP VMAP PMAP SMAP
      while IFS=$'\t' read -r ip h v p s; do
        HMAP["$ip"]="$h"
        VMAP["$ip"]="$v"
        PMAP["$ip"]="$p"
        SMAP["$ip"]="$s"
      done < <(jq -r '.[] | [.ip,
                               (.hostname // ""),
                               (.version  // ""),
                               (.pid      // ""),
                               (.serial   // "")] | @tsv' "$DISC_JSON")

      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
        VERS+=(  "${VMAP[$ip]:-}" )
        PIDS+=(  "${PMAP[$ip]:-}" )
        SER+=(   "${SMAP[$ip]:-}" )
      done

    elif [[ -s "$DISC_CSV" ]]; then
      # Fallback: build maps from discovery_results.csv
      declare -A HMAP VMAP PMAP SMAP
      local ip ssh login hostname version pid serial
      local first=1
      while IFS=, read -r ip ssh login hostname version pid serial; do
        if (( first )); then
          first=0
          continue
        fi
        # strip surrounding quotes if present
        ip="${ip%\"}"; ip="${ip#\"}"
        hostname="${hostname%\"}"; hostname="${hostname#\"}"
        version="${version%\"}";  version="${version#\"}"
        pid="${pid%\"}";          pid="${pid#\"}"
        serial="${serial%\"}";    serial="${serial#\"}"

        HMAP["$ip"]="$hostname"
        VMAP["$ip"]="$version"
        PMAP["$ip"]="$pid"
        SMAP["$ip"]="$serial"
      done < "$DISC_CSV"

      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
        VERS+=(  "${VMAP[$ip]:-}" )
        PIDS+=(  "${PMAP[$ip]:-}" )
        SER+=(   "${SMAP[$ip]:-}" )
      done

    else
      # No discovery metadata available; keep descriptions minimal.
      for _ in "${IPS[@]}"; do
        HOSTS+=("")
        PIDS+=("")
        VERS+=("")
        SER+=("")
      done
    fi
  fi

  (( ${#IPS[@]} > 0 )) || { dlg --title "No devices" --msgbox "The chosen source has zero devices." 7 60; clear; trap - EXIT; return 1; }

  local CHK=()
  for i in "${!IPS[@]}"; do
    local ip="${IPS[$i]}" h="${HOSTS[$i]}" p="${PIDS[$i]}" s="${SER[$i]}"
    # NOTE: version intentionally *not* shown here to avoid stale info.
    local desc; desc="$(trim "${h:-$ip}  ${p:+($p) }${s:+SN:$s}")"
    CHK+=( "$ip" "$desc" "on" )
  done

  dlg --title "Select switches" --checklist "Choose devices to preflight:" 20 78 12 "${CHK[@]}"
  [[ $? -eq 0 ]] || { clear; trap - EXIT; return 1; }
  read -r -a TARGETS <<<"$DOUT"
  (( ${#TARGETS[@]} )) || { clear; trap - EXIT; return 0; }

  # run directory
  RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/preflight"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"

  # export + persist "latest"
  PRE_FLIGHT_RUN_ID="$RUN_ID"; export PRE_FLIGHT_RUN_ID
  PRE_FLIGHT_RUN_DIR="$RUN_DIR"; export PRE_FLIGHT_RUN_DIR
  PRE_FLIGHT_SUMMARY=""; export PRE_FLIGHT_SUMMARY
  printf 'export PRE_FLIGHT_RUN_ID=%q\nexport PRE_FLIGHT_RUN_DIR=%q\n' \
    "$PRE_FLIGHT_RUN_ID" "$PRE_FLIGHT_RUN_DIR" > "$RUN_ROOT/latest.env"
  ln -sfn "$PRE_FLIGHT_RUN_DIR" "$RUN_ROOT/latest"

  # CSV header
  SUMMARY_CSV="$RUN_DIR/summary.csv"
  echo "ip,hostname,ios_ver,install_mode,meraki_mode,dns_ok,ntp_ok,ip_routing,default_route,domain_lookup,tunnel,ready,notes" > "$SUMMARY_CSV"
  PRE_FLIGHT_SUMMARY="$SUMMARY_CSV"; export PRE_FLIGHT_SUMMARY
  printf 'export PRE_FLIGHT_SUMMARY=%q\n' "$PRE_FLIGHT_SUMMARY" >> "$RUN_ROOT/latest.env"
  ln -sfn "$PRE_FLIGHT_SUMMARY" "$RUN_ROOT/latest.csv"

  # run workers
  UI_TITLE="Preflight"
  ui_start
  log "Preflight Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Env: ${DISC_ENV}"
  log "Targets: ${TARGETS[*]}"
  gauge 1 "Starting…"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}
  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( probe_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      if wait -n; then :; fi
      ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Probed $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done

  while (( DONE < TOTAL )); do
    if wait -n; then :; fi
    ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Probed $DONE / $TOTAL"
  done

  gauge 100 "Done"
  log "Summary: $SUMMARY_CSV"
  ui_stop

  clear
  echo "Preflight complete."
  echo "Run directory: $RUN_DIR"
  echo "Summary CSV:   $SUMMARY_CSV"
  trap - EXIT
}
# =====================================================================
# DNS FIX
# =====================================================================
fix_dns_one(){
  set +e
  local ip="$1" need_en=0 raw out changed="no" enabled_dl="no" resolved="no" notes=""
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  log "[${ip}] CONNECT…"
  is_priv15_for_ip "$ip" || need_en=1

  # pre-read current state
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^ip name-server\r\n'
    printf 'show running-config | include ^no ip domain lookup\r\n'
    printf 'show running-config | include ^ip domain lookup\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.dnsfix.log"; : > "$raw"

  local have_dns="no" domlkp_state="enabled"
  grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$out" && have_dns="yes"
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$out"; then domlkp_state="disabled"; fi

  log "[${ip}] Current: DNS=${have_dns} DOMAIN_LOOKUP=${domlkp_state}"

  local need_dns=0 need_dl=0
  [[ "$have_dns" != "yes" ]] && need_dns=1
  [[ "$domlkp_state" == "disabled" ]] && need_dl=1
  [[ $need_dns -eq 1 ]] && log "[${ip}] Will configure DNS from env: ${DNS_PRIMARY:-<none>} ${DNS_SECONDARY:-<none>}"
  [[ $need_dl  -eq 1 ]] && log "[${ip}] Will enable ip domain lookup"

  if (( need_dns || need_dl )); then
    [[ $need_dns -eq 1 ]] && changed="yes"
    if (( need_dl )); then enabled_dl="yes"; changed="yes"; fi

    {
      printf '\r\n'
      (( need_en )) && emit_enable
      printf 'configure terminal\r\n'
      if (( need_dns )); then
        [[ -n "${DNS_PRIMARY:-}"   ]] && printf 'ip name-server %s\r\n' "$DNS_PRIMARY"
        [[ -n "${DNS_SECONDARY:-}" ]] && printf 'ip name-server %s\r\n' "$DNS_SECONDARY"
      fi
      if (( need_dl )); then
        printf 'ip domain lookup\r\n'
      fi
      printf 'end\r\n'
      printf 'write memory\r\n'
      printf 'exit\r\n'
    } | timeout -k 15s 180s "${SSH_CMD[@]}" >>"$raw" 2>&1 || true
    tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.dnsfix.log"; : > "$raw"
  else
    log "[${ip}] Nothing to change."
  fi

  # verify config actually present after write
  {
    printf '\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^ip name-server\r\n'
    printf 'show running-config | include ^no ip domain lookup\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.dnsfix.log"
  if ! grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$out"; then
    [[ $need_dns -eq 1 ]] && notes+="dns_lines_missing_after_apply;"
  fi
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$out"; then
    [[ $need_dl -eq 1 ]] && notes+="domain_lookup_not_enabled;"
  fi

  # verify resolution: accept any success
  {
    printf '\r\n'
    (( need_en )) && emit_enable
    printf 'ping google.com repeat 2 timeout 2\r\n'
    printf '\r\n\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 60s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.dnsfix.log"
  if grep -Eiq 'Success +rate +is +([1-9][0-9]*|[0-9]*[1-9]) +percent' "$out" || grep -q '!' "$out"; then
    resolved="yes"
  else
    resolved="no"; notes+="dns_resolution_failed;"
  fi

  log "[${ip}] RESULT: CHANGED=${changed} DOMAIN_LOOKUP_ENABLED=${enabled_dl} RESOLVED=${resolved} ${notes:+NOTES=}${notes}"
  append_csv "$DNSFIX_CSV" "${ip},${changed},${enabled_dl},${resolved},${notes}"

  sleep 0.5
  rm -f "$raw" "$out"
}

meraki_fix_dns(){
  trap 'ui_stop' EXIT
  set_backtitle "Meraki DNS Updater"

  # env
  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  DNS_PRIMARY="$(__deq "${DNS_PRIMARY-}")"
  DNS_SECONDARY="$(__deq "${DNS_SECONDARY-}")"

  # latest preflight CSV
  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""
  if [[ -f "$LATEST_ENV" ]]; then source "$LATEST_ENV"; SUM="${PRE_FLIGHT_SUMMARY:-}"; fi
  [[ -z "${SUM:-}" || ! -f "$SUM" ]] && { dlg --title "No Preflight Summary" --msgbox "Could not find runs/preflight/latest.csv.\nRun preflight first." 9 70; clear; trap - EXIT; return 1; }

  # IOS-XE minimum version check (unless already done in 'all' pipeline)
  if [[ "${SKIP_IOS_CHECK:-0}" != "1" ]]; then
    if ! enforce_min_ios_or_abort "$SUM"; then
      trap - EXIT
      return 1
    fi
  fi

  # targets needing DNS or domain-lookup change
  mapfile -t TARGETS < <(awk -F, 'NR>1 { if ($6!="yes" || $10=="disabled") print $1 }' "$SUM")
  if (( ${#TARGETS[@]} == 0 )); then
    dialog --no-shadow --backtitle "$BACKTITLE" --infobox "All switches already have DNS and domain lookup enabled.\nNothing to do." 7 70
    sleep 2
    clear; trap - EXIT; return 0
  fi

  # run directory
  RUN_ID="dns-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/dnsfix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  # CSV for results
  DNSFIX_CSV="$RUN_DIR/dnsfix.csv"
  echo "ip,changed_dns,enabled_domain_lookup,resolution_ok,notes" > "$DNSFIX_CSV"

  # UI
  dialog --no-shadow --backtitle "$BACKTITLE" --infobox "Updating DNS entries and domain lookup if needed..." 7 70
  sleep 2
  UI_TITLE="DNS Fix"
  ui_start
  log "DNS Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets needing DNS/domain-lookup: ${TARGETS[*]}"
  log "Using DNS servers: ${DNS_PRIMARY:-<none>} ${DNS_SECONDARY:-<none>}"
  gauge 1 "Starting…"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}
  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( fix_dns_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      if wait -n; then :; fi
      ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Fixed $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done

  while (( DONE < TOTAL )); do
    if wait -n; then :; fi
    ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Fixed $DONE / $TOTAL"
  done

  gauge 100 "Done"
  log "Results: $DNSFIX_CSV"
  ui_stop
  sleep 0.5
  dialog --no-shadow --backtitle "$BACKTITLE" --infobox "DNS entries updated (if applicable)." 5 60
  sleep 2
  trap - EXIT
  return 0
}

# =====================================================================
# NTP FIX
# =====================================================================
fix_ntp_one(){
  set +e
  local ip="$1" need_en=0 raw out changed="no" synced="no" notes=""
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  log "[${ip}] CONNECT…"
  is_priv15_for_ip "$ip" || need_en=1

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^ntp server\r\n'
    printf 'show ntp status\r\n'
    printf 'show ntp associations\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.ntpfix.log"; : > "$raw"

  local have_p="no" have_s="no"
  [[ -n "${NTP_PRIMARY:-}"   ]] && grep -Eq "^[[:space:]]*ntp[[:space:]]+server[[:space:]]+${NTP_PRIMARY//./\\.}(\\b|$)" "$out" && have_p="yes"
  [[ -n "${NTP_SECONDARY:-}" ]] && grep -Eq "^[[:space:]]*ntp[[:space:]]+server[[:space:]]+${NTP_SECONDARY//./\\.}(\\b|$)" "$out" && have_s="yes"

  if { [[ -n "${NTP_PRIMARY:-}" ]] && [[ "$have_p" != "yes" ]]; } || \
     { [[ -n "${NTP_SECONDARY:-}" ]] && [[ "$have_s" != "yes" ]]; }; then
    changed="yes"
    {
      printf '\r\n'
      (( need_en )) && emit_enable
      printf 'configure terminal\r\n'
      [[ -n "${NTP_PRIMARY:-}"   ]] && [[ "$have_p" != "yes"   ]] && printf 'ntp server %s\r\n' "$NTP_PRIMARY"
      [[ -n "${NTP_SECONDARY:-}" ]] && [[ "$have_s" != "yes" ]] && printf 'ntp server %s\r\n' "$NTP_SECONDARY"
      printf 'end\r\n'
      printf 'write memory\r\n'
      printf 'exit\r\n'
    } | timeout -k 15s 180s "${SSH_CMD[@]}" >>"$raw" 2>&1 || true
    tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.ntpfix.log"; : > "$raw"

    log "[${ip}] Config applied; waiting 5s for NTP to settle…"
    sleep 5
  else
    log "[${ip}] NTP servers already present."
  fi

  {
    printf '\r\n'
    (( need_en )) && emit_enable
    printf 'show ntp status\r\n'
    printf 'show ntp associations\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.ntpfix.log"

  if grep -Eiq 'Clock +is +synchroni[sz]ed' "$out" || grep -Eq '^[*o+] ' "$out"; then
    synced="yes"; log "[${ip}] NTP synchronized."
  else
    synced="no"; notes+="ntp_not_synced_after_5s;"; log "[${ip}] NTP NOT synchronized after 5s; continuing."
  fi

  log "[${ip}] RESULT: CHANGED=${changed} SYNCED=${synced} ${notes:+NOTES=}${notes}"
  append_csv "$NTPFIX_CSV" "${ip},${changed},${synced},${notes}"

  sleep 0.5
  rm -f "$raw" "$out"
}

meraki_fix_ntp(){
  trap 'ui_stop' EXIT

  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"
  NTP_PRIMARY="$(__deq "${NTP_PRIMARY-}")"
  NTP_SECONDARY="$(__deq "${NTP_SECONDARY-}")"

  if [[ -z "${NTP_PRIMARY:-}" && -z "${NTP_SECONDARY:-}" ]]; then
    dialog --no-shadow --backtitle "Meraki NTP Updater" \
           --msgbox "No NTP servers defined in meraki_discovery.env (NTP_PRIMARY/NTP_SECONDARY)." 9 70
    clear; trap - EXIT; return 1
  fi

  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""
  [[ -f "$LATEST_ENV" ]] && source "$LATEST_ENV" && SUM="${PRE_FLIGHT_SUMMARY:-}"
  [[ -z "${SUM:-}" || ! -f "$SUM" ]] && {
    dialog --no-shadow --backtitle "Meraki NTP Updater" \
           --msgbox "Could not find runs/preflight/latest.csv.\nRun preflight first." 9 70
    clear; trap - EXIT; return 1; }

  # IOS-XE minimum version check (unless already done in 'all' pipeline)
  if [[ "${SKIP_IOS_CHECK:-0}" != "1" ]]; then
    if ! enforce_min_ios_or_abort "$SUM"; then
      trap - EXIT
      return 1
    fi
  fi

  mapfile -t TARGETS < <(awk -F, 'NR>1 { if ($7!="yes") print $1 }' "$SUM")
  if (( ${#TARGETS[@]} == 0 )); then
    dialog --no-shadow --backtitle "Meraki NTP Updater" \
           --infobox "All switches already have NTP configured.\nNothing to do." 7 65
    sleep 2; clear; trap - EXIT; return 0
  fi

  RUN_ID="ntp-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/ntpfix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  NTPFIX_CSV="$RUN_DIR/ntpfix.csv"
  echo "ip,changed_ntp,synced,notes" > "$NTPFIX_CSV"

  dialog --no-shadow --backtitle "Meraki NTP Updater" \
         --infobox "Updating NTP servers if needed…\n\nHold for 2 seconds." 7 55
  sleep 2

  UI_TITLE="NTP Fix"; set_backtitle "Meraki NTP Updater"
  ui_start
  log "NTP Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets needing NTP: ${TARGETS[*]}"
  log "Using NTP servers: ${NTP_PRIMARY:-<none>} ${NTP_SECONDARY:-<none>}"
  gauge 1 "Starting…"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}
  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( fix_ntp_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      if wait -n; then :; fi
      ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Updated $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done
  while (( DONE < TOTAL )); do
    if wait -n; then :; fi
    ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "Updated $DONE / $TOTAL"
  done

  gauge 100 "Done"
  ui_stop
  sleep 0.5
  dialog --no-shadow --backtitle "Meraki NTP Updater" --infobox "NTP entries updated if applicable." 5 48
  sleep 2
  clear
  trap - EXIT
  return 0
}

# =====================================================================
# AAA FIX (Meraki-required)
# =====================================================================
fix_aaa_one(){
  set +e
  local ip="$1" need_en=0 raw out changed="no" nm="off" login_ok="no" exec_ok="no" notes=""
  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  log "[${ip}] CONNECT…"
  is_priv15_for_ip "$ip" || need_en=1

  # Read current AAA
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^(no )?aaa new-model\r\n'
    printf 'show running-config | include ^aaa authentication login default\r\n'
    printf 'show running-config | include ^aaa authorization exec default\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.aaafix.log"; : > "$raw"

  local has_nm="no" has_login_exact="no" has_exec_exact="no"
  grep -Eq '^aaa[[:space:]]+new-model(\s|$)' "$out" && has_nm="yes"
  grep -Eq '^aaa[[:space:]]+authentication[[:space:]]+login[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && has_login_exact="yes"
  grep -Eq '^aaa[[:space:]]+authorization[[:space:]]+exec[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && has_exec_exact="yes"

  # If we need any of them, configure idempotently.
  if [[ "$has_nm" != "yes" || "$has_login_exact" != "yes" || "$has_exec_exact" != "yes" ]]; then
    changed="yes"
    {
      printf '\r\n'
      (( need_en )) && emit_enable
      printf 'configure terminal\r\n'
      [[ "$has_nm" != "yes" ]] && printf 'aaa new-model\r\n'
      # For default method lists, replace definitively to the Meraki-required form
      if [[ "$has_login_exact" != "yes" ]]; then
        printf 'no aaa authentication login default\r\n'
        printf 'aaa authentication login default local\r\n'
      fi
      if [[ "$has_exec_exact" != "yes" ]]; then
        printf 'no aaa authorization exec default\r\n'
        printf 'aaa authorization exec default local\r\n'
      fi
      printf 'end\r\n'
      printf 'write memory\r\n'
      printf 'exit\r\n'
    } | timeout -k 20s 200s "${SSH_CMD[@]}" >>"$raw" 2>&1 || true
    tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.aaafix.log"; : > "$raw"
  else
    log "[${ip}] AAA already compliant."
  fi

  # Verify after
  {
    printf '\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^aaa new-model\r\n'
    printf 'show running-config | include ^aaa authentication login default\r\n'
    printf 'show running-config | include ^aaa authorization exec default\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.aaafix.log"

  grep -Eq '^aaa[[:space:]]+new-model(\s|$)' "$out" && nm="on" || nm="off"
  grep -Eq '^aaa[[:space:]]+authentication[[:space:]]+login[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && login_ok="yes" || login_ok="no"
  grep -Eq '^aaa[[:space:]]+authorization[[:space:]]+exec[[:space:]]+default[[:space:]]+local(\s|$)' "$out" && exec_ok="yes" || exec_ok="no"

  if [[ "$nm" != "on" ]]; then notes+="aaa_new_model_verify_failed;"; fi
  if [[ "$login_ok" != "yes" ]]; then notes+="aaa_login_default_local_missing;"; fi
  if [[ "$exec_ok"  != "yes" ]]; then notes+="aaa_exec_default_local_missing;"; fi

  log "[${ip}] RESULT: CHANGED=${changed} NM=${nm} LOGIN_DEFAULT_LOCAL=${login_ok} AUTHZ_EXEC_DEFAULT_LOCAL=${exec_ok} ${notes:+NOTES=}${notes}"
  append_csv "$AAAFIX_CSV" "${ip},${changed},${nm},${login_ok},${exec_ok},${notes}"

  sleep 0.3
  rm -f "$raw" "$out"
}

meraki_fix_aaa(){
  trap 'ui_stop' EXIT

  # env
  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"

  # latest preflight summary
  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""
  if [[ -f "$LATEST_ENV" ]]; then source "$LATEST_ENV"; SUM="${PRE_FLIGHT_SUMMARY:-}"; fi
  [[ -z "${SUM:-}" || ! -f "$SUM" ]] && { dialog --no-shadow --infobox "No preflight summary found.\nRun preflight first." 6 60; sleep 2; clear; trap - EXIT; return 1; }

  # IOS-XE minimum version check (unless already done in 'all' pipeline)
  if [[ "${SKIP_IOS_CHECK:-0}" != "1" ]]; then
    if ! enforce_min_ios_or_abort "$SUM"; then
      trap - EXIT
      return 1
    fi
  fi

  # targets: any with aaa_new_model_missing OR aaa_login_missing OR aaa_exec_missing in notes (col 13)
  mapfile -t TARGETS < <(awk -F, 'NR>1 { if (index($13,"aaa_new_model_missing;")>0 || index($13,"aaa_login_missing;")>0 || index($13,"aaa_exec_missing;")>0) print $1 }' "$SUM")

  if (( ${#TARGETS[@]} == 0 )); then
    dialog --no-shadow --infobox "All switches already have required AAA.\nNothing to do." 6 60
    sleep 2; clear; trap - EXIT; return 0
  fi

  RUN_ID="aaa-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/aaafix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  AAAFIX_CSV="$RUN_DIR/aaafix.csv"
  echo "ip,changed_aaa,new_model,auth_login_default_local,authz_exec_default_local,notes" > "$AAFIX_CSV"

  dialog --no-shadow --infobox "Enforcing Meraki AAA settings where needed…\nPlease wait." 6 60
  sleep 2

  UI_TITLE="AAA Fix"
  ui_start
  log "AAA Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets needing AAA enforcement: ${TARGETS[*]}"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}
  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( fix_aaa_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      if wait -n; then :; fi
      ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "AAA fixed: $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done
  while (( DONE < TOTAL )); do
    if wait -n; then :; fi
    ((DONE++)); local pct=$(( 100 * DONE / TOTAL )); gauge "$pct" "AAA fixed: $DONE / $TOTAL"
  done

  gauge 100 "Done"
  ui_stop
  sleep 0.3
  dialog --no-shadow --infobox "AAA enforced (new-model, login default local, authz exec default local)." 6 70
  sleep 2
  clear
  trap - EXIT
}

# =====================================================================
# IP ROUTING / DEFAULT ROUTE FIX
# =====================================================================
fix_ipr_one(){
  set +e
  local ip="$1"
  local need_en=0 raw out
  local changed="no"
  local mgmt_mode="static"
  local mgmt_method=""
  local gw=""
  local iprt_before="unknown" iprt_after="unknown"
  local defrt_before="no" defrt_after="no"
  local ping_ok="no"
  local notes=""
  local route_dhcp_present="no" route_static_present="no"

  build_ssh_arr "$ip"; raw="$(mktemp)"; out="$(mktemp)"

  log "[${ip}] CONNECT… (ip routing/default route)"
  is_priv15_for_ip "$ip" || need_en=1

  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^ip routing\r\n'
    printf 'show running-config | include ^no ip routing\r\n'
    printf 'show running-config | include ^ip default-gateway\r\n'
    printf 'show running-config | include ^ip route 0.0.0.0 0.0.0.0\r\n'
    printf 'show ip route | include 0.0.0.0/0\r\n'
    printf 'show ip interface brief\r\n'
    printf 'exit\r\n'
  } | timeout -k 10s 150s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; mkdir -p "$RUN_DIR/devlogs"
  cat "$out" >> "$RUN_DIR/devlogs/${ip}.iprfix.log"; : > "$raw"

  # ip routing state (before)
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+routing' "$out"; then
    iprt_before="off"
  elif grep -Eq '^ip[[:space:]]+routing' "$out"; then
    iprt_before="on"
  else
    iprt_before="unknown"
  fi

  # Determine mgmt method from "show ip interface brief" output
  mgmt_method="$(awk -v ip="$ip" '
    /^Interface[[:space:]]+IP-Address[[:space:]]+OK\?[[:space:]]+Method/ {hdr=1; next}
    hdr && $2==ip {print $4; exit}
  ' "$out")"

  if [[ "$mgmt_method" =~ ^[Dd][Hh][Cc][Pp]$ ]]; then
    mgmt_mode="dhcp"
  else
    mgmt_mode="static"
  fi

  # default route presence from running-config
  if grep -Eq '^ip route 0\.0\.0\.0 0\.0\.0\.0[[:space:]]+dhcp(\s|$)' "$out"; then
    route_dhcp_present="yes"
    defrt_before="yes"
  fi

  if grep -Eq '^ip route 0\.0\.0\.0 0\.0\.0\.0[[:space:]]+([0-9]+\.){3}[0-9]+(\s|$)' "$out"; then
    route_static_present="yes"
    defrt_before="yes"
    [[ -z "$gw" ]] && gw="$(awk '
      /^ip route 0\.0\.0\.0 0\.0\.0\.0[[:space:]]+([0-9]+\.){3}[0-9]+/ {print $5; exit}
    ' "$out")"
  fi

  # if no static route yet, try ip default-gateway
  if [[ "$defrt_before" != "yes" || -z "$gw" ]]; then
    local gw_tmp
    gw_tmp="$(awk '
      /^ip default-gateway[[:space:]]+([0-9]+\.){3}[0-9]+/ {print $3; exit}
    ' "$out")"
    if [[ -n "$gw_tmp" ]]; then
      gw="$gw_tmp"
      [[ "$defrt_before" != "yes" ]] && defrt_before="legacy"
    fi
  fi

  # if still no gw, try from ip route table
  if [[ -z "$gw" ]]; then
    gw="$(awk '
      /0\.0\.0\.0\/0/ {
        for (i=1; i<=NF; i++) {
          if ($i=="via") {print $(i+1); exit}
        }
      }
    ' "$out")"
    [[ -n "$gw" && "$defrt_before" != "yes" ]] && defrt_before="yes"
  fi

  log "[${ip}] BEFORE: IPRT=${iprt_before} MGMT_MODE=${mgmt_mode} METHOD=${mgmt_method:-<unknown>} GW=${gw:-<none>} ROUTE_DHCP=${route_dhcp_present} ROUTE_STATIC=${route_static_present} DEFRT=${defrt_before}"

  # decide what to configure
  local do_iprt=0 do_route_dhcp=0 do_route_static=0

  [[ "$iprt_before" != "on" ]] && do_iprt=1

  if [[ "$mgmt_mode" == "dhcp" ]]; then
    [[ "$route_dhcp_present" != "yes" ]] && do_route_dhcp=1
  else
    if [[ -z "$gw" ]]; then
      notes+="no_gateway_detected_cannot_build_static_default;"
    else
      [[ "$route_static_present" != "yes" ]] && do_route_static=1
    fi
  fi

  if (( do_iprt || do_route_dhcp || do_route_static )); then
    changed="yes"
    {
      printf '\r\n'
      (( need_en )) && emit_enable
      printf 'configure terminal\r\n'
      if (( do_route_dhcp )); then
        printf 'ip route 0.0.0.0 0.0.0.0 dhcp\r\n'
      fi
      if (( do_route_static )); then
        printf 'ip route 0.0.0.0 0.0.0.0 %s\r\n' "$gw"
      fi
      if (( do_iprt )); then
        printf 'ip routing\r\n'
      fi
      printf 'end\r\n'
      printf 'write memory\r\n'
      printf 'exit\r\n'
    } | timeout -k 20s 200s "${SSH_CMD[@]}" >>"$raw" 2>&1 || true
    tr -d '\r' < "$raw" >> "$RUN_DIR/devlogs/${ip}.iprfix.log"; : > "$raw"
  else
    log "[${ip}] No ip routing/default-route changes needed."
  fi

  # verify + ping 8.8.8.8
  {
    printf '\r\n'
    (( need_en )) && emit_enable
    printf 'show running-config | include ^ip routing\r\n'
    printf 'show running-config | include ^no ip routing\r\n'
    printf 'show running-config | include ^ip route 0.0.0.0 0.0.0.0\r\n'
    printf 'show ip route | include 0.0.0.0/0\r\n'
    printf 'ping 8.8.8.8 repeat 3 timeout 2\r\n'
    printf 'exit\r\n'
  } | timeout -k 20s 200s "${SSH_CMD[@]}" >"$raw" 2>&1 || true

  tr -d '\r' < "$raw" > "$out"; cat "$out" >> "$RUN_DIR/devlogs/${ip}.iprfix.log"

  # ip routing state (after)
  if grep -Eq '^no[[:space:]]+ip[[:space:]]+routing' "$out"; then
    iprt_after="off"
  elif grep -Eq '^ip[[:space:]]+routing' "$out"; then
    iprt_after="on"
  else
    iprt_after="unknown"
  fi

  # default route present (after)
  if grep -Eq '^ip route 0\.0\.0\.0 0\.0\.0\.0[[:space:]]+(dhcp|([0-9]+\.){3}[0-9]+)' "$out" || \
     awk '/0\.0\.0\.0\/0/ {found=1} END{exit !found}' "$out"
  then
    defrt_after="yes"
  else
    defrt_after="no"
  fi

  # ping 8.8.8.8 result
  if grep -Eiq 'Success +rate +is +([1-9][0-9]*|[0-9]*[1-9]) +percent' "$out" || grep -q '!' "$out"; then
    ping_ok="yes"
  else
    ping_ok="no"
    notes+="ping_8.8.8.8_failed;"
  fi

  log "[${ip}] AFTER: IPRT=${iprt_after} DEFRT=${defrt_after} PING=${ping_ok} ${notes:+NOTES=}${notes}"
  append_csv "$IPRFIX_CSV" "${ip},${mgmt_mode},${changed},${iprt_after},${defrt_after},${ping_ok},${notes}"

  sleep 0.3
  rm -f "$raw" "$out"
}

meraki_fix_ip_routing(){
  trap 'ui_stop' EXIT

  # env
  [[ -f "$DISC_ENV" ]] && source "$DISC_ENV"
  SSH_USERNAME="$(__deq "${SSH_USERNAME-}")"
  SSH_PASSWORD="$(__deq "${SSH_PASSWORD-}")"
  ENABLE_PASSWORD="$(__deq "${ENABLE_PASSWORD-}")"

  # latest preflight summary
  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""

  if [[ -f "$LATEST_ENV" ]]; then
    source "$LATEST_ENV"
    SUM="${PRE_FLIGHT_SUMMARY:-}"
  fi

  if [[ -z "${SUM:-}" || ! -f "$SUM" ]]; then
    dialog --no-shadow --backtitle "$BACKTITLE" \
           --msgbox "Could not find runs/preflight/latest.csv.\nRun preflight first." 9 70
    clear; trap - EXIT; return 1
  fi

  # IOS-XE minimum version check (unless already done in 'all' pipeline)
  if [[ "${SKIP_IOS_CHECK:-0}" != "1" ]]; then
    if ! enforce_min_ios_or_abort "$SUM"; then
      trap - EXIT
      return 1
    fi
  fi

  # TARGETS: any device where ip_routing != "yes" OR default_route != "yes"
  # CSV columns: ip,hostname,ios_ver,install_mode,meraki_mode,dns_ok,ntp_ok,ip_routing,default_route,domain_lookup,tunnel,ready,notes
  mapfile -t TARGETS < <(awk -F, 'NR>1 { if ($8!="yes" || $9!="yes") print $1 }' "$SUM")

  if (( ${#TARGETS[@]} == 0 )); then
    dialog --no-shadow --backtitle "$BACKTITLE" \
           --infobox "All switches already have ip routing enabled and a default route.\nNothing to do." 7 75
    sleep 2
    clear; trap - EXIT; return 0
  fi

  # run directory
  RUN_ID="ipr-$(date -u +%Y%m%d%H%M%S)"
  RUN_ROOT="$SCRIPT_DIR/runs/iprfix"; mkdir -p "$RUN_ROOT"
  RUN_DIR="$RUN_ROOT/$RUN_ID"; mkdir -p "$RUN_DIR" "$RUN_DIR/devlogs"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"

  # CSV for results
  IPRFIX_CSV="$RUN_DIR/iprfix.csv"
  echo "ip,mgmt_mode,changed_config,ip_routing_enabled,default_route_present,ping_8_8_8_8_ok,notes" > "$IPRFIX_CSV"

  dialog --no-shadow --backtitle "$BACKTITLE" \
         --infobox "Ensuring ip routing + default route where needed...\nPlease wait." 7 75
  sleep 2

  UI_TITLE="IP Routing Fix"
  set_backtitle "Meraki IP Routing Updater"
  ui_start
  log "IP Routing Fix Run: $RUN_ID"
  log "Run dir: $RUN_DIR"
  log "Targets needing ip routing/default route: ${TARGETS[*]}"

  local MAX_CONCURRENCY="${MAX_CONCURRENCY:-5}"
  local ACTIVE=0 DONE=0 TOTAL=${#TARGETS[@]}

  rand_ms(){ awk -v m="${SPLAY_MS:-150}" 'BEGIN{srand(); printf "%.3f", (rand()*m)/1000.0}'; }

  for ip in "${TARGETS[@]}"; do
    ( fix_ipr_one "$ip" ) &
    ((ACTIVE++))
    sleep "$(rand_ms)"
    if (( ACTIVE >= MAX_CONCURRENCY )); then
      if wait -n; then :; fi
      ((DONE++))
      local pct=$(( 100 * DONE / TOTAL ))
      gauge "$pct" "Routing fixed on $DONE / $TOTAL"
      ((ACTIVE--))
    fi
  done

  while (( DONE < TOTAL )); do
    if wait -n; then :; fi
    ((DONE++))
    local pct=$(( 100 * DONE / TOTAL ))
    gauge "$pct" "Routing fixed on $DONE / $TOTAL"
  done

  gauge 100 "Done"
  ui_stop
  sleep 0.5
  dialog --no-shadow --backtitle "$BACKTITLE" \
         --infobox "ip routing + default route ensured where needed.\nSee iprfix.csv for details." 7 80
  sleep 2
  clear
  trap - EXIT
  return 0
}

# =====================================================================
# PIPELINE
# =====================================================================
meraki_all(){
  # full pipeline: preflight -> IOS check once -> DNS -> NTP -> AAA -> routing
  meraki_preflight || return $?

  local PRE_ROOT="$SCRIPT_DIR/runs/preflight"
  local LATEST_ENV="$PRE_ROOT/latest.env"
  local SUM=""

  if [[ -f "$LATEST_ENV" ]]; then
    source "$LATEST_ENV"
    SUM="${PRE_FLIGHT_SUMMARY:-}"
  fi

  if [[ -z "${SUM:-}" || ! -f "$SUM" ]]; then
    echo "Preflight summary missing after preflight. Aborting." >&2
    return 1
  fi

  # Run IOS-XE check ONCE for the 'all' pipeline
  if ! enforce_min_ios_or_abort "$SUM"; then
    return 1
  fi

  # Tell per-fix functions to skip their own IOS checks
  SKIP_IOS_CHECK=1

  meraki_fix_dns        || return $?
  meraki_fix_ntp        || true
  meraki_fix_aaa        || true
  meraki_fix_ip_routing || true
}

# =====================================================================
# Entry
# =====================================================================
case "${1:-all}" in
  preflight)   UI_TITLE="Preflight";        meraki_preflight ;;
  fix-dns)     UI_TITLE="DNS Fix";          meraki_fix_dns ;;
  fix-ntp)     UI_TITLE="NTP Fix";          meraki_fix_ntp ;;
  fix-aaa)     UI_TITLE="AAA Fix";          meraki_fix_aaa ;;
  fix-routing) UI_TITLE="IP Routing Fix";   meraki_fix_ip_routing ;;
  all|"")
    UI_TITLE="Preflight / All Fixes"
    meraki_all
    ;;
  *)
    echo "Loaded functions: meraki_preflight, meraki_fix_dns, meraki_fix_ntp, meraki_fix_aaa, meraki_fix_ip_routing, meraki_all"
    echo "Usage: $0 {preflight|fix-dns|fix-ntp|fix-aaa|fix-routing|all}"
    exit 1 ;;
esac
