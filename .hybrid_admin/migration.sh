#!/usr/bin/env bash
set -Euo pipefail

# ------------------------------------------------------------
# Shared helpers (dlg, SCRIPT_DIR, ios_ge_min_version)
# ------------------------------------------------------------

# dialog helper – always override so buttons say "Continue"
: "${DIALOG:=dialog}"

DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi

dlg() {
  # use the same label for OK and EXIT
  local common=(--ok-label "Continue" --exit-label "Continue")

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


SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; return 1; }; }

# ---- compare IOS-XE versions: returns 0 if $1 >= $2 ----
ios_ge_min_version() {
  local v_raw="$1" min_raw="$2"
  [[ -z "$v_raw" || -z "$min_raw" ]] && return 1

  local v nv
  v="${v_raw%% *}"
  v="${v//,/}"
  nv="$(sed 's/[^0-9.].*$//' <<<"$v")"
  [[ -z "$nv" ]] && return 1

  local a b c ma mb mc
  local IFS='.'
  read -r a b c  <<<"$nv"
  read -r ma mb mc <<<"$min_raw"

  a=${a:-0};  b=${b:-0};  c=${c:-0}
  ma=${ma:-0}; mb=${mb:-0}; mc=${mc:-0}

  if   (( a > ma )); then return 0
  elif (( a < ma )); then return 1; fi

  if   (( b > mb )); then return 0
  elif (( b < mb )); then return 1; fi

  if   (( c >= mc )); then return 0; else return 1; fi
}

# match discovery script behaviour – strip CR/LF and outer whitespace
clean_field() {
  local s
  s="$(printf '%s' "${1:-}" | tr -d '\r\n')"
  # trim leading/trailing whitespace
  s="$(printf '%s' "$s" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
  printf '%s' "$s"
}

# ------------------------------------------------------------
# Validation UI: split-screen tailbox + gauge (like discovery)
# ------------------------------------------------------------
VALIDATE_DIALOG_AVAILABLE=0
if command -v dialog >/dev/null 2>&1; then
  VALIDATE_DIALOG_AVAILABLE=1
fi

VALIDATE_STATUS_FILE=""
VALIDATE_PIPE=""
VALIDATE_FD=""
VALIDATE_DIALOG_PID=""

VALIDATE_TAIL_H=; VALIDATE_TAIL_W=
VALIDATE_GAUGE_H=; VALIDATE_GAUGE_W=
VALIDATE_GAUGE_ROW=; VALIDATE_GAUGE_COL=

_validate_calc_layout() {
  local lines cols
  if ! read -r lines cols < <(stty size 2>/dev/null); then
    lines=24 cols=80
  fi
  if (( lines < 18 || cols < 70 )); then
    VALIDATE_DIALOG_AVAILABLE=0
    return
  fi
  VALIDATE_TAIL_H=$((lines - 10)); (( VALIDATE_TAIL_H < 10 )) && VALIDATE_TAIL_H=10
  VALIDATE_TAIL_W=$((cols - 4));   (( VALIDATE_TAIL_W < 68 )) && VALIDATE_TAIL_W=68
  VALIDATE_GAUGE_H=7
  VALIDATE_GAUGE_W=$VALIDATE_TAIL_W
  VALIDATE_GAUGE_ROW=$((VALIDATE_TAIL_H + 2))
  VALIDATE_GAUGE_COL=2
}

_validate_fd_open() {
  [[ -n "${VALIDATE_FD:-}" ]] || return 1
  if [[ -e "/proc/$$/fd/$VALIDATE_FD" ]]; then
    return 0
  fi
  { : >&"$VALIDATE_FD"; } 2>/dev/null || return 1
  return 0
}

validate_ui_start() {
  _validate_calc_layout

  # Optional override of the dialog title:
  #   validate_ui_start "Meraki Cloud Monitoring onboarding"
  local title="${1:-Connectivity & IOS-XE validation}"

  # If the caller already set VALIDATE_STATUS_FILE (e.g. runs/migration/.../ui.status),
  # reuse it; otherwise, fall back to a temporary file.
  if [[ -z "${VALIDATE_STATUS_FILE:-}" ]]; then
    VALIDATE_STATUS_FILE="$(mktemp)"
  fi
  : >"$VALIDATE_STATUS_FILE"

  if (( VALIDATE_DIALOG_AVAILABLE )); then
    VALIDATE_PIPE="$(mktemp -u)"
    mkfifo "$VALIDATE_PIPE"
    exec {VALIDATE_FD}<>"$VALIDATE_PIPE"
    (
      dialog --no-shadow \
             --begin 1 2 --title "$title" \
             --tailboxbg "$VALIDATE_STATUS_FILE" "$VALIDATE_TAIL_H" "$VALIDATE_TAIL_W" \
             --and-widget \
             --begin "$VALIDATE_GAUGE_ROW" "$VALIDATE_GAUGE_COL" \
             --title "Overall Progress" \
             --gauge "Starting…" "$VALIDATE_GAUGE_H" "$VALIDATE_GAUGE_W" 0 < "$VALIDATE_PIPE"
    ) &
    VALIDATE_DIALOG_PID=$!
    sleep 0.15
  else
    echo "[validate] dialog not available; using plain output."
  fi
}

validate_ui_status() {
  local msg="$1"
  printf '%(%H:%M:%S)T %s\n' -1 "$msg" >>"$VALIDATE_STATUS_FILE"
  (( VALIDATE_DIALOG_AVAILABLE )) || echo "$msg"
}

validate_ui_gauge() {
  local pct="$1"; shift || true
  local text="${*:-Working…}"
  if (( VALIDATE_DIALOG_AVAILABLE )) && _validate_fd_open; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$text" >&"$VALIDATE_FD"; } 2>/dev/null || true
  else
    echo "[progress] ${pct}%% - $text"
  fi
}

validate_ui_stop() {
  if (( VALIDATE_DIALOG_AVAILABLE )); then
    if _validate_fd_open; then
      { printf 'XXX\n100\nDone.\nXXX\n' >&"$VALIDATE_FD"; } 2>/dev/null || true
      exec {VALIDATE_FD}>&- 2>/dev/null || true
    fi
    [[ -n "$VALIDATE_PIPE" ]] && rm -f "$VALIDATE_PIPE" 2>/dev/null || true
    [[ -n "$VALIDATE_DIALOG_PID" ]] && kill "$VALIDATE_DIALOG_PID" 2>/dev/null || true
  fi

  # IMPORTANT: do NOT delete VALIDATE_STATUS_FILE here – we want to keep ui.status
  # inside runs/migration/... for later review.
  # VALIDATE_STATUS_FILE will just be left on disk.

  VALIDATE_STATUS_FILE=""
  VALIDATE_PIPE=""
  VALIDATE_FD=""
  VALIDATE_DIALOG_PID=""
}


# ------------------------------------------------------------
# 1) Connectivity + IOS-XE + config + Meraki compatibility
#    validation with logging (parallel: up to 10 switches)
# ------------------------------------------------------------
validate_switches_before_migration() {
  local BACKTITLE_V="Catalyst validation – ping, IOS-XE, config & Meraki compatibility"

  local DISC_ENV="$SCRIPT_DIR/meraki_discovery.env"
  local SEL_JSON="$SCRIPT_DIR/selected_upgrade.json"
  local SEL_ENV="$SCRIPT_DIR/selected_upgrade.env"
  local DISC_JSON="$SCRIPT_DIR/discovery_results.json"
  local DISC_CSV="$SCRIPT_DIR/discovery_results.csv"
  local VALIDATED_JSON="$SCRIPT_DIR/validated_ips.json"

  need ping || return 1
  need ssh  || return 1
  need jq   || return 1

  # load discovery env for SSH creds + min IOS
  if [[ -f "$DISC_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$DISC_ENV"
  fi

  local SSH_USER="${SSH_USERNAME:-}"
  local SSH_PASS="${SSH_PASSWORD:-}"
  local MIN_IOS="${MIN_IOSXE_REQUIRED:-${FW_CAT9K_VERSION:-17.15.03}}"

  if [[ -z "$SSH_USER" ]]; then
    dlg --backtitle "$BACKTITLE_V" \
        --title "Missing SSH username" \
        --msgbox "SSH_USERNAME is not set in meraki_discovery.env.\n\nCannot validate switches." 10 70
    return 1
  fi

  # ---------- build candidate switch list ----------
  local SRC="" have_sel_json="" have_sel_ips="" have_disc_json=""
  local -a IPS HOSTS PIDS SER

  if [[ -s "$SEL_JSON" && "$(jq 'length' "$SEL_JSON" 2>/dev/null || echo 0)" -gt 0 ]]; then
    have_sel_json=1
  fi
  if [[ -f "$SEL_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$SEL_ENV"
    UPGRADE_SELECTED_IPS="${UPGRADE_SELECTED_IPS:-}"
    [[ -n "$UPGRADE_SELECTED_IPS" ]] && have_sel_ips=1
  fi
  if [[ -s "$DISC_JSON" ]]; then
    have_disc_json=1
  fi

  if   [[ -n "$have_sel_json" ]]; then SRC="seljson"
  elif [[ -n "$have_sel_ips"  ]]; then SRC="selips"
  elif [[ -n "$have_disc_json" ]]; then SRC="disc"
  else
    dlg --backtitle "$BACKTITLE_V" \
        --title "No switches" \
        --msgbox "No selected_upgrade.json, selected_upgrade.env, or discovery_results.json/csv found in:\n  $SCRIPT_DIR\n\nRun discovery/selection first." 12 80
    return 1
  fi

  if [[ "$SRC" == "seljson" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$SEL_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$SEL_JSON" 2>/dev/null)
    mapfile -t PIDS  < <(jq -r '.[].pid      // ""' "$SEL_JSON" 2>/dev/null)
    mapfile -t SER   < <(jq -r '.[].serial   // ""' "$SEL_JSON" 2>/dev/null)

    if [[ -s "$DISC_JSON" ]]; then
      declare -A HMAP PMAP SMAP
      while IFS=$'\t' read -r ip h p s; do
        HMAP["$ip"]="$h"
        PMAP["$ip"]="$p"
        SMAP["$ip"]="$s"
      done < <(jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' "$DISC_JSON")
      for i in "${!IPS[@]}"; do
        local ip="${IPS[$i]}"
        [[ -z "${HOSTS[$i]}" && -n "${HMAP[$ip]:-}" ]] && HOSTS[$i]="${HMAP[$ip]}"
        [[ -z "${PIDS[$i]}"  && -n "${PMAP[$ip]:-}" ]] && PIDS[$i]="${PMAP[$ip]}"
        [[ -z "${SER[$i]}"   && -n "${SMAP[$ip]:-}" ]] && SER[$i]="${SMAP[$ip]}"
      done
    fi

  elif [[ "$SRC" == "selips" ]]; then
    read -r -a IPS <<<"$UPGRADE_SELECTED_IPS"

    HOSTS=(); PIDS=(); SER=()
    if [[ -s "$DISC_JSON" ]]; then
      declare -A HMAP PMAP SMAP
      while IFS=$'\t' read -r ip h p s; do
        HMAP["$ip"]="$h"
        PMAP["$ip"]="$p"
        SMAP["$ip"]="$s"
      done < <(jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' "$DISC_JSON")
      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
        PIDS+=(  "${PMAP[$ip]:-}" )
        SER+=(   "${SMAP[$ip]:-}" )
      done
    elif [[ -s "$DISC_CSV" ]]; then
      declare -A HMAP PMAP SMAP
      local ip ssh login hostname version pid serial
      local first=1
      while IFS=, read -r ip ssh login hostname version pid serial; do
        if (( first )); then first=0; continue; fi
        ip="${ip%\"}"; ip="${ip#\"}"
        hostname="${hostname%\"}"; hostname="${hostname#\"}"
        pid="${pid%\"}"; pid="${pid#\"}"
        serial="${serial%\"}"; serial="${serial#\"}"
        HMAP["$ip"]="$hostname"
        PMAP["$ip"]="$pid"
        SMAP["$ip"]="$serial"
      done < "$DISC_CSV"
      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
        PIDS+=(  "${PMAP[$ip]:-}" )
        SER+=(   "${SMAP[$ip]:-}" )
      done
    else
      for _ in "${IPS[@]}"; do HOSTS+=(""); PIDS+=(""); SER+=(""); done
    fi

  else
    mapfile -t IPS   < <(jq -r '.[].ip' "$DISC_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$DISC_JSON" 2>/dev/null)
    mapfile -t PIDS  < <(jq -r '.[].pid      // ""' "$DISC_JSON" 2>/dev/null)
    mapfile -t SER   < <(jq -r '.[].serial   // ""' "$DISC_JSON" 2>/dev/null)
  fi

  if (( ${#IPS[@]} == 0 )); then
    dlg --backtitle "$BACKTITLE_V" \
        --title "No switches" \
        --msgbox "No switches found in selected/discovery files.\n\nRun discovery first." 10 70
    return 1
  fi

  # ---------- checklist: choose which switches to validate ----------
  local -a items=()
  for i in "${!IPS[@]}"; do
    local ip="${IPS[$i]}"
    local h="${HOSTS[$i]:-<unknown>}"
    local p="${PIDS[$i]:--}"
    local s="${SER[$i]:--}"
    local label
    printf -v label "%-15s %-24s %-12s %s" "$ip" "$h" "$p" "$s"
    items+=( "$ip" "$label" "on" )
  done

  local selection
  selection="$(dlg --separate-output \
                   --backtitle "$BACKTITLE_V" \
                   --title "Select switches to validate" \
                   --checklist "Choose which switches you want to ping and validate.\nUse SPACE to toggle, ENTER when done." \
                   22 100 14 \
                   "${items[@]}")" || return 1

  selection="$(trim "$selection")"
  if [[ -z "$selection" ]]; then
    dlg --backtitle "$BACKTITLE_V" \
        --title "No switches selected" \
        --msgbox "No switches were selected for validation.\n\nSkipping connectivity/IOS-XE checks." 10 70
    return 1
  fi

  mapfile -t IPS <<<"$selection"

  # ---------- create runs/migration logging structure ----------
  local RUN_ROOT="$SCRIPT_DIR/runs/migration"
  mkdir -p "$RUN_ROOT"

  local RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
  local RUN_DIR="$RUN_ROOT/$RUN_ID"
  mkdir -p "$RUN_DIR/devlogs"

  local SUMMARY_CSV="$RUN_DIR/summary.csv"
  echo "ip,hostname,ios_ver,ping_ok,dns_ok,ntp_ok,ip_routing,default_route,domain_lookup,aaa_new_model,aaa_login_default_local,aaa_exec_default_local,ping_google,meraki_compat,ready,notes" > "$SUMMARY_CSV"

  # expose "latest" like preflight does
  local LATEST_ENV="$RUN_ROOT/latest.env"
  export MIGRATION_RUN_ID="$RUN_ID"
  export MIGRATION_RUN_DIR="$RUN_DIR"
  export MIGRATION_SUMMARY="$SUMMARY_CSV"
  {
    printf 'export MIGRATION_RUN_ID=%q\n' "$MIGRATION_RUN_ID"
    printf 'export MIGRATION_RUN_DIR=%q\n' "$MIGRATION_RUN_DIR"
    printf 'export MIGRATION_SUMMARY=%q\n' "$MIGRATION_SUMMARY"
  } >"$LATEST_ENV"
  ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"
  ln -sfn "$SUMMARY_CSV" "$RUN_ROOT/latest.csv"

  # set ui.status location for the validate UI helpers
  VALIDATE_STATUS_FILE="$RUN_DIR/ui.status"
  : >"$VALIDATE_STATUS_FILE"

  # ---------- split-screen UI like discovery ----------
  validate_ui_start
  validate_ui_status "Minimum IOS-XE required: ${MIN_IOS}"
  validate_ui_status "Also checking DNS, NTP, ip routing, AAA, ping to google.com, and Meraki compatibility…"

  local total=${#IPS[@]}

  local have_sshpass=0
  if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSH_PASS" ]]; then
    have_sshpass=1
  fi

  # ---------- per-switch worker (runs in background) ----------
  _validate_one_switch_migration() {
    local ip="$1" host="$2"

    local ping_ok="no"
    local ver_ok="unknown"
    local ios=""

    local dns_ok="n/a" domlkp="n/a"
    local ntp_ok="n/a"
    local iprt="n/a"
    local defrt="n/a"
    local aaa_nm="n/a" aaa_login="n/a" aaa_exec="n/a"
    local ping_google="n/a"
    local meraki_compat="n/a"

    local -a reasons=()

    local ping_log="$RUN_DIR/devlogs/${ip}.ping.log"
    local ssh_log_tmp="$RUN_DIR/devlogs/${ip}.session.tmp"
    local ssh_log="$RUN_DIR/devlogs/${ip}.session.log"

    validate_ui_status "[$ip] Pinging (3 probes)…"

    if ping -c 3 -W 2 "$ip" >"$ping_log" 2>&1; then
      ping_ok="yes"
      validate_ui_status "[$ip] Ping OK; probing via SSH…"
    else
      ping_ok="no"
      reasons+=( "ping_failed" )
      validate_ui_status "[$ip] Ping FAILED."
    fi

    if [[ "$ping_ok" == "yes" ]]; then
      local ssh_cmd
      if (( have_sshpass )); then
        ssh_cmd=(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                 -o ConnectTimeout=25 -o BatchMode=no -tt "${SSH_USER}@${ip}")
      else
        ssh_cmd=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                 -o ConnectTimeout=25 -tt "${SSH_USER}@${ip}")
      fi

      {
        printf '\r\nterminal length 0\r\nterminal width 511\r\n'
        printf 'show version\r\n'
        printf 'show running-config | include ^ip name-server\r\n'
        printf 'show running-config | include ^ntp server\r\n'
        printf 'show running-config | include ^ip routing\r\n'
        printf 'show running-config | include ^no ip routing\r\n'
        printf 'show running-config | include ^ip route 0.0.0.0 0.0.0.0\r\n'
        printf 'show running-config | include ^ip default-gateway\r\n'
        printf 'show running-config | include ^no ip domain lookup\r\n'
        printf 'show running-config | include ^ip domain lookup\r\n'
        printf 'show running-config | include ^aaa new-model\r\n'
        printf 'show running-config | include ^aaa authentication login default\r\n'
        printf 'show running-config | include ^aaa authorization exec default\r\n'
        printf 'show meraki compatibility\r\n'
        printf 'ping google.com repeat 2 timeout 2\r\n'
        printf 'exit\r\n'
      } | "${ssh_cmd[@]}" >"$ssh_log_tmp" 2>&1 || true

      tr -d '\r' <"$ssh_log_tmp" >"$ssh_log"
      rm -f "$ssh_log_tmp" 2>/dev/null || true

      # hostname from prompt if possible
      local h_probe
      h_probe="$(awk 'match($0,/^([[:alnum:]_.:-]+)[>#][[:space:]]*$/,m){print m[1]; exit}' "$ssh_log")"
      if [[ -n "$h_probe" ]]; then
        host="$h_probe"
      fi

      # IOS-XE version
      ios="$(awk '
        match($0,/Cisco IOS XE Software, Version[[:space:]]+([^ ,]+)/,m){print m[1]; exit}
        match($0,/Version[[:space:]]+([0-9]+\.[0-9]+(\.[0-9A-Za-z]+)?)/,m){print m[1]; exit}
      ' "$ssh_log")"
      ios="$(clean_field "${ios:-}")"

      if [[ -z "$ios" ]]; then
        ver_ok="no"
        reasons+=( "ios_not_detected" )
        validate_ui_status "[$ip] Could not detect IOS-XE version."
      else
        if ios_ge_min_version "$ios" "$MIN_IOS"; then
          ver_ok="yes"
          validate_ui_status "[$ip] Version OK (>= ${MIN_IOS})."
        else
          ver_ok="no"
          reasons+=( "version_too_low" )
          validate_ui_status "[$ip] Version TOO LOW (requires ${MIN_IOS})."
        fi
      fi

      # DNS + domain lookup
      dns_ok="no"; domlkp="enabled"
      if grep -Eq '^[[:space:]]*ip[[:space:]]+name-server' "$ssh_log"; then
        dns_ok="yes"
      else
        reasons+=( "dns_missing" )
      fi
      if grep -Eq '^no[[:space:]]+ip[[:space:]]+domain[[:space:]]+lookup' "$ssh_log"; then
        domlkp="disabled"
        reasons+=( "domain_lookup_disabled" )
      fi

      # NTP
      ntp_ok="no"
      if grep -Eq '^[[:space:]]*ntp[[:space:]]+server[[:space:]]+' "$ssh_log"; then
        ntp_ok="yes"
      else
        reasons+=( "ntp_missing" )
      fi

      # ip routing / default route
      iprt="unknown"
      if grep -Eq '^no[[:space:]]+ip[[:space:]]+routing' "$ssh_log"; then
        iprt="no"
        reasons+=( "ip_routing_off" )
      elif grep -Eq '^ip[[:space:]]+routing' "$ssh_log"; then
        iprt="yes"
      fi

      defrt="no"
      if grep -Eq '^ip[[:space:]]+route[[:space:]]+0\.0\.0\.0[[:space:]]+0\.0\.0\.0' "$ssh_log" || \
         grep -Eq '^ip[[:space:]]+default-gateway[[:space:]]+([0-9]+\.){3}[0-9]+' "$ssh_log"; then
        defrt="yes"
      else
        reasons+=( "default_route_missing" )
      fi

      # AAA
      aaa_nm="no"; aaa_login="no"; aaa_exec="no"
      if grep -Eq '^aaa[[:space:]]+new-model(\s|$)' "$ssh_log"; then
        aaa_nm="yes"
      else
        reasons+=( "aaa_new_model_missing" )
      fi
      if grep -Eq '^aaa[[:space:]]+authentication[[:space:]]+login[[:space:]]+default[[:space:]]+local(\s|$)' "$ssh_log"; then
        aaa_login="yes"
      else
        reasons+=( "aaa_login_default_local_missing" )
      fi
      if grep -Eq '^aaa[[:space:]]+authorization[[:space:]]+exec[[:space:]]+default[[:space:]]+local(\s|$)' "$ssh_log"; then
        aaa_exec="yes"
      else
        reasons+=( "aaa_exec_default_local_missing" )
      fi

      # Meraki compatibility
      meraki_compat="no"
      if grep -qi "Invalid input detected" "$ssh_log"; then
        reasons+=( "meraki_cmd_unsupported" )
        validate_ui_status "[$ip] 'show meraki compatibility' not supported on this platform."
      elif grep -q "Meraki Cloud Monitoring: Compatible" "$ssh_log"; then
        meraki_compat="yes"
        validate_ui_status "[$ip] Meraki Cloud Monitoring compatibility: OK."
      elif grep -q "Meraki Cloud Monitoring: Not Compatible" "$ssh_log"; then
        reasons+=( "meraki_not_compatible" )
        validate_ui_status "[$ip] Meraki Cloud Monitoring compatibility: NOT COMPATIBLE."
      else
        reasons+=( "meraki_compat_unclear" )
        validate_ui_status "[$ip] Meraki compatibility output unclear – treating as NOT compatible."
      fi

      # ping google.com
      ping_google="no"
      if awk '
          /ping google\.com/ {ctx=1; next}
          ctx && /Success +rate +is/ {
            if ($0 !~ / 0 +percent/) {print "OK"; exit}
          }
          ctx && /!/ {print "OK"; exit}
        ' "$ssh_log" | grep -q OK; then
        ping_google="yes"
      else
        reasons+=( "ping_google_failed" )
      fi
    fi

    local ready="yes"
    if [[ "$ping_ok" != "yes" ]]; then ready="no"; fi
    if [[ "$ver_ok" != "yes" ]]; then ready="no"; fi
    if [[ "$dns_ok" != "yes" || "$domlkp" != "enabled" ]]; then ready="no"; fi
    if [[ "$ntp_ok" != "yes" ]]; then ready="no"; fi
    if [[ "$iprt" != "yes" ]]; then ready="no"; fi
    if [[ "$defrt" != "yes" ]]; then ready="no"; fi
    if [[ "$aaa_nm" != "yes" || "$aaa_login" != "yes" || "$aaa_exec" != "yes" ]]; then ready="no"; fi
    if [[ "$ping_google" != "yes" ]]; then ready="no"; fi
    if [[ "$meraki_compat" != "yes" ]]; then ready="no"; fi

    local notes=""
    if ((${#reasons[@]})); then
      notes="$(IFS=';'; printf '%s' "${reasons[*]}")"
    fi

    if [[ "$ready" == "yes" ]]; then
      validate_ui_status "[$ip] All checks PASSED."
    else
      validate_ui_status "[$ip] FAILED checks: ${notes:-see logs}"
    fi

    # per-switch CSV line (we'll stitch them into summary.csv later)
    local csv_file="$RUN_DIR/devlogs/summary_${ip//./_}.line"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
      "$ip" "$host" "${ios:-}" "$ping_ok" \
      "$dns_ok" "$ntp_ok" "$iprt" "$defrt" "$domlkp" \
      "$aaa_nm" "$aaa_login" "$aaa_exec" \
      "$ping_google" "$meraki_compat" \
      "$ready" "$notes" >"$csv_file"
  }

  # ---------- launch workers in parallel (max 10 at a time) ----------
  local max_parallel=10
  local ACTIVE=0 DONE=0

  validate_ui_gauge 1 "Starting validation… (up to ${max_parallel} in parallel)"

  for i in "${!IPS[@]}"; do
    local ip="${IPS[$i]}"
    local host="${HOSTS[$i]:-$ip}"

    _validate_one_switch_migration "$ip" "$host" &

    ((ACTIVE++))
    if (( ACTIVE >= max_parallel )); then
      if wait -n 2>/dev/null; then :; fi
      ((DONE++))
      validate_ui_gauge $(( 100 * DONE / total )) "Completed $DONE / $total…"
      ((ACTIVE--))
    fi
  done

  # wait for remaining jobs
  while (( DONE < total )); do
    if wait -n 2>/dev/null; then :; fi
    ((DONE++))
    validate_ui_gauge $(( 100 * DONE / total )) "Completed $DONE / $total…"
  done

  # ---------- assemble summary.csv from per-switch lines ----------
  for ip in "${IPS[@]}"; do
    local line_file="$RUN_DIR/devlogs/summary_${ip//./_}.line"
    [[ -f "$line_file" ]] && cat "$line_file" >>"$SUMMARY_CSV"
  done

  validate_ui_gauge 100 "Connectivity, IOS-XE, config & Meraki compatibility checks complete."
  validate_ui_stop   # close split-screen before showing summary dialogs

  # ---------- build validated_ips.json + summary text ----------
  local -a OK_IPS BAD_PING_IPS BAD_VER_IPS BAD_CFG_IPS BAD_MERAKI_IPS

  local summary="$RUN_DIR/validation_summary.txt"
  {
    echo "Connectivity, IOS-XE, config & Meraki compatibility validation"
    echo "================================================================"
    echo
    echo "Discovery env:  $DISC_ENV"
    echo "Min IOS-XE required:  $MIN_IOS"
    echo "Run directory:"
    echo "  $RUN_DIR"
    echo
    echo "Checked switches:"
    echo
    printf "%-16s %-22s %-10s %-5s %-8s %-8s %-9s %-11s %-10s %-18s %-6s %-7s\n" \
      "IP" "Hostname" "IOS-XE" "Ping" "DNS" "NTP" "IP-Route" "Def-Route" "DomLkup" "AAA(nm/login/exec)" "g.com" "Meraki"
    printf "%-16s %-22s %-10s %-5s %-8s %-8s %-9s %-11s %-10s %-18s %-6s %-7s\n" \
      "----------------" "----------------------" "---------" "-----" "--------" "--------" "---------" "-----------" "----------" "------------------" "------" "-------"

    local first=1
    local ip hostname ios_ver ping_ok dns_ok ntp_ok iprt defrt domlkp aaa_nm aaa_login aaa_exec ping_google meraki_compat ready notes

    while IFS=, read -r ip hostname ios_ver ping_ok dns_ok ntp_ok iprt defrt domlkp aaa_nm aaa_login aaa_exec ping_google meraki_compat ready notes; do
      if (( first )); then first=0; continue; fi  # skip header

      # strip possible quotes on some fields
      ip="${ip%\"}";        ip="${ip#\"}"
      hostname="${hostname%\"}"; hostname="${hostname#\"}"
      ios_ver="${ios_ver%\"}";   ios_ver="${ios_ver#\"}"
      notes="${notes%\"}";       notes="${notes#\"}"

      printf "%-16s %-22s %-10s %-5s %-8s %-8s %-9s %-11s %-10s %-18s %-6s %-7s\n" \
        "$ip" \
        "${hostname:-<unknown>}" \
        "${ios_ver:-<none>}" \
        "$([[ $ping_ok == "yes" ]] && echo "yes" || echo "no")" \
        "$dns_ok" \
        "$ntp_ok" \
        "$iprt" \
        "$defrt" \
        "$domlkp" \
        "${aaa_nm},${aaa_login},${aaa_exec}" \
        "$([[ $ping_google == "yes" ]] && echo "yes" || echo "no")" \
        "$([[ $meraki_compat == "yes" ]] && echo "yes" || echo "no")"

      # categorize for final lists
      if [[ "$ping_ok" != "yes" ]]; then
        BAD_PING_IPS+=( "$ip" )
      fi
      if [[ "$notes" == *version_too_low* || "$notes" == *ios_not_detected* ]]; then
        BAD_VER_IPS+=( "$ip (running ${ios_ver:-<none>})" )
      fi
      if [[ "$meraki_compat" != "yes" ]]; then
        BAD_MERAKI_IPS+=( "$ip" )
      fi
      if [[ "$ready" != "yes" && "$ping_ok" == "yes" && "$notes" != *version_too_low* && "$notes" != *ios_not_detected* && "$notes" != *meraki_* ]]; then
        BAD_CFG_IPS+=( "$ip (${notes:-config_failed})" )
      fi
      if [[ "$ready" == "yes" ]]; then
        OK_IPS+=( "$ip" )
      fi
    done <"$SUMMARY_CSV"

    echo

    if ((${#BAD_PING_IPS[@]})); then
      echo "Switches that FAILED ping:"
      for ip in "${BAD_PING_IPS[@]}"; do
        echo "  - $ip"
      done
      echo
    fi

    if ((${#BAD_VER_IPS[@]})); then
      echo "Switches that FAILED IOS-XE min version ($MIN_IOS):"
      for line in "${BAD_VER_IPS[@]}"; do
        echo "  - $line"
      done
      echo
    fi

    if ((${#BAD_MERAKI_IPS[@]})); then
      echo "Switches that are NOT Meraki Cloud Monitoring compatible:"
      for ip in "${BAD_MERAKI_IPS[@]}"; do
        echo "  - $ip"
      done
      echo
    fi

    if ((${#BAD_CFG_IPS[@]})); then
      echo "Switches that FAILED DNS/NTP/AAA/ip-routing/ping checks (but are Meraki-compatible):"
      for line in "${BAD_CFG_IPS[@]}"; do
        echo "  - $line"
      done
      echo
    fi

    if ((${#OK_IPS[@]})); then
      echo "Switches that PASSED ALL checks (ping, IOS-XE, DNS/NTP/AAA/ip routing, ping google.com, Meraki compatibility):"
      for ip in "${OK_IPS[@]}"; do
        echo "  - $ip"
      done
      echo
    fi
  } >"$summary"

  # ---------- write validated_ips.json for later mapping ----------
  {
    echo '['
    local first=1
    for ip in "${OK_IPS[@]}"; do
      if (( first )); then
        first=0
      else
        echo ','
      fi
      printf '  {"ip": "%s"}' "$ip"
    done
    echo
    echo ']'
  } >"$VALIDATED_JSON" 2>/dev/null || true

    # ---------- also write validated_switches.env for later tools ----------
  local VAL_ENV="$SCRIPT_DIR/validated_switches.env"
  {
    echo "# Generated by validate_switches_before_migration on $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
    # space-separated list of IPs that PASSED all checks
    printf 'export VALIDATED_SWITCH_IPS=%q\n' "${OK_IPS[*]}"
  } >"$VAL_ENV" 2>/dev/null || true


  # ---------- dialogs ----------
  dlg --backtitle "$BACKTITLE_V" \
      --title "Validation summary" \
      --textbox "$summary" 24 160 || true

  local rc=0
  if ((${#BAD_PING_IPS[@]} || ${#BAD_VER_IPS[@]} || ${#BAD_CFG_IPS[@]} || ${#BAD_MERAKI_IPS[@]})); then
    dlg --backtitle "$BACKTITLE_V" \
        --title "Validation failed" \
        --msgbox "Some switches failed ping, IOS-XE minimum version, Meraki compatibility,\n\nor required config checks (DNS/NTP/AAA/ip-routing/ping).\n\nReview the summary and correct issues before migration.\n\nOnly switches in the PASSED list will be eligible for Meraki mapping." 15 90
    rc=1
  else
    dlg --backtitle "$BACKTITLE_V" \
        --title "Validation OK" \
        --msgbox "All selected switches are reachable and meet rquirements. \nYou can safely continue with migration." 10 70
  fi

  return "$rc"
}

# ------------------------------------------------------------
# 2) Meraki org/network picker + switch→network mapper
#    (now uses upgrade_plan.* too)
# ------------------------------------------------------------
meraki_switch_network_mapper() {
  local API_BASE="https://api.meraki.com/api/v1"
  local BACKTITLE_M="Meraki switch mapping – map validated Catalyst switches"

  local DISC_JSON="$SCRIPT_DIR/discovery_results.json"
  local DISC_CSV="$SCRIPT_DIR/discovery_results.csv"
  local PLAN_JSON="$SCRIPT_DIR/upgrade_plan.json"
  local PLAN_CSV="$SCRIPT_DIR/upgrade_plan.csv"
  local PLAN_ENV="$SCRIPT_DIR/upgrade_plan.env"
  local VAL_ENV="$SCRIPT_DIR/validated_switches.env"
  local VAL_JSON="$SCRIPT_DIR/validated_ips.json"
  local ENV_FILE=""
  if [[ -n "${1:-}" && "${1:-}" != "-h" && "${1:-}" != "--help" ]]; then
    ENV_FILE="$1"
  else
    local -a CANDIDATES=(
      "$SCRIPT_DIR/ENV"
      "$SCRIPT_DIR/.env"
      "$SCRIPT_DIR/meraki_discovery.env"
      "$SCRIPT_DIR/meraki.env"
    )
    while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*.env" || true)
    while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*ENV" || true)
    while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*.ENV" || true)

    for f in "${CANDIDATES[@]}"; do
      [[ -f "$f" && -r "$f" ]] || continue
      if grep -Eq '(^|\s)(export\s+)?MERAKI_API_KEY=' "$f"; then
        ENV_FILE="$f"; break
      fi
    done
  fi

  if [[ -z "$ENV_FILE" ]]; then
    dlg --backtitle "$BACKTITLE_M" \
        --title "Meraki ENV not found" \
        --msgbox "Could not find an ENV-like file with MERAKI_API_KEY in $SCRIPT_DIR.\n\nPass a path as argument or create meraki_discovery.env / meraki.env." 12 80
    return 1
  fi

  local SEL_OUT_DIR MAP_ENV_OUT MAP_JSON_OUT
  SEL_OUT_DIR="$(dirname "$ENV_FILE")"
  MAP_ENV_OUT="$SEL_OUT_DIR/meraki_switch_network_map.env"
  MAP_JSON_OUT="$SEL_OUT_DIR/meraki_switch_network_map.json"

  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<USAGE
Usage: meraki_switch_network_mapper [optional:/path/to/envfile]

This will:
  1) Load MERAKI_API_KEY from an ENV-like file.
  2) Ask you to pick an Organization.
  3) Discover switches from upgrade_plan/discovery files.
  4) Filter to switches that:
       - passed the connectivity + IOS-XE validation step, and
       - have a valid PID + Serial (discovery/SSH succeeded).
  5) Show Meraki networks (productTypes includes "switch").
  6) Let you map each valid switch to a network (batch mapping per network).
  7) For each used network, pull a default physical address from
     the network or any existing device and let you confirm/edit it.
  8) Save the mapping to:
       $MAP_JSON_OUT
       $MAP_ENV_OUT
USAGE
    return 0
  fi

  need curl || return 1
  need jq   || return 1

  # per-call temp dir
  local TMPDIR
  TMPDIR="$(mktemp -d)"
  # No RETURN trap here – subshells used during paging would nuke TMPDIR too early.

  # Avoid history expansion issues with '!' in envs
  set +H
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"

  MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"
  _mask_key() { local k="$1"; local n=${#k}; [[ $n -gt 8 ]] && echo "${k:0:4}…${k: -4} (len=$n)" || echo "(len=$n)"; }

  local AUTH_MODE="${AUTH_MODE:-auto}"

  _do_curl() {
    local method="$1" path="$2" body="${3:-}" query="${4:-}" mode="$5"
    local hdr="$TMPDIR/hdr.$$" bodyf="$TMPDIR/body.$$"
    local -a H; H=(-H "Accept: application/json")
    if [[ "$mode" == "x-cisco" ]]; then
      H+=(-H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY")
    else
      H+=(-H "Authorization: Bearer $MERAKI_API_KEY")
    fi
    [[ -n "$body" ]] && H+=(-H "Content-Type: application/json")

    if [[ -n "$body" ]]; then
      curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' -X "$method" "${H[@]}" \
        "$API_BASE$path$query" --data "$body"
    else
      curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' -X "$method" "${H[@]}" \
        "$API_BASE$path$query"
    fi
  }

  _meraki_call() {
    local method="$1" path="$2" body="${3:-}" query="${4:-}"
    local code mode
    local -a attempt_modes
    if [[ "$AUTH_MODE" == "auto" ]]; then
      attempt_modes=("bearer" "x-cisco")
    else
      attempt_modes=("$AUTH_MODE")
    fi

    for mode in "${attempt_modes[@]}"; do
      while :; do
        code="$(_do_curl "$method" "$path" "$body" "$query" "$mode")"
        cp "$TMPDIR/hdr.$$" "$TMPDIR/last_headers" || true
        cp "$TMPDIR/body.$$" "$TMPDIR/last_body"   || true
        if [[ "$code" == "429" ]]; then
          local wait; wait="$(awk '/^Retry-After:/ {print $2}' "$TMPDIR/last_headers" | tr -d '\r')"
          [[ -z "$wait" ]] && wait=1
          sleep "$wait"; continue
        fi
        break
      done
      if [[ "$code" == "401" && "$AUTH_MODE" == "auto" && "$mode" == "bearer" ]]; then
        continue
      fi
      AUTH_MODE="$mode"
      break
    done
    echo "$code" > "$TMPDIR/code.$$"
  }

  _meraki_get_json() {
    local path="$1" query="${2:-}"
    _meraki_call GET "$path" "" "$query"
    local code; code="$(cat "$TMPDIR/code.$$")"
    if ! [[ "$code" =~ ^20[01]$ ]]; then
      echo "Meraki API error ($code):" >&2
      echo "Auth mode: $AUTH_MODE ; Key: $(_mask_key "$MERAKI_API_KEY")" >&2
      sed -n '1,160p' "$TMPDIR/last_body" >&2 || true
      return 1
    fi
    cat "$TMPDIR/last_body"
  }

  _meraki_get_all_pages() {
    local path="$1" query="${2:-?perPage=1000}"
    local accumulator="$TMPDIR/accum.$$"
    printf '[]' > "$accumulator"

    local nextStart=""
    while :; do
      local q="$query"
      [[ -n "$nextStart" ]] && q="${query}&startingAfter=$nextStart"
      _meraki_call GET "$path" "" "$q"
      local code; code="$(cat "$TMPDIR/code.$$")"
      if ! [[ "$code" =~ ^20[01]$ ]]; then
        echo "Meraki API error ($code) while paging:" >&2
        echo "Auth mode: $AUTH_MODE ; Key: $(_mask_key "$MERAKI_API_KEY")" >&2
        sed -n '1,160p' "$TMPDIR/last_body" >&2 || true
        return 1
      fi
      jq -s '.[0] + .[1]' "$accumulator" "$TMPDIR/last_body" > "$accumulator.tmp" && mv "$accumulator.tmp" "$accumulator"

      local link; link="$(grep -i '^Link:' "$TMPDIR/last_headers" | tr -d '\r' || true)"
      if grep -qi 'rel="next"' <<<"$link"; then
        nextStart="$(grep -oi 'startingAfter=[^&>;]*' <<<"$link" | tail -n1 | cut -d= -f2)"
        [[ -z "$nextStart" ]] && break
      else
        break
      fi
    done
    cat "$accumulator"
  }

  # ---- pick org ----
  local ORG_ID ORG_NAME

  pick_org() {
    local orgs_json; orgs_json="$(_meraki_get_all_pages "/organizations" "?perPage=1000")" || return 1

    local -a items=()
    while IFS=$'\t' read -r oid oname; do
      [[ -z "$oname" ]] && oname="(unnamed)"
      items+=("$oid" "$oname")
    done < <(jq -r '.[] | "\(.id)\t\(.name)"' <<<"$orgs_json")

    (( ${#items[@]} > 0 )) || { dlg --backtitle "$BACKTITLE_M" --msgbox "No organizations visible to this API key." 7 60; return 1; }

    local choice
    choice="$(dlg --clear \
                  --backtitle "$BACKTITLE_M – select organization" \
                  --menu "Select an Organization" 20 80 14 "${items[@]}")" || return 1

    ORG_ID="$choice"
    ORG_NAME="$(jq -r --arg id "$ORG_ID" '.[] | select(.id==$id) | .name' <<<"$orgs_json")"
  }

  # ---- switches (from upgrade_plan.* + discovery) ----
  declare -a IPS HOSTS PIDS SER
  declare -a MAPPABLE_IPS       # only switches with PID + Serial and that passed validation

  # ---- networks & mapping state ----
  declare -a NET_IDS NET_NAMES NET_LABELS
  declare -A NET_TYPES_BY_ID NET_ADDR
  declare -A MAP_NETID MAP_NETNAME USED_NETS INVALID_IP

  load_switches() {
    local SRC="" have_plan_json="" have_plan_ips="" have_plan_csv="" have_disc_json=""

    if [[ -s "$PLAN_JSON" && "$(jq 'length' "$PLAN_JSON" 2>/dev/null || echo 0)" -gt 0 ]]; then
      have_plan_json=1
    fi
    if [[ -s "$PLAN_CSV" ]]; then
      have_plan_csv=1
    fi
    if [[ -f "$PLAN_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$PLAN_ENV"
      UPGRADE_SELECTED_IPS="${UPGRADE_SELECTED_IPS:-}"
      [[ -n "$UPGRADE_SELECTED_IPS" ]] && have_plan_ips=1
    fi
    if [[ -s "$DISC_JSON" ]]; then
      have_disc_json=1
    fi

    if   [[ -n "$have_plan_json" ]]; then SRC="planjson"
    elif [[ -n "$have_plan_csv"  ]]; then SRC="plancsv"
    elif [[ -n "$have_plan_ips"  ]]; then SRC="planenv"
    elif [[ -n "$have_disc_json" ]]; then SRC="disc"
    else
      dlg --backtitle "$BACKTITLE_M" \
          --msgbox "No upgrade_plan.json / upgrade_plan.csv / upgrade_plan.env or discovery_results.json found." 9 80
      return 1
    fi

    IPS=(); HOSTS=(); PIDS=(); SER=()

    if [[ "$SRC" == "planjson" ]]; then
      mapfile -t IPS   < <(jq -r '.[].ip' "$PLAN_JSON" 2>/dev/null)

    elif [[ "$SRC" == "plancsv" ]]; then
      local first=1 ip
      while IFS=, read -r ip _; do
        if (( first )); then first=0; continue; fi
        ip="${ip%\"}"; ip="${ip#\"}"
        ip="$(trim "$ip")"
        [[ -n "$ip" ]] && IPS+=( "$ip" )
      done < "$PLAN_CSV"

    elif [[ "$SRC" == "planenv" ]]; then
      read -r -a IPS <<<"$UPGRADE_SELECTED_IPS"

    else
      # fallback: full discovery list
      mapfile -t IPS   < <(jq -r '.[].ip' "$DISC_JSON" 2>/dev/null)
      mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$DISC_JSON" 2>/dev/null)
      mapfile -t PIDS  < <(jq -r '.[].pid      // ""' "$DISC_JSON" 2>/dev/null)
      mapfile -t SER   < <(jq -r '.[].serial   // ""' "$DISC_JSON" 2>/dev/null)
    fi

    # If we came from a plan file, enrich with discovery info if available
    if [[ "$SRC" =~ ^plan && -s "$DISC_JSON" ]]; then
      declare -A HMAP PMAP SMAP
      while IFS=$'\t' read -r ip h p s; do
        HMAP["$ip"]="$h"
        PMAP["$ip"]="$p"
        SMAP["$ip"]="$s"
      done < <(jq -r '.[] | "\(.ip)\t\(.hostname // "")\t\(.pid // "")\t\(.serial // "")"' "$DISC_JSON")

      HOSTS=(); PIDS=(); SER=()
      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
        PIDS+=(  "${PMAP[$ip]:-}" )
        SER+=(   "${SMAP[$ip]:-}" )
      done
    fi

    (( ${#IPS[@]} > 0 )) || { dlg --backtitle "$BACKTITLE_M" --msgbox "No switches found in upgrade_plan.* / discovery files." 7 80; return 1; }

    # Load set of IPs that passed validation
    local -a VAL_ENV_IPS=()

    # Preferred: env file created by validation step
    if [[ -f "$VAL_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$VAL_ENV"
      VALIDATED_SWITCH_IPS="${VALIDATED_SWITCH_IPS:-}"
      if [[ -n "$VALIDATED_SWITCH_IPS" ]]; then
        read -r -a VAL_ENV_IPS <<<"$VALIDATED_SWITCH_IPS"
      fi
    fi

    # Fallback: validated_ips.json (older runs / manual use)
    if (( ${#VAL_ENV_IPS[@]} == 0 )) && [[ -s "$VAL_JSON" ]]; then
      mapfile -t VAL_ENV_IPS < <(jq -r '.[].ip' "$VAL_JSON" 2>/dev/null)
    fi

    if (( ${#VAL_ENV_IPS[@]} == 0 )); then
      dlg --backtitle "$BACKTITLE_M" \
          --title "No validation results found" \
          --msgbox "This tool expects you to run the connectivity & IOS-XE validation step first.\n\nValidation results file not found:\n  $VAL_ENV or $VAL_JSON\n\nRun validation and then re-run this tool." 14 80
      return 1
    fi

    declare -A VAL_OK
    for ip in "${VAL_ENV_IPS[@]}"; do
      VAL_OK["$ip"]=1
    done

    # Build list of switches that actually have PID + Serial AND passed validation
    MAPPABLE_IPS=()
    INVALID_IP=()
    local i
    for i in "${!IPS[@]}"; do
      local ip="${IPS[$i]}"
      local pid="$(trim "${PIDS[$i]:-}")"
      local ser="$(trim "${SER[$i]:-}")"

      if [[ -z "${VAL_OK[$ip]:-}" ]]; then
        INVALID_IP["$ip"]=1
        continue
      fi
      if [[ -n "$pid" && -n "$ser" ]]; then
        MAPPABLE_IPS+=( "$ip" )
      else
        INVALID_IP["$ip"]=1
      fi
    done

    local tmp="$TMPDIR/switch_list.txt"
    {
      echo "Planned switches to map (from upgrade_plan.*):"
      echo
      printf "%-16s %-24s %-15s %-15s %s\n" "IP" "Hostname" "PID" "Serial" "Status"
      printf "%-16s %-24s %-15s %-15s %s\n" "----------------" "------------------------" "---------------" "---------------" "-------------------------------"
      for i in "${!IPS[@]}"; do
        local ip="${IPS[$i]}"
        local h="${HOSTS[$i]:-<unknown>}"
        local p="${PIDS[$i]:-}"
        local s="${SER[$i]:-}"
        local status
        if [[ -z "${VAL_OK[$ip]:-}" ]]; then
          status="NOT VALIDATED – not in last ping/version run (not mapped)"
        elif [[ -z "$(trim "$p")" || -z "$(trim "$s")" ]]; then
          status="INVALID – no model/serial (not mapped)"
        else
          status="OK – eligible for mapping"
        fi
        printf "%-16s %-24s %-15s %-15s %s\n" "$ip" "$h" "$p" "$s" "$status"
      done
      echo
      echo "Only switches that BOTH:"
      echo "  • passed the connectivity & IOS-XE validation step, and"
      echo "  • have PID (model) and Serial number"
      echo "will appear in the network mapping dialogs."
    } > "$tmp"

    dlg --backtitle "$BACKTITLE_M – review discovered & validated switches" \
        --title "Switches to map" \
        --textbox "$tmp" 22 110 || true

    if (( ${#MAPPABLE_IPS[@]} == 0 )); then
      dlg --backtitle "$BACKTITLE_M" \
          --title "No valid switches" \
          --msgbox "None of the discovered switches both passed validation AND have a PID (model) and Serial number.\n\nOnly devices that were successfully validated and inventoried can be mapped to Meraki networks.\n\nCheck your discovery/validation results and try again." 16 80
      return 1
    fi
  }

  create_network_dialog() {
    local NET_NAME
    NET_NAME="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                    --inputbox "Enter a name for the new Network (Org: $ORG_NAME)" \
                    10 70 "Catalyst Switch Onboarding")" || return 1
    NET_NAME="$(trim "$NET_NAME")"
    [[ -n "$NET_NAME" ]] || { dlg --backtitle "$BACKTITLE_M" --msgbox "Network name cannot be empty." 7 60; return 1; }

    local -a checklist=(
      "appliance"        "MX / SD-WAN"                              off
      "switch"           "Switch (Meraki MS OR Catalyst IOS-XE)"    on
      "wireless"         "MR / Wireless"                            off
      "camera"           "MV / Cameras"                             off
      "cellularGateway"  "MG / Cellular"                            off
      "sensor"           "MT / Sensors"                             off
      "systemsManager"   "SM / MDM"                                 off
    )

    local selection
    selection="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                     --separate-output \
                     --checklist "Select product types for \"$NET_NAME\"\n(Keep 'switch' enabled for Catalyst onboarding)" \
                     20 80 12 "${checklist[@]}")" || return 1
    [[ -n "$selection" ]] || { dlg --backtitle "$BACKTITLE_M" --msgbox "At least one product type must be selected." 7 70; return 1; }

    mapfile -t PRODUCTS <<< "$selection"
    local ptypes_json; ptypes_json="$(printf '%s\n' "${PRODUCTS[@]}" | jq -R . | jq -s .)"

    local default_tz="America/New_York"
    local tz; tz="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                        --inputbox "Optional: timeZone (IANA) for \"$NET_NAME\"\nLeave blank to let Dashboard default" \
                        10 70 "$default_tz")" || return 1
    tz="$(trim "$tz")"

    local addr; addr="$(dlg --backtitle "$BACKTITLE_M: create Meraki network" \
                            --inputbox "Physical address for \"$NET_NAME\" (one line)\nExample: 123 AnyStreet St. City ST 12345" \
                            10 70 "")" || return 1
    addr="$(trim "$addr")"

    local body
    if [[ -n "$tz" && -n "$addr" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg tz "$tz" --arg addr "$addr" \
        '{name:$name, productTypes:$productTypes, timeZone:$tz, address:$addr}')"
    elif [[ -n "$tz" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg tz "$tz" \
        '{name:$name, productTypes:$productTypes, timeZone:$tz}')"
    elif [[ -n "$addr" ]]; then
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg addr "$addr" \
        '{name:$name, productTypes:$productTypes, address:$addr}')"
    else
      body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" \
        '{name:$name, productTypes:$productTypes}')"
    fi

    _meraki_call POST "/organizations/$ORG_ID/networks" "$body" ""
    local code; code="$(cat "$TMPDIR/code.$$")"
    [[ "$code" == "201" ]] || {
      dlg --backtitle "$BACKTITLE_M" --msgbox "Create network failed ($code).\n\nSee logs for details." 9 70
      return 1
    }

    local NET_ID NET_PRODUCT_TYPES
    NET_ID="$(jq -r '.id' "$TMPDIR/last_body")"
    NET_PRODUCT_TYPES="$(jq -c '.productTypes' "$TMPDIR/last_body")"
    local addr_ret; addr_ret="$(jq -r '.address // ""' "$TMPDIR/last_body")"
    [[ -z "$addr_ret" ]] && addr_ret="$addr"
    NET_ADDR["$NET_ID"]="$addr_ret"

    local url; url="$(jq -r '.url' "$TMPDIR/last_body")"

    dlg --backtitle "$BACKTITLE_M" \
        --msgbox "Created Network:\n\nName: $NET_NAME\nID:   $NET_ID\nTypes: $(jq -r '.|join(", ")' <<<"$NET_PRODUCT_TYPES")\nAddress: ${addr_ret:-<none>}\nURL:  $url\n" 15 90

    NET_IDS+=( "$NET_ID" )
    NET_NAMES+=( "$NET_NAME" )
    NET_TYPES_BY_ID["$NET_ID"]="$NET_PRODUCT_TYPES"
    local types_flat; types_flat="$(jq -r '.|join(",")' <<<"$NET_PRODUCT_TYPES")"
    NET_LABELS+=( "$NET_NAME  [$types_flat]" )
  }

  load_switch_networks() {
    NET_IDS=(); NET_NAMES=(); NET_LABELS=(); NET_TYPES_BY_ID=(); NET_ADDR=()

    local nets_json; nets_json="$(_meraki_get_all_pages "/organizations/$ORG_ID/networks" "?perPage=1000")" || return 1

    while IFS=$'\t' read -r nid nname ptypes addr; do
      [[ -z "$nid" ]] && continue
      [[ -z "$nname" ]] && nname="(unnamed)"

      if ! jq -e '. | index("switch")' <<<"$ptypes" >/dev/null 2>&1; then
        continue
      fi

      NET_IDS+=( "$nid" )
      NET_NAMES+=( "$nname" )
      NET_TYPES_BY_ID["$nid"]="$ptypes"
      NET_ADDR["$nid"]="$(trim "$addr")"

      local types_flat; types_flat="$(jq -r '.|join(",")' <<<"$ptypes")"
      NET_LABELS+=( "$nname  [$types_flat]" )
    done < <(jq -r '.[] | "\(.id)\t\(.name)\t\(.productTypes)\t\(.address // "")"' <<<"$nets_json")

    if [[ ${#NET_IDS[@]} -eq 0 ]]; then
      dlg --backtitle "$BACKTITLE_M" --title "No networks" --msgbox \
        "No Meraki networks with product type 'switch' were found in:\n  $ORG_NAME ($ORG_ID)\n\nCreate one first, then rerun this script." 12 80
      create_network_dialog || return 1
    fi
  }

  get_existing_address_for_network() {
    local nid="$1"
    local addr="${NET_ADDR[$nid]:-}"
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return
    fi

    local devs; devs="$(_meraki_get_all_pages "/networks/$nid/devices" "?perPage=1000")"
    addr="$(jq -r '[.[] | .address? // "" | select(. != "")][0] // ""' <<<"$devs")"
    echo "$addr"
  }

  ensure_addresses_for_used_networks() {
    for nid in "${!USED_NETS[@]}"; do
      local addr="${NET_ADDR[$nid]:-}"

      if [[ -z "$addr" ]]; then
        addr="$(get_existing_address_for_network "$nid")"
      fi

      local nname=""
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
          nname="${NET_NAMES[$i]}"
          break
        fi
      done
      [[ -z "$nname" ]] && nname="$nid"

      addr="$(dlg --backtitle "$BACKTITLE_M: confirm network address" \
                  --inputbox "Enter physical address for network:\n  $nname ($nid)\n\nExample: 123 AnyStreet St. City ST 12345\n\nLeave blank if you prefer to set it later." \
                  13 80 "$addr")" || return 1
      NET_ADDR["$nid"]="$(trim "$addr")"
    done
  }

  map_switches_to_networks() {
    # only switches that had PID + Serial and passed validation are mappable
    local -a UNASSIGNED=("${MAPPABLE_IPS[@]}")

    while :; do
      local remaining=${#UNASSIGNED[@]}
      (( remaining == 0 )) && break

      local -a menu_items=()
      for i in "${!NET_IDS[@]}"; do
        menu_items+=( "${NET_IDS[$i]}" "${NET_LABELS[$i]}" )
      done
      menu_items+=( "NEW" "Create a new 'switch' network" )
      menu_items+=( "DONE" "Finish mapping (leave remaining unmapped)" )

      local net_choice
      net_choice="$(dlg --backtitle "$BACKTITLE_M: assign switches to networks" \
                        --menu "Select a network for the next batch of switches.\nUnmapped, valid switches remaining: $remaining" \
                        22 90 16 "${menu_items[@]}")" || return 1

      if [[ "$net_choice" == "DONE" ]]; then
        if (( remaining > 0 )); then
          if ! dlg --backtitle "$BACKTITLE_M" \
                   --yesno "You still have $remaining valid switch(es) without a network mapping.\n\nAre you sure you want to finish and leave them unmapped?" 11 70; then
            continue
          fi
        fi
        break
      fi

      if [[ "$net_choice" == "NEW" ]]; then
        create_network_dialog || return 1
        continue
      fi

      local nid="$net_choice"
      local nname=""
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
          nname="${NET_NAMES[$i]}"; break
        fi
      done
      [[ -z "$nname" ]] && nname="$nid"

      local -a chk_items=()
      for ip in "${UNASSIGNED[@]}"; do
        local idx=""
        for j in "${!IPS[@]}"; do
          if [[ "${IPS[$j]}" == "$ip" ]]; then idx="$j"; break; fi
        done
        local desc
        if [[ -n "$idx" ]]; then
          desc="$(trim "${HOSTS[$idx]:-$ip}  ${PIDS[$idx]:+(${PIDS[$idx]}) }${SER[$idx]:+SN:${SER[$idx]}}")"
        else
          desc="$ip"
        fi
        chk_items+=( "$ip" "$desc" "off" )
      done

      local selection
      selection="$(dlg --backtitle "$BACKTITLE_M: assign switches to networks" \
                       --separate-output \
                       --checklist "Select switch(es) to assign to:\n  $nname ($nid)" \
                       22 90 14 "${chk_items[@]}")" || continue

      selection="$(trim "$selection")"
      [[ -z "$selection" ]] && continue
      mapfile -t chosen_ips <<<"$selection"

      local -a new_unassigned=()
      for ip in "${UNASSIGNED[@]}"; do
        local assigned_here=0
        for c in "${chosen_ips[@]}"; do
          if [[ "$c" == "$ip" ]]; then
            MAP_NETID["$ip"]="$nid"
            MAP_NETNAME["$ip"]="$nname"
            assigned_here=1
            break
          fi
        done
        (( assigned_here == 0 )) && new_unassigned+=( "$ip" )
      done
      UNASSIGNED=("${new_unassigned[@]}")
    done

    USED_NETS=()
    for ip in "${IPS[@]}"; do
      local nid="${MAP_NETID[$ip]:-}"
      [[ -z "$nid" ]] && continue
      USED_NETS["$nid"]=1
    done

    ensure_addresses_for_used_networks || return 1

    local tmp="$TMPDIR/map_summary.txt"
    {
      echo "Meraki Organization:"
      echo "  $ORG_NAME ($ORG_ID)"
      echo
      echo "Switch-to-network mappings (only switches with PID+Serial that passed validation are mappable):"
      echo
      printf "%-16s %-24s %-18s %-12s %s\n" "IP" "Hostname" "Network" "Net ID" "Serial"
      printf "%-16s %-24s %-18s %-12s %s\n" "----------------" "------------------------" "------------------" "------------" "----------------"
      for i in "${!IPS[@]}"; do
        local ip="${IPS[$i]}"
        local n="${MAP_NETNAME[$ip]:-<unmapped>}"
        local nid="${MAP_NETID[$ip]:-<none>}"
        printf "%-16s %-24s %-18s %-12s %s\n" \
          "$ip" "${HOSTS[$i]:-<unknown>}" "$n" "$nid" "${SER[$i]:-}"
      done
      echo
      echo "Network addresses (for networks used in mappings):"
      echo
      for nid in "${!USED_NETS[@]}"; do
        local nname=""
        for i in "${!NET_IDS[@]}"; do
          if [[ "${NET_IDS[$i]}" == "$nid" ]]; then
            nname="${NET_NAMES[$i]}"
            break
          fi
        done
        [[ -z "$nname" ]] && nname="$nid"
        printf "  %s (%s): %s\n" "$nname" "$nid" "${NET_ADDR[$nid]:-<none>}"
      done
    } > "$tmp"

    dlg --backtitle "$BACKTITLE_M: review mapping summary" \
        --title "Mapping summary" \
        --textbox "$tmp" 24 100 || true
  }

  save_mapping_files() {
    {
      echo "["
      local first=1
      for i in "${!IPS[@]}"; do
        local ip="${IPS[$i]}"
        local nid="${MAP_NETID[$ip]:-}"
        local nname="${MAP_NETNAME[$ip]:-}"
        [[ -z "$nid" ]] && continue   # only mapped switches (and thus only ones with PID+Serial and validated)

        local h="${HOSTS[$i]:-}"
        local p="${PIDS[$i]:-}"
        local s="${SER[$i]:-}"
        local addr="${NET_ADDR[$nid]:-}"

        local obj
        obj="$(jq -n --arg ip "$ip" \
                     --arg hostname "$h" \
                     --arg pid "$p" \
                     --arg serial "$s" \
                     --arg networkId "$nid" \
                     --arg networkName "$nname" \
                     --arg networkAddress "$addr" \
               '{ip:$ip, hostname:$hostname, pid:$pid, serial:$serial, networkId:$networkId, networkName:$networkName, networkAddress:$networkAddress}')"
        if (( first )); then
          first=0
        else
          printf ',\n'
        fi
        printf '%s' "$obj"
      done
      echo
      echo "]"
    } > "$MAP_JSON_OUT"

    local single_net_id="" single_net_name=""
    if (( ${#USED_NETS[@]} == 1 )); then
      for nid in "${!USED_NETS[@]}"; do
        single_net_id="$nid"
      done
      for i in "${!NET_IDS[@]}"; do
        if [[ "${NET_IDS[$i]}" == "$single_net_id" ]]; then
          single_net_name="${NET_NAMES[$i]}"
          break
        fi
      done
    fi

    {
      echo "# Generated by meraki_switch_network_mapper on $(date -u +'%Y-%m-%d %H:%M:%S UTC')"
      printf 'export MERAKI_ORG_ID=%q\n' "$ORG_ID"
      printf 'export MERAKI_ORG_NAME=%q\n' "$ORG_NAME"
      printf 'export MERAKI_SWITCH_NETWORK_MAP_FILE=%q\n' "$MAP_JSON_OUT"
      if [[ -n "$single_net_id" ]]; then
        printf 'export MERAKI_NETWORK_ID=%q\n' "$single_net_id"
        printf 'export MERAKI_NETWORK_NAME=%q\n' "$single_net_name"
      fi
    } > "$MAP_ENV_OUT"
  }

  pick_org                 || { [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; return 1; }
  load_switches            || { [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; return 1; }
  load_switch_networks     || { [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; return 1; }
  map_switches_to_networks || { [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; return 1; }
  save_mapping_files       || { [[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; return 1; }

  dlg --backtitle "$BACKTITLE_M" \
      --title "Done" \
      --infobox "Switch-to-network mapping saved." 5 60

  sleep 2

  # best-effort cleanup of Meraki temp dir
  [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
}





meraki_firewall_info_helper() {
  (
    set -Euo pipefail

    # ------------------------------------------------------------
    # Standalone Meraki "Firewall info" helper (embedded)
    # ------------------------------------------------------------

    SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

    # ----- tiny dependency checker -----
    for _cmd in curl jq; do
      if ! command -v "$_cmd" >/dev/null 2>&1; then
        echo "Missing dependency: $_cmd" >&2
        exit 1
      fi
    done

    # ----- minimal dialog wrapper -----
    : "${DIALOG:=dialog}"
    DIALOG_HAS_STDOUT=1
    if ! command -v "$DIALOG" >/dev/null 2>&1; then
      DIALOG=""
    else
      if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
        DIALOG_HAS_STDOUT=0
      fi
    fi

        BACKTITLE_F="Meraki upstream firewall requirements"

    dlg_msgbox() {
      local text="$1" h="${2:-10}" w="${3:-80}"
      if [[ -n "$DIALOG" ]]; then
        if (( DIALOG_HAS_STDOUT )); then
          "$DIALOG" --no-shadow \
            --backtitle "$BACKTITLE_F" \
            --ok-label "Continue" --exit-label "Continue" \
            --msgbox "$text" "$h" "$w"
        else
          "$DIALOG" --no-shadow \
            --backtitle "$BACKTITLE_F" \
            --ok-label "Continue" --exit-label "Continue" \
            --msgbox "$text" "$h" "$w" 2>/dev/null
        fi
      else
        printf '%s\n' "$text"
      fi
    }

    trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }

    BACKTITLE_F="Meraki upstream firewall requirements"

    # ------------------------------------------------------------
    # Find env with MERAKI_API_KEY
    #   - If you pass a path: ./firewall /path/to/env
    #   - Otherwise we search for something containing MERAKI_API_KEY
    # ------------------------------------------------------------
    ENV_FILE=""
    if [[ $# -gt 0 && "$1" != "-h" && "$1" != "--help" ]]; then
      ENV_FILE="$1"
    else
      base_dir="$SCRIPT_DIR"
      CANDIDATES=(
        "$base_dir/meraki_discovery.env"
        "$base_dir/meraki.env"
        "$base_dir/.env"
        "$base_dir/ENV"
      )
      while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$base_dir/*.env" 2>/dev/null || true)

      for f in "${CANDIDATES[@]}"; do
        [[ -f "$f" && -r "$f" ]] || continue
        if grep -Eq '(^|\s)(export\s+)?MERAKI_API_KEY=' "$f"; then
          ENV_FILE="$f"
          break
        fi
      done
    fi

    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
      cat <<USAGE
Usage: ./firewall [optional:/path/to/envfile]

This script will:
  1) Load MERAKI_API_KEY from the given env (or auto-detected one).
  2) Determine the Meraki Organization ID from:
       - MERAKI_ORG_ID (if already set), or
       - meraki_switch_network_map.env, or
       - meraki_switch_network_map.json (first networkId → /networks/{id}).
  3) Call /organizations/{orgId} to learn the Dashboard URL / shard.
  4) Build the "Firewall info" page URL for that org.
  5) Write firewall_info.txt under runs/migration (latest run if present),
     then:
       - show a dialog explaining what it found and where it wrote it,
       - drop back to CLI with a clickable URL and wait for ENTER.
USAGE
      exit 0
    fi

    if [[ -z "$ENV_FILE" ]]; then
      dlg_msgbox "Could not find an ENV-like file with MERAKI_API_KEY in:\n  $SCRIPT_DIR\n\nPass a path as argument or create meraki_discovery.env / meraki.env." 13 80
      exit 1
    fi

    # ------------------------------------------------------------
    # Load API key
    # ------------------------------------------------------------
    set +H  # no history expansion on !
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"

    MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"

    # ------------------------------------------------------------
    # Determine ORG ID
    #   1) MERAKI_ORG_ID already in env?
    #   2) meraki_switch_network_map.env
    #   3) meraki_switch_network_map.json (first networkId -> /networks/{id})
    # ------------------------------------------------------------
    ORG_ID="${MERAKI_ORG_ID:-}"

    MAP_ENV="$SCRIPT_DIR/meraki_switch_network_map.env"
    MAP_JSON="$SCRIPT_DIR/meraki_switch_network_map.json"

    if [[ -z "$ORG_ID" && -f "$MAP_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$MAP_ENV"
      ORG_ID="${MERAKI_ORG_ID:-$ORG_ID}"
    fi

    API_BASE="https://api.meraki.com/api/v1"

    TMPDIR="$(mktemp -d)"
    trap '[[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"' EXIT

    _meraki_call() {
      local method="$1" url="$2"
      local hdr="$TMPDIR/hdr" body="$TMPDIR/body" code mode

      for mode in bearer x-cisco; do
        if [[ "$mode" == "bearer" ]]; then
          code="$(curl -sS -D "$hdr" -o "$body" -w '%{http_code}' \
            -H "Accept: application/json" \
            -H "Authorization: Bearer $MERAKI_API_KEY" \
            -X "$method" "$url")"
        else
          code="$(curl -sS -D "$hdr" -o "$body" -w '%{http_code}' \
            -H "Accept: application/json" \
            -H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY" \
            -X "$method" "$url")"
        fi

        if [[ "$code" == "429" ]]; then
          local wait
          wait="$(awk '/^Retry-After:/ {print $2}' "$hdr" | tr -d '\r')"
          [[ -z "$wait" ]] && wait=1
          sleep "$wait"
          continue
        fi

        if [[ "$code" =~ ^20[01]$ ]]; then
          cat "$body"
          return 0
        fi
      done

      echo "Meraki API error ($code) for $url" >&2
      return 1
    }

    if [[ -z "$ORG_ID" && -s "$MAP_JSON" ]]; then
      first_net="$(jq -r '.[0].networkId // empty' "$MAP_JSON")"
      if [[ -n "$first_net" ]]; then
        net_json="$(_meraki_call GET "$API_BASE/networks/$first_net")" || {
          dlg_msgbox "Failed to query Meraki network ${first_net} to infer orgId." 10 80
          exit 1
        }
        ORG_ID="$(jq -r '.organizationId // empty' <<<"$net_json")"
      fi
    fi

    if [[ -z "$ORG_ID" ]]; then
      dlg_msgbox "Could not determine MERAKI_ORG_ID.\n\nExpected one of:\n  - MERAKI_ORG_ID already set in your env\n  - $MAP_ENV (from switch mapping)\n  - $MAP_JSON with at least one mapped network" 14 80
      exit 1
    fi

    # ------------------------------------------------------------
    # Fetch organization and build Firewall info URL
    # ------------------------------------------------------------
    org_json="$(_meraki_call GET "$API_BASE/organizations/$ORG_ID")" || {
      dlg_msgbox "Failed to fetch organization ${ORG_ID} from Meraki API." 10 80
      exit 1
    }

    ORG_NAME="$(jq -r '.name // ""' <<<"$org_json")"
    ORG_URL="$(jq -r '.url  // ""' <<<"$org_json")"

    base_url="https://dashboard.meraki.com"
    if [[ "$ORG_URL" =~ ^https?://[^/]+ ]]; then
      base_url="${BASH_REMATCH[0]}"
    fi
    host="${base_url#*://}"

    FWINFO_URL="${base_url}/manage/support/firewall_configuration"

    # ------------------------------------------------------------
    # Decide where to write firewall_info.txt
    #   Prefer: runs/migration/latest.env → MIGRATION_RUN_DIR
    # ------------------------------------------------------------
    RUN_ROOT="$SCRIPT_DIR/runs/migration"
    mkdir -p "$RUN_ROOT"

    FW_OUT=""
    if [[ -f "$RUN_ROOT/latest.env" ]]; then
      # shellcheck disable=SC1090
      source "$RUN_ROOT/latest.env" || true
      if [[ -n "${MIGRATION_RUN_DIR:-}" ]]; then
        FW_OUT="$MIGRATION_RUN_DIR/firewall_info.txt"
      fi
    fi

    if [[ -z "$FW_OUT" ]]; then
      FW_OUT="$RUN_ROOT/firewall_info-$(date -u +%Y%m%d%H%M%S).txt"
    fi

    cat >"$FW_OUT" <<EOF
Meraki upstream firewall information
====================================

Organization:  ${ORG_NAME:-<unknown>} (${ORG_ID})
Dashboard URL: ${ORG_URL:-<unknown>}
Shard host:    ${host}

Firewall info page for this org:
  ${FWINFO_URL}

How to view it:
  1. Open a browser and log into the Meraki Dashboard.
  2. Go to:  Help → Firewall info
     (or paste the URL above into your browser once logged in.)

NOTE:
  The full, authoritative list of IP ranges and ports is ONLY on
  the Dashboard "Firewall info" page. The public API does not
  expose that table directly.
EOF

    # ------------------------------------------------------------
    # Dialog explanation (nice UX), then drop back to CLI
    # ------------------------------------------------------------
    MSG=$'Meraki upstream firewall requirements for switches\n\n'"Organization:  ${ORG_NAME:-<unknown>} (${ORG_ID})"\
$'\n\nWhat this step did:\n'\
$'  • Determined your Meraki Dashboard organization and shard\n'\
$'  • Built the URL of the “Firewall info” page for this org\n'\
$'  • Saved a helper text file with those details:\n\n'"  $FW_OUT"\
$'\n\nHow the traffic flows:\n'\
$'  • All Meraki cloud communication from switches is OUTBOUND\n'\
$'    from your network toward the Meraki cloud.\n'\
$'  • On a normal stateful firewall, return traffic for those\n'\
$'    outbound sessions is automatically allowed.\n'\
$'  • You do NOT need inbound pinholes, port forwards, or static\n'\
$'    inbound rules for Meraki switch cloud management.\n'\
$'\nFor Meraki switches (MS and Cloud-Monitored Catalyst), make sure\n'\
$'your firewall allows outbound (egress) traffic from the switch\n'\
$'management VLANs/subnets to the Internet on at least:\n'\
$'\n'\
$'  • UDP 7351 and UDP 9350–9381 (outbound)\n'\
$'      - Primary Meraki cloud control channels and VPN registry\n'\
$'\n'\
$'  • TCP 443 (outbound)\n'\
$'      - Dashboard/API communication and Cloud Monitoring for\n'\
$'        Catalyst switches\n'\
$'\n'\
$'  • UDP 123 (outbound)\n'\
$'      - NTP time synchronization to Internet time servers\n'\
$'\n'\
$'  • DNS (UDP/TCP 53, outbound)\n'\
$'      - Name resolution for Meraki cloud FQDNs\n'\
$'\nDepending on your configuration and the Dashboard “Firewall info”\n'\
$'CSV for your org, you may also see additional switch-related\n'\
$'entries, for example:\n'\
$'\n'\
$'  • Outbound TCP/UDP ports from switches to on-prem services\n'\
$'    such as RADIUS, syslog, SNMP managers, or other tools.\n'\
$'\nThe full, authoritative list of IP ranges and ports — including\n'\
$'any extra switch-specific rows for your shard/region — is only\n'\
$'shown on the Dashboard “Firewall info” page.\n'\
$'\nAfter you press Continue, this script will return to the terminal\n'\
$'and show a clickable URL for that page so you can compare the\n'\
$'Dashboard firewall requirements with your own firewall policy.\n'

    dlg_msgbox "$MSG" 55 96

    # ------------------------------------------------------------
    # CLI: show clickable URL and pause until user is ready
    # ------------------------------------------------------------
    clear
    echo
    echo "===================================================="
    echo " Meraki Firewall Requirements – Dashboard Link"
    echo "===================================================="
    echo
    echo "Organization:  ${ORG_NAME:-<unknown>} (${ORG_ID})"
    echo "Dashboard URL: ${ORG_URL:-<unknown>}"
    echo
    echo "Firewall info page for this organization:"
    echo "  ${FWINFO_URL}"
    echo
    echo "Open that URL in your browser (most terminals let you"
    echo "Ctrl+Click or Cmd+Click the link above)."
    echo
    read -r -p "Press ENTER after you've reviewed the Dashboard firewall info to continue... " _
    echo
  )
  return $?
}



# ------------------------------------------------------------
# 3) Enable & verify "service meraki connect" on switches
#    (parallel: up to 10 at a time, with 3x 15s retries)
# ------------------------------------------------------------
  onboard_meraki_connect_switches() {
  local BACKTITLE_C="Meraki Cloud Monitoring – enable & verify connectivity"

  # Relax strict mode inside this function so a failing jq/SSH parse
  # does not kill the whole script.
  set +e
  set +u
  set +o pipefail

  local DISC_ENV="$SCRIPT_DIR/meraki_discovery.env"
  local VALIDATED_JSON="$SCRIPT_DIR/validated_ips.json"
  local VAL_ENV="$SCRIPT_DIR/validated_switches.env"
  local DISC_JSON="$SCRIPT_DIR/discovery_results.json"
  local DISC_CSV="$SCRIPT_DIR/discovery_results.csv"
  local MAP_JSON="$SCRIPT_DIR/meraki_switch_network_map.json"

  need ping || return 1
  need ssh  || return 1
  need jq   || return 1

  # ---------- SSH creds ----------
  if [[ -f "$DISC_ENV" ]]; then
    # shellcheck disable=SC1090
    source "$DISC_ENV"
  fi
  local SSH_USER="${SSH_USERNAME:-}"
  local SSH_PASS="${SSH_PASSWORD:-}"

  if [[ -z "$SSH_USER" ]]; then
    dlg --backtitle "$BACKTITLE_C" \
        --title "Missing SSH username" \
        --msgbox "SSH_USERNAME is not set in meraki_discovery.env.\n\nCannot onboard switches." 10 70
    return 1
  fi

    # ---------- decide which switches to onboard ----------
  # Preferred: use mapped switches from meraki_switch_network_map.json
  local -a IPS=()
  local -a HOSTS=()

  if [[ -s "$MAP_JSON" ]]; then
    mapfile -t IPS   < <(jq -r '.[].ip' "$MAP_JSON" 2>/dev/null)
    mapfile -t HOSTS < <(jq -r '.[].hostname // ""' "$MAP_JSON" 2>/dev/null)
  fi

  # Fallback (no mapping file): use validated list, like before
  if (( ${#IPS[@]} == 0 )); then
    if [[ -f "$VAL_ENV" ]]; then
      # shellcheck disable=SC1090
      source "$VAL_ENV"
      if [[ -n "${VALIDATED_SWITCH_IPS:-}" ]]; then
        read -r -a IPS <<<"$VALIDATED_SWITCH_IPS"
      fi
    fi

    if (( ${#IPS[@]} == 0 )) && [[ -s "$VALIDATED_JSON" ]]; then
      mapfile -t IPS < <(jq -r '.[].ip' "$VALIDATED_JSON" 2>/dev/null)
    fi

    if (( ${#IPS[@]} == 0 )); then
      dlg --backtitle "$BACKTITLE_C" \
          --title "No validated switches" \
          --msgbox "No validated switch list found.\n\nRun the connectivity/IOS-XE validation step first." 11 80
      return 1
    fi

    # optional: map IP -> hostname from discovery (fallback mode only)
    if [[ -s "$DISC_JSON" ]]; then
      declare -A HMAP
      while IFS=$'\t' read -r ip h; do
        HMAP["$ip"]="$h"
      done < <(jq -r '.[] | "\(.ip)\t\(.hostname // "")"' "$DISC_JSON")
      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
      done
    elif [[ -s "$DISC_CSV" ]]; then
      declare -A HMAP
      local ip ssh login hostname version pid serial
      local first=1
      while IFS=, read -r ip ssh login hostname version pid serial; do
        if (( first )); then first=0; continue; fi
        ip="${ip%\"}"; ip="${ip#\"}"
        hostname="${hostname%\"}"; hostname="${hostname#\"}"
        HMAP["$ip"]="$hostname"
      done < "$DISC_CSV"
      for ip in "${IPS[@]}"; do
        HOSTS+=( "${HMAP[$ip]:-}" )
      done
    else
      for _ in "${IPS[@]}"; do HOSTS+=(""); done
    fi

    # In fallback mode, keep the old checklist UI so the user can pick a subset
    local -a items=()
    for i in "${!IPS[@]}"; do
      local ip="${IPS[$i]}"
      local h="${HOSTS[$i]:-<unknown>}"
      local label
      printf -v label "%-15s %-32s" "$ip" "$h"
      items+=( "$ip" "$label" "on" )
    done

    local selection
    selection="$(dlg --separate-output \
                     --backtitle "$BACKTITLE_C" \
                     --title "Select switches to onboard" \
                     --checklist "These switches previously passed validation.\nSelect which ones you want to enable Meraki connect on.\nUse SPACE to toggle, ENTER when done." \
                     22 100 14 \
                     "${items[@]}")" || return 1

    selection="$(trim "$selection")"
    if [[ -z "$selection" ]]; then
      dlg --backtitle "$BACKTITLE_C" \
          --title "No switches selected" \
          --msgbox "No switches were selected for Meraki connect onboarding.\n\nNothing to do." 10 70
      return 1
    fi

    mapfile -t IPS <<<"$selection"
  fi







  # ---------- reuse / create runs/migration structure ----------
  local RUN_ROOT="$SCRIPT_DIR/runs/migration"
  mkdir -p "$RUN_ROOT"

  local RUN_DIR=""
  if [[ -n "${MIGRATION_RUN_DIR:-}" && -d "${MIGRATION_RUN_DIR:-}" ]]; then
    RUN_DIR="$MIGRATION_RUN_DIR"
  elif [[ -f "$RUN_ROOT/latest.env" ]]; then
    # shellcheck disable=SC1090
    source "$RUN_ROOT/latest.env" || true
    if [[ -n "${MIGRATION_RUN_DIR:-}" && -d "${MIGRATION_RUN_DIR:-}" ]]; then
      RUN_DIR="$MIGRATION_RUN_DIR"
    fi
  fi

  if [[ -z "$RUN_DIR" ]]; then
    local RUN_ID="run-$(date -u +%Y%m%d%H%M%S)"
    RUN_DIR="$RUN_ROOT/$RUN_ID"
    mkdir -p "$RUN_DIR"
    local SUMMARY_CSV_PLACEHOLDER="$RUN_DIR/summary.csv"
    touch "$SUMMARY_CSV_PLACEHOLDER"
    export MIGRATION_RUN_ID="$RUN_ID"
    export MIGRATION_RUN_DIR="$RUN_DIR"
    export MIGRATION_SUMMARY="$SUMMARY_CSV_PLACEHOLDER"
    {
      printf 'export MIGRATION_RUN_ID=%q\n' "$MIGRATION_RUN_ID"
      printf 'export MIGRATION_RUN_DIR=%q\n' "$MIGRATION_RUN_DIR"
      printf 'export MIGRATION_SUMMARY=%q\n' "$MIGRATION_SUMMARY"
    } >"$RUN_ROOT/latest.env"
    ln -sfn "$RUN_DIR" "$RUN_ROOT/latest"
  fi

  mkdir -p "$RUN_DIR/devlogs"

  local SUMMARY_CSV="$RUN_DIR/meraki_connect_summary.csv"
  echo "ip,hostname,service_enabled,config_fetch_ok,primary_tunnel,secondary_tunnel,registered,cloud_id,ready,notes" > "$SUMMARY_CSV"

  # ---------- split-screen UI ----------
  VALIDATE_STATUS_FILE="$RUN_DIR/meraki_connect_ui.status"
  : >"$VALIDATE_STATUS_FILE"
  validate_ui_start
  validate_ui_status "Running 'service meraki connect' and 'show meraki connect' on selected switches…"

  local total=${#IPS[@]}

  local have_sshpass=0
  if command -v sshpass >/dev/null 2>&1 && [[ -n "$SSH_PASS" ]]; then
    have_sshpass=1
  fi

  # ---------- per-switch worker ----------
  _onboard_one_switch_meraki() {
    local ip="$1" host="$2"

    local ping_ok="no"
    local svc_enabled="no"
    local fetch_ok="no"
    local primary="down"
    local secondary="down"
    local registered="no"
    local cloud_id=""

    local -a reasons=()

    local ping_log="$RUN_DIR/devlogs/${ip}.meraki_connect.ping.log"
    local ssh_log_tmp="$RUN_DIR/devlogs/${ip}.meraki_connect.tmp"
    local ssh_log="$RUN_DIR/devlogs/${ip}.meraki_connect.log"

    validate_ui_status "[$ip] Pinging (3 probes)…"
    if ping -c 3 -W 2 "$ip" >"$ping_log" 2>&1; then
      ping_ok="yes"
      validate_ui_status "[$ip] Ping OK; enabling Meraki connect via SSH…"
    else
      ping_ok="no"
      reasons+=( "ping_failed" )
      validate_ui_status "[$ip] Ping FAILED."
    fi

    if [[ "$ping_ok" == "yes" ]]; then
      local ssh_cmd
      if (( have_sshpass )); then
        ssh_cmd=(sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                 -o ConnectTimeout=30 -o BatchMode=no -tt "${SSH_USER}@${ip}")
      else
        ssh_cmd=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                 -o ConnectTimeout=30 -tt "${SSH_USER}@${ip}")
      fi

      # First: enable service in global config + immediate show
      {
        printf '\r\nterminal length 0\r\nterminal width 511\r\n'
        printf 'configure terminal\r\n'
        printf 'service meraki connect\r\n'
        printf 'end\r\n'
        printf 'show meraki connect\r\n'
        printf 'exit\r\n'
      } | "${ssh_cmd[@]}" >"$ssh_log_tmp" 2>&1 || true

      tr -d '\r' <"$ssh_log_tmp" >"$ssh_log"
      rm -f "$ssh_log_tmp" 2>/dev/null || true

      # hostname from prompt if possible
      local h_probe
      h_probe="$(awk 'match($0,/^([[:alnum:]_.:-]+)[>#][[:space:]]*$/,m){print m[1]; exit}' "$ssh_log")"
      if [[ -n "$h_probe" ]]; then
        host="$h_probe"
      fi

      # Check that service is enabled (from the first session)
      if grep -qi 'Service[[:space:]]\+meraki[[:space:]]\+connect:[[:space:]]*enable' "$ssh_log"; then
        svc_enabled="yes"
      else
        reasons+=( "service_not_enabled" )
      fi

      # Now: up to 3 attempts to see tunnels up / registered / cloud ID
      local attempt state_log
      for attempt in 1 2 3; do
        if (( attempt == 1 )); then
          state_log="$ssh_log"
        else
          state_log="$RUN_DIR/devlogs/${ip}.meraki_connect.state${attempt}.log"
          validate_ui_status "[$ip] Meraki connect not fully up yet (attempt $((attempt-1))/3); waiting 15s then re-checking…"
          sleep 15
          {
            printf '\r\nterminal length 0\r\nterminal width 511\r\n'
            printf 'show meraki connect\r\n'
            printf 'exit\r\n'
          } | "${ssh_cmd[@]}" >"$ssh_log_tmp" 2>&1 || true
          tr -d '\r' <"$ssh_log_tmp" >"$state_log"
          rm -f "$ssh_log_tmp" 2>/dev/null || true
        fi

        # Reset values before parsing this attempt
        fetch_ok="no"
        primary="down"
        secondary="down"
        registered="no"
        cloud_id=""

        # Fetch State line (Config fetch succeeded)
        local fetch_line
        fetch_line="$(awk -F':' '/Fetch State/ {print $2; exit}' "$state_log" 2>/dev/null || true)"
        fetch_line="$(echo "$fetch_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"
        if [[ "$fetch_line" == *"succeeded"* ]]; then
          fetch_ok="yes"
        fi

        # Tunnel state: only in "Meraki Tunnel State" section of *this* log
        local primary_state secondary_state
        primary_state="$(awk '
          /Meraki Tunnel State/ {ctx=1; next}
          ctx && /Meraki Tunnel Interface/ {ctx=0; exit}
          ctx && /Primary:/ {sub(/.*:/,""); gsub(/^[ \t]+/,""); print; exit}
        ' "$state_log" 2>/dev/null || true)"
        secondary_state="$(awk '
          /Meraki Tunnel State/ {ctx=1; next}
          ctx && /Meraki Tunnel Interface/ {ctx=0; exit}
          ctx && /Secondary:/ {sub(/.*:/,""); gsub(/^[ \t]+/,""); print; exit}
        ' "$state_log" 2>/dev/null || true)"

        primary_state="$(echo "$primary_state" | sed -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"
        secondary_state="$(echo "$secondary_state" | sed -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"

        [[ "$primary_state" == "up" ]] && primary="up"
        [[ "$secondary_state" == "up" ]] && secondary="up"

        # Device Registration section
        local reg_status
        reg_status="$(awk '
          /Meraki Device Registration/ {ctx=1; next}
          ctx && /^Meraki/ {ctx=0; exit}
          ctx && /Status:/ {sub(/.*:/,""); gsub(/^[ \t]+/,""); print; exit}
        ' "$state_log" 2>/dev/null || true)"
        reg_status="$(echo "$reg_status" | sed -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"

        [[ "$reg_status" == "registered" ]] && registered="yes"

        cloud_id="$(awk '
          /Meraki Device Registration/ {ctx=1; next}
          ctx && /^Meraki/ {ctx=0; exit}
          ctx && /Cloud ID:/ {sub(/.*:/,""); gsub(/^[ \t]+/,""); print; exit}
        ' "$state_log" 2>/dev/null || true)"
        cloud_id="$(echo "$cloud_id" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

        # If everything critical is now good, we can stop retrying
        if [[ "$fetch_ok" == "yes" && "$primary" == "up" && "$secondary" == "up" && "$registered" == "yes" && -n "$cloud_id" ]]; then
          break
        fi
      done

      # After all attempts, record missing pieces as reasons
      [[ "$fetch_ok" != "yes" ]]      && reasons+=( "config_fetch_not_succeeded" )
      [[ "$primary" != "up" ]]        && reasons+=( "primary_tunnel_not_up" )
      [[ "$secondary" != "up" ]]      && reasons+=( "secondary_tunnel_not_up" )
      [[ "$registered" != "yes" ]]    && reasons+=( "not_registered" )
      [[ -z "$cloud_id" ]]            && reasons+=( "cloud_id_missing" )
    fi

    local ready="yes"
    if [[ "$ping_ok" != "yes" ]]; then ready="no"; fi
    if [[ "$svc_enabled" != "yes" ]]; then ready="no"; fi
    if [[ "$fetch_ok" != "yes" ]]; then ready="no"; fi
    if [[ "$primary" != "up" ]]; then ready="no"; fi
    if [[ "$secondary" != "up" ]]; then ready="no"; fi
    if [[ "$registered" != "yes" ]]; then ready="no"; fi
    if [[ -z "$cloud_id" ]]; then ready="no"; fi

    local notes=""
    if ((${#reasons[@]})); then
      notes="$(IFS=';'; printf '%s' "${reasons[*]}")"
    fi

    if [[ "$ready" == "yes" ]]; then
      validate_ui_status "[$ip] Meraki connect READY (tunnels up, registered, Cloud ID: ${cloud_id})."
    else
      validate_ui_status "[$ip] Meraki connect NOT ready: ${notes:-see logs}."
    fi

    local csv_file="$RUN_DIR/devlogs/meraki_connect_${ip//./_}.line"
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
      "$ip" "${host:-$ip}" \
      "$svc_enabled" "$fetch_ok" "$primary" "$secondary" \
      "$registered" "$cloud_id" "$ready" "$notes" >"$csv_file"
  }

  # ---------- launch workers in parallel (max 10 at a time) ----------
  local max_parallel=10
  local ACTIVE=0 DONE=0

  validate_ui_gauge 1 "Starting Meraki connect onboarding… (up to ${max_parallel} in parallel)"

  for i in "${!IPS[@]}"; do
    local ip="${IPS[$i]}"
    local host="${HOSTS[$i]:-$ip}"

    _onboard_one_switch_meraki "$ip" "$host" &

    ((ACTIVE++))
    if (( ACTIVE >= max_parallel )); then
      if wait -n 2>/dev/null; then :; fi
      ((DONE++))
      validate_ui_gauge $(( 100 * DONE / total )) "Completed $DONE / $total…"
      ((ACTIVE--))
    fi
  done

  while (( DONE < total )); do
    if wait -n 2>/dev/null; then :; fi
    ((DONE++))
    validate_ui_gauge $(( 100 * DONE / total )) "Completed $DONE / $total…"
  done

  # ---------- assemble summary CSV ----------
  for ip in "${IPS[@]}"; do
    local line_file="$RUN_DIR/devlogs/meraki_connect_${ip//./_}.line"
    [[ -f "$line_file" ]] && cat "$line_file" >>"$SUMMARY_CSV"
  done

  validate_ui_gauge 100 "Meraki connect onboarding complete."
  validate_ui_stop

  # ---------- build JSON of ready Cloud IDs + summary text ----------
  local -a READY_IPS NOT_READY_IPS
  local CLOUD_JSON="$RUN_DIR/meraki_cloud_ids.json"
  local summary="$RUN_DIR/meraki_connect_summary.txt"

  {
    echo "Meraki connect onboarding summary"
    echo "================================"
    echo
    echo "Run directory:"
    echo "  $RUN_DIR"
    echo
    echo "Switch Meraki connect state:"
    echo
    printf "%-16s %-22s %-8s %-8s %-8s %-10s %-12s %-18s\n" \
      "IP" "Hostname" "Svc" "Fetch" "Prim" "Sec" "Reg" "Cloud ID"
    printf "%-16s %-22s %-8s %-8s %-8s %-10s %-12s %-18s\n" \
      "----------------" "----------------------" "----" "----" "----" "--------" "--------" "------------------"

    local first=1
    local ip hostname svc fetch primary secondary reg cloud ready notes

    while IFS=, read -r ip hostname svc fetch primary secondary reg cloud ready notes; do
      if (( first )); then first=0; continue; fi

      ip="${ip%\"}";        ip="${ip#\"}"
      hostname="${hostname%\"}"; hostname="${hostname#\"}"
      cloud="${cloud%\"}"; cloud="${cloud#\"}"
      ready="${ready%\"}"; ready="${ready#\"}"

      printf "%-16s %-22s %-8s %-8s %-8s %-10s %-12s %-18s\n" \
        "$ip" "${hostname:-<unknown>}" \
        "$svc" "$fetch" "$primary" "$secondary" "$reg" \
        "${cloud:-<none>}"

      if [[ "$ready" == "yes" ]]; then
        READY_IPS+=( "$ip" )
      else
        NOT_READY_IPS+=( "$ip" )
      fi
    done <"$SUMMARY_CSV"

    echo
    if ((${#READY_IPS[@]})); then
      echo "Switches that are READY for Dashboard onboarding (tunnels up, registered, Cloud ID present):"
      for ip in "${READY_IPS[@]}"; do
        echo "  - $ip"
      done
      echo
    fi

    if ((${#NOT_READY_IPS[@]})); then
      echo "Switches that are NOT yet ready (check individual logs under devlogs/):"
      for ip in "${NOT_READY_IPS[@]}"; do
        echo "  - $ip"
      done
      echo
    fi

    echo "Cloud IDs for READY switches are also exported to:"
    echo "  $CLOUD_JSON"
    echo

    if [[ -s "$MAP_JSON" ]]; then
      echo "Switch-to-network mapping file (updated with cloudId where available):"
      echo "  $MAP_JSON"
      echo
    fi
  } >"$summary"

  {
    echo '['
    local first=1
    local header=1
    local ip hostname svc fetch primary secondary reg cloud ready notes

    while IFS=, read -r ip hostname svc fetch primary secondary reg cloud ready notes; do
      if (( header )); then header=0; continue; fi

      ip="${ip%\"}";        ip="${ip#\"}"
      hostname="${hostname%\"}"; hostname="${hostname#\"}"
      cloud="${cloud%\"}"; cloud="${cloud#\"}"
      ready="${ready%\"}"; ready="${ready#\"}"

      if [[ "$ready" != "yes" || -z "$cloud" ]]; then
        continue
      fi

      if (( first )); then
        first=0
      else
        echo ','
      fi

      printf '  {"ip": "%s", "hostname": "%s", "cloudId": "%s"}' \
        "$ip" "${hostname:-}" "$cloud"
    done <"$SUMMARY_CSV"
    echo
    echo ']'
  } >"$CLOUD_JSON"

  ln -sfn "$CLOUD_JSON" "$RUN_ROOT/latest_cloud_ids.json"

  # ---------- inject cloudId into meraki_switch_network_map.json, if present ----------
if [[ -s "$MAP_JSON" && -s "$CLOUD_JSON" ]]; then
  validate_ui_status "Injecting Cloud IDs into $MAP_JSON (if any)…"
  local tmp_map="$RUN_DIR/meraki_switch_network_map.with_cloud.tmp"

  # Read both files at once:
  # .[0] = switch map JSON
  # .[1] = cloud IDs JSON
  if jq -s '
    . as [$map, $cloud]
    | $map
    | map(
        . as $d
        | ($cloud[] | select(.ip == $d.ip) | .cloudId) as $cid
        | if $cid then . + {cloudId:$cid} else . end
      )
  ' "$MAP_JSON" "$CLOUD_JSON" >"$tmp_map" 2>"$RUN_DIR/devlogs/meraki_connect_jq.log"; then
    # Use "command mv" to bypass any shell alias (mv -i etc.)
    command mv "$tmp_map" "$MAP_JSON"
  else
    validate_ui_status "Failed to inject Cloud IDs into $MAP_JSON (see devlogs/meraki_connect_jq.log)."
    rm -f "$tmp_map" 2>/dev/null || true
  fi
fi

  dlg --backtitle "$BACKTITLE_C" \
      --title "Meraki connect onboarding summary" \
      --textbox "$summary" 24 100 || true

    # Restore strict mode for the rest of the script
  set -e
  set -u
  set -o pipefail

  return 0
}

meraki_claim_cloud_monitored_switches() {
  local BACKTITLE_CL="Meraki Dashboard claim – Cloud-Monitored Catalyst switches"

  local MAP_JSON="$SCRIPT_DIR/meraki_switch_network_map.json"
  local DISC_ENV="$SCRIPT_DIR/meraki_discovery.env"
  local API_BASE="https://api.meraki.com/api/v1"

  need curl || return 1
  need jq   || return 1
  need base64 || return 1

  if [[ ! -s "$MAP_JSON" ]]; then
    dlg --backtitle "$BACKTITLE_CL" \
        --title "No mapping file" \
        --msgbox "Switch→network mapping file not found or empty:\n  $MAP_JSON\n\nRun the Meraki mapping/onboarding steps first." 12 80
    return 1
  fi

  if [[ ! -f "$DISC_ENV" ]]; then
    dlg --backtitle "$BACKTITLE_CL" \
        --title "ENV not found" \
        --msgbox "Discovery env file with MERAKI_API_KEY not found:\n  $DISC_ENV" 10 80
    return 1
  fi

  # ----- load API key + SSH creds -----
  set +H
  # shellcheck disable=SC1090
  source "$DISC_ENV"
  : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $DISC_ENV}"
  local SSH_USER="${SSH_USERNAME:-}"
  local SSH_PASS="${SSH_PASSWORD:-}"
  local ENABLE_PASS="${ENABLE_PASSWORD:-}"

  if [[ -z "$SSH_USER" || -z "$SSH_PASS" || -z "$ENABLE_PASS" ]]; then
    dlg --backtitle "$BACKTITLE_CL" \
        --title "Missing credentials" \
        --msgbox "SSH_USERNAME, SSH_PASSWORD, or ENABLE_PASSWORD is missing in:\n  $DISC_ENV\n\nThese are required to claim switches in MONITORED mode." 14 80
    return 1
  fi

  # ----- build list of devices (base64 rows) from MAP_JSON -----
  # Each row (after base64-decode) is:
  #   [ ip, hostname, networkId, networkName, cloudId, networkAddress ]
  local -a DEV_ROWS_B64=()
  mapfile -t DEV_ROWS_B64 < <(
    jq -r '
      .[]
      | select(.cloudId != null and .cloudId != "" and .networkId != null and .networkId != "")
      | [ .ip,
          (.hostname // ""),
          .networkId,
          (.networkName // ""),
          .cloudId,
          (.networkAddress // "")
        ]
      | @base64
    ' "$MAP_JSON"
  )

  if (( ${#DEV_ROWS_B64[@]} == 0 )); then
    dlg --backtitle "$BACKTITLE_CL" \
        --title "Nothing to claim" \
        --msgbox "No switches in $MAP_JSON have both a Meraki Cloud ID and a target networkId.\n\nRun Meraki connect + mapping again before claiming." 13 80
    return 1
  fi

  # helper: extract field N from a base64-encoded JSON array row
  _row_field() {
    local row_b64="$1" idx="$2"
    echo "$row_b64" | base64 -d 2>/dev/null | jq -r ".[$idx]"
  }

  # ----- show pre-claim summary -----
  local tmp_summary
  tmp_summary="$(mktemp)"
  {
    echo "Cloud-Monitored Catalyst switches ready to be claimed"
    echo "====================================================="
    echo
    printf "%-16s %-22s %-18s %-12s %-18s %s\n" \
      "IP" "Hostname" "Network" "Net ID" "Cloud ID" "Address"
    printf "%-16s %-22s %-18s %-12s %-18s %s\n" \
      "----------------" "----------------------" "------------------" "------------" "------------------" "------------------------------"

    local row ip host nid nname cid addr
    for row in "${DEV_ROWS_B64[@]}"; do
      ip="$(_row_field "$row" 0)"
      host="$(_row_field "$row" 1)"
      nid="$(_row_field "$row" 2)"
      nname="$(_row_field "$row" 3)"
      cid="$(_row_field "$row" 4)"
      addr="$(_row_field "$row" 5)"

      printf "%-16s %-22s %-18s %-12s %-18s %s\n" \
        "$ip" "${host:-<unknown>}" "${nname:-<none>}" "$nid" "$cid" "${addr:-<none>}"
    done
  } >"$tmp_summary"

  dlg --backtitle "$BACKTITLE_CL" \
      --title "Switches to claim" \
      --textbox "$tmp_summary" 22 110 || true

  rm -f "$tmp_summary" 2>/dev/null || true

  # ----- pick / reuse run directory for logs -----
  local RUN_ROOT="$SCRIPT_DIR/runs/migration"
  mkdir -p "$RUN_ROOT"
  local RUN_DIR=""
  if [[ -n "${MIGRATION_RUN_DIR:-}" && -d "${MIGRATION_RUN_DIR:-}" ]]; then
    RUN_DIR="$MIGRATION_RUN_DIR"
  elif [[ -f "$RUN_ROOT/latest.env" ]]; then
    # shellcheck disable=SC1090
    source "$RUN_ROOT/latest.env" || true
    if [[ -n "${MIGRATION_RUN_DIR:-}" && -d "${MIGRATION_RUN_DIR:-}" ]]; then
      RUN_DIR="$MIGRATION_RUN_DIR"
    fi
  fi
  if [[ -z "$RUN_DIR" ]]; then
    RUN_DIR="$RUN_ROOT/claim-$(date -u +%Y%m%d%H%M%S)"
    mkdir -p "$RUN_DIR"
  fi

  local CLAIM_LOG="$RUN_DIR/meraki_claim.log"
  : >"$CLAIM_LOG"
  ln -sfn "$CLAIM_LOG" "$SCRIPT_DIR/meraki_claim.log"

  # ----- temp dir for API -----
  local TMPDIR
  TMPDIR="$(mktemp -d)"

  # clean up temp on function exit
  trap '[[ -d "$TMPDIR" ]] && rm -rf "$TMPDIR"' RETURN

  # ----- tiny Meraki API helper (Bearer → X-Cisco fallback, 429 handling) -----
  _claim_call() {
    local method="$1" path="$2" body="$3"
    local hdr="$TMPDIR/hdr.$$" bodyf="$TMPDIR/body.$$"
    local code mode

    for mode in bearer x-cisco; do
      while :; do
        if [[ "$mode" == "bearer" ]]; then
          code="$(curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' \
            -H "Accept: application/json" \
            -H "Authorization: Bearer $MERAKI_API_KEY" \
            -H "Content-Type: application/json" \
            -X "$method" "$API_BASE$path" \
            --data "$body")"
        else
          code="$(curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' \
            -H "Accept: application/json" \
            -H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY" \
            -H "Content-Type: application/json" \
            -X "$method" "$API_BASE$path" \
            --data "$body")"
        fi

        if [[ "$code" == "429" ]]; then
          local wait
          wait="$(awk '/^Retry-After:/ {print $2}' "$hdr" | tr -d '\r')"
          [[ -z "$wait" ]] && wait=1
          sleep "$wait"
          continue
        fi
        break
      done

      if [[ "$code" == "401" && "$mode" == "bearer" ]]; then
        continue  # try X-Cisco next
      fi
      break
    done

    echo "$code" >"$TMPDIR/code.$$"
    cp "$hdr" "$TMPDIR/last_headers" 2>/dev/null || true
    cp "$bodyf" "$TMPDIR/last_body"   2>/dev/null || true

    if ! [[ "$code" =~ ^20[01]$ ]]; then
      return 1
    fi
    return 0
  }

  # ----- helper: log + push into dialog tailbox -----
  claim_status() {
    local msg="$1"
    printf '%s\n' "$msg" | tee -a "$CLAIM_LOG" >/dev/null
    validate_ui_status "$msg"
  }

  # ----- start claim UI (tailbox + gauge) -----
  local CLAIM_STATUS_FILE="$RUN_DIR/meraki_claim_ui.status"
  VALIDATE_STATUS_FILE="$CLAIM_STATUS_FILE"
  : >"$VALIDATE_STATUS_FILE"
  validate_ui_start "Meraki Dashboard claim – monitored mode"

  local total=${#DEV_ROWS_B64[@]}
  local DONE=0 any_fail=0

  validate_ui_gauge 1 "Starting Meraki claim…"

  local row ip host nid nname cid addr path
  for row in "${DEV_ROWS_B64[@]}"; do
    ip="$(_row_field "$row" 0)"
    host="$(_row_field "$row" 1)"
    nid="$(_row_field "$row" 2)"
    nname="$(_row_field "$row" 3)"
    cid="$(_row_field "$row" 4)"
    addr="$(_row_field "$row" 5)"

    host="$(echo "${host:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    addr="$(echo "${addr:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

    claim_status "[$ip] Claiming Cloud ID $cid into network ${nname:-<unknown>} ($nid)…"

    path="/networks/$nid/devices/claim"

    # body for /networks/{id}/devices/claim – one device at a time, MONITORED mode
    local claim_body
    claim_body="$(jq -n --arg cid "$cid" \
                       --arg u "$SSH_USER" \
                       --arg p "$SSH_PASS" \
                       --arg e "$ENABLE_PASS" '
      {
        serials:       [$cid],
        addAtomically: true,
        detailsByDevice: [
          {
            serial: $cid,
            details: [
              {name:"device mode",      value:"monitored"},
              {name:"username",        value:$u},
              {name:"password",        value:$p},
              {name:"enable password", value:$e}
            ]
          }
        ]
      }')" || true

    if _claim_call POST "$path" "$claim_body"; then
      claim_status "  -> Claim SUCCESS for $cid"
    else
      any_fail=1
      local code; code="$(cat "$TMPDIR/code.$$" 2>/dev/null || echo "?")"
      claim_status "  -> Claim FAILED for $cid (HTTP $code) on path $path. See meraki_claim.log for details."
      sed -n '1,80p' "$TMPDIR/last_body" >>"$CLAIM_LOG" 2>/dev/null || true
      ((DONE++))
      validate_ui_gauge $(( 100 * DONE / total )) "Claimed $DONE / $total (some failures)…"
      continue
    fi

    # Build payload to set device name (hostname) and physical address
        # Build payload to set physical address only
    # (Dashboard will learn hostname automatically from the device)
    local dev_body=""
    if [[ -n "$addr" ]]; then
      dev_body="$(jq -n --arg a "$addr" \
        '{address:$a, updateLocation:true, moveMapMarker:true}')" || true
      claim_status "  -> Updating Dashboard device address to: $addr"
    fi
        if [[ -n "$dev_body" ]]; then
      local update_ok=0
      local tries=0
      local code=""

      # Retry a few times if we get 404 (device record not visible yet)
      while (( tries < 5 )); do
        if _claim_call PUT "/devices/$cid" "$dev_body"; then
          update_ok=1
          break
        fi

        code="$(cat "$TMPDIR/code.$$" 2>/dev/null || echo "?")"

        # 404 is likely "device not visible yet" – wait and retry
        if [[ "$code" == "404" ]]; then
          claim_status "     Device address update got 404 for $cid – waiting 5s and retrying ($((tries+1))/5)…"
          sleep 5
          ((tries++))
          continue
        fi

        # Other errors probably won't be fixed by retrying
        break
      done

      if (( update_ok )); then
        claim_status "     Device address update SUCCESS"
      else
        any_fail=1
        claim_status "     Device address update FAILED for $cid (HTTP ${code:-?})."
        sed -n '1,80p' "$TMPDIR/last_body" >>"$CLAIM_LOG" 2>/dev/null || true
      fi
    fi

    ((DONE++))
    validate_ui_gauge $(( 100 * DONE / total )) "Claimed $DONE / $total switches…"
  done

  validate_ui_gauge 100 "Meraki claim complete."
  validate_ui_stop

  if (( any_fail == 0 )); then
    dlg --backtitle "$BACKTITLE_CL" \
        --title "Meraki claim complete" \
        --textbox "$CLAIM_LOG" 24 100 || true
  else
    dlg --backtitle "$BACKTITLE_CL" \
        --title "Meraki claim complete (with errors)" \
        --textbox "$CLAIM_LOG" 24 100 || true
  fi

  return "$any_fail"
}



# ------------------------------------------------------------
# Wrapper: run validation, mapping, firewall info, then onboard
# ------------------------------------------------------------
run_validate_map_and_onboard() {
  (
    set +e
    set +u
    set +o pipefail
    validate_switches_before_migration
  )
  local rc=$?

  if (( rc != 0 )); then
    echo "Validation failed – aborting mapping/onboarding. (rc=$rc)" >&2
    return "$rc"
  fi

  # tiny pause so dialogs clear nicely
  sleep 1

  meraki_switch_network_mapper "$@"         || return $?
  #meraki_firewall_info_helper "$@"          || true
  onboard_meraki_connect_switches "$@"      || return $?
  meraki_claim_cloud_monitored_switches "$@" || return $?
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  cmd="${1:-all}"
  shift || true

  case "$cmd" in
    firewall)
      meraki_firewall_info_helper "$@"
      ;;
    onboard)
      onboard_meraki_connect_switches "$@"
      ;;
    claim)
      meraki_claim_cloud_monitored_switches "$@"
      ;;
    validate-and-map)
      run_validate_and_map "$@"
      ;;
    all|*)
      run_validate_map_and_onboard "$@"
      ;;
  esac
fi
