#!/usr/bin/env bash
# cli_update.sh — run ad-hoc CLI commands on switches and view outputs.
#
# Features:
# - Uses SSH/enable creds from meraki_discovery.env when available.
# - Lets you target discovered switches (discovery_results.json) OR manual IPs.
# - For discovered targets, you can select a subset via checklist.
# - Detects prompt (">" vs "#"); only sends "enable" when needed.
# - Commands run in ENABLE mode; add 'conf t' as a command yourself if needed.
# - Automatically sends "terminal length 0" and "terminal width 511" (hidden from UI).
# - Stores run under runs/cli_runs/cli-<timestamp>/IP.out
# - ui.status tail log + progress gauge while running commands.
# - Viewer supports "Next switch" carousel between switches.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
BACKTITLE="CMDS-Deployment Server"
TITLE="CLI Update Tool"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need dialog
need ssh
need expect
need jq

BASE_ENV="$SCRIPT_DIR/meraki_discovery.env"
DISC_JSON="$SCRIPT_DIR/discovery_results.json"

# runs/cli_runs/cli-YYYYmmddHHMMSS
RUNS_ROOT="$SCRIPT_DIR/runs/cli_runs"
RUN_ID="cli-$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="$RUNS_ROOT/$RUN_ID"
mkdir -p "$RUN_DIR"

# Activity log (also used as the tailbox source)
DEV_LOG="$RUN_DIR/ui.status"
: >"$DEV_LOG"

# --- dialog wrapper ---------------------------------------------------------
dlg(){
  local tmp; tmp="$(mktemp)"
  dialog "$@" 2>"$tmp"
  local rc=$?
  DOUT=""
  [[ -s "$tmp" ]] && DOUT="$(<"$tmp")"
  rm -f "$tmp"
  return $rc
}

trim(){ printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }

# --- UI: tailbox + gauge ----------------------------------------------------
DIALOG_AVAILABLE=0
if command -v dialog >/dev/null 2>&1; then
  DIALOG_AVAILABLE=1
fi

STATUS_FILE="$DEV_LOG"  # tailbox watches this
PROG_PIPE=""
PROG_FD=""
DIALOG_PID=""

TAIL_H=; TAIL_W=; GAUGE_H=; GAUGE_W=; GAUGE_ROW=; GAUGE_COL=

ui_calc_layout() {
  local lines cols
  if ! read -r lines cols < <(stty size 2>/dev/null); then
    lines=24 cols=80
  fi

  if (( lines < 18 || cols < 70 )); then
    DIALOG_AVAILABLE=0
    return
  fi

  # Taller window for logs
  TAIL_H=$((lines - 8)); (( TAIL_H < 10 )) && TAIL_H=10
  TAIL_W=$((cols - 4));   (( TAIL_W < 68 )) && TAIL_W=68

  GAUGE_H=7
  GAUGE_W=$TAIL_W
  GAUGE_ROW=$((TAIL_H + 3))
  GAUGE_COL=2
}

ui_fd_open() {
  [[ -n "${PROG_FD:-}" ]] || return 1
  if [[ -e "/proc/$$/fd/$PROG_FD" ]]; then
    return 0
  fi
  { : >&"$PROG_FD"; } 2>/dev/null || return 1
  return 0
}

ui_start() {
  ui_calc_layout
  if (( ! DIALOG_AVAILABLE )); then
    echo "[info] CLI Update UI in plain mode (terminal too small or dialog missing)." >>"$DEV_LOG"
    return
  fi

  PROG_PIPE="$(mktemp -u)"
  mkfifo "$PROG_PIPE"
  exec {PROG_FD}<>"$PROG_PIPE"

  (
    dialog --no-shadow \
           --backtitle "$BACKTITLE" \
           --begin 2 2 --title "CLI Activity" \
           --tailboxbg "$STATUS_FILE" "$TAIL_H" "$TAIL_W" \
           --and-widget \
           --begin "$GAUGE_ROW" "$GAUGE_COL" --title "CLI Pack Progress" \
           --gauge "Starting…" "$GAUGE_H" "$GAUGE_W" 0 <"$PROG_PIPE"
  ) & DIALOG_PID=$!

  sleep 0.15
}

ui_status() {
  local msg="$1"
  printf '%s %s\n' "$(date '+%F %T')" "$msg" >>"$STATUS_FILE"
  if (( ! DIALOG_AVAILABLE )); then
    echo "$msg"
  fi
}

ui_gauge() {
  local pct="$1"; shift || true
  local msg="${*:-Working…}"
  printf '%s [gauge %s%%] %s\n' "$(date '+%F %T')" "$pct" "$msg" >>"$STATUS_FILE"

  if (( DIALOG_AVAILABLE )) && ui_fd_open; then
    { printf 'XXX\n%s\n%s\nXXX\n' "$pct" "$msg" >&"$PROG_FD"; } 2>/dev/null || true
  else
    echo "[progress] $pct% - $msg"
  fi
}

ui_stop() {
  if (( DIALOG_AVAILABLE )); then
    if ui_fd_open; then
      { printf 'XXX\n100\nDone.\nXXX\n' >&"$PROG_FD"; } 2>/dev/null || true
    fi
    if [[ -n "${PROG_FD:-}" ]]; then
      exec {PROG_FD}>&- 2>/dev/null || true
      PROG_FD=""
    fi
    [[ -n "$PROG_PIPE" ]] && rm -f "$PROG_PIPE" 2>/dev/null || true
    if [[ -n "${DIALOG_PID:-}" ]]; then
      kill "$DIALOG_PID" 2>/dev/null || true
      DIALOG_PID=""
    fi
  fi
}

cleanup(){
  ui_stop
  clear
}
trap cleanup EXIT

# --- 1) Load or prompt for SSH credentials / enable password ---------------
SSH_USERNAME=""
SSH_PASSWORD=""
ENABLE_PASSWORD=""

if [[ -f "$BASE_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$BASE_ENV" || true
  SSH_USERNAME="${SSH_USERNAME:-${SSH_USER:-}}"
  SSH_PASSWORD="${SSH_PASSWORD:-}"
  ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"
fi

while [[ -z "${SSH_USERNAME:-}" ]]; do
  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — SSH Username" \
      --inputbox "Enter SSH username for the switches:" 8 70
  [[ $? -eq 0 ]] || exit 1
  SSH_USERNAME="$(trim "${DOUT:-}")"
done

while [[ -z "${SSH_PASSWORD:-}" ]]; do
  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — SSH Password" \
      --insecure --passwordbox "Enter SSH password (masked):" 9 70
  [[ $? -eq 0 ]] || exit 1
  SSH_PASSWORD="$(trim "${DOUT:-}")"
done

while [[ -z "${ENABLE_PASSWORD:-}" ]]; do
  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — Enable Password" \
      --insecure --passwordbox \
"Enter the ENABLE password.

If the device prompt is '>', we will send:
  enable
  <this password>

If the device already lands at '#', we will NOT send enable." 11 72
  [[ $? -eq 0 ]] || exit 1
  ENABLE_PASSWORD="$(trim "${DOUT:-}")"
done

# --- 2) Target selection (discovered vs manual) -----------------------------
TARGET_IPS=()

prompt_manual_ips(){
  local example="# One IP per line. Lines starting with # are ignored.
192.168.1.10
192.168.1.11"
  local ips_raw
  while :; do
    local tmp_ips
    tmp_ips="$(mktemp)"
    printf '%s\n' "$example" >"$tmp_ips"
    dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — Manual IP list" \
        --editbox "$tmp_ips" 15 70
    local rc=$?
    rm -f "$tmp_ips"
    [[ $rc -eq 0 ]] || exit 1
    ips_raw="${DOUT:-}"

    TARGET_IPS=()
    while IFS= read -r line; do
      line="$(trim "$line")"
      [[ -z "$line" ]] && continue
      [[ "$line" == \#* ]] && continue
      TARGET_IPS+=("$line")
    done <<<"$ips_raw"

    if ((${#TARGET_IPS[@]} == 0)); then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "No IPs" \
             --msgbox "Please provide at least one IP address." 7 60
      continue
    fi
    break
  done
}

select_discovered_ips(){
  TARGET_IPS=()
  mapfile -t rows < <(jq -r '.[] | [.ip, (.hostname // "switch")] | @tsv' "$DISC_JSON" 2>/dev/null || true)
  ((${#rows[@]} > 0)) || return 1

  local MENU_ITEMS=()
  local ip host
  for row in "${rows[@]}"; do
    ip="${row%%$'\t'*}"
    host="${row#*$'\t'}"
    [[ -z "$ip" ]] && continue
    MENU_ITEMS+=("$ip" "$host" "on")
  done

  if ((${#MENU_ITEMS[@]} == 0)); then
    return 1
  fi

  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — Discovered Switches" \
      --checklist "Select one or more switches to run the CLI pack against:" \
      18 80 10 \
      "${MENU_ITEMS[@]}"
  local rc=$?
  [[ $rc -eq 0 ]] || return 1

  TARGET_IPS=()
  for tok in $DOUT; do
    tok="${tok%\"}"; tok="${tok#\"}"
    [[ -n "$tok" ]] && TARGET_IPS+=("$tok")
  done

  ((${#TARGET_IPS[@]} > 0)) || return 1
  return 0
}

have_disc_ips=0
if [[ -s "$DISC_JSON" ]]; then
  if jq -e '.[0].ip' "$DISC_JSON" >/dev/null 2>&1; then
    have_disc_ips=1
  fi
fi

if (( have_disc_ips )); then
  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — Target Source" \
      --menu "How do you want to provide targets?" 11 72 2 \
      disc   "Use discovered switches from discovery_results.json" \
      manual "Enter a manual IP list"
  rc=$?
  [[ $rc -eq 0 ]] || exit 1
  choice="${DOUT:-}"

  if [[ "$choice" == "disc" ]]; then
    if ! select_discovered_ips; then
      dialog --no-shadow --backtitle "$BACKTITLE" --title "No Targets Selected" \
             --msgbox "No discovered switches selected; please choose manual IP list." 8 70
      prompt_manual_ips
    fi
  else
    prompt_manual_ips
  fi
else
  prompt_manual_ips
fi

TOTAL=${#TARGET_IPS[@]}
(( TOTAL > 0 )) || { echo "No targets."; exit 1; }

# --- 3) CLI commands (comments; term hidden; remind about conf t) -----------
DEFAULT_CMDS="# Example CLI commands to run on each switch
# Lines starting with '#' are comments and will be ignored.
# Switches will be at ENABLE ('#') prompt. Use 'conf t' if required.
#
show run | sec aaa
show run | i ntp
show clock
-OR-
conf t
do show ntp status"

CLI_COMMANDS=""

while :; do
  tmp_cmd="$(mktemp)"
  if [[ -n "$CLI_COMMANDS" ]]; then
    printf '%s\n' "$CLI_COMMANDS" >"$tmp_cmd"
  else
    printf '%s\n' "$DEFAULT_CMDS" >"$tmp_cmd"
  fi

  dlg --no-shadow --backtitle "$BACKTITLE" --title "$TITLE — Commands to Run" \
      --editbox "$tmp_cmd" 18 80
  rc=$?
  rm -f "$tmp_cmd"
  [[ $rc -eq 0 ]] || exit 1
  CLI_COMMANDS="${DOUT:-}"

  # Require at least one non-comment, non-empty line
  if [[ -z "$(printf '%s\n' "$CLI_COMMANDS" | awk 'NF && $1 !~ /^#/')" ]]; then
    dialog --no-shadow --backtitle "$BACKTITLE" --title "No Commands" \
           --msgbox "Please enter at least one CLI command (non-comment)." 7 70
    continue
  fi
  break
done

# --- 4) Run CLI on each IP (using expect) -----------------------------------
declare -A STATUS_BY_IP=()

run_cli_for_ip(){
  local ip="$1"
  local outfile_raw="$RUN_DIR/${ip}.raw"
  local outfile="$RUN_DIR/${ip}.out"
  local rc status

  set +e
  HOST="$ip" USER="$SSH_USERNAME" PASS="$SSH_PASSWORD" ENPASS="$ENABLE_PASSWORD" \
  CMDS="$CLI_COMMANDS" \
  expect -f - <<'EXP' >"$outfile_raw" 2>&1
    log_user 1
    set host   $env(HOST)
    set user   $env(USER)
    set pass   $env(PASS)
    set enpass $env(ENPASS)
    set cmds   $env(CMDS)

    set timeout 15
    set prompt_re {[\r\n][^\r\n]*[>#] ?$}

    # SSH login
    spawn ssh -o LogLevel=ERROR \
              -o StrictHostKeyChecking=no \
              -o UserKnownHostsFile=/dev/null \
              -o ConnectTimeout=10 \
              -o PreferredAuthentications=password,keyboard-interactive \
              -o KbdInteractiveAuthentication=yes \
              -o PubkeyAuthentication=no \
              -o NumberOfPasswordPrompts=1 \
              -tt $user@$host

    set logged_in 0
    while {!$logged_in} {
      expect {
        -nocase -re {username:} { send -- "$user\r" }
        -nocase -re {password:} { send -- "$pass\r" }
        -re $prompt_re          { set logged_in 1 }
        "(yes/no)?"             { send -- "yes\r" }
        timeout                 { exit 20 }
        eof                     { exit 20 }
      }
    }

    # Find prompt char
    send -- "\r"
    expect -re {([>#])\s*$}
    set pchar $expect_out(1,string)

    set used_enable 0
    if {$pchar eq ">"} {
      if {$enpass ne ""} {
        set timeout 8
        send -- "enable\r"
        set done 0
        while {!$done} {
          expect {
            -nocase -re {password:} { send -- "$enpass\r" }
            -re {#\s*$}             { set used_enable 1; set done 1 }
            timeout                 { exit 21 }
            eof                     { exit 21 }
          }
        }
      }
    }

    # Normalize terminal (hidden from user)
    set timeout 15
    send -- "terminal length 0\r"
    expect -re $prompt_re
    send -- "terminal width 511\r"
    expect -re $prompt_re

    # Run user commands in enable mode
    set cmdlist [split $cmds "\n"]
    foreach c $cmdlist {
      set c_trim [string trim $c]
      if {$c_trim eq ""} { continue }
      if {[string index $c_trim 0] eq "#"} { continue }
      send -- "$c_trim\r"
      expect -re $prompt_re
    }

    send -- "exit\r"
    expect eof

    if {$used_enable} {
      exit 10
    } else {
      exit 0
    }
EXP
  rc=$?
  set -e

  # Clean transcript: strip CRs, the spawn line, and bare password prompts
  if [[ -s "$outfile_raw" ]]; then
    tr -d '\r' <"$outfile_raw" | \
      sed -e '1{/^spawn ssh /d;}' \
          -e '/password:$/d' >"$outfile" 2>/dev/null || cp "$outfile_raw" "$outfile"
  else
    : >"$outfile"
  fi
  rm -f "$outfile_raw"

  case "$rc" in
    0)  status="OK (priv=15, no enable)" ;;
    10) status="OK (priv=15 → enable)" ;;
    20) status="SSH/login failed" ;;
    21) status="Enable failed" ;;
    *)  status="Error (rc=$rc)" ;;
  esac

  STATUS_BY_IP["$ip"]="$status"
}

# Start UI and run the pack
ui_start
ui_status "CLI Update run: $RUN_ID"
ui_status "Targets: ${TARGET_IPS[*]}"
ui_gauge 1 "Initializing CLI pack…"

idx=0
for ip in "${TARGET_IPS[@]}"; do
  idx=$((idx + 1))
  ui_status "[$ip] Starting CLI pack ($idx/$TOTAL)…"
  run_cli_for_ip "$ip"
  ui_status "[$ip] Finished: ${STATUS_BY_IP[$ip]}"
  pct=$(( idx * 100 / TOTAL ))
  (( pct > 99 )) && pct=99
  ui_gauge "$pct" "Running CLI pack ($idx/$TOTAL)…"
done

ui_gauge 100 "CLI pack complete."
ui_status "CLI pack complete for ${TOTAL} switch(es)."
ui_stop

# --- 5) Results menu + carousel viewer --------------------------------------
show_output_carousel(){
  local start_ip="$1"; shift
  local ips=("$@")
  local total=${#ips[@]}
  [[ $total -eq 0 ]] && return 0

  local idx=0
  local i
  for i in "${!ips[@]}"; do
    [[ "${ips[$i]}" == "$start_ip" ]] && { idx=$i; break; }
  done

  while :; do
    local ip="${ips[$idx]}"
    local file="$RUN_DIR/${ip}.out"
    [[ -s "$file" ]] || echo "(no output captured for $ip)" >"$file"

    set +e
    dialog --no-shadow --backtitle "$BACKTITLE" \
           --title "Output for ${ip}" \
           --ok-label "Back to list" \
           --extra-button --extra-label "Next switch" \
           --cancel-label "Quit viewer" \
           --textbox "$file" 26 100
    local rc=$?
    set -e

    case "$rc" in
      0)  return 0 ;;                           # Back to results menu
      3)  idx=$(( (idx + 1) % total ));;        # Next switch in carousel
      1|255) return 0 ;;                        # Quit viewer
    esac
  done
}

while :; do
  MENU_ITEMS=()
  for ip in "${TARGET_IPS[@]}"; do
    MENU_ITEMS+=("$ip" "${STATUS_BY_IP[$ip]:-Done}")
  done

  dlg --no-shadow --backtitle "$BACKTITLE" \
      --title "CLI Results — $RUN_ID" \
      --menu "Select a switch to view its output.\nRun directory:\n  $RUN_DIR" \
      16 86 8 \
      "${MENU_ITEMS[@]}"
  rc=$?
  [[ $rc -ne 0 ]] && break

  sel_ip="${DOUT:-}"
  show_output_carousel "$sel_ip" "${TARGET_IPS[@]}"
done

exit 0