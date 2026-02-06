#!/usr/bin/env bash
# push_image.sh — single-switch image push + install (no policy checks)
# Flow:
#   1) Connect + show install summary (current version)
#   2) Select image from local images dir
#   3) HTTP copy -> flash:
#   4) install add file flash:<bin> activate commit prompt-level none
#   5) Wait for SSH disconnect (reboot) + wait for SSH return
#   6) Show install summary again (verify)

set -Eeuo pipefail
set +H

# -----------------------------
# Defaults (override via env)
# -----------------------------
IMAGES_DIR="${IMAGES_DIR:-/var/lib/tftpboot/images}"
HTTP_BASE_DEFAULT="${HTTP_BASE_DEFAULT:-}"
HTTP_CLIENT_SOURCE_IFACE="${HTTP_CLIENT_SOURCE_IFACE:-}"     # e.g. Vlan1
SSH_USERNAME="${SSH_USERNAME:-}"
SSH_PASSWORD="${SSH_PASSWORD:-}"                              # optional if using SSH_KEY_PATH
SSH_KEY_PATH="${SSH_KEY_PATH:-}"                              # optional
ENABLE_PASSWORD="${ENABLE_PASSWORD:-}"
TARGET_IP="${TARGET_IP:-}"

CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-8}"
WAIT_DOWN_SEC="${WAIT_DOWN_SEC:-900}"
WAIT_UP_SEC="${WAIT_UP_SEC:-2400}"
INSTALL_MAX_SECS="${INSTALL_MAX_SECS:-18000}"                 # 5h
COPY_MAX_SECS="${COPY_MAX_SECS:-7200}"                        # 2h
POLL_SEC="${POLL_SEC:-10}"

# -----------------------------
# Helpers
# -----------------------------
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
need awk; need sed; need timeout; need ssh; need ping; need stat
command -v sshpass >/dev/null 2>&1 || true

err(){ echo "ERROR: $*" >&2; }
info(){ echo "[info] $*"; }

__deq(){ local s="${1:-}"; s="${s//\\!/!}"; s="${s//\\;/;}"; s="${s//\\ / }"; s="${s//\\\\/\\}"; printf '%s' "$s"; }

shortver_from_string(){ awk 'match($0,/[0-9]+\.[0-9]+\.[0-9]+/){print substr($0,RSTART,RLENGTH)}'; }

detect_server_ip(){
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  fi
  [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i!="127.0.0.1"){print $i; exit}}')"
  echo "$ip"
}

build_ssh_arr(){
  local ip="$1"
  SSH_CMD=(ssh
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout="${CONNECT_TIMEOUT}"
    -o ServerAliveInterval=10
    -o ServerAliveCountMax=6
    -o PubkeyAcceptedKeyTypes=+ssh-rsa
    -o HostKeyAlgorithms=+ssh-rsa
    -o KexAlgorithms=+diffie-hellman-group14-sha1
    -tt "${SSH_USERNAME}@${ip}"
  )

  if [[ -n "${SSH_KEY_PATH}" && -r "${SSH_KEY_PATH}" ]]; then
    SSH_CMD+=(-i "$SSH_KEY_PATH" -o BatchMode=yes)
  else
    [[ -n "${SSH_PASSWORD}" ]] || { err "No SSH_KEY_PATH and SSH_PASSWORD empty."; exit 1; }
    command -v sshpass >/dev/null 2>&1 || { err "sshpass not installed (needed for password auth)."; exit 1; }
    SSH_CMD=(sshpass -p "$SSH_PASSWORD" "${SSH_CMD[@]}"
      -o PreferredAuthentications=password,keyboard-interactive
      -o KbdInteractiveAuthentication=yes
      -o PubkeyAuthentication=no
      -o NumberOfPasswordPrompts=1
    )
  fi
}

is_priv15_for_ip() {
  local ip="$1" raw out ok=1
  build_ssh_arr "$ip"
  raw="$(mktemp)"; out="$(mktemp)"
  {
    printf '\r\n'
    printf 'terminal length 0\r\n'
    printf 'terminal width 511\r\n'
    printf 'show privilege\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 25s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$out"
  grep -Eiq 'Current privilege level is[[:space:]]*15' "$out" && ok=0
  rm -f "$raw" "$out"
  return $ok
}

emit_enable(){
  printf 'enable\r\n'
  sleep 0.2
  if [[ -n "${ENABLE_PASSWORD:-}" ]]; then
    printf '%s\r\n' "$ENABLE_PASSWORD"
  else
    printf '\r\n'
  fi
  printf 'show privilege\r\n'
  sleep 0.2
}

flash_bytes_from_capture(){
  local outfile="$1" base="$2"
  awk -v f="$base" 'BEGIN{mx=-1;seen=0} index($0,f){seen=1;for(i=1;i<=NF;i++) if($i~/^[0-9]+$/){n=$i+0;if(n>mx)mx=n}} END{if(seen&&mx>=0)print mx}' "$outfile"
}

fmt_bytes(){
  awk -v b="${1:-0}" 'BEGIN{
    if(b<1024)printf("%d B",b);
    else if(b<1048576)printf("%.1f KB",b/1024);
    else if(b<1073741824)printf("%.1f MB",b/1048576);
    else printf("%.2f GB",b/1073741824);
  }'
}

run_show_install_summary(){
  local ip="$1" need_en=0 raw norm v=""
  build_ssh_arr "$ip"
  is_priv15_for_ip "$ip" || need_en=1
  raw="$(mktemp)"; norm="$(mktemp)"
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'show install summary\r\n'
    printf 'exit\r\n'
  } | timeout -k 5s 90s "${SSH_CMD[@]}" >"$raw" 2>&1 || true
  tr -d '\r' < "$raw" > "$norm"
  v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+C[[:space:]]+/{print $NF; exit}' "$norm")"
  [[ -z "$v" ]] && v="$(awk 'BEGIN{IGNORECASE=1}/^IMG[[:space:]]+U[[:space:]]+/{print $NF; exit}' "$norm")"
  v="$(printf '%s\n' "$v" | shortver_from_string)"
  echo "----- show install summary (parsed version: ${v:-unknown}) -----"
  sed -n '1,180p' "$norm"
  echo "---------------------------------------------------------------"
  rm -f "$raw" "$norm"
}

wait_for_ssh_down(){
  local ip="$1" timeout_s="${2:-900}" start
  start="$(date +%s)"
  info "Waiting for SSH to drop (expected reboot)…"
  while true; do
    if ! timeout -k 2s 4s ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
          -o ConnectTimeout=3 "${SSH_USERNAME}@${ip}" "exit" >/dev/null 2>&1; then
      info "SSH disconnect detected."
      return 0
    fi
    if (( $(date +%s) - start > timeout_s )); then
      err "Timed out waiting for SSH to drop."
      return 1
    fi
    sleep 3
  done
}

wait_for_ssh_up(){
  local ip="$1" timeout_s="${2:-2400}" start
  start="$(date +%s)"
  info "Waiting for SSH to return…"
  while true; do
    if timeout -k 2s 6s ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=5 "${SSH_USERNAME}@${ip}" "exit" >/dev/null 2>&1; then
      info "SSH is back."
      return 0
    fi
    if (( $(date +%s) - start > timeout_s )); then
      err "Timed out waiting for SSH to return."
      return 1
    fi
    sleep 6
  done
}

select_image(){
  [[ -d "$IMAGES_DIR" ]] || { err "Images dir not found: $IMAGES_DIR"; exit 1; }
  mapfile -t bins < <(find "$IMAGES_DIR" -maxdepth 1 -type f -name '*.bin' -printf '%f\n' | sort)
  ((${#bins[@]} > 0)) || { err "No .bin files found in $IMAGES_DIR"; exit 1; }

  echo
  echo "Available images in: $IMAGES_DIR"
  echo "--------------------------------"
  local i=1
  for f in "${bins[@]}"; do
    printf "  %2d) %s\n" "$i" "$f"
    ((i++))
  done
  echo "--------------------------------"
  local choice=""
  while true; do
    read -rp "Select image number: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] || { echo "Enter a number."; continue; }
    (( choice>=1 && choice<=${#bins[@]} )) || { echo "Out of range."; continue; }
    SELECTED_IMAGE="${bins[$((choice-1))]}"
    break
  done
}

http_copy_with_progress(){
  local ip="$1" base="$2" size_bytes="$3" http_base="$4"
  local url="${http_base%/}/${base}"
  local need_en=0

  build_ssh_arr "$ip"
  is_priv15_for_ip "$ip" || need_en=1

  info "Checking if file already exists on flash: $base"
  local pre_raw pre_norm existing=""
  pre_raw="$(mktemp)"; pre_norm="$(mktemp)"
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'dir flash: | include %s\r\n' "$base"
    printf 'exit\r\n'
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$pre_raw" 2>/dev/null || true
  tr -d '\r' < "$pre_raw" > "$pre_norm"
  existing="$(flash_bytes_from_capture "$pre_norm" "$base" || true)"
  rm -f "$pre_raw" "$pre_norm"

  if [[ -n "$existing" && -n "$size_bytes" && "$existing" == "$size_bytes" ]]; then
    info "File already present with matching size: $existing bytes. Skipping copy."
    return 0
  fi

  info "HTTP copy: $url  ->  flash:$base"

  # Start copy in background SSH session
  local copy_raw copy_pid
  copy_raw="$(mktemp)"

  (
    {
      printf '\r\nterminal length 0\r\nterminal width 511\r\n'
      (( need_en )) && emit_enable
      if [[ -n "${HTTP_CLIENT_SOURCE_IFACE:-}" ]]; then
        printf 'configure terminal\r\nip http client source-interface %s\r\nend\r\n' "$HTTP_CLIENT_SOURCE_IFACE"
      fi
      printf 'copy %s flash:%s\r\n' "$url" "$base"
      printf '\r\n'; sleep 0.5; printf '\r\n'
      printf 'exit\r\n'
    } | timeout -k 30s "${COPY_MAX_SECS}" "${SSH_CMD[@]}"
  ) >"$copy_raw" 2>&1 & copy_pid=$!

  # Poll flash size while copy runs
  local last="" cur="" pct=0
  while kill -0 "$copy_pid" 2>/dev/null; do
    local p_raw p_norm
    p_raw="$(mktemp)"; p_norm="$(mktemp)"
    build_ssh_arr "$ip"; is_priv15_for_ip "$ip" || need_en=1
    {
      printf '\r\nterminal length 0\r\nterminal width 511\r\n'
      (( need_en )) && emit_enable
      printf 'dir flash: | include %s\r\nexit\r\n' "$base"
    } | timeout -k 5s 30s "${SSH_CMD[@]}" >"$p_raw" 2>/dev/null || true
    tr -d '\r' < "$p_raw" > "$p_norm"
    cur="$(flash_bytes_from_capture "$p_norm" "$base" || true)"
    rm -f "$p_raw" "$p_norm"

    if [[ -n "$cur" && "$cur" != "$last" ]]; then
      if [[ -n "$size_bytes" && "$size_bytes" =~ ^[0-9]+$ && "$size_bytes" -gt 0 ]]; then
        pct=$((100*cur/size_bytes)); ((pct>99 && cur<size_bytes)) && pct=99
        info "Copy progress: $(fmt_bytes "$cur") / $(fmt_bytes "$size_bytes") (${pct}%)"
      else
        info "Copy progress: $(fmt_bytes "$cur")"
      fi
      last="$cur"
    else
      info "Copying… (poll again in ${POLL_SEC}s)"
    fi
    sleep "$POLL_SEC"
  done

  wait "$copy_pid" || true

  # Final verify
  local post_raw post_norm post=""
  post_raw="$(mktemp)"; post_norm="$(mktemp)"
  build_ssh_arr "$ip"; is_priv15_for_ip "$ip" || need_en=1
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'dir flash: | include %s\r\nexit\r\n' "$base"
  } | timeout -k 8s 60s "${SSH_CMD[@]}" >"$post_raw" 2>/dev/null || true
  tr -d '\r' < "$post_raw" > "$post_norm"
  post="$(flash_bytes_from_capture "$post_norm" "$base" || true)"
  rm -f "$post_raw" "$post_norm"

  if [[ -n "$size_bytes" && -n "$post" && "$post" == "$size_bytes" ]]; then
    info "Copy OK (bytes=$post)"
    rm -f "$copy_raw"
    return 0
  fi

  err "Copy verification failed. See output:"
  sed -n '1,200p' "$copy_raw" >&2
  rm -f "$copy_raw"
  return 1
}

install_and_wait_reboot(){
  local ip="$1" base="$2"
  local need_en=0

  build_ssh_arr "$ip"
  is_priv15_for_ip "$ip" || need_en=1

  info "Starting install: install add file flash:${base} activate commit prompt-level none"
  info "We will keep the session alive and wait for the switch to drop SSH (reboot)."

  set +e
  {
    printf '\r\nterminal length 0\r\nterminal width 511\r\n'
    (( need_en )) && emit_enable
    printf 'write memory\r\n'
    sleep 0.4
    printf 'install add file flash:%s activate commit prompt-level none\r\n' "$base"

    # Keepalive loop: DO NOT send exit; SSH will drop when device reboots
    while true; do
      sleep 10
      printf '\r\n'
    done
  } | timeout -k 30s "${INSTALL_MAX_SECS}" "${SSH_CMD[@]}"
  local rc=$?
  set -e

  info "Install SSH session ended (rc=$rc). Treating as expected if reboot occurred."

  wait_for_ssh_down "$ip" "$WAIT_DOWN_SEC" || true
  wait_for_ssh_up   "$ip" "$WAIT_UP_SEC"   || true
}

# -----------------------------
# Main
# -----------------------------
# Load any escaped vars if they came from env files
SSH_USERNAME="$(__deq "$SSH_USERNAME")"
SSH_PASSWORD="$(__deq "$SSH_PASSWORD")"
ENABLE_PASSWORD="$(__deq "$ENABLE_PASSWORD")"

[[ -n "$TARGET_IP" ]] || read -rp "Target switch IP: " TARGET_IP
[[ -n "$SSH_USERNAME" ]] || read -rp "SSH username: " SSH_USERNAME

if [[ -z "$SSH_KEY_PATH" ]]; then
  [[ -n "$SSH_PASSWORD" ]] || { read -rsp "SSH password (or Ctrl+C): " SSH_PASSWORD; echo; }
fi

if [[ -z "$ENABLE_PASSWORD" ]]; then
  read -rsp "Enable password (press Enter if none): " ENABLE_PASSWORD; echo
fi

[[ -n "$HTTP_BASE_DEFAULT" ]] || {
  srv="$(detect_server_ip)"
  HTTP_BASE_DEFAULT="http://${srv}/images"
}
read -rp "HTTP base [${HTTP_BASE_DEFAULT}]: " HTTP_BASE
HTTP_BASE="${HTTP_BASE:-$HTTP_BASE_DEFAULT}"

read -rp "Images dir [${IMAGES_DIR}]: " IMD
IMAGES_DIR="${IMD:-$IMAGES_DIR}"

# Quick reachability
info "Pinging $TARGET_IP…"
ping -c 2 -W 2 "$TARGET_IP" >/dev/null 2>&1 || info "Ping failed (continuing anyway)."

echo
info "Current installed version (before):"
run_show_install_summary "$TARGET_IP"

# Select file
select_image
IMG_PATH="${IMAGES_DIR%/}/${SELECTED_IMAGE}"
LOCAL_SIZE="$(stat -c '%s' "$IMG_PATH" 2>/dev/null || echo "")"
echo
echo "Selected image: ${SELECTED_IMAGE}"
echo "Local size: ${LOCAL_SIZE:-unknown} bytes"
echo

# Copy
http_copy_with_progress "$TARGET_IP" "$SELECTED_IMAGE" "$LOCAL_SIZE" "$HTTP_BASE"

# Install + wait reboot
install_and_wait_reboot "$TARGET_IP" "$SELECTED_IMAGE"

# Verify
echo
info "Installed version (after):"
run_show_install_summary "$TARGET_IP"

info "Done."