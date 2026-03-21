#!/usr/bin/env bash
set -Eeuo pipefail

# meraki_cfgsrc_probe.sh
# Purpose: Pull raw Meraki JSON + show which fields/keys exist for "Configuration source"
# Reads MERAKI_API_KEY from ./meraki_discovery.env (or ENV_FILE=... override)

: "${DIALOG:=dialog}"
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
BASE_DIR="$SCRIPT_DIR"

ENV_FILE="${ENV_FILE:-$BASE_DIR/meraki_discovery.env}"
API_BASE="https://api.meraki.com/api/v1"
AUTH_MODE="${AUTH_MODE:-auto}"   # auto|bearer|x-cisco

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"${1-}"; }

# ---------------- dialog wrapper (SAFE) ----------------
DIALOG_HAS_OUTPUT_FD=0
DIALOG_HAS_STDOUT=0
if "$DIALOG" --help 2>&1 | grep -q -- '--output-fd'; then DIALOG_HAS_OUTPUT_FD=1; fi
if "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then DIALOG_HAS_STDOUT=1; fi

dlg() {
  local common=(--clear --ok-label "Continue" --cancel-label "Back")
  if [[ $DIALOG_HAS_OUTPUT_FD -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --output-fd 1 "$@" 2>/dev/tty
    return $?
  fi
  if [[ $DIALOG_HAS_STDOUT -eq 1 ]]; then
    "$DIALOG" "${common[@]}" --stdout "$@" 2>/dev/tty
    return $?
  fi
  echo "ERROR: dialog supports neither --output-fd nor --stdout. Install a newer 'dialog'." >&2
  exit 1
}

mask_key() {
  local k="${1-}" n=${#k}
  if (( n > 8 )); then printf '%s…%s (len=%s)' "${k:0:4}" "${k: -4}" "$n"; else printf '(len=%s)' "$n"; fi
}

# ---------------- run dir ----------------
RUN_ID="probe-$(date -u +%Y%m%d%H%M%S)"
RUN_DIR="$BASE_DIR/runs/meraki_probe/$RUN_ID"
mkdir -p "$RUN_DIR"
LOG="$RUN_DIR/probe.log"
: >"$LOG"

log() { printf '[%s] %s\n' "$(date +'%Y-%m-%dT%H:%M:%S%z')" "$*" | tee -a "$LOG" >/dev/null; }

# ---------------- Meraki API helpers ----------------
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR" 2>/dev/null || true; }
trap cleanup EXIT

load_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Missing env file: $ENV_FILE" >&2
    exit 1
  fi
  set +H
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set -H 2>/dev/null || true
  : "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"
  MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"
  log "Loaded API key: $(mask_key "$MERAKI_API_KEY") auth_mode=$AUTH_MODE"
}

_do_curl() {
  local method="$1" path="$2" query="${3:-}" mode="$4"
  local hdr="$TMPDIR/hdr.$$" bodyf="$TMPDIR/body.$$"
  local -a H; H=(-H "Accept: application/json")

  if [[ "$mode" == "x-cisco" ]]; then
    H+=(-H "X-Cisco-Meraki-API-Key: $MERAKI_API_KEY")
  else
    H+=(-H "Authorization: Bearer $MERAKI_API_KEY")
  fi

  curl -sS -D "$hdr" -o "$bodyf" -w '%{http_code}' -X "$method" "${H[@]}" \
    "$API_BASE$path$query"
}

meraki_get() {
  local path="$1" query="${2:-}"
  local code mode
  local -a attempt_modes=()

  if [[ "$AUTH_MODE" == "auto" ]]; then
    attempt_modes=("bearer" "x-cisco")
  else
    attempt_modes=("$AUTH_MODE")
  fi

  for mode in "${attempt_modes[@]}"; do
    while :; do
      code="$(_do_curl GET "$path" "$query" "$mode")"
      cp "$TMPDIR/hdr.$$" "$TMPDIR/last_headers" 2>/dev/null || true
      cp "$TMPDIR/body.$$" "$TMPDIR/last_body"   2>/dev/null || true

      if [[ "$code" == "429" ]]; then
        local wait
        wait="$(awk '/^Retry-After:/ {print $2}' "$TMPDIR/last_headers" | tr -d '\r')"
        [[ -z "$wait" ]] && wait=1
        sleep "$wait"
        continue
      fi
      break
    done

    if [[ "$code" == "401" && "$AUTH_MODE" == "auto" && "$mode" == "bearer" ]]; then
      continue
    fi

    AUTH_MODE="$mode"
    break
  done

  log "GET $path$query -> http=$code auth_mode=$AUTH_MODE"
  echo "$code" >"$TMPDIR/code.$$"
}

get_all_pages() {
  # Uses Link header 'startingAfter='
  local path="$1" query="${2:-?perPage=1000}"
  local accum="$TMPDIR/accum.$$"
  printf '[]' >"$accum"
  local nextStart=""

  while :; do
    local q="$query"
    [[ -n "$nextStart" ]] && q="${query}&startingAfter=$nextStart"

    meraki_get "$path" "$q"
    local code; code="$(cat "$TMPDIR/code.$$")"
    if ! [[ "$code" =~ ^20[01]$ ]]; then
      echo "ERROR http=$code for $path$q" >&2
      sed -n '1,80p' "$TMPDIR/last_body" >&2 || true
      return 1
    fi

    jq -s '.[0] + .[1]' "$accum" "$TMPDIR/last_body" >"$accum.tmp" && mv "$accum.tmp" "$accum"

    local link; link="$(grep -i '^Link:' "$TMPDIR/last_headers" | tr -d '\r' || true)"
    if grep -qi 'rel="next"' <<<"$link"; then
      nextStart="$(grep -oi 'startingAfter=[^&>;]*' <<<"$link" | tail -n1 | cut -d= -f2)"
      [[ -z "$nextStart" ]] && break
    else
      break
    fi
  done

  cat "$accum"
}

pick_org() {
  "$DIALOG" --backtitle "Meraki Probe" --infobox "Fetching organizations..." 5 60
  local orgs; orgs="$(get_all_pages "/organizations" "?perPage=1000")"
  printf '%s' "$orgs" >"$RUN_DIR/orgs.json"

  local -a items=()
  while IFS=$'\t' read -r id name; do
    [[ -z "$id" ]] && continue
    [[ -z "$name" ]] && name="(unnamed)"
    items+=( "$id" "$name" )
  done < <(jq -r '.[] | [(.id//""), (.name//"")] | @tsv' <<<"$orgs")

  ORG_ID="$(dlg --backtitle "Meraki Probe" --title "Select Organization" \
    --menu "Pick org to probe." 20 70 12 "${items[@]}")" || exit 1

  ORG_NAME="$(jq -r --arg id "$ORG_ID" '.[] | select(.id==$id) | (.name//"")' <<<"$orgs" | head -n1)"
  ORG_NAME="$(trim "$ORG_NAME")"
  log "Selected org: $ORG_NAME ($ORG_ID)"
}

pick_network() {
  "$DIALOG" --backtitle "Meraki Probe" --infobox "Fetching networks for org..." 6 60
  local nets; nets="$(get_all_pages "/organizations/$ORG_ID/networks" "?perPage=1000")"
  printf '%s' "$nets" >"$RUN_DIR/networks.json"

  local -a items=()
  while IFS=$'\t' read -r id name types; do
    [[ -z "$id" ]] && continue
    [[ -z "$name" ]] && name="(unnamed)"
    items+=( "$id" "$name  [$types]" )
  done < <(jq -r '
    .[]
    | [(.id//""), (.name//""), ((.productTypes//[])|join(","))] | @tsv
  ' <<<"$nets")

  NET_ID="$(dlg --backtitle "Meraki Probe" --title "Select Network" \
    --menu "Pick network to probe.\n\n(Tip: choose the one you’re migrating.)" 22 90 16 "${items[@]}")" || exit 1

  NET_NAME="$(jq -r --arg id "$NET_ID" '.[] | select(.id==$id) | (.name//"")' <<<"$nets" | head -n1)"
  NET_NAME="$(trim "$NET_NAME")"
  log "Selected network: $NET_NAME ($NET_ID)"
}

probe_devices() {
  "$DIALOG" --backtitle "Meraki Probe" --infobox "Fetching network devices..." 6 60
  local devs; devs="$(get_all_pages "/networks/$NET_ID/devices" "?perPage=1000")"
  printf '%s' "$devs" >"$RUN_DIR/network_devices.json"

  # Show quick summary
  jq -r '
    . as $all
    | [
        "Network devices returned: \($all|length)",
        "",
        "Switch-like devices:",
        (
          $all
          | map(select((.productType == "switch") or (((.model // "") | tostring) | test("^(MS|C9|C8|C7)"))))
          | map([.serial, (.name//"(unnamed)"), (.model//"-"), (.lanIp//"-")] | @tsv)
          | (["serial\tname\tmodel\tlanIp"] + .) | .[]
        )
      ]
    | .[]
  ' "$RUN_DIR/network_devices.json" >"$RUN_DIR/devices_summary.txt"

  dlg --backtitle "Meraki Probe" --title "Network devices summary" --textbox "$RUN_DIR/devices_summary.txt" 26 120 || true
}

probe_inventory_cfgsrc() {
  "$DIALOG" --backtitle "Meraki Probe" --infobox "Fetching org inventory (switch)..." 6 66
  local inv; inv="$(get_all_pages "/organizations/$ORG_ID/inventory/devices" "?perPage=1000&productTypes[]=switch")"
  printf '%s' "$inv" >"$RUN_DIR/org_inventory_switch.json"

  # Build a focused subset for THIS network
  jq --arg net "$NET_ID" '
    .[]
    | select((.networkId//"") == $net)
    | {
        serial: (.serial//""),
        model: (.model//""),
        name: (.name//""),
        networkId: (.networkId//""),
        details: (.details//[])
      }
  ' "$RUN_DIR/org_inventory_switch.json" >"$RUN_DIR/inventory_for_network.json"

  # Show what detail keys exist (unique)
  jq -r '
    (.details // [])[] | .name
  ' "$RUN_DIR/inventory_for_network.json" | sort -u >"$RUN_DIR/detail_keys.txt" || true

  # For each device, extract ANY detail whose name contains "config"
  jq -r '
    [
      .serial,
      (.name//"(unnamed)"),
      (
        (.details // [])
        | map(select((.name//""|ascii_downcase) | test("config")))
        | map("\(.name)=\(.value)") | join(" | ")
      )
    ] | @tsv
  ' "$RUN_DIR/inventory_for_network.json" >"$RUN_DIR/inventory_config_related.tsv"

  {
    echo "Org inventory rows for this network (switch):"
    echo "Org:     $ORG_NAME ($ORG_ID)"
    echo "Network: $NET_NAME ($NET_ID)"
    echo
    echo "Unique detail keys (what Meraki actually returns):"
    echo "----------------------------------------------"
    sed -n '1,200p' "$RUN_DIR/detail_keys.txt"
    echo
    echo "Per-device details that contain 'config' in the key name:"
    echo "--------------------------------------------------------"
    echo -e "serial\tname\tconfig-related-details"
    sed -n '1,200p' "$RUN_DIR/inventory_config_related.tsv"
    echo
    echo "Files saved:"
    echo "  $RUN_DIR/network_devices.json"
    echo "  $RUN_DIR/org_inventory_switch.json"
    echo "  $RUN_DIR/inventory_for_network.json"
  } >"$RUN_DIR/inventory_summary.txt"

  dlg --backtitle "Meraki Probe" --title "Inventory + Configuration fields" --textbox "$RUN_DIR/inventory_summary.txt" 30 140 || true
}

main() {
  need curl
  need jq
  need "$DIALOG"

  load_env
  mkdir -p "$BASE_DIR/runs/meraki_probe"

  dlg --backtitle "Meraki Probe" --title "Meraki API Probe" \
    --msgbox "This will pull raw JSON from the Meraki API and show what fields exist for:\n\n- Network devices\n- Org inventory (switch)\n\nRun output:\n  $RUN_DIR\n\nAPI key:\n  $(mask_key "$MERAKI_API_KEY")" 16 72

  pick_org
  pick_network
  probe_devices
  probe_inventory_cfgsrc

  dlg --backtitle "Meraki Probe" --title "Done" \
    --msgbox "Probe complete.\n\nSaved files in:\n  $RUN_DIR\n\nNext step: tell me which key/value corresponds to the Dashboard 'Configuration source' column." 12 70
}

main "$@"
