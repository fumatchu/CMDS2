#!/usr/bin/env bash
# Meraki Org/Network picker + creator (dialog UI)
# - Auto-detects ENV in this script's dir (ENV, .env, meraki_discovery.env, meraki.env, or any *.env/*ENV with MERAKI_API_KEY)
# - Bearer auth by default, auto-fallback to X-Cisco-Meraki-API-Key on 401
# - Trims CRs/spaces from MERAKI_API_KEY (Windows-safe)
# - Uses dialog --stdout (fallback) and --separate-output for checklists
# - Ensures selected network includes product type "switch" (Catalyst cloud-managed IOS-XE needs this)
# - Saves selection to meraki_selection.env next to your ENV

set -Eeuo pipefail

API_BASE="https://api.meraki.com/api/v1"
: "${DIALOG:=dialog}"

# ---------------- working space & ENV resolution ----------------
SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"

if [[ -n "${1:-}" ]]; then
  ENV_FILE="$1"
else
  CANDIDATES=(
    "$SCRIPT_DIR/ENV"
    "$SCRIPT_DIR/.env"
    "$SCRIPT_DIR/meraki_discovery.env"
    "$SCRIPT_DIR/meraki.env"
  )
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*.env" || true)
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*ENV" || true)
  while IFS= read -r f; do CANDIDATES+=("$f"); done < <(compgen -G "$SCRIPT_DIR/*.ENV" || true)

  ENV_FILE=""
  for f in "${CANDIDATES[@]}"; do
    [[ -f "$f" && -r "$f" ]] || continue
    if grep -Eq '(^|\s)(export\s+)?MERAKI_API_KEY=' "$f"; then
      ENV_FILE="$f"; break
    fi
  done
fi

if [[ -z "${ENV_FILE:-}" ]]; then
  echo "ERROR: No ENV-like file found in $SCRIPT_DIR (looked for ENV/.env/meraki_discovery.env/meraki.env and any *.env/*ENV with MERAKI_API_KEY=)." >&2
  echo "Tip: pass path explicitly:  $0 /path/to/your.env" >&2
  exit 1
fi

echo "Using ENV file: $ENV_FILE" >&2
SEL_OUT="$(dirname "$ENV_FILE")/meraki_selection.env"

# ---------------- helpers ----------------
die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
cleanup() { [[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"; }
trap cleanup EXIT
TMPDIR="$(mktemp -d)"

# dialog capture helper: prefer --stdout; fallback to stderr capture
DIALOG_HAS_STDOUT=1
if ! "$DIALOG" --help 2>&1 | grep -q -- '--stdout'; then
  DIALOG_HAS_STDOUT=0
fi
dlg() {
  if [[ $DIALOG_HAS_STDOUT -eq 1 ]]; then
    "$DIALOG" --stdout "$@"
  else
    local out="$TMPDIR/dlgout.$$"
    if "$DIALOG" "$@" 2> "$out"; then
      cat "$out"
    else
      return 1
    fi
  fi
}

# ---------------- preflight ----------------
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
  cat <<USAGE
Usage: $0 [optional:/path/to/envfile]
Loads ENV from this script's directory by default.

Outputs:
  Saves selection to $(dirname "$ENV_FILE")/meraki_selection.env
USAGE
  exit 0
}

need curl
need jq
need "$DIALOG"

# Avoid history expansion issues with '!' in envs
set +H
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${MERAKI_API_KEY:?MERAKI_API_KEY is not set in $ENV_FILE}"

# Trim CRs/whitespace from key (Windows-safe)
MERAKI_API_KEY="$(printf '%s' "$MERAKI_API_KEY" | tr -d '\r' | awk '{$1=$1;print}')"
_mask_key() { local k="$1"; local n=${#k}; [[ $n -gt 8 ]] && echo "${k:0:4}…${k: -4} (len=$n)" || echo "(len=$n)"; }

# ---------------- Meraki API core (rate-limit, pagination, auth fallback) ----------------
AUTH_MODE="${AUTH_MODE:-auto}"  # auto|bearer|x-cisco

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
  local code mode attempt_modes
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
      continue    # try legacy header next
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
    exit 1
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
      exit 1
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

# ---------------- Dialog UI ----------------
pick_org() {
  local orgs_json; orgs_json="$(_meraki_get_all_pages "/organizations" "?perPage=1000")"

  local -a items=()
  while IFS=$'\t' read -r oid oname; do
    [[ -z "$oname" ]] && oname="(unnamed)"
    items+=("$oid" "$oname")
  done < <(jq -r '.[] | "\(.id)\t\(.name)"' <<<"$orgs_json")

  [[ ${#items[@]} -gt 0 ]] || die "No organizations visible to this API key."

  local choice
  choice="$(dlg --clear --backtitle "Meraki Picker" \
    --menu "Select an Organization" 20 80 14 "${items[@]}")" || exit 1
  ORG_ID="$choice"
  ORG_NAME="$(jq -r --arg id "$ORG_ID" '.[] | select(.id==$id) | .name' <<<"$orgs_json")"
}

ensure_network_has_switch() {
  local njson; njson="$(_meraki_get_json "/networks/$NET_ID")"
  NET_PRODUCT_TYPES="$(jq -c '.productTypes' <<<"$njson")"
  if jq -e '.productTypes | index("switch")' <<<"$njson" >/dev/null 2>&1; then
    return 0
  fi
  if dlg --yesno "Selected network \"$NET_NAME\" does not include product type 'switch'.\n\nCatalyst (cloud-managed IOS-XE) onboarding requires a network with 'switch'.\n\nCreate a new 'switch' network now?" 14 80; then
    create_network_dialog
  else
    die "Aborted: please select or create a network that includes product type 'switch'."
  fi
}

pick_or_create_network() {
  local nets_json; nets_json="$(_meraki_get_all_pages "/organizations/$ORG_ID/networks" "?perPage=1000")"

  local -a items=("NEW" "➕  Create a new network in \"$ORG_NAME\"")
  while IFS=$'\t' read -r nid nname ptypes; do
    [[ -z "$nname" ]] && nname="(unnamed)"
    local label="$nname  [$(tr -d '[]" ' <<<"$ptypes")]"
    items+=("$nid" "$label")
  done < <(jq -r '.[] | "\(.id)\t\(.name)\t\(.productTypes)"' <<<"$nets_json")

  local sel
  sel="$(dlg --clear --backtitle "Meraki Picker - $ORG_NAME" \
        --menu "Select an existing Network or choose NEW" 25 90 18 "${items[@]}")" || exit 1

  if [[ "$sel" == "NEW" ]]; then
    create_network_dialog
  else
    NET_ID="$sel"
    NET_NAME="$(jq -r --arg id "$NET_ID" '.[] | select(.id==$id) | .name' <<<"$nets_json")"
    NET_PRODUCT_TYPES="$(jq -c --arg id "$NET_ID" '.[] | select(.id==$id) | .productTypes' <<<"$nets_json")"
    ensure_network_has_switch
  fi
}

create_network_dialog() {
  NET_NAME="$(dlg --inputbox "Enter a name for the new Network (Org: $ORG_NAME)" 10 70 "Catalyst Switch Onboarding")" || exit 1
  [[ -n "$NET_NAME" ]] || die "Network name cannot be empty."

  # Clarify that 'switch' covers Meraki MS AND Catalyst (cloud-managed IOS-XE)
  local -a checklist=(
    "appliance"        "MX / SD-WAN"                              off
    "switch"           "Switch (Meraki MS OR Catalyst IOS-XE)"    on
    "wireless"         "MR / Wireless"                            off
    "camera"           "MV / Cameras"                             off
    "cellularGateway"  "MG / Cellular"                            off
    "sensor"           "MT / Sensors"                             off
    "systemsManager"   "SM / MDM"                                 off
  )

  # --separate-output MUST be before --checklist
  local selection
  selection="$(dlg --separate-output \
                   --checklist "Select product types for \"$NET_NAME\"\n(Keep 'switch' enabled for CS onboarding)" \
                   20 80 12 "${checklist[@]}")" || exit 1

  [[ -n "$selection" ]] || die "At least one product type must be selected."

  # Convert newline-separated selection to JSON array
  mapfile -t PRODUCTS <<< "$selection"
  local ptypes_json; ptypes_json="$(printf '%s\n' "${PRODUCTS[@]}" | jq -R . | jq -s .)"

  local default_tz="America/New_York"
  local tz; tz="$(dlg --inputbox "Optional: timeZone (IANA) for \"$NET_NAME\"\nLeave blank to let Dashboard default" 10 70 "$default_tz")" || exit 1
  [[ -z "$tz" ]] && tz=""

  local body
  if [[ -n "$tz" ]]; then
    body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" --arg tz "$tz" \
      '{name:$name, productTypes:$productTypes, timeZone:$tz}')"
  else
    body="$(jq -n --arg name "$NET_NAME" --argjson productTypes "$ptypes_json" \
      '{name:$name, productTypes:$productTypes}')"
  fi

  _meraki_call POST "/organizations/$ORG_ID/networks" "$body" ""
  local code; code="$(cat "$TMPDIR/code.$$")"
  [[ "$code" == "201" ]] || {
    echo "Create network failed ($code):" >&2
    sed -n '1,160p' "$TMPDIR/last_body" >&2 || true
    exit 1
  }
  NET_ID="$(jq -r '.id' "$TMPDIR/last_body")"
  NET_NAME="$(jq -r '.name' "$TMPDIR/last_body")"
  NET_PRODUCT_TYPES="$(jq -c '.productTypes' "$TMPDIR/last_body")"
  local url; url="$(jq -r '.url' "$TMPDIR/last_body")"

  dlg --msgbox "Created Network:\n\nName: $NET_NAME\nID:   $NET_ID\nTypes: $(jq -r '.|join(", ")' <<<"$NET_PRODUCT_TYPES")\nURL:  $url\n" 14 90
}

save_selection() {
  cat > "$SEL_OUT" <<EOF
# Generated by meraki_org_net_menu.sh on $(date -u +'%Y-%m-%d %H:%M:%S UTC')
export MERAKI_ORG_ID="$ORG_ID"
export MERAKI_ORG_NAME="$ORG_NAME"
export MERAKI_NETWORK_ID="$NET_ID"
export MERAKI_NETWORK_NAME="$NET_NAME"
export MERAKI_NETWORK_PRODUCT_TYPES='${NET_PRODUCT_TYPES:-["switch"]}'
EOF
}

# ---------------- flow ----------------
pick_org
pick_or_create_network
save_selection

MSG="Selection saved to:
$SEL_OUT

Organization: $ORG_NAME ($ORG_ID)
Network:      $NET_NAME ($NET_ID)

Tip for Catalyst registration (IOS-XE):
- L3 SVI with Internet, default route, DNS
- ip http client source-interface: ${HTTP_CLIENT_SOURCE_IFACE:-<set in ENV>}
- VLAN for Internet-bound SVI:      ${HTTP_CLIENT_VLAN_ID:-<set in ENV>}

Next: claim cloud IDs (serials) into this network."
dlg --title "Done" --msgbox "$MSG" 20 90
clear
echo "Saved selection to: $SEL_OUT"
echo "ORG: $ORG_NAME ($ORG_ID)"
echo "NET: $NET_NAME ($NET_ID)"
