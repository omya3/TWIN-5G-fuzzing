#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="${1:-remote_traces}"
INPUT="${BASE_DIR}/ngap-registration-core-augmented.json"
OUT_DIR="${BASE_DIR}/first_nas_type_campaign"

mkdir -p "$OUT_DIR"

generate_case() {
  local code="$1"
  local label="$2"
  local slug="$3"

  python3 -m src.ngap_nas_fuzz.cli mutate \
    --input "$INPUT" \
    --output "${OUT_DIR}/${slug}.json" \
    --mutation patch-plain-nas-message-type \
    --index 1 \
    --value "$code" \
    --field "$label"
}

# These are the message types we have already observed in the clean trace,
# plus the first invalid-message experiment that already worked end-to-end.
generate_case 0x41 "Registration request" "msgtype-41-registration-request"
generate_case 0x56 "Authentication request" "msgtype-56-authentication-request"
generate_case 0x57 "Authentication response" "msgtype-57-authentication-response"
generate_case 0x5c "Identity response" "msgtype-5c-identity-response"
generate_case 0x5d "Security mode command" "msgtype-5d-security-mode-command"

echo "Generated campaign cases in ${OUT_DIR}:"
ls -1 "${OUT_DIR}"/*.json
