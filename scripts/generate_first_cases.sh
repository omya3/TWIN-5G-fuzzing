#!/usr/bin/env bash

set -euo pipefail

BASE_DIR="${1:-remote_traces}"
INPUT="${BASE_DIR}/ngap-registration-structured.json"
CORE="${BASE_DIR}/ngap-registration-core.json"
AUGMENTED_CORE="${BASE_DIR}/ngap-registration-core-augmented.json"
JSON_INPUT="${BASE_DIR}/ngap-registration.json"

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$INPUT" \
  --output "$CORE" \
  --mutation slice-trace \
  --index 3 \
  --other-index 10

python3 -m src.ngap_nas_fuzz.cli augment-json \
  --input "$CORE" \
  --json-input "$JSON_INPUT" \
  --output "$AUGMENTED_CORE"

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$AUGMENTED_CORE" \
  --output "${BASE_DIR}/case1-duplicate-ics-response.json" \
  --mutation duplicate-message \
  --index 7

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$AUGMENTED_CORE" \
  --output "${BASE_DIR}/case2-reorder-ics.json" \
  --mutation reorder-messages \
  --index 6 \
  --other-index 7

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$AUGMENTED_CORE" \
  --output "${BASE_DIR}/case3-amf-id-mismatch.json" \
  --mutation set-ngap-field \
  --index 7 \
  --field AMF_UE_NGAP_ID \
  --value 999

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$AUGMENTED_CORE" \
  --output "${BASE_DIR}/case4-initial-nas-type.json" \
  --mutation nas-message-type \
  --index 1 \
  --value "Identity response"

python3 -m src.ngap_nas_fuzz.cli mutate \
  --input "$AUGMENTED_CORE" \
  --output "${BASE_DIR}/case5-raw-nas-msgtype-patched.json" \
  --mutation patch-plain-nas-message-type \
  --index 1 \
  --value 0x5c \
  --field "Identity response"

echo "Generated:"
ls -1 "${BASE_DIR}"/case*.json "$CORE" "$AUGMENTED_CORE"
