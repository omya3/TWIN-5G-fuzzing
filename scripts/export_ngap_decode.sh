#!/usr/bin/env bash

set -euo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <capture.pcapng> [output-prefix]" >&2
  exit 1
fi

INPUT="$1"
PREFIX="${2:-${INPUT%.*}}"

tshark -r "$INPUT" -Y "ngap" -V > "${PREFIX}.txt"
tshark -r "$INPUT" -Y "ngap" -T json > "${PREFIX}.json"

echo "Wrote:"
echo "  ${PREFIX}.txt"
echo "  ${PREFIX}.json"
