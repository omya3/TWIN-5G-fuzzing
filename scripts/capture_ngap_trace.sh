#!/usr/bin/env bash

set -euo pipefail

OUT_DIR="${1:-$HOME/twin-traces}"
OUT_FILE="${2:-ngap-registration-$(date +%Y%m%d-%H%M%S).pcapng}"
INTERFACE="${3:-any}"

mkdir -p "$OUT_DIR"

echo "Capturing NGAP traffic on interface '$INTERFACE' to '$OUT_DIR/$OUT_FILE'"
echo "Press Ctrl-C after the registration flow completes."

sudo tshark -i "$INTERFACE" -f "sctp port 38412" -w "$OUT_DIR/$OUT_FILE"
