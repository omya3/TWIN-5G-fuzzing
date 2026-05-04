#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 <history-json> [output-dir]" >&2
  exit 2
fi

HISTORY_PATH="$1"
OUTPUT_DIR="${2:-submission_reports}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"
mkdir -p "$OUTPUT_DIR"

MESSAGES=(
  "Registration Request"
  "Identity Response"
  "Authentication Response"
  "Security Mode Complete"
  "PDU Session Establishment Request"
)

for MESSAGE in "${MESSAGES[@]}"; do
  SLUG="$(printf '%s' "$MESSAGE" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')"
  python3 -m src.ngap_nas_fuzz.cli export-nas-campaign-report \
    --history "$HISTORY_PATH" \
    --message "$MESSAGE" \
    --output "${OUTPUT_DIR}/${SLUG}.md"
done

python3 - "$HISTORY_PATH" "${OUTPUT_DIR}/overview.md" <<'PY'
import json
import sys
from pathlib import Path

from src.ngap_nas_fuzz.nas_scheduler import (
    NasCampaignObservation,
    summarize_campaign_history,
)

history_path = Path(sys.argv[1])
overview_path = Path(sys.argv[2])

raw_history = json.loads(history_path.read_text())
history = [NasCampaignObservation.from_dict(item) for item in raw_history]
summaries = summarize_campaign_history(history)

lines = [
    "# TWiN NAS Campaign Overview",
    "",
    f"- History observations considered: {len(history)}",
    f"- Families summarized: {len(summaries)}",
    "",
    "| Message | Family | Supported | Live Tried | Dominant Live Result | Saturation |",
    "| --- | --- | --- | --- | --- | --- |",
]

for summary in summaries:
    dominant = (
        sorted(summary.live_result_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
        if summary.live_result_counts
        else "none"
    )
    lines.append(
        "| {message} | {family} | {supported}/{total} | {live}/{total} | {dominant} | {saturation} |".format(
            message=summary.message_name,
            family=summary.family_name,
            supported=summary.executable_known_operators,
            total=summary.total_known_operators,
            live=summary.live_tried_operators,
            dominant=dominant,
            saturation=summary.saturation,
        )
    )

future_work = [
    summary
    for summary in summaries
    if summary.executable_known_operators == 0
]
if future_work:
    lines.extend(["", "## Planned-Only Future Work", ""])
    for summary in future_work:
        lines.append(
            f"- `{summary.message_name} :: {summary.family_name}` is modeled but not yet live-executable in the current proxy/bridge implementation."
        )

overview_path.write_text("\n".join(lines) + "\n")
print(f"Wrote overview report to {overview_path}")
PY

echo
echo "Wrote submission reports to ${OUTPUT_DIR}:"
ls -1 "$OUTPUT_DIR"
