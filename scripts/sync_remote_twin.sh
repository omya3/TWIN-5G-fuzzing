#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 <user@host> [remote-path]" >&2
  exit 2
fi

TARGET="$1"
REMOTE_ROOT="${2:-/home/omkar/TWIN}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"

if [ ! -d src ] || [ ! -d proxy ] || [ ! -d tests ]; then
  echo "[sync] Expected to run from the TWiN repository root." >&2
  exit 1
fi

SYNC_PATHS=(
  README.md
  requirements.txt
  docs
  proxy
  scripts
  src
  tests
)

echo "[sync] Repo root: $REPO_ROOT"
echo "[sync] Remote target: ${TARGET}:${REMOTE_ROOT}"
echo "[sync] Syncing the working tree needed for build, tests, docs, and reports..."

rsync -avz \
  --exclude '.git/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.DS_Store' \
  "${SYNC_PATHS[@]}" \
  "${TARGET}:${REMOTE_ROOT}/"

cat <<EOF

[sync] Remote follow-up:
ssh ${TARGET} <<'REMOTE'
cd ${REMOTE_ROOT}
make -C proxy clean
make -C proxy
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_*.py'
REMOTE

[sync] Campaign follow-up example:
ssh ${TARGET} <<'REMOTE'
cd ${REMOTE_ROOT}
python3 -m src.ngap_nas_fuzz.cli show-nas-frontiers \\
  --history /home/omkar/twin-traces/nas-campaign/history.json \\
  --limit 12
REMOTE
EOF
