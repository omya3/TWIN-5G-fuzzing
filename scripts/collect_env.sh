#!/usr/bin/env bash

set -u

echo "=== System ==="
uname -a || true
echo

if [ -f /etc/os-release ]; then
  echo "=== /etc/os-release ==="
  cat /etc/os-release
  echo
fi

echo "=== User ==="
whoami || true
id || true
echo

echo "=== Python ==="
command -v python3 || true
python3 --version 2>/dev/null || true
echo

echo "=== Networking / Capture Tools ==="
for cmd in tshark tcpdump wireshark scapy docker podman git gcc make cmake; do
  printf "%-10s : " "$cmd"
  command -v "$cmd" || echo "not found"
done
echo

echo "=== 5G Stack Commands ==="
for cmd in open5gs-amfd open5gs-mmed nr-gnb nr-ue; do
  printf "%-14s : " "$cmd"
  command -v "$cmd" || echo "not found"
done
echo

echo "=== Service Status Hints ==="
for svc in open5gs-amfd open5gs-mmed mongod docker; do
  if command -v systemctl >/dev/null 2>&1; then
    echo "--- $svc ---"
    systemctl status "$svc" --no-pager 2>/dev/null | head -20 || echo "status unavailable"
  fi
done
