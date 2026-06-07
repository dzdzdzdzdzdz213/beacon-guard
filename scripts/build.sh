#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== BeaconGuard Build ==="

echo "  [1/4] Building eBPF programs..."
cd "$ROOT/bpf"
make clean 2>/dev/null || true
make
echo "  ✅ eBPF built"

echo "  [2/4] Building Go loader..."
cd "$ROOT/loader"
go build -o beacon-guard .
echo "  ✅ Go loader built"

echo "  [3/4] Installing Python deps..."
cd "$ROOT/api"
pip install -q -r requirements.txt 2>/dev/null || true
echo "  ✅ Python deps ready"

echo "  [4/4] Installing Node deps..."
cd "$ROOT/frontend"
npm install --silent 2>/dev/null || true
echo "  ✅ Node deps ready"

echo ""
echo "=== Build complete ==="
echo ""
echo "To run:"
echo "  sudo ./loader/beacon-guard --config config.json"
echo "  cd api && python main.py"
echo "  cd frontend && npm start"
