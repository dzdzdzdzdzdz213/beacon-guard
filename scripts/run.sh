#!/usr/bin/env bash
set -euo pipefail

# Start all BeaconGuard components

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() {
  echo ""
  echo "Shutting down..."
  kill $LOADER_PID $API_PID $FRONTEND_PID 2>/dev/null || true
  wait
}

trap cleanup EXIT INT TERM

echo "=== BeaconGuard Launcher ==="

# Start Go loader (requires root for eBPF)
echo "Starting loader (requires sudo)..."
sudo "$ROOT/loader/beacon-guard" --config "$ROOT/config.json" &
LOADER_PID=$!

# Start API
echo "Starting API server..."
cd "$ROOT/api"
python main.py &
API_PID=$!

# Start frontend
echo "Starting frontend..."
cd "$ROOT/frontend"
npm start &
FRONTEND_PID=$!

echo ""
echo "All components started:"
echo "  Dashboard: http://localhost:3000"
echo "  API:       http://localhost:9091/docs"
echo "  Loader:    PID $LOADER_PID"
echo ""
echo "Press Ctrl+C to stop all"

wait
