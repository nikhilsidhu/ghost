#!/usr/bin/env bash
# Launch relay + N ghost-app instances for local testing.
# Usage: ./scripts/spawn-instances.sh [N]  (default: 2)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
N="${1:-2}"

# Kill leftover processes from a previous run
echo "cleaning up old processes..."
pkill -f "ghost-relay" 2>/dev/null || true
pkill -f "ghost-app" 2>/dev/null || true
pkill -f "tauri dev" 2>/dev/null || true
pkill -f "vite.*ghost-app" 2>/dev/null || true
sleep 1

cleanup() {
    echo "shutting down..."
    kill $(jobs -p) 2>/dev/null
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# Relay
echo "starting relay..."
cd "$ROOT/ghost-relay"
cargo run &
sleep 1

# Instance 1 — default config, default data dir
echo "starting instance 1..."
cd "$ROOT/ghost-app"
npx tauri dev &

# Instances 2..N — each gets a unique data dir, vite port, tauri port, and identifier
for i in $(seq 2 "$N"); do
    VITE_PORT=$((1420 + (i - 1) * 2))
    TAURI_PORT=$((1430 + i - 1))
    DATA_DIR="/tmp/ghost-$i"
    mkdir -p "$DATA_DIR"

    echo "starting instance $i (vite=$VITE_PORT, data=$DATA_DIR)..."
    GHOST_DATA_DIR="$DATA_DIR" npx tauri dev \
        --config "{\"identifier\":\"com.ghost.app.dev$i\",\"build\":{\"devUrl\":\"http://localhost:$VITE_PORT\",\"beforeDevCommand\":\"npx vite --port $VITE_PORT\"}}" \
        --port "$TAURI_PORT" &
done

echo "all instances launched. ctrl-c to stop all."
wait
