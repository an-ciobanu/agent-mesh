#!/usr/bin/env bash
# P5 UI demo: build everything, launch the orchestrator (which spawns the whole
# mesh — registry, transparency log, authority, and a roster of event-emitting
# agents), and open the browser. Each collision on the canvas triggers a REAL
# agent-to-agent greet; click an interaction to see the two agents' own events.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build
go build -o bin/orchestrator ./cmd/orchestrator

UI_ADDR="127.0.0.1:18080"
echo "== starting orchestrator on http://$UI_ADDR =="
./bin/orchestrator --addr "$UI_ADDR" &
ORCH=$!
cleanup() { kill "$ORCH" 2>/dev/null || true; }
trap cleanup EXIT

sleep 3
URL="http://$UI_ADDR"
if command -v open >/dev/null 2>&1; then open "$URL"; else echo "open $URL"; fi

echo "orchestrator running (pid $ORCH). Press Ctrl-C to stop the whole mesh."
wait "$ORCH"
