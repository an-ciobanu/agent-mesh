#!/usr/bin/env bash
# P0 demo: start the registry, start two agents that self-register, then
# search the registry and fetch a discovered agent's card. Proves discovery
# works with no agent knowing another agent's address in advance.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5

./bin/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 --registry "http://$REG_ADDR" & pids+=("$!")
./bin/agent --name authority-1  --role authority --addr 127.0.0.1:18102 --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1

echo "== search role=greeter =="
curl -s "http://$REG_ADDR/search?role=greeter"; echo

echo "== fetch the greeter's agent card =="
CARD_URL=$(curl -s "http://$REG_ADDR/search?role=greeter" | \
  python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["cardURL"])')
curl -s "$CARD_URL"; echo

echo "== all agents =="
curl -s "http://$REG_ADDR/search"; echo

echo "P0 demo OK"
