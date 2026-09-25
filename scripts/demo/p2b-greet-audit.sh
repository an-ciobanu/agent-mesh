#!/usr/bin/env bash
# P2b demo: registry + transparency log + a sealing greeter. meshctl discovers
# the greeter, sends an identity-signed greet; the greeter seals a greet.completed
# statement to the log and returns the evidence; meshctl independently audits it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
TL_ADDR="127.0.0.1:18091"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
./bin/transparency --addr "$TL_ADDR" & pids+=("$!")
sleep 0.7

./bin/agent --name greeter-open --role greeter --addr 127.0.0.1:18101 \
  --registry "http://$REG_ADDR" --transparency "http://$TL_ADDR" & pids+=("$!")
sleep 1

echo "== meshctl greet --audit =="
OUT=$(./bin/meshctl greet --registry "http://$REG_ADDR" --transparency "http://$TL_ADDR" \
  --from visitor --to-role greeter --text "hello there" --audit)
echo "$OUT"

echo "$OUT" | grep -q "sealed: entry"
echo "$OUT" | grep -q "audit verdict: valid"
echo "P2b demo OK"
