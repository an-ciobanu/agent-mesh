#!/usr/bin/env bash
# P1 demo: start the registry, start an open greeter agent, then use meshctl to
# discover it by role and send an identity-signed greet. Proves a signed greet
# flows end-to-end with no agent hardcoding another's address or keys.
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
sleep 1

echo "== meshctl greet (visitor -> role=greeter) =="
OUT=$(./bin/meshctl greet --registry "http://$REG_ADDR" --from visitor --to-role greeter --text "hello there")
echo "$OUT"

echo "$OUT" | grep -q "this is ans://v1.0.0.greeter-open.mesh.local"
echo "P1 demo OK"
