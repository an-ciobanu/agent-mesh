#!/usr/bin/env bash
# P4b demo: start the registry and a nonce-gated greeter. The greeter's card
# advertises that a DPoP proof-of-possession is required; meshctl discovers the
# greeter, fetches a nonce from its get_nonce MCP tool, builds a P-256 DPoP proof
# over it, and greets. The nonce greeter is self-contained (no authority).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
GREETER_ADDR="127.0.0.1:18103"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5
./bin/agent --name greeter-nonce --role greeter-nonce --addr "$GREETER_ADDR" \
	--registry "http://$REG_ADDR" --policy nonce & pids+=("$!")
sleep 1

echo "== meshctl greet (nonce / DPoP-gated) =="
OUT=$(./bin/meshctl greet --from visitor --to-role greeter-nonce --text "hello there")
echo "$OUT"
echo "$OUT" | grep -q "reply:"

echo "P4b demo OK"
