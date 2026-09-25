#!/usr/bin/env bash
# P3a demo: start the registry and an authority; meshctl discovers the authority
# and requests a mandate over MCP (issue_mandate), then verifies the authority's
# COSE signature on it.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
AUTH_ADDR="127.0.0.1:18110"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5

./bin/authority --name authority-1 --addr "$AUTH_ADDR" --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1

echo "== meshctl mandate-check =="
OUT=$(./bin/meshctl mandate-check --registry "http://$REG_ADDR" --subject visitor --audience greeter-mandate --scope greet)
echo "$OUT"
echo "$OUT" | grep -q "mandate issued and verified OK"

echo "P3a demo OK"
