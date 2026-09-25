#!/usr/bin/env bash
# P3b demo: start the registry, an authority, and a mandate-gated greeter. The
# greeter's card advertises that a mandate is required and points to the
# authority by role. meshctl discovers the greeter, follows the card to the
# authority, obtains a mandate over MCP (issue_mandate), and greets — with
# nothing hardcoded about who to talk to.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

REG_ADDR="127.0.0.1:18090"
AUTH_ADDR="127.0.0.1:18110"
GREETER_ADDR="127.0.0.1:18102"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/registry --addr "$REG_ADDR" & pids+=("$!")
sleep 0.5
./bin/authority --name authority-1 --addr "$AUTH_ADDR" --registry "http://$REG_ADDR" & pids+=("$!")
sleep 1
./bin/agent --name greeter-mandate --role greeter-mandate --addr "$GREETER_ADDR" \
	--registry "http://$REG_ADDR" --policy mandate --authority-role authority --scope greet & pids+=("$!")
sleep 1

echo "== meshctl greet (mandate-gated) =="
OUT=$(./bin/meshctl greet --from visitor --to-role greeter-mandate --text "hello there")
echo "$OUT"
echo "$OUT" | grep -q "reply:"

echo "P3b demo OK"
