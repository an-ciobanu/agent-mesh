#!/usr/bin/env bash
# P2a demo: start the transparency log, then use meshctl tl-check to seal a
# COSE_Sign1 statement and independently verify the TL-signed receipt + RFC 6962
# inclusion proof.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

make build

TL_ADDR="127.0.0.1:18091"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

./bin/transparency --addr "$TL_ADDR" & pids+=("$!")
sleep 0.7

echo "== checkpoint (empty log) =="
curl -s "http://$TL_ADDR/checkpoint"; echo

echo "== meshctl tl-check (seal + verify) =="
OUT=$(./bin/meshctl tl-check --transparency "http://$TL_ADDR")
echo "$OUT"
echo "$OUT" | grep -q "inclusion proof verified OK"

echo "== checkpoint (after one entry) =="
curl -s "http://$TL_ADDR/checkpoint"; echo

echo "P2a demo OK"
