#!/bin/sh
# Builds the receipt verification page into a directory of static files.
# Usage: web/build.sh [OUTDIR]   (default: web/dist)
# Put a registry.json listing the operators and witnesses you trust next to
# the page; registry.example.json shows the format.
set -eu
cd "$(dirname "$0")/.."
out=${1:-web/dist}
mkdir -p "$out"
GOOS=js GOARCH=wasm go build -trimpath -ldflags=-s -o "$out/deedlog.wasm" ./web/wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/index.html web/app.js web/style.css "$out/"
echo "built $out (add registry.json)"
