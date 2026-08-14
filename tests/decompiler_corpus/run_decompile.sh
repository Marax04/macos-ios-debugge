#!/usr/bin/env bash
# Decompile every corpus binary with the dump_decompile driver.
# Output: out/<binary-stem>/sub_*.c per function.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
DRIVER="$HERE/../../target/release/examples/dump_decompile.exe"
if [ ! -x "$DRIVER" ]; then
  echo "driver not built: $DRIVER" >&2
  exit 1
fi
mkdir -p "$HERE/out"
for bin in "$HERE"/bin/*.exe; do
  stem="$(basename "$bin" .exe)"
  outdir="$HERE/out/$stem"
  rm -rf "$outdir"; mkdir -p "$outdir"
  echo "=== $stem ==="
  "$DRIVER" "$bin" "$outdir" 2>&1 | head -3
  echo "  files: $(ls "$outdir"/*.c 2>/dev/null | wc -l)"
done
