#!/bin/bash
# Usage: check.sh <dir-of-.c-files> — prints failing files with gcc error, tallies total/fail.
cd "$(dirname "$0")"
DIR="$1"
# Without this guard a bare `check.sh` globs `/*.c` and prints a confident
# `TOTAL: 1/1 passing` — a meaningless number that reads like a pass.
if [ -z "$DIR" ] || [ ! -d "$DIR" ]; then
  echo "usage: check.sh <dir-of-.c-files>" >&2
  exit 2
fi
total=0
fail=0
# Unique per-PID temp file — a shared path races when multiple check.sh
# instances (or overlapping foreground/background runs) run concurrently,
# producing spurious/flaky failure counts.
TMPC="/tmp/_check_$$.c"
trap 'rm -f "$TMPC"' EXIT
for f in "$DIR"/*.c; do
  # Skip *.hlil.c — a separate experimental HLIL pseudo-code dump (not the
  # recompilability target; e.g. contains dangling `goto ADDR;` with no
  # label), added alongside the normal .c files by ongoing HLIL work.
  case "$f" in *.hlil.c) continue ;; esac
  total=$((total+1))
  # -I"$DIR": whole-project reconstruction bucket files (`RUSTRE_BUCKET_BY_SOURCE=1`)
  # carry a relative `#include "<bucket>.h"`. The prelude is concatenated into
  # $TMPC under /tmp, so without this the include resolves against /tmp and every
  # bucket file fails with "No such file or directory" — a harness artifact that
  # looks exactly like emitted-code breakage. Measured: it accounted for all 12
  # failures in an 11156-file run.
  out=$(cat ida_defs.h "$f" > "$TMPC" 2>/dev/null; gcc -std=gnu89 -fsyntax-only -w -I"$DIR" "$TMPC" 2>&1)
  if [ -n "$out" ]; then
    fail=$((fail+1))
    echo "FAIL: $f"
    echo "$out" | head -5
    echo "---"
  fi
done
echo "TOTAL: $((total-fail))/$total passing"
