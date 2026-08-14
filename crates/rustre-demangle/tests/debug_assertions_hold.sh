#!/usr/bin/env bash
# The gates run release builds, where `debug_assert!` is compiled out — so an
# internal invariant can be wrong for iterations without anything noticing.
#
# It happened: iter 79 moved `dropped_swift_local_name` from substring matching to
# identifier-boundary matching but left its `debug_assert!` on the old predicate.
# `$s4main5outeryyF1aL_yyF` then panicked in **any** build with debug assertions
# on — every debug build a consumer makes — while all four release gates stayed
# green. Found at iter 81, one iteration later.
#
# This runs the suite as a RELEASE build (as the project requires) with assertions
# switched on, which is the cheapest way to exercise them without a debug build.
# An isolated target dir keeps the flag from invalidating the main one.
#
# Usage: bash crates/rustre-demangle/tests/debug_assertions_hold.sh
set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 1

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/c/Users/Fra/AppData/Local/Temp/claude/dm58}-da"
export RUSTFLAGS="-C debug-assertions=on"

echo "release build, debug assertions ON, target dir $CARGO_TARGET_DIR"
cargo test --release -p rustre-demangle 2>&1 \
  | grep -E '^test result|panicked at' \
  | awk '/panicked/ {print; bad=1}
         /test result/ {p+=$4; f+=$6; i+=$8}
         END {printf "PASS %d FAIL %d IGNORED %d\n", p, f, i; exit (bad || f>0) ? 1 : 0}'
