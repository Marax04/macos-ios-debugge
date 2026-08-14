#!/bin/bash
# Fidelity check: emitted signature ARITY vs the real, published prototype.
#
# Why this exists: the recompilability metric (check.sh) only proves the emitted
# C is syntactically and type-valid. It is BLIND to being confidently wrong —
# e.g. phantom parameters compile perfectly. A regression that invented 2233 of
# them left check.sh reading a flat 11143/11144. This script catches that class.
#
# The ground truth below is NOT guesswork: these are mingw-w64 / libgcc unwind
# functions with published prototypes, statically linked into the corpus binaries
# and recovered by name from their symbols.
#
# Usage: fidelity.sh [out-dir]   (default: ./out)
cd "$(dirname "$0")"
DIR="${1:-out}"
pass=0
fail=0

check() {
  local fn="$1" want="$2"
  local sig
  sig=$(grep -rhoE "^[a-zA-Z_][a-zA-Z_0-9 \*]*(__fastcall )?$fn\([^)]*\) \{" --include=*.c "$DIR" | head -1)
  if [ -z "$sig" ]; then
    echo "SKIP $fn (not found)"
    return
  fi
  local args got
  args=$(echo "$sig" | sed 's/.*'"$fn"'(\(.*\)) {/\1/')
  if [ -z "$args" ] || [ "$args" = "void" ]; then
    got=0
  else
    got=$(echo "$args" | tr ',' '\n' | wc -l)
  fi
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
    echo "OK   $fn: arity $got"
  else
    fail=$((fail + 1))
    echo "BAD  $fn: want $want, got $got  --  $sig"
  fi
}

# libgcc unwinder (unwind-dw2.c / unwind-generic.h).
check _Unwind_GetIP 1
check _Unwind_GetCFA 1
check _Unwind_GetGR 2
check _Unwind_SetGR 3
check _Unwind_SetIP 2
check _Unwind_GetRegionStart 1
check _Unwind_GetLanguageSpecificData 1
check _Unwind_FindEnclosingFunction 1
check _Unwind_DeleteException 1
check _Unwind_Backtrace 2
check _Unwind_Resume 1
# mingw-w64 PE helpers (pseudo-reloc.c / mingw_helpers.c).
check _GetPEImageBase 0
check _IsNonwritableInCurrentImage 1
check _FindPESection 2
check _pei386_runtime_relocator 0
check __mingw_GetSectionForAddress 1

echo "TOTAL: $pass/$((pass + fail)) signatures at the correct arity"
