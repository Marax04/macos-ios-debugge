#!/usr/bin/env bash
# Gate 4, done correctly.
#
# `cargo test --release -p rustre-demangle -- --ignored` **stops at the first
# failing test binary**, so the aggregate reports only a prefix of the ignored
# set (discovered iter 54). Compensating by checking a few targets by hand is not
# enough either: that is how iters 54-76 reported "4 intentional failures" when
# the real number is 9 (discovered iter 77). This enumerates every target that
# has an ignored test and runs each one's ignored set.
#
# Expected baseline as of 2026-07-31: 12 ignored tests, 11 failing, 1 passing.
#
# Briefly 13/12/1 while `msvc_local_scope.rs::the_enclosing_overload_is_named`
# was an open gap; FIXED the next iteration (the function-tail parser gained a
# `_partial` variant), so the count returned to 12/11/1. A gap that turns out to
# be blocked on our own code rather than on ground truth belongs in the fixed
# column, not in this list.
#
# Was 11/10/1 until `d_storage_and_type_injectivity.rs::
# a_storage_class_and_a_type_constructor_render_differently` was added — a
# DOCUMENTED GAP, not a regression: D's `ref` storage class `K` and the `R` type
# constructor render identically, so two distinct symbols collapse into one
# name. Which side is wrong needs a D oracle, the same gate that blocks `__T…`
# template names and `Q<n>` back-references.
#
# Was 10/9/1 until `disambiguator_collisions.rs::
# disambiguators_should_not_collapse_distinct_symbols` was added — a DOCUMENTED
# GAP, not a regression: Zig and Clojure drop a numeric disambiguator and two
# distinct symbols render alike, and deciding whether that id names one entity
# or several needs a corpus for those languages. A rising count here is only
# acceptable with that kind of note; otherwise it means a gap was papered over
# by marking a failing test ignored.
# Every failure is intentional — each documents an open decision by asserting the
# behaviour that is *not* implemented, in this crate's house style.
#
#   convention_decoding    1  julia_codegen_prefixes_are_distinguishable
#   d_storage_and_type_injectivity 1 D `K` (ref storage) and `R` collide
#   disambiguator_collisions 1 Zig/Clojure disambiguators collapse distinct symbols
#   fidelity_demangle      1  fidelity_known_gaps                     (PASSES)
#   go_completeness        1  go_namespace_symbols_report_a_compound_as_a_bare_name
#   options_are_honoured   1  DemangleOptions is inert
#   path_equivalence       1  entry points disagree
#   swift_completeness     1  local_functions_do_not_lose_their_name
#   swift_signature_order  3  param/result inversion, methods, initializers
#   unused_registry        1  demangler_registry decodes less than the live path
#
# Usage: bash crates/rustre-demangle/tests/ignored_gate.sh
set -uo pipefail
cd "$(dirname "$0")/../../.." || exit 1

targets=$(grep -l 'ignore =' crates/rustre-demangle/tests/*.rs \
          | xargs -n1 basename | sed 's/\.rs$//')

total_pass=0
total_fail=0
for t in $targets; do
    line=$(cargo test --release -p rustre-demangle --test "$t" -- --ignored 2>&1 \
           | grep -E '^test result' | head -1)
    p=$(echo "$line" | sed -n 's/.* \([0-9]*\) passed.*/\1/p')
    f=$(echo "$line" | sed -n 's/.* \([0-9]*\) failed.*/\1/p')
    printf '%-24s passed=%s failed=%s\n' "$t" "${p:-?}" "${f:-?}"
    total_pass=$((total_pass + ${p:-0}))
    total_fail=$((total_fail + ${f:-0}))
done

# The lib target's ignored set, if any.
line=$(cargo test --release -p rustre-demangle --lib -- --ignored 2>&1 \
       | grep -E '^test result' | head -1)
p=$(echo "$line" | sed -n 's/.* \([0-9]*\) passed.*/\1/p')
f=$(echo "$line" | sed -n 's/.* \([0-9]*\) failed.*/\1/p')
printf '%-24s passed=%s failed=%s\n' "lib" "${p:-0}" "${f:-0}"
total_pass=$((total_pass + ${p:-0}))
total_fail=$((total_fail + ${f:-0}))

echo "----"
echo "ignored total: $((total_pass + total_fail))  passing: $total_pass  failing: $total_fail"
echo "baseline:      12                            1                    11"
