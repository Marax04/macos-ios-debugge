#!/usr/bin/env python3
"""Freeze the arity ground truth into `prototypes.json`.

WHY FREEZE IT: `fidelity.sh` hardcodes 16 prototypes, which is too small a sample
to see anything — one function is 6.25% of the score, so noise and signal have the
same amplitude. This widens the set to every corpus function whose prototype is
PUBLISHED in the installed mingw-w64 headers.

WHY A FILE AND NOT A LIVE SCAN: the metric must not move when the local msys
install is updated. A frozen file with provenance is auditable; a live scan is a
number whose basis changed silently. Same rule as `measure.sh`: no number from a
moving input.

Every entry carries the exact declaration it was derived from, so a disputed arity
can be checked by reading the row rather than trusting this parser.

Regenerate deliberately (and review the diff):
    python gen_prototypes.py [--inc C:/msys64/mingw64/include] [--out prototypes.json]
"""
import argparse
import json
import os
import re
import sys

# A declaration, not a definition: `... name ( args ) ;`. Deliberately strict —
# a missed prototype costs coverage, a wrong one corrupts the ground truth, and
# only the second failure mode is dangerous.
DECL = re.compile(
    r'(?:^|[;}\)]|\n)\s*'
    r'((?:[A-Za-z_][\w \*]*?[\w\*])\s+'
    r'(?:__cdecl\s+|__stdcall\s+|WINAPI\s+|__attribute__\s*\(\([^)]*\)\)\s*)*'
    r'([A-Za-z_]\w*)\s*\(([^;{)]*)\)\s*(?:__attribute__\s*\(\([^;]*\)\))?\s*;)',
    re.S,
)


# The original 16 from `fidelity.sh`. libgcc's unwind ABI and mingw's PE helpers
# are not declared in the scanned include tree, so a header scan alone would LOSE
# the very functions the metric was built on. Hand-verified against the published
# `unwind.h` / mingw-w64 runtime sources; kept verbatim so widening the sample can
# never silently narrow it.
CURATED = {
    "_Unwind_GetIP": 1, "_Unwind_GetCFA": 1, "_Unwind_GetGR": 2,
    "_Unwind_SetGR": 3, "_Unwind_SetIP": 2, "_Unwind_GetRegionStart": 1,
    "_Unwind_GetLanguageSpecificData": 1, "_Unwind_FindEnclosingFunction": 1,
    "_Unwind_DeleteException": 1, "_Unwind_Backtrace": 2, "_Unwind_Resume": 1,
    "_GetPEImageBase": 0, "_IsNonwritableInCurrentImage": 1,
    "_FindPESection": 2, "_pei386_runtime_relocator": 0,
    "__mingw_GetSectionForAddress": 1,
}


def arity(args: str):
    """Parameter count. -1 = variadic (excluded from the metric: the emitted
    signature legitimately cannot match a `...` prototype)."""
    args = args.strip()
    if args in ("", "void", "VOID"):
        return 0
    if "..." in args:
        return -1
    depth = n = 0
    n = 1
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            n += 1
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inc", default=r"C:\msys64\mingw64\include")
    ap.add_argument("--names", required=True,
                    help="file of function names observed in the corpus, one per line")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "prototypes.json"))
    a = ap.parse_args()

    if not os.path.isdir(a.inc):
        sys.exit(f"include dir not found: {a.inc}")

    wanted = {l.strip() for l in open(a.names) if l.strip()}
    wanted = {n for n in wanted if not re.match(r"^(sub|off|loc|unk|nullsub|j)_", n)}

    # Names defined by the corpus's OWN sources are not runtime functions, and a
    # header that happens to declare the same identifier is not their prototype.
    # Measured: `find_max` (sample1) collided with a pb_ds C++ template header and
    # `dot` (sample6) likewise — both would have been scored as phantom-parameter
    # failures against a prototype that has nothing to do with them.
    local = set()
    src_dir = os.path.join(os.path.dirname(os.path.abspath(a.out)), "src")
    if os.path.isdir(src_dir):
        fn_def = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{', re.M)
        for f in os.listdir(src_dir):
            if f.endswith((".c", ".cpp", ".cc", ".h")):
                try:
                    local |= set(fn_def.findall(
                        open(os.path.join(src_dir, f), encoding="utf-8", errors="ignore").read()))
                except OSError:
                    pass
    wanted -= local

    found, conflicts, files = {}, set(), 0
    for root, _, fs in os.walk(a.inc):
        # The C++ tree is templates and class members, not the C ABI this metric
        # is about; its declarations collide with ordinary identifiers.
        if os.sep + "c++" in root:
            continue
        for f in fs:
            if not f.endswith((".h", ".hpp")):
                continue
            files += 1
            try:
                text = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            rel = os.path.relpath(os.path.join(root, f), a.inc).replace("\\", "/")
            for m in DECL.finditer(text):
                whole, name, args = m.group(1), m.group(2), m.group(3)
                if name not in wanted:
                    continue
                n = arity(args)
                if name in found:
                    # Two headers disagree ⇒ this parser cannot be trusted for
                    # this name. Drop it rather than pick one: a wrong ground
                    # truth is worse than a smaller sample.
                    if found[name]["arity"] != n:
                        conflicts.add(name)
                    continue
                found[name] = {
                    "arity": n,
                    "header": rel,
                    "decl": " ".join(whole.split())[:200],
                }
    for name in conflicts:
        found.pop(name, None)

    # Curated entries WIN over a scanned one: they were verified by hand against
    # the published prototype, the scanner was not.
    for name, n in CURATED.items():
        found[name] = {
            "arity": n,
            "header": "curated (fidelity.sh, hand-verified)",
            "decl": f"published prototype, {n} parameter(s)",
        }

    fixed = {k: v for k, v in found.items() if v["arity"] >= 0}
    out = {
        "_provenance": {
            "source": "mingw-w64 installed headers",
            "include_dir": a.inc,
            "headers_scanned": files,
            "conflicting_dropped": sorted(conflicts),
            "note": "variadic prototypes are recorded with arity -1 and excluded "
                    "from the metric; an emitted signature cannot match `...`.",
        },
        "prototypes": dict(sorted(found.items())),
    }
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print(f"headers scanned      : {files}")
    print(f"names wanted         : {len(wanted)}")
    print(f"prototypes frozen    : {len(found)}  (non-variadic: {len(fixed)})")
    print(f"dropped (conflicting): {len(conflicts)} {sorted(conflicts)[:6]}")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
