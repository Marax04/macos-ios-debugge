#!/usr/bin/env python3
"""Cross-build consistency: the same function, reconstructed from several binaries.

The corpus statically links the same mingw/CRT runtime into all twelve programs,
so ~1361 named functions are reconstructed more than once from independently
compiled copies. That gives a signal no other metric here has:

    if two reconstructions of the same function disagree, at least one is wrong —
    and no ground truth is needed to know it.

`fidelity_arity.py` can only judge the ~135 functions with a published prototype.
This judges an order of magnitude more, for free, because the corpus is its own
control group.

WHAT IT DOES NOT PROVE, and this matters: consistency is not correctness. Six
builds can agree and all be wrong — `_Unwind_FindEnclosingFunction` is emitted
with 0 parameters everywhere and the published prototype says 1, so it is
perfectly consistent and uniformly incorrect. That is exactly why this
COMPLEMENTS the prototype ground truth rather than replacing it: one catches
uniform error, the other catches non-uniform error, and neither sees both.

A disagreement is also not automatically a bug in the emitter: a function can be
genuinely different between builds (`main` really does vary). The output names
the function and lists the per-build values so the call is a reading, not a
guess.

    python cross_build.py <snapshot-out-dir> [--json]
"""
import argparse
import collections
import json
import os
import re
import sys

# --- selettore path A / path B ---------------------------------------------
# Con MEASURE_PATH_B non impostata il predicato e' esattamente quello di prima
# (`.c` ma non `.hlil.c`), quindi le colonne path A restano confrontabili con
# lo storico. Con MEASURE_PATH_B=1 si misurano le unita' di path B.
_PATH_B = __import__("os").environ.get("MEASURE_PATH_B") == "1"


def _seleziona_unita(nome):
    """True se `nome` e' un'unita' del path attualmente misurato."""
    if _PATH_B:
        return nome.endswith(".hlil.c")
    return nome.endswith(".c") and not nome.endswith(".hlil.c")



SIG = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.M)
KEYWORDS = {"if", "while", "for", "switch", "do", "else", "return", "sizeof"}
# `fn_` e' la grafia sintetica di PATH B (misurato: 7368 file `.hlil.c` la
# definiscono, 0 file di path A). Senza di essa la metrica confrontava
# `fn_140001570` fra build INDIPENDENTI, cioe' due funzioni diverse che
# condividono solo un indirizzo: 197 dei 201 «incoerenti» di path B erano
# questo artefatto. Aggiungerla non puo' muovere path A (0 occorrenze).
SYNTHETIC = ("sub_", "off_", "loc_", "unk_", "nullsub", "j_", "fn_")

# `main` legitimately differs between programs (`main(void)` vs `main(argc, argv)`)
# and between a program's own entry point and the CRT's. Counting it as an
# inconsistency would put a permanent false positive in the metric.
EXEMPT = {"main", "WinMain", "wmain", "DllMain", "WinMainCRTStartup"}


def arity(args: str):
    args = args.strip()
    if args in ("", "void"):
        return 0
    if "..." in args:
        return -1
    depth = 0
    n = 1
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            n += 1
    return n


def collect(out_dir):
    """name -> {bucket: arity}. First definition per bucket wins."""
    seen = collections.defaultdict(dict)
    for bucket in sorted(os.listdir(out_dir)):
        bdir = os.path.join(out_dir, bucket)
        if not os.path.isdir(bdir):
            continue
        for f in sorted(os.listdir(bdir)):
            if not _seleziona_unita(f):
                continue
            try:
                text = open(os.path.join(bdir, f), encoding="utf-8",
                            errors="ignore").read()
            except OSError:
                continue
            for m in SIG.finditer(text):
                name = m.group(1)
                if name in KEYWORDS or name.startswith(SYNTHETIC):
                    continue
                seen[name].setdefault(bucket, arity(m.group(2)))
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    seen = collect(a.out_dir)
    multi = {n: v for n, v in seen.items() if len(v) >= 2 and n not in EXEMPT}
    disagree = {n: v for n, v in multi.items() if len(set(v.values())) > 1}

    if a.json:
        print(json.dumps({
            "compared": len(multi),
            "inconsistent": len(disagree),
            "names": sorted(disagree),
        }))
        return 0 if not disagree else 1

    for name in sorted(disagree):
        per = disagree[name]
        counts = collections.Counter(per.values())
        majority, _ = counts.most_common(1)[0]
        odd = [b for b, v in sorted(per.items()) if v != majority]
        print(f"INCONSISTENT  {name}: mostly {majority} params, "
              f"but {', '.join(f'{b}={per[b]}' for b in odd)}")
    print()
    print(f"functions in >=2 builds : {len(multi)}")
    print(f"INCONSISTENT arity      : {len(disagree)}")
    print("(consistency is not correctness: a function wrong in every build "
          "looks perfectly consistent here)")
    return 0 if not disagree else 1


if __name__ == "__main__":
    sys.exit(main())
