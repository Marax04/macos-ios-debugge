#!/usr/bin/env python3
"""Arity fidelity with a gradient: emitted signature vs published prototype.

Replaces `fidelity.sh`'s 16 hardcoded checks with the frozen set in
`prototypes.json` (~140). Why that matters: at n=16 a single function is 6.25% of
the score, so an ordinary fluctuation and a real regression are indistinguishable.
This reports a percentage over a sample where one function is <1%.

It also splits the failures, which `fidelity.sh` does not:

  OVER  emitted MORE parameters than exist — the phantom-parameter class. This is
        the dangerous one: it compiles perfectly, so the recompilability metric is
        structurally blind to it, and it is *confidently wrong* output.
  UNDER emitted FEWER — visible incompleteness. Bad, but honest.

A single "15/16" cannot tell those apart, and they have opposite causes
(over-recovery of live registers vs. missed stack arguments).

    python fidelity_arity.py <snapshot-out-dir> [--json]
    # e.g. python fidelity_arity.py runs/baseline/out
"""
import argparse
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



HERE = os.path.dirname(os.path.abspath(__file__))

# `name(args) {` at the start of a line — a definition, not a call. Control-flow
# keywords must be excluded: `while (x) {` matches the same shape, a trap already
# documented in CLAUDE.md.
KEYWORDS = {"if", "while", "for", "switch", "do", "else", "return", "sizeof"}


def emitted_arity(args: str):
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


def scan(out_dir, wanted):
    """name -> (arity, signature) of the WORST definition found.

    "First definition wins" was wrong, and measurably so: `__acrt_iob_func` is
    emitted correctly with 1 parameter in five builds and with a phantom second
    parameter in `sample7_cpp`. Taking the first match scored it correct and hid
    the defect entirely — `cross_build.py` had to find it. The same runtime is
    linked into every corpus binary, so a name recurring is not a reason to
    assume the recurrences are identical.

    A function now counts as correct only if EVERY definition of it is correct;
    when they differ, the mismatching one is reported, because that is the one
    that needs fixing.
    """
    sig_re = re.compile(
        r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.M)
    seen = {}
    for root, _, files in os.walk(out_dir):
        for f in files:
            if not _seleziona_unita(f):
                continue
            try:
                text = open(os.path.join(root, f), encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for m in sig_re.finditer(text):
                name = m.group(1)
                if name in KEYWORDS or name not in wanted:
                    continue
                got = emitted_arity(m.group(2))
                sig = " ".join(m.group(0).split())
                prev = seen.get(name)
                # Keep the definition that DISAGREES with the prototype, so a
                # single bad build cannot be masked by several good ones.
                if prev is None or (prev[0] == wanted[name] and got != wanted[name]):
                    seen[name] = (got, sig)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--protos", default=os.path.join(HERE, "prototypes.json"))
    a = ap.parse_args()

    truth = json.load(open(a.protos))["prototypes"]
    truth = {k: v for k, v in truth.items() if v["arity"] >= 0}  # variadic excluded

    emitted = scan(a.out_dir, {k: v["arity"] for k, v in truth.items()})
    ok, over, under, missing = [], [], [], []
    for name, t in sorted(truth.items()):
        if name not in emitted:
            missing.append(name)          # not defined in this corpus build
            continue
        got, sig = emitted[name]
        if got == -1:
            continue
        if got == t["arity"]:
            ok.append(name)
        elif got > t["arity"]:
            over.append((name, t["arity"], got, sig, t["header"]))
        else:
            under.append((name, t["arity"], got, sig, t["header"]))

    checked = len(ok) + len(over) + len(under)
    pct = 100.0 * len(ok) / checked if checked else 0.0

    if a.json:
        print(json.dumps({
            "checked": checked, "correct": len(ok),
            "over": len(over), "under": len(under),
            "not_present_in_build": len(missing),
            "pct": round(pct, 2),
        }))
        return 0 if not (over or under) else 1

    for name, want, got, sig, hdr in over:
        print(f"OVER   {name}: want {want}, got {got}   [{hdr}]\n         {sig}")
    for name, want, got, sig, hdr in under:
        print(f"UNDER  {name}: want {want}, got {got}   [{hdr}]\n         {sig}")
    print()
    print(f"checked              : {checked} of {len(truth)} known prototypes "
          f"({len(missing)} not present in this build)")
    print(f"correct arity        : {len(ok)}  ({pct:.1f}%)")
    print(f"OVER  (phantom args) : {len(over)}   <-- compiles clean, silently wrong")
    print(f"UNDER (missed args)  : {len(under)}")
    return 0 if not (over or under) else 1


if __name__ == "__main__":
    sys.exit(main())
