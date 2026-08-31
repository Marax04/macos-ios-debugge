#!/usr/bin/env python3
"""Signature sanity: defects visible in the emitted signature alone.

Why a separate check when `check.sh` already fails these files: the
recompilability metric reports a single number over 11k files, so a naming defect
arrives as "33 failures" mixed in with an unrelated SSE type regression. Counting
this class on its own makes it trackable — it can go to zero while the SSE class
is still broken, and a regression in it cannot hide behind an unchanged total.

Currently detects:

  DUPLICATE_PARAM  the same identifier used twice in one parameter list, e.g.
                   `sub_140094540(struct ... *a1, int a2, int str, __int64 str)`.
                   The usage-based namer assigned `str` to two parameters without
                   uniquifying. gcc rejects it outright, so any function shaped
                   like this is unconditionally unusable — no judgement call.

  SHADOWS_KEYWORD  a parameter named as a C keyword or a common libc symbol,
                   which compiles in isolation but collides once the file is
                   included alongside real headers.

Both are decided by the text of the signature, so there is no inference here and
nothing to argue with: either the same name appears twice or it does not.

    python sig_sanity.py <snapshot-out-dir> [--json]
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



# `name(args) {` at line start. Control-flow keywords share this shape and must
# be excluded, a trap already documented in CLAUDE.md.
SIG = re.compile(r'^[A-Za-z_][\w \*]*?\b([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{', re.M)
KEYWORDS = {"if", "while", "for", "switch", "do", "else", "return", "sizeof"}
RESERVED = {"int", "char", "long", "short", "float", "double", "void", "struct",
            "union", "enum", "const", "static", "signed", "unsigned", "register"}


def param_names(args: str):
    """Identifier of each parameter, in order. Unnamed parameters yield None."""
    args = args.strip()
    if args in ("", "void"):
        return []
    out, depth, cur = [], 0, ""
    for ch in args:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    names = []
    for p in out:
        p = p.strip().rstrip("[]")
        m = re.search(r'([A-Za-z_]\w*)\s*$', p)
        names.append(m.group(1) if m and m.group(1) not in RESERVED else None)
    return names


def scan(out_dir):
    dup, shadow, total = [], [], 0
    for root, _, files in os.walk(out_dir):
        for f in sorted(files):
            if not _seleziona_unita(f):
                continue
            path = os.path.join(root, f)
            try:
                text = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for m in SIG.finditer(text):
                fname = m.group(1)
                if fname in KEYWORDS:
                    continue
                total += 1
                names = [n for n in param_names(m.group(2)) if n]
                seen = set()
                for n in names:
                    if n in seen:
                        dup.append((os.path.relpath(path, out_dir), fname, n))
                        break
                    seen.add(n)
                for n in names:
                    if n in RESERVED:
                        shadow.append((os.path.relpath(path, out_dir), fname, n))
                        break
    return total, dup, shadow


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    total, dup, shadow = scan(a.out_dir)
    if a.json:
        print(json.dumps({"signatures": total, "duplicate_param": len(dup),
                          "shadows_keyword": len(shadow)}))
        return 0 if not dup else 1

    for path, fn, name in dup[:20]:
        print(f"DUPLICATE_PARAM  {fn}  parameter '{name}' appears twice   [{path}]")
    for path, fn, name in shadow[:10]:
        print(f"SHADOWS_KEYWORD  {fn}  parameter '{name}'   [{path}]")
    print()
    print(f"signatures scanned : {total}")
    print(f"DUPLICATE_PARAM    : {len(dup)}   <-- rejected by any C compiler")
    print(f"SHADOWS_KEYWORD    : {len(shadow)}")
    return 0 if not dup else 1


if __name__ == "__main__":
    sys.exit(main())
