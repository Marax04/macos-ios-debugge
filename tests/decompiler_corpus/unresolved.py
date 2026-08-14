#!/usr/bin/env python3
"""Unresolved data symbols: what the emitted project references but never defines.

The finding this exists to track: across the corpus the decompiler emits **22773
`extern __int64 off_…;` declarations and zero definitions**. Not one. Every
reference to an in-image data address is declared external and nothing ever
provides it, so 5564 of 11144 emitted files (49.9%) cannot link on their own.

`check.sh` cannot see this and is not wrong not to: `-fsyntax-only` accepts an
`extern` with no definition, by design. That is exactly why "99.7% recompilable"
and "half the project cannot link" are both true at once — they measure different
things, and only one of them was being measured.

WHAT IS AND IS NOT THE DECOMPILER'S FAULT — the raw count overstates the defect,
so this classifies each address by the PE section it lands in:

  .rdata/.data/.bss   real in-image data (jump tables, string constants, globals)
                      that the emitter could materialise and does not. ACTIONABLE.
  .text               a CODE address declared as data — the `apply` class, where
                      `off_140001480` is `add_fn`, a function emitted a few files
                      away. Small in number, sharpest as a defect.
  outside the image   addresses in no section at all — relocations and
                      runtime-resolved references, concentrated in the C# and Rust
                      buckets. Leaving these `extern` is defensible; counting them
                      as missing data was an error in the first estimate here
                      (it put the actionable figure ~15x too high).

So the headline number to track is `actionable`, not `total`.

    python unresolved.py <snapshot-out-dir> [--json]
"""
import argparse
import collections
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXTERN = re.compile(r'extern\s+[\w \*]+?\boff_([0-9A-Fa-f]+)\s*;')
# A DEFINITION allocates storage: `__int64 off_X;` or `__int64 off_X = …;` at
# file scope. An assignment inside a function body (`off_140007008 = v3;`) is a
# USE and satisfies no linker.
#
# The first version of this pattern accepted both and reported 2350 "defined"
# symbols, contradicting the finding it was written to track. Every match was a
# store into a global. Requiring a type before the name is what separates the two.
#
# 2026-08-06: la seconda forma. `RUSTRE_EMIT_DATA` + `RUSTRE_HLIL_ADDROF`
# definiscono l'oggetto come ARRAY (`static uint8_t off_X[64] = { … };`), e il
# pattern — che pretendeva `=` o `;` SUBITO dopo il nome — non lo vedeva:
# riportava "0 defined" mentre nel testo c'erano 1936 definizioni. La metrica
# misurava il mondo di prima. Il `\[[^\]]*\]` opzionale copre entrambe le forme.
DEFINED = re.compile(
    r'^(?!\s*extern\b)[A-Za-z_][\w]*[\w \*]*\boff_([0-9A-Fa-f]+)\s*(?:\[[^\]]*\])?\s*(?:=[^;]*)?;',
    re.M)
ACTIONABLE_SECTIONS = {".rdata", ".data", ".bss"}


def sections(exe):
    """(start, end, name) per PE section, from objdump -h."""
    try:
        out = subprocess.run(["objdump", "-h", exe], capture_output=True,
                             text=True).stdout
    except OSError:
        return []
    secs = []
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 6 and p[1].startswith("."):
            try:
                size, vma = int(p[2], 16), int(p[3], 16)
            except ValueError:
                continue
            secs.append((vma, vma + size, p[1]))
    return sorted(secs)


def section_of(secs, addr):
    for lo, hi, name in secs:
        if lo <= addr < hi:
            return name
    return "outside_image"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--bin", default=os.path.join(HERE, "bin"))
    a = ap.parse_args()

    by_section = collections.Counter()
    per_bucket, total_files, files_with_unresolved, defined_total = {}, 0, 0, 0

    for bucket in sorted(os.listdir(a.out_dir)):
        bdir = os.path.join(a.out_dir, bucket)
        if not os.path.isdir(bdir):
            continue
        secs = sections(os.path.join(a.bin, bucket + ".exe"))
        syms, bad, n = set(), 0, 0
        for f in sorted(os.listdir(bdir)):
            if not f.endswith(".c") or f.endswith(".hlil.c"):
                continue
            n += 1
            try:
                text = open(os.path.join(bdir, f), encoding="utf-8",
                            errors="ignore").read()
            except OSError:
                continue
            found = set(EXTERN.findall(text))
            defined_total += len(DEFINED.findall(text))
            if found:
                bad += 1
                syms |= found
        total_files += n
        files_with_unresolved += bad
        if secs:
            for s in syms:
                by_section[section_of(secs, int(s, 16))] += 1
        else:
            by_section["unknown_no_binary"] += len(syms)
        per_bucket[bucket] = {"files": n, "files_with_unresolved": bad,
                              "distinct_symbols": len(syms)}

    actionable = sum(v for k, v in by_section.items() if k in ACTIONABLE_SECTIONS)
    code_as_data = by_section.get(".text", 0)

    if a.json:
        print(json.dumps({
            "files": total_files,
            "files_with_unresolved": files_with_unresolved,
            "data_symbols_defined": defined_total,
            "actionable": actionable,
            "code_as_data": code_as_data,
            "by_section": dict(by_section),
        }))
        return 0

    for b, v in sorted(per_bucket.items(),
                       key=lambda kv: -kv[1]["files_with_unresolved"]):
        print(f"  {b:14} {v['files_with_unresolved']:4}/{v['files']:<4} files, "
              f"{v['distinct_symbols']} distinct symbols")
    print()
    print(f"files with an unresolved reference : {files_with_unresolved}/{total_files}"
          f" ({100.0 * files_with_unresolved / max(total_files, 1):.1f}%)")
    print(f"data symbols actually DEFINED      : {defined_total}")
    print(f"ACTIONABLE (.rdata/.data/.bss)     : {actionable}")
    print(f"code addresses declared as data    : {code_as_data}   <-- the `apply` class")
    print(f"outside the image (likely fine)    : {by_section.get('outside_image', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
