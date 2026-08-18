#!/usr/bin/env python3
"""Behavioural fidelity: does the emitted C *do* what the original did?

Every other metric in this repo stops short of the actual goal:

  check.sh        proves the C parses and type-checks (`-fsyntax-only`).
  fidelity_arity  proves the SIGNATURE has the right number of parameters.
  neither         ever links the result, and neither ever runs it.

"Syntactically valid" and "reconstructed" are different claims, and only the
second is the stated goal of this project. This measures the second: compile the
emitted function, LINK it, CALL it next to the original compiled from source,
on identical inputs, and compare the returned values.

The outcomes are deliberately distinct, because each points at a different bug:

  NOT_EMITTED   no definition of this function in the snapshot at all
  COMPILE_FAIL  the emitted C does not compile standalone
  LINK_FAIL     it compiles but references symbols nothing provides (cold-path
                splits, jump tables, other `sub_` bodies) — the reconstruction is
                not self-contained, which `-fsyntax-only` cannot see
  CRASH         it ran and died — typically a mis-typed pointer walking off an
                array (`find_max` in the unrolled build)
  HANG          it ran and never returned within EXEC_TIMEOUT_S — a lost loop
                exit condition, a defect class already seen in this project
  DIVERGE       it ran and returned different values, or left a buffer different
  AGREE         same values on every input, and same buffer contents after

Collapsing CRASH and HANG into one "failed" bucket would hide which of two very
different defects is present, so they stay separate.

A DIVERGE is worth more than any syntactic number: it is a concrete input on
which the reconstruction is wrong, which is the only kind of evidence that
cannot be argued with.

    python behavior.py <snapshot-out-dir> [--json] [--keep]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CC = "gcc"
# Generous enough for a 20k-case sweep, short enough that a lost loop exit is
# reported in seconds instead of wedging the run.
EXEC_TIMEOUT_S = 60


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def find_definition(bucket_dir, name):
    """The emitted .c defining `name`. Control-flow keywords can't appear here
    because we anchor on the exact identifier followed by `(`...`) {`."""
    pat = re.compile(r'^[A-Za-z_][\w \*]*?\b' + re.escape(name) + r'\s*\([^)]*\)\s*\{', re.M)
    for f in sorted(os.listdir(bucket_dir)):
        if not f.endswith(".c") or f.endswith(".hlil.c"):
            continue
        p = os.path.join(bucket_dir, f)
        try:
            if pat.search(open(p, encoding="utf-8", errors="ignore").read()):
                return p
        except OSError:
            pass
    return None


def undefined_symbols(obj):
    r = run(["nm", "-u", obj])
    syms = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if parts and parts[-1] not in ("U", "w"):
            syms.append(parts[-1])
    # nm prints "        U name"
    syms = [l.split()[-1] for l in r.stdout.splitlines() if l.strip().startswith("U ")]
    return sorted(set(syms))


def c_literal(v, ctype):
    if ctype.startswith("uint64"):
        return f"{v}ULL"
    if ctype.startswith("int64"):
        return f"{v}LL"
    if v == -2147483648:
        return "(-2147483647-1)"
    return str(v)


def init_text(v):
    """C initialiser for a buffer element: a scalar, or a brace list for a struct."""
    if isinstance(v, list):
        return "{" + ", ".join(init_text(x) for x in v) + "}"
    return str(v)


def build_harness(work, spec_fn, name, harness_prelude=""):
    """Harness calls reference and emitted side by side and prints one line per
    input. Values are printed, not just compared, so a divergence is readable.

    Buffer arguments get TWO independent copies, one per side, and the buffers are
    compared after the call as well as the return value. Several corpus functions
    write through their pointer (`accumulate` fills `pts[i].sum`); comparing only
    the return value would pass a reconstruction that writes the right total into
    the wrong field.
    """
    ret, args = spec_fn["ret"], spec_fn["args"]
    proto_args = ", ".join(args) if args else "void"
    lines = [
        '#include <stdio.h>',
        '#include <stdint.h>',
        '#include <stddef.h>',
        '#include <string.h>',
        harness_prelude,
        f'extern {ret} {name}({proto_args});',
        f'extern {ret} em_{name}({proto_args});',
        "",
        "int main(void) {",
        "    int diverged = 0;",
    ]
    fmt = "%llu" if ret.startswith("uint64") else "%lld"
    for case_no, inp in enumerate(spec_fn["inputs"]):
        setup, ref_call, em_call, cmps = [], [], [], []
        for i, (v, ctype) in enumerate(zip(inp, args)):
            if isinstance(v, dict) and "buf" in v:
                elem = v.get("elem", ctype.replace("const", "").replace("*", "").strip())
                init = ", ".join(init_text(x) for x in v["buf"])
                setup += [
                    f"        {elem} rb{i}[] = {{{init}}};",
                    f"        {elem} eb{i}[] = {{{init}}};",
                ]
                ref_call.append(f"rb{i}")
                em_call.append(f"eb{i}")
                cmps.append(
                    f'        if (memcmp(rb{i}, eb{i}, sizeof(rb{i})) != 0) '
                    f'{{ diverged = 1; printf("DIVERGE case {case_no} arg {i}: '
                    f'buffer contents differ after call\\n"); }}')
            elif isinstance(v, dict) and "str" in v:
                s = v["str"].replace('\\', '\\\\').replace('"', '\\"')
                setup += [f'        char rb{i}[] = "{s}";', f'        char eb{i}[] = "{s}";']
                ref_call.append(f"rb{i}")
                em_call.append(f"eb{i}")
            else:
                lit = c_literal(v, ctype)
                ref_call.append(lit)
                em_call.append(lit)
        tag = f"case {case_no}"
        lines += ["    {"] + setup + [
            f"        {ret} r = {name}({', '.join(ref_call)});",
            f"        {ret} e = em_{name}({', '.join(em_call)});",
            f'        if (r != e) {{ diverged = 1; printf("DIVERGE {tag} ref={fmt} emitted={fmt}\\n",'
            f' (long long)r, (long long)e); }}',
        ] + cmps + ["    }"]
    # Randomised sweep over the declared ranges, on top of the curated cases.
    #
    # A hand-picked list proves the boundaries; it does not prove the ordinary
    # middle. `dot` agreeing on three inputs is weak evidence — the same function
    # agreeing on ten thousand is not. The generator is a fixed-seed xorshift
    # inlined in the harness, so the sweep is deterministic: a divergence found
    # here reproduces exactly, and the metric does not flicker between runs.
    #
    # Scalars only. A random buffer would also need a random length, and getting
    # that wrong reads as a decompiler bug when it is a harness bug.
    #
    # What this does and does NOT prove, verified by injecting a known divergence:
    # a DENSE one (wrong for half the range) is caught immediately, a single magic
    # value inside a 100k-wide range survived 5000 draws. So an AGREE over a sweep
    # means "no broad disagreement", never "proven equivalent" -- the curated cases
    # remain the ones that pin down the boundaries.
    rnd = spec_fn.get("random")
    if rnd and all(not isinstance(r, dict) for r in (spec_fn["inputs"][0] if spec_fn["inputs"] else [])):
        ranges = rnd["ranges"]
        lines += [
            "    {",
            "        unsigned long long s = 0x2545F4914F6CDD1DULL;  /* fixed seed */",
            "        int shown = 0;",
            f"        for (long it = 0; it < {int(rnd['cases'])}; it++) {{",
        ]
        for i, (ctype, (lo, hi)) in enumerate(zip(args, ranges)):
            span = int(hi) - int(lo) + 1
            lines += [
                "            s ^= s << 13; s ^= s >> 7; s ^= s << 17;",
                f"            {ctype} v{i} = ({ctype})({lo} + (long long)(s % {span}ULL));",
            ]
        call = ", ".join(f"v{i}" for i in range(len(args)))
        lines += [
            f"            {ret} r = {name}({call});",
            f"            {ret} e = em_{name}({call});",
            "            if (r != e) { diverged = 1; if (shown++ < 3) printf("
            f'"DIVERGE random ref={fmt} emitted={fmt}\\n", (long long)r, (long long)e); }}',
            "        }",
            "    }",
        ]

    lines += ['    if (!diverged) printf("AGREE\\n");', "    return 0;", "}"]
    p = os.path.join(work, f"harness_{name}.c")
    open(p, "w").write("\n".join(lines))
    return p


def linker_for(source):
    """Driver to link the final executable with, chosen by reference language.

    C, Rust and Go all link with plain `gcc`: none of them needs libstdc++ or the
    Itanium exception ABI on the final line (the Rust staticlib and the Go
    c-archive are self-contained apart from the system libraries listed by
    `extra_link_args`). Only C++ needs `g++`.
    """
    ext = os.path.splitext(source)[1].lower()
    return "g++" if ext in (".cpp", ".cc") else CC


# Windows system libraries the Rust `staticlib` reference pulls in (libstd's
# std::sys layer). They must come AFTER the objects on the link line, which is
# where `check_one` appends them. Verified necessary for sample8_rust_features.rs
# (Vec/Box/str::parse) and harmless for sample3.
RUST_STATICLIB_LIBS = ["-lws2_32", "-lntdll", "-luserenv", "-lbcrypt",
                       "-lole32", "-loleaut32", "-ladvapi32"]


def extra_link_args(bspec):
    """Trailing `-l` flags a bucket's reference build requires, if any."""
    if bspec.get("reference_mode") == "staticlib" and \
            os.path.splitext(bspec["source"])[1].lower() == ".rs":
        return list(RUST_STATICLIB_LIBS)
    return list(bspec.get("link_libs", []))


def build_reference(work, bucket, src, bspec=None):
    """Compile the ORIGINAL source into something the harness can call.

    One entry point per language, because "the reference" means a different
    build for each — but the requirement is identical in all cases: the original
    function must end up callable through the plain C ABI, and `main` must not
    collide with the harness's own.

    The corpus sources were written for this: the C++ ones declare their
    functions `extern "C"` and the Rust ones `#[no_mangle] pub extern "C"`, so no
    name mangling and no unstable ABI stands in the way. That is a property of
    the corpus, not luck, and it is what makes cross-language coverage cheap.

    Returns (object_path, None) or (None, error_message).
    """
    bspec = bspec or {}
    ext = os.path.splitext(src)[1].lower()
    obj = os.path.join(work, f"{bucket}_ref.o")

    if ext == ".c":
        r = run([CC, "-std=gnu99", "-w", "-Dmain=ref_main_unused",
                 "-c", src, "-o", obj])
    elif ext in (".cpp", ".cc"):
        # `-Dmain=` would also rename the C++ `main`, which is what we want; the
        # `extern "C"` functions keep their unmangled names either way.
        r = run(["g++", "-std=gnu++17", "-w", "-Dmain=ref_main_unused",
                 "-c", src, "-o", obj])
    elif ext == ".rs":
        # Two modes, because one does not cover both Rust samples.
        #
        # default ("obj"): `--crate-type=lib --emit=obj` keeps only what the
        #   source defines, which is all the harness needs from
        #   `#[no_mangle] extern "C"` functions, and avoids dragging a second
        #   runtime into a C link. Sufficient for sample3_struct_loop.rs, whose
        #   object has no undefined symbols at all.
        # "staticlib": required by any source that touches std's allocator
        #   (sample8_rust_features.rs uses Vec/Box/str::parse). With `--emit=obj`
        #   that source leaves `__rustc::__rust_no_alloc_shim_is_unstable_v2`
        #   undefined; supplying the symbol by hand links but then segfaults,
        #   because the allocator itself is still missing. A staticlib emits no
        #   `main`, so no `-Dmain=` equivalent is needed, but it does need the
        #   system libraries in RUST_STATICLIB_LIBS on the final link line.
        #
        # Keep `-C opt-level=2` WITHOUT `-C debug-assertions`: the reference then
        # has wrapping integer arithmetic, which the spec's overflow-edge inputs
        # depend on.
        if bspec.get("reference_mode") == "staticlib":
            lib = os.path.join(work, f"lib{bucket}_ref.a")
            r = run(["rustc", "--edition=2021", "--target", "x86_64-pc-windows-gnu",
                     "--crate-type=staticlib", "-C", "opt-level=2",
                     "-C", "panic=abort", "-o", lib, src])
            if r.returncode != 0:
                return None, "reference build failed (.rs staticlib): " + r.stderr.strip()[:300]
            return lib, None
        r = run(["rustc", "--edition=2021", "--crate-type=lib", "--emit=obj",
                 "-C", "opt-level=2", "-C", "panic=abort",
                 "-o", obj, src])
    elif ext == ".go":
        # Nothing is compiled here. A Go function cannot be called from C at all
        # (Go's internal register ABI plus a runtime that must be initialised),
        # so the reference is a PREBUILT cgo `c-archive` of `//export`ed shims:
        #     cd behav/goref && go build -buildmode=c-archive -o libgoref.a .
        # The shims are named exactly as the decompiler names the functions
        # (`main_accumulate`, not `accumulate`) because the harness calls the
        # reference by the same name it looks up in the bucket. The archive works
        # everywhere `src_obj` is used: it only ever lands on the final link line,
        # last. It needs no extra `-l` flags and no explicit runtime init -- the
        # archive's constructor self-initialises the Go runtime. `main` is not
        # exported, so nothing collides with the harness's own.
        arc = bspec.get("reference_archive", "behav/goref/libgoref.a")
        arc = arc if os.path.isabs(arc) else os.path.join(HERE, arc)
        if not os.path.exists(arc):
            return None, (f"go reference archive missing: {arc} "
                          "(run: cd behav/goref && go build -buildmode=c-archive -o libgoref.a .)")
        return arc, None
    else:
        return None, f"no reference compiler wired for '{ext}' sources"

    if r.returncode != 0:
        return None, f"reference build failed ({ext}): " + r.stderr.strip()[:300]
    return obj, None


def build_bucket(work, bucket_dir, prelude, ref_names, obj_of_file):
    """Compile EVERY emitted body in the bucket into one linkable set.

    Single-file linking answers "is this function self-contained?", which the
    compiler's own output rarely is: `classify` is split into a hot body plus a
    `classify_cold` tail, and an indirect call lands on a `off_…` target defined
    in a different emitted file. Linking the whole bucket asks the question this
    project actually cares about — does the RECONSTRUCTION link as a project.

    Every symbol the original source also defines is prefixed `em_`, so the
    emitted and reference bodies can coexist in one executable and be compared
    against each other rather than silently resolving to the same definition.
    """
    objs, failed = [], []
    renames = os.path.join(work, "renames.txt")
    with open(renames, "w") as fh:
        for n in sorted(ref_names):
            fh.write(f"{n} em_{n}\n")
        fh.write("main em_main_unused\n")

    for f in sorted(os.listdir(bucket_dir)):
        if not f.endswith(".c") or f.endswith(".hlil.c"):
            continue
        unit = os.path.join(work, "u_" + f)
        with open(unit, "w", encoding="utf-8") as out:
            out.write(open(prelude, encoding="utf-8").read())
            out.write("\n")
            out.write(open(os.path.join(bucket_dir, f), encoding="utf-8",
                           errors="ignore").read())
        obj = unit[:-2] + ".o"
        r = run([CC, "-std=gnu89", "-w", "-c", unit, "-o", obj, "-I", bucket_dir])
        if r.returncode != 0:
            failed.append(f)
            continue
        run(["objcopy", "--redefine-syms", renames, obj])
        objs.append(obj)
        obj_of_file[f] = obj
    return objs, failed


def symbol_tables(objs):
    """defined-symbol -> object, and object -> undefined symbols."""
    defines, needs = {}, {}
    for o in objs:
        u = []
        for line in run(["nm", o]).stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "U":
                u.append(parts[1])
            elif len(parts) >= 3 and parts[1] not in ("U", "u"):
                defines.setdefault(parts[2], o)
        needs[o] = u
    return defines, needs


def closure(root_obj, defines, needs):
    """Objects transitively required by `root_obj`.

    Linking the whole bucket makes one file's unresolved data symbol block every
    function in the sample — an unrelated failure reported as if it were this
    function's. The closure asks the narrower, answerable question: is THIS
    reconstruction complete, together with everything it actually calls."""
    seen, stack = {root_obj}, [root_obj]
    while stack:
        o = stack.pop()
        for sym in needs.get(o, []):
            owner = defines.get(sym)
            if owner and owner not in seen:
                seen.add(owner)
                stack.append(owner)
    return sorted(seen)


def classify_missing(sym, bucket_dir):
    """Turn an unresolved symbol into a diagnosis.

    "needs off_140001480" says nothing about what to fix. The three cases behind
    it are entirely different defects, and the corpus has one of each:

      REFERENCED_AS_DATA  the address IS emitted, as a function, in this very
                          bucket — `apply` declares `extern __int64 off_140001480`
                          and takes its address, while `sub_140001480.c` defines
                          `add_fn` at exactly that address. Nothing is missing:
                          one site classified an address as data and another as
                          code. This is the cheap one to fix.
      INTERIOR_ADDRESS    a branch into the middle of an emitted function
                          (`sub_1400014C5` lies inside the body at 0x1400014a0),
                          i.e. a cold-path split never given its own definition.
      DATA_NOT_EMITTED    a real data address (a switch jump table) that no
                          emitted file defines.

    LIMIT, stated rather than glossed over: only REFERENCED_AS_DATA is exact (the
    address equals an emitted entry point). INTERIOR_ADDRESS infers from "falls
    between two function starts", which holds in this corpus because `.rdata`
    sits above `.text` — a data word placed *between* two functions would be
    labelled INTERIOR. Treat that label as a strong hint, not a proof; the other
    two are decidable.
    """
    m = re.match(r'^(?:off|sub|loc|unk)_([0-9A-Fa-f]+)$', sym)
    if not m:
        return "external"
    addr = int(m.group(1), 16)
    summary = os.path.join(bucket_dir, "summary.json")
    try:
        funcs = sorted(f["address"] for f in json.load(open(summary))["files"])
    except (OSError, ValueError, KeyError):
        return "unknown"
    if addr in funcs:
        return "REFERENCED_AS_DATA (address is an emitted function)"
    import bisect
    i = bisect.bisect_right(funcs, addr) - 1
    # Interior only if it lands before the next function start, i.e. plausibly
    # inside that body rather than in a distant data region.
    if i >= 0 and i + 1 < len(funcs) and funcs[i] < addr < funcs[i + 1]:
        return f"INTERIOR_ADDRESS (inside emitted {hex(funcs[i])})"
    return "DATA_NOT_EMITTED"


def check_one(work, bucket_dir, src_obj, name, spec_fn, prelude, bucket_objs,
              defines, needs, obj_of_file, harness_prelude="", linker=None,
              link_libs=()):
    emitted_c = find_definition(bucket_dir, name)
    if not emitted_c:
        return {"status": "NOT_EMITTED"}
    root = obj_of_file.get(os.path.basename(emitted_c))
    if not root:
        return {"status": "COMPILE_FAIL", "file": os.path.basename(emitted_c)}

    parts = closure(root, defines, needs)
    h = build_harness(work, spec_fn, name, harness_prelude)
    exe = os.path.join(work, f"{name}.exe")
    # The harness is COMPILED as C and only LINKED with the reference language's
    # driver. Handing a `.c` file to `g++` compiles it as C++, which mangles the
    # harness's own declarations and makes every symbol undefined -- a harness
    # artefact that reads exactly like a decompiler defect (`em_total_area(int):
    # external`). The link driver still matters: emitted C++ bodies need the
    # Itanium exception ABI and libstdc++, which `gcc` does not pull in.
    h_obj = h[:-2] + "_h.o"
    r = run([CC, "-std=gnu99", "-w", "-c", h, "-o", h_obj])
    if r.returncode != 0:
        return {"status": "HARNESS_FAIL", "error": r.stderr.strip()[:200]}
    # Link order matters: harness, reference, emitted closure, then any system
    # libraries the reference needs (a static archive only resolves symbols that
    # are still undefined at the point it appears).
    # Link order matters: harness, reference, emitted closure, then any system
    # libraries the reference needs. A static ARCHIVE reference (Go c-archive,
    # Rust staticlib) goes AFTER the emitted objects instead of before them -- an
    # archive only contributes members that resolve symbols still undefined at
    # the point where it appears on the line.
    if src_obj.endswith(".a"):
        line = [h_obj, *parts, src_obj, *link_libs]
    else:
        line = [h_obj, src_obj, *parts, *link_libs]
    r = run([(linker or CC), "-w", *line, "-o", exe])
    if r.returncode != 0:
        missing = sorted(set(re.findall(r"undefined reference to `([^']+)'", r.stderr)))
        return {"status": "LINK_FAIL", "file": os.path.basename(emitted_c),
                "objects": len(parts), "undefined": missing[:8],
                "why": {s: classify_missing(s, bucket_dir) for s in missing[:8]}}

    # A reconstruction that loops forever is a REAL and previously-seen defect
    # class in this project (`while(true)` with the exit condition lost). Without
    # a timeout the harness blocks on it indefinitely and measure.sh never
    # returns — the metric would hang instead of reporting, which is the worst
    # possible failure mode for a measurement tool.
    #
    # HANG is reported as its own status, not folded into CRASH: they point at
    # different bugs (lost loop exit vs bad memory access).
    try:
        r = run([exe], timeout=EXEC_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"status": "HANG", "file": os.path.basename(emitted_c),
                "timeout_s": EXEC_TIMEOUT_S}
    if r.returncode != 0:
        return {"status": "CRASH", "file": os.path.basename(emitted_c),
                "exit": r.returncode}
    if "AGREE" in r.stdout:
        return {"status": "AGREE", "file": os.path.basename(emitted_c),
                "inputs": len(spec_fn["inputs"]),
                "random": int(spec_fn.get("random", {}).get("cases", 0))}
    return {"status": "DIVERGE", "file": os.path.basename(emitted_c),
            "cases": r.stdout.strip().splitlines()[:6],
            "inputs": len(spec_fn["inputs"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--json-out", metavar="PATH",
                    help="also write the JSON payload to PATH while stdout "
                         "stays the text report. One run, both outputs: "
                         "measure.sh used to invoke this script TWICE (once per "
                         "format), and each run compiles, links and executes "
                         "every function in the spec against 2000-3300 objects "
                         "per bucket -- measured at ~30 minutes thrown away per "
                         "measurement (runs/wip_0815: behavior.txt 20:03:48, "
                         "behavior.json 20:33:55).")
    ap.add_argument("--keep", action="store_true", help="keep the build dir")
    ap.add_argument("--spec", default=os.path.join(HERE, "behavior_spec.json"))
    a = ap.parse_args()

    spec = json.load(open(a.spec))
    prelude = os.path.join(HERE, "ida_defs.h")
    work = tempfile.mkdtemp(prefix="behavior_")
    results, tally = {}, {}

    try:
        for bucket, bspec in spec["buckets"].items():
            if not bspec.get("functions"):
                continue
            # Where this bucket's decompiled output lives.
            #
            # Default (and every pre-existing bucket): a subdirectory of the
            # snapshot passed on the command line, named after the bucket. That
            # is how measure.sh snapshots are laid out.
            #
            # A bucket may instead declare its own "out_dir", relative to this
            # directory (or absolute). The symbol-rich binaries built for the
            # cross-language buckets live in behav/bin/ and are decompiled into
            # behav/out/<bucket>, which is NOT inside any snapshot -- without
            # this key those buckets could never be reached. Absent, behaviour is
            # exactly as before.
            if bspec.get("out_dir"):
                od = bspec["out_dir"]
                bucket_dir = od if os.path.isabs(od) else os.path.join(HERE, od)
                bucket_dir = os.path.join(bucket_dir, bspec.get("out_name", bucket))
            else:
                bucket_dir = os.path.join(a.out_dir, bucket)
            if not os.path.isdir(bucket_dir):
                continue
            src = os.path.join(HERE, "src", bspec["source"])
            src_obj, err = build_reference(work, bucket, src, bspec)
            if err:
                results[bucket] = {"_error": err}
                continue
            obj_of_file = {}
            bucket_objs, compile_failed = build_bucket(
                work, bucket_dir, prelude, set(bspec["functions"]), obj_of_file)
            defines, needs = symbol_tables(bucket_objs)
            results.setdefault(bucket, {})["_bucket"] = {
                "objects_linked": len(bucket_objs),
                "compile_failures": len(compile_failed),
            }
            for name, fspec in bspec["functions"].items():
                res = check_one(work, bucket_dir, src_obj, name, fspec, prelude,
                                bucket_objs, defines, needs, obj_of_file,
                                bspec.get("harness_prelude", ""),
                                linker_for(bspec["source"]),
                                extra_link_args(bspec))
                results.setdefault(bucket, {})[name] = res
                tally[res["status"]] = tally.get(res["status"], 0) + 1
    finally:
        if a.keep:
            print(f"build dir kept: {work}", file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)

    total = sum(tally.values())
    agree = tally.get("AGREE", 0)
    # Per-function status travels with the counts. Counts alone hide a swap:
    # one function regressing AGREE→DIVERGE while another improves leaves the
    # totals identical and the output quietly worse.
    #
    # Built unconditionally, so `--json-out` can write it while stdout carries
    # the text report: the analysis above is the expensive part and repeating it
    # for a second output format is pure waste.
    per_fn = {f"{b}:{n}": r["status"]
              for b, fns in results.items()
              for n, r in fns.items() if n != "_bucket"}
    payload = json.dumps({"total": total, "agree": agree, "tally": tally,
                          "pct": round(100.0 * agree / total, 2) if total else 0.0,
                          "functions": per_fn})
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    if a.json:
        print(payload)
        return 0

    for bucket, fns in results.items():
        print(f"[{bucket}]")
        for name, r in fns.items():
            if name == "_bucket":
                print(f"  bucket: {r['objects_linked']} objects linked, "
                      f"{r['compile_failures']} compile failures")
                continue
            extra = ""
            if r["status"] == "LINK_FAIL":
                why = r.get("why", {})
                extra = "".join("\n      " + f"{s}: {why.get(s, '?')}"
                                for s in r.get("undefined", [])[:4])
            elif r["status"] == "DIVERGE":
                extra = "\n      " + "\n      ".join(r.get("cases", []))
            elif r["status"] == "AGREE":
                extra = f"  ({r['inputs']} curated"
                extra += f" + {r['random']} random)" if r.get("random") else ")"
            print(f"  {r['status']:12} {name}{extra}")
    print()
    print(f"functions tested : {total}")
    print(f"AGREE            : {agree}  ({100.0*agree/total if total else 0:.1f}%)")
    for k, v in sorted(tally.items()):
        if k != "AGREE":
            print(f"{k:17}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
