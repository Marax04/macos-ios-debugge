# RustRE — decompiler

Compiler/runtime-aware decompiler that turns x86-64 binaries into readable,
**recompilable** pseudo-C. Goal: beat IDA/Hex-Rays on fidelity and reconstruct
whole projects, not just print pseudo-C. Main crate: `crates/rustre-decompiler`
(pipeline in `src/lib.rs::run_with_structured_emit`, per-function passes at the
tail of `decompile`/`emit`).

## Build & test (ALWAYS release)

- Build: `cargo build --release -p rustre-decompiler`
- Test: `cargo test --release -p rustre-decompiler --lib`
- Driver (decompile a binary to a dir): `target/release/examples/dump_decompile.exe <bin> <outdir>`
- Disassemble one function: `target/release/examples/disasm_dump.exe <bin> <va>`
- Never use debug builds. After a code change rebuild before regenerating the corpus, and check the binary mtime (a build race with concurrent edits can leave a stale binary).
- Corpus: **repo-root** `tests/decompiler_corpus/{bin,src,out}` — 12 real C/C++/Rust/Go/C# programs.
  NOT `crates/rustre-decompiler/tests/decompiler_corpus/` — that path exists but holds only an empty
  `out/` stub, and has already cost more than one session a wasted detour. Regenerate with the driver over every `bin/*.exe`, then verify brace balance per-occurrence (PowerShell `[regex]::Matches($t,'\{').Count`, NOT `grep -c`). Since string-literal emission (2026-07-14) strip literals FIRST — `[regex]::Replace($t,'"(\\.|[^"\\])*"','')` — or braces inside emitted strings false-flag balanced files.

## Recompilability metric (N3 self-verification)

Emitted C is checked for syntactic/type validity:
`gcc -std=gnu89 -fsyntax-only -w` on each `.c` prepended with an `ida_defs.h`
prelude (stdint/string/emmintrin + `_QWORD/_DWORD/HANDLE/…` typedefs +
`#define __fastcall/__cdecl/__noreturn/true/false`; do NOT typedef `__int64` — a
mingw builtin). `gnu89` is REQUIRED: C23 breaks unprototyped `()` decls.
Corpus baseline rose from ~3% to ~80% over the 2026-07-11 session, to
99.9% (11136/11144) on 2026-07-14 after the emission-fix pass (JUMPOUT gotos,
width-based unknown types, WinAPI prototypes, struct-field access, string
literals, switch recovery), and to **11143/11144 on 2026-07-16**.

**Measured 11117/11144 on 2026-07-23 (27 failures) — a regression.** Concentrated
in one class: ~23 are `__m128i` type mismatches (`_mm_storeu_si128`,
`_mm_add_epi64`, `_mm_cvtsi128_si64`, and `incompatible types when assigning to
'double' from '__m128i'`), i.e. the scalar-only xmm→`__int64` narrowing applied
inconsistently — the value is narrowed but still handed to an intrinsic that
wants a vector. It hits C#, Go, C++ and C buckets alike, so it is not a
frontend-specific edge case. The other 4 are two parameters emitted with the same
name (`… int str, __int64 str`), which no C compiler accepts; `sig_sanity.py`
tracks that class separately.

## Fidelity metrics — this one is NOT optional

The recompilability metric only proves the C is syntactically and type-valid. It
is **blind to being confidently wrong**: phantom parameters compile perfectly, so
a regression that invented 2233 of them left it reading a flat 11143/11144 while
fidelity collapsed. Never judge a change on `check.sh` alone. Two harnesses, with
different ground truth — run BOTH after a regen:
- `cargo test --release -p rustre-decompiler --test fidelity` — emitted BODY vs the
  known source of sample1/6/11 (whose `.c`/`.cpp` live in `tests/decompiler_corpus/src`).
- `tests/decompiler_corpus/fidelity.sh` — emitted signature ARITY vs the PUBLISHED
  prototypes of 16 mingw-w64/libgcc functions statically linked into the corpus
  (`_Unwind_GetIP` 1, `_GetPEImageBase` 0, …). Baseline **15/16** (2026-07-16).
When the two metrics disagree, that is a finding, not noise: a fidelity win that
dents `check.sh` usually points at a missing cast shape, not a bad inference —
read the gcc error before reverting.

## `measure.sh` — produce numbers ONLY through this (2026-07-23)

`tests/decompiler_corpus/measure.sh` is now the sanctioned way to get any corpus
number. Run `--label before`, make the change, rebuild, then
`--label after --compare before` (add `--full` for the ~11k-gcc recompilability
pass). Exit 1 = a metric regressed, exit 3 = the run is TAINTED.

**`out/` is NOT an oracle.** Many agents own this crate concurrently and
regenerate `out/` in place; on 2026-07-23 it was overwritten mid-verification.
Every absolute number in this repo is therefore uninterpretable on its own.
`measure.sh` fixes that two ways: each run writes an immutable snapshot under
`runs/<label>/` and comparisons are snapshot-vs-snapshot, and the input tree
(decompiler/arch-x86/il-lift sources, harnesses, driver) is content-fingerprinted
before AND after — if it moved, metrics are NOT published. It also refuses to run
when a source is newer than the driver, the stale-binary trap this file already
warns about. To prove a change is emission-neutral, `diff -rq` your own two
snapshots; that argument survives concurrent edits, an absolute figure does not.

**The measuring harness is fingerprinted too.** Making a metric stricter lowers
its number without the emitted code getting worse — teaching `fidelity_arity.py`
to check every definition moved arity 123→122, and the comparison called that a
REGRESSION. So each snapshot records a hash of the metric scripts; when it
differs (or when the baseline predates it, which is *unknown*, not *equal*)
differences are printed as `changed (harness differs)` and are not counted as
regressions. If you change a metric, expect this note and re-baseline.

Snapshots are pruned: the emitted tree of all but the two most recent runs is
deleted, metrics/`confidence.json`/`behavior.json` are kept forever. Comparing
against a pruned baseline still works — that is verified, not assumed. `runs/` is
SHARED between agents, so age vetoes the count: a snapshot younger than 6h is
never pruned, because it may be somebody's `before/` waiting for its `after/`.

Metrics it records, beyond the two above:
- **Arity, widened to ~135 prototypes** (`fidelity_arity.py`, ground truth frozen
  in `prototypes.json` with provenance per row). The legacy 16 are a subset kept
  for continuity — at n=16 one function is 6.25%, so noise and signal have the
  same amplitude. It splits OVER (phantom args — compiles clean, silently wrong)
  from UNDER (missed args). Baseline **122/135, 6 over / 7 under**.
  It checks EVERY definition of a name, not the first: the same runtime is linked
  into all twelve binaries, and `__acrt_iob_func` is emitted correctly in five of
  them and with a phantom second parameter in `sample7_cpp`. First-match scoring
  called that correct and hid it.
- **Cross-build consistency** (`cross_build.py`) — ~1359 runtime functions are
  reconstructed from several independently compiled binaries, so the corpus is
  its own control group: two reconstructions that disagree cannot both be right,
  with no ground truth needed. Baseline **2 inconsistent of 1359**. Consistency is
  NOT correctness — `_Unwind_FindEnclosingFunction` is emitted with 0 parameters
  in every build against a published prototype of 1, so it is perfectly
  consistent and uniformly wrong. This metric catches non-uniform error, the
  prototype metric catches uniform error; neither sees both.
- **Behaviour** (`behavior.py`) — the only metric that measures the stated goal
  rather than a proxy: compile the emitted function, LINK its transitive closure,
  RUN it beside the original compiled from source, compare return values *and*
  buffer contents. Statuses are distinct on purpose (LINK_FAIL / CRASH / HANG /
  DIVERGE / AGREE) because each names a different defect. Baseline **7/14**.
- **Signature sanity** (`sig_sanity.py`) — duplicate parameter names and keyword
  shadowing, tracked apart from recompilability so a naming regression cannot
  hide inside a total dominated by another class. Baseline **4** duplicates.
- **Unresolved data symbols** (`unresolved.py`) — the emitted project declares
  **22773 `extern __int64 off_…;` and defines ZERO of them**, so 5503 of 11144
  files (49.4%) cannot link. `-fsyntax-only` accepts an undefined `extern` by
  design, which is why "99.8% recompilable" and "half the project cannot link"
  are both true. Classified by PE section, because the raw count overstates the
  defect ~4x: **6653 actionable** (`.rdata`/`.data`/`.bss` — real in-image data
  the emitter could materialise), 3974 outside the image (relocations and
  runtime-resolved references, legitimately extern), and **438 in `.text`**, of
  which **423 are exact entry points of functions this same bucket already
  emits**. That last group is the cheapest defect in the corpus: `apply`
  declares `extern __int64 off_140001480` and takes its address while
  `sub_140001480.c` defines `add_fn` at precisely that address — the right answer
  is already in the output, a few files away.
  Measured, not assumed: patching only those two references in an isolated copy
  moved `apply` from LINK_FAIL to DIVERGE — it then links and runs, and reveals a
  *second* defect underneath (`f(v2, a3, a3)` where the source calls `f(a2, a3)`,
  passing a function pointer as the first argument). Fixing the symbol class is
  necessary but does not by itself produce correct code.

  **UPDATE 2026-08-14 — the `.text`/`apply` class is CLOSED, this paragraph is
  stale above.** Re-measured with the same `unresolved.py` on a fresh 11342-file
  snapshot: `code addresses declared as data` is now **0** (the tool labels that
  very row `<-- the apply class`). It was closed by the pass at `lib.rs:9759`,
  which rewrites an `off_HEX` that is a function ENTRY POINT into the spelling
  the function is DEFINED under (via `name_of`, not the `sub_HEX` spelling —
  measured: **zero** of the emitted `__int64 sub_HEX();` match their target and
  7675 do not). Current figures: 5582/11342 files (49.2%) with an unresolved
  reference, **7329 actionable**, 4008 outside the image.
  **The open front is DATA, and it is a PATH ASYMMETRY**: path A emits **11337**
  `extern` and defines **ZERO**; path B emits 4404 and defines **8654** (66%).
  Cause, read not guessed: `data_symbol_definitions` (`lib.rs:11794`) has one
  productive call site, inside **`prepend_hlil_externs`** — an `hlil_` name, so
  path B only. The logic exists and its output is inspectable; the work is to
  PORT it to path A, which is what `behavior.py` and `unresolved.py` actually
  read. ⚠ Note the distinction the LINK_FAIL work turns on: adding a
  DECLARATION raises recompilability and cannot move linkability — only a
  DEFINITION can.

Why behaviour matters even at 15/63: `count_set_flags` scores confidence **92 "(no
signals)"** and compiles cleanly while reading 32 bytes past each element. Both
`check.sh` and the confidence score are structurally blind to that; only running
it finds it.

---

## ⚠ BASELINE 2026-08-18 — `runs/base_0818`. READ THIS BEFORE ANY NUMBER ABOVE

Everything above this line predates 2026-08-18. Where the two disagree, **this
section is the measured one**; the older text is kept because its *reasoning*
is still correct, but four of its figures are not.

The driver was rebuilt before this run: the previous `.exe` was stale
(15-08 04:11 vs `lib.rs` 19:59) — exactly the trap this file warns about.

| metric | base_0818 | what CLAUDE.md said above |
|---|---|---|
| emitted files | **11342** | 11144 |
| arity vs 135 prototypes | **122/135 (90.4%)** — 6 OVER, 7 UNDER | same — still true |
| fidelity, 16 published | **14/16** | 15/16 — **a real regression, see below** |
| behaviour | **15/63 (23.8%)** | 7/14 — **old scale, see below** |
| ↳ LINK_FAIL / CRASH / DIVERGE | 19 / 12 / 11 | — |
| ↳ COMPILE_FAIL / NOT_EMITTED | 3 / 3 | — |
| `goto` emitted | **0** of 11342 files | — |
| `JUMPOUT` | **18**, in 12 files, all C# | — |
| data symbols defined (path A) | **5427** | "ZERO" — closed, see commit `7c33d8b` |
| unresolved actionable | **4012** | 7329 / 6653 |

### The behaviour scale changed — do not compare the rates

12 functions on 23-07 (5 AGREE = 41.7%) → **63** from 15-08 (15 AGREE = 23.8%).
The `7/14` above is the OLD scale. The rate went DOWN because the wider sample
stopped being kind, not because the emitter got worse. **Never compare a
behaviour percentage across a sample-size change.**

### The 14/16 fidelity regression is real, and it is not the harness

`fidelity.sh` has ONE commit since it was created, so this is not the
harness-differs case. `_pei386_runtime_relocator` went from arity 0 to **4
phantom parameters**.

Cause, isolated: the decompiler contradicts itself — it defines
`__int64 __fastcall __mingw_GetSectionCount()` with 0 parameters and calls it as
`__mingw_GetSectionCount(a1, a2, a3, a4)`. Rule D9 in `win64_param_regs_live_in`
(`lib.rs:2450`) reads the 4 arguments at the call site, concludes rcx/rdx/r8/r9
are live-in, and promotes them to parameters **of the caller**. The error
propagates UPWARD.

### `JUMPOUT` breaks the link — it is not cosmetic

`JUMPOUT` is **not defined in `ida_defs.h`** (35 lines, 0 occurrences).
Measured: `gcc -std=gnu89 -fsyntax-only -w` → exit 0; add
`-Werror=implicit-function-declaration` → `implicit declaration of function
'JUMPOUT'`. All 18 are the same shape: a tail jump through a pointer
(`ptr->field_18` ×8, `*(result+32)`, `*v6`). Fix: the guard at `lib.rs:17939`
accepts only simple identifiers; extend it to `({op})()`. Verified downstream:
`cast_indirect_call_targets` (`lib.rs:8632`) already documents and tests
`(ptr->field_30)();` → `((__int64 (*)())(ptr->field_30))();`.

### ~28% of files call functions never declared

Sample of 60 files: 60/60 pass with `-w`, **17/60 fail** with
`-Werror=implicit-function-declaration`. Three classes:
(a) missing forward decls for resolved CRT/WinAPI names (`fpreset`,
    `EnterCriticalSection`, `_amsg_exit`, `__p__commode`) — the filter at
    `lib.rs:148` of `emit_callee_forward_decls`, already tuned in BOTH
    directions (declaring them gives "conflicting types", not declaring them
    gives "undeclared identifier");
(b) intrinsics absent from the prelude: `__readgsqword`,
    `_InterlockedExchange64` — note the irony: `__readgsqword` is emitted *on
    purpose* by a recompilability pass and then not declared, so the pass
    cancels itself;
(c) **50 `push(...)` in 32 files**: x86 mnemonics emitted as C calls.

### A sixth metric exists: `callsite_consistency.py`

Compares the arity a function is **defined** with against the arity it is
**called** with, inside the SAME emitted project. Like `cross_build.py` it needs
**no external ground truth**: if the code contradicts itself, one side is wrong.

On `base_0818`: 10330 definitions inspected, **9756 OVER**, **6042 UNDER**.

It fills a real hole. `check.sh` is **blind by construction**: `gcc -std=gnu89`
accepts `f(a,b,c,d)` against `__int64 f();` because an empty parameter list is a
NON-prototyped declaration, not a promise of zero arguments — the same blindness
that once read 11143/11144 with 2233 phantom parameters. It independently
fingered `_pei386_runtime_relocator` (defined 4, called with 2), the same
function the fidelity regression points at, found by another route.

### The cheapest open experiment in the repo — ZERO lines of code

`published_lib_arity` (`lib.rs:13803`) consults `LibrarySignatureDb` in
`rustre-analysis-type`, which holds **154 mingw/libgcc signatures extracted
mechanically from the headers** (`mingw_runtime_sigs.rs`, with `header:line` per
row). The function **returns immediately** because `RUSTRE_LIBSIG_ARITY`
defaults to OFF. That is why `_Unwind_FindEnclosingFunction` is emitted with 0
parameters while the right signature (1 parameter, `unwind.h:183`) sits in the
database it just consulted. The source comment asks explicitly that flipping it
to default-ON be done "with the number in hand".

### `measure.sh` runs `behavior.py` TWICE

Once for the text output and once for `--json`, ~30 minutes each: a full measure
costs ~62 minutes instead of ~32. Fix: compute once, derive the text from the
JSON.

### Method note

The `measure.sh` fingerprint covers **only the `.rs` files** (line 66) plus the
harnesses and the driver. A `.md` can be written while a measurement runs.

## Emission features (all general, never per-language)

- **Structure recovery**: if/else/loops, switch from jump tables.
- **Idiom re-raising** (beyond IDA): pointer-stride `do/while` → `for`; strength-reduced pointer loop → counted `for (i…) base[i]`; `rep movs` → `memcpy`; `rep stos` (zero fill) → `memset`.
- **Type recovery**: pointer-param promotion (incl. `*(aN+K)` offset-deref); struct-field recovery with the struct type flowed into the **signature**; int narrowing; unsigned promotion; WinAPI/CRT **API-signature type propagation**; `void`→`int` return typing.
- **SSE/x87**: scalar float compare (`ucomisd`…) → `cmp` fusion; scalar-only `__m128i` xmm → `__int64` (gated on no `_mm_` use, verified not to regress struct recovery); `_mm_setzero_ps()` → `_mm_setzero_si128()`/`0` to match the destination type.
- **Flag recovery**: cmp/test/comi→branch fusion, ZF-from-compound-ALU, cross-block.
- **Naming**: `v_HEX` stack slots and register locals get usage-based names (result/i/ptr/dst/src/n).
- **Recompilability passes**: forward declarations for called `sub_`/`off_`; Hex-Rays-style explicit casts (pointer↔int on return/assign, pointer in bitwise/shift/mul, pointer array subscript, indirect-call → function pointer); TLS/segment access → `__readgsqword`/`__readfsdword`; bare frame-reg (`rsp`) declarations; a final syntactic-repair net.
- **Honest confidence** score per function.

## Working style for this repo

- Change one thing, add a unit test, rebuild release, regenerate the corpus, re-measure recompilability + brace balance, spot-check real output. Re-measure the error categories each iteration — it catches self-inflicted regressions.
- A signature-line matcher `(…) {` also matches `while`/`for`/`if` headers — gate control-flow keywords.
- A syntactic-repair pass must run LAST (before `score_confidence`), after every producer, or it silently no-ops.
- The sibling crates `rustre-arch-x86`/`rustre-il-lift` are sometimes broken by concurrent edits (e.g. nonexistent iced_x86 mnemonics); retry, then apply the trivial fix if stable-broken.
