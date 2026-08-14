# rustre-demangle

Multi-ABI symbol demangler: Itanium, MSVC, Rust (legacy + v0), Swift, D, Go,
Obj-C, plus ~20 convention-based detectors in `lang_extra`/`lang_more`.

## Gates — run all four, not just the first two

```sh
cargo test --release -p rustre-demangle                       # 929 passing, 0 failing
cargo clippy --release -p rustre-demangle --all-targets       # must be 0
cargo run --release -p rustre-demangle --example bench_baseline   # 1.15-1.20M calls/s
cargo test --release -p rustre-demangle -- --ignored          # documented gaps (see below)
```

Tests and clippy alone are **not** sufficient. A pre-check added to the
dispatch path once halved throughput and survived 12 green iterations because
nobody measured. Report the throughput number alongside the test count.

Compare throughput **within a run**, never against a figure from another day:
this machine swings ~2× under load. To attribute a cost, measure with and
without the change in the same session. The range above is deliberately a
range — quoting the best figure ever seen turns an ordinary measurement into
an apparent regression.

A single low reading is not a finding. One gate run reported 494k; three
immediate re-runs gave 1.16–1.17M on the same binary. Re-measure before
reporting a regression, and check the machine is idle
(`ps -W | grep -c 'cargo\|rustc'`).

## The metric that matters is classification, not the decode count

`real corpus: 3010/6074` is **not** 50% coverage. Of the corpus, ~2200 entries
are linker section names and ~630 are undecorated C identifiers — none have a
demangling. The authoritative metric is `decline_reason` (`src/decline.rs`):

- `UnsupportedAbi` — a recognised mangling sigil that no backend decoded. **The
  only variant that means a defect.** Locked at 0.
- `Unknown` — no category fits. Locked at 0; a new symbol shape must be
  understood and named, not parked here.
- `SUBSTANTIVE_FLOOR` — decodes where output ≠ input. Immune to identity-echo
  churn, but *not* to removing fabricated output, which is a real
  transformation.

Five steps in this file's history **lowered** the decode count (3042→3016,
3048→3024, 3024→3023, 3023→3020, 3020→3010). Each removed output that was invented, not
decoded. A raw count reads that as a loss; it is a fidelity
gain. Lower a floor only with that kind of evidence, and record why in the
comment above the constant.

Before concluding a symbol class is missing coverage, run
`cargo run --release -p rustre-demangle --example other_triage`.

## Corpora

- `tests/data/real_symbols.txt` — 6074 symbols, `nm` over the 12 repo-root
  corpus binaries. Itanium + Go only.
- `tests/data/pdb_symbols.txt` — 394 symbols from `sample3_rust.pdb` /
  `sample8_rust.pdb`. **The only source of real Rust v0 and MSVC symbols**:
  `sample3_rust.exe` is stripped, so `nm` finds neither ABI. Adding this
  corpus immediately exposed two real defects.

Regenerate with `tests/data/regenerate.sh`, never by hand — it also asserts the
properties whose absence broke these files before (Go generics carry spaces, so
taking `nm`'s last field truncates them silently).

No corpus exists for Swift, D, Obj-C, Ada, Fortran, OCaml or Haskell — and
neither corpus is Mach-O, which hid a whole class of gap. **Apple's symbol
table prefixes every symbol with `_`**, so real symbols read from a macOS or
iOS binary are `_$s…` (Swift), `__R…` (Rust v0), `__D…` (D), `__Z…` (Itanium).
Only the Itanium form was handled; the rest were declined wholesale until
2026-07-23. `rustc-demangle` accepts `__R`, which settled the Rust case as
fact. When adding an ABI, handle the underscored form from the start, and
remember the corpora cannot catch this.

Known and deliberately unfixed: Go keeps the underscore in the package —
`_main.main` yields `namespace: "_main"`, so grouping by package differs
between a Mach-O and an ELF build of the same program. Unlike the cases above
the symbol still decodes, the output is a faithful echo rather than
fabrication, and stripping a leading `_` from any dotted name is a heuristic
with no Go oracle and no Mach-O corpus to check it against. Fix it when either
exists.

## Oracles

Itanium → `cpp_demangle`, Rust → `rustc-demangle`, MSVC → `msvc-demangler`.
All three are wired into differential suites over the *real* corpora, and they
both vindicate and contradict: `__Zoom` → `operator||(unsigned long)` looks
fabricated and is correct (`oo` is `operator||`, `m` is `unsigned long`) —
established only because an oracle said so.

**Go and Swift have no oracle.** Every fabricated-output defect found so far
was in Go, and the one open fidelity suspicion is in Swift. That is not a
coincidence: they are the ABIs where nothing can contradict a wrong answer.

Decoding correctness is otherwise established everywhere it can be:

| ABI / detector | how correctness is established |
|---|---|
| Itanium, Rust, MSVC | differential suites against oracles, over the real corpora — MSVC now includes ALL 14 real PDB symbols (`differential_msvc_pdb.rs`), RTTI and deleting destructors included, no exclusions |
| D | documented grammar, discriminating cases (`tests/d_decoding.rs`) |
| JNI, gfortran, Ada, OCaml, GHC | documented escapes/conventions (`tests/convention_decoding.rs`) |
| Ruby, Lua, PHP, Perl XS, MEX, Windows decorations | same file, compound-name cases |
| Go, Swift | structural invariants only — no oracle exists |

Use *discriminating* inputs, not the obvious one. `luaopen_socket` and
`Init_mymodule` pass whether or not the implementation knows that Lua treats
`_` as a submodule separator and Ruby does not; `luaopen_socket_core` and
`Init_my_ext_core` tell them apart. OCaml split only the first `__` for as
long as anyone tested `camlList__map`.

**Start from the grammar, not from the corpus.** Ask what each piece of the
symbol must become, then build a case that separates a correct implementation
from a plausible one. That is what found the most recent defects, all
invisible to everything else: OCaml dropping inner module components, and Go
losing named components around closure markers (`…init.OnceValue[bool].func5`
→ `…init[bool]`, and `…traceAdvance.func3.osyield.1` → `…traceAdvance`). In
each the corpus was green, the structural invariants were green, and the
fields agreed with each other — a *piece of the output was simply missing*,
which no property defined over the fields can notice. The generalised form of
that check is `tests/go_completeness.rs`, defined over the **input**: every
named component must reappear in the output.

**A probe that reports many failures is usually a broken probe.** That
completeness check went 116 → 104 → 84 → 1 across four revisions: first it
split on `.` without respecting brackets, then it ignored the space the
renderer inserts after commas, then it counted the `type:`/`go:` namespaces
that are deliberately *rewritten* rather than echoed. Only the last figure was
real. Had the code been "fixed" to drive the first number down, it would have
lost the `go.shape.` stripping and the type-descriptor rendering — both
correct. Read the reported cases before believing the count.

## Recurring defect shapes

0. **Sigil checks live in `src/sigil.rs`. Never write `starts_with("_R")`.**
   That test existed in five places and took forty iterations to clear, one
   discovery at a time; `_D` was in five more and `_T` in three. Every fix
   looked complete because the evidence to hand showed a single copy. Worse,
   tightening `demangle` while leaving `detect` turned a consistent error into
   a divergence: `if d.detect(s) { d.demangle(s).unwrap() }` then panicked on
   89 corpus symbols.

   Every claiming site now calls `sigil::{is_rust_v0, is_rust_legacy, is_d,
   is_swift}`, `demangler_registry` included — whether that module should
   exist is an open question, but that was never a reason to leave a known bug
   in public API. The one deliberate exception is the *exclusion* tests in
   `go_demangler`/`legacy_native`, where a loose prefix rejects more rather
   than claiming more, so tightening them would make an exclusion less
   selective. `tests/detect_demangle_agreement.rs` guards the `detect`/
   `demangle` pairing that surfaced the last two copies.

1. **A classifier out of step with its backends.** Too loose invents defects:
   `_R` claimed `_RTC_Initialize`, `_T` claimed `_TIFFOpen`, `_D` claimed
   `_DllMainCRTStartup` — C names filed as unhandled mangled symbols, phantoms
   that hide real ones. Too tight loses information: `MangleLanguage::Java` was
   unreachable from `classify`, so `filter_by_language(…, Java)` returned
   nothing on JNI input. Delegate to the backend's own `detect` in both
   directions rather than writing a second rule.
2. **Tests that check shape, not effect.** `input_count == 10` held while 5 of
   10 test vectors failed to decode; `with_verbosity(Minimal).simplify_templates`
   held while nothing consumed the field. Assert that two configurations give
   *different results*, and add a vacuity guard (`assert!(checked > N)`) —
   "no offenders because it is right" and "no offenders because it is empty"
   look identical from a green test.

   A detector has **two** independent properties: it must not claim what is not
   its (`tests/detector_conventions.rs`) and it must render what it claims
   correctly (`tests/convention_decoding.rs`). Checking one and calling the
   area covered is how OCaml went for years splitting only the first `__`, so
   `camlStdlib__Printf__printf_42` read as `Stdlib.Printf__printf`. The
   single-module case looked right, which is the case anyone writes first.
3. **Duplicated dispatch.** `ItaniumDemangler`, `MsvcDemangler`, `AutoDemangler`
   and `DemanglerCache` each exist 2–3 times, and the copies disagree in both
   directions. `backends::SwiftDemangler::detect` (the live one) omitted `_$s`
   while `swift_demangler::SwiftDemangler::detect` listed it — so **no Swift
   symbol from an Apple binary decoded at all**, since Mach-O prefixes every
   symbol with `_`. `crate::demangle` → `backends::AutoDemangler` is the live
   path; check there first.

4. **Verify the abstraction covers every site before consolidating onto it.**
   Migrating the Swift sites to `sigil::is_swift` would have *broken* the two
   that handled `_$s`, because the new predicate did not. Consolidation that
   propagates a gap is a regression wearing tidy-up clothes. Check equivalence
   case by case, then migrate.

## Open decisions (documented as ignored tests asserting correct behaviour)

- ~~MSVC RTTI and deleting destructors are wrong on the real corpus.~~ **FIXED
  (2026-07-23).** A differential over the 14 real PDB MSVC symbols
  (`differential_msvc_pdb.rs`) found 7 disagreed with `msvc-demangler` — the
  deleting destructors (`??_E`/`??_G`) dropped their trailing signature, and the
  RTTI descriptors (`??_R0`-4) were character-scraped into fabricated fields.
  Deleting destructors now reuse the shared member-function tail; RTTI decodes by
  grammar (type key for `??_R0`, four signed MSVC numbers for `??_R1` → `(0,-1,
  0,64)`, cv byte for `??_R4`). All 14 real symbols now match the oracle and the
  differential runs with no exclusions. Kept here as a record because it is the
  template for the remaining no-oracle work: point an oracle at the *real*
  corpus, not synthetic inputs.
- `DemangleOptions` is **inert** — no function takes it. Implement or deprecate.
  Measured 2026-07-30, the number this entry was missing: **0 consumers
  workspace-wide** and 0 in production code here. It is constructed only by tests
  that assert its own construction (`lib_tests.rs`, `blitz.rs`,
  `options_are_honoured.rs`) — the "test the effect, not the constructor" trap in
  its purest form. So deprecating breaks nobody, and implementing would be new API
  for no existing caller.
  **Measurement trap:** a naive `grep DemangleOptions src/` shows two hits in
  `backends.rs` and `cpp_demangler.rs`, which are `cpp_demangle::DemangleOptions`
  — the *dependency's* identically-named type. That is how an inert type looks
  used.
- `batch_demangle` ≠ `demangle` on 391 symbols; **356 because `Demangler2` has
  no Go support at all**. Converging means giving it an ABI, not refactoring.
- **`rust_demangler::demangle_rust` is correct on 0 of 135 real v0 symbols.**
  83 error out (`Path backref 5 OOB`, `Unknown path tag 'c'`), 52 decode
  wrongly — and wrongly enough to lose identity: `…12try_demangle` and
  `…8demangle` both render `rustc_demangle[a20b64e359616fff]::{{vtable}}`.
  `crate::demangle` delegates to `rustc-demangle` and is exact on all 135.
  ~12 consumer call sites. Pinned by `tests/rust_demangler_accuracy.rs`.

  Not every alternative is broken, which is why these get measured rather than
  assumed: `cpp_demangler` (12 call sites) matches the live path on 813/813
  Itanium (legacy-Rust hash renderings excluded — a deliberate presentation
  difference) and 32/32 MSVC. None of the others was born broken; they drifted
  because nothing compared them. `tests/cpp_demangler_agreement.rs` keeps this one
  from joining them.

  **But read 813/813 for what it is (measured 2026-07-30).** `cpp_demangler::
  demangle_itanium` **delegates to `cpp_demangle`**, exactly as the live path in
  `backends.rs` does; its own comment says the hand-written `ItaniumParser` is kept
  only as a fallback for the vendor forms that engine rejects. So the figure compares
  two wrappers over the same engine: it establishes that their normalisation layers
  agree, **not** that a parser in this crate is accurate. It was previously worded
  "the only healthy one", which reads as the latter.

  The measurement that is *not* tautological: the ~5 shapes `cpp_demangle` rejects,
  which are the only place the local parser runs. One of them fabricates —
  `_Z1fUt_` (an unnamed type) renders `f(?U, unsigned short, unsigned short)`, three
  parameters invented from one type, where the live path declines. Fixing it is
  blocked on the trailing-garbage rule described in
  `tests/cpp_demangler_invalid_utf8.rs`.

  Checked at the same time, so the rest of this table can be trusted: only
  `backends.rs` delegates (Itanium to `cpp_demangle`, Rust to `rustc_demangle`).
  `itanium_full`, `itanium_native`, `rust_demangler`, `msvc_full` and
  `demangler_registry` are all hand-written, so their figures are genuine — and
  **MSVC does not delegate at all**, which makes the live path's 33/33 against
  `msvc-demangler` a real result rather than a self-comparison.

- **`ItaniumNativeDemangler` is 37% wrong on parameter count.** ~10 call sites
  in other crates use it directly. Of the 815 real Itanium symbols, 782 decode
  through both paths; of those, 117 (15%) are identical to `demangle`, 136
  (17%) differ only in `const` placement, and **529 (68%) differ substantively,
  293 (37%) with the wrong arity** — it loses the `St`
  (`std::`) substitution and `S<n>_` back-references, so one parameter becomes
  several (`std::type_info const*` → `const std*, type_info, _`), and it can
  render a namespace as a call (`__cxxabiv1(__gxx_personality_imp)`). Fixing
  the parser, making it delegate, or steering callers to `demangle` are all
  open; the figures are pinned by `tests/itanium_native_accuracy.rs`.

- **Consumers call the weaker dispatchers.** Scope the grep to the workspace,
  not this crate: `itanium_full` (8 uses), `msvc_full` (2) and
  `demangler_dispatcher` (3) are all referenced from other crates, so calling
  them "dead" is wrong. Most are deliberate per-entry-point MCP wire tools in
  `rustre-mcp-tools/src/tools/dm.rs`, which is a fair reason to exist.
  `rustre-symbols-pdb/src/lib.rs:1892` is not: it uses
  `demangler_dispatcher::auto_demangle` for production work and consequently
  leaves **1940 corpus symbols undecoded** that `demangle()` handles, plus
  **136** rendered with crate disambiguators kept
  (`core[d2e35dc664ad455]::panicking::assert_failed`). One-line fix in that
  crate, but it is that crate's call.
  Genuinely unreferenced workspace-wide: `demangler_registry` and
  `demangler_benchmark`. The registry decodes 2209 fewer corpus symbols than
  the live path — missing capability, which is the open question; its `_R`
  false positives were a separate bug and are fixed.
- **Three** incompatible types named `DemanglerCache`, not two: `demangler_cache`,
  `demangler_registry`, and `stats` — the last is the crate-root re-export and so
  the one a consumer reaches first. Measured 2026-07-30: the root one **agrees
  with `demangle` on 12936 lookups** across capacities 16/256/100000, and its
  documented "never promotes, insertion-ordered eviction" policy holds
  (`tests/root_cache_correctness.rs`). `demangler_cache`'s is covered by
  `tests/cache_correctness.rs`. `demangler_registry`'s is a raw get/insert map
  with no correctness coverage. So the open question is the **name collision and
  the triplication**, not correctness of the two that are measured.
- **Swift signatures look inverted**: the ABI grammar is
  `result-type params-type`, the code comment says the reverse, and the only
  full-signature test is the symmetric case where it cannot show. Needs a Swift
  oracle before changing anything.
