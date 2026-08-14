export const meta = {
  name: 'close-the-gaps',
  description: 'Close the 4 real gaps vs a commercial decompiler: fidelity harness, ptr-scaling bug class, IL integration slice, fifth bug class — each adversarially verified',
  phases: [
    { title: 'Work', detail: 'four independent gap tasks in parallel' },
    { title: 'Verify', detail: 'adversarial verifier per task, no barrier' },
  ],
}

const COMMON = `
GROUND RULES (violating any of these means your work is rejected):
- Repo root: C:\\Users\\Fra\\Desktop\\RustRE. Main crate: crates/rustre-decompiler (pipeline in src/lib.rs::run_with_structured_emit).
- RELEASE builds ONLY: cargo build --release -p <crate>; cargo test --release -p <crate> --lib. Never debug.
- Report EXACT before/after test counts (run the suite before touching anything).
- NEVER weaken, delete, or #[ignore] a test. Never special-case production code to make a test pass.
- FAILING TEST FIRST, then fix, then REVERT-CHECK: re-inject the bug, confirm ONLY the new test fails, restore the fix.
- NEVER guess flag/instruction semantics. Cite the AMD APM vol.3 (pub 24594, https://kib.kiev.ua/x86docs/AMD/AMD64/24594_APM_v3-r3.34.pdf, pdftotext -layout).
- NOT a git repo — there is no diff to revert with; be careful, keep backups of files you rewrite heavily.
- crates/rustre-debug and wire_tools.rs are OFF LIMITS.
- Corpus driver: target/release/examples/dump_decompile.exe <bin> <outdir>; corpus at crates/rustre-decompiler/tests/decompiler_corpus/{bin,src,out}. Before regenerating, rebuild release and CHECK THE DRIVER EXE MTIME (build races leave stale binaries).
- Brace balance check: strip string literals FIRST ([regex]::Replace($t,'"(\\\\.|[^"\\\\])*"','')) then count with [regex]::Matches. Recompilability check: gcc -std=gnu89 -fsyntax-only -w with the ida_defs.h prelude (do NOT typedef __int64).
- In crates/rustre-arch-x86 lift.rs, NEVER write a concrete M::<Variant> name in a comment (coverage scan counts it; an assert enforces 100% exactly).
- If a command is blocked by a safety classifier, do NOT retry it in a loop — note it and work around or report.
Your final message is raw data for the orchestrator, not prose for a human: report what you did, exact test counts before/after, files touched, and honest failures.`

const TASKS = [
  {
    key: 'gap3-fidelity-harness',
    prompt: `Build a fidelity harness comparing decompiler output to ground-truth source.${COMMON}

TASK: Extend the ground-truth comparison beyond accumulate(). Compare emitted C in tests/decompiler_corpus/out against real source in tests/decompiler_corpus/src, function by function: start with find_max and main in sample1_c, then sample6 and sample11. Deliver:
1. An honest per-function report: what is semantically RIGHT and what is WRONG, quoting the emitted output next to the source.
2. A checked-in crates/rustre-decompiler/tests/fidelity.rs that asserts ONLY what is TRUE TODAY (e.g. substring/structure assertions on the emitted files), with // TODO(fidelity): comments for every known-wrong item. It must pass with cargo test --release -p rustre-decompiler --test fidelity.
Do not fix decompiler bugs here — catalogue them precisely (function, file, defect, why it's wrong vs source).`,
    verify: r => `Adversarially verify a fidelity-harness delivery. Default to refuted:true when uncertain.${COMMON}

The worker reported: <<<${r}>>>
Check: (a) tests/fidelity.rs exists, compiles, and passes under cargo test --release -p rustre-decompiler --test fidelity; (b) its assertions are NOT vacuous (each must actually constrain the emitted output — try mentally flipping the output and see if it'd fail); (c) spot-check 3 of the reported right/wrong claims against the actual out/ and src/ files; (d) hunt for cheating: assertions on trivia, claims not backed by quoted output.`,
  },
  {
    key: 'gap4-ptr-scaling',
    prompt: `Fix the pointer-arithmetic scaling bug as a CLASS.${COMMON}

TASK: In accumulate (tests/decompiler_corpus/out/sample1_c), a variable retyped to a 24-byte struct pointer keeps its raw byte-arithmetic: ptr += 24 now advances 24*24=576 bytes. Any pass that retypes an integer variable to T* MUST rescale its arithmetic (+= K becomes += K/sizeof(T), and comparisons/derefs consistently) or refuse the retyping when K % sizeof(T) != 0.
1. Audit EVERY int→pointer retyping site in crates/rustre-decompiler (pointer-param promotion, struct-field recovery, offset-deref promotion...). List them.
2. Failing test first (unit test capturing the 576-byte defect), then the fix, then revert-check.
3. CRITICAL: explain and test how you distinguish arithmetic that is ALREADY element-scaled from raw byte offsets — rescaling twice is the opposite bug.
4. Rebuild release (check exe mtime), regenerate the corpus, confirm accumulate now emits correct stride, re-measure recompilability (baseline 11142/11144) and brace balance — no regressions.`,
    verify: r => `Adversarially verify a pointer-scaling fix. Default to refuted:true when uncertain.${COMMON}

The worker reported: <<<${r}>>>
Check: (a) re-run cargo test --release -p rustre-decompiler --lib yourself and compare counts; (b) do the REVERT-CHECK yourself if feasible, or verify the worker's revert-check evidence is concrete; (c) read the actual regenerated accumulate output — is the stride genuinely correct now, not just different; (d) check for the double-scaling opposite bug in at least 2 other corpus files using pointer arithmetic; (e) hunt for cheating: weakened tests, special-cased struct size 24, skipped corpus regen.`,
  },
  {
    key: 'gap1-il-integration',
    prompt: `Land ONE narrow, additive, opt-in IL integration slice.${COMMON}

TASK: The rustre-il-* stack (~75k lines: SSA, dominators, GVN, alias analysis) is completely disconnected from rustre-decompiler (not even a Cargo dependency). Ground truth proves it matters: in accumulate, one register serves as both the pts parameter and the total accumulator — exactly what MLIL SSA splitting would separate into two variables.
1. Map the disconnect honestly: what types/IRs each side speaks, what a bridge needs.
2. Land ONE additive opt-in slice — best target: use MLIL SSA to split reused registers into distinct variables in the emitted C. It must be behind an opt-in flag or a safe default that changes nothing else.
3. Show a REAL before/after on emitted C for accumulate (quote both). A wiring that changes no output is worthless. If truly blocked, an honest "here is exactly what blocks it, with the smallest viable next step" beats a fake integration.
4. All existing tests stay green (835 lib baseline in rustre-decompiler; IL crates each green). Report exact counts.`,
    verify: r => `Adversarially verify an IL-integration slice. Default to refuted:true when uncertain.${COMMON}

The worker reported: <<<${r}>>>
Check: (a) is there a real Cargo dependency + code path, or just dead wiring; (b) reproduce the claimed before/after on accumulate yourself by rebuilding and running the driver; (c) re-run rustre-decompiler lib tests and at least one IL crate's tests, compare counts; (d) verify the slice is genuinely opt-in/additive — corpus recompilability must not regress from 11142/11144; (e) hunt for cheating: hardcoded accumulate-specific behavior, output changed by an unrelated hack rather than SSA info.`,
  },
  {
    key: 'gap2-fifth-bug-class',
    prompt: `Find the FIFTH semantic bug class in the decompiler stack.${COMMON}

TASK: Four bug classes are known (gen-before-kill liveness; arg-less flag intrinsics with shared names; LHS/comparison uses uncounted by DCE; pointer-arith scaling). Find a FIFTH real class — a PATTERN, not a one-off. Leads, in priority order:
- args: vec![] in lifters (lift_snp_rmp is a named suspect) — lost operand deps / CSE merge hazards;
- 'recognised' sets claiming unimplemented cases, returning Some(Unknown) that short-circuits an .or_else chain;
- instruction-family match arms missing a member (siblings handled, one forgotten);
- inverted flag senses between adjacent instructions;
- width/sign-extension errors; operand order matching mnemonic text vs actual encoding.
For the class you find: demonstrate at least 2 concrete instances, failing test first per instance, fix, revert-check, exact test counts. Never guess semantics — cite the AMD APM. If a lead turns out clean, SAY it is clean and how you proved it (a locked-in probe beats an assertion).`,
    verify: r => `Adversarially verify a claimed bug-class discovery. Default to refuted:true when uncertain.${COMMON}

The worker reported: <<<${r}>>>
Check: (a) is it genuinely a CLASS (2+ independent instances) and genuinely a bug (verify semantics against the AMD APM yourself for at least one instance); (b) re-run the affected crates' tests yourself, compare counts; (c) do or validate the revert-check; (d) hunt for cheating: 'bug' that is actually correct behavior, tests asserting the implementation rather than the spec, instances that are the SAME site counted twice.`,
  },
]

const VERDICT = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    real_vs_cosmetic: { type: 'string' },
    evidence: { type: 'string' },
    test_counts: { type: 'string' },
  },
  required: ['refuted', 'evidence'],
}

const results = await pipeline(
  TASKS,
  (t) => agent(t.prompt, { label: `work:${t.key}`, phase: 'Work' }),
  (report, t) => report == null ? null :
    agent(t.verify(String(report).slice(0, 20000)), { label: `verify:${t.key}`, phase: 'Verify', schema: VERDICT })
      .then(v => ({ task: t.key, report, verdict: v })),
)

return results.filter(Boolean)
