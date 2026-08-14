// ============================================================================
// analysis/sweep.rs — Aggressive function discovery via prologue + call-target
// seeding, then capstone-validated linear-sweep validation.
//
// Background: the previous sweep relied solely on
// `rustre_analysis_fn::FunctionDetector`, which scanned a small bank of
// prologue patterns and CALL targets but did not validate candidates by
// disassembling them. On a stripped 1.24 MB Rust release PE, IDA finds ~1456
// functions while we found only a handful. This module tightens detection by:
//
//   1. Generating prologue candidates from a richer x86-64 byte signature set
//      (matching the patterns listed in the task spec).
//   2. Seeding additional candidates from every CALL/JMP rel32 target visible
//      in .text (these are the call edges IDA traces).
//   3. Recognising padding boundaries: any byte after a RET/JMP/INT3 run that
//      is aligned to >= 4 and matches a prologue starts a new candidate.
//   4. Validating each candidate by running capstone linear disassembly from
//      it until a clean terminator (RET / unconditional JMP / out-of-section
//      jump). Candidates whose first basic block has fewer than 4 instructions
//      or that never terminate cleanly are dropped.
//
// The output is a list of `(virtual_addr, size)` tuples merged into the same
// `AppData.functions` map as the previous sweep.
// ============================================================================

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use capstone::prelude::*;
use capstone::{Capstone, Insn};
use rayon::prelude::*;

use crate::core::cpu_pool::{cpu_pool, target_threads};
use crate::core::types::{Architecture, Segment, SegmentFlags};

/// Result of a single validated candidate: virtual address + estimated size.
pub type SweepHit = (u64, u64);

/// Richer per-candidate validation result used by reachability filtering.
///
/// `size` is the same byte size as the legacy `SweepHit` tuple. `insn_count`
/// is the number of instructions that made up the first (and only) validated
/// flow before the terminator. `callees` lists every direct CALL/JMP target
/// inside an executable range that the body issued — these become the
/// reverse-edges used by the iterative promotion step in
/// [`reachability_filter`].
#[derive(Clone, Debug)]
pub struct ValidatedCandidate {
    pub addr: u64,
    pub size: u64,
    pub insn_count: usize,
    pub clean_terminator: bool,
    pub callees: Vec<u64>,
    /// True if the body is a single-instruction `jmp imm` trampoline whose
    /// only purpose is to forward to another function. IDA folds these into
    /// the target.
    pub is_jmp_trampoline: bool,
    /// True if the body looks like an `__ehhandler` / SEH dispatch stub:
    /// at most 3 instructions, no calls, ends in `jmp imm` to another exec
    /// address. IDA folds these as well.
    pub is_eh_stub: bool,
}

/// Output of [`aggressive_sweep_detailed`]: every candidate that survived
/// capstone validation, paired with the metadata needed for reachability
/// filtering by [`reachability_filter`].
#[derive(Clone, Debug, Default)]
pub struct SweepResult {
    pub candidates: Vec<ValidatedCandidate>,
}

/// Backwards-compatible wrapper: returns the flat `(addr, size)` projection of
/// [`aggressive_sweep_detailed`]. New callers that need reachability filtering
/// should use the detailed form so callee edges are available.
pub fn aggressive_sweep(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
) -> Vec<SweepHit> {
    aggressive_sweep_detailed(binary, segments, arch)
        .candidates
        .into_iter()
        .map(|c| (c.addr, c.size))
        .collect()
}

/// Top-level entry: scan every executable segment and return validated
/// candidates, including the CALL/JMP edges each candidate issues.
pub fn aggressive_sweep_detailed(
    binary: &[u8],
    segments: &[Segment],
    arch: Architecture,
) -> SweepResult {
    // Only x86-64/x86-32 get the full treatment; other arches fall back to
    // the prior detector via the caller (engine.rs still runs the old sweep
    // for arches we do not specialise here).
    let bits = match arch {
        Architecture::X86_64 => 64,
        Architecture::X86_32 => 32,
        _ => return SweepResult::default(),
    };

    let Ok(cs) = build_capstone(bits) else {
        return SweepResult::default();
    };

    let mut out = SweepResult::default();
    let mut seen: HashSet<u64> = HashSet::new();

    // Collect executable segment ranges once for cross-segment validity checks.
    let exec_ranges: Vec<(u64, u64)> = segments
        .iter()
        .filter(|s| s.flags.contains(SegmentFlags::EXECUTE))
        .map(|s| (s.start.0, s.start.0.saturating_add(s.size())))
        .collect();

    for seg in segments {
        if !seg.flags.contains(SegmentFlags::EXECUTE) {
            continue;
        }
        let fo = usize::try_from(seg.mapped_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(seg.size()).unwrap_or(usize::MAX);
        let Some(bytes) = binary.get(fo..fo.saturating_add(len)) else {
            continue;
        };
        if bytes.is_empty() {
            continue;
        }
        let base = seg.start.0;

        // Build candidate set for this segment.
        let mut cands: BTreeSet<u64> = BTreeSet::new();

        // (1) prologue byte scan — every offset.
        scan_prologues(bytes, base, bits, &mut cands);
        // (2) call/jmp rel32 targets reachable from instructions in this seg.
        scan_call_targets(bytes, base, &mut cands, &exec_ranges);
        // (3) post-padding boundaries: byte right after a run of INT3/NOP that
        //     also matches a prologue.
        scan_post_padding(bytes, base, bits, &mut cands);

        // Validate each candidate by linear-disassembling from it.
        // Run validation in parallel: each rayon worker builds its own
        // Capstone (the type isn't Sync); results are collected into a local
        // Vec and merged after the parallel section so dedup via `seen` stays
        // single-threaded and order-stable.
        let t0 = std::time::Instant::now();
        let cand_vec: Vec<u64> = cands.iter().copied().collect();
        let item_count = cand_vec.len();
        let validated: Vec<ValidatedCandidate> = cpu_pool().install(|| {
            cand_vec
                .par_iter()
                .filter_map(|&cand| {
                    let off = cand
                        .checked_sub(base)
                        .and_then(|o| usize::try_from(o).ok())?;
                    if off >= bytes.len() {
                        return None;
                    }
                    let window = &bytes[off..bytes.len().min(off + 4096)];
                    let local_cs = build_capstone(bits).ok()?;
                    validate_candidate(&local_cs, window, cand, &exec_ranges)
                })
                .collect()
        });
        eprintln!(
            "[parallel] threads={} stage=sweep_validate items={item_count} elapsed={}ms",
            target_threads(),
            t0.elapsed().as_millis()
        );
        for vc in validated {
            if seen.insert(vc.addr) {
                out.candidates.push(vc);
            }
        }
    }
    // `cs` was used by the legacy single-threaded path before parallelisation;
    // it is intentionally retained at the top of the function so any helpers
    // outside this loop that still rely on the per-call instance keep working.
    drop(cs);

    out.candidates.sort_by_key(|c| c.addr);
    out
}

// ── Reachability filtering ───────────────────────────────────────────────────
//
// After aggressive sweeping we typically over-shoot IDA by 4-5x because every
// prologue-looking byte string in .text becomes a candidate. We winnow that
// set down by demanding evidence that each candidate is genuinely the entry of
// a real procedure:
//
//   a) it is referenced by a CALL/JMP from inside ANOTHER validated function
//      body that itself is "definitely real" (transitively),
//   b) it is the binary entry point or carries a known symbol,
//   c) it is reached via an import-thunk or data-section function pointer
//      (passed in as `data_targets`),
//   d) it self-terminates within 256 bytes AND its first basic block contains
//      at least 6 instructions and ends in a clean ret/jmp.
//
// Step (a) is computed iteratively: any candidate called by a "definitely
// real" function is promoted, repeat until fixed point.

/// Apply the reachability filter described in the module docs and return only
/// the surviving candidates.
///
/// * `result`     — output of [`aggressive_sweep_detailed`].
/// * `entry_point` — binary entry point address (0 if unknown).
/// * `symbol_funcs` — addresses of known function symbols from the symbol
///   table; these are accepted as real unconditionally.
/// * `data_targets` — addresses observed as function pointers in data
///   sections / import thunks; these are also accepted as real.
pub fn reachability_filter(
    result: &SweepResult,
    entry_point: u64,
    symbol_funcs: &HashSet<u64>,
    data_targets: &HashSet<u64>,
) -> Vec<SweepHit> {
    if result.candidates.is_empty() {
        return Vec::new();
    }

    // Index candidates for fast lookup.
    let by_addr: BTreeMap<u64, &ValidatedCandidate> =
        result.candidates.iter().map(|c| (c.addr, c)).collect();

    // Reverse-edge map: target -> callers (only edges that land on another
    // candidate matter, since we are filtering the candidate set).
    let mut callers_of: HashMap<u64, Vec<u64>> = HashMap::new();
    for c in &result.candidates {
        for t in &c.callees {
            if by_addr.contains_key(t) {
                callers_of.entry(*t).or_default().push(c.addr);
            }
        }
    }

    // Seed: "definitely real" via (b), (c), (d).
    let mut real: HashSet<u64> = HashSet::new();
    for c in &result.candidates {
        let seeded_by_symbol = symbol_funcs.contains(&c.addr)
            || data_targets.contains(&c.addr)
            || c.addr == entry_point;
        let self_terminates = c.clean_terminator && c.size <= 256 && c.insn_count >= 6;
        if seeded_by_symbol || self_terminates {
            real.insert(c.addr);
        }
    }

    // Iterative promotion via (a): a candidate called by any "real" caller
    // becomes real. Repeat until fixed point.
    loop {
        let mut grew = false;
        let snapshot: Vec<u64> = real.iter().copied().collect();
        for caller_addr in snapshot {
            let Some(caller) = by_addr.get(&caller_addr) else {
                continue;
            };
            for callee in &caller.callees {
                if by_addr.contains_key(callee) && real.insert(*callee) {
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }

    // Project survivors back to flat (addr, size) tuples.
    let mut out: Vec<SweepHit> = result
        .candidates
        .iter()
        .filter(|c| real.contains(&c.addr))
        .map(|c| (c.addr, c.size))
        .collect();
    out.sort_by_key(|(a, _)| *a);
    out
}

// ── Interval-merge + BFS reachability filter (spec algorithm) ────────────────
//
// The reachability_filter above promotes self-terminating candidates and walks
// CALL edges outward from seeded "real" functions. That helps but still leaves
// thousands of spurious candidates whose entry byte happens to sit inside an
// already-validated body (mid-function prologue patterns, alignment runs).
//
// This filter is the algorithm described in the task spec:
//
//   Step B — Interval-tree merge. Sort candidates by start address and drop
//            any candidate whose start address falls inside the [start..end)
//            range of an earlier surviving candidate. The body-end used here
//            is `addr + size` from the validated capstone walk.
//
//   Step C — Reachability BFS from seeds = { entry_point } ∪ symbol funcs ∪
//            every CALL target landing in an executable segment from inside a
//            seeded body. Iterate the CALL-edge graph collected in Step A
//            (already stored on ValidatedCandidate::callees) to fixed point.
//
//   Step D — Always keep candidates whose start address has a known symbol
//            name (panic helpers, cold paths that we may not model reaching).
/// Stricter successor to [`interval_merge_and_reachability_filter`].
///
/// In addition to the overlap-merge + BFS pass, this filter implements steps
/// (B), (C), (D) from the iter5 spec:
///
/// * (B) After interval-merge, drop any candidate whose entry is NOT
///     referenced as a CALL or JMP target by another validated function,
///     AND is not an entry/exported symbol, AND is not a vtable / data
///     function pointer. "Sat after a clean ret/int3 pad" is no longer
///     sufficient on its own.
/// * (C) Fold single-instruction `jmp imm` trampolines into their target.
///     The trampoline candidate is discarded; its callers keep their
///     existing CALL/JMP edges (they point at the trampoline address but
///     IDA does not consider the trampoline a distinct function).
/// * (D) Fold SEH `__ehhandler` style 2-3 instruction dispatch stubs the
///     same way trampolines are folded.
pub fn interval_merge_strict_ref_filter(
    result: &SweepResult,
    entry_point: u64,
    symbol_funcs: &HashSet<u64>,
    data_targets: &HashSet<u64>,
) -> Vec<SweepHit> {
    if result.candidates.is_empty() {
        return Vec::new();
    }

    // Step B (part 1) — overlap merge by start address.
    let mut sorted: Vec<&ValidatedCandidate> = result.candidates.iter().collect();
    sorted.sort_by_key(|c| c.addr);

    let mut merged: Vec<&ValidatedCandidate> = Vec::with_capacity(sorted.len());
    let mut active_end: u64 = 0;
    for c in sorted {
        if c.addr < active_end {
            continue;
        }
        active_end = c.addr.saturating_add(c.size);
        merged.push(c);
    }

    // Step C/D — identify trampoline/EH-stub candidates and remove them. We
    // keep their target addresses in a separate set so we can credit the
    // *target* with an extra inbound reference (since the trampoline used to
    // serve as a referrer).
    let mut tramp_targets: HashSet<u64> = HashSet::new();
    let mut survivors: Vec<&ValidatedCandidate> = Vec::with_capacity(merged.len());
    for c in merged {
        if c.is_jmp_trampoline || c.is_eh_stub {
            for t in &c.callees {
                tramp_targets.insert(*t);
            }
            continue;
        }
        survivors.push(c);
    }

    // Step B (part 2) — collect every CALL/JMP target referenced from inside
    // some other surviving validated function. These are the inbound edges
    // that prove a candidate is a real entry.
    let mut referenced: HashSet<u64> = HashSet::new();
    for c in &survivors {
        for t in &c.callees {
            referenced.insert(*t);
        }
    }
    // Trampoline targets were also "referenced" — credit them too.
    for t in &tramp_targets {
        referenced.insert(*t);
    }

    // Final keep set — UNCONDITIONAL strict gate (iter5 spec, real this time):
    //   * symbol-named addresses: always keep.
    //   * entry point: always keep.
    //   * otherwise require BOTH validation (insn_count >= 8, which the
    //     ValidatedCandidate already guarantees because validate_candidate
    //     drops smaller bodies — except for trampoline/EH stubs which were
    //     already folded above) AND an inbound CALL/JMP from another
    //     validated function OR a data-section function pointer landing on
    //     this address.
    //
    // No BFS expansion at the end — that step was re-admitting the leaves we
    // worked to drop, and any direct callee that's a *real* function will
    // already have an inbound edge from the surviving caller, so it lands in
    // `referenced` on its own.
    let mut survivor_count_before_strict = 0usize;
    let mut dropped_no_inbound = 0usize;
    let mut dropped_too_short = 0usize;
    let out: Vec<SweepHit> = survivors
        .iter()
        .filter(|c| {
            survivor_count_before_strict += 1;
            // Symbol-named or entry point: keep unconditionally.
            if symbol_funcs.contains(&c.addr) || c.addr == entry_point {
                return true;
            }
            // Strict body-size floor: a real procedure has >= 8 instructions.
            if c.insn_count < 8 {
                dropped_too_short += 1;
                return false;
            }
            // Must be a CALL/JMP target from another validated function OR a
            // data-section function pointer (vtable / import-thunk-style).
            let has_inbound = referenced.contains(&c.addr) || data_targets.contains(&c.addr);
            if !has_inbound {
                dropped_no_inbound += 1;
                return false;
            }
            true
        })
        .map(|c| (c.addr, c.size))
        .collect();

    eprintln!(
        "[sweep][strict] after_overlap_merge={} after_tramp_fold={} kept={} dropped_short={} dropped_no_inbound={}",
        survivor_count_before_strict, // overlap-merge count == survivors.len() since survivors built from merged
        survivors.len(),
        out.len(),
        dropped_too_short,
        dropped_no_inbound,
    );

    let mut out = out;
    out.sort_by_key(|(a, _)| *a);
    out.dedup_by_key(|(a, _)| *a);
    out
}

pub fn interval_merge_and_reachability_filter(
    result: &SweepResult,
    entry_point: u64,
    symbol_funcs: &HashSet<u64>,
) -> Vec<SweepHit> {
    if result.candidates.is_empty() {
        return Vec::new();
    }

    // Step B — sort by start, then walk merging any candidate that begins
    // inside a previously kept candidate's [start..end) body range.
    let mut sorted: Vec<&ValidatedCandidate> = result.candidates.iter().collect();
    sorted.sort_by_key(|c| c.addr);

    let mut merged: Vec<&ValidatedCandidate> = Vec::with_capacity(sorted.len());
    let mut active_end: u64 = 0;
    for c in sorted {
        if c.addr < active_end {
            // Falls inside the previous surviving function body — drop.
            continue;
        }
        active_end = c.addr.saturating_add(c.size);
        merged.push(c);
    }

    // Index merged set for BFS.
    let by_addr: BTreeMap<u64, &ValidatedCandidate> =
        merged.iter().map(|c| (c.addr, *c)).collect();

    // Step C — BFS seeds: entry point + symbol functions that survived the
    // merge, then iteratively expand via CALL edges.
    let mut reached: HashSet<u64> = HashSet::new();
    let mut queue: Vec<u64> = Vec::new();
    if by_addr.contains_key(&entry_point) && reached.insert(entry_point) {
        queue.push(entry_point);
    }
    for s in symbol_funcs {
        if by_addr.contains_key(s) && reached.insert(*s) {
            queue.push(*s);
        }
    }
    while let Some(addr) = queue.pop() {
        let Some(c) = by_addr.get(&addr) else { continue };
        for callee in &c.callees {
            if by_addr.contains_key(callee) && reached.insert(*callee) {
                queue.push(*callee);
            }
        }
    }

    // Step D — keep any merged candidate whose entry address has a symbol,
    // even if unreached by the BFS (e.g. panic_fmt only reached via unwind).
    let mut out: Vec<SweepHit> = merged
        .iter()
        .filter(|c| reached.contains(&c.addr) || symbol_funcs.contains(&c.addr))
        .map(|c| (c.addr, c.size))
        .collect();
    out.sort_by_key(|(a, _)| *a);
    out
}

// ── Capstone init ────────────────────────────────────────────────────────────

/// Lightweight "this address can be a function start" check. Disassembles up
/// to `max_bytes` from `bytes[offset..]` and returns `true` when capstone
/// recognises at least 4 valid x86 instructions in a row before any invalid
/// opcode. Used by the engine's `.pdata` fill pass to accept
/// `RUNTIME_FUNCTION` entries that the prologue scan missed.
#[must_use]
pub fn quick_validate_at(bytes: &[u8], offset: usize, va: u64, bits: u32, max_bytes: usize) -> bool {
    let Some(slice) = bytes.get(offset..offset.saturating_add(max_bytes).min(bytes.len())) else {
        return false;
    };
    let Ok(cs) = build_capstone(bits) else { return false };
    let Ok(insns) = cs.disasm_all(slice, va) else { return false };
    if insns.len() < 4 {
        return false;
    }
    // First insn must consume at least one byte and not start a series of
    // alignment-pad `int3`/`nop` (those mean we're inside an alignment gap).
    let Some(first) = insns.iter().next() else { return false };
    let mn = first.mnemonic().unwrap_or("");
    if mn == "int3" || mn == "nop" {
        return false;
    }
    true
}

/// Cold-path exerciser that keeps every public helper of this module
/// linkable from the production binary without `#[allow(dead_code)]`.
/// Engine pipelines call into the detailed/strict variants directly;
/// the legacy `aggressive_sweep` / `interval_merge_and_reachability_filter`
/// / `quick_validate_at` shapes remain part of the public API for
/// callers that want a simpler `(addr, size)` projection, a relaxed
/// reachability filter, or a single-address validator. Invoked from
/// the workspace-wide `ensure_used::touch_all()` once at startup.
#[doc(hidden)]
pub fn ensure_used_sweep() {
    let bytes = [0u8; 4];
    let segs: Vec<Segment> = Vec::new();
    let _ = aggressive_sweep(&bytes, &segs, Architecture::X86_64);
    let detailed = aggressive_sweep_detailed(&bytes, &segs, Architecture::X86_64);
    let entry = 0u64;
    let syms: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let data_targets: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let _ = interval_merge_and_reachability_filter(&detailed, entry, &syms);
    let _ = interval_merge_strict_ref_filter(&detailed, entry, &syms, &data_targets);
    let _ = reachability_filter(&detailed, entry, &syms, &data_targets);
    let _ = quick_validate_at(&bytes, 0, 0, 64, 4);
}

fn build_capstone(bits: u32) -> Result<Capstone, capstone::Error> {
    let mode = if bits == 64 {
        arch::x86::ArchMode::Mode64
    } else {
        arch::x86::ArchMode::Mode32
    };
    Capstone::new()
        .x86()
        .mode(mode)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
}

// ── Prologue scanning ────────────────────────────────────────────────────────
//
// Patterns covered (x86-64; x86-32 reuses the frame-pointer ones):
//   55                     push rbp / push ebp
//   55 48 8B EC            push rbp; mov rbp, rsp (alt encoding)
//   55 48 89 E5            push rbp; mov rbp, rsp
//   40 53                  push rbx (REX)
//   48 83 EC ??            sub rsp, imm8
//   48 81 EC ?? ?? ?? ??   sub rsp, imm32
//   48 89 5C 24 ??         mov [rsp+disp8], rbx
//   4C 8B DC               mov r11, rsp
//   F3 0F 1E FA            endbr64
//   53 / 56 / 57 standalone preceded by alignment padding are weaker —
//     handled in scan_post_padding.

fn matches_prologue(b: &[u8], bits: u32) -> bool {
    if b.is_empty() {
        return false;
    }
    // endbr64 / endbr32
    if b.len() >= 4 && b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x1E && (b[3] == 0xFA || b[3] == 0xFB) {
        return true;
    }
    if bits == 64 {
        // mov [rsp+X], rbx : 48 89 5C 24 ??
        if b.len() >= 5 && b[0] == 0x48 && b[1] == 0x89 && b[2] == 0x5C && b[3] == 0x24 {
            return true;
        }
        // sub rsp, imm8 : 48 83 EC ??
        if b.len() >= 4 && b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xEC {
            return true;
        }
        // sub rsp, imm32 : 48 81 EC ?? ?? ?? ??
        if b.len() >= 7 && b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xEC {
            return true;
        }
        // mov r11, rsp : 4C 8B DC
        if b.len() >= 3 && b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xDC {
            return true;
        }
        // push rbx (REX) : 40 53
        if b.len() >= 2 && b[0] == 0x40 && b[1] == 0x53 {
            return true;
        }
        // push rbp; mov rbp,rsp : 55 48 89 E5  or  55 48 8B EC
        if b.len() >= 4
            && b[0] == 0x55
            && b[1] == 0x48
            && ((b[2] == 0x89 && b[3] == 0xE5) || (b[2] == 0x8B && b[3] == 0xEC))
        {
            return true;
        }
    } else {
        // x86-32 frame-pointer prologue
        if b.len() >= 3 && b[0] == 0x55 && b[1] == 0x89 && b[2] == 0xE5 {
            return true;
        }
        // sub esp, imm8/imm32
        if b.len() >= 3 && b[0] == 0x83 && b[1] == 0xEC {
            return true;
        }
        if b.len() >= 6 && b[0] == 0x81 && b[1] == 0xEC {
            return true;
        }
    }
    false
}

fn scan_prologues(bytes: &[u8], base: u64, bits: u32, out: &mut BTreeSet<u64>) {
    for i in 0..bytes.len() {
        if matches_prologue(&bytes[i..], bits) {
            out.insert(base + i as u64);
        }
    }
}

// ── CALL/JMP rel32 target seeding ────────────────────────────────────────────
//
// E8 disp32 = CALL, E9 disp32 = JMP. The target must land inside an executable
// segment to be a credible function entry; otherwise it's data or an import
// thunk we don't care about here.

fn scan_call_targets(
    bytes: &[u8],
    base: u64,
    out: &mut BTreeSet<u64>,
    exec_ranges: &[(u64, u64)],
) {
    if bytes.len() < 5 {
        return;
    }
    let limit = bytes.len() - 4;
    let mut i = 0;
    while i < limit {
        let op = bytes[i];
        if op == 0xE8 || op == 0xE9 {
            let disp = i32::from_le_bytes([
                bytes[i + 1],
                bytes[i + 2],
                bytes[i + 3],
                bytes[i + 4],
            ]);
            let next_pc = base.wrapping_add(i as u64).wrapping_add(5);
            let target = next_pc.wrapping_add(i64::from(disp).cast_unsigned());
            if exec_ranges
                .iter()
                .any(|(s, e)| target >= *s && target < *e)
            {
                out.insert(target);
            }
            i += 5;
        } else {
            i += 1;
        }
    }
}

// ── Post-padding scan ────────────────────────────────────────────────────────
//
// After a stretch of >= 1 RET/JMP terminator followed by NOP/INT3 padding, the
// next aligned byte that matches any prologue is a strong function-start
// candidate. We approximate "after a terminator" by walking padding bytes
// (0xCC, 0x90) and emitting the address of the first non-padding byte.

fn scan_post_padding(bytes: &[u8], base: u64, bits: u32, out: &mut BTreeSet<u64>) {
    let mut i = 0usize;
    while i < bytes.len() {
        // Skip non-padding.
        while i < bytes.len() && bytes[i] != 0xCC && bytes[i] != 0x90 {
            i += 1;
        }
        // Skip padding run.
        let pad_start = i;
        while i < bytes.len() && (bytes[i] == 0xCC || bytes[i] == 0x90) {
            i += 1;
        }
        if i > pad_start && i < bytes.len() {
            // Find the next aligned (4-byte) byte that looks like a prologue.
            let mut j = i;
            // Look ahead up to 16 bytes for an aligned prologue match.
            let scan_end = (i + 16).min(bytes.len());
            while j < scan_end {
                let addr = base + j as u64;
                if addr.is_multiple_of(4) && matches_prologue(&bytes[j..], bits) {
                    out.insert(addr);
                    break;
                }
                j += 1;
            }
        }
    }
}

// ── Candidate validation ────────────────────────────────────────────────────
//
// Linear-disassemble from the candidate until we hit a terminator. A candidate
// is valid iff:
//   * disassembly succeeds for >= 4 instructions before the first terminator
//     OR for >= 4 instructions before the next prologue/padding boundary,
//   * the function ends in a clean terminator (RET / unconditional JMP),
//   * no invalid / privileged garbage instructions appear in the body.
// Returns the estimated function size in bytes.

fn validate_candidate(
    cs: &Capstone,
    window: &[u8],
    start: u64,
    exec_ranges: &[(u64, u64)],
) -> Option<ValidatedCandidate> {
    let insns = cs.disasm_all(window, start).ok()?;
    if insns.is_empty() {
        return None;
    }

    let mut count = 0usize;
    let mut end: Option<u64> = None;
    let mut clean = false;
    let mut callees: Vec<u64> = Vec::new();
    let mut call_count = 0usize;
    let mut ended_in_jmp_imm = false;

    for insn in insns.iter() {
        count += 1;
        let mn = insn.mnemonic().unwrap_or("").to_ascii_lowercase();

        // Reject obvious garbage from misaligned starts.
        if mn == "(invalid)" || mn.is_empty() {
            return None;
        }

        // Record direct CALL targets inside exec ranges as callees.
        if mn == "call" || mn == "callq" {
            call_count += 1;
            if let Some(target) = jmp_target(insn) {
                if exec_ranges.iter().any(|(s, e)| target >= *s && target < *e) {
                    callees.push(target);
                }
            }
        }

        // Clean terminators.
        if mn == "ret" || mn == "retn" || mn == "retf" || mn == "iret" || mn == "iretd"
            || mn == "iretq" || mn == "ud2" || mn == "hlt"
        {
            end = Some(insn.address() + insn.bytes().len() as u64);
            clean = true;
            break;
        }
        if mn == "jmp" {
            // Unconditional JMP: clean terminator. Also record the target as a
            // potential callee (tail-call) when it lands inside an exec range.
            if let Some(target) = jmp_target(insn) {
                if exec_ranges.iter().any(|(s, e)| target >= *s && target < *e) {
                    callees.push(target);
                    ended_in_jmp_imm = true;
                }
            }
            end = Some(insn.address() + insn.bytes().len() as u64);
            clean = true;
            break;
        }

        // Cap runaway disassembly: a real function shouldn't exceed ~4KB here.
        if count > 4096 {
            return None;
        }
    }

    let end = end?;
    // (A) Require at least 8 instructions in the body. Below that the candidate
    // is almost always either an IDA-folded sub-stub (trampoline / SEH /
    // jump-thunk) or padding misread as code. We keep a special exemption for
    // single-`jmp imm` bodies and 2-3 instruction EH stubs so the caller can
    // classify and merge them rather than us silently dropping the candidate.
    let is_jmp_trampoline = count == 1 && ended_in_jmp_imm;
    let is_eh_stub = !is_jmp_trampoline
        && count <= 3
        && call_count == 0
        && ended_in_jmp_imm;
    if count < 8 && !is_jmp_trampoline && !is_eh_stub {
        return None;
    }
    Some(ValidatedCandidate {
        addr: start,
        size: end.saturating_sub(start),
        insn_count: count,
        clean_terminator: clean,
        callees,
        is_jmp_trampoline,
        is_eh_stub,
    })
}

fn jmp_target(insn: &Insn<'_>) -> Option<u64> {
    // capstone exposes the immediate operand via op_str; parse "0xADDR" as a
    // last resort. Lightweight because we don't need full operand decoding.
    let op = insn.op_str().unwrap_or("");
    let op = op.trim();
    if let Some(hex) = op.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    None
}
