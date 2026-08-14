//! Analysis integration bridge — 2026-07-12 (Sprint 4).
//!
//! Thin adapters that expose rustre-analysis-{dataflow,vsa,vtable} to the
//! decompiler pipeline.  The `filter_dead_declarations` function is the
//! primary new entry point: given a slice of pseudo-code lines it identifies
//! variable declarations whose LHS name is never subsequently used and
//! returns those names so the caller can suppress or comment them out.

use rustre_analysis_dataflow as adf;
use rustre_analysis_vsa as vsa;
use rustre_il_mlil::MlilBasicBlock;

// ────────────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────────────

/// Run reaching-definitions on the supplied pseudo-code lines and return the
/// number of definition sets computed.  Used by tests and diagnostics.
///
/// The lines are modelled as a single basic block so that the result is a
/// conservative over-approximation (safe for diagnostic use).
#[must_use]
pub fn compute_reaching_defs_count(lines: &[String]) -> usize {
    let nodes = build_single_block_cfg(lines);
    let result = adf::compute_reaching_defs(&nodes);
    result.len()
}

/// Run liveness analysis on `lines` and return the set of variable names that
/// are *defined* (appear on the LHS of an assignment) but never *used* (never
/// appear on any RHS).
///
/// These correspond to the `int v_1240; int v_1250; …` declarations that
/// should be suppressed in the emitted pseudo-C.
///
/// # Algorithm
/// 1. Scan `lines` to extract `(var_id, var_name)` pairs for every LHS
///    assignment and every RHS token that is a known variable name.
/// 2. Build a single-block `LivenessCfgNode` with `gen = RHS uses` and
///    `kill = LHS defs`.
/// 3. Run `compute_liveness`; the `live_in` of the single block gives all
///    upward-exposed uses.
/// 4. A variable is dead if it appears in `kill` but not in `live_in`.
#[must_use]
pub fn filter_dead_declarations(lines: &[String]) -> Vec<String> {
    use std::collections::{HashMap, HashSet};

    // ── pass 1: collect all LHS definitions and RHS uses ─────────────────
    let mut defs: Vec<String> = Vec::new(); // ordered LHS names
    let mut uses_set: HashSet<String> = HashSet::new();

    // Collect every identifier in `text` as a use.
    let tokenise_uses = |text: &str, uses_set: &mut HashSet<String>| {
        for tok in text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            let tok = tok.trim();
            if !tok.is_empty()
                && tok.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            {
                uses_set.insert(tok.to_string());
            }
        }
    };

    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            // A COMPARISON is not an assignment — but both of its sides are
            // READ. These arms used to `continue`, skipping the line entirely
            // and discarding those reads, so a variable used ONLY in a
            // comparison looked "defined but never used" and its defining
            // assignment was commented out as dead.
            //
            // Seen for real in `accumulate` (sample1_c/sub_140001460.c), where
            // the loop bound was killed and then compared against:
            //     // DCE(df):  v4 = a1 + v3*8;
            //     } while (ptr != v4);
            let after = trimmed.as_bytes().get(eq_pos + 1).copied();
            if after == Some(b'=') {
                tokenise_uses(trimmed, &mut uses_set); // `==`
                continue;
            }
            let before = &trimmed[..eq_pos];
            if before.ends_with(['!', '<', '>']) {
                tokenise_uses(trimmed, &mut uses_set); // `!=`, `<=`, `>=`
                continue;
            }
            let lhs = before.trim();
            let lhs_is_plain_name =
                !lhs.is_empty() && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if lhs_is_plain_name {
                // `v = …` — a pure definition of `v`; nothing on the left is read.
                defs.push(lhs.to_string());
            } else {
                // A COMPOUND left-hand side is NOT a definition of a local — and
                // every name inside it is READ, to compute where to store:
                //   `*dst = 1`          reads dst
                //   `arr[i] = 1`        reads arr and i
                //   `ptr->field = 1`    reads ptr
                //   `*(a1 + a4 - 32) = x` reads a1 and a4
                // Only the RHS used to be tokenised for uses, so these reads were
                // invisible. The variable then looked "defined but never used",
                // its defining assignment was commented out as dead, and the
                // emitted C dereferenced an uninitialised pointer — e.g.
                // `// DCE(df): dst = off_1400043E0;` immediately above `*dst = 1;`
                // in the real corpus output.
                for tok in lhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    let tok = tok.trim();
                    if !tok.is_empty()
                        && tok.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    {
                        uses_set.insert(tok.to_string());
                    }
                }
            }
            // Tokenise the RHS for uses.
            let rhs = &trimmed[eq_pos + 1..];
            for tok in rhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                let tok = tok.trim();
                if !tok.is_empty() && tok.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                    uses_set.insert(tok.to_string());
                }
            }
        } else {
            // Non-assignment lines: tokenise everything for uses.
            for tok in trimmed.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                let tok = tok.trim();
                if !tok.is_empty() && tok.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                    uses_set.insert(tok.to_string());
                }
            }
        }
    }

    if defs.is_empty() {
        return Vec::new();
    }

    // ── alias closure: sub-registers are one family, not separate names ──
    // `al`/`ah`/`ax`/`eax`/`rax` alias the same architectural register: a use
    // of ANY member reads the others' writes (a partial write composes into
    // the wide value; a wide read extracts the narrow bytes). Keying liveness
    // on the textual name alone dropped whole compose chains — pack_fields
    // (sample11_c) returned a raw param because its al/ah writes looked dead
    // against the `movzwl %ax` read. Close the use-set over each family.
    for canon in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", //
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ] {
        let family = crate::reg_width_aliases(canon);
        if family.iter().any(|a| uses_set.contains(*a)) {
            for a in family {
                uses_set.insert(a.to_string());
            }
        }
    }

    // ── pass 2: assign numeric IDs to variable names ──────────────────────
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let get_id = |name: &str, map: &mut HashMap<String, u32>, id: &mut u32| -> u32 {
        if let Some(&existing) = map.get(name) {
            return existing;
        }
        let v = *id;
        map.insert(name.to_string(), v);
        *id += 1;
        v
    };

    let kill_ids: Vec<u32> = defs
        .iter()
        .map(|n| get_id(n, &mut name_to_id, &mut next_id))
        .collect();

    let gen_ids: Vec<u32> = uses_set
        .iter()
        .filter_map(|n| {
            // Only include tokens that were also seen as defs (avoid noise).
            // Token not yet in map — add it so liveness sees it as a use.
            Some(*name_to_id.entry(n.clone()).or_insert_with(|| {
                let v = next_id;
                next_id += 1;
                v
            }))
        })
        .collect();

    // ── pass 3: single-block CFG, no successors ───────────────────────────
    // (bb_id=0, successors=[], gen=gen_ids, kill=kill_ids)
    let nodes: Vec<adf::LivenessCfgNode> = vec![(0u32, vec![], gen_ids, kill_ids.clone())];

    let liveness = adf::compute_liveness(&nodes);

    // live_in[0] = gen ∪ (live_out[0] \ kill) = gen (since live_out = ∅ for
    // a single terminal block).  A defined variable is dead when its id is
    // NOT in live_in[0].
    let live_in_set: std::collections::HashSet<u32> = liveness
        .get(&0)
        .map(|(li, _)| li.iter().copied().collect())
        .unwrap_or_default();

    // Build id→name reverse map for the result.
    let id_to_name: HashMap<u32, &str> =
        name_to_id.iter().map(|(n, &id)| (id, n.as_str())).collect();

    kill_ids
        .iter()
        .filter(|&&id| !live_in_set.contains(&id))
        .filter_map(|&id| id_to_name.get(&id).map(|n| (*n).to_string()))
        .collect()
}

/// Run `eliminate_dead_code` and `copy_propagate` on a `LivenessCfgNode`
/// slice built from the supplied pseudo-code lines.  Returns the transformed
/// node list (primarily useful for tests and diagnostics).
#[must_use]
pub fn run_dataflow_passes(lines: &[String]) -> Vec<adf::LivenessCfgNode> {
    let nodes = build_single_block_cfg(lines);
    let liveness = adf::compute_liveness(&nodes);
    let reaching = adf::compute_reaching_defs(&nodes);
    let nodes = adf::eliminate_dead_code(nodes, &liveness);
    adf::copy_propagate(nodes, &reaching)
}

// ────────────────────────────────────────────────────────────────────────────
// VSA integration — Sprint 5
// ────────────────────────────────────────────────────────────────────────────

/// Run forward VSA over `cfg` (worklist-based fixpoint with widening).
///
/// Returns one `VsaState` per basic block (indexed by block id), representing
/// the abstract register/variable state at block entry.
///
/// # Errors
///
/// Propagates [`vsa::VsaError`] on empty programs or non-convergence.
pub fn run_forward(
    cfg: &vsa::VsaCfg,
) -> Result<Vec<vsa::VsaState>, vsa::VsaError> {
    let analyzer = vsa::VsaAnalyzer::new(vsa::VsaState::new());
    analyzer.run(cfg)
}

/// Resolve indirect call targets using per-block VSA states.
///
/// For every `VsaInstr::IndirectCall` in `cfg`, concretises the callee
/// value-set (up to 512 candidates) and returns one
/// [`vsa::IndirectCallResolution`] per call site.  The classifier has no
/// section-range information by default, so all concretisable addresses are
/// returned regardless of section membership.
#[must_use]
pub fn resolve_indirect_calls(
    states: &[vsa::VsaState],
    cfg: &vsa::VsaCfg,
) -> Vec<vsa::IndirectCallResolution> {
    let classifier = vsa::AddressClassifier::new();
    let resolver = vsa::IndirectCallResolver::new(states, &classifier);
    resolver.resolve(cfg)
}

/// Detect jump tables: for each `IndirectCall` instruction whose target
/// value-set is bounded, return [`vsa::JumpTableBounds`].
///
/// Uses an entry size of 8 bytes (the default pointer width on x86-64).  Call
/// [`vsa::bound_jump_table`] directly with a different `entry_size` if needed.
#[must_use]
pub fn detect_jump_tables(
    states: &[vsa::VsaState],
    cfg: &vsa::VsaCfg,
) -> Vec<vsa::JumpTableBounds> {
    let mut out = Vec::new();
    for block in &cfg.blocks {
        let state = &states[block.id];
        for instr in &block.instrs {
            if let vsa::VsaInstr::IndirectCall { target } = instr {
                let vs = state.get(target);
                if let Some(bounds) = vsa::bound_jump_table(&vs, 8) {
                    out.push(bounds);
                }
            }
        }
    }
    out
}

/// Collect the indirect *jump* sites of an MLIL function.
///
/// `build_vsa_cfg_from_mlil` deliberately drops `Jump`/`JumpTable` (they have
/// no VSA transfer function), so the sites would otherwise be invisible to any
/// downstream jump-table analysis. This returns them separately, WITHOUT
/// emitting a `VsaInstr`:
///
/// * mapping them to [`vsa::VsaInstr::IndirectCall`] — the obvious shortcut —
///   would make them show up in `resolve_indirect_calls`, whose output is
///   rewritten into the emitted text by `apply_vsa_resolved_calls`, turning a
///   jump into `sub_X(...)` on **path A**. That is forbidden (rule #28).
///
/// Each entry is `(block index, instruction VA, SSA name of the jump dest)`.
/// The block index uses exactly the same convention as
/// [`build_vsa_cfg_from_mlil`]: the position of the block in `blocks`, so it
/// indexes the per-block state slice returned by [`run_forward`] directly.
///
/// Only sites whose `dest` is a plain variable reference are reported; a
/// constant destination is a direct jump and needs no analysis.
#[must_use]
pub fn collect_indirect_jump_sites(blocks: &[MlilBasicBlock]) -> Vec<(usize, u64, String)> {
    use rustre_il_mlil::{MlilExpr, MlilInstruction};

    fn var_name(expr: &MlilExpr) -> Option<String> {
        if let MlilExpr::Var { var, .. } = expr {
            Some(format!("{}#{}", var.name, var.version))
        } else {
            None
        }
    }

    // Same block indexing as `build_vsa_cfg_from_mlil` (see `id_to_idx` there):
    // the VsaCfg block id IS the enumerate position, so the map is only needed
    // to assert the two agree when the MLIL ids are not already 0..n.
    let id_to_idx: std::collections::HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

    let mut out = Vec::new();
    for (idx, block) in blocks.iter().enumerate() {
        let blk = id_to_idx.get(&block.id).copied().unwrap_or(idx);
        for ann in &block.instrs {
            match &ann.instr {
                MlilInstruction::Jump { dest } | MlilInstruction::JumpTable { dest, .. } => {
                    if let Some(name) = var_name(dest) {
                        out.push((blk, ann.address.as_u64(), name));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// The concrete pointer span a jump site's value-set covers, as
/// `(lowest, highest)` inclusive, or `None` when the set is unbounded
/// (`Top`/`Bottom`) or not concretisable within `limit`.
///
/// Callers use this to fetch exactly the image window that
/// [`resolve_jump_table_targets`] needs to back its [`vsa::TableImage`].
#[must_use]
pub fn indirect_jump_pointer_span(
    states: &[vsa::VsaState],
    site: &(usize, u64, String),
    limit: usize,
) -> Option<(u64, u64)> {
    let state = states.get(site.0)?;
    let vs = state.get(&site.2);
    if vs.is_top() || vs.is_bottom() {
        return None;
    }
    let ptrs = vs.concretize(limit)?;
    let lo = ptrs.iter().copied().min()?;
    let hi = ptrs.iter().copied().max()?;
    Some((lo, hi))
}

/// Resolve the concrete targets of indirect jump sites by delegating to
/// [`vsa::resolve_indirect_targets`] in `rustre-analysis-vsa`.
///
/// This is the real delegation to the dedicated crate: `jumptable.rs` already
/// implements and tests target enumeration over a backing [`vsa::TableImage`],
/// and nothing in the decompiler called it — the jump-table half of the VSA
/// bridge produced only an opaque *count* (`detect_jump_tables`, kept
/// unchanged above for continuity) with no consumer.
///
/// `bytes` is the image window whose first byte lives at `image_base`.
/// Returns one `(jump VA, targets)` pair per site that resolved; sites whose
/// value-set is `Top`/`Bottom` or that produced no readable entry are dropped.
#[must_use]
pub fn resolve_jump_table_targets(
    states: &[vsa::VsaState],
    sites: &[(usize, u64, String)],
    image_base: u64,
    bytes: &[u8],
    entry_size: u8,
    limit: usize,
) -> Vec<(u64, Vec<u64>)> {
    let image = vsa::TableImage {
        base: image_base,
        bytes,
        endian: rustre_core::endian::Endian::Little,
    };
    let mut out = Vec::new();
    for site in sites {
        let Some(state) = states.get(site.0) else { continue };
        let vs = state.get(&site.2);
        if vs.is_top() || vs.is_bottom() {
            continue;
        }
        let targets = vsa::resolve_indirect_targets(&vs, &image, entry_size, limit);
        if targets.is_empty() {
            continue;
        }
        out.push((site.1, targets));
    }
    out
}

// ────────────────────────────────────────────────────────────────────────────
// VSA CFG builder — MLIL → VsaCfg conversion
// ────────────────────────────────────────────────────────────────────────────

/// Convert a slice of [`MlilBasicBlock`]s produced by the MLIL CFG builder
/// into a [`vsa::VsaCfg`] suitable for [`run_forward`].
///
/// The mapping is intentionally shallow: only the instruction variants that
/// directly influence VSA (constants, copies, arithmetic, loads, stores, phi
/// nodes, and indirect calls) are emitted; all other instructions are silently
/// dropped.  This is safe — VSA is an over-approximation and dropping
/// instructions only widens the abstract state.
#[must_use]
pub fn build_vsa_cfg_from_mlil(blocks: &[MlilBasicBlock]) -> vsa::VsaCfg {
    use rustre_il_mlil::{MlilExpr, MlilInstruction};

    let n = blocks.len();
    if n == 0 {
        // Single empty entry block so the analyser has something to iterate.
        return vsa::VsaCfg::new(
            vec![vsa::VsaBlock { id: 0, instrs: Vec::new() }],
            vec![Vec::new()],
            0,
        );
    }

    let mut vsa_blocks: Vec<vsa::VsaBlock> = Vec::with_capacity(n);
    let mut successors: Vec<Vec<usize>> = Vec::with_capacity(n);

    // Index from MLIL block id (u32) to sequential 0-based position.
    // Blocks are assumed to be ordered 0..n already; if not we still produce
    // a valid (potentially mis-ordered) CFG.
    let id_to_idx: std::collections::HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

    for (idx, block) in blocks.iter().enumerate() {
        let mut instrs: Vec<vsa::VsaInstr> = Vec::new();

        // Helper closures: extract a simple string name from an expression,
        // or `None` if it is not a plain variable reference.
        fn var_name(expr: &MlilExpr) -> Option<String> {
            if let MlilExpr::Var { var, .. } = expr {
                Some(format!("{}#{}", var.name, var.version))
            } else {
                None
            }
        }

        for ann in &block.instrs {
            match &ann.instr {
                MlilInstruction::Assign { dest, src, .. } => {
                    let dst = format!("{}#{}", dest.name, dest.version);
                    match src {
                        MlilExpr::Const { value, .. } => {
                            instrs.push(vsa::VsaInstr::Const {
                                dst,
                                value: *value,
                            });
                        }
                        MlilExpr::Var { var, .. } => {
                            instrs.push(vsa::VsaInstr::Copy {
                                dst,
                                src: format!("{}#{}", var.name, var.version),
                            });
                        }
                        MlilExpr::Add(lhs, rhs, _) => {
                            if let (Some(l), Some(r)) = (var_name(lhs), var_name(rhs)) {
                                instrs.push(vsa::VsaInstr::Add { dst, lhs: l, rhs: r });
                            }
                        }
                        MlilExpr::Sub(lhs, rhs, _) => {
                            if let (Some(l), Some(r)) = (var_name(lhs), var_name(rhs)) {
                                instrs.push(vsa::VsaInstr::Sub { dst, lhs: l, rhs: r });
                            }
                        }
                        MlilExpr::And(lhs, rhs, _) => {
                            if let (Some(l), Some(r)) = (var_name(lhs), var_name(rhs)) {
                                instrs.push(vsa::VsaInstr::And { dst, lhs: l, rhs: r });
                            }
                        }
                        MlilExpr::Or(lhs, rhs, _) => {
                            if let (Some(l), Some(r)) = (var_name(lhs), var_name(rhs)) {
                                instrs.push(vsa::VsaInstr::Or { dst, lhs: l, rhs: r });
                            }
                        }
                        MlilExpr::Load { addr: ptr_expr, .. } => {
                            if let Some(ptr) = var_name(ptr_expr) {
                                instrs.push(vsa::VsaInstr::Load { dst, ptr });
                            }
                        }
                        _ => {} // unsupported src — skip
                    }
                }
                MlilInstruction::Store { addr, src, .. } => {
                    if let (Some(ptr), Some(val)) = (var_name(addr), var_name(src)) {
                        instrs.push(vsa::VsaInstr::Store { ptr, val });
                    }
                }
                MlilInstruction::Call { dest, .. } => {
                    // Emit an IndirectCall when the callee is a variable (not a
                    // concrete address constant).
                    if let Some(target) = var_name(dest) {
                        instrs.push(vsa::VsaInstr::IndirectCall { target });
                    }
                }
                MlilInstruction::TailCall { dest, .. } => {
                    if let Some(target) = var_name(dest) {
                        instrs.push(vsa::VsaInstr::IndirectCall { target });
                    }
                }
                MlilInstruction::Phi { dest, sources } => {
                    let dst = format!("{}#{}", dest.name, dest.version);
                    let src_names: Vec<String> = sources
                        .iter()
                        .map(|v| format!("{}#{}", v.name, v.version))
                        .collect();
                    instrs.push(vsa::VsaInstr::Phi { dst, srcs: src_names });
                }
                _ => {} // Ret, Jump, CondJump, Nop, … — no VSA effect
            }
        }

        vsa_blocks.push(vsa::VsaBlock { id: idx, instrs });
        let succs: Vec<usize> = block
            .successors
            .iter()
            .filter_map(|&sid| id_to_idx.get(&sid).copied())
            .collect();
        successors.push(succs);
    }

    vsa::VsaCfg::new(vsa_blocks, successors, 0)
}

// ────────────────────────────────────────────────────────────────────────────
// cpp feature gate
// ────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "cpp")]
pub mod cpp {
    use rustre_analysis_vtable as vt;

    /// Name of the vtable-recovery pass provided by `rustre-analysis-vtable`.
    #[must_use]
    pub fn vtable_pass_name() -> String {
        let _pass = vt::VtableAnalysisPass::new();
        "vtable_recovery".to_string()
    }

    /// Scan an image for C++ vtable candidates.
    ///
    /// `sections` is `(name, virtual_addr, virtual_size, raw_offset, raw_size,
    /// flags)` — the same shape the loader's section table already carries;
    /// `image` is the raw file bytes; `bits` is 32 or 64.
    ///
    /// Executable sections (PE `IMAGE_SCN_MEM_EXECUTE`, or the canonical
    /// `.text` name) define the code ranges a slot pointer must land in; every
    /// NON-executable file-backed section is then scanned for runs of such
    /// pointers.  Returns `(address, slot_count, confidence)` per candidate.
    ///
    /// This is a PURE function: it reads the bytes it is handed and returns a
    /// vector.  It has no effect on emitted code unless a caller consumes it.
    #[must_use]
    pub fn scan_vtables(
        sections: &[(String, u64, u64, u64, u64, u32)],
        image: &[u8],
        bits: u32,
    ) -> Vec<(u64, usize, f32)> {
        let ptr = if bits == 64 { 8usize } else { 4usize };
        let mut sc = vt::VtableScanner::new(ptr, 3);
        let is_exec = |name: &str, flags: u32| flags & 0x2000_0000 != 0 || name == ".text";
        for (name, va, vsize, _ro, _rs, flags) in sections {
            if is_exec(name, *flags) && *vsize > 0 {
                sc.add_code_range(*va, va.saturating_add(*vsize));
            }
        }
        let mut out = Vec::new();
        for (name, va, _vsize, raw_offset, raw_size, flags) in sections {
            if is_exec(name, *flags) || *raw_size == 0 {
                continue;
            }
            let Ok(lo) = usize::try_from(*raw_offset) else { continue };
            let Ok(len) = usize::try_from(*raw_size) else { continue };
            let Some(hi) = lo.checked_add(len) else { continue };
            let Some(slice) = image.get(lo..hi) else { continue };
            for c in sc.scan(slice, *va) {
                out.push((c.address, c.slot_count, c.confidence));
            }
        }
        out
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

/// Build a single-block `LivenessCfgNode` from a slice of pseudo-code lines.
///
/// `gen` = all identifier tokens that appear on any RHS (upward-exposed uses).
/// `kill` = all identifier tokens that appear on any LHS (definitions).
fn build_single_block_cfg(lines: &[String]) -> Vec<adf::LivenessCfgNode> {
    use std::collections::{HashMap, HashSet};

    let mut defs: HashSet<String> = HashSet::new();
    let mut uses: HashSet<String> = HashSet::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        if let Some(eq_pos) = trimmed.find('=') {
            let after = trimmed.as_bytes().get(eq_pos + 1).copied();
            if after == Some(b'=') { continue; }
            let before = &trimmed[..eq_pos];
            if before.ends_with(['!', '<', '>']) { continue; }
            let lhs = before.trim();
            if !lhs.is_empty() && lhs.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                defs.insert(lhs.to_string());
            }
            let rhs = &trimmed[eq_pos + 1..];
            for tok in rhs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                let tok = tok.trim();
                if !tok.is_empty() && tok.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                    uses.insert(tok.to_string());
                }
            }
        } else {
            for tok in trimmed.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                let tok = tok.trim();
                if !tok.is_empty() && tok.chars().next().map_or(false, |c| c.is_ascii_alphabetic() || c == '_') {
                    uses.insert(tok.to_string());
                }
            }
        }
    }

    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let mut assign = |name: &str| -> u32 {
        if let Some(&id) = name_to_id.get(name) { return id; }
        let id = next_id;
        name_to_id.insert(name.to_string(), id);
        next_id += 1;
        id
    };

    let kill_ids: Vec<u32> = defs.iter().map(|n| assign(n)).collect();
    let gen_ids: Vec<u32> = uses.iter().map(|n| assign(n)).collect();

    vec![(0u32, vec![], gen_ids, kill_ids)]
}

// ────────────────────────────────────────────────────────────────────────────
// Liveness on the REAL MLIL CFG — multi-block, with successors
// ────────────────────────────────────────────────────────────────────────────
//
// `filter_dead_declarations` above builds a CFG of ONE block from pseudo-C
// text, so `compute_liveness` degenerates to `dead = kill \ gen`: a plain
// set-difference that the fixpoint loop can never change. Nothing in the
// decompiler ever handed the dataflow crate a graph with edges.
//
// The two functions below do. They are modelled on `build_vsa_cfg_from_mlil`
// (same id→index remap, same `name#version` key), so the result depends on the
// TOPOLOGY of the function: a definition in a loop header stays live because a
// back-edge successor reads it, which no textual set-difference can see.

/// Collect every SSA variable READ by `instr`, in `name#version` form.
///
/// PHI sources count as reads: that over-approximates liveness (the value is
/// really read on the incoming edge, not in this block), which is the safe
/// direction — it can only keep a variable ALIVE, never kill one.
fn mlil_instr_reads(instr: &rustre_il_mlil::MlilInstruction, out: &mut Vec<String>) {
    use rustre_il_mlil::{walk_expr, MlilExpr, MlilExprVisitor, MlilInstruction};

    struct Collect<'a>(&'a mut Vec<String>);
    impl MlilExprVisitor for Collect<'_> {
        fn visit_expr(&mut self, expr: &MlilExpr) {
            if let MlilExpr::Var { var, .. } = expr {
                self.0.push(format!("{}#{}", var.name, var.version));
            }
        }
    }
    let mut c = Collect(out);

    match instr {
        MlilInstruction::Assign { src, .. } => walk_expr(src, &mut c),
        MlilInstruction::Store { addr, src, .. } => {
            walk_expr(addr, &mut c);
            walk_expr(src, &mut c);
        }
        MlilInstruction::Jump { dest } | MlilInstruction::JumpTable { dest, .. } => {
            walk_expr(dest, &mut c);
        }
        MlilInstruction::CondJump { cond, .. } => walk_expr(cond, &mut c),
        MlilInstruction::Call { dest, args, .. } | MlilInstruction::TailCall { dest, args } => {
            walk_expr(dest, &mut c);
            for a in args {
                walk_expr(a, &mut c);
            }
        }
        MlilInstruction::SysCall { args, .. } => {
            for a in args {
                walk_expr(a, &mut c);
            }
        }
        MlilInstruction::Ret { values } => {
            for e in values {
                walk_expr(e, &mut c);
            }
        }
        MlilInstruction::Phi { sources, .. } => {
            for v in sources {
                c.0.push(format!("{}#{}", v.name, v.version));
            }
        }
        MlilInstruction::Nop
        | MlilInstruction::Undefined
        | MlilInstruction::Trap { .. } => {}
    }
}

/// Build a MULTI-BLOCK `LivenessCfgNode` list from the MLIL basic blocks,
/// together with the `id → name` map needed to read the result back.
///
/// * node id  — sequential index (`blocks[i].id → i`), same remap as
///   [`build_vsa_cfg_from_mlil`], so a non-contiguous MLIL id space is safe.
/// * successors — `block.successors` mapped through the same table; edges the
///   table does not know (out-of-function jumps) are dropped.
/// * `kill` — the `dest` of every `Assign` and every `Phi`.
/// * `gen`  — every variable READ in the block *before* being redefined in it
///   (upward-exposed uses), which is what the backward fixpoint needs.
///
/// `Call`/`SysCall` return variables are deliberately NOT put in `kill`: a
/// smaller `kill` only widens `live_in = gen ∪ (live_out \ kill)`, i.e. keeps
/// more variables alive, and a call result is never something we want to
/// report as dead here.
#[must_use]
pub fn build_liveness_cfg_from_mlil(
    blocks: &[MlilBasicBlock],
) -> (Vec<adf::LivenessCfgNode>, std::collections::HashMap<u32, String>) {
    use rustre_il_mlil::MlilInstruction;
    use std::collections::{HashMap, HashSet};

    let mut id_to_name: HashMap<u32, String> = HashMap::new();
    let mut name_to_id: HashMap<String, u32> = HashMap::new();
    let mut next_id: u32 = 0;

    if blocks.is_empty() {
        return (Vec::new(), id_to_name);
    }

    // Same id-allocation scheme as `filter_dead_declarations`.
    macro_rules! var_id {
        ($name:expr) => {{
            let n: String = $name;
            if let Some(&existing) = name_to_id.get(&n) {
                existing
            } else {
                let v = next_id;
                next_id += 1;
                name_to_id.insert(n.clone(), v);
                id_to_name.insert(v, n);
                v
            }
        }};
    }

    let block_idx: HashMap<u32, usize> =
        blocks.iter().enumerate().map(|(i, b)| (b.id, i)).collect();

    let mut nodes: Vec<adf::LivenessCfgNode> = Vec::with_capacity(blocks.len());

    for (idx, block) in blocks.iter().enumerate() {
        let mut gen_ids: Vec<u32> = Vec::new();
        let mut kill_ids: Vec<u32> = Vec::new();
        let mut defined_here: HashSet<String> = HashSet::new();
        let mut seen_gen: HashSet<u32> = HashSet::new();
        let mut seen_kill: HashSet<u32> = HashSet::new();

        for ann in &block.instrs {
            // Reads first: a use only counts as `gen` when it is upward-exposed
            // (not yet redefined inside this block).
            let mut reads: Vec<String> = Vec::new();
            mlil_instr_reads(&ann.instr, &mut reads);
            for r in reads {
                if defined_here.contains(&r) {
                    continue;
                }
                let id = var_id!(r);
                if seen_gen.insert(id) {
                    gen_ids.push(id);
                }
            }
            // Then the definition.
            if let MlilInstruction::Assign { dest, .. } | MlilInstruction::Phi { dest, .. } =
                &ann.instr
            {
                let key = format!("{}#{}", dest.name, dest.version);
                defined_here.insert(key.clone());
                let id = var_id!(key);
                if seen_kill.insert(id) {
                    kill_ids.push(id);
                }
            }
        }

        let succs: Vec<u32> = block
            .successors
            .iter()
            .filter_map(|sid| block_idx.get(sid).map(|&i| u32::try_from(i).unwrap_or(0)))
            .collect();

        nodes.push((
            u32::try_from(idx).unwrap_or(0),
            succs,
            gen_ids,
            kill_ids,
        ));
    }

    (nodes, id_to_name)
}

/// Variables that the MLIL-level liveness fixpoint proves dead.
///
/// A variable is dead when it is DEFINED in some block `b` (`kill[b]`), is not
/// in `live_out[b]` (no successor — including a loop back-edge — reads it), and
/// is not read inside `b` itself after the definition. The `live_out` test is
/// the reason this needs a real CFG: with a single block `live_out` is always
/// empty and the answer collapses back to `kill \ gen`.
///
/// Names come back in SSA `name#version` form; the caller strips the suffix to
/// match the emitted pseudo-C identifiers.
#[must_use]
pub fn dead_vars_from_mlil(blocks: &[MlilBasicBlock]) -> Vec<String> {
    use std::collections::HashSet;

    let (nodes, id_to_name) = build_liveness_cfg_from_mlil(blocks);
    if nodes.is_empty() {
        return Vec::new();
    }

    let liveness = adf::compute_liveness(&nodes);

    // Reads occurring ANYWHERE in a block (not only upward-exposed ones): a
    // definition consumed later in its own block is obviously not dead, and
    // `gen` alone cannot see that.
    let mut read_anywhere: HashSet<String> = HashSet::new();
    for block in blocks {
        for ann in &block.instrs {
            let mut reads: Vec<String> = Vec::new();
            mlil_instr_reads(&ann.instr, &mut reads);
            read_anywhere.extend(reads);
        }
    }

    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (bb_id, _succs, _gen, kill) in &nodes {
        let live_out: HashSet<u32> = liveness
            .get(bb_id)
            .map(|(_li, lo)| lo.iter().copied().collect())
            .unwrap_or_default();
        for id in kill {
            if live_out.contains(id) {
                continue;
            }
            let Some(name) = id_to_name.get(id) else { continue };
            if read_anywhere.contains(name) {
                continue;
            }
            if seen.insert(name.clone()) {
                out.push(name.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(src: &[&str]) -> Vec<String> {
        src.iter().map(|s| (*s).to_string()).collect()
    }

    /// A name on the LEFT of an assignment can still be READ, whenever the
    /// left-hand side is compound: `*dst = 1` reads `dst` to compute where to
    /// store. Uses were only collected from the RHS, so such a variable looked
    /// "defined but never used" and its defining assignment was commented out
    /// as dead — leaving emitted C that dereferences an uninitialised pointer.
    ///
    /// Seen for real in the corpus (`sample1_c/sub_1400013e0.c`):
    ///     // DCE(df):     dst = off_1400043E0;
    ///     *dst = 1;
    #[test]
    fn lhs_deref_counts_as_a_use_not_a_dead_def() {
        let dead = filter_dead_declarations(&lines(&["dst = off_1400043E0;", "*dst = 1;"]));
        assert!(
            !dead.contains(&"dst".to_string()),
            "`*dst = 1` READS dst, so `dst = …` is not dead. Got dead = {dead:?}"
        );
    }

    #[test]
    fn compound_lhs_forms_all_count_as_uses() {
        // Array index: reads both the base and the index.
        let dead = filter_dead_declarations(&lines(&[
            "arr = off_1;",
            "i = 0;",
            "arr[i] = 1;",
        ]));
        assert!(!dead.contains(&"arr".to_string()), "arr[i] reads arr: {dead:?}");
        assert!(!dead.contains(&"i".to_string()), "arr[i] reads i: {dead:?}");

        // Field store through a pointer reads the pointer.
        let dead = filter_dead_declarations(&lines(&["ptr = off_2;", "ptr->field_0 = 5;"]));
        assert!(!dead.contains(&"ptr".to_string()), "ptr->f reads ptr: {dead:?}");

        // Computed address reads every name in the expression.
        let dead = filter_dead_declarations(&lines(&[
            "a1 = off_3;",
            "a4 = off_4;",
            "*(a1 + a4 - 32) = 7;",
        ]));
        assert!(!dead.contains(&"a1".to_string()), "reads a1: {dead:?}");
        assert!(!dead.contains(&"a4".to_string()), "reads a4: {dead:?}");
    }

    /// A comparison is not an assignment — but both sides are READ. These lines
    /// contain an `=` (inside `==`/`!=`/`<=`/`>=`), so they used to be skipped
    /// wholesale, discarding those reads. A variable used ONLY in a comparison
    /// then looked dead and its defining assignment was commented out.
    ///
    /// Seen for real in `accumulate` (corpus `sample1_c/sub_140001460.c`), where
    /// the loop bound was killed and then compared against:
    ///     // DCE(df):     v4 = a1 + v3*8;
    ///     } while (ptr != v4);
    #[test]
    fn variable_used_only_in_a_comparison_is_not_dead() {
        // `!=` — the real accumulate case.
        let dead = filter_dead_declarations(&lines(&[
            "v4 = a1 + v3*8;",
            "do {",
            "ptr += 24;",
            "} while (ptr != v4);",
        ]));
        assert!(
            !dead.contains(&"v4".to_string()),
            "`while (ptr != v4)` READS v4, so `v4 = …` is not dead. Got dead = {dead:?}"
        );

        // `==`, `<=`, `>=` must behave the same way.
        for cmp in ["if (x == bound) {", "if (x <= bound) {", "if (x >= bound) {"] {
            let dead = filter_dead_declarations(&lines(&["bound = 10;", cmp, "}"]));
            assert!(
                !dead.contains(&"bound".to_string()),
                "`{cmp}` READS bound. Got dead = {dead:?}"
            );
        }
    }

    /// The pass must still do its job: a genuinely write-only local stays dead.
    /// Without this, "count the LHS as a use" would trivially disable all DCE.
    #[test]
    fn genuinely_dead_store_is_still_reported() {
        let dead = filter_dead_declarations(&lines(&["v_1240 = *(rsp + 8);", "return 0;"]));
        assert!(
            dead.contains(&"v_1240".to_string()),
            "a local that is assigned and never read must still be dead: {dead:?}"
        );
    }

    /// A plain-name LHS is a pure def — assigning to `v` must not make `v` live.
    #[test]
    fn plain_name_lhs_is_a_def_not_a_use() {
        let dead = filter_dead_declarations(&lines(&["v = 1;", "v = 2;", "return 0;"]));
        assert!(dead.contains(&"v".to_string()), "{dead:?}");
    }

    /// Sub-register aliasing: a value composed through `al`/`ah` and read via
    /// the wide `ax`/`eax` alias is LIVE — al/ah/ax/eax/rax are one register
    /// family, not five unrelated names. This is the pack_fields total-loss
    /// class (sample11_c/sub_140001530 emitted `return a4;`).
    #[test]
    fn subregister_write_read_through_wide_alias_is_live() {
        let dead = filter_dead_declarations(&lines(&[
            "al = a1 & 1;",
            "ah = a2;",
            "eax = ax;",
            "return eax;",
        ]));
        assert!(
            !dead.contains(&"al".to_string()) && !dead.contains(&"ah".to_string()),
            "partial-byte writes read through the wide alias must be live: {dead:?}"
        );
        // And the reverse: a wide def read through a narrow alias is live too.
        let dead2 = filter_dead_declarations(&lines(&["ecx = a1;", "v2 = cl;", "return v2;"]));
        assert!(!dead2.contains(&"ecx".to_string()), "{dead2:?}");
    }

    /// REGOLA #2 — a pass that no-ops is a bug. The whole point of handing the
    /// dataflow crate a MULTI-BLOCK CFG is that `compute_liveness` then has
    /// something to propagate: with one block `live_out` is always empty and
    /// the answer is the textual set-difference `kill \ gen`.
    ///
    /// Shape (id 0 = entry, back-edge 2 → 1):
    ///
    ///   0: def 10           (no local use)
    ///   1: use 10, def 11   ← loop header
    ///   2: use 11           → 1
    ///
    /// Block 0's `live_out` must contain 10 (block 1 reads it), and block 1's
    /// `live_out` must contain BOTH 11 (block 2 reads it) and 10 — 10 survives
    /// only because the back-edge 2 → 1 re-enters block 1, whose `live_in`
    /// still holds it. A single-block CFG with the same gen/kill yields an
    /// EMPTY `live_out`, so the two answers must differ.
    #[test]
    fn liveness_fixpoint_propagates_across_blocks() {
        let multi: Vec<adf::LivenessCfgNode> = vec![
            (0, vec![1], vec![], vec![10]),
            (1, vec![2], vec![10], vec![11]),
            (2, vec![1], vec![11], vec![]),
        ];
        let res = adf::compute_liveness(&multi);

        let lo0 = &res.get(&0).expect("block 0").1;
        assert!(
            lo0.contains(&10),
            "block 0 defines 10 and its successor reads it: live_out[0] = {lo0:?}"
        );

        let lo1 = &res.get(&1).expect("block 1").1;
        assert!(
            lo1.contains(&11),
            "block 2 reads 11: live_out[1] = {lo1:?}"
        );
        assert!(
            lo1.contains(&10),
            "the back-edge 2 -> 1 makes 10 live out of block 1: live_out[1] = {lo1:?}"
        );

        // Control group: the SAME gen/kill as one terminal block. `live_out` is
        // empty, so 10 would be reported dead — the multi-block answer is not
        // reachable by set-difference.
        let single: Vec<adf::LivenessCfgNode> =
            vec![(0, vec![], vec![10, 11], vec![10, 11])];
        let res_single = adf::compute_liveness(&single);
        let lo_single = &res_single.get(&0).expect("single block").1;
        assert!(
            lo_single.is_empty(),
            "a terminal single block has no successors, so nothing is live out: {lo_single:?}"
        );
        assert_ne!(
            lo0, lo_single,
            "if these agree the multi-block CFG changed nothing and the wiring is cosmetic"
        );
    }

    /// The MLIL builder must produce the edges, not just the nodes: a variable
    /// defined in the entry block and read only in a SUCCESSOR block must not
    /// be reported dead. `filter_dead_declarations`' single-block model has no
    /// way to express this.
    #[test]
    fn dead_vars_from_mlil_respects_successor_edges() {
        use rustre_core::address::Address;
        use rustre_il_mlil::{
            MlilAnnotatedInstr, MlilBasicBlock, MlilExpr, MlilInstruction, Size, SsaVar,
        };

        let ann = |instr: MlilInstruction| MlilAnnotatedInstr {
            address: Address::new(0),
            instr,
        };
        let blk = |id: u32, succs: Vec<u32>, instrs: Vec<MlilAnnotatedInstr>| MlilBasicBlock {
            id,
            start: Address::new(0),
            end: Address::new(0),
            instrs,
            predecessors: Vec::new(),
            successors: succs,
        };

        // block 0: live#1 = 0;  dead#1 = 0;   → block 1
        // block 1: ret live#1
        let blocks = vec![
            blk(
                0,
                vec![1],
                vec![
                    ann(MlilInstruction::Assign {
                        dest: SsaVar::new("live", 1),
                        size: Size::QWord,
                        src: MlilExpr::Const { value: 0, size: Size::QWord },
                    }),
                    ann(MlilInstruction::Assign {
                        dest: SsaVar::new("dead", 1),
                        size: Size::QWord,
                        src: MlilExpr::Const { value: 0, size: Size::QWord },
                    }),
                ],
            ),
            blk(
                1,
                vec![],
                vec![ann(MlilInstruction::Ret {
                    values: vec![MlilExpr::Var {
                        var: SsaVar::new("live", 1),
                        size: Size::QWord,
                    }],
                })],
            ),
        ];

        let dead = dead_vars_from_mlil(&blocks);
        assert!(
            dead.contains(&"dead#1".to_string()),
            "`dead#1` is written and never read anywhere: {dead:?}"
        );
        assert!(
            !dead.contains(&"live#1".to_string()),
            "`live#1` is read in the SUCCESSOR block, so it is live out of block 0: {dead:?}"
        );
    }

    /// `build_vsa_cfg_from_mlil` drops `Jump`/`JumpTable` on purpose, so the
    /// only way a jump-table analysis can see an indirect jump is through
    /// `collect_indirect_jump_sites`. Before it existed the site count was
    /// structurally zero and the whole branch was unreachable.
    #[test]
    fn collect_indirect_jump_sites_sees_a_jumptable_terminator() {
        use rustre_core::address::Address;
        use rustre_il_mlil::{
            MlilAnnotatedInstr, MlilBasicBlock, MlilExpr, MlilInstruction, Size, SsaVar,
        };

        let block = MlilBasicBlock {
            id: 0,
            start: Address::new(0x1000),
            end: Address::new(0x1010),
            instrs: vec![
                // A direct jump to a constant is NOT a site.
                MlilAnnotatedInstr {
                    address: Address::new(0x1000),
                    instr: MlilInstruction::Jump {
                        dest: MlilExpr::Const {
                            value: 0x2000,
                            size: Size::QWord,
                        },
                    },
                },
                MlilAnnotatedInstr {
                    address: Address::new(0x1008),
                    instr: MlilInstruction::JumpTable {
                        dest: MlilExpr::Var {
                            var: SsaVar::new("rax", 3),
                            size: Size::QWord,
                        },
                        targets: vec![Address::new(0x2000), Address::new(0x2010)],
                    },
                },
            ],
            predecessors: Vec::new(),
            successors: Vec::new(),
        };

        let sites = collect_indirect_jump_sites(std::slice::from_ref(&block));
        assert_eq!(sites.len(), 1, "exactly one indirect site: {sites:?}");
        assert_eq!(sites[0], (0usize, 0x1008u64, "rax#3".to_string()));
    }

    /// End-to-end proof that the decompiler now DELEGATES to
    /// `rustre-analysis-vsa::jumptable` instead of only counting: with a
    /// concrete pointer value-set and a synthetic image the resolver returns
    /// the target addresses actually stored in the bytes.
    #[test]
    fn resolve_jump_table_targets_reads_real_entries_from_the_image() {
        // Table at 0x1000: three 8-byte absolute targets.
        let mut bytes = Vec::new();
        for t in [0x4010u64, 0x4020, 0x4030] {
            bytes.extend_from_slice(&t.to_le_bytes());
        }

        let mut state = vsa::VsaState::new();
        // pointer set {0x1000, 0x1008, 0x1010}
        state.set("rax#3", vsa::ValueSet::strided(0x1000, 0x1010, 8));
        let states = vec![state];

        let sites = vec![(0usize, 0x1008u64, "rax#3".to_string())];
        let out = resolve_jump_table_targets(&states, &sites, 0x1000, &bytes, 8, 64);

        assert_eq!(out.len(), 1, "one resolved site: {out:?}");
        assert_eq!(out[0].0, 0x1008, "keyed by the jump VA");
        assert_eq!(out[0].1, vec![0x4010, 0x4020, 0x4030]);

        // A `Top` destination must resolve to nothing (never invent a switch).
        let mut top = vsa::VsaState::new();
        top.set("rax#3", vsa::ValueSet::Top);
        assert!(resolve_jump_table_targets(&[top], &sites, 0x1000, &bytes, 8, 64).is_empty());
    }

    /// The span helper must bound exactly the window the image needs, and must
    /// refuse (rather than guess a window) when the set is unbounded.
    #[test]
    fn indirect_jump_pointer_span_bounds_the_image_window() {
        let mut state = vsa::VsaState::new();
        state.set("rax#3", vsa::ValueSet::strided(0x1000, 0x1010, 8));
        let site = (0usize, 0x1008u64, "rax#3".to_string());
        assert_eq!(
            indirect_jump_pointer_span(std::slice::from_ref(&state), &site, 64),
            Some((0x1000, 0x1010))
        );

        let mut top = vsa::VsaState::new();
        top.set("rax#3", vsa::ValueSet::Top);
        assert_eq!(indirect_jump_pointer_span(&[top], &site, 64), None);
    }
}
