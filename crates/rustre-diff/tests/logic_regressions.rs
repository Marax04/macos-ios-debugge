//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_diff::bindiff_engine::{
    BasicBlock, BinDiffEngine, BlockBytesHash, BlockSignature, FunctionInfo, InstructionInfo,
};

fn insn(address: u64, mnemonic: &str) -> InstructionInfo {
    InstructionInfo {
        address,
        opcode_hash: mnemonic.len() as u32,
        mnemonic: mnemonic.to_string(),
        operand_count: 0,
        is_call: false,
        is_branch: false,
        is_ret: mnemonic == "ret",
        call_target: None,
        branch_targets: Vec::new(),
        bytes: mnemonic.as_bytes().to_vec(),
    }
}

fn block(start: u64, mnemonics: &[&str], successors: Vec<u64>) -> BasicBlock {
    let instructions: Vec<InstructionInfo> = mnemonics
        .iter()
        .enumerate()
        .map(|(i, m)| insn(start + i as u64, m))
        .collect();
    let bytes: Vec<u8> = instructions.iter().flat_map(|i| i.bytes.clone()).collect();
    BasicBlock {
        start_address: start,
        end_address: start + instructions.len() as u64,
        block_sig: BlockSignature::from_instructions(&instructions),
        bytes_hash: BlockBytesHash::from_bytes(&bytes),
        instructions,
        successors,
        predecessors: Vec::new(),
        is_entry: false,
        is_exit: true,
    }
}

fn func(address: u64, name: &str, blocks: Vec<BasicBlock>, cfg_hash: u64) -> FunctionInfo {
    FunctionInfo {
        address,
        name: name.to_string(),
        basic_blocks: blocks,
        cfg_hash,
        call_graph_hash: 0,
        callee_addresses: Vec::new(),
        caller_addresses: Vec::new(),
        loop_count: 0,
        is_library: false,
        is_thunk: false,
        binary_id: 0,
    }
}

// ── pass1_name_matches: synthetic names are not identities ─────────────────

/// In a stripped binary every function is named `sub_<addr>` or nothing at all.
/// Matching on that string pairs two completely unrelated functions and stamps
/// the result with confidence 0.99 — the highest the engine can express.
#[test]
fn empty_names_are_not_matched_at_maximum_confidence() {
    let p = vec![func(0x1000, "", vec![block(0x1000, &["ret"], vec![])], 0xAA)];
    let s = vec![func(0x9000, "", vec![block(0x9000, &["ret"], vec![])], 0xBB)];

    let result = BinDiffEngine::new(p, s).diff();
    let by_name = result
        .matches
        .iter()
        .any(|m| m.confidence >= 0.99 && m.primary_address == 0x1000);
    assert!(
        !by_name,
        "two nameless functions were paired by name at confidence 0.99"
    );
}

/// `sub_140001000` is a placeholder the disassembler invented from the address,
/// not a symbol. Two binaries can each invent it for different code.
#[test]
fn synthetic_sub_names_are_not_matched_by_name() {
    let p = vec![func(
        0x1000,
        "sub_1000",
        vec![block(0x1000, &["ret"], vec![])],
        0xAA,
    )];
    let s = vec![func(
        0x9000,
        "sub_1000",
        vec![block(0x9000, &["push", "pop", "ret"], vec![])],
        0xBB,
    )];

    let result = BinDiffEngine::new(p, s).diff();
    assert!(
        !result.matches.iter().any(|m| m.confidence >= 0.99),
        "a synthetic sub_ name was treated as a real symbol"
    );
}

/// Real symbols must still match by name — the fix must not disable pass 1.
#[test]
fn real_names_still_match_by_name() {
    let p = vec![func(
        0x1000,
        "parse_header",
        vec![block(0x1000, &["ret"], vec![])],
        0xAA,
    )];
    let s = vec![func(
        0x9000,
        "parse_header",
        vec![block(0x9000, &["ret"], vec![])],
        0xBB,
    )];

    let result = BinDiffEngine::new(p, s).diff();
    assert_eq!(result.matches.len(), 1);
    assert!((result.matches[0].confidence - 0.99).abs() < 1e-9);
    assert_eq!(result.matches[0].secondary_address, 0x9000);
}

// ── pass2_hash_matches: the sentinel and the double claim ──────────────────

/// `cfg_hash == 0` is what a `FunctionInfo` carries when the hash was never
/// computed. Treating it as a value pairs every such function with every other
/// at confidence 0.95.
#[test]
fn uncomputed_cfg_hash_is_not_a_match_key() {
    let p = vec![func(0x1000, "a", vec![block(0x1000, &["ret"], vec![])], 0)];
    let s = vec![func(0x9000, "b", vec![block(0x9000, &["nop"], vec![])], 0)];

    let result = BinDiffEngine::new(p, s).diff();
    assert!(
        !result
            .matches
            .iter()
            .any(|m| m.confidence >= 0.95 && m.confidence < 0.99),
        "two functions with an uncomputed cfg_hash (0) were paired at 0.95"
    );
}

/// `primary_by_cfg` is snapshotted before the loop and never consulted against
/// `matched_primary`, so N secondaries sharing a CFG hash all claim the SAME
/// primary. Matching must stay a partial injection: no primary twice.
#[test]
fn one_primary_is_never_claimed_by_two_secondaries() {
    let p = vec![func(0x1000, "a", vec![block(0x1000, &["ret"], vec![])], 0x77)];
    let s = vec![
        func(0x9000, "b", vec![block(0x9000, &["ret"], vec![])], 0x77),
        func(0x9100, "c", vec![block(0x9100, &["ret"], vec![])], 0x77),
    ];

    let result = BinDiffEngine::new(p, s).diff();
    let claims = result
        .matches
        .iter()
        .filter(|m| m.primary_address == 0x1000)
        .count();
    assert_eq!(
        claims, 1,
        "primary 0x1000 was matched {claims} times; matching must be injective"
    );
}

/// A genuine CFG-hash match must still be produced.
#[test]
fn distinct_cfg_hashes_still_match() {
    let p = vec![func(0x1000, "a", vec![block(0x1000, &["ret"], vec![])], 0x77)];
    let s = vec![func(0x9000, "b", vec![block(0x9000, &["ret"], vec![])], 0x77)];

    let result = BinDiffEngine::new(p, s).diff();
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].primary_address, 0x1000);
    assert_eq!(result.matches[0].secondary_address, 0x9000);
}

/// The result must not depend on `HashMap` iteration order: two runs over the
/// same input must produce the same pairing.
#[test]
fn matching_is_deterministic_across_runs() {
    let build = || {
        let p: Vec<FunctionInfo> = (0..8)
            .map(|i| {
                func(
                    0x1000 + i * 0x10,
                    &format!("p{i}"),
                    vec![block(0x1000 + i * 0x10, &["ret"], vec![])],
                    0x55,
                )
            })
            .collect();
        let s: Vec<FunctionInfo> = (0..8)
            .map(|i| {
                func(
                    0x9000 + i * 0x10,
                    &format!("s{i}"),
                    vec![block(0x9000 + i * 0x10, &["ret"], vec![])],
                    0x55,
                )
            })
            .collect();
        BinDiffEngine::new(p, s).diff()
    };

    let first = build();
    let mut a: Vec<(u64, u64)> = first
        .matches
        .iter()
        .map(|m| (m.primary_address, m.secondary_address))
        .collect();
    a.sort_unstable();

    for _ in 0..8 {
        let mut b: Vec<(u64, u64)> = build()
            .matches
            .iter()
            .map(|m| (m.primary_address, m.secondary_address))
            .collect();
        b.sort_unstable();
        assert_eq!(a, b, "matching depends on HashMap iteration order");
    }
}

// ── semantic_diff::build_diff_details: the instruction list was always empty ──

use rustre_diff::semantic_diff::{DiffDetail, FunctionEntry, SemanticDiff};

fn entry(addr: u64, name: &str, mnemonics: &[&str]) -> FunctionEntry {
    FunctionEntry::new(addr, name, mnemonics.iter().map(|s| (*s).to_string()).collect())
}

/// `lcs_diff` returns the pairs the LCS MATCHED — pairs that are equal by
/// construction. Filtering them for inequality is vacuously false, so
/// `DiffDetail::InstructionChanged` could never be emitted for any input:
/// every report claimed "no instruction changed", however different the code.
#[test]
fn a_changed_instruction_is_actually_reported() {
    let old = entry(0x1000, "f", &["push rbp", "mov rbp, rsp", "xor eax, eax", "ret"]);
    let new = entry(0x1000, "f", &["push rbp", "mov rbp, rsp", "mov eax, 1", "ret"]);

    let report = SemanticDiff::new().diff(&[old], &[new]);
    let changed: Vec<&DiffDetail> = report
        .diffs
        .iter()
        .flat_map(|d| d.diff_details.iter())
        .filter(|d| matches!(d, DiffDetail::InstructionChanged { .. }))
        .collect();

    assert!(
        !changed.is_empty(),
        "the third instruction differs but no InstructionChanged was emitted"
    );
}

/// Two identical functions must still produce no instruction-level noise.
#[test]
fn identical_functions_report_no_instruction_changes() {
    let f = entry(0x1000, "f", &["push rbp", "mov rbp, rsp", "ret"]);
    let report = SemanticDiff::new().diff(&[f.clone()], &[f]);
    assert!(
        !report
            .diffs
            .iter()
            .flat_map(|d| d.diff_details.iter())
            .any(|d| matches!(d, DiffDetail::InstructionChanged { .. })),
        "identical bodies must not report instruction changes"
    );
}

/// An instruction present only in the new build must surface too.
#[test]
fn an_inserted_instruction_is_reported() {
    let old = entry(0x1000, "f", &["push rbp", "ret"]);
    let new = entry(0x1000, "f", &["push rbp", "nop", "ret"]);

    let report = SemanticDiff::new().diff(&[old], &[new]);
    let any = report
        .diffs
        .iter()
        .flat_map(|d| d.diff_details.iter())
        .any(|d| matches!(d, DiffDetail::InstructionChanged { .. }));
    assert!(any, "an inserted instruction produced no detail at all");
}

// ── basic_block_diff: FlowChanged / FullyChanged were unreachable ────────────

use rustre_diff::basic_block_diff::{BasicBlock as BbBlock, BasicBlockDiffer, BlockMatchKind};

fn bb(start: u64, bytes: &[u8], successors: Vec<u64>) -> BbBlock {
    BbBlock::new(start, start + bytes.len() as u64, bytes.to_vec(), successors)
}

/// `ContentChanged` is documented as "same control-flow successors but
/// different content", yet `diff` applied it without ever looking at the
/// successor lists. A block whose edges were rewritten — the single most
/// interesting thing a patch can do to control flow — was reported as a
/// content tweak, and `FlowChanged`/`FullyChanged` were dead variants.
#[test]
fn rewritten_successors_are_not_reported_as_a_content_tweak() {
    let old = vec![bb(0x1000, &[0x90, 0x90, 0x90, 0x74], vec![0x2000])];
    let new = vec![bb(0x1000, &[0x90, 0x90, 0x90, 0x75], vec![0x3000, 0x4000])];

    let diff = BasicBlockDiffer::new().diff("f", &old, &new);
    let kinds: Vec<BlockMatchKind> = diff.matches.iter().map(|m| m.kind).collect();
    assert!(
        kinds.contains(&BlockMatchKind::FlowChanged)
            || kinds.contains(&BlockMatchKind::FullyChanged),
        "successors went from [0x2000] to [0x3000, 0x4000] but the block was \
         classified {kinds:?}"
    );
}

/// When the edges are untouched, `ContentChanged` remains the right answer.
#[test]
fn same_successors_with_different_bytes_stay_content_changed() {
    let old = vec![bb(0x1000, &[0x90, 0x90, 0x90, 0x31], vec![0x2000])];
    let new = vec![bb(0x1000, &[0x90, 0x90, 0x90, 0x33], vec![0x2000])];

    let diff = BasicBlockDiffer::new().diff("f", &old, &new);
    assert!(
        diff.matches
            .iter()
            .any(|m| m.kind == BlockMatchKind::ContentChanged),
        "identical successors with changed bytes is exactly ContentChanged"
    );
}

/// Identical blocks must stay Identical.
#[test]
fn identical_blocks_stay_identical() {
    let b = vec![bb(0x1000, &[0x90, 0xC3], vec![0x2000])];
    let diff = BasicBlockDiffer::new().diff("f", &b, &b);
    assert_eq!(diff.matches.len(), 1);
    assert_eq!(diff.matches[0].kind, BlockMatchKind::Identical);
}
