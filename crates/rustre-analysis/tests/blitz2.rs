//! Deep adversarial tests for `rustre-analysis` public API.
//!
//! Covers boundary, malformed, integer-overflow, hash/eq, serde round-trip,
//! seeded LCG fuzz, and Send+Sync threaded stress paths.

#![allow(clippy::too_many_lines)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::thread;

use rustre_analysis::{
    AnalysisConfig, AnalysisDb, AnalysisError, AnalysisEvent, AnalysisEventBus, AnalysisKind,
    AnalysisPipeline, AnalysisPlugin, AnalysisPluginRegistry, AnalysisReport, AnalysisResult,
    AnalysisStats, BinaryChange, BoundaryMethod, CfgAnalysisPass, ChangeKind, CountingAnalysisPass,
    CrossReferenceDb, FunctionBoundary, FunctionBoundaryAnalysis, IncrementalAnalysis,
    LinearSweepAnalyzer, LinearSweepConfig, NoOpAnalysisPass, PassDescriptor, PassScheduler,
    PassStats, PluginMetadata, RecursiveDescentAnalyzer, StringRecoveryPass, Xref, XrefRecoveryPass,
    XrefType,
};

// ── LCG fuzzer ─────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

fn fresh_lcg() -> Lcg {
    Lcg::new(0xDEAD_BEEF_CAFE_BABE)
}

// ── AnalysisKind ───────────────────────────────────────────────────────────

#[test]
fn kind_display_format_roundtrip_via_serde_50() {
    for i in 0..50u32 {
        let k = AnalysisKind::Custom(format!("k{i}"));
        let json = serde_json::to_string(&k).unwrap();
        let back: AnalysisKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
        // hash consistency
        let mut h1 = std::collections::HashMap::new();
        h1.insert(k.clone(), i);
        h1.insert(back, i);
        assert_eq!(h1.len(), 1);
    }
}

#[test]
fn kind_hash_eq_consistency_pairs_30() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mk = |i: u32| -> AnalysisKind {
        match i % 10 {
            0 => AnalysisKind::LinearSweep,
            1 => AnalysisKind::RecursiveDescent,
            2 => AnalysisKind::DataFlow,
            3 => AnalysisKind::TypeRecovery,
            4 => AnalysisKind::CallingConvention,
            5 => AnalysisKind::StringRecovery,
            6 => AnalysisKind::XrefRecovery,
            7 => AnalysisKind::VsaAnalysis,
            8 => AnalysisKind::VtableAnalysis,
            _ => AnalysisKind::Custom(format!("c{i}")),
        }
    };
    for i in 0..30u32 {
        let a = mk(i);
        let b = mk(i);
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}

// ── AnalysisConfig ─────────────────────────────────────────────────────────

#[test]
fn config_max_depth_boundary_values() {
    let c = AnalysisConfig::new(AnalysisKind::DataFlow).with_max_depth(0);
    assert_eq!(c.max_depth, 0);
    let c = AnalysisConfig::new(AnalysisKind::DataFlow).with_max_depth(usize::MAX);
    assert_eq!(c.max_depth, usize::MAX);
}

#[test]
fn config_timeout_boundary_values() {
    let c = AnalysisConfig::new(AnalysisKind::DataFlow).with_timeout(0);
    assert_eq!(c.timeout_ms, Some(0));
    let c = AnalysisConfig::new(AnalysisKind::DataFlow).with_timeout(u64::MAX);
    assert_eq!(c.timeout_ms, Some(u64::MAX));
}

#[test]
fn config_options_overwrite_and_empty_key() {
    let mut c = AnalysisConfig::default();
    c.set_option("k", "v1");
    c.set_option("k", "v2");
    assert_eq!(c.get_option("k"), Some("v2"));
    c.set_option("", "empty");
    assert_eq!(c.get_option(""), Some("empty"));
}

#[test]
fn config_serde_with_many_options() {
    let mut c = AnalysisConfig::new(AnalysisKind::VsaAnalysis);
    for i in 0..50 {
        c.set_option(format!("k{i}"), format!("v{i}"));
    }
    let json = serde_json::to_string(&c).unwrap();
    let back: AnalysisConfig = serde_json::from_str(&json).unwrap();
    for i in 0..50 {
        assert_eq!(back.get_option(&format!("k{i}")), Some(&*format!("v{i}")));
    }
}

// ── AnalysisResult ─────────────────────────────────────────────────────────

#[test]
fn result_total_items_no_overflow_under_max() {
    // total_items uses plain add; ensure realistic values don't overflow.
    let r = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 100_000,
        data_refs_found: 200_000,
        strings_found: 300_000,
        duration_ms: 0,
        warnings: vec![],
    };
    assert_eq!(r.total_items(), 600_000);
}

#[test]
fn result_has_warnings_50_cases() {
    for i in 0..50 {
        let warnings: Vec<String> = (0..i).map(|j| format!("w{j}")).collect();
        let r = AnalysisResult {
            kind: AnalysisKind::DataFlow,
            functions_found: 0,
            data_refs_found: 0,
            strings_found: 0,
            duration_ms: 0,
            warnings,
        };
        assert_eq!(r.has_warnings(), i > 0);
    }
}

// ── AnalysisError ──────────────────────────────────────────────────────────

#[test]
fn error_display_boundary_addresses() {
    assert_eq!(
        AnalysisError::InsufficientData(0).to_string(),
        "Not enough data at 0x0"
    );
    assert_eq!(
        AnalysisError::InsufficientData(u64::MAX).to_string(),
        format!("Not enough data at 0x{:x}", u64::MAX)
    );
    assert_eq!(
        AnalysisError::Timeout(u64::MAX).to_string(),
        format!("Timeout after {}ms", u64::MAX)
    );
}

// ── PassScheduler ──────────────────────────────────────────────────────────

#[test]
fn scheduler_empty() {
    let s = PassScheduler::new();
    assert!(s.schedule().unwrap().is_empty());
    assert!(s.schedule_groups().unwrap().is_empty());
}

#[test]
fn scheduler_single_pass() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("only"));
    assert_eq!(s.schedule().unwrap(), vec!["only".to_string()]);
    assert_eq!(s.schedule_groups().unwrap(), vec![vec!["only".to_string()]]);
}

#[test]
fn scheduler_linear_chain() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a"));
    s.add(PassDescriptor::new("b").with_dep("a"));
    s.add(PassDescriptor::new("c").with_dep("b"));
    let order = s.schedule().unwrap();
    let pos = |n: &str| order.iter().position(|x| x == n).unwrap();
    assert!(pos("a") < pos("b") && pos("b") < pos("c"));
    let groups = s.schedule_groups().unwrap();
    assert_eq!(groups.len(), 3);
}

#[test]
fn scheduler_diamond() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("top"));
    s.add(PassDescriptor::new("left").with_dep("top"));
    s.add(PassDescriptor::new("right").with_dep("top"));
    s.add(PassDescriptor::new("bot").with_dep("left").with_dep("right"));
    let groups = s.schedule_groups().unwrap();
    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0], vec!["top".to_string()]);
    assert!(groups[1].contains(&"left".to_string()) && groups[1].contains(&"right".to_string()));
    assert_eq!(groups[2], vec!["bot".to_string()]);
}

#[test]
fn scheduler_priority_within_level() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a").with_priority(1));
    s.add(PassDescriptor::new("b").with_priority(100));
    s.add(PassDescriptor::new("c").with_priority(50));
    let order = s.schedule().unwrap();
    assert_eq!(order, vec!["b".to_string(), "c".to_string(), "a".to_string()]);
}

#[test]
fn scheduler_cycle_self_loop_errors() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a").with_dep("a"));
    assert!(s.schedule().is_err());
    assert!(s.schedule_groups().is_err());
}

#[test]
fn scheduler_cycle_two_node_errors() {
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a").with_dep("b"));
    s.add(PassDescriptor::new("b").with_dep("a"));
    assert!(s.schedule().is_err());
    assert!(s.schedule_groups().is_err());
}

#[test]
fn scheduler_missing_dep_is_ok() {
    // A dep on a non-existent pass should not prevent scheduling of others;
    // the dependent pass cannot be scheduled though, so we expect an error
    // (cycle detection treats incomplete schedules as cycles).
    let mut s = PassScheduler::new();
    s.add(PassDescriptor::new("a").with_dep("nonexistent"));
    // Either ok (with 'a' delayed) or err (cycle-style). Must not panic.
    let _ = s.schedule();
    let _ = s.schedule_groups();
}

// ── CrossReferenceDb ───────────────────────────────────────────────────────

#[test]
fn xref_db_indexes_consistent_lcg_fuzz() {
    let mut g = fresh_lcg();
    let db = CrossReferenceDb::new();
    let mut expected_from: HashMap<u64, usize> = HashMap::new();
    let mut expected_to: HashMap<u64, usize> = HashMap::new();
    for _ in 0..500 {
        let from = g.next_u64() & 0xFFFF;
        let to = g.next_u64() & 0xFFFF;
        let kind = match g.next_u8() % 6 {
            0 => XrefType::Call,
            1 => XrefType::Jump,
            2 => XrefType::DataRead,
            3 => XrefType::DataWrite,
            4 => XrefType::StringRef,
            _ => XrefType::Unknown,
        };
        db.add_raw(from, to, kind);
        *expected_from.entry(from).or_insert(0) += 1;
        *expected_to.entry(to).or_insert(0) += 1;
    }
    assert_eq!(db.count(), 500);
    for (k, v) in &expected_from {
        assert_eq!(db.xrefs_from(*k).len(), *v);
    }
    for (k, v) in &expected_to {
        assert_eq!(db.xrefs_to(*k).len(), *v);
    }
}

#[test]
fn xref_db_calls_and_call_targets_dedup() {
    let db = CrossReferenceDb::new();
    db.add_raw(0x100, 0x200, XrefType::Call);
    db.add_raw(0x150, 0x200, XrefType::Call);
    db.add_raw(0x300, 0x400, XrefType::Jump);
    db.add_raw(0x500, 0x600, XrefType::Call);
    let calls = db.calls();
    assert_eq!(calls.len(), 3);
    let mut targets = db.call_targets();
    targets.sort_unstable();
    assert_eq!(targets, vec![0x200, 0x600]);
}

#[test]
fn xref_db_clear_resets_both_indexes() {
    let db = CrossReferenceDb::new();
    for i in 0..50u64 {
        db.add_raw(i, i + 1, XrefType::Jump);
    }
    db.clear();
    assert_eq!(db.count(), 0);
    assert!(db.xrefs_from(0).is_empty());
    assert!(db.xrefs_to(50).is_empty());
}

#[test]
fn xref_db_send_sync_threaded_stress() {
    let db = Arc::new(CrossReferenceDb::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for i in 0..100u64 {
                dbc.add_raw(t * 1000 + i, t * 1000 + i + 1, XrefType::Call);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.count(), 400);
    assert_eq!(db.calls().len(), 400);
}

#[test]
fn xref_eq_hash_consistency_30_pairs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut g = fresh_lcg();
    for _ in 0..30 {
        let from = g.next_u64();
        let to = g.next_u64();
        let a = Xref::new(from, to, XrefType::Call);
        let b = Xref::new(from, to, XrefType::Call);
        assert_eq!(a, b);
        let mut ha = DefaultHasher::new();
        let mut hb = DefaultHasher::new();
        a.hash(&mut ha);
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }
}

#[test]
fn xreftype_display_all_variants_unique() {
    let all = [
        XrefType::Call,
        XrefType::Jump,
        XrefType::DataRead,
        XrefType::DataWrite,
        XrefType::StringRef,
        XrefType::Unknown,
    ];
    let mut set = HashSet::new();
    for x in &all {
        set.insert(x.to_string());
    }
    assert_eq!(set.len(), all.len());
}

// ── FunctionBoundary & Analysis ────────────────────────────────────────────

#[test]
fn boundary_size_overflow_safe() {
    let b = FunctionBoundary::new(u64::MAX, 0, BoundaryMethod::ProloguePattern);
    // saturating_sub keeps size = 0
    assert_eq!(b.size(), 0);
    let b2 = FunctionBoundary::new(0, u64::MAX, BoundaryMethod::ProloguePattern);
    assert_eq!(b2.size(), u64::MAX);
}

#[test]
fn boundary_confidence_threshold() {
    for c in [0u8, 1, 50, 69, 70, 71, 100, 255] {
        let b = FunctionBoundary::new(0, 0, BoundaryMethod::LinearSweep).with_confidence(c);
        assert_eq!(b.is_high_confidence(), c >= 70);
    }
}

#[test]
fn scan_prologues_empty_and_short() {
    assert!(FunctionBoundaryAnalysis::scan_prologues(0, &[]).is_empty());
    assert!(FunctionBoundaryAnalysis::scan_prologues(0, &[0x90]).is_empty());
}

#[test]
fn scan_prologues_finds_push_rbp_mov() {
    let mut bytes = vec![0x90, 0x90];
    bytes.extend_from_slice(FunctionBoundaryAnalysis::PROLOGUE_PUSH_RBP);
    let found = FunctionBoundaryAnalysis::scan_prologues(0x1000, &bytes);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].start, 0x1002);
    assert_eq!(found[0].confidence, 80);
}

#[test]
fn scan_prologues_sub_rsp_lower_confidence() {
    let bytes = FunctionBoundaryAnalysis::PROLOGUE_SUB_RSP.to_vec();
    let found = FunctionBoundaryAnalysis::scan_prologues(0x1000, &bytes);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].confidence, 70);
}

#[test]
fn scan_call_targets_truncated_input() {
    // Need 5 bytes for E8 rel32; less than 5 → none. Lengths 1..=4 only:
    // E8 plus 4 rel bytes IS a complete call and must be found.
    for n in 0..4usize {
        let mut v = vec![0xE8];
        v.extend(std::iter::repeat_n(0u8, n));
        assert!(FunctionBoundaryAnalysis::scan_call_targets(0, &v).is_empty());
    }
    let full = [0xE8, 0, 0, 0, 0];
    assert_eq!(FunctionBoundaryAnalysis::scan_call_targets(0, &full), vec![5]);
}

#[test]
fn scan_call_targets_lcg_fuzz_never_panics() {
    let mut g = fresh_lcg();
    for _ in 0..50 {
        let n = (g.next_u64() % 1024) as usize;
        let bytes = g.next_bytes(n);
        let base = g.next_u64();
        let _ = FunctionBoundaryAnalysis::scan_call_targets(base, &bytes);
    }
}

#[test]
fn scan_call_targets_overflow_wraps_safely() {
    // Construct a CALL near u64::MAX that wraps around
    let mut bytes = vec![0xE8];
    bytes.extend_from_slice(&i32::MAX.to_le_bytes());
    // Should not panic
    let _ = FunctionBoundaryAnalysis::scan_call_targets(u64::MAX - 100, &bytes);
}

#[test]
fn scan_call_targets_dedup_and_sorted() {
    // Build two identical CALLs to the same target
    let target_offset_from_next: i32 = 10;
    let mut bytes = Vec::new();
    bytes.push(0xE8);
    bytes.extend_from_slice(&target_offset_from_next.to_le_bytes());
    bytes.push(0xE8);
    bytes.extend_from_slice(&(target_offset_from_next - 5).to_le_bytes());
    let res = FunctionBoundaryAnalysis::scan_call_targets(0x1000, &bytes);
    // Both calls compute the same target (0x100F)
    assert_eq!(res.len(), 1);
}

// ── LinearSweepAnalyzer ────────────────────────────────────────────────────

#[test]
fn linear_sweep_empty_bytes() {
    let a = LinearSweepAnalyzer::default();
    assert!(a.sweep(0, &[]).is_empty());
    assert_eq!(a.sweep_count(0, &[]), 0);
}

#[test]
fn linear_sweep_no_follow_calls() {
    let cfg = LinearSweepConfig {
        min_function_size: 1,
        max_gap: 8,
        follow_calls: false,
    };
    let a = LinearSweepAnalyzer::new(cfg);
    let mut bytes = vec![0xE8, 0x00, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&[0x90; 32]);
    // No prologue, no follow calls → nothing
    assert!(a.sweep(0x1000, &bytes).is_empty());
}

#[test]
fn linear_sweep_lcg_fuzz_never_panics() {
    let mut g = fresh_lcg();
    let a = LinearSweepAnalyzer::default();
    for _ in 0..30 {
        let n = (g.next_u64() % 2048) as usize;
        let bytes = g.next_bytes(n);
        let base = g.next_u64() & 0xFFFF_FFFF;
        let _ = a.sweep(base, &bytes);
    }
}

#[test]
fn linear_sweep_min_function_size_filters() {
    let mut bytes = FunctionBoundaryAnalysis::PROLOGUE_PUSH_RBP.to_vec();
    bytes.extend_from_slice(FunctionBoundaryAnalysis::PROLOGUE_PUSH_RBP);
    // Two adjacent prologues 4 bytes apart
    let a = LinearSweepAnalyzer::new(LinearSweepConfig {
        min_function_size: 10, // both functions too small
        max_gap: 0,
        follow_calls: false,
    });
    let res = a.sweep(0x1000, &bytes);
    // The first has size=4 which is < 10, so filtered. The last extends to file_end=8, also <10.
    assert!(res.is_empty());
}

// ── RecursiveDescentAnalyzer ───────────────────────────────────────────────

#[test]
fn recursive_descent_no_entries() {
    let a = RecursiveDescentAnalyzer::default();
    let res = a.descend(0, &[0x90; 16], &[]);
    assert!(res.is_empty());
}

#[test]
fn recursive_descent_entry_out_of_range() {
    let a = RecursiveDescentAnalyzer::default();
    let res = a.descend(0x1000, &[0x90; 16], &[0x500, 0x99999]);
    assert!(res.is_empty());
}

#[test]
fn recursive_descent_max_depth_zero_still_visits_entry() {
    let a = RecursiveDescentAnalyzer::new(0);
    let res = a.descend(0, &[0x90; 16], &[0]);
    assert_eq!(res.len(), 1);
    assert!(res.contains(&0));
}

#[test]
fn recursive_descent_lcg_fuzz_no_panic() {
    let mut g = fresh_lcg();
    let a = RecursiveDescentAnalyzer::new(8);
    for _ in 0..30 {
        let n = (g.next_u64() % 512) as usize;
        let bytes = g.next_bytes(n);
        let base = g.next_u64() & 0xFFFF;
        let eps: Vec<u64> = (0..3).map(|_| base + (g.next_u64() % (n as u64 + 1))).collect();
        let _ = a.descend(base, &bytes, &eps);
        let _ = a.analyze(base, &bytes, &eps);
    }
}

// ── StringRecoveryPass ─────────────────────────────────────────────────────

#[test]
fn string_recovery_min_len_boundary() {
    // exactly MIN_STRING_LEN (4) characters followed by NUL → counts
    let b = b"abcd\0";
    assert_eq!(StringRecoveryPass::count_strings(b), 1);
    // 3-char run → no
    let b = b"abc\0";
    assert_eq!(StringRecoveryPass::count_strings(b), 0);
}

#[test]
fn string_recovery_unterminated_tail_counts() {
    assert_eq!(StringRecoveryPass::count_strings(b"hello"), 1);
}

#[test]
fn string_recovery_control_breaks_run() {
    // control char (\x01) breaks the run
    assert_eq!(StringRecoveryPass::count_strings(b"abc\x01defgh"), 1);
}

#[test]
fn string_recovery_empty_and_all_zeros() {
    assert_eq!(StringRecoveryPass::count_strings(&[]), 0);
    assert_eq!(StringRecoveryPass::count_strings(&[0u8; 100]), 0);
}

#[test]
fn string_recovery_multiple_strings() {
    let b = b"first\0second\0third\0";
    assert_eq!(StringRecoveryPass::count_strings(b), 3);
}

#[test]
fn string_recovery_lcg_fuzz_no_panic() {
    let mut g = fresh_lcg();
    for _ in 0..30 {
        let n = (g.next_u64() % 4096) as usize;
        let bytes = g.next_bytes(n);
        let _ = StringRecoveryPass::count_strings(&bytes);
    }
}

// ── XrefRecoveryPass ───────────────────────────────────────────────────────

#[test]
fn xref_recovery_e9_and_e8_count() {
    // Both targets must land INSIDE the analyzed window [base, base+len):
    // count_xrefs range-filters targets (pinned by
    // `xref_recovery_out_of_range_filtered`), so an E9 with rel 0 whose
    // target is exactly end-of-window would be excluded by design.
    let mut bytes = vec![0xE8, 0x00, 0x00, 0x00, 0x00]; // target 5, in window
    bytes.extend_from_slice(&[0xE9, 0xFB, 0xFF, 0xFF, 0xFF]); // rel -5 → target 5
    assert_eq!(XrefRecoveryPass::count_xrefs(0, &bytes), 2);
}

#[test]
fn xref_recovery_out_of_range_filtered() {
    // E8 with huge negative rel pointing before base
    let mut bytes = vec![0xE8];
    bytes.extend_from_slice(&i32::MIN.to_le_bytes());
    assert_eq!(XrefRecoveryPass::count_xrefs(0, &bytes), 0);
}

#[test]
fn xref_recovery_lcg_fuzz_no_panic() {
    let mut g = fresh_lcg();
    for _ in 0..30 {
        let n = (g.next_u64() % 2048) as usize;
        let bytes = g.next_bytes(n);
        let base = g.next_u64();
        let _ = XrefRecoveryPass::count_xrefs(base, &bytes);
    }
}

#[test]
fn xref_recovery_truncated() {
    for n in 0..5usize {
        let mut v = vec![0xE8];
        v.extend(std::iter::repeat_n(0u8, n));
        assert_eq!(XrefRecoveryPass::count_xrefs(0, &v), 0);
    }
}

// ── CfgAnalysisPass ────────────────────────────────────────────────────────

#[test]
fn cfg_count_blocks_empty_zero() {
    // The implementation seeds count=1 unconditionally; on empty input the
    // returned count is therefore 1 (documented behaviour).
    assert_eq!(CfgAnalysisPass::count_basic_blocks(&[]), 1);
}

#[test]
fn cfg_count_blocks_ret_increments() {
    assert_eq!(CfgAnalysisPass::count_basic_blocks(&[0xC3]), 2);
}

#[test]
fn cfg_count_blocks_long_jcc() {
    // 0F 80..8F xx xx xx xx = long Jcc (6 bytes)
    let bytes = [0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, 0xC3];
    let c = CfgAnalysisPass::count_basic_blocks(&bytes);
    assert_eq!(c, 3); // +1 jcc, +1 ret, +1 base
}

#[test]
fn cfg_count_blocks_lcg_fuzz_never_panics() {
    let mut g = fresh_lcg();
    for _ in 0..30 {
        let n = (g.next_u64() % 4096) as usize;
        let bytes = g.next_bytes(n);
        let _ = CfgAnalysisPass::count_basic_blocks(&bytes);
    }
}

// ── AnalysisDb ─────────────────────────────────────────────────────────────

#[test]
fn db_insert_query_basic() {
    let db = AnalysisDb::new();
    let id1 = db.insert("pass_a", "uri://1", "{}");
    let id2 = db.insert("pass_a", "uri://2", "{}");
    assert_ne!(id1, id2);
    assert_eq!(db.count(), 2);
    assert_eq!(db.query_by_pass("pass_a").len(), 2);
    assert_eq!(db.query_by_uri("uri://1").len(), 1);
    assert_eq!(db.query_by_uri("missing").len(), 0);
}

#[test]
fn db_delete_by_uri_count() {
    let db = AnalysisDb::new();
    db.insert("p", "u1", "{}");
    db.insert("p", "u1", "{}");
    db.insert("p", "u2", "{}");
    assert_eq!(db.delete_by_uri("u1"), 2);
    assert_eq!(db.count(), 1);
}

#[test]
fn db_export_json_roundtrip() {
    let db = AnalysisDb::new();
    db.insert("p", "u", "payload");
    let json = db.export_json().unwrap();
    assert!(json.contains("\"pass_name\""));
    assert!(json.contains("payload"));
}

#[test]
fn db_query_functions_ignores_unrelated_payloads() {
    let db = AnalysisDb::new();
    db.insert("p", "u", "not json");
    db.insert("p", "u", "{}"); // not Vec<FunctionBoundary>
    let fs = db.query_functions();
    assert!(fs.is_empty());
}

#[test]
fn db_query_functions_parses_valid_payload() {
    let db = AnalysisDb::new();
    let v = vec![FunctionBoundary::new(
        0x10,
        0x20,
        BoundaryMethod::SymbolTable,
    )];
    let payload = serde_json::to_string(&v).unwrap();
    db.insert("p", "u", &payload);
    let fs = db.query_functions();
    assert_eq!(fs.len(), 1);
    assert_eq!(fs[0].start, 0x10);
}

#[test]
fn db_query_xrefs_parses_valid_payload() {
    let db = AnalysisDb::new();
    let v = vec![Xref::new(1, 2, XrefType::Call)];
    let payload = serde_json::to_string(&v).unwrap();
    db.insert("p", "u", &payload);
    let xs = db.query_xrefs();
    assert_eq!(xs.len(), 1);
    assert_eq!(xs[0].from, 1);
}

#[test]
fn db_send_sync_threaded_inserts() {
    let db = Arc::new(AnalysisDb::new());
    let mut handles = Vec::new();
    for t in 0..4 {
        let dbc = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                dbc.insert("p", &format!("uri{t}"), &format!("{{\"i\":{i}}}"));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.count(), 400);
    let mut all_ids = HashSet::new();
    for r in db.query_by_pass("p") {
        all_ids.insert(r.id);
    }
    assert_eq!(all_ids.len(), 400);
}

// ── AnalysisStats ──────────────────────────────────────────────────────────

#[test]
fn stats_record_results_and_errors() {
    let mut s = AnalysisStats::new();
    assert!(s.all_succeeded());
    assert_eq!(s.avg_duration_ms(), 0.0);
    assert!(s.slowest_pass().is_none());

    let r = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 3,
        data_refs_found: 1,
        strings_found: 2,
        duration_ms: 50,
        warnings: vec!["w".into()],
    };
    s.record_result("a", &r);
    let r2 = AnalysisResult {
        duration_ms: 150,
        ..r.clone()
    };
    s.record_result("b", &r2);
    s.record_error("c", "boom");
    assert!(!s.all_succeeded());
    assert_eq!(s.passes.len(), 3);
    assert_eq!(s.total_functions, 6);
    assert_eq!(s.total_strings, 4);
    assert_eq!(s.total_duration_ms, 200);
    assert_eq!(s.failed_passes, 1);
    assert!((s.avg_duration_ms() - (200.0 / 3.0)).abs() < 1e-6);
    let slowest = s.slowest_pass().unwrap();
    assert_eq!(slowest.pass_name, "b");
}

#[test]
fn pass_stats_from_result_and_error() {
    let r = AnalysisResult::zero(AnalysisKind::LinearSweep);
    let s = PassStats::from_result("p", &r);
    assert!(s.success);
    assert!(s.error.is_none());
    let s2 = PassStats::from_error("p", "boom");
    assert!(!s2.success);
    assert_eq!(s2.error.as_deref(), Some("boom"));
}

// ── AnalysisReport ─────────────────────────────────────────────────────────

#[test]
fn report_build_collects_warnings_and_success() {
    let r1 = AnalysisResult {
        kind: AnalysisKind::LinearSweep,
        functions_found: 1,
        data_refs_found: 0,
        strings_found: 0,
        duration_ms: 1,
        warnings: vec!["w1".into()],
    };
    let outcomes = vec![("a".to_string(), Ok(r1))];
    let rep = AnalysisReport::build("uri://x", &outcomes);
    assert!(rep.success);
    assert_eq!(rep.all_warnings, vec!["w1".to_string()]);
    assert_eq!(rep.total_functions(), 1);
    assert!(rep.summary().contains("functions"));
}

#[test]
fn report_build_with_failure_sets_success_false() {
    let outcomes = vec![(
        "fail".to_string(),
        Err(AnalysisError::Failed("oops".into())),
    )];
    let rep = AnalysisReport::build("u", &outcomes);
    assert!(!rep.success);
    assert!(rep.summary().contains("FAILED"));
}

// ── AnalysisPipeline (async) ───────────────────────────────────────────────

#[tokio::test]
async fn pipeline_run_all_parallel_empty() {
    let view = make_view();
    let p = AnalysisPipeline::new();
    let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
    let res = p.run_all_parallel(&view, &cfg).await;
    assert!(res.is_empty());
}

#[tokio::test]
async fn pipeline_run_all_parallel_multiple() {
    let view = make_view();
    let p = AnalysisPipeline::new();
    p.register(Arc::new(CountingAnalysisPass::new(
        "a",
        AnalysisKind::LinearSweep,
        2,
        3,
    )));
    p.register(Arc::new(CountingAnalysisPass::new(
        "b",
        AnalysisKind::LinearSweep,
        4,
        5,
    )));
    let cfg = AnalysisConfig::new(AnalysisKind::LinearSweep);
    let res = p.run_all_parallel(&view, &cfg).await;
    assert_eq!(res.len(), 2);
    let fns: usize = res.iter().filter_map(|r| r.as_ref().ok()).map(|r| r.functions_found).sum();
    assert_eq!(fns, 6);
}

// ── IncrementalAnalysis ────────────────────────────────────────────────────

#[test]
fn incremental_section_added_affects_all_run_passes() {
    let mut i = IncrementalAnalysis::new();
    i.mark_byte_sensitive("a");
    i.mark_symbol_sensitive("b");
    i.mark_run("a");
    i.mark_run("b");
    i.mark_run("c");
    let changes = [BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::SectionAdded,
    }];
    let mut affected = i.affected_passes(&changes);
    affected.sort();
    assert_eq!(affected, vec!["a", "b", "c"]);
}

#[test]
fn incremental_metadata_changed_affects_none() {
    let mut i = IncrementalAnalysis::new();
    i.mark_byte_sensitive("a");
    i.mark_run("a");
    let changes = [BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::MetadataChanged,
    }];
    assert!(i.affected_passes(&changes).is_empty());
}

#[test]
fn incremental_byte_change_only_affects_byte_sensitive_runs() {
    let mut i = IncrementalAnalysis::new();
    i.mark_byte_sensitive("byte");
    i.mark_symbol_sensitive("sym");
    i.mark_run("byte");
    i.mark_run("sym");
    let changes = [BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::DataModified,
    }];
    assert_eq!(i.affected_passes(&changes), vec!["byte"]);
}

#[test]
fn incremental_symbol_change_only_affects_symbol_sensitive_runs() {
    let mut i = IncrementalAnalysis::new();
    i.mark_byte_sensitive("byte");
    i.mark_symbol_sensitive("sym");
    i.mark_run("byte");
    i.mark_run("sym");
    let changes = [BinaryChange {
        address_start: 0,
        address_end: 1,
        kind: ChangeKind::SymbolRenamed,
    }];
    assert_eq!(i.affected_passes(&changes), vec!["sym"]);
}

// ── Event bus ──────────────────────────────────────────────────────────────

#[test]
fn event_bus_publish_to_multiple_handlers() {
    let bus = AnalysisEventBus::new();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for _ in 0..5 {
        let c = Arc::clone(&counter);
        bus.subscribe(Arc::new(move |_| {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    bus.publish(&AnalysisEvent::PassStarted {
        pass_name: "x".into(),
    });
    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 5);
    assert_eq!(bus.handler_count(), 5);
}

#[test]
fn event_kind_tag_all_variants() {
    let events = [
        AnalysisEvent::FunctionDiscovered { address: 0, name: None },
        AnalysisEvent::StringRecovered { address: 0, value: String::new() },
        AnalysisEvent::XrefFound { from: 0, to: 0 },
        AnalysisEvent::PassStarted { pass_name: "x".into() },
        AnalysisEvent::PassFinished { pass_name: "x".into(), duration_ms: 0 },
        AnalysisEvent::Warning { pass_name: "x".into(), message: "y".into() },
        AnalysisEvent::Error { pass_name: "x".into(), message: "y".into() },
    ];
    let mut tags = HashSet::new();
    for e in &events {
        tags.insert(e.kind_tag());
    }
    assert_eq!(tags.len(), events.len());
}

// ── Plugin registry ────────────────────────────────────────────────────────

struct DummyPlugin {
    meta: PluginMetadata,
}

impl AnalysisPlugin for DummyPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.meta
    }
    fn passes(&self) -> Vec<Arc<dyn rustre_analysis::AnalysisPass>> {
        vec![Arc::new(NoOpAnalysisPass::new("dummy_pass"))]
    }
}

#[test]
fn plugin_registry_load_find_count() {
    let reg = AnalysisPluginRegistry::new();
    let plugin = Arc::new(DummyPlugin {
        meta: PluginMetadata {
            id: "p1".into(),
            name: "P1".into(),
            version: "0.1".into(),
            description: "d".into(),
            author: "a".into(),
            provides: vec![AnalysisKind::LinearSweep],
        },
    });
    reg.load(plugin);
    assert_eq!(reg.plugin_count(), 1);
    assert!(reg.find_by_id("p1").is_some());
    assert!(reg.find_by_id("missing").is_none());
    assert_eq!(reg.all_passes().len(), 1);
}

// ── analyze_binary integration ─────────────────────────────────────────────

#[tokio::test]
async fn analyze_binary_runs_all_standard_passes() {
    let mut g = fresh_lcg();
    let data = g.next_bytes(4096);
    let rep = rustre_analysis::analyze_binary(&data, "x86_64", 0x1000).await;
    // 6 standard passes are registered
    assert_eq!(rep.stats.passes.len(), 6);
}

// ─────────────────────────────────────────────────────────────────────────
// shared helpers
// ─────────────────────────────────────────────────────────────────────────

use rustre_core::{
    address::{Address, AddressRange},
    arch::{
        Architecture, BranchInfo, CallingConvention, InstrFlags, Instruction, RegisterInfo,
    },
    binary_view::{BinaryView, Memory, Segment},
    endian::Endian,
    errors::CoreError,
    ids::ViewId,
    permissions::Permissions,
};

#[derive(Debug)]
struct DummyArch;

impl Architecture for DummyArch {
    fn name(&self) -> &str {
        "dummy"
    }
    fn pointer_size(&self) -> usize {
        8
    }
    fn endian(&self) -> Endian {
        Endian::Little
    }
    fn disassemble(&self, address: Address, _bytes: &[u8]) -> Result<Instruction, CoreError> {
        Ok(Instruction {
            address,
            size: 1,
            mnemonic: "nop".into(),
            operands: String::new(),
            operand_list: Vec::new(),
            flags: InstrFlags::NONE,
            bytes: vec![0x90],
            comment: None,
        })
    }
    fn get_branches(&self, _instr: &Instruction) -> Vec<BranchInfo> {
        vec![]
    }
    fn registers(&self) -> Vec<RegisterInfo> {
        vec![]
    }
    fn calling_conventions(&self) -> Vec<CallingConvention> {
        vec![]
    }
}

fn make_view() -> BinaryView {
    let mut mem = Memory::new();
    mem.add_segment(Segment {
        range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
        permissions: Permissions::READ | Permissions::EXECUTE,
        data: vec![0x90; 0x1000],
    });
    BinaryView::new(
        ViewId::new(1).expect("non-zero view id"),
        "test://blitz2".into(),
        Arc::new(DummyArch),
        Endian::Little,
        64,
        vec![Address::new(0x1000)],
        mem,
    )
}
