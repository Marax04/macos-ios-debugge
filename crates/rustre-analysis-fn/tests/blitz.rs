//! Adversarial / exhaustive test suite for `rustre-analysis-fn` lib.rs surface.

use rustre_analysis_fn::*;
use rustre_core::address::{Address, AddressRange};

// ── MemorySlice ──────────────────────────────────────────────────────────────

#[test]
fn memslice_empty() {
    let mem = MemorySlice::new(Address::new(0x1000), &[]);
    assert!(mem.is_empty());
    assert_eq!(mem.len(), 0);
    assert_eq!(mem.read_u8(Address::new(0x1000)), None);
    assert!(!mem.contains(Address::new(0x1000)));
    assert_eq!(mem.end(), Address::new(0x1000));
}

#[test]
fn memslice_read_u16_at_last_byte_returns_none() {
    let data = [0xAA, 0xBB, 0xCC];
    let mem = MemorySlice::new(Address::new(0), &data);
    assert_eq!(mem.read_u16_le(Address::new(2)), None);
}

#[test]
fn memslice_read_u32_partial_returns_none() {
    let data = [1u8, 2, 3];
    let mem = MemorySlice::new(Address::new(0), &data);
    assert_eq!(mem.read_u32_le(Address::new(0)), None);
}

#[test]
fn memslice_read_u64_at_offset_with_insufficient_bytes() {
    let data = [0u8; 8];
    let mem = MemorySlice::new(Address::new(0), &data);
    // Reading u64 starting at offset 1 needs bytes 1..9, only 7 available
    assert_eq!(mem.read_u64_le(Address::new(1)), None);
    assert_eq!(mem.read_u64_le(Address::new(0)), Some(0));
}

#[test]
fn memslice_slice_at_zero_len_at_end() {
    let data = [1u8, 2, 3, 4];
    let mem = MemorySlice::new(Address::new(0x100), &data);
    // Slice at the last valid offset with len 1 must succeed
    assert_eq!(mem.slice_at(Address::new(0x103), 1), Some([4u8].as_slice()));
    // Slice past the end must fail
    assert_eq!(mem.slice_at(Address::new(0x104), 1), None);
}

#[test]
fn memslice_contains_boundaries() {
    let data = [0u8; 4];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    assert!(mem.contains(Address::new(0x1000)));
    assert!(mem.contains(Address::new(0x1003)));
    assert!(!mem.contains(Address::new(0x1004)));
}

#[test]
fn memslice_end_wraps_safely_near_u64_max() {
    // Base near top of address space + small slice should wrap via wrapping_add.
    let data = [0u8; 4];
    let mem = MemorySlice::new(Address::new(u64::MAX - 1), &data);
    // end is base + 4 which wraps
    let _ = mem.end();
}

// ── FunctionBoundary ─────────────────────────────────────────────────────────

#[test]
fn boundary_byte_size_none_when_no_end() {
    let fb = FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::CallTarget);
    assert_eq!(fb.byte_size(), None);
}

#[test]
fn boundary_byte_size_basic() {
    let fb = FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::CallTarget)
        .with_end(Address::new(0x1020));
    assert_eq!(fb.byte_size(), Some(0x20));
}

#[test]
fn boundary_byte_size_saturates_when_end_before_start() {
    let fb = FunctionBoundary::new(Address::new(0x1000), Confidence::Low, DetectionSource::User)
        .with_end(Address::new(0x500));
    // saturating_sub → 0
    assert_eq!(fb.byte_size(), Some(0));
}

#[test]
fn boundary_with_name() {
    let fb = FunctionBoundary::new(Address::new(0), Confidence::Certain, DetectionSource::SymbolTable)
        .with_name("main");
    assert_eq!(fb.name.as_deref(), Some("main"));
}

#[test]
fn confidence_ordering() {
    assert!(Confidence::Low < Confidence::Medium);
    assert!(Confidence::Medium < Confidence::High);
    assert!(Confidence::High < Confidence::Certain);
}

// ── ProloguePattern ──────────────────────────────────────────────────────────

#[test]
fn prologue_empty_pattern_matches_anything() {
    let pat = ProloguePattern {
        name: "empty",
        arch: "x86_64",
        bytes: &[],
        confidence: Confidence::Low,
    };
    // Vacuously true: zip of zero elements + iter::all returns true.
    assert!(pat.matches(&[0xFF]));
    assert!(pat.matches(&[]));
    assert_eq!(pat.min_len(), 0);
}

#[test]
fn prologue_all_wildcards_matches_any_long_enough_input() {
    let pat = ProloguePattern {
        name: "all_wild",
        arch: "x86_64",
        bytes: &[None, None, None],
        confidence: Confidence::Low,
    };
    assert!(pat.matches(&[0, 1, 2]));
    assert!(pat.matches(&[0xFF, 0xFF, 0xFF, 0xFF]));
    assert!(!pat.matches(&[0, 1]));
}

#[test]
fn all_x86_64_patterns_distinct_names() {
    let pats = x86_64_prologue_patterns();
    let mut names: Vec<&str> = pats.iter().map(|p| p.name).collect();
    names.sort_unstable();
    let n = names.len();
    names.dedup();
    assert_eq!(n, names.len(), "duplicate pattern names");
}

#[test]
fn all_patterns_have_correct_arch_label() {
    for p in x86_64_prologue_patterns() {
        assert_eq!(p.arch, "x86_64");
    }
    for p in x86_32_prologue_patterns() {
        assert_eq!(p.arch, "x86_32");
    }
    for p in arm64_prologue_patterns() {
        assert_eq!(p.arch, "arm64");
    }
}

#[test]
fn classical_x86_64_prologue_matches_real_bytes() {
    // push rbp; mov rbp, rsp
    let bytes = [0x55u8, 0x48, 0x89, 0xE5, 0x90];
    let pats = x86_64_prologue_patterns();
    assert!(pats.iter().any(|p| p.matches(&bytes)));
}

// ── CallTargetCollector ──────────────────────────────────────────────────────

#[test]
fn call_collector_empty_slice() {
    let mem = MemorySlice::new(Address::new(0), &[]);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    assert!(c.collect(&mem).is_empty());
}

#[test]
fn call_collector_too_small_for_call() {
    // 4 bytes < 5 bytes needed for E8 imm32
    let data = [0xE8, 0, 0, 0];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    assert!(c.collect(&mem).is_empty());
}

#[test]
fn call_collector_x86_forward_call() {
    // base 0x1000: E8 05 00 00 00 -> next_pc=0x1005, target=0x100A
    let mut data = vec![0x90u8; 16];
    data[0] = 0xE8;
    data[1..5].copy_from_slice(&5i32.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    let t = c.collect(&mem);
    assert!(t.contains(&Address::new(0x100A)));
}

#[test]
fn call_collector_x86_backward_call() {
    // base 0x2000, at offset 10: E8 with disp = -10 -> target = 0x2000+10+5-10 = 0x2005
    let mut data = vec![0x90u8; 32];
    data[10] = 0xE8;
    let disp: i32 = -10;
    data[11..15].copy_from_slice(&disp.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x2000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    let t = c.collect(&mem);
    assert!(t.contains(&Address::new(0x2005)));
}

#[test]
fn call_collector_range_filter() {
    // Target 0x100A but only accept [0x2000, 0x3000)
    let mut data = vec![0x90u8; 16];
    data[0] = 0xE8;
    data[1] = 0x05;
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64)
        .with_range(Address::new(0x2000), Address::new(0x3000));
    assert!(c.collect(&mem).is_empty());
}

#[test]
fn call_collector_dedup_and_sort() {
    // Two identical CALLs to the same target.
    let mut data = vec![0x90u8; 32];
    data[0] = 0xE8;
    data[1..5].copy_from_slice(&0x0Ai32.to_le_bytes()); // target 0x100F
    data[10] = 0xE8;
    // disp from offset 10: next_pc=15, want target=0x100F → disp=0
    data[11..15].copy_from_slice(&0i32.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    let t = c.collect(&mem);
    // sorted + deduped
    let mut sorted = t.clone();
    sorted.sort_by_key(|a| a.as_u64());
    sorted.dedup();
    assert_eq!(t, sorted);
}

#[test]
fn call_collector_arm64_bl_forward() {
    // BL opcode = 100101 in bits[31:26]. Word = 0x94000001 → offset_instr=1 → byte_offset=4
    let word: u32 = 0x9400_0001;
    let mut data = vec![0u8; 16];
    data[0..4].copy_from_slice(&word.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x4000), &data);
    let c = CallTargetCollector::new(DetectedArch::Arm64);
    let t = c.collect(&mem);
    // pc=0x4000 + 4 = 0x4004
    assert!(t.contains(&Address::new(0x4004)));
}

#[test]
fn call_collector_arm64_bl_backward() {
    // imm26 = 0x3FFFFFF (-1 after sign-extension) → offset_instr=-1 → byte_offset=-4
    let word: u32 = (0b10_0101 << 26) | 0x03FF_FFFF;
    let mut data = vec![0u8; 16];
    data[8..12].copy_from_slice(&word.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x5000), &data);
    let c = CallTargetCollector::new(DetectedArch::Arm64);
    let t = c.collect(&mem);
    // pc = 0x5000 + 8 = 0x5008, target = 0x5008 - 4 = 0x5004
    assert!(t.contains(&Address::new(0x5004)));
}

#[test]
fn call_collector_unknown_arch_falls_back_to_x86() {
    let mut data = vec![0x90u8; 16];
    data[0] = 0xE8;
    data[1..5].copy_from_slice(&5i32.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::Unknown);
    assert!(c.collect(&mem).contains(&Address::new(0x100A)));
}

// ── GapAnalyzer ──────────────────────────────────────────────────────────────

#[test]
fn gap_default_settings() {
    let g = GapAnalyzer::default();
    assert_eq!(g.min_gap_size, 8);
    assert_eq!(g.nop_byte, 0x90);
    assert_eq!(g.int3_byte, 0xCC);
}

#[test]
fn gap_with_nop_setter() {
    let g = GapAnalyzer::new().with_nop(0x00);
    assert_eq!(g.nop_byte, 0x00);
}

#[test]
fn gap_empty_known_returns_whole_range() {
    let mem = MemorySlice::new(Address::new(0x1000), &[0u8; 64]);
    let g = GapAnalyzer::new();
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x1040));
    let gaps = g.find_gaps(&[], range, &mem);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].start, Address::new(0x1000));
}

#[test]
fn gap_between_two_known() {
    let mem = MemorySlice::new(Address::new(0x1000), &[0u8; 128]);
    let g = GapAnalyzer::new();
    let starts = [Address::new(0x1000), Address::new(0x1040)];
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x1080));
    let gaps = g.find_gaps(&starts, range, &mem);
    // Expect gap [0x1000,0x1040) and [0x1040,0x1080)
    assert!(gaps.iter().any(|g| g.start == Address::new(0x1000) && g.end == Address::new(0x1040)));
    assert!(gaps.iter().any(|g| g.start == Address::new(0x1040) && g.end == Address::new(0x1080)));
}

#[test]
fn gap_below_min_size_filtered() {
    let mem = MemorySlice::new(Address::new(0x1000), &[0u8; 16]);
    let g = GapAnalyzer { min_gap_size: 100, nop_byte: 0x90, int3_byte: 0xCC };
    let range = AddressRange::new(Address::new(0x1000), Address::new(0x1010));
    assert!(g.find_gaps(&[], range, &mem).is_empty());
}

#[test]
fn gap_first_code_byte_skips_padding() {
    let mut data = vec![0x90u8; 8];
    data.push(0xAB); // first real code byte
    data.extend_from_slice(&[0u8; 4]);
    let mem = MemorySlice::new(Address::new(0x2000), &data);
    let g = GapAnalyzer::new();
    let gap = AddressRange::new(Address::new(0x2000), Address::new(0x200D));
    assert_eq!(g.first_code_byte(gap, &mem), Some(Address::new(0x2008)));
}

#[test]
fn gap_first_code_byte_all_padding_returns_none() {
    let data = vec![0x90u8, 0xCC, 0x90, 0xCC];
    let mem = MemorySlice::new(Address::new(0x3000), &data);
    let g = GapAnalyzer::new();
    let gap = AddressRange::new(Address::new(0x3000), Address::new(0x3004));
    assert_eq!(g.first_code_byte(gap, &mem), None);
}

// ── FunctionDetector ─────────────────────────────────────────────────────────

#[test]
fn detector_disable_chains() {
    let d = FunctionDetector::new(DetectedArch::X86_64)
        .disable_prologue_scan()
        .disable_gap_analysis();
    assert!(!d.enable_prologue_scan);
    assert!(!d.enable_gap_analysis);
    assert!(d.enable_call_target_scan);
}

#[test]
fn detector_with_arch() {
    let d = FunctionDetector::new(DetectedArch::Unknown).with_arch(DetectedArch::Arm64);
    assert_eq!(d.arch, DetectedArch::Arm64);
}

#[test]
fn detector_analyze_empty_slice() {
    let mem = MemorySlice::new(Address::new(0x1000), &[]);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    assert!(d.analyze(&mem, Vec::new()).is_empty());
}

#[test]
fn detector_scan_prologues_finds_classical() {
    let mut data = vec![0u8; 32];
    data[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    let res = d.scan_prologues(&mem);
    assert!(res.iter().any(|fb| fb.start == Address::new(0x1000)));
}

#[test]
fn detector_estimate_end_x86_ret() {
    // start with mov... then ret (C3) at offset 3
    let data = vec![0x48u8, 0x89, 0xE5, 0xC3, 0x90];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    let end = d.estimate_end(Address::new(0x1000), &mem);
    assert_eq!(end, Some(Address::new(0x1004)));
}

#[test]
fn detector_estimate_end_x86_ret_imm16() {
    let data = vec![0xC2u8, 0x04, 0x00];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    assert_eq!(d.estimate_end(Address::new(0x1000), &mem), Some(Address::new(0x1003)));
}

#[test]
fn detector_estimate_end_x86_jmp_rel8() {
    let data = vec![0xEBu8, 0x10];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    assert_eq!(d.estimate_end(Address::new(0x1000), &mem), Some(Address::new(0x1002)));
}

#[test]
fn detector_estimate_end_x86_jmp_rel32() {
    let data = vec![0xE9u8, 0, 0, 0, 0];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    assert_eq!(d.estimate_end(Address::new(0x1000), &mem), Some(Address::new(0x1005)));
}

#[test]
fn detector_estimate_end_int3_padding() {
    let data = vec![0x90u8, 0x90, 0xCC, 0xCC];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    // INT3 at offset 2 ends function (CC is not at start)
    assert_eq!(d.estimate_end(Address::new(0x1000), &mem), Some(Address::new(0x1002)));
}

#[test]
fn detector_estimate_end_arm64_ret() {
    // RET = 0xD65F03C0
    let word: u32 = 0xD65F_03C0;
    let mut data = vec![0u8; 8];
    data[4..8].copy_from_slice(&word.to_le_bytes());
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::Arm64);
    let end = d.estimate_end(Address::new(0x1000), &mem);
    assert_eq!(end, Some(Address::new(0x1008)));
}

#[test]
fn detector_estimate_end_no_terminator() {
    let data = vec![0u8; 64];
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    // Bytes are all 0x00, which is not a terminator → walks to OOB → returns None
    assert_eq!(d.estimate_end(Address::new(0x1000), &mem), None);
}

#[test]
fn detector_merge_keeps_highest_confidence() {
    let d = FunctionDetector::new(DetectedArch::X86_64);
    let v = vec![
        FunctionBoundary::new(Address::new(0x1000), Confidence::Low, DetectionSource::HeuristicGap),
        FunctionBoundary::new(Address::new(0x1000), Confidence::Certain, DetectionSource::SymbolTable),
        FunctionBoundary::new(Address::new(0x2000), Confidence::Medium, DetectionSource::CallTarget),
    ];
    let merged = d.merge_results(v);
    assert_eq!(merged.len(), 2);
    let at_1000 = merged.iter().find(|fb| fb.start == Address::new(0x1000)).unwrap();
    assert_eq!(at_1000.confidence, Confidence::Certain);
}

#[test]
fn detector_merge_sorted_by_address() {
    let d = FunctionDetector::new(DetectedArch::X86_64);
    let v = vec![
        FunctionBoundary::new(Address::new(0x3000), Confidence::Low, DetectionSource::CallTarget),
        FunctionBoundary::new(Address::new(0x1000), Confidence::Low, DetectionSource::CallTarget),
        FunctionBoundary::new(Address::new(0x2000), Confidence::Low, DetectionSource::CallTarget),
    ];
    let merged = d.merge_results(v);
    let addrs: Vec<u64> = merged.iter().map(|f| f.start.as_u64()).collect();
    assert_eq!(addrs, vec![0x1000, 0x2000, 0x3000]);
}

#[test]
fn detector_analyze_respects_hints() {
    let mem = MemorySlice::new(Address::new(0x1000), &[0u8; 64]);
    let d = FunctionDetector::new(DetectedArch::X86_64);
    let hint = FunctionBoundary::new(Address::new(0x1000), Confidence::Certain, DetectionSource::User)
        .with_end(Address::new(0x1010));
    let result = d.analyze(&mem, vec![hint]);
    assert!(result.iter().any(|fb| fb.source == DetectionSource::User));
}

#[test]
fn detector_min_function_size_filters() {
    let mut d = FunctionDetector::new(DetectedArch::X86_64);
    d.min_function_size = 1000;
    let fb = FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::User)
        .with_end(Address::new(0x1010));
    let mem = MemorySlice::new(Address::new(0x1000), &[0u8; 64]);
    // Disable scans so we can isolate the filter
    let d = d.disable_prologue_scan().disable_gap_analysis();
    let d = FunctionDetector { enable_call_target_scan: false, ..d };
    let result = d.analyze(&mem, vec![fb]);
    assert!(result.is_empty(), "expected filter to remove tiny function, got {:?}", result);
}

// ── FunctionBoundarySet ──────────────────────────────────────────────────────

#[test]
fn boundary_set_at_and_count() {
    let v = vec![
        FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x2000), Confidence::Low, DetectionSource::User),
    ];
    let set = FunctionBoundarySet::new(v);
    assert_eq!(set.count(), 2);
    assert!(set.at(Address::new(0x1000)).is_some());
    assert!(set.at(Address::new(0x1500)).is_none());
}

#[test]
fn boundary_set_high_confidence_filter() {
    let v = vec![
        FunctionBoundary::new(Address::new(0x1000), Confidence::Low, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x2000), Confidence::Medium, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x3000), Confidence::High, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x4000), Confidence::Certain, DetectionSource::User),
    ];
    let set = FunctionBoundarySet::new(v);
    assert_eq!(set.high_confidence().count(), 2);
}

#[test]
fn boundary_set_iter_count_matches() {
    let v = vec![
        FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x2000), Confidence::Low, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x3000), Confidence::Medium, DetectionSource::User),
    ];
    let set = FunctionBoundarySet::new(v);
    assert_eq!(set.iter().count(), 3);
    assert_eq!(set.sorted_by_address().len(), 3);
}

// ── detect_functions top-level ───────────────────────────────────────────────

#[test]
fn detect_functions_classical_prologue() {
    let mut data = vec![0xCCu8; 64];
    data[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
    data[4] = 0xC3; // ret
    let mem = MemorySlice::new(Address::new(0x1000), &data);
    let set = detect_functions(DetectedArch::X86_64, &mem);
    assert!(set.count() > 0);
    assert!(set.at(Address::new(0x1000)).is_some());
}

#[test]
fn detect_functions_empty() {
    let mem = MemorySlice::new(Address::new(0), &[]);
    let set = detect_functions(DetectedArch::X86_64, &mem);
    assert_eq!(set.count(), 0);
    assert_eq!(set.stats.total_found, 0);
}

#[test]
fn detect_functions_stats_bytes_analyzed() {
    let data = vec![0u8; 100];
    let mem = MemorySlice::new(Address::new(0), &data);
    let set = detect_functions(DetectedArch::X86_64, &mem);
    assert_eq!(set.stats.bytes_analyzed, 100);
}

// ── FunctionDetectionPass ────────────────────────────────────────────────────

#[test]
fn detection_pass_metadata() {
    use rustre_analysis::AnalysisPass;
    let pass = FunctionDetectionPass::default();
    assert_eq!(pass.name(), "function_detection");
    assert_eq!(pass.priority(), 100);
    assert!(!pass.description().is_empty());
}

#[test]
fn detection_pass_debug_includes_arch() {
    let pass = FunctionDetectionPass::x86_64();
    let s = format!("{:?}", pass);
    assert!(s.contains("FunctionDetectionPass"));
}

// ── Send/Sync invariants ─────────────────────────────────────────────────────

#[test]
fn types_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<FunctionBoundary>();
    assert_send_sync::<Confidence>();
    assert_send_sync::<DetectionSource>();
    assert_send_sync::<DetectedArch>();
    assert_send_sync::<FunctionDetector>();
    assert_send_sync::<FunctionBoundarySet>();
    assert_send_sync::<FunctionDetectionPass>();
}

// ── Hash / Eq consistency ────────────────────────────────────────────────────

#[test]
fn boundary_eq_hash_consistent() {
    use std::collections::HashSet;
    let a = FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::User);
    let b = FunctionBoundary::new(Address::new(0x1000), Confidence::High, DetectionSource::User);
    assert_eq!(a, b);
    let mut s = HashSet::new();
    s.insert(a);
    assert!(s.contains(&b));
}

#[test]
fn detection_source_variants_distinct() {
    use std::collections::HashSet;
    let all = [
        DetectionSource::EntryPoint,
        DetectionSource::CallTarget,
        DetectionSource::ProloguePattern,
        DetectionSource::ExceptionHandler,
        DetectionSource::SymbolTable,
        DetectionSource::Flirt,
        DetectionSource::HeuristicGap,
        DetectionSource::User,
    ];
    let set: HashSet<_> = all.iter().cloned().collect();
    assert_eq!(set.len(), 8);
}
