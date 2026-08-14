//! Deep adversarial tests for `rustre-analysis-fn` core public API in `lib.rs`.

use rustre_analysis_fn::{
    arm64_prologue_patterns, detect_functions, x86_32_prologue_patterns, x86_64_prologue_patterns,
    CallTargetCollector, Confidence, DetectedArch, DetectionSource, FunctionBoundary,
    FunctionBoundarySet, FunctionDetector, GapAnalyzer, MemorySlice, ProloguePattern,
};
use rustre_core::address::{Address, AddressRange};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::thread;

// ── LCG ──────────────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn next_u8(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u8()).collect()
    }
}

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

// ── MemorySlice round-trip ───────────────────────────────────────────────────

#[test]
fn t01_memory_slice_u8_roundtrip_50() {
    let mut data = vec![0u8; 50];
    for (i, b) in data.iter_mut().enumerate() {
        *b = i as u8;
    }
    let m = MemorySlice::new(Address::new(0x4000), &data);
    for i in 0..50u64 {
        assert_eq!(m.read_u8(Address::new(0x4000 + i)), Some(i as u8));
    }
}

#[test]
fn t02_memory_slice_u16_roundtrip() {
    let mut data = Vec::new();
    let mut expected = Vec::new();
    for i in 0..60u16 {
        let v = i.wrapping_mul(0x0101);
        data.extend_from_slice(&v.to_le_bytes());
        expected.push(v);
    }
    let m = MemorySlice::new(Address::new(0x100), &data);
    for (i, v) in expected.iter().enumerate() {
        assert_eq!(m.read_u16_le(Address::new(0x100 + (i * 2) as u64)), Some(*v));
    }
}

#[test]
fn t03_memory_slice_u32_roundtrip() {
    let mut data = Vec::new();
    let mut expected = Vec::new();
    for i in 0..55u32 {
        let v = i.wrapping_mul(0xCAFE_BABE);
        data.extend_from_slice(&v.to_le_bytes());
        expected.push(v);
    }
    let m = MemorySlice::new(Address::new(0x800), &data);
    for (i, v) in expected.iter().enumerate() {
        assert_eq!(m.read_u32_le(Address::new(0x800 + (i * 4) as u64)), Some(*v));
    }
}

#[test]
fn t04_memory_slice_u64_roundtrip() {
    let mut data = Vec::new();
    let mut expected = Vec::new();
    for i in 0..52u64 {
        let v = i.wrapping_mul(0xDEAD_BEEF_1234_5678);
        data.extend_from_slice(&v.to_le_bytes());
        expected.push(v);
    }
    let m = MemorySlice::new(Address::new(0), &data);
    for (i, v) in expected.iter().enumerate() {
        assert_eq!(m.read_u64_le(Address::new((i * 8) as u64)), Some(*v));
    }
}

#[test]
fn t05_memory_slice_oob_below_base() {
    let data = [0u8; 16];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    assert_eq!(m.read_u8(Address::new(0)), None);
    assert_eq!(m.read_u8(Address::new(0x0FFF)), None);
    assert_eq!(m.read_u16_le(Address::new(0x0FFE)), None);
    assert_eq!(m.read_u32_le(Address::new(0x0FF0)), None);
}

#[test]
fn t06_memory_slice_oob_above_end() {
    let data = [0u8; 16];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    assert_eq!(m.read_u8(Address::new(0x1010)), None);
    assert_eq!(m.read_u8(Address::new(u64::MAX)), None);
    assert_eq!(m.read_u16_le(Address::new(0x100F)), None);
    assert_eq!(m.read_u32_le(Address::new(0x100D)), None);
    assert_eq!(m.read_u64_le(Address::new(0x1009)), None);
}

#[test]
fn t07_memory_slice_boundary_partial_reads() {
    let data = [0xFFu8; 4];
    let m = MemorySlice::new(Address::new(0x10), &data);
    // u16 at last position with 1 byte left -> None
    assert_eq!(m.read_u16_le(Address::new(0x13)), None);
    // u32 at offset 0 ok
    assert_eq!(m.read_u32_le(Address::new(0x10)), Some(0xFFFF_FFFF));
    // u64 needs 8 bytes, not available
    assert_eq!(m.read_u64_le(Address::new(0x10)), None);
}

#[test]
fn t08_memory_slice_empty() {
    let data: [u8; 0] = [];
    let m = MemorySlice::new(Address::new(0x2000), &data);
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
    assert_eq!(m.end(), Address::new(0x2000));
    assert!(!m.contains(Address::new(0x2000)));
    assert_eq!(m.read_u8(Address::new(0x2000)), None);
}

#[test]
fn t09_memory_slice_max_address_base() {
    let data = [1u8, 2, 3];
    // base near u64::MAX; end() must saturate via wrapping
    let m = MemorySlice::new(Address::new(u64::MAX - 2), &data);
    assert_eq!(m.read_u8(Address::new(u64::MAX - 2)), Some(1));
    assert_eq!(m.read_u8(Address::new(u64::MAX)), Some(3));
}

#[test]
fn t10_memory_slice_slice_at_exact_end() {
    let data = [1u8, 2, 3, 4];
    let m = MemorySlice::new(Address::new(0), &data);
    assert_eq!(m.slice_at(Address::new(0), 4), Some(&[1, 2, 3, 4][..]));
    assert_eq!(m.slice_at(Address::new(0), 5), None);
    assert_eq!(m.slice_at(Address::new(3), 1), Some(&[4u8][..]));
}

#[test]
fn t11_memory_slice_contains_boundaries() {
    let data = [0u8; 10];
    let m = MemorySlice::new(Address::new(100), &data);
    assert!(m.contains(Address::new(100)));
    assert!(m.contains(Address::new(109)));
    assert!(!m.contains(Address::new(110)));
    assert!(!m.contains(Address::new(99)));
}

// ── ProloguePattern ──────────────────────────────────────────────────────────

#[test]
fn t12_prologue_pattern_min_len_matches_bytes_len() {
    let pat = ProloguePattern {
        name: "x",
        arch: "x86_64",
        bytes: &[Some(0x55), None, Some(0x90)],
        confidence: Confidence::Low,
    };
    assert_eq!(pat.min_len(), 3);
}

#[test]
fn t13_prologue_pattern_all_wildcards() {
    let pat = ProloguePattern {
        name: "wild",
        arch: "x86_64",
        bytes: &[None, None, None],
        confidence: Confidence::Low,
    };
    assert!(pat.matches(&[0, 0, 0]));
    assert!(pat.matches(&[0xFF, 0xFF, 0xFF]));
    assert!(!pat.matches(&[0, 0])); // too short
}

#[test]
fn t14_prologue_pattern_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xDEAD_BEEF_CAFE_BABE);
    let patterns = x86_64_prologue_patterns();
    for _ in 0..200 {
        let len = (lcg.next() % 32) as usize;
        let buf = lcg.bytes(len);
        for p in &patterns {
            // Just must not panic
            let _ = p.matches(&buf);
        }
    }
}

#[test]
fn t15_prologue_patterns_min_len_invariant() {
    for p in x86_64_prologue_patterns()
        .iter()
        .chain(x86_32_prologue_patterns().iter())
        .chain(arm64_prologue_patterns().iter())
    {
        assert!(p.min_len() >= 1);
        assert_eq!(p.min_len(), p.bytes.len());
    }
}

#[test]
fn t16_arm64_pattern_byte_count_multiple_of_4_or_correct_size() {
    for p in arm64_prologue_patterns() {
        // ARM64 prologues should be at least 4 bytes
        assert!(p.min_len() >= 4, "{}", p.name);
    }
}

// ── CallTargetCollector ──────────────────────────────────────────────────────

#[test]
fn t17_call_collector_fuzz_x86_no_panic() {
    let mut lcg = Lcg::new(0x1234_5678_9ABC_DEF0);
    let collector = CallTargetCollector::new(DetectedArch::X86_64)
        .with_range(Address::new(0), Address::new(u64::MAX));
    for _ in 0..50 {
        let len = (lcg.next() % 256) as usize;
        let buf = lcg.bytes(len);
        let m = MemorySlice::new(Address::new(0x10_0000), &buf);
        let _ = collector.collect(&m);
    }
}

#[test]
fn t18_call_collector_fuzz_arm64_no_panic() {
    let mut lcg = Lcg::new(0xAAAA_BBBB_CCCC_DDDD);
    let collector = CallTargetCollector::new(DetectedArch::Arm64);
    for _ in 0..50 {
        // ensure 4-byte aligned length
        let len = ((lcg.next() % 64) as usize) * 4;
        let buf = lcg.bytes(len);
        let m = MemorySlice::new(Address::new(0x40_0000), &buf);
        let _ = collector.collect(&m);
    }
}

#[test]
fn t19_call_collector_returns_sorted_unique() {
    // Build code with many calls
    let mut code = vec![0x90u8; 200];
    for i in 0..10 {
        let off = i * 10;
        code[off] = 0xE8;
        // disp such that target is 0x1000 + off + 5 + 0x20
        let disp: i32 = 0x20;
        let db = disp.to_le_bytes();
        code[off + 1] = db[0];
        code[off + 2] = db[1];
        code[off + 3] = db[2];
        code[off + 4] = db[3];
    }
    let m = MemorySlice::new(Address::new(0x1000), &code);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    let t = c.collect_x86_calls(&m);
    for w in t.windows(2) {
        assert!(w[0].as_u64() < w[1].as_u64());
    }
}

#[test]
fn t20_call_collector_negative_displacement() {
    // E8 with -5 disp -> target = next_pc - 5 = (base + 0 + 5) - 5 = base
    let mut code = vec![0x90u8; 32];
    code[10] = 0xE8;
    let disp: i32 = -10;
    let db = disp.to_le_bytes();
    code[11] = db[0];
    code[12] = db[1];
    code[13] = db[2];
    code[14] = db[3];
    let m = MemorySlice::new(Address::new(0x1000), &code);
    let c = CallTargetCollector::new(DetectedArch::X86_64)
        .with_range(Address::new(0x1000), Address::new(0x2000));
    let t = c.collect_x86_calls(&m);
    // next_pc = 0x100A + 5 = 0x100F; target = 0x100F - 10 = 0x1005
    assert!(t.contains(&Address::new(0x1005)), "got {t:?}");
}

#[test]
fn t21_call_collector_arm64_bl() {
    // BL with offset = 1 -> target = pc + 4
    // BL encoding: opcode bits[31:26] = 0b100101 (0x25 << 26 = 0x9400_0000)
    let word: u32 = 0x9400_0001;
    let bytes = word.to_le_bytes();
    let mut code = vec![0u8; 32];
    code[0] = bytes[0];
    code[1] = bytes[1];
    code[2] = bytes[2];
    code[3] = bytes[3];
    let m = MemorySlice::new(Address::new(0x4000), &code);
    let c = CallTargetCollector::new(DetectedArch::Arm64)
        .with_range(Address::new(0x4000), Address::new(0x5000));
    let t = c.collect_arm64_calls(&m);
    assert!(t.contains(&Address::new(0x4004)));
}

#[test]
fn t22_call_collector_empty_input() {
    let data: [u8; 0] = [];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    assert!(c.collect(&m).is_empty());
}

#[test]
fn t23_call_collector_truncated_e8() {
    // E8 at very end with insufficient bytes — must not panic, must produce no targets for it
    let code = vec![0x90, 0x90, 0xE8, 0x00, 0x00]; // only 2 bytes of disp follow → not enough
    let m = MemorySlice::new(Address::new(0x1000), &code);
    let c = CallTargetCollector::new(DetectedArch::X86_64);
    let _ = c.collect(&m); // no panic
}

#[test]
fn t24_call_collector_unknown_arch_falls_back_x86() {
    let mut code = vec![0x90u8; 16];
    code[0] = 0xE8;
    code[1] = 0x05;
    code[2] = 0x00;
    code[3] = 0x00;
    code[4] = 0x00;
    let m = MemorySlice::new(Address::new(0x1000), &code);
    let c = CallTargetCollector::new(DetectedArch::Unknown)
        .with_range(Address::new(0x1000), Address::new(0x2000));
    let t = c.collect(&m);
    assert!(t.contains(&Address::new(0x100A)));
}

// ── GapAnalyzer ──────────────────────────────────────────────────────────────

#[test]
fn t25_gap_analyzer_empty_known() {
    let data = vec![0u8; 0x100];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    let a = GapAnalyzer::new();
    let r = AddressRange::new(Address::new(0x1000), Address::new(0x1100));
    let gaps = a.find_gaps(&[], r, &m);
    // Either yields one big gap or none, but never panics
    assert!(gaps.iter().all(|g| g.start.as_u64() < g.end.as_u64()));
}

#[test]
fn t26_gap_analyzer_min_gap_size_filters() {
    let data = vec![0u8; 0x100];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    let a = GapAnalyzer {
        min_gap_size: 100,
        nop_byte: 0x90,
        int3_byte: 0xCC,
    };
    let known = vec![Address::new(0x1000), Address::new(0x1010)];
    let r = AddressRange::new(Address::new(0x1000), Address::new(0x1100));
    let gaps = a.find_gaps(&known, r, &m);
    for g in &gaps {
        assert!(g.end.as_u64() - g.start.as_u64() >= 100);
    }
}

#[test]
fn t27_gap_analyzer_with_nop() {
    let a = GapAnalyzer::new().with_nop(0x00);
    assert_eq!(a.nop_byte, 0x00);
    assert_eq!(a.int3_byte, 0xCC);
}

#[test]
fn t28_gap_analyzer_default() {
    let a = GapAnalyzer::default();
    assert_eq!(a.nop_byte, 0x90);
    assert_eq!(a.int3_byte, 0xCC);
    assert_eq!(a.min_gap_size, 8);
}

#[test]
fn t29_gap_analyzer_first_code_byte_int3() {
    let data = vec![0xCCu8, 0xCC, 0xCC, 0x55, 0x48, 0x89, 0xE5];
    let m = MemorySlice::new(Address::new(0x2000), &data);
    let a = GapAnalyzer::new();
    let gap = AddressRange::new(Address::new(0x2000), Address::new(0x2007));
    assert_eq!(a.first_code_byte(gap, &m), Some(Address::new(0x2003)));
}

#[test]
fn t30_gap_analyzer_fuzz_no_panic() {
    let mut lcg = Lcg::new(0xCAFE_F00D_DEAD_BEEF);
    let a = GapAnalyzer::new();
    for _ in 0..50 {
        let n = ((lcg.next() % 8) as usize) + 1;
        let mut known: Vec<Address> = (0..n)
            .map(|_| Address::new(0x1000 + (lcg.next() % 0x1000)))
            .collect();
        known.sort_by_key(|a| a.as_u64());
        let data = vec![0u8; 0x2000];
        let m = MemorySlice::new(Address::new(0x1000), &data);
        let r = AddressRange::new(Address::new(0x1000), Address::new(0x3000));
        let _ = a.find_gaps(&known, r, &m);
    }
}

// ── FunctionBoundary ─────────────────────────────────────────────────────────

#[test]
fn t31_function_boundary_with_end_and_name() {
    let fb = FunctionBoundary::new(
        Address::new(0x100),
        Confidence::High,
        DetectionSource::ProloguePattern,
    )
    .with_end(Address::new(0x150))
    .with_name("foo");
    assert_eq!(fb.start, Address::new(0x100));
    assert_eq!(fb.end, Some(Address::new(0x150)));
    assert_eq!(fb.name.as_deref(), Some("foo"));
    assert_eq!(fb.byte_size(), Some(0x50));
}

#[test]
fn t32_function_boundary_byte_size_none_when_no_end() {
    let fb = FunctionBoundary::new(
        Address::new(0x100),
        Confidence::Low,
        DetectionSource::HeuristicGap,
    );
    assert_eq!(fb.byte_size(), None);
}

#[test]
fn t33_function_boundary_byte_size_saturates_on_inverted() {
    let fb = FunctionBoundary::new(
        Address::new(0x200),
        Confidence::Medium,
        DetectionSource::CallTarget,
    )
    .with_end(Address::new(0x100));
    assert_eq!(fb.byte_size(), Some(0)); // saturating_sub
}

#[test]
fn t34_function_boundary_hash_eq_consistency_30() {
    let sources = [
        DetectionSource::EntryPoint,
        DetectionSource::CallTarget,
        DetectionSource::ProloguePattern,
        DetectionSource::ExceptionHandler,
        DetectionSource::SymbolTable,
        DetectionSource::Flirt,
        DetectionSource::HeuristicGap,
        DetectionSource::User,
    ];
    let confs = [
        Confidence::Low,
        Confidence::Medium,
        Confidence::High,
        Confidence::Certain,
    ];
    let mut pairs = 0;
    for i in 0..30u64 {
        let s = &sources[(i as usize) % sources.len()];
        let c = confs[(i as usize) % confs.len()];
        let a = FunctionBoundary::new(Address::new(i * 0x100), c, s.clone());
        let b = FunctionBoundary::new(Address::new(i * 0x100), c, s.clone());
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        pairs += 1;
    }
    assert_eq!(pairs, 30);
}

#[test]
fn t35_confidence_hash_eq_consistency() {
    let cs = [
        Confidence::Low,
        Confidence::Medium,
        Confidence::High,
        Confidence::Certain,
    ];
    for c in cs {
        let d = c;
        assert_eq!(c, d);
        assert_eq!(hash_of(&c), hash_of(&d));
    }
}

#[test]
fn t36_detection_source_hash_eq() {
    let s = DetectionSource::ProloguePattern;
    let t = DetectionSource::ProloguePattern;
    assert_eq!(s, t);
    assert_eq!(hash_of(&s), hash_of(&t));
    assert_ne!(s, DetectionSource::Flirt);
}

// ── FunctionDetector / detect_functions ──────────────────────────────────────

#[test]
fn t37_function_detector_fuzz_random_bytes_no_panic() {
    let mut lcg = Lcg::new(0xF00D_BEEF_DEAD_CAFE);
    for _ in 0..40 {
        let len = ((lcg.next() % 512) as usize) + 8;
        let buf = lcg.bytes(len);
        let m = MemorySlice::new(Address::new(0x1_0000), &buf);
        for arch in [
            DetectedArch::X86_64,
            DetectedArch::X86_32,
            DetectedArch::Arm64,
            DetectedArch::Unknown,
        ] {
            let _ = detect_functions(arch, &m);
        }
    }
}

#[test]
fn t38_function_detector_empty_memory() {
    let data: [u8; 0] = [];
    let m = MemorySlice::new(Address::new(0x1000), &data);
    let set = detect_functions(DetectedArch::X86_64, &m);
    assert_eq!(set.count(), 0);
    assert_eq!(set.stats.bytes_analyzed, 0);
}

#[test]
fn t39_function_detector_merge_keeps_highest_confidence() {
    let det = FunctionDetector::new(DetectedArch::X86_64);
    let same = Address::new(0x100);
    let a = FunctionBoundary::new(same, Confidence::Low, DetectionSource::HeuristicGap);
    let b = FunctionBoundary::new(same, Confidence::Medium, DetectionSource::CallTarget);
    let c = FunctionBoundary::new(same, Confidence::Certain, DetectionSource::SymbolTable);
    let d = FunctionBoundary::new(same, Confidence::High, DetectionSource::ProloguePattern);
    let m = det.merge_results(vec![a, b, c, d]);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].confidence, Confidence::Certain);
}

#[test]
fn t40_function_detector_merge_sorted() {
    let det = FunctionDetector::new(DetectedArch::X86_64);
    let mut input = Vec::new();
    let mut lcg = Lcg::new(0x99);
    for _ in 0..40 {
        let a = Address::new(lcg.next() % 0x1_0000);
        input.push(FunctionBoundary::new(
            a,
            Confidence::Low,
            DetectionSource::HeuristicGap,
        ));
    }
    let merged = det.merge_results(input);
    for w in merged.windows(2) {
        assert!(w[0].start.as_u64() < w[1].start.as_u64());
    }
}

#[test]
fn t41_function_detector_min_function_size_filter() {
    // Tiny boundary < min_function_size should be discarded
    let mut code = vec![0x90u8; 0x40];
    // Prologue at 0
    code[0] = 0x55;
    code[1] = 0x48;
    code[2] = 0x89;
    code[3] = 0xE5;
    code[4] = 0xC3; // RET at +4 -> size ~5

    let m = MemorySlice::new(Address::new(0x1000), &code);
    let det = FunctionDetector {
        arch: DetectedArch::X86_64,
        enable_prologue_scan: true,
        enable_call_target_scan: false,
        enable_gap_analysis: false,
        min_function_size: 100, // way too big
    };
    let r = det.analyze(&m, Vec::new());
    // Estimated function ends quickly; should be filtered out due to size
    assert!(r.iter().all(|fb| fb.byte_size().unwrap_or(0) >= 100 || fb.byte_size().is_none()));
}

#[test]
fn t42_function_detector_disable_passes() {
    let det = FunctionDetector::new(DetectedArch::X86_64)
        .disable_prologue_scan()
        .disable_gap_analysis();
    assert!(!det.enable_prologue_scan);
    assert!(!det.enable_gap_analysis);
}

#[test]
fn t43_function_detector_estimate_end_ret() {
    let mut code = vec![0x90u8; 16];
    code[5] = 0xC3; // RET
    let m = MemorySlice::new(Address::new(0x100), &code);
    let det = FunctionDetector::new(DetectedArch::X86_64);
    let end = det.estimate_end(Address::new(0x100), &m);
    assert_eq!(end, Some(Address::new(0x106)));
}

#[test]
fn t44_function_detector_estimate_end_arm64_ret() {
    // ARM64 RET = 0xD65F03C0 (LE: C0 03 5F D6)
    let mut code = vec![0u8; 16];
    code[0] = 0x90;
    code[1] = 0x90;
    code[2] = 0x90;
    code[3] = 0x90;
    code[4] = 0xC0;
    code[5] = 0x03;
    code[6] = 0x5F;
    code[7] = 0xD6;
    let m = MemorySlice::new(Address::new(0x100), &code);
    let det = FunctionDetector::new(DetectedArch::Arm64);
    let end = det.estimate_end(Address::new(0x100), &m);
    assert_eq!(end, Some(Address::new(0x108)));
}

#[test]
fn t45_function_detector_estimate_end_no_terminator() {
    let code = vec![0x90u8; 32]; // all NOPs, no terminator
    let m = MemorySlice::new(Address::new(0x100), &code);
    let det = FunctionDetector::new(DetectedArch::X86_64);
    // Will fail to read past end and return None
    let _end = det.estimate_end(Address::new(0x100), &m);
    // Just shouldn't panic
}

#[test]
fn t46_function_boundary_set_iter_and_sorted() {
    let bounds = vec![
        FunctionBoundary::new(Address::new(0x30), Confidence::High, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x10), Confidence::High, DetectionSource::User),
        FunctionBoundary::new(Address::new(0x20), Confidence::High, DetectionSource::User),
    ];
    let set = FunctionBoundarySet::new(bounds);
    assert_eq!(set.count(), 3);
    let it: Vec<_> = set.iter().collect();
    assert_eq!(it.len(), 3);
    let sorted = set.sorted_by_address();
    assert_eq!(sorted.len(), 3);
}

#[test]
fn t47_function_boundary_set_at_lookup_misses() {
    let set = FunctionBoundarySet::new(vec![FunctionBoundary::new(
        Address::new(0xAAAA),
        Confidence::Certain,
        DetectionSource::SymbolTable,
    )]);
    assert!(set.at(Address::new(0)).is_none());
    assert!(set.at(Address::new(u64::MAX)).is_none());
    assert!(set.at(Address::new(0xAAAA)).is_some());
}

#[test]
fn t48_confidence_ordering_total() {
    let mut v = vec![
        Confidence::Certain,
        Confidence::Low,
        Confidence::High,
        Confidence::Medium,
    ];
    v.sort();
    assert_eq!(
        v,
        vec![
            Confidence::Low,
            Confidence::Medium,
            Confidence::High,
            Confidence::Certain,
        ]
    );
}

// ── Stress / threads ─────────────────────────────────────────────────────────

#[test]
fn t49_send_sync_detect_functions_threads() {
    // Confidence, DetectionSource and FunctionBoundary are all owned/Clone/Send/Sync.
    let code = Arc::new({
        let mut c = vec![0x90u8; 256];
        c[0] = 0x55;
        c[1] = 0x48;
        c[2] = 0x89;
        c[3] = 0xE5;
        c[8] = 0xC3;
        c
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&code);
        handles.push(thread::spawn(move || {
            let mut total = 0usize;
            for _ in 0..100 {
                let m = MemorySlice::new(Address::new(0x1000), &c);
                let set = detect_functions(DetectedArch::X86_64, &m);
                total += set.count();
            }
            total
        }));
    }
    let mut sum = 0;
    for h in handles {
        sum += h.join().unwrap();
    }
    assert!(sum > 0);
}

#[test]
fn t50_call_target_collector_threaded() {
    let code = Arc::new({
        let mut c = vec![0x90u8; 256];
        c[0] = 0xE8;
        c[1] = 0x10;
        c[2] = 0x00;
        c[3] = 0x00;
        c[4] = 0x00;
        c
    });
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&code);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let m = MemorySlice::new(Address::new(0x1000), &c);
                let coll = CallTargetCollector::new(DetectedArch::X86_64)
                    .with_range(Address::new(0x1000), Address::new(0x2000));
                let t = coll.collect(&m);
                assert!(t.contains(&Address::new(0x1015)));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn t51_prologue_patterns_unique_names() {
    let mut seen = HashSet::new();
    for p in x86_64_prologue_patterns() {
        assert!(seen.insert(p.name.to_string()), "dup {}", p.name);
    }
    let mut seen = HashSet::new();
    for p in x86_32_prologue_patterns() {
        assert!(seen.insert(p.name.to_string()), "dup {}", p.name);
    }
    let mut seen = HashSet::new();
    for p in arm64_prologue_patterns() {
        assert!(seen.insert(p.name.to_string()), "dup {}", p.name);
    }
}

#[test]
fn t52_detect_functions_with_overflow_base() {
    // Base near u64::MAX, ensure no panic
    let mut code = vec![0x90u8; 16];
    code[0] = 0x55;
    code[1] = 0x48;
    code[2] = 0x89;
    code[3] = 0xE5;
    code[8] = 0xC3;
    let m = MemorySlice::new(Address::new(u64::MAX - 32), &code);
    let _ = detect_functions(DetectedArch::X86_64, &m);
}

#[test]
fn t53_function_detector_analyze_with_hints() {
    let code = vec![0x90u8; 32];
    let m = MemorySlice::new(Address::new(0x1000), &code);
    let det = FunctionDetector::new(DetectedArch::X86_64);
    let hint = FunctionBoundary::new(
        Address::new(0x1000),
        Confidence::Certain,
        DetectionSource::User,
    );
    let r = det.analyze(&m, vec![hint.clone()]);
    assert!(r.iter().any(|fb| fb.start == Address::new(0x1000) && fb.confidence == Confidence::Certain));
}

#[test]
fn t54_call_target_collector_range_exclusive_upper() {
    let mut code = vec![0x90u8; 16];
    code[0] = 0xE8;
    let disp: i32 = 0x100 - 5;
    let db = disp.to_le_bytes();
    code[1] = db[0];
    code[2] = db[1];
    code[3] = db[2];
    code[4] = db[3];
    let m = MemorySlice::new(Address::new(0x1000), &code);
    // Target = 0x1000 + 0x100 = 0x1100; max=0x1100 exclusive → excluded
    let c = CallTargetCollector::new(DetectedArch::X86_64)
        .with_range(Address::new(0x1000), Address::new(0x1100));
    let t = c.collect_x86_calls(&m);
    assert!(!t.contains(&Address::new(0x1100)));
}

// ── Gap F: extra .pdata function recovery ───────────────────────────────────

#[test]
fn t55_find_extra_pdata_funcs_recovers_uncovered_region() {
    use rustre_analysis_fn::{find_extra_pdata_funcs, RuntimeFunction};

    let image_base = Address::new(0x14000_0000);
    let text_base = Address::new(0x14000_1000);

    // Layout (offsets relative to text_base):
    //   0x00..0x10  -> covered pdata function A (push rbp; mov rbp,rsp; nop*11; ret)
    //   0x10..0x30  -> UNCOVERED gap with a real prologue + ret
    //   0x30..0x40  -> covered pdata function B
    let mut text = vec![0xCCu8; 0x40];

    // A: push rbp; mov rbp, rsp; ... ; ret
    text[0x00] = 0x55;
    text[0x01] = 0x48;
    text[0x02] = 0x89;
    text[0x03] = 0xE5;
    text[0x0F] = 0xC3;

    // Gap: lead with CC padding, then prologue at 0x14, ret at 0x1C, CC pad to 0x30.
    for b in text.iter_mut().take(0x14).skip(0x10) {
        *b = 0xCC;
    }
    text[0x14] = 0x55; // push rbp
    text[0x15] = 0x48; // mov rbp, rsp ...
    text[0x16] = 0x89;
    text[0x17] = 0xE5;
    text[0x18] = 0x90; // nop
    text[0x19] = 0x90;
    text[0x1A] = 0x90;
    text[0x1B] = 0x90;
    text[0x1C] = 0xC3; // ret
    for b in text.iter_mut().take(0x30).skip(0x1D) {
        *b = 0xCC;
    }

    // B: push rbp; ... ; ret
    text[0x30] = 0x55;
    text[0x31] = 0x48;
    text[0x32] = 0x89;
    text[0x33] = 0xE5;
    text[0x3F] = 0xC3;

    // pdata covers A (RVA 0x1000..0x1010) and B (RVA 0x1030..0x1040). Gap (0x1010..0x1030) is missing.
    let pdata = vec![
        RuntimeFunction { begin_rva: 0x1000, end_rva: 0x1010, unwind_rva: 0 },
        RuntimeFunction { begin_rva: 0x1030, end_rva: 0x1040, unwind_rva: 0 },
    ];

    let text_range = AddressRange::new(text_base, text_base + text.len() as u64);
    let (extras, stats) = find_extra_pdata_funcs(image_base, text_range, &text, &pdata);

    assert_eq!(stats.pdata_count, 2);
    assert!(stats.gaps_scanned >= 1, "expected at least one gap, got {}", stats.gaps_scanned);
    assert_eq!(extras.len(), 1, "expected exactly one recovered function");
    let fb = &extras[0];
    assert_eq!(fb.start, text_base + 0x14u64);
    assert_eq!(fb.confidence, Confidence::Medium);
    assert_eq!(fb.source, DetectionSource::HeuristicGap);
    assert!(fb.end.unwrap().as_u64() <= (text_base + 0x30u64).as_u64());
}

#[test]
fn t56_find_extra_pdata_funcs_ignores_padding_only_gaps() {
    use rustre_analysis_fn::{find_extra_pdata_funcs, RuntimeFunction};

    let image_base = Address::new(0x14000_0000);
    let text_base = Address::new(0x14000_1000);

    // Pure CC padding in the gap; no prologue means no extras.
    let mut text = vec![0xCCu8; 0x40];
    text[0x00] = 0x55;
    text[0x01] = 0x48;
    text[0x02] = 0x89;
    text[0x03] = 0xE5;
    text[0x0F] = 0xC3;
    text[0x30] = 0x55;
    text[0x31] = 0x48;
    text[0x32] = 0x89;
    text[0x33] = 0xE5;
    text[0x3F] = 0xC3;

    let pdata = vec![
        RuntimeFunction { begin_rva: 0x1000, end_rva: 0x1010, unwind_rva: 0 },
        RuntimeFunction { begin_rva: 0x1030, end_rva: 0x1040, unwind_rva: 0 },
    ];
    let text_range = AddressRange::new(text_base, text_base + text.len() as u64);
    let (extras, _stats) = find_extra_pdata_funcs(image_base, text_range, &text, &pdata);
    assert!(extras.is_empty(), "padding-only gap should not produce extras");
}
