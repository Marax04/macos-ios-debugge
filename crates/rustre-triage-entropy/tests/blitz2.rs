//! Adversarial deep-coverage tests for rustre-triage-entropy.

use rustre_triage_entropy::{
    analyze_blocks, shannon_entropy, shannon_entropy_f32, ByteHistogram, EntropyAnalyzer,
    EntropyBlock, EntropyCategory, EntropyError, EntropyRating, EntropyReport, EntropyResult,
    HeatmapData, PackingDetector, SectionEntropy,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ─── Seeded LCG ───────────────────────────────────────────────────────────────
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut g = make_lcg(seed);
    (0..n).map(|_| (g() >> 24) as u8).collect()
}

// ─── shannon_entropy core ─────────────────────────────────────────────────────

#[test]
fn entropy_empty_zero() {
    assert!((shannon_entropy(&[]) - (0.0)).abs() < f64::EPSILON);
    assert!((shannon_entropy_f32(&[]) - (0.0)).abs() < f32::EPSILON);
}

#[test]
fn entropy_single_byte_zero() {
    for b in 0u8..=255 {
        assert!((shannon_entropy(&[b]) - (0.0)).abs() < f64::EPSILON);
    }
}

#[test]
fn entropy_constant_zero() {
    for b in [0u8, 1, 42, 127, 200, 255] {
        let data = vec![b; 1000];
        assert!((shannon_entropy(&data) - (0.0)).abs() < f64::EPSILON);
    }
}

#[test]
fn entropy_uniform_all_256_is_eight() {
    let data: Vec<u8> = (0u8..=255).collect();
    let h = shannon_entropy(&data);
    assert!((h - 8.0).abs() < 1e-9);
    let h2 = shannon_entropy_f32(&data);
    assert!((h2 - 8.0).abs() < 1e-5);
}

#[test]
fn entropy_two_equal_freqs_one() {
    let mut d = vec![0u8; 100];
    d.extend(vec![255u8; 100]);
    let h = shannon_entropy(&d);
    assert!((h - 1.0).abs() < 1e-9);
}

#[test]
fn entropy_range_invariant_fuzz() {
    for seed in 0..50u64 {
        let n = ((seed * 17) % 4000 + 1) as usize;
        let data = rand_bytes(seed.wrapping_add(1), n);
        let h = shannon_entropy(&data);
        assert!((0.0..=8.0).contains(&h), "h={h} seed={seed}");
        let h32 = shannon_entropy_f32(&data);
        assert!((0.0..=8.0).contains(&h32));
        // f32 and f64 must agree to ~5 decimal places
        assert!((h - f64::from(h32)).abs() < 1e-3, "h={h} h32={h32}");
    }
}

#[test]
fn entropy_invariant_under_permutation() {
    // Entropy depends only on distribution; permuting bytes should not change it.
    let mut a = rand_bytes(0xAAAA, 1024);
    let mut b = a.clone();
    b.reverse();
    assert!((shannon_entropy(&a) - shannon_entropy(&b)).abs() < 1e-12);
    // Sort doesn't change distribution either.
    a.sort_unstable();
    let mut c = a.clone();
    c.reverse();
    assert!((shannon_entropy(&a) - shannon_entropy(&c)).abs() < 1e-12);
}

#[test]
fn entropy_max_eight_for_uniform_multiples() {
    for k in 1..=8 {
        let mut data = Vec::new();
        for _ in 0..k {
            data.extend(0u8..=255);
        }
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 1e-9, "k={k} h={h}");
    }
}

// ─── EntropyRating ────────────────────────────────────────────────────────────

#[test]
fn rating_boundaries() {
    assert_eq!(EntropyRating::from_entropy(-1.0), EntropyRating::VeryLow);
    assert_eq!(EntropyRating::from_entropy(0.0), EntropyRating::VeryLow);
    assert_eq!(EntropyRating::from_entropy(0.999), EntropyRating::VeryLow);
    assert_eq!(EntropyRating::from_entropy(1.0), EntropyRating::Low);
    assert_eq!(EntropyRating::from_entropy(2.999), EntropyRating::Low);
    assert_eq!(EntropyRating::from_entropy(3.0), EntropyRating::Medium);
    assert_eq!(EntropyRating::from_entropy(4.999), EntropyRating::Medium);
    assert_eq!(EntropyRating::from_entropy(5.0), EntropyRating::High);
    assert_eq!(EntropyRating::from_entropy(6.999), EntropyRating::High);
    assert_eq!(EntropyRating::from_entropy(7.0), EntropyRating::VeryHigh);
    assert_eq!(EntropyRating::from_entropy(f64::INFINITY), EntropyRating::VeryHigh);
}

#[test]
fn rating_display_round_trip_labels() {
    let pairs = [
        (EntropyRating::VeryLow, "VeryLow"),
        (EntropyRating::Low, "Low"),
        (EntropyRating::Medium, "Medium"),
        (EntropyRating::High, "High"),
        (EntropyRating::VeryHigh, "VeryHigh"),
    ];
    for (r, s) in pairs {
        assert_eq!(r.to_string(), s);
    }
}

#[test]
fn rating_eq_hash_consistency() {
    // Eq holds → equal copies. Test all variants.
    let all = [
        EntropyRating::VeryLow,
        EntropyRating::Low,
        EntropyRating::Medium,
        EntropyRating::High,
        EntropyRating::VeryHigh,
    ];
    for a in all {
        for b in all {
            let eq = a == b;
            if eq {
                // Same enum copy semantics.
                assert_eq!(a, b);
            }
            assert_eq!(a == b, !(a != b));
        }
    }
}

// ─── EntropyCategory ──────────────────────────────────────────────────────────

#[test]
fn category_boundaries_exhaustive() {
    let cases: &[(f32, EntropyCategory)] = &[
        (-10.0, EntropyCategory::Empty),
        (0.0, EntropyCategory::Empty),
        (0.999, EntropyCategory::Empty),
        (1.0, EntropyCategory::Text),
        (3.999, EntropyCategory::Text),
        (4.0, EntropyCategory::Code),
        (4.999, EntropyCategory::Code),
        (5.0, EntropyCategory::Data),
        (5.999, EntropyCategory::Data),
        (6.0, EntropyCategory::Compressed),
        (6.999, EntropyCategory::Compressed),
        (7.0, EntropyCategory::Encrypted),
        (7.499, EntropyCategory::Encrypted),
        (7.5, EntropyCategory::Random),
        (8.0, EntropyCategory::Random),
        (100.0, EntropyCategory::Random),
    ];
    for (e, expected) in cases {
        assert_eq!(EntropyCategory::classify(*e), *expected, "e={e}");
    }
}

#[test]
fn category_label_display_match() {
    let all = [
        EntropyCategory::Empty,
        EntropyCategory::Text,
        EntropyCategory::Code,
        EntropyCategory::Data,
        EntropyCategory::Compressed,
        EntropyCategory::Encrypted,
        EntropyCategory::Random,
    ];
    for c in all {
        assert_eq!(c.to_string(), c.label());
        assert!(!c.label().is_empty());
    }
}

#[test]
fn category_eq_pair_table() {
    let all = [
        EntropyCategory::Empty,
        EntropyCategory::Text,
        EntropyCategory::Code,
        EntropyCategory::Data,
        EntropyCategory::Compressed,
        EntropyCategory::Encrypted,
        EntropyCategory::Random,
    ];
    let mut pair_count = 0;
    for a in &all {
        for b in &all {
            pair_count += 1;
            let eq = a == b;
            // Reflexivity: each equals itself
            if std::ptr::eq(a, b) {
                assert!(eq);
            }
            // Antisymmetry of !=
            assert_eq!(eq, !(a != b));
        }
    }
    assert!(pair_count >= 30);
}

// ─── SectionEntropy ───────────────────────────────────────────────────────────

#[test]
fn section_zero_data() {
    let s = SectionEntropy::new(".bss", &[0u8; 256], 0x400);
    assert_eq!(s.name, ".bss");
    assert!((s.entropy - (0.0)).abs() < f64::EPSILON);
    assert_eq!(s.offset, 0x400);
    assert_eq!(s.size, 256);
    assert_eq!(s.rating, EntropyRating::VeryLow);
    assert!(!s.is_packed());
    assert!(!s.is_encrypted());
}

#[test]
fn section_uniform_is_packed_and_encrypted() {
    let data: Vec<u8> = (0u8..=255).collect();
    let s = SectionEntropy::new(".text", &data, 0);
    assert!(s.is_packed());
    assert!(s.is_encrypted());
}

#[test]
fn section_empty_slice() {
    let s = SectionEntropy::new(".empty", &[], 0);
    assert!((s.entropy - (0.0)).abs() < f64::EPSILON);
    assert_eq!(s.size, 0);
}

#[test]
fn section_boundary_packed_threshold() {
    // entropy must be strictly > 7.0 for is_packed.
    // Use constant data: entropy = 0 → not packed.
    let s = SectionEntropy::new("x", &[1u8; 100], 0);
    assert!(!s.is_packed());
}

// ─── EntropyAnalyzer ──────────────────────────────────────────────────────────

#[test]
fn analyzer_empty_data() {
    let a = EntropyAnalyzer::new(256);
    let r = a.analyze(&[]);
    assert!((r.overall - (0.0)).abs() < f64::EPSILON);
    assert!(r.chunks.is_empty());
    assert!(r.sections.is_empty());
}

#[test]
fn analyzer_chunk_size_zero() {
    let a = EntropyAnalyzer::new(0);
    let r = a.analyze(&[1, 2, 3, 4, 5]);
    assert!(r.chunks.is_empty());
}

#[test]
fn analyzer_partial_chunks() {
    let a = EntropyAnalyzer::new(100);
    let r = a.analyze(&vec![0u8; 250]);
    assert_eq!(r.chunks.len(), 3);
}

#[test]
fn analyzer_max_chunk_entropy_correct() {
    let a = EntropyAnalyzer::new(256);
    let mut data = vec![0u8; 256];
    data.extend(0u8..=255);
    let r = a.analyze(&data);
    assert!((r.max_chunk_entropy() - 8.0).abs() < 1e-9);
}

#[test]
fn analyzer_max_chunk_entropy_empty() {
    let r = EntropyResult {
        overall: 0.0,
        rating: EntropyRating::VeryLow,
        sections: vec![],
        chunks: vec![],
    };
    assert!((r.max_chunk_entropy() - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn analyzer_sections_oob_clamped() {
    let a = EntropyAnalyzer::new(64);
    let data = vec![1u8; 100];
    // Section beyond data length must be clamped, not panic.
    let secs = [(".oversized", 50, 1000), (".past_end", 200, 50)];
    let r = a.analyze_sections(&data, &secs);
    assert_eq!(r.sections.len(), 2);
    assert!(r.sections[0].size <= 50);
    // Past-end section yields empty slice
    assert_eq!(r.sections[1].size, 0);
}

#[test]
fn analyzer_sections_overflow_protection() {
    let a = EntropyAnalyzer::new(64);
    let data = vec![0u8; 100];
    let secs = [(".overflow", usize::MAX - 10, usize::MAX)];
    // Must not panic via saturating_add.
    let r = a.analyze_sections(&data, &secs);
    assert_eq!(r.sections.len(), 1);
}

#[test]
fn analyzer_packed_sections_filter() {
    let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
    let a = EntropyAnalyzer::new(256);
    let r = a.analyze_sections(&data, &[(".packed", 0, 256), (".empty_named", 300, 5)]);
    let packed = r.packed_sections();
    assert!(!packed.is_empty());
    for s in &packed {
        assert!(s.is_packed());
    }
}

#[test]
fn analyzer_fuzz_no_panic() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..50 {
        let n = ((g() >> 48) as usize) % 2048;
        let chunk = ((g() >> 48) as usize) % 300;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let a = EntropyAnalyzer::new(chunk);
        let r = a.analyze(&data);
        assert!((0.0..=8.0).contains(&r.overall));
    }
}

// ─── EntropyError ─────────────────────────────────────────────────────────────

#[test]
fn entropy_error_display() {
    assert_eq!(EntropyError::EmptyInput.to_string(), "empty input");
    assert_eq!(
        EntropyError::InvalidChunk(42).to_string(),
        "invalid chunk size: 42"
    );
    assert_eq!(
        EntropyError::InvalidChunk(0).to_string(),
        "invalid chunk size: 0"
    );
}

// ─── analyze_blocks / EntropyBlock ────────────────────────────────────────────

#[test]
fn analyze_blocks_empty_or_zero() {
    assert!(analyze_blocks(&[], 256).is_empty());
    assert!(analyze_blocks(&[1, 2, 3], 0).is_empty());
    assert!(analyze_blocks(&[], 0).is_empty());
}

#[test]
fn analyze_blocks_offsets_correct() {
    let data = vec![7u8; 1000];
    let blocks = analyze_blocks(&data, 256);
    assert_eq!(blocks.len(), 4);
    for (i, b) in blocks.iter().enumerate() {
        assert_eq!(b.offset, (i as u64) * 256);
    }
    // Last block is partial
    assert_eq!(blocks[3].size, 1000 - 3 * 256);
}

#[test]
fn analyze_blocks_boundary_sizes() {
    for n in [1usize, 255, 256, 257, 511, 512, 513] {
        for bs in [1usize, 16, 64, 256, 1024] {
            let data = vec![0u8; n];
            let blocks = analyze_blocks(&data, bs);
            let expected = n.div_ceil(bs);
            assert_eq!(blocks.len(), expected, "n={n} bs={bs}");
            let total: usize = blocks.iter().map(|b| b.size).sum();
            assert_eq!(total, n);
        }
    }
}

#[test]
fn entropy_block_from_slice_classifies() {
    let b = EntropyBlock::from_slice(0, &[0u8; 64]);
    assert_eq!(b.category, EntropyCategory::Empty);
    let data: Vec<u8> = (0u8..=255).collect();
    let b2 = EntropyBlock::from_slice(100, &data);
    assert_eq!(b2.category, EntropyCategory::Random);
    assert_eq!(b2.offset, 100);
}

// ─── ByteHistogram ────────────────────────────────────────────────────────────

#[test]
fn histogram_basic() {
    let data = vec![0u8, 0, 1, 2, 2, 2];
    let h = ByteHistogram::new(&data);
    assert_eq!(h.total, 6);
    assert_eq!(h.count_of(0), 2);
    assert_eq!(h.count_of(1), 1);
    assert_eq!(h.count_of(2), 3);
    assert_eq!(h.count_of(255), 0);
}

#[test]
fn histogram_empty() {
    let h = ByteHistogram::new(&[]);
    assert_eq!(h.total, 0);
    assert!((h.chi_square_statistic() - (0.0)).abs() < f64::EPSILON);
    assert!(!h.is_likely_random());
    assert_eq!(h.counts.len(), 256);
    assert!(h.counts.iter().all(|&c| c == 0));
}

#[test]
fn histogram_chi_square_uniform_zero() {
    let data: Vec<u8> = (0u8..=255).collect();
    let h = ByteHistogram::new(&data);
    assert!(h.chi_square_statistic().abs() < 1e-9);
}

#[test]
fn histogram_chi_square_skewed_large() {
    let data = vec![42u8; 256];
    let h = ByteHistogram::new(&data);
    // All weight on one bucket, expected=1 each. χ² = (256-1)²/1 + 255*(0-1)²/1 = 65025 + 255 = 65280
    let chi2 = h.chi_square_statistic();
    assert!(chi2 > 60000.0, "chi2={chi2}");
    assert!(!h.is_likely_random());
}

#[test]
fn histogram_is_likely_random_threshold() {
    // Construct data with chi2 inside [200, 310]: random-looking bytes from LCG over 4096 samples
    let data = rand_bytes(0x12345, 4096);
    let h = ByteHistogram::new(&data);
    let chi2 = h.chi_square_statistic();
    assert!(chi2 > 0.0);
    // Just check correlation between predicate and range.
    assert_eq!(h.is_likely_random(), (200.0..=310.0).contains(&chi2));
}

#[test]
fn histogram_most_common_basic() {
    let mut data = vec![5u8; 50];
    data.extend(vec![3u8; 30]);
    data.extend(vec![7u8; 10]);
    let h = ByteHistogram::new(&data);
    let top = h.most_common_bytes(3);
    assert_eq!(top[0], (5, 50));
    assert_eq!(top[1], (3, 30));
    assert_eq!(top[2], (7, 10));
}

#[test]
fn histogram_most_common_clamped() {
    let h = ByteHistogram::new(&[1, 2, 3]);
    let top = h.most_common_bytes(usize::MAX);
    assert_eq!(top.len(), 256);
}

#[test]
fn histogram_most_common_zero_request() {
    let h = ByteHistogram::new(&[1, 2, 3]);
    assert!(h.most_common_bytes(0).is_empty());
}

#[test]
fn histogram_fuzz_invariants() {
    let mut g = make_lcg(0xCAFE_F00D);
    for _ in 0..50 {
        let n = ((g() >> 48) as usize) % 5000;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let h = ByteHistogram::new(&data);
        assert_eq!(h.total, n);
        let sum: u32 = h.counts.iter().sum();
        assert_eq!(sum as usize, n);
        let chi2 = h.chi_square_statistic();
        assert!(chi2 >= 0.0 || !chi2.is_nan());
    }
}

// ─── HeatmapData ──────────────────────────────────────────────────────────────

#[test]
fn heatmap_color_rgb_ranges() {
    assert_eq!(HeatmapData::color_rgb(0.0), [0, 0, 128]);
    assert_eq!(HeatmapData::color_rgb(1.99), [0, 0, 128]);
    assert_eq!(HeatmapData::color_rgb(2.0), [0, 128, 255]);
    assert_eq!(HeatmapData::color_rgb(3.99), [0, 128, 255]);
    assert_eq!(HeatmapData::color_rgb(4.0), [0, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(5.99), [0, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(6.0), [255, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(6.99), [255, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(7.0), [200, 0, 0]);
    assert_eq!(HeatmapData::color_rgb(8.0), [200, 0, 0]);
    assert_eq!(HeatmapData::color_rgb(100.0), [200, 0, 0]);
}

#[test]
fn heatmap_ascii_empty_and_zero_width() {
    assert!(HeatmapData::from_blocks(vec![]).to_ascii_heatmap(80).is_empty());
    let hm = HeatmapData::from_data(&vec![0u8; 256], 64);
    assert!(hm.to_ascii_heatmap(0).is_empty());
}

#[test]
fn heatmap_ascii_structure() {
    let hm = HeatmapData::from_data(&vec![0u8; 1024], 64);
    let art = hm.to_ascii_heatmap(40);
    assert!(art.contains('|'));
    assert!(art.contains("--"));
    // Should contain at least two lines of borders.
    let dashes: usize = art.matches('-').count();
    assert!(dashes >= 40);
}

#[test]
fn heatmap_ascii_fuzz_width_no_panic() {
    let data: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    let hm = HeatmapData::from_data(&data, 32);
    for w in [1usize, 2, 5, 16, 79, 80, 200, 1000] {
        let _ = hm.to_ascii_heatmap(w);
    }
}

#[test]
fn heatmap_rgb_colors_length_matches() {
    let hm = HeatmapData::from_data(&vec![0u8; 1024], 128);
    assert_eq!(hm.to_rgb_colors().len(), hm.blocks.len());
    assert_eq!(hm.blocks.len(), 8);
}

#[test]
fn heatmap_from_blocks_round_trip() {
    let blocks = analyze_blocks(&vec![0u8; 256], 64);
    let n = blocks.len();
    let hm = HeatmapData::from_blocks(blocks);
    assert_eq!(hm.blocks.len(), n);
}

// ─── PackingDetector ──────────────────────────────────────────────────────────

#[test]
fn packing_detector_empty() {
    assert!(PackingDetector::detect_packing_indicators(&[]).is_empty());
}

#[test]
fn packing_detector_tiny_no_panic() {
    for n in 0..64 {
        let data = vec![0u8; n];
        let _ = PackingDetector::detect_packing_indicators(&data);
    }
}

#[test]
fn packing_detector_upx_magic_anywhere() {
    let mut data = vec![0u8; 256];
    data[50..54].copy_from_slice(b"UPX!");
    let ind = PackingDetector::detect_packing_indicators(&data);
    assert!(ind.iter().any(|s| s.contains("UPX magic")));
}

#[test]
fn packing_detector_garbage_no_pe_signature() {
    // 64+ bytes, no PE\0\0 anywhere → should return without panicking
    let data = vec![0xFFu8; 1024];
    let ind = PackingDetector::detect_packing_indicators(&data);
    // Should not contain PE-derived indicators.
    assert!(!ind.iter().any(|s| s.contains("High entropy .text")));
}

#[test]
fn packing_detector_fuzz_random_no_panic() {
    let mut g = make_lcg(0x9E37_79B1);
    for _ in 0..50 {
        let n = ((g() >> 48) as usize) % 4096;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let _ind = PackingDetector::detect_packing_indicators(&data);
    }
}

#[test]
fn packing_detector_truncated_pe_header() {
    // Construct a minimal "looks like PE" prefix: 64 bytes with valid e_lfanew
    // but the pointer lands outside the buffer.
    let mut data = vec![0u8; 128];
    data[0x3c..0x40].copy_from_slice(&1_000_000u32.to_le_bytes());
    let ind = PackingDetector::detect_packing_indicators(&data);
    // Should bail out gracefully (no panic).
    assert!(ind.is_empty() || ind.iter().all(|s| !s.is_empty()));
}

#[test]
fn packing_detector_e_lfanew_max() {
    let mut data = vec![0u8; 128];
    data[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    // Must not panic.
    let _ = PackingDetector::detect_packing_indicators(&data);
}

// ─── EntropyReport ────────────────────────────────────────────────────────────

#[test]
fn report_zeros() {
    let report = EntropyReport::generate(&vec![0u8; 2048]);
    assert!((report.overall_entropy - (0.0)).abs() < f32::EPSILON);
    assert_eq!(report.category, EntropyCategory::Empty);
    assert_eq!(report.sections.len(), 4);
    assert_eq!(report.histogram.total, 2048);
}

#[test]
fn report_uniform_random_category() {
    let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let report = EntropyReport::generate(&data);
    assert!((report.overall_entropy - 8.0).abs() < 0.01);
    assert_eq!(report.category, EntropyCategory::Random);
}

#[test]
fn report_block_size_one() {
    let report = EntropyReport::generate_with_block_size(&[0u8; 32], 1);
    assert_eq!(report.sections.len(), 32);
    for s in &report.sections {
        assert_eq!(s.size, 1);
    }
}

#[test]
fn report_block_size_zero_normalized() {
    // Implementation uses `block_size.max(1)` so zero must not panic.
    let report = EntropyReport::generate_with_block_size(&[0u8; 16], 0);
    assert_eq!(report.sections.len(), 16);
}

#[test]
fn report_empty_data() {
    let report = EntropyReport::generate(&[]);
    assert!((report.overall_entropy - (0.0)).abs() < f32::EPSILON);
    assert!(report.sections.is_empty());
    assert_eq!(report.histogram.total, 0);
    assert!(!report.is_likely_packed);
}

#[test]
fn report_high_entropy_blocks_filter() {
    let mut data = vec![0u8; 512];
    data.extend((0u8..=255).cycle().take(512));
    let report = EntropyReport::generate_with_block_size(&data, 256);
    let high = report.high_entropy_blocks(7.0);
    assert!(!high.is_empty());
    for b in high {
        assert!(b.entropy > 7.0);
    }
}

#[test]
fn report_summary_and_display() {
    let report = EntropyReport::generate(&vec![0u8; 512]);
    let s = report.summary();
    assert!(s.contains("EntropyReport"));
    assert!(s.contains("overall"));
    assert!(s.contains("category"));

    let d = format!("{report}");
    assert!(d.contains("Overall entropy"));
    assert!(d.contains("Category"));
    assert!(d.contains("Chi-square"));
}

#[test]
fn report_heatmap_consistency() {
    let report = EntropyReport::generate(&vec![0u8; 2048]);
    let hm = report.heatmap();
    assert_eq!(hm.blocks.len(), report.sections.len());
    let rgb = hm.to_rgb_colors();
    assert_eq!(rgb.len(), report.sections.len());
}

#[test]
fn report_default_block_size_constant() {
    assert_eq!(EntropyReport::DEFAULT_BLOCK_SIZE, 512);
}

#[test]
fn report_fuzz_no_panic() {
    let mut g = make_lcg(0xBADC_0DE_DEAD_BEAF);
    for _ in 0..50 {
        let n = ((g() >> 48) as usize) % 4096;
        let bs = (((g() >> 48) as usize) % 600) + 1;
        let data: Vec<u8> = (0..n).map(|_| (g() >> 24) as u8).collect();
        let r = EntropyReport::generate_with_block_size(&data, bs);
        assert!((0.0..=8.0).contains(&r.overall_entropy));
        assert_eq!(r.histogram.total, n);
    }
}

// ─── Send/Sync threaded stress ────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<EntropyRating>();
    assert_send_sync::<EntropyCategory>();
    assert_send_sync::<EntropyBlock>();
    assert_send_sync::<SectionEntropy>();
    assert_send_sync::<ByteHistogram>();
    assert_send_sync::<HeatmapData>();
    assert_send_sync::<EntropyResult>();
    assert_send_sync::<EntropyReport>();
    assert_send_sync::<EntropyAnalyzer>();
    assert_send_sync::<EntropyError>();
}

#[test]
fn threaded_entropy_stress() {
    use std::sync::Arc;
    use std::thread;
    let data: Arc<Vec<u8>> = Arc::new((0u8..=255).cycle().take(4096).collect());
    let mut handles = Vec::new();
    for tid in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let slice = &d[..((tid * 100 + i) % d.len()).max(1)];
                let h = shannon_entropy(slice);
                assert!((0.0..=8.0).contains(&h));
                let h2 = shannon_entropy_f32(slice);
                assert!((0.0..=8.0).contains(&h2));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_report_stress() {
    use std::sync::Arc;
    use std::thread;
    let data: Arc<Vec<u8>> = Arc::new(rand_bytes(0xF00D, 2048));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = Arc::clone(&data);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let r = EntropyReport::generate(&d);
                assert_eq!(r.histogram.total, d.len());
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── Hash/Eq consistency proxies on derived Eq types ──────────────────────────

fn hash_of<T: Hash>(v: &T) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

#[test]
fn rating_hash_eq_consistency() {
    let all = [
        EntropyRating::VeryLow,
        EntropyRating::Low,
        EntropyRating::Medium,
        EntropyRating::High,
        EntropyRating::VeryHigh,
    ];
    let mut checked = 0;
    for a in all {
        for b in all {
            checked += 1;
            if a == b {
                assert_eq!(hash_of(&a), hash_of(&b));
            }
        }
    }
    assert!(checked >= 25);
}

#[test]
fn category_hash_eq_consistency() {
    let all = [
        EntropyCategory::Empty,
        EntropyCategory::Text,
        EntropyCategory::Code,
        EntropyCategory::Data,
        EntropyCategory::Compressed,
        EntropyCategory::Encrypted,
        EntropyCategory::Random,
    ];
    let mut pairs = 0;
    for a in &all {
        for b in &all {
            pairs += 1;
            if a == b {
                assert_eq!(hash_of(a), hash_of(b));
            }
        }
    }
    assert!(pairs >= 30);
}

// ─── Serde JSON round-trip (sanity) ───────────────────────────────────────────

#[test]
fn serde_round_trip_category() {
    let all = [
        EntropyCategory::Empty,
        EntropyCategory::Text,
        EntropyCategory::Code,
        EntropyCategory::Data,
        EntropyCategory::Compressed,
        EntropyCategory::Encrypted,
        EntropyCategory::Random,
    ];
    for c in all {
        let j = serde_json::to_string(&c).unwrap();
        let back: EntropyCategory = serde_json::from_str(&j).unwrap();
        assert_eq!(back, c);
    }
}

#[test]
fn serde_round_trip_rating() {
    let all = [
        EntropyRating::VeryLow,
        EntropyRating::Low,
        EntropyRating::Medium,
        EntropyRating::High,
        EntropyRating::VeryHigh,
    ];
    for r in all {
        let j = serde_json::to_string(&r).unwrap();
        let back: EntropyRating = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }
}

#[test]
fn serde_round_trip_block() {
    let b = EntropyBlock::from_slice(123, &[1, 2, 3, 4, 5, 6]);
    let j = serde_json::to_string(&b).unwrap();
    let back: EntropyBlock = serde_json::from_str(&j).unwrap();
    assert_eq!(back.offset, b.offset);
    assert_eq!(back.size, b.size);
    assert_eq!(back.category, b.category);
}
