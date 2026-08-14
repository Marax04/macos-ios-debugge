//! Blitz test suite for rustre-triage-entropy lib.rs public API.

use rustre_triage_entropy::*;

// ─── shannon_entropy ──────────────────────────────────────────────────────────

#[test]
fn shannon_empty() {
    assert!((shannon_entropy(&[]) - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn shannon_single_byte_zero() {
    assert!((shannon_entropy(&[0]) - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn shannon_single_value_long() {
    assert!((shannon_entropy(&[7u8; 10_000]) - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn shannon_two_values_equal() {
    let mut d = vec![0u8; 500];
    d.extend(vec![1u8; 500]);
    let h = shannon_entropy(&d);
    assert!((h - 1.0).abs() < 1e-9, "{h}");
}

#[test]
fn shannon_uniform_256() {
    let d: Vec<u8> = (0u8..=255).collect();
    let h = shannon_entropy(&d);
    assert!((h - 8.0).abs() < 1e-9);
}

#[test]
fn shannon_uniform_256_many() {
    let d: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let h = shannon_entropy(&d);
    assert!((h - 8.0).abs() < 1e-9, "{h}");
}

#[test]
fn shannon_in_range_clamped() {
    for n in [1, 2, 50, 256, 1024] {
        let d: Vec<u8> = (0..n).map(|i| (i * 13) as u8).collect();
        let h = shannon_entropy(&d);
        assert!((0.0..=8.0).contains(&h), "n={n} h={h}");
    }
}

#[test]
fn shannon_four_values_equal_is_two() {
    let mut d = vec![];
    for v in 0..4u8 {
        d.extend(vec![v; 64]);
    }
    let h = shannon_entropy(&d);
    assert!((h - 2.0).abs() < 1e-9, "{h}");
}

// ─── shannon_entropy_f32 ──────────────────────────────────────────────────────

#[test]
fn shannon_f32_empty() {
    assert!((shannon_entropy_f32(&[]) - (0.0)).abs() < f32::EPSILON);
}

#[test]
fn shannon_f32_uniform() {
    let d: Vec<u8> = (0u8..=255).collect();
    assert!((shannon_entropy_f32(&d) - 8.0).abs() < 1e-5);
}

#[test]
fn shannon_f32_matches_f64_loosely() {
    let d: Vec<u8> = (0..1000).map(|i| (i * 7) as u8).collect();
    let f32_h = f64::from(shannon_entropy_f32(&d));
    let f64_h = shannon_entropy(&d);
    assert!((f32_h - f64_h).abs() < 1e-3, "f32={f32_h} f64={f64_h}");
}

// ─── EntropyRating ────────────────────────────────────────────────────────────

#[test]
fn rating_boundaries() {
    assert_eq!(EntropyRating::from_entropy(0.0), EntropyRating::VeryLow);
    assert_eq!(EntropyRating::from_entropy(0.999), EntropyRating::VeryLow);
    assert_eq!(EntropyRating::from_entropy(1.0), EntropyRating::Low);
    assert_eq!(EntropyRating::from_entropy(2.999), EntropyRating::Low);
    assert_eq!(EntropyRating::from_entropy(3.0), EntropyRating::Medium);
    assert_eq!(EntropyRating::from_entropy(4.999), EntropyRating::Medium);
    assert_eq!(EntropyRating::from_entropy(5.0), EntropyRating::High);
    assert_eq!(EntropyRating::from_entropy(6.999), EntropyRating::High);
    assert_eq!(EntropyRating::from_entropy(7.0), EntropyRating::VeryHigh);
    assert_eq!(EntropyRating::from_entropy(8.0), EntropyRating::VeryHigh);
}

#[test]
fn rating_display_all() {
    assert_eq!(EntropyRating::VeryLow.to_string(), "VeryLow");
    assert_eq!(EntropyRating::Low.to_string(), "Low");
    assert_eq!(EntropyRating::Medium.to_string(), "Medium");
    assert_eq!(EntropyRating::High.to_string(), "High");
    assert_eq!(EntropyRating::VeryHigh.to_string(), "VeryHigh");
}

#[test]
fn rating_serde_roundtrip() {
    let r = EntropyRating::Medium;
    let s = serde_json::to_string(&r).unwrap();
    let back: EntropyRating = serde_json::from_str(&s).unwrap();
    assert_eq!(r, back);
}

#[test]
fn rating_eq_and_copy() {
    let a = EntropyRating::High;
    let b = a;
    assert_eq!(a, b);
}

// ─── SectionEntropy ───────────────────────────────────────────────────────────

#[test]
fn section_entropy_zeros() {
    let s = SectionEntropy::new(".bss", &[0u8; 100], 0x400);
    assert_eq!(s.name, ".bss");
    assert_eq!(s.size, 100);
    assert_eq!(s.offset, 0x400);
    assert!((s.entropy - (0.0)).abs() < f64::EPSILON);
    assert_eq!(s.rating, EntropyRating::VeryLow);
    assert!(!s.is_packed());
    assert!(!s.is_encrypted());
}

#[test]
fn section_entropy_uniform_packed_and_encrypted() {
    let d: Vec<u8> = (0u8..=255).collect();
    let s = SectionEntropy::new(".text", &d, 0);
    assert!(s.is_packed());
    assert!(s.is_encrypted());
    assert_eq!(s.rating, EntropyRating::VeryHigh);
}

#[test]
fn section_entropy_empty_input() {
    let s = SectionEntropy::new(".x", &[], 0);
    assert!((s.entropy - (0.0)).abs() < f64::EPSILON);
    assert_eq!(s.size, 0);
}

#[test]
fn section_entropy_string_name() {
    let s = SectionEntropy::new(String::from(".rdata"), &[1, 2, 3], 8);
    assert_eq!(s.name, ".rdata");
}

// ─── EntropyAnalyzer ──────────────────────────────────────────────────────────

#[test]
fn analyzer_empty_data() {
    let a = EntropyAnalyzer::new(64);
    let r = a.analyze(&[]);
    assert!((r.overall - (0.0)).abs() < f64::EPSILON);
    assert!(r.chunks.is_empty());
    assert!(r.sections.is_empty());
}

#[test]
fn analyzer_chunk_count() {
    let a = EntropyAnalyzer::new(100);
    let r = a.analyze(&vec![0u8; 1000]);
    assert_eq!(r.chunks.len(), 10);
}

#[test]
fn analyzer_partial_last_chunk() {
    let a = EntropyAnalyzer::new(100);
    let r = a.analyze(&[0u8; 150]);
    assert_eq!(r.chunks.len(), 2);
}

#[test]
fn analyzer_zero_chunk_size() {
    let a = EntropyAnalyzer::new(0);
    let r = a.analyze(&[1, 2, 3]);
    assert!(r.chunks.is_empty());
}

#[test]
fn analyzer_chunk_larger_than_data() {
    let a = EntropyAnalyzer::new(10_000);
    let r = a.analyze(&[1, 2, 3, 4]);
    assert_eq!(r.chunks.len(), 1);
}

#[test]
fn analyzer_sections_basic() {
    let d: Vec<u8> = (0u8..=255).collect();
    let a = EntropyAnalyzer::new(64);
    let secs = [(".a", 0, 128), (".b", 128, 128)];
    let r = a.analyze_sections(&d, &secs);
    assert_eq!(r.sections.len(), 2);
    assert_eq!(r.sections[0].name, ".a");
    assert_eq!(r.sections[1].name, ".b");
    assert_eq!(r.sections[0].size, 128);
    assert_eq!(r.sections[1].size, 128);
}

#[test]
fn analyzer_sections_clamped_oversized() {
    let d = vec![0u8; 100];
    let a = EntropyAnalyzer::new(32);
    let secs = [(".big", 50, 1000)];
    let r = a.analyze_sections(&d, &secs);
    assert_eq!(r.sections.len(), 1);
    assert_eq!(r.sections[0].size, 50);
}

#[test]
fn analyzer_sections_offset_beyond_data() {
    let d = vec![0u8; 100];
    let a = EntropyAnalyzer::new(32);
    let secs = [(".oob", 200, 10)];
    let r = a.analyze_sections(&d, &secs);
    assert_eq!(r.sections.len(), 1);
    assert_eq!(r.sections[0].size, 0);
    // offset preserved per docs
    assert_eq!(r.sections[0].offset, 200);
}

#[test]
fn analyzer_max_chunk_entropy_no_chunks() {
    let a = EntropyAnalyzer::new(0);
    let r = a.analyze(&[1, 2, 3]);
    assert!((r.max_chunk_entropy() - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn analyzer_packed_sections_filter() {
    let mut d = vec![0u8; 256];
    d.extend(0u8..=255u8);
    let a = EntropyAnalyzer::new(64);
    let secs = [(".low", 0, 256), (".hi", 256, 256)];
    let r = a.analyze_sections(&d, &secs);
    let packed = r.packed_sections();
    assert_eq!(packed.len(), 1);
    assert_eq!(packed[0].name, ".hi");
}

#[test]
fn analyzer_const_new() {
    const A: EntropyAnalyzer = EntropyAnalyzer::new(128);
    assert_eq!(A.chunk_size, 128);
}

// ─── EntropyError ─────────────────────────────────────────────────────────────

#[test]
fn entropy_error_empty_input_display() {
    assert_eq!(EntropyError::EmptyInput.to_string(), "empty input");
}

#[test]
fn entropy_error_invalid_chunk_display() {
    let e = EntropyError::InvalidChunk(42);
    let s = e.to_string();
    assert!(s.contains("42"), "{s}");
    assert!(s.contains("invalid chunk size"), "{s}");
}

// ─── EntropyCategory ──────────────────────────────────────────────────────────

#[test]
fn category_full_boundaries() {
    assert_eq!(EntropyCategory::classify(0.0), EntropyCategory::Empty);
    assert_eq!(EntropyCategory::classify(0.999), EntropyCategory::Empty);
    assert_eq!(EntropyCategory::classify(1.0), EntropyCategory::Text);
    assert_eq!(EntropyCategory::classify(3.999), EntropyCategory::Text);
    assert_eq!(EntropyCategory::classify(4.0), EntropyCategory::Code);
    assert_eq!(EntropyCategory::classify(4.999), EntropyCategory::Code);
    assert_eq!(EntropyCategory::classify(5.0), EntropyCategory::Data);
    assert_eq!(EntropyCategory::classify(5.999), EntropyCategory::Data);
    assert_eq!(EntropyCategory::classify(6.0), EntropyCategory::Compressed);
    assert_eq!(EntropyCategory::classify(6.999), EntropyCategory::Compressed);
    assert_eq!(EntropyCategory::classify(7.0), EntropyCategory::Encrypted);
    assert_eq!(EntropyCategory::classify(7.499), EntropyCategory::Encrypted);
    assert_eq!(EntropyCategory::classify(7.5), EntropyCategory::Random);
    assert_eq!(EntropyCategory::classify(8.0), EntropyCategory::Random);
}

#[test]
fn category_label_and_display_match() {
    for c in [
        EntropyCategory::Empty,
        EntropyCategory::Text,
        EntropyCategory::Code,
        EntropyCategory::Data,
        EntropyCategory::Compressed,
        EntropyCategory::Encrypted,
        EntropyCategory::Random,
    ] {
        assert_eq!(c.to_string(), c.label());
    }
}

#[test]
fn category_serde_roundtrip() {
    let c = EntropyCategory::Compressed;
    let s = serde_json::to_string(&c).unwrap();
    let back: EntropyCategory = serde_json::from_str(&s).unwrap();
    assert_eq!(c, back);
}

// ─── EntropyBlock / analyze_blocks ────────────────────────────────────────────

#[test]
fn block_from_slice() {
    let b = EntropyBlock::from_slice(123, &[0u8; 32]);
    assert_eq!(b.offset, 123);
    assert_eq!(b.size, 32);
    assert!((b.entropy - (0.0)).abs() < f32::EPSILON);
    assert_eq!(b.category, EntropyCategory::Empty);
}

#[test]
fn block_uniform_random_category() {
    let d: Vec<u8> = (0u8..=255).collect();
    let b = EntropyBlock::from_slice(0, &d);
    assert!(b.entropy > 7.9);
    assert_eq!(b.category, EntropyCategory::Random);
}

#[test]
fn analyze_blocks_empty() {
    assert!(analyze_blocks(&[], 256).is_empty());
}

#[test]
fn analyze_blocks_zero_size() {
    assert!(analyze_blocks(&[1, 2, 3, 4], 0).is_empty());
}

#[test]
fn analyze_blocks_offset_progression() {
    let d = vec![0u8; 1000];
    let blocks = analyze_blocks(&d, 100);
    assert_eq!(blocks.len(), 10);
    for (i, b) in blocks.iter().enumerate() {
        assert_eq!(b.offset, (i as u64) * 100);
        assert_eq!(b.size, 100);
    }
}

#[test]
fn analyze_blocks_partial_last() {
    let d = vec![0u8; 250];
    let blocks = analyze_blocks(&d, 100);
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[2].size, 50);
    assert_eq!(blocks[2].offset, 200);
}

#[test]
fn analyze_blocks_block_size_one() {
    let d = vec![5u8; 4];
    let blocks = analyze_blocks(&d, 1);
    assert_eq!(blocks.len(), 4);
    for b in &blocks {
        assert_eq!(b.size, 1);
        assert!((b.entropy - (0.0)).abs() < f32::EPSILON);
    }
}

// ─── ByteHistogram ────────────────────────────────────────────────────────────

#[test]
fn histogram_basic_counts() {
    let h = ByteHistogram::new(&[0, 0, 1, 2, 2, 2]);
    assert_eq!(h.count_of(0), 2);
    assert_eq!(h.count_of(1), 1);
    assert_eq!(h.count_of(2), 3);
    assert_eq!(h.count_of(3), 0);
    assert_eq!(h.total, 6);
}

#[test]
fn histogram_counts_length_256() {
    let h = ByteHistogram::new(&[]);
    assert_eq!(h.counts.len(), 256);
    assert_eq!(h.total, 0);
}

#[test]
fn histogram_count_of_all_bytes() {
    let d: Vec<u8> = (0u8..=255).collect();
    let h = ByteHistogram::new(&d);
    for b in 0u8..=255 {
        assert_eq!(h.count_of(b), 1);
    }
}

#[test]
fn histogram_chi_square_empty_is_zero() {
    assert!((ByteHistogram::new(&[]).chi_square_statistic() - (0.0)).abs() < f64::EPSILON);
}

#[test]
fn histogram_chi_square_uniform_is_zero() {
    let d: Vec<u8> = (0u8..=255).collect();
    let chi2 = ByteHistogram::new(&d).chi_square_statistic();
    assert!(chi2.abs() < 1e-9);
}

#[test]
fn histogram_chi_square_all_zeros_large() {
    // All n bytes go into bucket 0 → chi2 = (n - n/256)^2/(n/256) + 255*(n/256)^2/(n/256)
    let n = 256.0_f64;
    let h = ByteHistogram::new(&vec![0u8; 256]);
    let chi2 = h.chi_square_statistic();
    // expected = 1.0; (256-1)^2 + 255*1 = 65025 + 255 = 65280
    let expected = (256.0_f64 - 1.0).powi(2) / 1.0 + 255.0 * (1.0_f64).powi(2) / 1.0;
    assert!((chi2 - expected).abs() < 1e-6, "chi2={chi2} expected={expected} n={n}");
}

#[test]
fn histogram_is_likely_random_uniform_false() {
    // perfectly uniform → chi2=0 → false
    let d: Vec<u8> = (0u8..=255).collect();
    assert!(!ByteHistogram::new(&d).is_likely_random());
}

#[test]
fn histogram_is_likely_random_skewed_false() {
    assert!(!ByteHistogram::new(&[0u8; 1000]).is_likely_random());
}

#[test]
fn histogram_most_common_basic() {
    let mut d = vec![5u8; 30];
    d.extend(vec![7u8; 20]);
    d.extend(vec![9u8; 10]);
    let h = ByteHistogram::new(&d);
    let top = h.most_common_bytes(3);
    assert_eq!(top[0], (5u8, 30));
    assert_eq!(top[1], (7u8, 20));
    assert_eq!(top[2], (9u8, 10));
}

#[test]
fn histogram_most_common_clamp() {
    let h = ByteHistogram::new(&[0u8; 10]);
    let top = h.most_common_bytes(usize::MAX);
    assert_eq!(top.len(), 256);
}

#[test]
fn histogram_most_common_zero() {
    let h = ByteHistogram::new(&[1, 2, 3]);
    assert!(h.most_common_bytes(0).is_empty());
}

#[test]
fn histogram_serde_roundtrip() {
    let h = ByteHistogram::new(&[1, 2, 3, 1, 2, 1]);
    let s = serde_json::to_string(&h).unwrap();
    let back: ByteHistogram = serde_json::from_str(&s).unwrap();
    assert_eq!(back.total, 6);
    assert_eq!(back.count_of(1), 3);
    assert_eq!(back.count_of(2), 2);
    assert_eq!(back.count_of(3), 1);
}

// ─── HeatmapData ──────────────────────────────────────────────────────────────

#[test]
fn heatmap_color_rgb_full_palette() {
    assert_eq!(HeatmapData::color_rgb(0.0), [0, 0, 128]);
    assert_eq!(HeatmapData::color_rgb(1.999), [0, 0, 128]);
    assert_eq!(HeatmapData::color_rgb(2.0), [0, 128, 255]);
    assert_eq!(HeatmapData::color_rgb(3.999), [0, 128, 255]);
    assert_eq!(HeatmapData::color_rgb(4.0), [0, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(5.999), [0, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(6.0), [255, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(6.999), [255, 200, 0]);
    assert_eq!(HeatmapData::color_rgb(7.0), [200, 0, 0]);
    assert_eq!(HeatmapData::color_rgb(8.0), [200, 0, 0]);
}

#[test]
fn heatmap_from_data_block_count() {
    let d = vec![0u8; 1024];
    let hm = HeatmapData::from_data(&d, 256);
    assert_eq!(hm.blocks.len(), 4);
}

#[test]
fn heatmap_ascii_empty_blocks() {
    let hm = HeatmapData::from_blocks(vec![]);
    assert_eq!(hm.to_ascii_heatmap(80), "");
}

#[test]
fn heatmap_ascii_zero_width() {
    let hm = HeatmapData::from_data(&vec![0u8; 512], 64);
    assert_eq!(hm.to_ascii_heatmap(0), "");
}

#[test]
fn heatmap_ascii_width_one() {
    let hm = HeatmapData::from_data(&vec![0u8; 512], 64);
    let s = hm.to_ascii_heatmap(1);
    assert!(s.contains('|'), "{s}");
}

#[test]
fn heatmap_ascii_borders_and_lines() {
    let hm = HeatmapData::from_data(&vec![0u8; 512], 64);
    let s = hm.to_ascii_heatmap(40);
    let lines: Vec<&str> = s.lines().collect();
    // border line, |row|, border line, scale
    assert!(lines.len() >= 4, "{s}");
    assert!(lines[0].chars().all(|c| c == '-'));
    assert_eq!(lines[0].len(), 42);
}

#[test]
fn heatmap_to_rgb_colors_matches_blocks() {
    let d: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    let hm = HeatmapData::from_data(&d, 256);
    let colors = hm.to_rgb_colors();
    assert_eq!(colors.len(), hm.blocks.len());
    for c in colors {
        // high entropy → red
        assert_eq!(c, [200, 0, 0]);
    }
}

#[test]
fn heatmap_ascii_high_entropy_uses_hash() {
    let d: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    let hm = HeatmapData::from_data(&d, 256);
    let s = hm.to_ascii_heatmap(20);
    assert!(s.contains('#'), "{s}");
}

// ─── PackingDetector ──────────────────────────────────────────────────────────

#[test]
fn packing_detector_empty() {
    assert!(PackingDetector::detect_packing_indicators(&[]).is_empty());
}

#[test]
fn packing_detector_short_no_pe() {
    let d = vec![0u8; 32];
    let v = PackingDetector::detect_packing_indicators(&d);
    assert!(v.is_empty());
}

#[test]
fn packing_detector_upx_magic_only() {
    let mut d = vec![0u8; 256];
    d[100..104].copy_from_slice(b"UPX!");
    let v = PackingDetector::detect_packing_indicators(&d);
    assert!(v.iter().any(|s| s.contains("UPX magic")));
}

#[test]
fn packing_detector_no_pe_signature() {
    // Data has e_lfanew pointing nowhere meaningful (no PE\0\0)
    let mut d = vec![0u8; 256];
    d[0x3c] = 0x80;
    d[0x3d] = 0;
    d[0x3e] = 0;
    d[0x3f] = 0;
    // No PE sig at offset 0x80 → returns empty (after potential UPX check)
    let v = PackingDetector::detect_packing_indicators(&d);
    // No UPX magic, no valid PE → empty
    assert!(v.is_empty(), "{v:?}");
}

#[test]
fn packing_detector_valid_pe_no_imports() {
    // Construct a minimal PE-ish header so import RVA == 0 triggers indicator
    let mut d = vec![0u8; 1024];
    let e_lfanew = 0x80_usize;
    d[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    d[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    // num_sections = 0, opt_header_size = 224 (PE32 standard)
    d[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&0u16.to_le_bytes());
    d[e_lfanew + 20..e_lfanew + 22].copy_from_slice(&224u16.to_le_bytes());
    // optional header magic at e_lfanew + 24 → PE32 = 0x10b
    d[e_lfanew + 24..e_lfanew + 26].copy_from_slice(&0x10bu16.to_le_bytes());
    // import_dir_offset = e_lfanew + 24 + 104 = 232, zero bytes already → RVA = 0
    let v = PackingDetector::detect_packing_indicators(&d);
    assert!(
        v.iter().any(|s| s.contains("No import directory")),
        "{v:?}"
    );
    // "Few imports (<5)" is NOT additionally emitted here, and that is
    // correct: `count_pe_imports` returns `None` when the import RVA is zero,
    // because there is no descriptor table to walk. The zero-import case is
    // reported by its own, strictly more informative indicator above — adding
    // "Few imports" on top would restate the same fact less precisely.
    //
    // (This assertion had never actually run: `cargo test` stops at the first
    // failing target, and this crate's lib target was red, so the whole
    // `blitz` binary was skipped.)
    assert!(
        !v.iter().any(|s| s.contains("Few imports")),
        "the zero-import case is covered by 'No import directory', not 'Few imports': {v:?}"
    );
}

#[test]
fn packing_detector_upx_section_name() {
    let mut d = vec![0u8; 2048];
    let e_lfanew = 0x80_usize;
    d[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    d[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    d[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    d[e_lfanew + 20..e_lfanew + 22].copy_from_slice(&224u16.to_le_bytes());
    d[e_lfanew + 24..e_lfanew + 26].copy_from_slice(&0x10bu16.to_le_bytes());
    let section_start = e_lfanew + 24 + 224;
    d[section_start..section_start + 4].copy_from_slice(b"UPX0");
    let v = PackingDetector::detect_packing_indicators(&d);
    assert!(
        v.iter().any(|s| s.contains("UPX magic in section name")),
        "{v:?}"
    );
}

#[test]
fn packing_detector_packer_name_aspack() {
    let mut d = vec![0u8; 2048];
    let e_lfanew = 0x80_usize;
    d[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    d[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    d[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&1u16.to_le_bytes());
    d[e_lfanew + 20..e_lfanew + 22].copy_from_slice(&224u16.to_le_bytes());
    d[e_lfanew + 24..e_lfanew + 26].copy_from_slice(&0x10bu16.to_le_bytes());
    let section_start = e_lfanew + 24 + 224;
    d[section_start..section_start + 7].copy_from_slice(b".aspack");
    let v = PackingDetector::detect_packing_indicators(&d);
    assert!(
        v.iter().any(|s| s.contains("Section name indicates packer")),
        "{v:?}"
    );
}

// ─── EntropyReport ────────────────────────────────────────────────────────────

#[test]
fn report_zeros() {
    let r = EntropyReport::generate(&vec![0u8; 2048]);
    assert!((r.overall_entropy - (0.0)).abs() < f32::EPSILON);
    assert_eq!(r.category, EntropyCategory::Empty);
    assert!(!r.sections.is_empty());
    assert_eq!(r.histogram.total, 2048);
}

#[test]
fn report_uniform_random() {
    let d: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
    let r = EntropyReport::generate(&d);
    assert!((r.overall_entropy - 8.0).abs() < 0.01);
    assert_eq!(r.category, EntropyCategory::Random);
}

#[test]
fn report_default_block_size_constant() {
    assert_eq!(EntropyReport::DEFAULT_BLOCK_SIZE, 512);
}

#[test]
fn report_custom_block_size() {
    let r = EntropyReport::generate_with_block_size(&vec![0u8; 1024], 128);
    assert_eq!(r.sections.len(), 8);
}

#[test]
fn report_block_size_zero_max_to_one() {
    // Per src: block_size.max(1) used → zero becomes 1
    let r = EntropyReport::generate_with_block_size(&[0u8; 16], 0);
    assert_eq!(r.sections.len(), 16);
}

#[test]
fn report_heatmap_matches_sections() {
    let r = EntropyReport::generate(&vec![0u8; 4096]);
    let hm = r.heatmap();
    assert_eq!(hm.blocks.len(), r.sections.len());
}

#[test]
fn report_high_entropy_blocks_threshold() {
    let d: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let r = EntropyReport::generate(&d);
    let high = r.high_entropy_blocks(7.0);
    assert!(!high.is_empty());
    let none = r.high_entropy_blocks(9.0);
    assert!(none.is_empty());
}

#[test]
fn report_summary_format() {
    let r = EntropyReport::generate(&vec![0u8; 512]);
    let s = r.summary();
    assert!(s.starts_with("EntropyReport {"));
    assert!(s.contains("overall"));
    assert!(s.contains("category"));
    assert!(s.contains("packed"));
    assert!(s.contains("indicators"));
}

#[test]
fn report_display() {
    let r = EntropyReport::generate(&vec![0u8; 512]);
    let s = format!("{r}");
    assert!(s.contains("=== Entropy Report ==="));
    assert!(s.contains("Overall entropy"));
    assert!(s.contains("Category"));
    assert!(s.contains("Likely packed"));
    assert!(s.contains("Chi-square"));
    assert!(s.contains("Blocks"));
}

#[test]
fn report_packed_flag_when_upx_present() {
    let mut d = vec![0u8; 512];
    d[100..104].copy_from_slice(b"UPX!");
    let r = EntropyReport::generate(&d);
    assert!(r.is_likely_packed);
    assert!(!r.packing_indicators.is_empty());
}

#[test]
fn report_not_packed_for_random_bytes_without_signatures() {
    // High entropy alone shouldn't trigger "packed" unless an indicator says so.
    // But the small uniform buffer is < 64 bytes so detector returns early empty;
    // grow it to 600 to ensure PE path is entered but no signatures.
    let d: Vec<u8> = (0u8..=255).cycle().take(600).collect();
    let r = EntropyReport::generate(&d);
    // No UPX, no PE sig → no indicators
    assert!(!r.is_likely_packed, "{:?}", r.packing_indicators);
}

#[test]
fn report_serde_roundtrip() {
    let r = EntropyReport::generate(&vec![0u8; 256]);
    let s = serde_json::to_string(&r).unwrap();
    let back: EntropyReport = serde_json::from_str(&s).unwrap();
    assert_eq!(back.overall_entropy, r.overall_entropy);
    assert_eq!(back.category, r.category);
    assert_eq!(back.histogram.total, r.histogram.total);
    assert_eq!(back.sections.len(), r.sections.len());
}

// ─── Sanity / concurrency ─────────────────────────────────────────────────────

const fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn types_are_send_sync() {
    assert_send_sync::<EntropyAnalyzer>();
    assert_send_sync::<EntropyResult>();
    assert_send_sync::<EntropyReport>();
    assert_send_sync::<ByteHistogram>();
    assert_send_sync::<HeatmapData>();
    assert_send_sync::<EntropyBlock>();
    assert_send_sync::<SectionEntropy>();
    assert_send_sync::<EntropyError>();
}
