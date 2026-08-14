//! Deep adversarial tests for rustre-hex (Y069 blitz2).

use rustre_hex::*;

// ── Seeded LCG ───────────────────────────────────────────────────────────────
fn make_lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

fn rand_bytes(n: usize, g: &mut impl FnMut() -> u64) -> Vec<u8> {
    (0..n).map(|_| (g() & 0xFF) as u8).collect()
}

// ── HexBuffer round-trips ────────────────────────────────────────────────────

#[test]
fn write_then_read_round_trip_many() {
    let mut g = make_lcg();
    for _ in 0..60 {
        let len = (g() as usize % 256) + 1;
        let data = rand_bytes(len, &mut g);
        let mut buf = HexBuffer::zeroed(len);
        buf.write(0, &data).unwrap();
        assert_eq!(buf.read(0, len).unwrap(), &data[..]);
    }
}

#[test]
fn insert_then_delete_undo() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let base = rand_bytes(((g() & 0x3F) + 1) as usize, &mut g);
        let ins = rand_bytes(((g() & 0xF) + 1) as usize, &mut g);
        let off = (g() as usize) % (base.len() + 1);
        let mut buf = HexBuffer::new(base.clone());
        buf.insert(off, &ins).unwrap();
        assert_eq!(buf.len(), base.len() + ins.len());
        assert!(buf.undo());
        assert_eq!(buf.data, base);
    }
}

#[test]
fn delete_then_undo_restores() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let base = rand_bytes(((g() & 0x3F) + 4) as usize, &mut g);
        let off = (g() as usize) % base.len();
        let max_del = base.len() - off;
        let dlen = ((g() as usize) % max_del) + 1;
        let mut buf = HexBuffer::new(base.clone());
        buf.delete(off, dlen).unwrap();
        assert!(buf.undo());
        assert_eq!(buf.data, base);
    }
}

#[test]
fn write_undo_redo_loop() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let n = ((g() & 0x1F) + 4) as usize;
        let orig = rand_bytes(n, &mut g);
        let patch = rand_bytes(n, &mut g);
        let mut buf = HexBuffer::new(orig.clone());
        buf.write(0, &patch).unwrap();
        assert_eq!(buf.data, patch);
        assert!(buf.undo());
        assert_eq!(buf.data, orig);
        assert!(buf.redo());
        assert_eq!(buf.data, patch);
    }
}

#[test]
fn xor_xor_is_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let key = rand_bytes((g() % 8 + 1) as usize, &mut g);
        let mut buf = HexBuffer::new(data.clone());
        buf.xor_range(0..n, &key).unwrap();
        buf.xor_range(0..n, &key).unwrap();
        assert_eq!(buf.data, data);
    }
}

#[test]
fn not_not_is_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let mut buf = HexBuffer::new(data.clone());
        buf.not_range(0..n).unwrap();
        buf.not_range(0..n).unwrap();
        assert_eq!(buf.data, data);
    }
}

#[test]
fn reverse_reverse_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 2) as usize;
        let data = rand_bytes(n, &mut g);
        let mut buf = HexBuffer::new(data.clone());
        buf.reverse_range(0..n).unwrap();
        buf.reverse_range(0..n).unwrap();
        assert_eq!(buf.data, data);
    }
}

#[test]
fn rotate_left_rotate_right_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 2) as usize;
        let data = rand_bytes(n, &mut g);
        let amt = (g() as usize) % n;
        let mut buf = HexBuffer::new(data.clone());
        buf.rotate_left(0..n, amt).unwrap();
        buf.rotate_right(0..n, amt).unwrap();
        assert_eq!(buf.data, data);
    }
}

#[test]
fn add_then_subtract_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let addend = (g() & 0xFF) as u8;
        let mut buf = HexBuffer::new(data.clone());
        buf.add_range(0..n, addend).unwrap();
        buf.add_range(0..n, addend.wrapping_neg()).unwrap();
        assert_eq!(buf.data, data);
    }
}

#[test]
fn negate_twice_identity() {
    let mut g = make_lcg();
    for _ in 0..40 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let mut buf = HexBuffer::new(data.clone());
        buf.negate_range(0..n).unwrap();
        buf.negate_range(0..n).unwrap();
        assert_eq!(buf.data, data);
    }
}

// ── Boundaries ────────────────────────────────────────────────────────────────

#[test]
fn read_at_end_returns_empty_slice() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    let s = buf.read(3, 5).unwrap();
    assert!(s.is_empty());
}

#[test]
fn read_past_end_errors() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.read(4, 1).is_err());
}

#[test]
fn write_oob_errors() {
    let mut buf = HexBuffer::new(vec![0u8; 3]);
    assert!(buf.write(2, &[1, 2, 3]).is_err());
    assert!(buf.write(4, &[1]).is_err());
}

#[test]
fn insert_past_end_errors() {
    let mut buf = HexBuffer::new(vec![1, 2]);
    assert!(buf.insert(3, &[0]).is_err());
}

#[test]
fn delete_past_end_errors() {
    let mut buf = HexBuffer::new(vec![1, 2]);
    assert!(buf.delete(3, 1).is_err());
}

#[test]
fn fill_empty_pattern_errors() {
    let mut buf = HexBuffer::new(vec![0u8; 4]);
    assert!(buf.fill(0..4, &[]).is_err());
}

#[test]
fn fill_invalid_range_errors() {
    let mut buf = HexBuffer::new(vec![0u8; 4]);
    assert!(buf.fill(3..2, &[0xFF]).is_err());
    assert!(buf.fill(0..10, &[0xFF]).is_err());
}

#[test]
fn xor_empty_key_errors() {
    let mut buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.xor_range(0..3, &[]).is_err());
}

#[test]
fn rotate_amount_modulo_len() {
    let mut buf = HexBuffer::new(vec![1, 2, 3, 4]);
    buf.rotate_left(0..4, 6).unwrap(); // 6 % 4 == 2
    assert_eq!(buf.data, vec![3, 4, 1, 2]);
}

// ── Search ────────────────────────────────────────────────────────────────────

#[test]
fn kmp_finds_overlapping() {
    let m = kmp_search(b"aaaa", b"aa");
    assert_eq!(m, vec![0, 1, 2]);
}

#[test]
fn kmp_empty_needle_returns_all_positions() {
    let m = kmp_search(b"abc", b"");
    assert_eq!(m, vec![0, 1, 2, 3]);
}

#[test]
fn search_empty_pattern_returns_empty() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.search(&[]).is_empty());
}

#[test]
fn search_pattern_longer_than_data() {
    let buf = HexBuffer::new(vec![1, 2]);
    assert!(buf.search(&[1, 2, 3, 4]).is_empty());
}

#[test]
fn hex_pattern_wildcards() {
    let buf = HexBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let r = buf.find_hex_pattern("DE ?? BE EF").unwrap();
    assert_eq!(r, vec![0]);
    let r = buf.find_hex_pattern("DE ? BE EF").unwrap();
    assert_eq!(r, vec![0]);
}

#[test]
fn hex_pattern_invalid_token_errors() {
    let buf = HexBuffer::new(vec![0; 8]);
    assert!(buf.find_hex_pattern("ZZ").is_err());
    assert!(buf.find_hex_pattern("DEAD").is_err()); // wrong length
}

#[test]
fn hex_pattern_empty_returns_empty() {
    let buf = HexBuffer::new(vec![0; 4]);
    let r = buf.find_hex_pattern("").unwrap();
    assert!(r.is_empty());
}

#[test]
fn regex_unanchored_finds_all() {
    let buf = HexBuffer::new(b"axxbxxc".to_vec());
    let r = buf.search_regex("[abc]").unwrap();
    assert!(r.contains(&0) && r.contains(&3) && r.contains(&6));
}

#[test]
fn regex_anchor_start() {
    let buf = HexBuffer::new(b"helloworld".to_vec());
    let r = buf.search_regex("^hello").unwrap();
    assert_eq!(r, vec![0]);
}

#[test]
fn regex_hex_escape() {
    let buf = HexBuffer::new(vec![0x00, 0xFF, 0x10]);
    let r = buf.search_regex(r"\xFF").unwrap();
    assert!(r.contains(&1));
}

#[test]
fn regex_invalid_pattern_errors() {
    let buf = HexBuffer::new(vec![0; 4]);
    assert!(buf.search_regex(r"\xZZ").is_err());
}

#[test]
fn find_string_ascii_non_ascii_errors() {
    let buf = HexBuffer::new(b"hello".to_vec());
    assert!(buf.find_string("héllo", Encoding::Ascii).is_err());
}

#[test]
fn find_string_latin1_non_latin_errors() {
    let buf = HexBuffer::new(vec![0; 4]);
    assert!(buf.find_string("日", Encoding::Latin1).is_err());
}

#[test]
fn find_all_with_limit() {
    let buf = HexBuffer::new(vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA]);
    let opts = FindReplaceOptions {
        mode: SearchMode::Exact,
        wrap: false,
        limit: Some(2..5),
    };
    let r = buf.find_all(&[0xAA], &opts).unwrap();
    let offsets: Vec<usize> = r.iter().map(|m| m.offset).collect();
    assert_eq!(offsets, vec![2, 4]);
}

#[test]
fn find_all_invalid_limit_errors() {
    let buf = HexBuffer::new(vec![0; 8]);
    let opts = FindReplaceOptions {
        mode: SearchMode::Exact,
        wrap: false,
        limit: Some(5..3),
    };
    assert!(buf.find_all(&[0], &opts).is_err());
}

#[test]
fn replace_all_empty_needle_errors() {
    let mut buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.replace_all(&[], &[0xFF], &FindReplaceOptions::default()).is_err());
}

#[test]
fn replace_all_back_to_front() {
    let mut buf = HexBuffer::new(vec![0xAA, 0xBB, 0xAA, 0xBB]);
    let count = buf.replace_all(&[0xAA, 0xBB], &[0xCC], &FindReplaceOptions::default()).unwrap();
    assert_eq!(count, 2);
    assert_eq!(buf.data, vec![0xCC, 0xCC]);
}

// ── Typed reads ───────────────────────────────────────────────────────────────

#[test]
fn typed_le_be_round_trip() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let v = g() as u32;
        let le = v.to_le_bytes().to_vec();
        let be = v.to_be_bytes().to_vec();
        let bl = HexBuffer::new(le);
        let bb = HexBuffer::new(be);
        if let TypedValue::U32(x) = bl.read_typed(0, DataType::U32Le).unwrap() {
            assert_eq!(x, v);
        } else { panic!() }
        if let TypedValue::U32(x) = bb.read_typed(0, DataType::U32Be).unwrap() {
            assert_eq!(x, v);
        } else { panic!() }
    }
}

#[test]
fn typed_signed_extremes() {
    let buf = HexBuffer::new(vec![0xFFu8; 8]);
    assert_eq!(buf.read_typed(0, DataType::I8).unwrap(), TypedValue::I8(-1));
    assert_eq!(buf.read_typed(0, DataType::I16Le).unwrap(), TypedValue::I16(-1));
    assert_eq!(buf.read_typed(0, DataType::I32Le).unwrap(), TypedValue::I32(-1));
    assert_eq!(buf.read_typed(0, DataType::I64Le).unwrap(), TypedValue::I64(-1));
}

#[test]
fn typed_truncated_errors() {
    let buf = HexBuffer::new(vec![0u8; 3]);
    assert!(buf.read_typed(0, DataType::U32Le).is_err());
    assert!(buf.read_typed(0, DataType::U64Le).is_err());
    assert!(buf.read_typed(0, DataType::F64Le).is_err());
}

#[test]
fn typed_cstr_no_null_reads_to_end() {
    let buf = HexBuffer::new(b"abc".to_vec());
    assert_eq!(buf.read_typed(0, DataType::CStr).unwrap(), TypedValue::Str("abc".to_string()));
}

#[test]
fn typed_cstr_at_end_errors() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.read_typed(3, DataType::CStr).is_err());
}

#[test]
fn typed_utf16_overflow_errors() {
    let buf = HexBuffer::new(vec![0u8; 4]);
    assert!(buf.read_typed(0, DataType::Utf16(usize::MAX)).is_err());
}

#[test]
fn datatype_utf16_size_overflow_is_none() {
    assert_eq!(DataType::Utf16(usize::MAX).fixed_size(), None);
}

#[test]
fn datatype_fixed_sizes_all() {
    let pairs = [
        (DataType::U8, 1), (DataType::I8, 1),
        (DataType::U16Le, 2), (DataType::U16Be, 2),
        (DataType::I16Le, 2), (DataType::I16Be, 2),
        (DataType::U32Le, 4), (DataType::U32Be, 4),
        (DataType::I32Le, 4), (DataType::I32Be, 4),
        (DataType::F32Le, 4), (DataType::F32Be, 4),
        (DataType::U64Le, 8), (DataType::U64Be, 8),
        (DataType::I64Le, 8), (DataType::I64Be, 8),
        (DataType::F64Le, 8), (DataType::F64Be, 8),
    ];
    for (dt, sz) in pairs {
        assert_eq!(dt.fixed_size(), Some(sz));
    }
}

// ── Histogram / statistics ────────────────────────────────────────────────────

#[test]
fn histogram_total_matches_data_len() {
    let mut g = make_lcg();
    for _ in 0..30 {
        let n = ((g() & 0xFF) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let h = Histogram::compute(&data);
        assert_eq!(h.total as usize, n);
        let sum: u64 = h.counts.iter().sum();
        assert_eq!(sum as usize, n);
    }
}

#[test]
fn histogram_freq_empty_returns_zero() {
    let h = Histogram::compute(&[]);
    assert_eq!(h.frequency(0), 0.0);
    assert_eq!(h.total, 0);
}

#[test]
fn histogram_normalised_max_is_one() {
    let h = Histogram::compute(&[1, 1, 2, 3]);
    let n = h.normalised();
    let max = n.iter().cloned().fold(0.0f64, f64::max);
    assert!((max - 1.0).abs() < 1e-9);
}

#[test]
fn statistics_constant_entropy_zero() {
    let stats = ByteStatistics::compute(&[7u8; 100]).unwrap();
    assert!(stats.entropy.abs() < 1e-9);
    assert_eq!(stats.unique_count, 1);
    assert_eq!(stats.mode, 7);
}

#[test]
fn statistics_empty_errors() {
    assert!(ByteStatistics::compute(&[]).is_err());
}

// ── CRC / hashes known vectors ───────────────────────────────────────────────

#[test]
fn crc32_known() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF43926);
}

#[test]
fn crc16_ccitt_known_empty() {
    assert_eq!(crc16_ccitt(b""), 0xFFFF);
}

#[test]
fn adler32_known() {
    assert_eq!(adler32(b""), 1);
    assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
}

#[test]
fn fnv1a_consistency() {
    let mut g = make_lcg();
    for _ in 0..30 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        assert_eq!(fnv1a32(&data), fnv1a32(&data));
        assert_eq!(fnv1a64(&data), fnv1a64(&data));
    }
}

// ── Patch round-trip ─────────────────────────────────────────────────────────

#[test]
fn patch_apply_revert_identity() {
    let mut g = make_lcg();
    for _ in 0..30 {
        let n = ((g() & 0x3F) + 4) as usize;
        let orig = rand_bytes(n, &mut g);
        let new = rand_bytes(n, &mut g);
        let mut buf = orig.clone();
        let patch = HexPatch::new(0, orig.clone(), new.clone());
        patch.apply(&mut buf).unwrap();
        assert_eq!(buf, new);
        patch.revert(&mut buf).unwrap();
        assert_eq!(buf, orig);
    }
}

#[test]
fn patch_oob_errors() {
    let mut buf = vec![0u8; 4];
    let patch = HexPatch::new(2, vec![0; 4], vec![1; 4]);
    assert!(patch.apply(&mut buf).is_err());
}

#[test]
fn patch_set_apply_revert_identity() {
    let orig = vec![0u8, 1, 2, 3, 4, 5, 6, 7];
    let mut buf = orig.clone();
    let mut set = HexPatchSet::new();
    set.add(HexPatch::new(0, vec![0], vec![0xAA]));
    set.add(HexPatch::new(4, vec![4], vec![0xBB]));
    set.apply_all(&mut buf).unwrap();
    assert_eq!(buf[0], 0xAA);
    assert_eq!(buf[4], 0xBB);
    set.revert_all(&mut buf).unwrap();
    assert_eq!(buf, orig);
}

#[test]
fn patch_set_json_round_trip() {
    let mut set = HexPatchSet::new();
    set.add(HexPatch::new(0, vec![0xAA], vec![0xBB]));
    set.add(HexPatch::new(10, vec![1, 2], vec![3, 4]));
    let j = set.to_json().unwrap();
    let back = HexPatchSet::from_json(&j).unwrap();
    assert_eq!(back.len(), 2);
}

// ── Multi-cursor ─────────────────────────────────────────────────────────────

#[test]
fn multicursor_remove_oob_errors() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(5);
    assert!(mc.remove_cursor(99).is_err());
}

#[test]
fn multicursor_remove_last_no_op() {
    let mut mc = MultiCursorState::new();
    assert!(mc.remove_cursor(0).is_ok());
    assert_eq!(mc.count(), 1);
}

#[test]
fn multicursor_move_clamped() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(50);
    mc.move_all(-1000, 100);
    assert_eq!(mc.cursors()[0].offset, 0);
    mc.move_all(1000, 100);
    assert!(mc.cursors().iter().all(|c| c.offset <= 100));
}

#[test]
fn multicursor_sort_and_collapse() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(30);
    mc.add_cursor(5);
    mc.add_cursor(15);
    mc.sort();
    let offs: Vec<usize> = mc.cursors().iter().map(|c| c.offset).collect();
    assert!(offs.windows(2).all(|w| w[0] <= w[1]));
}

// ── HexDiff ───────────────────────────────────────────────────────────────────

#[test]
fn diff_then_patch_makes_equal() {
    let mut g = make_lcg();
    for _ in 0..20 {
        let n = ((g() & 0x3F) + 1) as usize;
        let a = rand_bytes(n, &mut g);
        let b = rand_bytes(n, &mut g);
        let mut left = HexBuffer::new(a);
        let right = HexBuffer::new(b);
        let regions = HexDiff::compare(&left, &right);
        for r in &regions {
            // skip regions where lengths differ (different-length buffers)
            if r.right.len() == r.len {
                HexDiff::apply_patch(&mut left, r).unwrap();
            }
        }
        assert_eq!(left.data, right.data);
    }
}

#[test]
fn diff_identical_empty() {
    let a = HexBuffer::new(vec![1, 2, 3, 4, 5]);
    let b = HexBuffer::new(vec![1, 2, 3, 4, 5]);
    assert!(HexDiff::compare(&a, &b).is_empty());
}

// ── ByteClass ────────────────────────────────────────────────────────────────

#[test]
fn byte_class_partition_covers_all() {
    for b in 0u8..=255 {
        let c = ByteClass::of(b);
        match b {
            0 => assert_eq!(c, ByteClass::Null),
            0x01..=0x1F | 0x7F => assert_eq!(c, ByteClass::ControlAscii),
            0x20..=0x7E => assert_eq!(c, ByteClass::PrintableAscii),
            _ => assert_eq!(c, ByteClass::HighByte),
        }
    }
}

#[test]
fn printable_null_counts() {
    let data = b"hello\0world\x01";
    assert_eq!(printable_count(data), 10);
    assert_eq!(null_count(data), 1);
}

// ── RunLength ─────────────────────────────────────────────────────────────────

#[test]
fn run_length_round_trip_total_length() {
    let mut g = make_lcg();
    for _ in 0..30 {
        let n = ((g() & 0xFF) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let runs = run_length_encode(&data);
        let total: usize = runs.iter().map(|r| r.length).sum();
        assert_eq!(total, n);
        // reconstruct
        let mut reconstructed = Vec::with_capacity(n);
        for r in &runs {
            for _ in 0..r.length {
                reconstructed.push(r.value);
            }
        }
        assert_eq!(reconstructed, data);
    }
}

#[test]
fn run_length_empty() {
    assert!(run_length_encode(&[]).is_empty());
    assert!(longest_run(&[]).is_none());
}

#[test]
fn longest_run_picks_max() {
    let r = longest_run(b"aaabbcccccdd").unwrap();
    assert_eq!(r.value, b'c');
    assert_eq!(r.length, 5);
}

// ── HexRegion / Map ──────────────────────────────────────────────────────────

#[test]
fn region_overlaps_logic() {
    let r1 = HexRegion::new("a", 0, 10);
    let r2 = HexRegion::new("b", 5, 15);
    let r3 = HexRegion::new("c", 10, 20);
    assert!(r1.overlaps(&r2));
    assert!(!r1.overlaps(&r3));
    assert!(r2.overlaps(&r3));
}

#[test]
fn region_contains() {
    let r = HexRegion::new("x", 5, 10);
    assert!(r.contains(5));
    assert!(r.contains(9));
    assert!(!r.contains(10));
    assert!(!r.contains(4));
}

#[test]
fn region_map_basic() {
    let mut m = HexRegionMap::new();
    m.add(HexRegion::new("h", 0, 16));
    m.add(HexRegion::new("body", 16, 100));
    assert_eq!(m.len(), 2);
    assert_eq!(m.at_offset(8).len(), 1);
    assert_eq!(m.at_offset(50).len(), 1);
    assert!(m.get("h").is_some());
    assert!(m.remove("h"));
    assert_eq!(m.len(), 1);
}

#[test]
fn region_map_overlapping_pairs() {
    let mut m = HexRegionMap::new();
    m.add(HexRegion::new("a", 0, 10));
    m.add(HexRegion::new("b", 5, 15));
    m.add(HexRegion::new("c", 20, 30));
    assert_eq!(m.overlapping_pairs().len(), 1);
}

// ── ByteFrequency ─────────────────────────────────────────────────────────────

#[test]
fn byte_frequency_most_common() {
    let f = ByteFrequency::compute(&[1, 1, 1, 2, 3]);
    assert_eq!(f.most_common(), (1, 3));
    assert_eq!(f.distinct_count(), 3);
    assert_eq!(f.least_common_nonzero(), Some((2, 1))); // tie -> first by index
}

#[test]
fn byte_frequency_empty() {
    let f = ByteFrequency::compute(&[]);
    assert_eq!(f.total, 0);
    assert_eq!(f.frequency(0), 0.0);
    assert_eq!(f.entropy(), 0.0);
}

// ── HexCompareResult ─────────────────────────────────────────────────────────

#[test]
fn compare_identical_similarity_one() {
    let c = HexCompareResult::compare(&[1, 2, 3], &[1, 2, 3]);
    assert!(c.is_identical());
    assert!((c.similarity() - 1.0).abs() < 1e-9);
}

#[test]
fn compare_empty_inputs() {
    let c = HexCompareResult::compare(&[], &[]);
    assert_eq!(c.compared_len, 0);
    assert!((c.similarity() - 1.0).abs() < 1e-9);
}

// ── HexBookmarkList / HexAnnotationSet JSON ──────────────────────────────────

#[test]
fn annotation_set_json_round_trip() {
    let mut s = HexAnnotationSet::new();
    s.add(HexAnnotation::new(0, "header").with_length(4));
    s.add(HexAnnotation::new(8, "magic"));
    let j = s.to_json().unwrap();
    let back = HexAnnotationSet::from_json(&j).unwrap();
    assert_eq!(back.len(), 2);
}

#[test]
fn annotation_at_offset() {
    let mut s = HexAnnotationSet::new();
    s.add(HexAnnotation::new(0, "a").with_length(4));
    assert_eq!(s.at(2).len(), 1);
    assert!(s.at(10).is_empty());
}

#[test]
fn bookmark_list_remove_sort() {
    let mut bl = HexBookmarkList::new();
    bl.add(HexBookmark::new("z", 100));
    bl.add(HexBookmark::new("a", 10));
    bl.sort_by_offset();
    assert_eq!(bl.all()[0].offset, 10);
    assert!(bl.remove("a"));
    assert_eq!(bl.len(), 1);
    assert!(!bl.remove("nope"));
}

// ── chunk_bytes ───────────────────────────────────────────────────────────────

#[test]
fn chunk_bytes_basic() {
    let chunks = chunk_bytes(&[1, 2, 3, 4, 5], 2);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].offset, 0);
    assert_eq!(chunks[2].data, vec![5]);
}

#[test]
fn chunk_bytes_zero_size_empty() {
    assert!(chunk_bytes(&[1, 2, 3], 0).is_empty());
    assert!(chunk_bytes(&[], 5).is_empty());
}

// ── Threaded Send+Sync stress ─────────────────────────────────────────────────

#[test]
fn hexbuffer_threaded_read_stress() {
    use std::sync::Arc;
    use std::thread;
    let buf = Arc::new(HexBuffer::new((0u8..=200).collect()));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let b = buf.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let off = i % b.len();
                let _ = b.read(off, 1).unwrap();
                let _ = b.histogram();
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

#[test]
fn crc_threaded_stress() {
    use std::sync::Arc;
    use std::thread;
    let data: Arc<Vec<u8>> = Arc::new((0u8..=255).collect());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let d = data.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = crc32(&d);
                let _ = adler32(&d);
                let _ = fnv1a32(&d);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}

// ── KMP fuzz ─────────────────────────────────────────────────────────────────

#[test]
fn kmp_fuzz_never_panics() {
    let mut g = make_lcg();
    for _ in 0..50 {
        let hn = ((g() & 0xFF) + 1) as usize;
        let nn = ((g() & 0xF) + 1) as usize;
        let hay = rand_bytes(hn, &mut g);
        let needle = rand_bytes(nn, &mut g);
        let matches = kmp_search(&hay, &needle);
        for &m in &matches {
            assert!(m + needle.len() <= hay.len());
            assert_eq!(&hay[m..m + needle.len()], &needle[..]);
        }
    }
}

// ── Regex fuzz: never panic ──────────────────────────────────────────────────

#[test]
fn regex_fuzz_no_panic() {
    let mut g = make_lcg();
    let patterns = [".", ".*", "a+", "[abc]", "^x", "y$", r"\xAB", "a?b", "[^z]+"];
    for _ in 0..50 {
        let n = ((g() & 0x3F) + 1) as usize;
        let data = rand_bytes(n, &mut g);
        let p = patterns[(g() as usize) % patterns.len()];
        let buf = HexBuffer::new(data);
        let _ = buf.search_regex(p);
    }
}

// ── ByteRun helper ───────────────────────────────────────────────────────────

#[test]
fn byte_run_end() {
    let r = ByteRun::new(0xAA, 5, 10);
    assert_eq!(r.end(), 15);
}

// ── Hex pattern fuzz ─────────────────────────────────────────────────────────

#[test]
fn hex_pattern_fuzz_no_panic() {
    let mut g = make_lcg();
    let buf = HexBuffer::new(rand_bytes(256, &mut g));
    for _ in 0..30 {
        let len = ((g() & 0x7) + 1) as usize;
        let mut s = String::new();
        for i in 0..len {
            if i > 0 { s.push(' '); }
            let r = g() & 0x3;
            if r == 0 { s.push('?'); }
            else { s.push_str(&format!("{:02X}", g() & 0xFF)); }
        }
        let _ = buf.find_hex_pattern(&s);
    }
}

// ── HexBuffer state roundtrip via serde ──────────────────────────────────────

#[test]
fn hexbuffer_serde_round_trip() {
    let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 5]);
    buf.add_bookmark(2, "mid", 0xFF);
    let j = serde_json::to_string(&buf).unwrap();
    let back: HexBuffer = serde_json::from_str(&j).unwrap();
    assert_eq!(back.data, buf.data);
    assert_eq!(back.bookmarks.len(), 1);
}

// ── Bookmark add/replace ─────────────────────────────────────────────────────

#[test]
fn add_bookmark_replaces_same_offset() {
    let mut buf = HexBuffer::new(vec![0u8; 32]);
    buf.add_bookmark(4, "first", 0x11);
    buf.add_bookmark(4, "second", 0x22);
    assert_eq!(buf.bookmarks.len(), 1);
    assert_eq!(buf.bookmarks[0].name, "second");
}

// ── Virtual address overflow safety ──────────────────────────────────────────

#[test]
fn virtual_address_saturates() {
    let mut buf = HexBuffer::new(vec![0u8; 4]);
    buf.base_address = u64::MAX - 2;
    // doesn't panic
    let _ = buf.virtual_address(0);
    let _ = buf.virtual_address(100);
}

#[test]
fn offset_for_va_below_base_returns_none() {
    let mut buf = HexBuffer::new(vec![0u8; 16]);
    buf.base_address = 0x1000;
    assert!(buf.offset_for_va(0x500).is_none());
    assert_eq!(buf.offset_for_va(0x1004), Some(4));
    assert!(buf.offset_for_va(0x2000).is_none());
}

// ── Annotations overlap query ────────────────────────────────────────────────

#[test]
fn annotations_overlapping_query() {
    let mut buf = HexBuffer::new(vec![0u8; 64]);
    buf.add_annotation(DataAnnotation::new(0, 8, "a", DataType::U64Le));
    buf.add_annotation(DataAnnotation::new(8, 4, "b", DataType::U32Le));
    let overlap = buf.annotations_overlapping(4, 6);
    assert_eq!(overlap.len(), 2);
    let overlap = buf.annotations_overlapping(20, 4);
    assert!(overlap.is_empty());
}

// ── TypedValue Display ───────────────────────────────────────────────────────

#[test]
fn typed_value_display_formats() {
    assert_eq!(format!("{}", TypedValue::U8(0x42)), "66");
    assert_eq!(format!("{}", TypedValue::Str("x".into())), "x");
    let s = format!("{}", TypedValue::Bytes(vec![0xAB, 0xCD]));
    assert!(s.contains("AB") && s.contains("CD"));
}

// ── HexBuffer set_cursor_file_offset ─────────────────────────────────────────

#[test]
fn set_cursor_file_offset_oob_errors() {
    let mut buf = HexBuffer::new(vec![0u8; 4]);
    assert!(buf.set_cursor_file_offset(rustre_core::address::FileOffset(100)).is_err());
    assert!(buf.set_cursor_file_offset(rustre_core::address::FileOffset(3)).is_ok());
    assert_eq!(buf.cursor, 3);
}

// ── statistics_range bounds ──────────────────────────────────────────────────

#[test]
fn statistics_range_bounds_errors() {
    let buf = HexBuffer::new(vec![1, 2, 3, 4]);
    assert!(buf.statistics_range(10..20).is_err());
    assert!(buf.statistics_range(3..2).is_err());
    assert!(buf.statistics_range(0..0).is_err()); // empty -> EmptyBuffer
}

// ── histogram_range bounds ──────────────────────────────────────────────────

#[test]
fn histogram_range_invalid() {
    let buf = HexBuffer::new(vec![1, 2, 3]);
    assert!(buf.histogram_range(0..10).is_err());
}

// ── read_padded edges ────────────────────────────────────────────────────────

#[test]
fn read_padded_past_end_all_zeros() {
    let buf = HexBuffer::new(vec![1, 2]);
    let v = buf.read_padded(100, 4);
    assert_eq!(v, vec![0, 0, 0, 0]);
}

// ── Replace with longer / shorter sequences ──────────────────────────────────

#[test]
fn replace_all_shorter_replacement() {
    let mut buf = HexBuffer::new(vec![1, 2, 3, 4, 1, 2, 3, 4]);
    let count = buf.replace_all(&[1, 2, 3, 4], &[0xFF], &FindReplaceOptions::default()).unwrap();
    assert_eq!(count, 2);
    assert_eq!(buf.data, vec![0xFF, 0xFF]);
}

#[test]
fn replace_all_longer_replacement() {
    let mut buf = HexBuffer::new(vec![1, 2, 1, 2]);
    let count = buf.replace_all(&[1, 2], &[9, 9, 9], &FindReplaceOptions::default()).unwrap();
    assert_eq!(count, 2);
    assert_eq!(buf.data, vec![9, 9, 9, 9, 9, 9]);
}
