//! Exhaustive integration test suite for `rustre-hex`.
//! Tests target public APIs in lib.rs and hex_editor_core.rs.

use rustre_hex::*;
use rustre_hex::hex_editor_core::{
    ByteInserter, ClipboardOps, EditBuffer, EditCommand, EditorError, FindReplaceEngine,
    HexEditorCore, RedoHistory, SelectionRange, UndoHistory,
};

// ── HexBuffer basics ────────────────────────────────────────────────────────

#[test]
fn hexbuffer_new_zero_len() {
    let b = HexBuffer::new(vec![]);
    assert_eq!(b.len(), 0);
    assert!(b.is_empty());
}

#[test]
fn hexbuffer_zeroed() {
    let b = HexBuffer::zeroed(16);
    assert_eq!(b.len(), 16);
    assert!(b.data.iter().all(|&x| x == 0));
}

#[test]
fn hexbuffer_read_in_bounds() {
    let b = HexBuffer::new(vec![1, 2, 3, 4]);
    assert_eq!(b.read(1, 2).unwrap(), &[2, 3]);
}

#[test]
fn hexbuffer_read_truncates_at_end() {
    let b = HexBuffer::new(vec![1, 2, 3]);
    // Asks for 10 bytes starting at 1 → returns what's available.
    assert_eq!(b.read(1, 10).unwrap(), &[2, 3]);
}

#[test]
fn hexbuffer_read_offset_at_len_returns_empty() {
    let b = HexBuffer::new(vec![1, 2, 3]);
    assert_eq!(b.read(3, 5).unwrap(), &[] as &[u8]);
}

#[test]
fn hexbuffer_read_offset_past_end_errors() {
    let b = HexBuffer::new(vec![1, 2, 3]);
    assert!(matches!(b.read(4, 1), Err(HexError::OutOfBounds(_, _))));
}

#[test]
fn hexbuffer_write_overwrite() {
    let mut b = HexBuffer::new(vec![0, 0, 0, 0]);
    b.write(1, &[0xAA, 0xBB]).unwrap();
    assert_eq!(b.data, vec![0, 0xAA, 0xBB, 0]);
}

#[test]
fn hexbuffer_write_past_end_errors() {
    let mut b = HexBuffer::new(vec![1, 2, 3]);
    assert!(b.write(2, &[1, 2, 3]).is_err());
}

#[test]
fn hexbuffer_insert_then_undo() {
    let mut b = HexBuffer::new(vec![1, 2, 3]);
    b.insert(1, &[9, 9]).unwrap();
    assert_eq!(b.data, vec![1, 9, 9, 2, 3]);
    assert!(b.undo());
    assert_eq!(b.data, vec![1, 2, 3]);
    assert!(b.redo());
    assert_eq!(b.data, vec![1, 9, 9, 2, 3]);
}

#[test]
fn hexbuffer_delete_works() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4, 5]);
    b.delete(1, 2).unwrap();
    assert_eq!(b.data, vec![1, 4, 5]);
}

#[test]
fn hexbuffer_undo_empty_returns_false() {
    let mut b = HexBuffer::new(vec![1]);
    assert!(!b.undo());
}

#[test]
fn hexbuffer_redo_after_new_edit_is_cleared() {
    let mut b = HexBuffer::new(vec![1, 2, 3]);
    b.write(0, &[9]).unwrap();
    b.undo();
    b.write(0, &[8]).unwrap(); // should clear redo
    assert!(!b.redo());
}

// ── Block operations ─────────────────────────────────────────────────────────

#[test]
fn hexbuffer_fill_pattern() {
    let mut b = HexBuffer::new(vec![0u8; 5]);
    b.fill(0..5, &[0xAA, 0xBB]).unwrap();
    assert_eq!(b.data, vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA]);
}

#[test]
fn hexbuffer_fill_empty_pattern_errors() {
    let mut b = HexBuffer::new(vec![0u8; 4]);
    assert!(matches!(b.fill(0..4, &[]), Err(HexError::EmptyBuffer)));
}

#[test]
fn hexbuffer_fill_invalid_range_errors() {
    let mut b = HexBuffer::new(vec![0u8; 4]);
    assert!(matches!(b.fill(2..1, &[1]), Err(HexError::InvalidRange(_, _))));
    assert!(matches!(b.fill(0..10, &[1]), Err(HexError::InvalidRange(_, _))));
}

#[test]
fn hexbuffer_reverse_range() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.reverse_range(0..4).unwrap();
    assert_eq!(b.data, vec![4, 3, 2, 1]);
}

#[test]
fn hexbuffer_reverse_len_lt_2_is_noop() {
    let mut b = HexBuffer::new(vec![1, 2]);
    b.reverse_range(1..1).unwrap();
    assert_eq!(b.data, vec![1, 2]);
}

#[test]
fn hexbuffer_shift_left() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.shift_left(0..4, 1, 0xFF).unwrap();
    assert_eq!(b.data, vec![2, 3, 4, 0xFF]);
}

#[test]
fn hexbuffer_shift_right() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.shift_right(0..4, 1, 0xFF).unwrap();
    assert_eq!(b.data, vec![0xFF, 1, 2, 3]);
}

#[test]
fn hexbuffer_shift_amount_ge_len_clamps() {
    let mut b = HexBuffer::new(vec![1, 2, 3]);
    b.shift_left(0..3, 99, 0).unwrap();
    assert_eq!(b.data, vec![0, 0, 0]);
}

#[test]
fn hexbuffer_rotate_left() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.rotate_left(0..4, 1).unwrap();
    assert_eq!(b.data, vec![2, 3, 4, 1]);
}

#[test]
fn hexbuffer_rotate_right() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.rotate_right(0..4, 1).unwrap();
    assert_eq!(b.data, vec![4, 1, 2, 3]);
}

#[test]
fn hexbuffer_rotate_full_cycle() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    b.rotate_left(0..4, 4).unwrap();
    assert_eq!(b.data, vec![1, 2, 3, 4]);
}

// ── Bitwise ─────────────────────────────────────────────────────────────────

#[test]
fn hexbuffer_xor_repeating_key() {
    let mut b = HexBuffer::new(vec![0xFF; 4]);
    b.xor_range(0..4, &[0x0F]).unwrap();
    assert_eq!(b.data, vec![0xF0; 4]);
}

#[test]
fn hexbuffer_xor_self_inverse() {
    let mut b = HexBuffer::new(vec![1, 2, 3, 4]);
    let orig = b.data.clone();
    b.xor_range(0..4, &[0xAB, 0xCD]).unwrap();
    b.xor_range(0..4, &[0xAB, 0xCD]).unwrap();
    assert_eq!(b.data, orig);
}

#[test]
fn hexbuffer_xor_empty_key_errors() {
    let mut b = HexBuffer::new(vec![1, 2]);
    assert!(matches!(b.xor_range(0..2, &[]), Err(HexError::EmptyBuffer)));
}

#[test]
fn hexbuffer_and_range() {
    let mut b = HexBuffer::new(vec![0xFF; 2]);
    b.and_range(0..2, &[0x0F]).unwrap();
    assert_eq!(b.data, vec![0x0F, 0x0F]);
}

#[test]
fn hexbuffer_or_range() {
    let mut b = HexBuffer::new(vec![0x00; 2]);
    b.or_range(0..2, &[0xA5]).unwrap();
    assert_eq!(b.data, vec![0xA5, 0xA5]);
}

#[test]
fn hexbuffer_not_range() {
    let mut b = HexBuffer::new(vec![0x00, 0xFF]);
    b.not_range(0..2).unwrap();
    assert_eq!(b.data, vec![0xFF, 0x00]);
}

#[test]
fn hexbuffer_add_range_wraps() {
    let mut b = HexBuffer::new(vec![0xFE, 0x01]);
    b.add_range(0..2, 3).unwrap();
    assert_eq!(b.data, vec![0x01, 0x04]);
}

#[test]
fn hexbuffer_negate_range() {
    let mut b = HexBuffer::new(vec![1, 2, 0]);
    b.negate_range(0..3).unwrap();
    assert_eq!(b.data, vec![0xFFu8.wrapping_add(1).wrapping_sub(1), 254, 0]);
    // (-1, -2, 0) as u8
    assert_eq!(b.data, vec![255, 254, 0]);
}

// ── Typed reads ─────────────────────────────────────────────────────────────

#[test]
fn read_typed_u16le_be() {
    let b = HexBuffer::new(vec![0x34, 0x12]);
    assert_eq!(b.read_typed(0, DataType::U16Le).unwrap(), TypedValue::U16(0x1234));
    assert_eq!(b.read_typed(0, DataType::U16Be).unwrap(), TypedValue::U16(0x3412));
}

#[test]
fn read_typed_u32le() {
    let b = HexBuffer::new(vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(b.read_typed(0, DataType::U32Le).unwrap(), TypedValue::U32(0x12345678));
}

#[test]
fn read_typed_i8_negative() {
    let b = HexBuffer::new(vec![0xFF]);
    assert_eq!(b.read_typed(0, DataType::I8).unwrap(), TypedValue::I8(-1));
}

#[test]
fn read_typed_f32() {
    let b = HexBuffer::new(1.0f32.to_le_bytes().to_vec());
    match b.read_typed(0, DataType::F32Le).unwrap() {
        TypedValue::F32(v) => assert_eq!(v, 1.0),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn read_typed_cstr() {
    let b = HexBuffer::new(b"hello\0world".to_vec());
    match b.read_typed(0, DataType::CStr).unwrap() {
        TypedValue::Str(s) => assert_eq!(s, "hello"),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn read_typed_cstr_no_terminator_reads_all() {
    let b = HexBuffer::new(b"abc".to_vec());
    match b.read_typed(0, DataType::CStr).unwrap() {
        TypedValue::Str(s) => assert_eq!(s, "abc"),
        _ => panic!(),
    }
}

#[test]
fn read_typed_oob_errors() {
    let b = HexBuffer::new(vec![1]);
    assert!(b.read_typed(0, DataType::U32Le).is_err());
}

#[test]
fn read_typed_bytes() {
    let b = HexBuffer::new(vec![1, 2, 3, 4]);
    assert_eq!(
        b.read_typed(1, DataType::Bytes(2)).unwrap(),
        TypedValue::Bytes(vec![2, 3])
    );
}

#[test]
fn datatype_fixed_size_matrix() {
    assert_eq!(DataType::U8.fixed_size(), Some(1));
    assert_eq!(DataType::U32Le.fixed_size(), Some(4));
    assert_eq!(DataType::F64Be.fixed_size(), Some(8));
    assert_eq!(DataType::Bytes(7).fixed_size(), Some(7));
    assert_eq!(DataType::Utf16(5).fixed_size(), Some(10));
    assert_eq!(DataType::CStr.fixed_size(), None);
}

// ── KMP search ──────────────────────────────────────────────────────────────

#[test]
fn kmp_search_basic() {
    assert_eq!(kmp_search(b"abcabcabc", b"abc"), vec![0, 3, 6]);
}

#[test]
fn kmp_search_overlapping() {
    assert_eq!(kmp_search(b"aaaaa", b"aa"), vec![0, 1, 2, 3]);
}

#[test]
fn kmp_search_not_found() {
    assert_eq!(kmp_search(b"abc", b"xyz"), Vec::<usize>::new());
}

#[test]
fn hexbuffer_search_empty_pattern_returns_empty() {
    // HexBuffer::search special-cases empty pattern → empty Vec
    let b = HexBuffer::new(vec![1, 2, 3]);
    assert_eq!(b.search(&[]), Vec::<usize>::new());
}

#[test]
fn hexbuffer_search_pattern_longer_than_data() {
    let b = HexBuffer::new(vec![1, 2]);
    assert_eq!(b.search(&[1, 2, 3]), Vec::<usize>::new());
}

// ── Hex pattern with wildcards ──────────────────────────────────────────────

#[test]
fn find_hex_pattern_basic() {
    let b = HexBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(b.find_hex_pattern("DE AD BE EF").unwrap(), vec![0]);
}

#[test]
fn find_hex_pattern_wildcards() {
    let b = HexBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(b.find_hex_pattern("DE ?? BE EF").unwrap(), vec![0]);
    assert_eq!(b.find_hex_pattern("DE ? BE EF").unwrap(), vec![0]);
}

#[test]
fn find_hex_pattern_bad_token() {
    let b = HexBuffer::new(vec![0xDE]);
    assert!(b.find_hex_pattern("ZZ").is_err());
}

#[test]
fn find_hex_pattern_empty_input() {
    let b = HexBuffer::new(vec![0xDE]);
    assert_eq!(b.find_hex_pattern("").unwrap(), Vec::<usize>::new());
}

// ── Statistics / Histogram ──────────────────────────────────────────────────

#[test]
fn statistics_empty_errors() {
    let b = HexBuffer::new(vec![]);
    assert!(matches!(b.statistics(), Err(HexError::EmptyBuffer)));
}

#[test]
fn statistics_uniform() {
    let s = ByteStatistics::compute(&[5, 5, 5, 5]).unwrap();
    assert_eq!(s.min, 5);
    assert_eq!(s.max, 5);
    assert_eq!(s.mean, 5.0);
    assert_eq!(s.unique_count, 1);
    assert_eq!(s.mode, 5);
    assert_eq!(s.mode_count, 4);
    assert_eq!(s.entropy, 0.0);
}

#[test]
fn statistics_two_byte_entropy_is_one() {
    let s = ByteStatistics::compute(&[0, 1]).unwrap();
    assert!((s.entropy - 1.0).abs() < 1e-9);
}

#[test]
fn histogram_total() {
    let h = Histogram::compute(&[1, 1, 2, 3]);
    assert_eq!(h.total, 4);
    assert_eq!(h.counts[1], 2);
    assert_eq!(h.counts[2], 1);
}

#[test]
fn histogram_frequency_empty_returns_zero() {
    let h = Histogram::compute(&[]);
    assert_eq!(h.frequency(0), 0.0);
}

#[test]
fn histogram_top_n() {
    let h = Histogram::compute(&[1, 1, 1, 2, 2, 3]);
    let top = h.top_n(2);
    assert_eq!(top[0], (1, 3));
    assert_eq!(top[1], (2, 2));
}

// ── Entropy ─────────────────────────────────────────────────────────────────

#[test]
fn entropy_empty_or_zero_block() {
    assert!(entropy(&[], 4).is_empty());
    assert!(entropy(&[1, 2, 3], 0).is_empty());
}

#[test]
fn entropy_uniform_block_is_zero() {
    let e = entropy(&[7, 7, 7, 7], 4);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0], 0.0);
}

// ── Diff ────────────────────────────────────────────────────────────────────

#[test]
fn hexdiff_no_difference() {
    let a = HexBuffer::new(vec![1, 2, 3]);
    let b = HexBuffer::new(vec![1, 2, 3]);
    assert!(HexDiff::compare(&a, &b).is_empty());
}

#[test]
fn hexdiff_single_region() {
    let regs = HexDiff::compare_slices(&[1, 2, 3, 4], &[1, 9, 9, 4]);
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].offset, 1);
    assert_eq!(regs[0].len, 2);
}

#[test]
fn hexdiff_unequal_length() {
    let regs = HexDiff::compare_slices(&[1, 2], &[1, 2, 3]);
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].right, vec![3]);
}

#[test]
fn hexdiff_apply_patch() {
    let mut left = HexBuffer::new(vec![1, 2, 3, 4]);
    let right = HexBuffer::new(vec![1, 9, 9, 4]);
    let regs = HexDiff::compare(&left, &right);
    HexDiff::apply_patch(&mut left, &regs[0]).unwrap();
    assert_eq!(left.data, right.data);
}

// ── Hex string conversion ───────────────────────────────────────────────────

#[test]
fn bytes_to_hex_round_trip() {
    let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let s = bytes_to_hex_string(&bytes);
    assert_eq!(s, "DEADBEEF");
    assert_eq!(hex_string_to_bytes(&s).unwrap(), bytes);
}

#[test]
fn hex_string_to_bytes_spaces_ok() {
    assert_eq!(
        hex_string_to_bytes("DE AD BE EF").unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
}

#[test]
fn hex_string_odd_length_errors() {
    assert!(hex_string_to_bytes("ABC").is_err());
}

#[test]
fn hex_string_invalid_chars_errors() {
    assert!(hex_string_to_bytes("ZZ").is_err());
}

#[test]
fn decode_cstr_stops_at_null() {
    assert_eq!(decode_cstr(b"abc\0def"), "abc");
}

#[test]
fn decode_cstr_no_null_returns_all() {
    assert_eq!(decode_cstr(b"abc"), "abc");
}

#[test]
fn decode_utf16le_basic() {
    let data = vec![b'A', 0, b'B', 0];
    assert_eq!(decode_utf16le(&data).unwrap(), "AB");
}

#[test]
fn decode_utf16le_odd_length_errors() {
    assert!(decode_utf16le(&[1, 2, 3]).is_err());
}

#[test]
fn decode_utf16le_stops_at_null() {
    let data = vec![b'A', 0, 0, 0, b'B', 0];
    assert_eq!(decode_utf16le(&data).unwrap(), "A");
}

// ── Checksums ───────────────────────────────────────────────────────────────

#[test]
fn crc32_known_value() {
    // "123456789" → 0xCBF43926
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn crc16_ccitt_known() {
    // CRC-16/CCITT-FALSE of "123456789" = 0x29B1
    assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
}

#[test]
fn crc16_ibm_zero_for_empty() {
    assert_eq!(crc16_ibm(&[]), 0);
}

#[test]
fn adler32_empty_is_one() {
    assert_eq!(adler32(&[]), 1);
}

#[test]
fn fnv1a32_empty_is_seed() {
    assert_eq!(fnv1a32(&[]), 0x811c_9dc5);
}

#[test]
fn fnv1a64_empty_is_seed() {
    assert_eq!(fnv1a64(&[]), 0xcbf2_9ce4_8422_2325);
}

// ── Chunks ──────────────────────────────────────────────────────────────────

#[test]
fn chunk_bytes_normal() {
    let c = chunk_bytes(&[1, 2, 3, 4, 5], 2);
    assert_eq!(c.len(), 3);
    assert_eq!(c[0].offset, 0);
    assert_eq!(c[2].data, vec![5]);
}

#[test]
fn chunk_bytes_zero_or_empty() {
    assert!(chunk_bytes(&[1, 2], 0).is_empty());
    assert!(chunk_bytes(&[], 2).is_empty());
}

// ── Strings ─────────────────────────────────────────────────────────────────

#[test]
fn extract_strings_min_len_filter() {
    let data = b"\x00ab\x00hello world\x00";
    let s = extract_strings(data, 5);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].value, "hello world");
}

#[test]
fn extract_strings_run_to_end() {
    let data = b"abcdef";
    let s = extract_strings(data, 3);
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].value, "abcdef");
}

// ── Render hex lines ────────────────────────────────────────────────────────

#[test]
fn render_hex_lines_basic() {
    let lines = render_hex_lines(&[1, 2, 3, 4], 4);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].offset, 0);
    assert_eq!(lines[0].bytes, vec![1, 2, 3, 4]);
}

#[test]
fn render_hex_lines_width_zero_returns_empty() {
    assert!(render_hex_lines(&[1, 2], 0).is_empty());
}

#[test]
fn hexline_render_contains_address() {
    let l = HexLine::new(0x10, vec![0xAB], 4);
    let s = l.render();
    assert!(s.contains("00000010"));
    assert!(s.contains("AB"));
}

// ── Bookmarks ───────────────────────────────────────────────────────────────

#[test]
fn bookmark_add_remove_nearest() {
    let mut b = HexBuffer::new(vec![0u8; 100]);
    b.add_bookmark(10, "a", 0xFF);
    b.add_bookmark(80, "b", 0xFF);
    assert_eq!(b.bookmarks.len(), 2);
    assert_eq!(b.nearest_bookmark(15).unwrap().offset, 10);
    assert_eq!(b.nearest_bookmark(70).unwrap().offset, 80);
    assert!(b.remove_bookmark(10));
    assert!(!b.remove_bookmark(10));
}

#[test]
fn bookmark_dedup_replaces() {
    let mut b = HexBuffer::new(vec![0u8; 10]);
    b.add_bookmark(0, "a", 1);
    b.add_bookmark(0, "b", 2);
    assert_eq!(b.bookmarks.len(), 1);
    assert_eq!(b.bookmarks[0].name, "b");
}

// ── Annotations ─────────────────────────────────────────────────────────────

#[test]
fn annotation_overlap() {
    let mut b = HexBuffer::new(vec![0u8; 32]);
    b.add_annotation(DataAnnotation::new(0, 4, "x", DataType::U32Le));
    b.add_annotation(DataAnnotation::new(10, 4, "y", DataType::U32Le));
    let ov = b.annotations_overlapping(2, 5);
    assert_eq!(ov.len(), 1);
}

// ── MultiCursorState ────────────────────────────────────────────────────────

#[test]
fn multi_cursor_default() {
    let mc = MultiCursorState::new();
    assert_eq!(mc.count(), 1);
}

#[test]
fn multi_cursor_add_dedup() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(5);
    mc.add_cursor(5);
    assert_eq!(mc.count(), 2);
}

#[test]
fn multi_cursor_move_all_clamps() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(5);
    mc.move_all(-100, 100);
    for c in mc.cursors() {
        assert_eq!(c.offset, 0);
    }
    mc.move_all(200, 100);
    for c in mc.cursors() {
        assert_eq!(c.offset, 100);
    }
}

#[test]
fn multi_cursor_remove_oob_errors() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(2);
    assert!(mc.remove_cursor(99).is_err());
}

#[test]
fn multi_cursor_remove_last_is_noop() {
    let mut mc = MultiCursorState::new();
    // Only 1 cursor; remove returns Ok and keeps it.
    assert!(mc.remove_cursor(0).is_ok());
    assert_eq!(mc.count(), 1);
}

#[test]
fn multi_cursor_collapse() {
    let mut mc = MultiCursorState::new();
    mc.add_cursor(5);
    mc.add_cursor(9);
    mc.collapse();
    assert_eq!(mc.count(), 1);
}

// ── HexRegion / HexRegionMap ────────────────────────────────────────────────

#[test]
fn region_overlap_predicates() {
    let a = HexRegion::new("a", 0, 10);
    let b = HexRegion::new("b", 5, 15);
    let c = HexRegion::new("c", 10, 20);
    assert!(a.overlaps(&b));
    assert!(!a.overlaps(&c));
    assert!(a.contains(0));
    assert!(!a.contains(10));
}

#[test]
fn region_map_overlapping_pairs() {
    let mut m = HexRegionMap::new();
    m.add(HexRegion::new("a", 0, 10));
    m.add(HexRegion::new("b", 5, 15));
    m.add(HexRegion::new("c", 100, 110));
    let pairs = m.overlapping_pairs();
    assert_eq!(pairs.len(), 1);
}

// ── ByteClass ───────────────────────────────────────────────────────────────

#[test]
fn byte_class_categories() {
    assert_eq!(ByteClass::of(0), ByteClass::Null);
    assert_eq!(ByteClass::of(0x10), ByteClass::ControlAscii);
    assert_eq!(ByteClass::of(0x41), ByteClass::PrintableAscii);
    assert_eq!(ByteClass::of(0x7F), ByteClass::ControlAscii);
    assert_eq!(ByteClass::of(0xFF), ByteClass::HighByte);
}

#[test]
fn printable_and_null_count() {
    let data = b"ab\0c\xFF";
    assert_eq!(printable_count(data), 3);
    assert_eq!(null_count(data), 1);
}

// ── RLE ─────────────────────────────────────────────────────────────────────

#[test]
fn rle_basic() {
    let runs = run_length_encode(&[1, 1, 1, 2, 3, 3]);
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0], ByteRun::new(1, 0, 3));
    assert_eq!(runs[1], ByteRun::new(2, 3, 1));
    assert_eq!(runs[2], ByteRun::new(3, 4, 2));
}

#[test]
fn rle_empty() {
    assert!(run_length_encode(&[]).is_empty());
}

#[test]
fn longest_run_basic() {
    let r = longest_run(&[1, 2, 2, 2, 3]).unwrap();
    assert_eq!(r.value, 2);
    assert_eq!(r.length, 3);
}

// ── VA / offset_for_va ──────────────────────────────────────────────────────

#[test]
fn va_offset_round_trip() {
    let mut b = HexBuffer::new(vec![0u8; 16]);
    b.base_address = 0x1000;
    assert_eq!(b.virtual_address(4), 0x1004);
    assert_eq!(b.offset_for_va(0x1004), Some(4));
    assert_eq!(b.offset_for_va(0x0FFF), None);
    assert_eq!(b.offset_for_va(0x2000), None);
}

// ── Read padded ─────────────────────────────────────────────────────────────

#[test]
fn read_padded_zero_pads_beyond_end() {
    let b = HexBuffer::new(vec![1, 2, 3]);
    assert_eq!(b.read_padded(1, 5), vec![2, 3, 0, 0, 0]);
}

#[test]
fn read_padded_far_oob_all_zero() {
    let b = HexBuffer::new(vec![1, 2]);
    assert_eq!(b.read_padded(100, 3), vec![0, 0, 0]);
}

// ── FindReplaceOptions / find_all / replace_all ─────────────────────────────

#[test]
fn find_all_exact_mode() {
    let b = HexBuffer::new(vec![0xAA, 0xBB, 0xAA, 0xBB]);
    let r = b.find_all(&[0xAA, 0xBB], &FindReplaceOptions::default()).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].offset, 0);
    assert_eq!(r[1].offset, 2);
}

#[test]
fn find_all_with_limit() {
    let b = HexBuffer::new(vec![1, 2, 1, 2, 1, 2]);
    let opts = FindReplaceOptions {
        mode: SearchMode::Exact,
        wrap: true,
        limit: Some(2..6),
    };
    let r = b.find_all(&[1, 2], &opts).unwrap();
    assert_eq!(r.len(), 2);
    assert_eq!(r[0].offset, 2);
    assert_eq!(r[1].offset, 4);
}

#[test]
fn find_all_limit_invalid_range_errors() {
    let b = HexBuffer::new(vec![1; 4]);
    let opts = FindReplaceOptions {
        mode: SearchMode::Exact,
        wrap: false,
        limit: Some(5..10),
    };
    assert!(b.find_all(&[1], &opts).is_err());
}

#[test]
fn replace_all_same_size() {
    let mut b = HexBuffer::new(vec![0xDE, 0xAD, 0xDE, 0xAD]);
    let n = b
        .replace_all(&[0xDE, 0xAD], &[0xFF, 0xFF], &FindReplaceOptions::default())
        .unwrap();
    assert_eq!(n, 2);
    assert_eq!(b.data, vec![0xFF, 0xFF, 0xFF, 0xFF]);
}

#[test]
fn replace_all_different_size_grows() {
    let mut b = HexBuffer::new(vec![1, 2, 1, 2]);
    let n = b
        .replace_all(&[1, 2], &[9, 9, 9], &FindReplaceOptions::default())
        .unwrap();
    assert_eq!(n, 2);
    assert_eq!(b.data, vec![9, 9, 9, 9, 9, 9]);
}

#[test]
fn replace_all_empty_needle_errors() {
    let mut b = HexBuffer::new(vec![1]);
    assert!(b.replace_all(&[], &[2], &FindReplaceOptions::default()).is_err());
}

// ── EditBuffer (hex_editor_core) ────────────────────────────────────────────

#[test]
fn editbuffer_undo_redo_chain() {
    let mut b = EditBuffer::new(vec![1, 2, 3]);
    b.write(0, &[9]).unwrap();
    b.write(1, &[8]).unwrap();
    b.undo().unwrap();
    b.undo().unwrap();
    assert_eq!(b.data, vec![1, 2, 3]);
    b.redo().unwrap();
    assert_eq!(b.data[0], 9);
}

#[test]
fn editbuffer_xor_inverse() {
    let mut b = EditBuffer::new(vec![0xAA; 4]);
    b.xor(0..4, &[0xFF]).unwrap();
    assert!(b.data.iter().all(|&x| x == 0x55));
    b.undo().unwrap();
    assert!(b.data.iter().all(|&x| x == 0xAA));
}

#[test]
fn editbuffer_fill_undo() {
    let mut b = EditBuffer::new(vec![1, 2, 3, 4]);
    b.fill(0..4, &[0]).unwrap();
    assert_eq!(b.data, vec![0; 4]);
    b.undo().unwrap();
    assert_eq!(b.data, vec![1, 2, 3, 4]);
}

#[test]
fn editbuffer_delete_undo() {
    let mut b = EditBuffer::new(vec![1, 2, 3, 4]);
    b.delete(1, 2).unwrap();
    assert_eq!(b.data, vec![1, 4]);
    b.undo().unwrap();
    assert_eq!(b.data, vec![1, 2, 3, 4]);
}

#[test]
fn editbuffer_insert_undo() {
    let mut b = EditBuffer::new(vec![1, 2, 3]);
    b.insert(1, &[9, 9]).unwrap();
    b.undo().unwrap();
    assert_eq!(b.data, vec![1, 2, 3]);
}

#[test]
fn editbuffer_redo_empty_errors() {
    let mut b = EditBuffer::new(vec![1]);
    assert!(matches!(b.redo(), Err(EditorError::RedoEmpty)));
}

#[test]
fn editbuffer_xor_empty_key_errors() {
    let mut b = EditBuffer::new(vec![1]);
    assert!(matches!(b.xor(0..1, &[]), Err(EditorError::EmptyBuffer)));
}

// ── UndoHistory / RedoHistory ───────────────────────────────────────────────

#[test]
fn undo_history_caps_at_max_depth() {
    let mut h = UndoHistory::new(2);
    for i in 0..5u8 {
        h.push(EditCommand::Insert { offset: 0, bytes: vec![i] });
    }
    assert_eq!(h.len(), 2);
    // Oldest dropped: last two are i=3, i=4. peek = back = i=4.
    if let Some(EditCommand::Insert { bytes, .. }) = h.peek() {
        assert_eq!(bytes, &vec![4]);
    } else {
        panic!();
    }
}

#[test]
fn undo_history_new_with_zero_clamps_to_one() {
    let mut h = UndoHistory::new(0);
    h.push(EditCommand::Insert { offset: 0, bytes: vec![1] });
    h.push(EditCommand::Insert { offset: 0, bytes: vec![2] });
    assert_eq!(h.len(), 1);
}

#[test]
fn redo_history_clear() {
    let mut r = RedoHistory::new(5);
    r.push(EditCommand::Delete { offset: 0, bytes: vec![1] });
    r.clear();
    assert!(r.is_empty());
}

// ── SelectionRange ──────────────────────────────────────────────────────────

#[test]
fn selection_range_extend_then_move() {
    let mut s = SelectionRange::new(3);
    s.extend_to(7);
    assert!(s.has_selection());
    s.move_to(2);
    assert!(!s.has_selection());
    assert_eq!(s.cursor, 2);
}

// ── ClipboardOps ────────────────────────────────────────────────────────────

#[test]
fn clipboard_paste_empty_errors() {
    let ops = ClipboardOps::new();
    let mut buf = EditBuffer::new(vec![1, 2]);
    assert!(matches!(
        ops.paste(&mut buf, 0),
        Err(EditorError::ClipboardEmpty)
    ));
}

#[test]
fn clipboard_copy_invalid_range_errors() {
    let mut ops = ClipboardOps::new();
    let buf = EditBuffer::new(vec![1, 2]);
    assert!(matches!(
        ops.copy(&buf, 3..10),
        Err(EditorError::InvalidRange(_, _))
    ));
}

// ── FindReplaceEngine ───────────────────────────────────────────────────────

#[test]
fn engine_find_all_empty_needle_errors() {
    let buf = EditBuffer::new(vec![1, 2, 3]);
    let mut eng = FindReplaceEngine::new();
    assert!(matches!(eng.find_all(&buf, &[]), Err(EditorError::NoResults)));
}

#[test]
fn engine_find_hex_pattern_wildcards() {
    let buf = EditBuffer::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let mut eng = FindReplaceEngine::new();
    let m = eng.find_hex_pattern(&buf, "DE ?? BE EF").unwrap();
    assert_eq!(m.len(), 1);
}

#[test]
fn engine_find_hex_pattern_invalid_token_errors() {
    let buf = EditBuffer::new(vec![1, 2, 3]);
    let mut eng = FindReplaceEngine::new();
    assert!(eng.find_hex_pattern(&buf, "ZZ").is_err());
}

#[test]
fn engine_find_next_prev() {
    let buf = EditBuffer::new(vec![0xAA, 0, 0xAA, 0, 0xAA]);
    let mut eng = FindReplaceEngine::new();
    assert_eq!(eng.find_next(&buf, &[0xAA], 0).unwrap().offset, 2);
    assert_eq!(eng.find_prev(&buf, &[0xAA], 4).unwrap().offset, 2);
}

#[test]
fn engine_replace_first_only() {
    let mut buf = EditBuffer::new(vec![1, 2, 1, 2]);
    let mut eng = FindReplaceEngine::new();
    let did = eng.replace_first(&mut buf, &[1, 2], &[9, 9]).unwrap();
    assert!(did);
    assert_eq!(buf.data, vec![9, 9, 1, 2]);
}

// ── ByteInserter ────────────────────────────────────────────────────────────

#[test]
fn byte_inserter_u16_endianness() {
    let mut b = EditBuffer::new(vec![]);
    ByteInserter::insert_u16_le(&mut b, 0, 0x1234).unwrap();
    assert_eq!(b.data, vec![0x34, 0x12]);

    let mut b2 = EditBuffer::new(vec![]);
    ByteInserter::insert_u16_be(&mut b2, 0, 0x1234).unwrap();
    assert_eq!(b2.data, vec![0x12, 0x34]);
}

#[test]
fn byte_inserter_u32_be() {
    let mut b = EditBuffer::new(vec![]);
    ByteInserter::insert_u32_be(&mut b, 0, 0xDEAD_BEEF).unwrap();
    assert_eq!(b.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn byte_inserter_u64_le() {
    let mut b = EditBuffer::new(vec![]);
    ByteInserter::insert_u64_le(&mut b, 0, 1).unwrap();
    assert_eq!(b.data, vec![1, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn align_up_alignment_zero_or_one_noop() {
    let mut b = EditBuffer::new(vec![1, 2, 3]);
    ByteInserter::align_up(&mut b, 3, 0).unwrap();
    ByteInserter::align_up(&mut b, 3, 1).unwrap();
    assert_eq!(b.data, vec![1, 2, 3]);
}

#[test]
fn align_up_already_aligned_noop() {
    let mut b = EditBuffer::new(vec![1, 2, 3, 4]);
    ByteInserter::align_up(&mut b, 4, 4).unwrap();
    assert_eq!(b.data.len(), 4);
}

// ── HexEditorCore ───────────────────────────────────────────────────────────

#[test]
fn editor_core_select_clamps_to_buffer() {
    let mut e = HexEditorCore::new(vec![0u8; 4]);
    e.select(2, 100);
    assert!(e.selection.has_selection());
    // end exclusive becomes 4
    assert_eq!(e.selection.end(), 4);
}

#[test]
fn editor_core_select_empty_no_selection() {
    let mut e = HexEditorCore::new(vec![0u8; 4]);
    e.select(2, 2);
    assert!(!e.selection.has_selection());
}

#[test]
fn editor_core_write_insert_mode() {
    let mut e = HexEditorCore::new(vec![1, 2, 3]);
    e.insert_mode = true;
    e.goto(1);
    e.write_at_cursor(&[9]).unwrap();
    assert_eq!(e.buffer.data, vec![1, 9, 2, 3]);
}

#[test]
fn editor_core_cut_selection() {
    let mut e = HexEditorCore::new(vec![1, 2, 3, 4, 5]);
    e.select(1, 3);
    e.cut_selection().unwrap();
    assert_eq!(e.clipboard.clipboard.get(), &[2, 3]);
}

#[test]
fn editor_core_va_offset_consistency() {
    let mut e = HexEditorCore::new(vec![0u8; 8]);
    e.base_address = 0xFF00;
    assert_eq!(e.offset_for_va(0xFF04), Some(4));
    assert_eq!(e.offset_for_va(0xFEFF), None);
}

// ── Edit command inverse round-trip (hex_editor_core) ──────────────────────

#[test]
fn edit_command_xor_inverse_preserves_offset() {
    let cmd = EditCommand::Xor {
        offset: 5,
        old: vec![0xAA, 0xBB],
        key: vec![0xFF],
    };
    if let EditCommand::Xor { offset, .. } = cmd.inverse() {
        assert_eq!(offset, 5);
    } else {
        panic!()
    }
}

#[test]
fn edit_command_fill_inverse_is_write() {
    let cmd = EditCommand::Fill {
        offset: 0,
        old: vec![1, 2],
        pattern: vec![0xAB, 0xCD],
    };
    assert!(matches!(cmd.inverse(), EditCommand::Write { .. }));
}

// ── Encoding round-trip ─────────────────────────────────────────────────────

#[test]
fn hexbuffer_serde_round_trip() {
    let mut b = HexBuffer::new(vec![1, 2, 3]);
    b.add_bookmark(0, "x", 0);
    let json = serde_json::to_string(&b).unwrap();
    let b2: HexBuffer = serde_json::from_str(&json).unwrap();
    assert_eq!(b.data, b2.data);
    assert_eq!(b.bookmarks.len(), b2.bookmarks.len());
}

// ── ByteRun end ─────────────────────────────────────────────────────────────

#[test]
fn byte_run_end() {
    let r = ByteRun::new(0, 5, 3);
    assert_eq!(r.end(), 8);
}

// ── Cursor selection_range ──────────────────────────────────────────────────

#[test]
fn cursor_selection_range_normalises() {
    let mut c = Cursor::new(10);
    c.anchor = Some(3);
    assert_eq!(c.selection_range(), Some(3..10));
    c.anchor = Some(20);
    assert_eq!(c.selection_range(), Some(10..20));
}

#[test]
fn cursor_begin_clear_selection() {
    let mut c = Cursor::new(5);
    c.begin_selection();
    assert_eq!(c.anchor, Some(5));
    c.clear_selection();
    assert_eq!(c.anchor, None);
}
