//! Regression tests for the `pos + uleb128_len` overflow class: a length
//! encoded as (near-)`u64::MAX` must not wrap the bounds check in release
//! builds (panic on slice), nor move a cursor backwards (infinite loop).

use rustre_symbols_dwarf::dwarf_abbrev::{read_form_value, DwForm};
use rustre_symbols_dwarf::dwarf_location_expr::parse_location_expr;

/// ULEB128 encoding of `u64::MAX` (10 bytes).
const ULEB_U64_MAX: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

#[test]
fn exprloc_with_u64_max_length_returns_none() {
    let mut data = ULEB_U64_MAX.to_vec();
    data.extend_from_slice(&[0u8; 8]);
    let mut pos = 0usize;
    let v = read_form_value(&data, &mut pos, DwForm::Exprloc, 8, false, 0);
    assert!(v.is_none(), "wrapped bounds check must reject, not panic");
}

#[test]
fn block_with_u64_max_length_returns_none() {
    let mut data = ULEB_U64_MAX.to_vec();
    data.extend_from_slice(&[0u8; 8]);
    let mut pos = 0usize;
    let v = read_form_value(&data, &mut pos, DwForm::Block, 8, false, 0);
    assert!(v.is_none());
}

#[test]
fn implicit_value_with_u64_max_length_terminates() {
    // DW_OP_implicit_value (0x9e) followed by a u64::MAX ULEB length.
    let mut expr = vec![0x9E];
    expr.extend_from_slice(&ULEB_U64_MAX);
    expr.extend_from_slice(&[0u8; 4]);
    // Must terminate (Ok or Err) without panicking or looping forever.
    let _ = parse_location_expr(&expr, 8);
}

#[test]
fn entry_value_with_u64_max_length_terminates() {
    // DW_OP_entry_value (0xa3) followed by a u64::MAX ULEB length.
    let mut expr = vec![0xA3];
    expr.extend_from_slice(&ULEB_U64_MAX);
    expr.extend_from_slice(&[0u8; 4]);
    let _ = parse_location_expr(&expr, 8);
}
