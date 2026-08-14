//! `ExportOptions::apply_offset` and `ImportOptions::apply_offset` are two
//! byte-identical copies of the same rebasing arithmetic in different modules.
//! Two copies of one computation must agree on every input, and both must be
//! total: `base_offset` is a public `i64`, and the original code computed
//! `-self.base_offset`, which **overflows for `i64::MIN`** — the one value with
//! no positive counterpart.
//!
//! These are independent knobs, not an inverse pair: both *add* a positive
//! offset, and both default to 0. A caller wanting a round trip sets the import
//! offset to the negation of the export one. That is why the test asserts
//! agreement rather than cancellation.

use rustre_symbols::symbol_exporter::ExportOptions;
use rustre_symbols::symbol_importer::ImportOptions;

/// The special values a public `i64` can hold, `i64::MIN` included.
fn offsets() -> Vec<(&'static str, i64)> {
    vec![
        ("zero", 0),
        ("plus one", 1),
        ("minus one", -1),
        ("page", 0x1000),
        ("negative page", -0x1000),
        ("max", i64::MAX),
        ("min", i64::MIN),
    ]
}

fn addresses() -> Vec<(&'static str, u64)> {
    vec![
        ("zero", 0),
        ("low", 0x1000),
        ("typical image base", 0x1_4000_0000),
        ("max", u64::MAX),
    ]
}

#[test]
fn the_two_copies_agree_on_every_offset_and_address() {
    let mut checked = 0usize;
    let mut divergences = Vec::new();

    for (olabel, offset) in offsets() {
        let export = ExportOptions {
            base_offset: offset,
            ..ExportOptions::default()
        };
        let import = ImportOptions {
            base_offset: offset,
            ..ImportOptions::default()
        };

        for (alabel, addr) in addresses() {
            let e = export.apply_offset(addr);
            let i = import.apply_offset(addr);
            if e != i {
                divergences.push(format!(
                    "offset {olabel}, address {alabel}: export gave {e:#x}, import gave {i:#x}"
                ));
            }
            checked += 1;
        }
    }

    assert_eq!(
        checked,
        offsets().len() * addresses().len(),
        "anti-vacuity: every offset/address pair must have been exercised"
    );
    assert!(divergences.is_empty(), "{}", divergences.join("\n"));
}

#[test]
fn the_most_negative_offset_shifts_by_its_true_magnitude() {
    // `-i64::MIN` does not exist. The magnitude is 2^63, and subtracting it from
    // 2^63 must land exactly on zero — an implementation that negated instead
    // would either panic or shift by the wrong amount.
    let two_pow_63: u64 = 1 << 63;

    let export = ExportOptions {
        base_offset: i64::MIN,
        ..ExportOptions::default()
    };
    let import = ImportOptions {
        base_offset: i64::MIN,
        ..ImportOptions::default()
    };

    assert_eq!(export.apply_offset(two_pow_63), 0);
    assert_eq!(import.apply_offset(two_pow_63), 0);
}

#[test]
fn an_ordinary_rebase_still_moves_the_address() {
    // Premise: the agreement above is not trivially satisfied by both copies
    // ignoring the offset entirely.
    let export = ExportOptions {
        base_offset: 0x1000,
        ..ExportOptions::default()
    };
    assert_eq!(export.apply_offset(0x2000), 0x3000);

    let back = ImportOptions {
        base_offset: -0x1000,
        ..ImportOptions::default()
    };
    assert_eq!(back.apply_offset(0x3000), 0x2000);
}
