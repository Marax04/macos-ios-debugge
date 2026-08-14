//! The `DW_TAG_*` constants, pinned against the DWARF specification.
//!
//! This crate ships several parallel type-tree implementations — the module doc
//! of `dwarf_type_parser` says so outright: "each carries an independent bug
//! set and a fix applied here does not propagate".  Constant tables copied by
//! hand between them are exactly where that drift lands, and a wrong tag value
//! is silent: the decoder simply classifies a DIE as something it is not.
//!
//! The tag encodings are fixed by the DWARF standard (DWARF 5, §7.5.3, table
//! 7.3 — unchanged since DWARF 2), so the specification is the arbiter here,
//! not a majority vote among the copies.
//!
//! This test was written after `DW_TAG_SET_TYPE` was found defined as `0x11`,
//! which is `DW_TAG_compile_unit` — the value this crate's own `lib.rs`
//! assigns to `DW_TAG_COMPILE_UNIT`.

use rustre_symbols_dwarf::dwarf_type_decoder::tag;

/// Every tag encoding used by the type decoder, with its standard value.
const SPEC: &[(&str, u16)] = &[
    ("DW_TAG_array_type", 0x01),
    ("DW_TAG_class_type", 0x02),
    ("DW_TAG_enumeration_type", 0x04),
    ("DW_TAG_formal_parameter", 0x05),
    ("DW_TAG_member", 0x0D),
    ("DW_TAG_pointer_type", 0x0F),
    ("DW_TAG_reference_type", 0x10),
    ("DW_TAG_string_type", 0x12),
    ("DW_TAG_structure_type", 0x13),
    ("DW_TAG_subroutine_type", 0x15),
    ("DW_TAG_typedef", 0x16),
    ("DW_TAG_union_type", 0x17),
    ("DW_TAG_unspecified_parameters", 0x18),
    ("DW_TAG_inheritance", 0x1C),
    ("DW_TAG_ptr_to_member_type", 0x1F),
    ("DW_TAG_set_type", 0x20),
    ("DW_TAG_subrange_type", 0x21),
    ("DW_TAG_base_type", 0x24),
    ("DW_TAG_const_type", 0x26),
    ("DW_TAG_enumerator", 0x28),
    ("DW_TAG_file_type", 0x29),
    ("DW_TAG_subprogram", 0x2E),
    ("DW_TAG_template_type_parameter", 0x2F),
    ("DW_TAG_volatile_type", 0x35),
    ("DW_TAG_restrict_type", 0x37),
    ("DW_TAG_namespace", 0x39),
    ("DW_TAG_unspecified_type", 0x3B),
    ("DW_TAG_rvalue_reference_type", 0x42),
    ("DW_TAG_atomic_type", 0x47),
    ("DW_TAG_immutable_type", 0x4B),
];

/// What the decoder actually defines, in the same order.
const ACTUAL: &[(&str, u16)] = &[
    ("DW_TAG_array_type", tag::DW_TAG_ARRAY_TYPE),
    ("DW_TAG_class_type", tag::DW_TAG_CLASS_TYPE),
    ("DW_TAG_enumeration_type", tag::DW_TAG_ENUMERATION_TYPE),
    ("DW_TAG_formal_parameter", tag::DW_TAG_FORMAL_PARAMETER),
    ("DW_TAG_member", tag::DW_TAG_MEMBER),
    ("DW_TAG_pointer_type", tag::DW_TAG_POINTER_TYPE),
    ("DW_TAG_reference_type", tag::DW_TAG_REFERENCE_TYPE),
    ("DW_TAG_string_type", tag::DW_TAG_STRING_TYPE),
    ("DW_TAG_structure_type", tag::DW_TAG_STRUCTURE_TYPE),
    ("DW_TAG_subroutine_type", tag::DW_TAG_SUBROUTINE_TYPE),
    ("DW_TAG_typedef", tag::DW_TAG_TYPEDEF),
    ("DW_TAG_union_type", tag::DW_TAG_UNION_TYPE),
    ("DW_TAG_unspecified_parameters", tag::DW_TAG_UNSPECIFIED_PARAMS),
    ("DW_TAG_inheritance", tag::DW_TAG_INHERITANCE),
    ("DW_TAG_ptr_to_member_type", tag::DW_TAG_PTR_TO_MEMBER_TYPE),
    ("DW_TAG_set_type", tag::DW_TAG_SET_TYPE),
    ("DW_TAG_subrange_type", tag::DW_TAG_SUBRANGE_TYPE),
    ("DW_TAG_base_type", tag::DW_TAG_BASE_TYPE),
    ("DW_TAG_const_type", tag::DW_TAG_CONST_TYPE),
    ("DW_TAG_enumerator", tag::DW_TAG_ENUMERATOR),
    ("DW_TAG_file_type", tag::DW_TAG_FILE_TYPE),
    ("DW_TAG_subprogram", tag::DW_TAG_SUBPROGRAM),
    ("DW_TAG_template_type_parameter", tag::DW_TAG_TEMPLATE_TYPE_PARAM),
    ("DW_TAG_volatile_type", tag::DW_TAG_VOLATILE_TYPE),
    ("DW_TAG_restrict_type", tag::DW_TAG_RESTRICT_TYPE),
    ("DW_TAG_namespace", tag::DW_TAG_NAMESPACE),
    ("DW_TAG_unspecified_type", tag::DW_TAG_UNSPECIFIED_TYPE),
    ("DW_TAG_rvalue_reference_type", tag::DW_TAG_RVALUE_REF_TYPE),
    ("DW_TAG_atomic_type", tag::DW_TAG_ATOMIC_TYPE),
    ("DW_TAG_immutable_type", tag::DW_TAG_IMMUTABLE_TYPE),
];

#[test]
fn tag_constants_match_the_dwarf_specification() {
    assert_eq!(
        SPEC.len(),
        ACTUAL.len(),
        "the two tables must line up entry for entry"
    );

    for (&(spec_name, spec_value), &(actual_name, actual_value)) in SPEC.iter().zip(ACTUAL) {
        assert_eq!(spec_name, actual_name, "the two tables drifted out of order");
        assert_eq!(
            actual_value, spec_value,
            "{spec_name} is defined as {actual_value:#04x} but the DWARF \
             specification assigns it {spec_value:#04x}"
        );
    }
}

/// Two different tags cannot share an encoding.  This is what catches a value
/// copied from the wrong row: `DW_TAG_set_type` was 0x11, the encoding of
/// `DW_TAG_compile_unit`, and only a collision check makes that visible without
/// consulting the standard.
#[test]
fn no_two_tags_share_an_encoding() {
    let mut seen: Vec<(&str, u16)> = Vec::new();
    for &(name, value) in ACTUAL {
        if let Some(&(other, _)) = seen.iter().find(|&&(_, v)| v == value) {
            panic!("{name} and {other} both use encoding {value:#04x}");
        }
        seen.push((name, value));
    }
    assert_eq!(seen.len(), ACTUAL.len());
}

/// `DW_TAG_compile_unit` is 0x11 and is defined elsewhere in this crate; no
/// type tag may claim that encoding.
#[test]
fn no_type_tag_claims_the_compile_unit_encoding() {
    for &(name, value) in ACTUAL {
        assert_ne!(
            value, 0x11,
            "{name} claims 0x11, which is DW_TAG_compile_unit"
        );
    }
}
