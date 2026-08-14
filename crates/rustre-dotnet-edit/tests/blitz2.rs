//! Deep adversarial test suite for rustre-dotnet-edit.
//!
//! Focuses on the IL patch engine, descriptor builders, `ManagedResource`,
//! `SignatureStripper`, instruction encoder, and `EditTransaction` state.

use rustre_dotnet::{CilInstruction, CilOperand};
use rustre_dotnet_edit::{
    EditError, EditTransaction, IlPatch, ManagedResource, Modification, NewFieldDescriptor,
    NewMethodDescriptor, NewTypeDescriptor, SignatureStripper, encode_instructions,
};
use std::collections::HashSet;

// ───── seeded LCG ─────────────────────────────────────────────────────────────

struct Lcg(u64);
impl Lcg {
    const fn new() -> Self {
        Self(0xDEAD_BEEF_CAFE_BABE)
    }
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    const fn u32(&mut self) -> u32 {
        (self.next() >> 32) as u32
    }
    const fn u8(&mut self) -> u8 {
        self.next() as u8
    }
}

// helper: produce a base sequence of instructions at sequential offsets
fn base_instrs() -> Vec<CilInstruction> {
    vec![
        CilInstruction::simple(0x00, "nop"),
        CilInstruction::simple(0x01, "ldc.i4.0"),
        CilInstruction::simple(0x02, "ldc.i4.1"),
        CilInstruction::simple(0x03, "add"),
        CilInstruction::simple(0x04, "ret"),
    ]
}

// ───── IlPatch tests ──────────────────────────────────────────────────────────

#[test]
fn ilpatch_replace_at_existing_offset() {
    let mut v = base_instrs();
    IlPatch::Replace {
        offset: 0x02,
        instruction: CilInstruction::simple(0x02, "ldc.i4.7"),
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v[2].opcode, "ldc.i4.7");
    assert_eq!(v.len(), 5);
}

#[test]
fn ilpatch_replace_unknown_offset_errors() {
    let mut v = base_instrs();
    let r = IlPatch::Replace {
        offset: 0xDEAD,
        instruction: CilInstruction::simple(0, "nop"),
    }
    .apply(&mut v);
    assert!(r.is_err());
    assert_eq!(v.len(), 5);
}

#[test]
fn ilpatch_insert_before_grows_list() {
    let mut v = base_instrs();
    IlPatch::InsertBefore {
        offset: 0x03,
        instructions: vec![
            CilInstruction::simple(0xAA, "nop"),
            CilInstruction::simple(0xAB, "nop"),
        ],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.len(), 7);
    // base_instrs: [nop@0, ldc.i4.0@1, ldc.i4.1@2, add@3, ret@4]
    // InsertBefore offset=0x03 inserts at position 3 (where add was)
    assert_eq!(v[3].offset, 0xAA);
    assert_eq!(v[4].offset, 0xAB);
    assert_eq!(v[5].opcode, "add");
}

#[test]
fn ilpatch_insert_before_missing_offset_errors() {
    let mut v = base_instrs();
    let r = IlPatch::InsertBefore {
        offset: 0xFFFF,
        instructions: vec![CilInstruction::simple(0, "nop")],
    }
    .apply(&mut v);
    assert!(r.is_err());
}

#[test]
fn ilpatch_insert_after_places_after_target() {
    let mut v = base_instrs();
    IlPatch::InsertAfter {
        offset: 0x00,
        instructions: vec![CilInstruction::simple(0x99, "nop")],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v[1].offset, 0x99);
}

#[test]
fn ilpatch_insert_after_missing_offset_errors() {
    let mut v = base_instrs();
    let r = IlPatch::InsertAfter {
        offset: 0xFFFF,
        instructions: vec![],
    }
    .apply(&mut v);
    assert!(r.is_err());
}

#[test]
fn ilpatch_remove_at_offset() {
    let mut v = base_instrs();
    IlPatch::Remove { offset: 0x02 }.apply(&mut v).unwrap();
    assert_eq!(v.len(), 4);
    assert!(!v.iter().any(|i| i.offset == 0x02));
}

#[test]
fn ilpatch_remove_missing_offset_errors() {
    let mut v = base_instrs();
    let r = IlPatch::Remove { offset: 0xFFFF }.apply(&mut v);
    assert!(r.is_err());
}

#[test]
fn ilpatch_replace_range_drops_and_inserts() {
    let mut v = base_instrs();
    IlPatch::ReplaceRange {
        start: 0x01,
        end: 0x04,
        instructions: vec![CilInstruction::simple(0xC0, "nop")],
    }
    .apply(&mut v)
    .unwrap();
    // nop at 0x00, our nop at 0xC0, then ret at 0x04
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].offset, 0x00);
    assert_eq!(v[1].offset, 0xC0);
    assert_eq!(v[2].opcode, "ret");
}

#[test]
fn ilpatch_replace_range_empty_range_is_pure_insert() {
    let mut v = base_instrs();
    IlPatch::ReplaceRange {
        start: 0x02,
        end: 0x02,
        instructions: vec![CilInstruction::simple(0xC0, "nop")],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.len(), 6);
}

#[test]
fn ilpatch_prepend_to_empty() {
    let mut v: Vec<CilInstruction> = vec![];
    IlPatch::Prepend {
        instructions: vec![CilInstruction::simple(0, "nop")],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn ilpatch_prepend_to_nonempty() {
    let mut v = base_instrs();
    IlPatch::Prepend {
        instructions: vec![
            CilInstruction::simple(0xF0, "nop"),
            CilInstruction::simple(0xF1, "nop"),
        ],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v[0].offset, 0xF0);
    assert_eq!(v[1].offset, 0xF1);
    assert_eq!(v[2].opcode, "nop"); // original 0x00 nop
}

#[test]
fn ilpatch_append_inserts_before_final_ret() {
    let mut v = base_instrs();
    IlPatch::Append {
        instructions: vec![CilInstruction::simple(0xEE, "pop")],
    }
    .apply(&mut v)
    .unwrap();
    let last = v.last().unwrap();
    assert_eq!(last.opcode, "ret");
    assert_eq!(v[v.len() - 2].opcode, "pop");
}

#[test]
fn ilpatch_append_without_ret_appends_at_end() {
    let mut v = vec![CilInstruction::simple(0, "nop")];
    IlPatch::Append {
        instructions: vec![CilInstruction::simple(0xEE, "pop")],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.last().unwrap().opcode, "pop");
}

#[test]
fn ilpatch_round_trip_replace_inverse() {
    // Replacing twice with the original restores the original opcode.
    let original = base_instrs();
    let mut v = original.clone();
    IlPatch::Replace {
        offset: 0x03,
        instruction: CilInstruction::simple(0x03, "sub"),
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v[3].opcode, "sub");
    IlPatch::Replace {
        offset: 0x03,
        instruction: CilInstruction::simple(0x03, "add"),
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v[3].opcode, original[3].opcode);
}

#[test]
fn ilpatch_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..200 {
        let mut v = base_instrs();
        let kind = g.u8() % 7;
        let off = g.u32();
        let patch = match kind {
            0 => IlPatch::Replace {
                offset: off,
                instruction: CilInstruction::simple(off, "nop"),
            },
            1 => IlPatch::InsertBefore {
                offset: off,
                instructions: vec![CilInstruction::simple(0, "nop")],
            },
            2 => IlPatch::InsertAfter {
                offset: off,
                instructions: vec![CilInstruction::simple(0, "nop")],
            },
            3 => IlPatch::Remove { offset: off },
            4 => IlPatch::ReplaceRange {
                start: off,
                end: off.wrapping_add(g.u32() & 0xFF),
                instructions: vec![],
            },
            5 => IlPatch::Prepend {
                instructions: vec![CilInstruction::simple(0, "nop")],
            },
            _ => IlPatch::Append {
                instructions: vec![CilInstruction::simple(0, "nop")],
            },
        };
        let _ = patch.apply(&mut v); // must not panic
    }
}

// ───── ManagedResource ───────────────────────────────────────────────────────

#[test]
fn managed_resource_new_defaults_public() {
    let r = ManagedResource::new("foo", vec![1, 2, 3]);
    assert_eq!(r.name, "foo");
    assert_eq!(r.data, vec![1, 2, 3]);
    assert_eq!(r.flags, 1);
    assert!(r.is_public());
}

#[test]
fn managed_resource_private_flag() {
    let mut r = ManagedResource::new("p", vec![]);
    r.flags = 2;
    assert!(!r.is_public());
}

#[test]
fn managed_resource_clone_preserves_fields() {
    let r = ManagedResource::new("x", vec![9, 8]);
    let c = r.clone();
    assert_eq!(c.name, r.name);
    assert_eq!(c.data, r.data);
    assert_eq!(c.flags, r.flags);
}

// ───── NewTypeDescriptor / NewMethodDescriptor / NewFieldDescriptor ──────────

#[test]
fn new_type_public_class_has_expected_flags() {
    let t = NewTypeDescriptor::public_class("C", "N");
    assert_eq!(t.name, "C");
    assert_eq!(t.namespace, "N");
    assert_eq!(t.flags, 0x101);
    assert!(t.base_type_name.is_none());
    assert!(t.interfaces.is_empty());
}

#[test]
fn new_type_public_interface_has_expected_flags() {
    let t = NewTypeDescriptor::public_interface("I", "N");
    assert_eq!(t.flags, 0xA1);
}

#[test]
fn new_method_static_void_returns_void_sig() {
    let m = NewMethodDescriptor::static_void("M");
    assert_eq!(m.return_type_sig, vec![0x01]);
    // static flag bit 0x0010 set
    assert!(m.flags & 0x0010 != 0);
    let sig = m.encode_sig();
    // calling conv=0 (static), param_count=0, then return type 0x01
    assert_eq!(sig, vec![0x00, 0x00, 0x01]);
}

#[test]
fn new_method_instance_void_calling_conv_has_this() {
    let m = NewMethodDescriptor::instance_void("M");
    let sig = m.encode_sig();
    assert_eq!(sig[0], 0x20); // HASTHIS
    assert_eq!(sig[1], 0); // 0 params
}

#[test]
fn new_method_encode_sig_with_params() {
    let mut m = NewMethodDescriptor::static_void("M");
    m.param_types = vec![vec![0x08], vec![0x0E]]; // int32, string
    let sig = m.encode_sig();
    assert_eq!(sig[0], 0x00); // static
    assert_eq!(sig[1], 2); // param count
    assert_eq!(sig[2], 0x01); // return void
    assert_eq!(sig[3], 0x08);
    assert_eq!(sig[4], 0x0E);
}

#[test]
fn new_method_encode_sig_caps_param_count_at_255() {
    let mut m = NewMethodDescriptor::static_void("M");
    m.param_types = (0..300).map(|_| vec![0x08]).collect();
    let sig = m.encode_sig();
    assert_eq!(sig[1], 255);
}

#[test]
fn new_field_public_field_flags() {
    let f = NewFieldDescriptor::public_field("x", 0x08);
    assert_eq!(f.flags, 0x0006);
    assert_eq!(f.type_sig, vec![0x06, 0x08]);
}

#[test]
fn new_field_public_static_flags() {
    let f = NewFieldDescriptor::public_static("x", 0x08);
    assert_eq!(f.flags, 0x0016);
}

// ───── SignatureStripper ─────────────────────────────────────────────────────

#[test]
fn signature_stripper_rejects_too_small_buffer() {
    let mut data = vec![0u8; 8];
    let r = SignatureStripper::strip(&mut data);
    assert!(r.is_err());
}

#[test]
fn signature_stripper_rejects_bad_pe_offset() {
    let mut data = vec![0u8; 0x40];
    // Set the PE offset way past the buffer.
    data[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let r = SignatureStripper::strip(&mut data);
    assert!(r.is_err());
}

#[test]
fn signature_stripper_rejects_unknown_pe_magic() {
    // Build a buffer big enough to reach opt_start with a bogus magic.
    let mut data = vec![0u8; 0x400];
    let pe_off: u32 = 0x80;
    data[0x3C..0x40].copy_from_slice(&pe_off.to_le_bytes());
    // OptHeaderSize = 96 so we can read magic, but not enough for PE32/PE32+
    let opt_size: u16 = 200;
    let pe_off = pe_off as usize;
    data[pe_off + 20..pe_off + 22].copy_from_slice(&opt_size.to_le_bytes());
    // magic = 0xDEAD
    let opt_start = pe_off + 24;
    data[opt_start..opt_start + 2].copy_from_slice(&0xDEADu16.to_le_bytes());
    let r = SignatureStripper::strip(&mut data);
    assert!(r.is_err());
}

#[test]
fn signature_stripper_fuzz_never_panics() {
    let mut g = Lcg::new();
    for _ in 0..50 {
        let len = 0x100 + (g.u32() as usize % 0x400);
        let mut buf: Vec<u8> = (0..len).map(|_| g.u8()).collect();
        let _ = SignatureStripper::strip(&mut buf); // must not panic
    }
}

// ───── encode_instructions ───────────────────────────────────────────────────

#[test]
fn encode_empty_yields_tiny_header_zero_size() {
    let out = encode_instructions(&[]);
    // tiny: (0 << 2) | 0x02 = 0x02
    assert_eq!(out, vec![0x02]);
}

#[test]
fn encode_nop_ret_tiny_format() {
    let v = vec![
        CilInstruction::simple(0, "nop"),
        CilInstruction::simple(1, "ret"),
    ];
    let out = encode_instructions(&v);
    // header byte: ((2) << 2) | 0x02 = 0x0A
    assert_eq!(out[0], 0x0A);
    assert_eq!(out[1], 0x00);
    assert_eq!(out[2], 0x2A);
}

#[test]
fn encode_known_opcodes_have_distinct_first_bytes() {
    let pairs = [
        ("nop", 0x00u8),
        ("ret", 0x2A),
        ("ldnull", 0x14),
        ("ldc.i4.0", 0x16),
        ("ldc.i4.8", 0x1E),
        ("ldc.i4.m1", 0x15),
        ("dup", 0x25),
        ("pop", 0x26),
        ("throw", 0x7A),
        ("add", 0x58),
        ("sub", 0x59),
        ("mul", 0x5A),
        ("ldlen", 0x8E),
        ("endfinally", 0xDC),
    ];
    for (op, b) in pairs {
        let v = vec![CilInstruction::simple(0, op)];
        let out = encode_instructions(&v);
        // header is one byte
        assert_eq!(out[1], b, "opcode {op}");
    }
}

#[test]
fn encode_ldc_i4_emits_int32_le() {
    let v = vec![CilInstruction::with_i32(0, "ldc.i4", 0x1234_5678)];
    let out = encode_instructions(&v);
    // After 1-byte tiny header & 1 opcode byte
    assert_eq!(out[1], 0x20);
    assert_eq!(&out[2..6], &0x1234_5678i32.to_le_bytes());
}

#[test]
fn encode_call_emits_token() {
    let v = vec![CilInstruction::with_token(0, "call", 0x0A00_0001)];
    let out = encode_instructions(&v);
    assert_eq!(out[1], 0x28);
    assert_eq!(&out[2..6], &0x0A00_0001u32.to_le_bytes());
}

#[test]
fn encode_two_byte_prefix_opcodes() {
    let v = vec![CilInstruction::simple(0, "ceq")];
    let out = encode_instructions(&v);
    assert_eq!(out[1], 0xFE);
    assert_eq!(out[2], 0x01);
}

#[test]
fn encode_unknown_opcode_falls_back_to_nop() {
    let v = vec![CilInstruction::simple(0, "definitely_not_real")];
    let out = encode_instructions(&v);
    assert_eq!(out[1], 0x00);
}

#[test]
fn encode_fat_header_when_body_64_bytes_or_more() {
    // 64 nops gives a 64-byte body. Tiny limit is <64, so we get fat header.
    let v: Vec<_> = (0..64).map(|i| CilInstruction::simple(i, "nop")).collect();
    let out = encode_instructions(&v);
    // Fat header is 12 bytes
    assert_eq!(out.len(), 12 + 64);
    // First flags word low byte has fat bit pattern: 0x3003
    let flags = u16::from_le_bytes([out[0], out[1]]);
    assert_eq!(flags, 0x3003);
    let code_size = u32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    assert_eq!(code_size, 64);
}

#[test]
fn encode_fuzz_never_panics() {
    let mut g = Lcg::new();
    let opcodes = [
        "nop", "ret", "add", "sub", "mul", "ldnull", "dup", "pop", "throw", "ldc.i4", "call",
        "ldfld", "stfld", "br.s", "br", "switch", "box", "ldstr", "unknown_opcode",
    ];
    for _ in 0..100 {
        let n = (g.u8() % 16) as usize;
        let v: Vec<_> = (0..n)
            .map(|i| {
                let op = opcodes[(g.u8() as usize) % opcodes.len()];
                let mut instr = CilInstruction::simple(i as u32, op);
                match g.u8() % 4 {
                    0 => instr.operand = CilOperand::Int32(g.u32() as i32),
                    1 => instr.operand = CilOperand::Token(g.u32()),
                    2 => instr.operand = CilOperand::Branch(g.u32() & 0x3F),
                    _ => instr.operand = CilOperand::Switch(vec![g.u32() & 0x3F]),
                }
                instr
            })
            .collect();
        let _ = encode_instructions(&v); // must not panic
    }
}

// ───── EditError Display ─────────────────────────────────────────────────────

#[test]
fn edit_error_display_variants() {
    let s = format!("{}", EditError::TypeNotFound("X".into()));
    assert!(s.contains('X'));
    let s = format!(
        "{}",
        EditError::MethodNotFound {
            type_name: "T".into(),
            method_name: "M".into()
        }
    );
    assert!(s.contains('T') && s.contains('M'));
    let s = format!(
        "{}",
        EditError::FieldNotFound {
            type_name: "T".into(),
            field_name: "F".into()
        }
    );
    assert!(s.contains('F'));
    let s = format!(
        "{}",
        EditError::NoMethodBody {
            type_name: "T".into(),
            method_name: "M".into()
        }
    );
    assert!(s.contains('T') && s.contains('M'));
    let s = format!("{}", EditError::InvalidIlOffset(0xABCD));
    assert!(s.contains("ABCD"));
    let s = format!("{}", EditError::InvalidFlags(0xDEAD_BEEF));
    assert!(s.contains("DEADBEEF"));
    let s = format!("{}", EditError::ResourceNotFound("r".into()));
    assert!(s.contains('r'));
    let s = format!("{}", EditError::Custom("oops".into()));
    assert_eq!(s, "oops");
}

#[test]
fn edit_error_is_error_trait() {
    fn assert_err<E: std::error::Error>(_: &E) {}
    assert_err(&EditError::Custom("x".into()));
}

// ───── EditTransaction ───────────────────────────────────────────────────────

#[test]
fn edit_transaction_new_is_empty() {
    let t = EditTransaction::new();
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
}

#[test]
fn edit_transaction_add_increments_len() {
    let mut t = EditTransaction::new();
    t.add(Modification::StripStrongName);
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());
    t.add(Modification::RemoveResource { name: "r".into() });
    assert_eq!(t.len(), 2);
}

// ───── IlPatch serde round-trip ──────────────────────────────────────────────

#[test]
fn ilpatch_serde_round_trip_replace() {
    let p = IlPatch::Replace {
        offset: 0x10,
        instruction: CilInstruction::simple(0x10, "nop"),
    };
    let json = serde_json::to_string(&p).unwrap();
    let p2: IlPatch = serde_json::from_str(&json).unwrap();
    if let IlPatch::Replace { offset, .. } = p2 {
        assert_eq!(offset, 0x10);
    } else {
        panic!("variant mismatch");
    }
}

#[test]
fn ilpatch_serde_round_trip_remove() {
    let p = IlPatch::Remove { offset: 0xAB };
    let json = serde_json::to_string(&p).unwrap();
    let p2: IlPatch = serde_json::from_str(&json).unwrap();
    if let IlPatch::Remove { offset } = p2 {
        assert_eq!(offset, 0xAB);
    } else {
        panic!("variant mismatch");
    }
}

// ───── Send/Sync ─────────────────────────────────────────────────────────────

#[test]
fn descriptors_are_send_sync() {
    fn check<T: Send + Sync>() {}
    check::<NewTypeDescriptor>();
    check::<NewMethodDescriptor>();
    check::<NewFieldDescriptor>();
    check::<ManagedResource>();
    check::<IlPatch>();
    check::<Modification>();
}

#[test]
fn ilpatch_threaded_apply_independence() {
    use std::sync::Arc;
    use std::thread;
    let patch = Arc::new(IlPatch::InsertBefore {
        offset: 0x02,
        instructions: vec![CilInstruction::simple(0x99, "nop")],
    });
    let mut handles = vec![];
    for _ in 0..4 {
        let p = Arc::clone(&patch);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let mut v = base_instrs();
                p.apply(&mut v).unwrap();
                assert_eq!(v.len(), 6);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ───── Modification cloning / fields ─────────────────────────────────────────

#[test]
fn modification_clone_preserves_data() {
    let m = Modification::RenameType {
        old: "A".into(),
        new: "B".into(),
    };
    let c = m;
    if let Modification::RenameType { old, new } = c {
        assert_eq!(old, "A");
        assert_eq!(new, "B");
    } else {
        panic!();
    }
}

#[test]
fn modification_set_assembly_version_fields() {
    let m = Modification::SetAssemblyVersion {
        major: 1,
        minor: 2,
        build: 3,
        revision: 4,
    };
    if let Modification::SetAssemblyVersion {
        major,
        minor,
        build,
        revision,
    } = m
    {
        assert_eq!((major, minor, build, revision), (1, 2, 3, 4));
    } else {
        panic!();
    }
}

// ───── IL patch offset uniqueness ────────────────────────────────────────────

#[test]
fn ilpatch_replace_range_preserves_order_outside_range() {
    let mut v: Vec<_> = (0..10u32)
        .map(|i| CilInstruction::simple(i, "nop"))
        .collect();
    IlPatch::ReplaceRange {
        start: 3,
        end: 7,
        instructions: vec![CilInstruction::simple(99, "ret")],
    }
    .apply(&mut v)
    .unwrap();
    let offsets: Vec<u32> = v.iter().map(|i| i.offset).collect();
    assert_eq!(offsets, vec![0, 1, 2, 99, 7, 8, 9]);
}

#[test]
fn ilpatch_remove_all_in_loop() {
    let mut v = base_instrs();
    for off in [0x00u32, 0x01, 0x02, 0x03, 0x04] {
        IlPatch::Remove { offset: off }.apply(&mut v).unwrap();
    }
    assert!(v.is_empty());
}

#[test]
fn ilpatch_offsets_are_unique_after_inserts() {
    let mut v = base_instrs();
    IlPatch::InsertBefore {
        offset: 0x02,
        instructions: vec![CilInstruction::simple(0xAA, "nop")],
    }
    .apply(&mut v)
    .unwrap();
    let seen: HashSet<u32> = v.iter().map(|i| i.offset).collect();
    assert_eq!(seen.len(), v.len());
}

// ───── Boundary tests on integer widths ──────────────────────────────────────

#[test]
fn encode_ldc_i4_zero_and_max_and_min() {
    for val in [0i32, i32::MAX, i32::MIN, -1, 1] {
        let v = vec![CilInstruction::with_i32(0, "ldc.i4", val)];
        let out = encode_instructions(&v);
        assert_eq!(&out[2..6], &val.to_le_bytes());
    }
}

#[test]
fn new_method_descriptor_signature_with_zero_params() {
    let m = NewMethodDescriptor::static_void("M");
    let sig = m.encode_sig();
    assert_eq!(sig[1], 0);
}

#[test]
fn ilpatch_prepend_empty_instructions_is_noop() {
    let mut v = base_instrs();
    let before = v.len();
    IlPatch::Prepend {
        instructions: vec![],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.len(), before);
}

#[test]
fn ilpatch_append_empty_instructions_is_noop() {
    let mut v = base_instrs();
    let before = v.len();
    IlPatch::Append {
        instructions: vec![],
    }
    .apply(&mut v)
    .unwrap();
    assert_eq!(v.len(), before);
}
