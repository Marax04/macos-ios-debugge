//! Blitz test suite for rustre-dotnet-edit. Targets standalone APIs that do not
//! require a fully-parsed `AssemblyFile`: IL patching, encoding, resource editor,
//! optimizer passes, CIL patcher byte utilities, signature stripper, descriptors.

use rustre_dotnet::{CilInstruction, CilOperand};
use rustre_dotnet_edit::{
    EditError, IlPatch, ManagedResource, NewFieldDescriptor, NewMethodDescriptor,
    NewTypeDescriptor, SignatureStripper, encode_instructions,
};
use rustre_dotnet_edit::cil_optimizer::{
    self, CilOptimizer, OptimizationLevel, elim_dead_push_pop, fold_constants,
    inline_return_const, peephole_arithmetic, remove_nops, remove_unreachable, renumber,
    simplify_branches,
};
use rustre_dotnet_edit::cil_patcher::{cil_nop_sled, find_instruction, is_prefix_opcode, take_code_slice};
use rustre_dotnet_edit::resource_editor::{
    ResourceEditor, ResourceEntry, ResourceEntryBuilder, ResourceFlags, ResourceKind,
    ResourceSerializer,
};

// ─── helpers ──────────────────────────────────────────────────────────────────

fn ldc(off: u32, v: i32) -> CilInstruction {
    CilInstruction::with_i32(off, "ldc.i4", v)
}
fn simple(off: u32, op: &str) -> CilInstruction {
    CilInstruction::simple(off, op)
}

// ─── ManagedResource ──────────────────────────────────────────────────────────

#[test]
fn managed_resource_new_defaults_public() {
    let r = ManagedResource::new("foo", vec![1, 2, 3]);
    assert_eq!(r.name, "foo");
    assert_eq!(r.flags, 1);
    assert_eq!(r.data, vec![1, 2, 3]);
    assert!(r.is_public());
}

#[test]
fn managed_resource_private_flag() {
    let mut r = ManagedResource::new("p", vec![]);
    r.flags = 2;
    assert!(!r.is_public());
}

#[test]
fn managed_resource_empty_data() {
    let r = ManagedResource::new("e", Vec::new());
    assert_eq!(r.data.len(), 0);
    assert!(r.is_public());
}

// ─── EditError display ────────────────────────────────────────────────────────

#[test]
fn edit_error_display_variants() {
    let e = EditError::TypeNotFound("Foo".to_string());
    assert!(format!("{e}").contains("Foo"));
    let e = EditError::MethodNotFound { type_name: "T".into(), method_name: "M".into() };
    let s = format!("{e}");
    assert!(s.contains('M') && s.contains('T'));
    let e = EditError::FieldNotFound { type_name: "T".into(), field_name: "F".into() };
    assert!(format!("{e}").contains('F'));
    let e = EditError::NoMethodBody { type_name: "T".into(), method_name: "M".into() };
    assert!(format!("{e}").contains("T::M"));
    let e = EditError::InvalidIlOffset(0xABCD);
    assert!(format!("{e}").contains("ABCD"));
    let e = EditError::InvalidFlags(0xDEAD_BEEF);
    assert!(format!("{e}").contains("DEADBEEF"));
    let e = EditError::ResourceNotFound("r".into());
    assert!(format!("{e}").contains('r'));
    let e = EditError::Custom("custom".into());
    assert_eq!(format!("{e}"), "custom");
}

// ─── IlPatch ──────────────────────────────────────────────────────────────────

#[test]
fn ilpatch_replace_ok() {
    let mut v = vec![simple(0, "nop"), simple(1, "ret")];
    IlPatch::Replace { offset: 0, instruction: simple(0, "ldnull") }
        .apply(&mut v).unwrap();
    assert_eq!(v[0].opcode, "ldnull");
}

#[test]
fn ilpatch_replace_unknown_offset() {
    let mut v = vec![simple(0, "ret")];
    let err = IlPatch::Replace { offset: 5, instruction: simple(5, "nop") }
        .apply(&mut v).unwrap_err();
    assert!(err.to_string().contains("0005"));
}

#[test]
fn ilpatch_insert_before() {
    let mut v = vec![simple(0, "ret")];
    IlPatch::InsertBefore { offset: 0, instructions: vec![simple(0, "nop"), simple(0, "nop")] }
        .apply(&mut v).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].opcode, "nop");
    assert_eq!(v[1].opcode, "nop");
    assert_eq!(v[2].opcode, "ret");
}

#[test]
fn ilpatch_insert_after() {
    let mut v = vec![simple(0, "nop"), simple(1, "ret")];
    IlPatch::InsertAfter { offset: 0, instructions: vec![simple(0, "dup")] }
        .apply(&mut v).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[1].opcode, "dup");
}

#[test]
fn ilpatch_remove_ok() {
    let mut v = vec![simple(0, "nop"), simple(1, "ret")];
    IlPatch::Remove { offset: 0 }.apply(&mut v).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, "ret");
}

#[test]
fn ilpatch_remove_missing() {
    let mut v = vec![simple(0, "ret")];
    assert!(IlPatch::Remove { offset: 99 }.apply(&mut v).is_err());
}

#[test]
fn ilpatch_replace_range_removes_and_inserts() {
    let mut v = vec![simple(0, "nop"), simple(1, "nop"), simple(2, "nop"), simple(3, "ret")];
    IlPatch::ReplaceRange { start: 1, end: 3, instructions: vec![simple(1, "ldnull")] }
        .apply(&mut v).unwrap();
    let ops: Vec<_> = v.iter().map(|i| i.opcode.as_str()).collect();
    assert_eq!(ops, vec!["nop", "ldnull", "ret"]);
}

#[test]
fn ilpatch_replace_range_empty_at_end() {
    let mut v = vec![simple(0, "ret")];
    IlPatch::ReplaceRange { start: 10, end: 20, instructions: vec![simple(0, "nop")] }
        .apply(&mut v).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].opcode, "nop"); // inserted at end since no offset >= start
}

#[test]
fn ilpatch_prepend() {
    let mut v = vec![simple(0, "ret")];
    IlPatch::Prepend { instructions: vec![simple(0, "nop"), simple(0, "dup")] }
        .apply(&mut v).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].opcode, "nop");
    assert_eq!(v[1].opcode, "dup");
}

#[test]
fn ilpatch_append_before_ret() {
    let mut v = vec![simple(0, "nop"), simple(1, "ret")];
    IlPatch::Append { instructions: vec![simple(0, "dup")] }
        .apply(&mut v).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[1].opcode, "dup");
    assert_eq!(v[2].opcode, "ret");
}

#[test]
fn ilpatch_append_no_ret_goes_to_end() {
    let mut v = vec![simple(0, "nop")];
    IlPatch::Append { instructions: vec![simple(0, "ldnull")] }
        .apply(&mut v).unwrap();
    assert_eq!(v[1].opcode, "ldnull");
}

#[test]
fn ilpatch_debug_format() {
    let p = IlPatch::Remove { offset: 7 };
    let dbg = format!("{p:?}");
    assert!(dbg.contains("Remove") && dbg.contains('7'));
}

// ─── Descriptors ──────────────────────────────────────────────────────────────

#[test]
fn new_type_public_class_flags() {
    let d = NewTypeDescriptor::public_class("C", "N");
    assert_eq!(d.name, "C");
    assert_eq!(d.namespace, "N");
    assert_eq!(d.flags, 0x101);
    assert!(d.base_type_name.is_none());
    assert!(d.interfaces.is_empty());
}

#[test]
fn new_type_public_interface_flags() {
    let d = NewTypeDescriptor::public_interface("I", "N");
    assert_eq!(d.flags, 0xA1);
}

#[test]
fn new_method_static_void_body() {
    let d = NewMethodDescriptor::static_void("M");
    assert_eq!(d.name, "M");
    assert_eq!(d.flags & 0x0010, 0x0010, "static bit must be set");
    let body = d.body.as_ref().unwrap();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0].opcode, "ret");
}

#[test]
fn new_method_instance_void_calling_conv() {
    let d = NewMethodDescriptor::instance_void("M");
    let sig = d.encode_sig();
    // first byte 0x20 = HASTHIS for instance
    assert_eq!(sig[0], 0x20, "instance method should have HASTHIS bit");
    assert_eq!(sig[1], 0, "no params");
    assert_eq!(sig[2], 0x01, "void return");
}

#[test]
fn new_method_static_sig_calling_conv() {
    let d = NewMethodDescriptor::static_void("M");
    let sig = d.encode_sig();
    assert_eq!(sig[0], 0x00, "static method should have no HASTHIS bit");
}

#[test]
fn new_method_encode_sig_with_params() {
    let mut d = NewMethodDescriptor::static_void("M");
    d.param_types = vec![vec![0x08], vec![0x0A]]; // I4, I8
    let sig = d.encode_sig();
    assert_eq!(sig[1], 2, "param count");
    // return + 2 params follow
    assert!(sig.windows(1).any(|w| w == [0x08]));
    assert!(sig.windows(1).any(|w| w == [0x0A]));
}

#[test]
fn new_field_public_field() {
    let f = NewFieldDescriptor::public_field("x", 0x08);
    assert_eq!(f.flags, 0x0006);
    assert_eq!(f.type_sig, vec![0x06, 0x08]);
}

#[test]
fn new_field_public_static() {
    let f = NewFieldDescriptor::public_static("x", 0x09);
    assert_eq!(f.flags & 0x0010, 0x0010);
    assert_eq!(f.type_sig, vec![0x06, 0x09]);
}

// ─── encode_instructions ──────────────────────────────────────────────────────

#[test]
fn encode_tiny_header_single_ret() {
    let bytes = encode_instructions(&[simple(0, "ret")]);
    assert_eq!(bytes.len(), 2);
    // tiny header: (code_size << 2) | 0x02
    assert_eq!(bytes[0], (1u8 << 2) | 0x02);
    assert_eq!(bytes[1], 0x2A);
}

#[test]
fn encode_unknown_opcode_emits_nop() {
    let bytes = encode_instructions(&[simple(0, "definitely_not_an_opcode"), simple(1, "ret")]);
    // last byte ret; second-to-last nop (0x00)
    let n = bytes.len();
    assert_eq!(bytes[n - 1], 0x2A);
    assert_eq!(bytes[n - 2], 0x00);
}

#[test]
fn encode_ldc_i4_payload() {
    let instr = CilInstruction::with_i32(0, "ldc.i4", 0x1234_5678);
    let bytes = encode_instructions(&[instr, simple(5, "ret")]);
    // header(1) + 0x20 + 4 bytes + 0x2A = 7
    assert_eq!(bytes.len(), 7);
    assert_eq!(bytes[1], 0x20);
    let val = i32::from_le_bytes(bytes[2..6].try_into().unwrap());
    assert_eq!(val, 0x1234_5678);
}

#[test]
fn encode_fat_header_when_body_large() {
    // Produce 70 ret bytes
    let mut instrs: Vec<CilInstruction> = Vec::new();
    for i in 0..70u32 {
        instrs.push(simple(i, "ret"));
    }
    let bytes = encode_instructions(&instrs);
    // fat header is 12 bytes, then body
    assert_eq!(bytes.len(), 12 + 70);
    let flags = u16::from_le_bytes([bytes[0], bytes[1]]);
    assert_eq!(flags, 0x3003);
    let code_size = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    assert_eq!(code_size, 70);
}

#[test]
fn encode_branch_short_relative_offset() {
    // br.s with target = 2 (the offset just after the 2-byte instruction starting at 0)
    let instr = CilInstruction::branch(0, "br.s", 2);
    let bytes = encode_instructions(&[instr]);
    // header(1) + 0x2B + delta
    assert_eq!(bytes[1], 0x2B);
    // delta = 2 - 2 = 0
    assert_eq!(bytes[2] as i8, 0);
}

// ─── cil_optimizer ────────────────────────────────────────────────────────────

#[test]
fn opt_remove_nops_counts() {
    let mut v = vec![simple(0, "nop"), simple(1, "nop"), simple(2, "ret")];
    assert_eq!(remove_nops(&mut v), 2);
    assert_eq!(v.len(), 1);
}

#[test]
fn opt_fold_constants_add() {
    let mut v = vec![ldc(0, 5), ldc(1, 7), simple(2, "add"), simple(3, "ret")];
    let n = fold_constants(&mut v);
    assert_eq!(n, 1);
    assert_eq!(v.len(), 2);
    if let CilOperand::Int32(x) = v[0].operand { assert_eq!(x, 12); } else { panic!() }
}

#[test]
fn opt_fold_constants_overflow_skips() {
    let mut v = vec![ldc(0, i32::MAX), ldc(1, 1), simple(2, "add"), simple(3, "ret")];
    let n = fold_constants(&mut v);
    assert_eq!(n, 0, "checked_add overflow should not fold");
    assert_eq!(v.len(), 4);
}

#[test]
fn opt_fold_constants_bitops() {
    let mut v = vec![ldc(0, 0b1100), ldc(1, 0b1010), simple(2, "and"), simple(3, "ret")];
    let _ = fold_constants(&mut v);
    if let CilOperand::Int32(x) = v[0].operand { assert_eq!(x, 0b1000); } else { panic!() }
}

#[test]
fn opt_elim_dead_push_pop() {
    let mut v = vec![simple(0, "dup"), simple(1, "pop"), simple(2, "ret")];
    assert_eq!(elim_dead_push_pop(&mut v), 1);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].opcode, "ret");
}

#[test]
fn opt_simplify_branches_branch_to_next() {
    let mut v = vec![
        CilInstruction::branch(0, "br", 5),
        simple(5, "ret"),
    ];
    let n = simplify_branches(&mut v);
    assert_eq!(n, 1);
    assert_eq!(v.len(), 1);
}

#[test]
fn opt_remove_unreachable_after_ret() {
    let mut v = vec![simple(0, "ret"), simple(1, "nop"), simple(2, "nop")];
    let n = remove_unreachable(&mut v);
    assert_eq!(n, 2);
    assert_eq!(v.len(), 1);
}

#[test]
fn opt_remove_unreachable_none() {
    let mut v = vec![simple(0, "nop"), simple(1, "ret")];
    let n = remove_unreachable(&mut v);
    assert_eq!(n, 0);
}

#[test]
fn opt_peephole_add_zero_removed() {
    let mut v = vec![ldc(0, 0), simple(1, "add"), simple(2, "ret")];
    let n = peephole_arithmetic(&mut v);
    assert_eq!(n, 1);
    assert_eq!(v.len(), 1);
}

#[test]
fn opt_peephole_mul_one_removed() {
    let mut v = vec![ldc(0, 1), simple(1, "mul"), simple(2, "ret")];
    let n = peephole_arithmetic(&mut v);
    assert_eq!(n, 1);
}

#[test]
fn opt_inline_return_const_detected() {
    let mut v = vec![ldc(0, 42), simple(1, "ret")];
    assert_eq!(inline_return_const(&mut v), 1);
}

#[test]
fn opt_inline_return_const_short() {
    let mut v = vec![simple(0, "ret")];
    assert_eq!(inline_return_const(&mut v), 0);
}

#[test]
fn opt_renumber_sequential() {
    let mut v = vec![simple(10, "nop"), simple(99, "ret")];
    renumber(&mut v);
    assert_eq!(v[0].offset, 0);
    assert_eq!(v[1].offset, 1);
}

#[test]
fn opt_cil_optimizer_default_runs() {
    let opt = CilOptimizer::new(OptimizationLevel::Moderate);
    let mut v = vec![simple(0, "nop"), ldc(1, 1), ldc(2, 2), simple(3, "add"), simple(4, "ret")];
    let result = opt.optimize(&mut v);
    assert!(result.original_count >= result.optimized_count);
    let _ = cil_optimizer::CilOptimizer::new(OptimizationLevel::None);
}

#[test]
fn opt_cil_optimizer_passes_accessor() {
    let opt = CilOptimizer::new(OptimizationLevel::Aggressive);
    assert!(!opt.passes().is_empty());
}

// ─── cil_patcher utility fns ──────────────────────────────────────────────────

#[test]
fn cil_patcher_nop_sled_size() {
    assert_eq!(cil_nop_sled(0).len(), 0);
    let s = cil_nop_sled(16);
    assert!(s.iter().all(|&b| b == 0));
    assert_eq!(s.len(), 16);
}

#[test]
fn cil_patcher_find_instruction_all_offsets() {
    let code = vec![0x00, 0x16, 0x00, 0x2A, 0x00];
    let nops = find_instruction(&code, 0x00);
    assert_eq!(nops, vec![0, 2, 4]);
    let none = find_instruction(&code, 0xFF);
    assert!(none.is_empty());
}

#[test]
fn cil_patcher_take_code_slice_truncates() {
    let code = vec![1u8, 2, 3, 4, 5];
    assert_eq!(take_code_slice(&code, 3), vec![1, 2, 3]);
    assert_eq!(take_code_slice(&code, 99), code);
    assert_eq!(take_code_slice(&code, 0), Vec::<u8>::new());
}

#[test]
fn cil_patcher_is_prefix_opcode() {
    assert!(is_prefix_opcode(0xFE));
    assert!(!is_prefix_opcode(0x00));
    assert!(!is_prefix_opcode(0xFF));
}

// ─── SignatureStripper ────────────────────────────────────────────────────────

#[test]
fn sig_stripper_too_small() {
    let mut data = vec![0u8; 10];
    assert!(SignatureStripper::strip(&mut data).is_err());
}

#[test]
fn sig_stripper_garbage_pe_offset_oor() {
    let mut data = vec![0u8; 0x40];
    // PE offset says 0xFFFFFFFF -> out of range
    data[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let res = SignatureStripper::strip(&mut data);
    assert!(res.is_err());
}

#[test]
fn sig_stripper_unknown_magic() {
    // Build a minimal buffer: MZ at 0, PE offset at 0x3C points to 0x80.
    // Need at least 0x80 + 24 (COFF) + opt header bytes.
    let mut data = vec![0u8; 0x200];
    let pe_off = 0x80usize;
    data[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    // opt header size at pe_off + 20 (2 bytes): set to 96
    data[pe_off + 20..pe_off + 22].copy_from_slice(&96u16.to_le_bytes());
    // opt magic at pe_off+24 — bogus
    data[pe_off + 24..pe_off + 26].copy_from_slice(&0xBEEFu16.to_le_bytes());
    let err = SignatureStripper::strip(&mut data).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("magic"));
}

// ─── resource_editor ──────────────────────────────────────────────────────────

#[test]
fn re_entry_embedded_public_defaults() {
    let e = ResourceEntry::embedded("r", vec![1, 2]);
    assert_eq!(e.name, "r");
    assert_eq!(e.flags, ResourceFlags::Public);
    assert_eq!(e.kind, ResourceKind::Embedded);
    assert!(!e.dirty);
    assert_eq!(e.data_size(), 2);
}

#[test]
fn re_entry_private_constructor() {
    let e = ResourceEntry::embedded_private("r", vec![]);
    assert_eq!(e.flags, ResourceFlags::Private);
}

#[test]
fn re_entry_linked_has_file() {
    let e = ResourceEntry::linked("r", "file.bin");
    assert_eq!(e.kind, ResourceKind::Linked);
    assert_eq!(e.linked_file.as_deref(), Some("file.bin"));
    assert!(e.data.is_empty());
}

#[test]
fn re_entry_length_prefixed_roundtrip() {
    let e = ResourceEntry::embedded("x", vec![10, 20, 30]);
    let blob = e.to_length_prefixed_blob();
    let back = ResourceEntry::from_length_prefixed_blob("x", &blob).unwrap();
    assert_eq!(back.data, vec![10, 20, 30]);
}

#[test]
fn re_entry_length_prefixed_too_short() {
    let res = ResourceEntry::from_length_prefixed_blob("x", &[0u8, 0]);
    assert!(res.is_err());
}

#[test]
fn re_entry_length_prefixed_truncated() {
    // Length says 100 but only 2 bytes follow.
    let mut blob = 100u32.to_le_bytes().to_vec();
    blob.extend_from_slice(&[1, 2]);
    assert!(ResourceEntry::from_length_prefixed_blob("x", &blob).is_err());
}

#[test]
fn re_entry_mime_detection() {
    assert_eq!(ResourceEntry::embedded("a", b"\x89PNG\r\n\x1a\n".to_vec()).detect_mime(), "image/png");
    assert_eq!(ResourceEntry::embedded("a", b"\xff\xd8\xff\xe0".to_vec()).detect_mime(), "image/jpeg");
    assert_eq!(ResourceEntry::embedded("a", b"PK\x03\x04xxx".to_vec()).detect_mime(), "application/zip");
    assert_eq!(ResourceEntry::embedded("a", b"GIF89a".to_vec()).detect_mime(), "image/gif");
    assert_eq!(ResourceEntry::embedded("a", b"BMfoo".to_vec()).detect_mime(), "image/bmp");
    let mut wav = b"RIFF\0\0\0\0WAVEfmt ".to_vec();
    wav.truncate(16);
    assert_eq!(ResourceEntry::embedded("a", wav).detect_mime(), "audio/wav");
    assert_eq!(ResourceEntry::embedded("a", b"<?xml v=1?>".to_vec()).detect_mime(), "text/xml");
    assert_eq!(ResourceEntry::embedded("a", vec![]).detect_mime(), "application/octet-stream");
    assert_eq!(ResourceEntry::embedded("a", vec![0xCA, 0xFE]).detect_mime(), "application/octet-stream");
}

#[test]
fn re_entry_adler32_known() {
    // Adler-32 of "Wikipedia" = 0x11E60398
    let e = ResourceEntry::embedded("a", b"Wikipedia".to_vec());
    assert_eq!(e.checksum_adler32(), 0x11E6_0398);
}

#[test]
fn re_entry_adler32_empty_is_one() {
    let e = ResourceEntry::embedded("a", vec![]);
    assert_eq!(e.checksum_adler32(), 1);
}

#[test]
fn re_serializer_roundtrip() {
    let v = vec![
        ResourceEntry::embedded("a", vec![1, 2, 3]),
        ResourceEntry::embedded_private("b", vec![]),
        ResourceEntry::embedded("c", (0..255u8).collect()),
    ];
    let bytes = ResourceSerializer::serialize(&v);
    let back = ResourceSerializer::deserialize(&bytes).unwrap();
    assert_eq!(back.len(), v.len());
    assert_eq!(back[0].name, "a");
    assert_eq!(back[0].data, vec![1, 2, 3]);
    assert_eq!(back[1].flags, ResourceFlags::Private);
    assert_eq!(back[2].data.len(), 255);
}

#[test]
fn re_serializer_empty() {
    let bytes = ResourceSerializer::serialize(&[]);
    assert_eq!(bytes, 0u32.to_le_bytes().to_vec());
    let back = ResourceSerializer::deserialize(&bytes).unwrap();
    assert!(back.is_empty());
}

#[test]
fn re_serializer_truncated_inputs() {
    assert!(ResourceSerializer::deserialize(&[]).is_err());
    assert!(ResourceSerializer::deserialize(&[0u8; 3]).is_err());
    // Claims 1 entry then nothing else.
    let bad = 1u32.to_le_bytes().to_vec();
    assert!(ResourceSerializer::deserialize(&bad).is_err());
}

#[test]
fn re_editor_basic_crud() {
    let mut ed = ResourceEditor::new();
    assert!(ed.is_empty());
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.add(ResourceEntry::embedded("b", vec![2, 3])).unwrap();
    assert_eq!(ed.len(), 2);
    assert!(ed.contains("a"));
    assert_eq!(ed.total_data_size(), 3);
    let names = ed.names();
    assert!(names.contains(&"a") && names.contains(&"b"));
    assert!(ed.has_changes());
}

#[test]
fn re_editor_add_duplicate_errors() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![])).unwrap();
    assert!(ed.add(ResourceEntry::embedded("a", vec![])).is_err());
}

#[test]
fn re_editor_remove_missing_errors() {
    let mut ed = ResourceEditor::new();
    assert!(ed.remove("nope").is_err());
}

#[test]
fn re_editor_remove_rebuilds_name_map() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.add(ResourceEntry::embedded("b", vec![2])).unwrap();
    ed.add(ResourceEntry::embedded("c", vec![3])).unwrap();
    ed.remove("a").unwrap();
    // After removal the remaining lookups must work.
    assert_eq!(ed.get("b").unwrap().data, vec![2]);
    assert_eq!(ed.get("c").unwrap().data, vec![3]);
    assert!(!ed.contains("a"));
}

#[test]
fn re_editor_replace_updates_data_and_marks_dirty() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.replace("a", vec![9, 9, 9]).unwrap();
    let r = ed.get("a").unwrap();
    assert_eq!(r.data, vec![9, 9, 9]);
    assert!(r.dirty);
}

#[test]
fn re_editor_replace_missing_errors() {
    let mut ed = ResourceEditor::new();
    assert!(ed.replace("x", vec![]).is_err());
}

#[test]
fn re_editor_rename_ok() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.rename("a", "b").unwrap();
    assert!(ed.contains("b") && !ed.contains("a"));
}

#[test]
fn re_editor_rename_conflict_errors() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![])).unwrap();
    ed.add(ResourceEntry::embedded("b", vec![])).unwrap();
    assert!(ed.rename("a", "b").is_err());
}

#[test]
fn re_editor_set_flags() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![])).unwrap();
    ed.set_flags("a", ResourceFlags::Private).unwrap();
    assert_eq!(ed.get("a").unwrap().flags, ResourceFlags::Private);
}

#[test]
fn re_editor_sort_by_name_keeps_lookup() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("c", vec![3])).unwrap();
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.add(ResourceEntry::embedded("b", vec![2])).unwrap();
    ed.sort_by_name();
    assert_eq!(ed.entries()[0].name, "a");
    assert_eq!(ed.get("c").unwrap().data, vec![3]);
}

#[test]
fn re_editor_retain_predicate() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("keep", vec![1])).unwrap();
    ed.add(ResourceEntry::embedded("drop", vec![2])).unwrap();
    ed.retain(|r| r.name == "keep");
    assert!(ed.contains("keep") && !ed.contains("drop"));
}

#[test]
fn re_editor_find_by_magic() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("p", b"\x89PNG\r\n\x1a\n".to_vec())).unwrap();
    ed.add(ResourceEntry::embedded("q", b"plaintext".to_vec())).unwrap();
    let pngs = ed.find_by_magic(b"\x89PNG");
    assert_eq!(pngs.len(), 1);
    assert_eq!(pngs[0].name, "p");
}

#[test]
fn re_editor_find_by_mime() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("p", b"\x89PNG\r\n\x1a\n".to_vec())).unwrap();
    ed.add(ResourceEntry::embedded("o", b"random".to_vec())).unwrap();
    let pngs = ed.find_by_mime("image/png");
    assert_eq!(pngs.len(), 1);
}

#[test]
fn re_editor_to_bytes_roundtrip() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("r1", vec![1, 2, 3])).unwrap();
    ed.add(ResourceEntry::embedded_private("r2", vec![9])).unwrap();
    let bytes = ed.to_bytes();
    let ed2 = ResourceEditor::from_bytes(&bytes).unwrap();
    assert_eq!(ed2.len(), 2);
    assert_eq!(ed2.get("r1").unwrap().data, vec![1, 2, 3]);
    assert_eq!(ed2.get("r2").unwrap().flags, ResourceFlags::Private);
}

#[test]
fn re_editor_clear_dirty() {
    let mut ed = ResourceEditor::new();
    ed.add(ResourceEntry::embedded("a", vec![1])).unwrap();
    ed.replace("a", vec![2]).unwrap();
    assert!(ed.has_changes());
    ed.clear_dirty();
    assert!(!ed.has_changes());
    assert!(!ed.get("a").unwrap().dirty);
}

#[test]
fn re_builder_default_public_embedded() {
    let e = ResourceEntryBuilder::new("x").data(vec![1, 2]).build();
    assert_eq!(e.flags, ResourceFlags::Public);
    assert_eq!(e.kind, ResourceKind::Embedded);
    assert_eq!(e.data, vec![1, 2]);
}

#[test]
fn re_builder_private_and_linked() {
    let e = ResourceEntryBuilder::new("x").private().linked("f.bin").build();
    assert_eq!(e.flags, ResourceFlags::Private);
    assert_eq!(e.kind, ResourceKind::Linked);
    assert_eq!(e.linked_file.as_deref(), Some("f.bin"));
}

#[test]
fn re_flags_bits() {
    assert_eq!(ResourceFlags::Public.bits(), 1);
    assert_eq!(ResourceFlags::Private.bits(), 2);
}

#[test]
fn re_kind_implementation_tag() {
    assert_eq!(ResourceKind::Embedded.implementation_tag(), 0);
    assert_eq!(ResourceKind::Linked.implementation_tag(), 0);
    assert_eq!(ResourceKind::Assembly.implementation_tag(), 1);
}
