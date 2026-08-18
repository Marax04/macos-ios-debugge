//! Adversarial deep tests for `rustre-mobile-smali` public API (Y103 / blitz2).
//!
//! Focus: round-trips, fuzz, boundaries, malformed inputs, threaded stress.

use std::sync::Arc;
use std::thread;

use rustre_mobile_smali::printer::{
    access_string, diff_classes, escape_string, print_class, print_field, print_instr,
    print_method, print_operand, print_reg,
};
use rustre_mobile_smali::{
    DalvikAssembler, DalvikDisassembler, DalvikOpcode, DexContext, SmaliAccess, SmaliClass,
    SmaliDisassembler, SmaliInstr, SmaliInstruction, SmaliMethod, SmaliOp,
    SmaliOperand, SmaliReg, instruction_size_bytes, opcode_to_smali, parse_method_descriptor,
    parse_type_descriptor,
};

// Truncation/conversion helpers (test-local; intentional boundaries).
#[inline] fn u16_to_u8(v: u16) -> u8 { u8::try_from(v & 0xff).unwrap_or(0) }
#[inline] fn u64_to_u8(v: u64) -> u8 { u8::try_from(v & 0xff).unwrap_or(0) }
#[inline] fn u64_to_u32(v: u64) -> u32 { u32::try_from(v & 0xffff_ffff).unwrap_or(0) }
#[inline] fn u64_to_usize(v: u64) -> usize { usize::try_from(v).unwrap_or(usize::MAX) }
#[inline] const fn u64_to_i64(v: u64) -> i64 { v.cast_signed() }
#[inline] fn u64_to_i32(v: u64) -> i32 { i32::try_from(v & 0xffff_ffff).unwrap_or(i32::MAX) }

// ─── Seeded LCG ──────────────────────────────────────────────────────────────

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── DalvikOpcode ────────────────────────────────────────────────────────────

#[test]
fn opcode_from_byte_total_no_panic() {
    for b in 0u16..=255 {
        let op = DalvikOpcode::from_byte(u16_to_u8(b));
        // round-trip on encoded byte
        assert_eq!(op.as_byte(), u16_to_u8(b), "byte {b:#x}");
    }
}

#[test]
fn opcode_from_byte_roundtrip_fuzz() {
    let mut g = lcg();
    for _ in 0..200 {
        let b = u64_to_u8(g());
        let op = DalvikOpcode::from_byte(b);
        assert_eq!(op.as_byte(), b);
    }
}

#[test]
fn opcode_to_smali_nonempty_for_all() {
    for b in 0u16..=255 {
        let op = DalvikOpcode::from_byte(u16_to_u8(b));
        let s = opcode_to_smali(op);
        assert!(!s.is_empty(), "{b:#x}");
    }
}

#[test]
fn opcode_hash_eq_consistency() {
    use std::collections::HashSet;
    let mut set: HashSet<DalvikOpcode> = HashSet::new();
    for b in 0u16..=255 {
        set.insert(DalvikOpcode::from_byte(u16_to_u8(b)));
    }
    // re-inserting same opcodes shouldn't grow the set
    let len = set.len();
    for b in 0u16..=255 {
        set.insert(DalvikOpcode::from_byte(u16_to_u8(b)));
    }
    assert_eq!(set.len(), len);
}

#[test]
fn opcode_pair_eq_consistency() {
    for b in 0u16..=255 {
        let a = DalvikOpcode::from_byte(u16_to_u8(b));
        let c = DalvikOpcode::from_byte(u16_to_u8(b));
        assert_eq!(a, c);
        assert_eq!(a as u8, c as u8);
    }
}

// ─── instruction_size_bytes ──────────────────────────────────────────────────

#[test]
fn instruction_size_always_positive_and_even() {
    for b in 0u16..=255 {
        let op = DalvikOpcode::from_byte(u16_to_u8(b));
        let sz = instruction_size_bytes(op);
        assert!(sz >= 2, "size {sz} for {b:#x}");
        assert!(sz.is_multiple_of(2), "odd size {sz} for {b:#x}");
        assert!(sz <= 10);
    }
}

#[test]
fn instruction_size_known_values() {
    assert_eq!(instruction_size_bytes(DalvikOpcode::Nop), 2);
    assert_eq!(instruction_size_bytes(DalvikOpcode::Const16), 4);
    assert_eq!(instruction_size_bytes(DalvikOpcode::Const), 6);
    assert_eq!(instruction_size_bytes(DalvikOpcode::ConstWide), 10);
    assert_eq!(instruction_size_bytes(DalvikOpcode::InvokeVirtual), 6);
}

// ─── SmaliReg ────────────────────────────────────────────────────────────────

#[test]
fn reg_display_boundary_63_64() {
    assert_eq!(SmaliReg { num: 63 }.to_string(), "v63");
    assert_eq!(SmaliReg { num: 64 }.to_string(), "p0");
}

#[test]
fn reg_display_full_range() {
    for n in 0u16..=255 {
        let r = SmaliReg { num: u16_to_u8(n) };
        let s = r.to_string();
        if n < 64 {
            assert_eq!(s, format!("v{n}"));
        } else {
            assert_eq!(s, format!("p{}", n - 64));
        }
    }
}

#[test]
fn reg_print_reg_matches_display() {
    for n in 0u16..=255 {
        let r = SmaliReg { num: u16_to_u8(n) };
        assert_eq!(print_reg(&r), r.to_string());
    }
}

#[test]
fn reg_hash_eq_consistency() {
    use std::collections::HashMap;
    let mut h: HashMap<SmaliReg, u32> = HashMap::new();
    for n in 0u16..=255 {
        h.insert(SmaliReg { num: u16_to_u8(n) }, u32::from(n));
    }
    assert_eq!(h.len(), 256);
    for n in 0u16..=255 {
        assert_eq!(h.get(&SmaliReg { num: u16_to_u8(n) }), Some(&u32::from(n)));
    }
}

// ─── SmaliOp Display ─────────────────────────────────────────────────────────

#[test]
fn smali_op_display_other_passthrough() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = g() & 0x1f;
        let name: String = (0..n).map(|_| ((g() & 0x3f) as u8 + b'a') as char).collect();
        let op = SmaliOp::Other(name.clone());
        assert_eq!(op.to_string(), name);
    }
}

#[test]
fn smali_op_known_displays() {
    let cases: &[(SmaliOp, &str)] = &[
        (SmaliOp::Nop, "nop"),
        (SmaliOp::MoveWide, "move-wide"),
        (SmaliOp::MoveObject, "move-object"),
        (SmaliOp::MoveResult, "move-result"),
        (SmaliOp::ReturnVoid, "return-void"),
        (SmaliOp::Const4, "const/4"),
        (SmaliOp::Const16, "const/16"),
        (SmaliOp::ConstString, "const-string"),
        (SmaliOp::IfEq, "if-eq"),
        (SmaliOp::IfNez, "if-nez"),
        (SmaliOp::IGet, "iget"),
        (SmaliOp::IPut, "iput"),
        (SmaliOp::SGet, "sget"),
        (SmaliOp::SPut, "sput"),
        (SmaliOp::InvokeVirtual, "invoke-virtual"),
        (SmaliOp::InvokeSuper, "invoke-super"),
        (SmaliOp::InvokeDirect, "invoke-direct"),
        (SmaliOp::InvokeStatic, "invoke-static"),
        (SmaliOp::InvokeInterface, "invoke-interface"),
        (SmaliOp::NewInstance, "new-instance"),
        (SmaliOp::ArrayLength, "array-length"),
        (SmaliOp::CheckCast, "check-cast"),
    ];
    for (op, s) in cases {
        assert_eq!(op.to_string(), *s);
    }
}

// ─── SmaliOperand display ────────────────────────────────────────────────────

#[test]
fn operand_literal_zero_positive_negative() {
    assert_eq!(SmaliOperand::Literal(0).to_string(), "0x0");
    assert_eq!(SmaliOperand::Literal(1).to_string(), "0x1");
    assert_eq!(SmaliOperand::Literal(255).to_string(), "0xff");
    assert_eq!(SmaliOperand::Literal(-1).to_string(), "-0x1");
    assert_eq!(SmaliOperand::Literal(i64::MAX).to_string(), "0x7fffffffffffffff");
    // i64::MIN special case: unsigned_abs in i128 still works
    let s = SmaliOperand::Literal(i64::MIN).to_string();
    assert!(s.starts_with("-0x"));
}

#[test]
fn operand_str_quotes_content() {
    let s = SmaliOperand::Str("hello".into()).to_string();
    assert_eq!(s, "\"hello\"");
}

#[test]
fn operand_print_operand_roundtrip() {
    let ops = [
        SmaliOperand::Reg(SmaliReg { num: 7 }),
        SmaliOperand::Literal(42),
        SmaliOperand::Literal(-42),
        SmaliOperand::Str("abc".into()),
        SmaliOperand::TypeRef("Ljava/lang/Object;".into()),
        SmaliOperand::FieldRef("Lfoo;->bar:I".into()),
        SmaliOperand::MethodRef("Lfoo;->m()V".into()),
    ];
    for o in &ops {
        assert_eq!(print_operand(o), o.to_string());
    }
}

// ─── SmaliInstr ──────────────────────────────────────────────────────────────

#[test]
fn instr_to_text_no_operands() {
    let i = SmaliInstr {
        op: SmaliOp::ReturnVoid,
        operands: vec![],
        label: None,
    };
    assert_eq!(i.to_text(), "return-void");
}

#[test]
fn instr_to_text_with_label() {
    let i = SmaliInstr {
        op: SmaliOp::Nop,
        operands: vec![],
        label: Some(":L0".into()),
    };
    let t = i.to_text();
    assert!(t.starts_with(":L0\n"));
    assert!(t.ends_with("nop"));
}

#[test]
fn instr_to_text_multi_operand_separators() {
    let i = SmaliInstr {
        op: SmaliOp::Move,
        operands: vec![
            SmaliOperand::Reg(SmaliReg { num: 0 }),
            SmaliOperand::Reg(SmaliReg { num: 1 }),
        ],
        label: None,
    };
    assert_eq!(i.to_text(), "move v0, v1");
}

#[test]
fn instr_print_matches_to_text() {
    let i = SmaliInstr {
        op: SmaliOp::Const4,
        operands: vec![
            SmaliOperand::Reg(SmaliReg { num: 2 }),
            SmaliOperand::Literal(5),
        ],
        label: None,
    };
    // printer adds leading "    " indent — verify it contains the textual form
    let p = print_instr(&i);
    assert!(p.contains("const/4"));
    assert!(p.contains("v2"));
    assert!(p.contains("0x5"));
}

// ─── SmaliAccess bitflags ────────────────────────────────────────────────────

#[test]
fn access_string_empty_and_combinations() {
    assert_eq!(access_string(SmaliAccess::empty()), "");
    assert_eq!(access_string(SmaliAccess::PUBLIC), "public");
    let combo = SmaliAccess::PUBLIC | SmaliAccess::STATIC | SmaliAccess::FINAL;
    assert_eq!(access_string(combo), "public static final");
}

#[test]
fn access_string_all_flags_order_deterministic() {
    let all = SmaliAccess::PUBLIC
        | SmaliAccess::PRIVATE
        | SmaliAccess::PROTECTED
        | SmaliAccess::STATIC
        | SmaliAccess::FINAL
        | SmaliAccess::ABSTRACT
        | SmaliAccess::NATIVE
        | SmaliAccess::CONSTRUCTOR;
    let s = access_string(all);
    assert_eq!(
        s,
        "public private protected static final abstract native constructor"
    );
    // re-run to confirm determinism
    assert_eq!(access_string(all), s);
}

#[test]
fn access_bitflags_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let bits = (g() & 0xff) as u32;
        let a = SmaliAccess::from_bits_truncate(bits);
        let _ = access_string(a);
        // contains check consistency
        if a.contains(SmaliAccess::PUBLIC) {
            assert!(access_string(a).contains("public"));
        }
    }
}

// ─── escape_string ───────────────────────────────────────────────────────────

#[test]
fn escape_string_basics() {
    assert_eq!(escape_string(""), "");
    assert_eq!(escape_string("abc"), "abc");
    assert_eq!(escape_string("a\"b"), "a\\\"b");
    assert_eq!(escape_string("a\\b"), "a\\\\b");
    assert_eq!(escape_string("a\nb"), "a\\nb");
    assert_eq!(escape_string("a\tb"), "a\\tb");
    assert_eq!(escape_string("a\rb"), "a\\rb");
    assert_eq!(escape_string("a\0b"), "a\\0b");
}

#[test]
fn escape_string_control_char_unicode_form() {
    let s = escape_string("\x01\x1f");
    assert!(s.contains("\\u0001"));
    assert!(s.contains("\\u001F"));
}

#[test]
fn escape_string_fuzz_no_panic_no_unescaped_quote() {
    let mut g = lcg();
    for _ in 0..100 {
        let n = (g() & 0x3f) as usize;
        let s: String = (0..n)
            .map(|_| char::from_u32((g() & 0x7f) as u32).unwrap_or('?'))
            .collect();
        let e = escape_string(&s);
        // every raw " must be escaped
        let raw_quotes = s.chars().filter(|c| *c == '"').count();
        let escaped_quotes = e.matches("\\\"").count();
        assert_eq!(raw_quotes, escaped_quotes);
    }
}

// ─── parse_type_descriptor ───────────────────────────────────────────────────

#[test]
fn parse_type_descriptor_primitives() {
    let cases = [
        ("B", "byte"), ("C", "char"), ("D", "double"), ("F", "float"),
        ("I", "int"), ("J", "long"), ("S", "short"), ("Z", "boolean"),
        ("V", "void"),
    ];
    for (d, n) in cases {
        assert_eq!(parse_type_descriptor(d), n);
    }
}

#[test]
fn parse_type_descriptor_object() {
    assert_eq!(
        parse_type_descriptor("Ljava/lang/String;"),
        "java.lang.String"
    );
    assert_eq!(parse_type_descriptor("LFoo;"), "Foo");
}

#[test]
fn parse_type_descriptor_array() {
    assert_eq!(parse_type_descriptor("[I"), "int[]");
    assert_eq!(parse_type_descriptor("[[I"), "int[][]");
    assert_eq!(
        parse_type_descriptor("[Ljava/lang/String;"),
        "java.lang.String[]"
    );
}

#[test]
fn parse_type_descriptor_empty_and_truncated() {
    assert_eq!(parse_type_descriptor(""), "void");
    // unterminated L descriptor — must not panic
    let _ = parse_type_descriptor("Ljava/lang/String");
    let _ = parse_type_descriptor("[");
    let _ = parse_type_descriptor("[[[");
}

#[test]
fn parse_type_descriptor_fuzz_no_panic() {
    let mut g = lcg();
    let alphabet = b"BCDFIJSZV[L;abcdefghijk/";
    for _ in 0..200 {
        let n = (g() & 0x1f) as usize;
        let s: String = (0..n)
            .map(|_| alphabet[(u64_to_usize(g())) % alphabet.len()] as char)
            .collect();
        let _ = parse_type_descriptor(&s);
    }
}

// ─── parse_method_descriptor ─────────────────────────────────────────────────

#[test]
fn parse_method_descriptor_basic() {
    let (p, r) = parse_method_descriptor("()V");
    assert!(p.is_empty());
    assert_eq!(r, "void");

    let (p, r) = parse_method_descriptor("(II)I");
    assert_eq!(p, vec!["int", "int"]);
    assert_eq!(r, "int");

    let (p, r) = parse_method_descriptor("(Ljava/lang/String;)V");
    assert_eq!(p, vec!["java.lang.String"]);
    assert_eq!(r, "void");
}

#[test]
fn parse_method_descriptor_empty_no_paren() {
    let (p, r) = parse_method_descriptor("");
    assert!(p.is_empty());
    assert_eq!(r, "void");

    let (p, r) = parse_method_descriptor("garbage");
    assert!(p.is_empty());
    assert_eq!(r, "void");
}

#[test]
fn parse_method_descriptor_fuzz_no_panic() {
    let mut g = lcg();
    let alphabet = b"()BIJVL;[/abcF";
    for _ in 0..200 {
        let n = (g() & 0x1f) as usize;
        let s: String = (0..n)
            .map(|_| alphabet[(u64_to_usize(g())) % alphabet.len()] as char)
            .collect();
        let _ = parse_method_descriptor(&s);
    }
}

// ─── DexContext ──────────────────────────────────────────────────────────────

#[test]
fn dex_context_lookups_in_range() {
    let ctx = DexContext {
        strings: vec!["hello".into(), "world".into()],
        types: vec!["LFoo;".into()],
        methods: vec!["m()V".into()],
        fields: vec!["f:I".into()],
    };
    assert_eq!(ctx.string(0), "hello");
    assert_eq!(ctx.string(1), "world");
    assert_eq!(ctx.type_desc(0), "LFoo;");
    assert_eq!(ctx.method(0), "m()V");
    assert_eq!(ctx.field(0), "f:I");
}

#[test]
fn dex_context_out_of_range_placeholders() {
    let ctx = DexContext::dummy();
    assert!(ctx.string(7).contains("@0x7"));
    assert!(ctx.type_desc(7).contains("@0x7"));
    assert!(ctx.method(7).contains("@0x7"));
    assert!(ctx.field(7).contains("@0x7"));
}

#[test]
fn dex_context_max_index_no_overflow() {
    let ctx = DexContext::dummy();
    let _ = ctx.string(u32::MAX);
    let _ = ctx.type_desc(u32::MAX);
    let _ = ctx.method(u32::MAX);
    let _ = ctx.field(u32::MAX);
}

// ─── SmaliDisassembler & DalvikDisassembler ──────────────────────────────────

#[test]
fn disassembler_empty_input() {
    let v = SmaliDisassembler::disassemble_bytecode(&[], 0);
    assert!(v.is_empty());
    let v2 = SmaliDisassembler::disassemble_bytecode(&[0x00], 0); // odd byte, no full unit
    assert!(v2.is_empty());
}

#[test]
fn disassembler_nop_stream() {
    // 4 NOPs = 8 bytes
    let bytes = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let v = SmaliDisassembler::disassemble_bytecode(&bytes, 0);
    assert_eq!(v.len(), 4);
    for i in &v {
        assert_eq!(i.op, DalvikOpcode::Nop);
    }
}

#[test]
fn disassembler_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let n = ((g() & 0x7f) as usize) * 2; // even length
        let bytes: Vec<u8> = (0..n).map(|_| u64_to_u8(g())).collect();
        let _ = SmaliDisassembler::disassemble_bytecode(&bytes, 0);
        let ctx = DexContext::dummy();
        let _ = DalvikDisassembler::disassemble(&bytes, &ctx);
    }
}

#[test]
fn disassembler_truncated_does_not_panic() {
    // A const-wide is 10 bytes — feed only 4
    let bytes = vec![0x18, 0x00, 0x00, 0x00];
    let _ = SmaliDisassembler::disassemble_bytecode(&bytes, 0);
}

// ─── DalvikAssembler ────────────────────────────────────────────────────────

const fn mk_instr(op: DalvikOpcode) -> SmaliInstruction {
    SmaliInstruction {
        offset: 0,
        op,
        regs: vec![],
        string_idx: None,
        type_idx: None,
        field_idx: None,
        method_idx: None,
        literal: None,
        branch_target: None,
    }
}

#[test]
fn assembler_size_matches_instruction_size() {
    for b in 0u16..=255 {
        let op = DalvikOpcode::from_byte(u16_to_u8(b));
        let bytes = DalvikAssembler::encode(&mk_instr(op));
        let expected = instruction_size_bytes(op);
        // Assembler may fall back to NOP (2 bytes) for unimplemented; that's ok.
        // But for the documented sizes, the output must be >= 2 bytes.
        assert!(bytes.len() >= 2, "op {:?} -> {} bytes", op, bytes.len());
        assert!(bytes.len() == expected || bytes.len() == 2);
    }
}

#[test]
fn assembler_nop_emits_two_zeros() {
    let bytes = DalvikAssembler::encode(&mk_instr(DalvikOpcode::Nop));
    assert_eq!(bytes, vec![0x00, 0x00]);
}

#[test]
fn assembler_return_void() {
    let bytes = DalvikAssembler::encode(&mk_instr(DalvikOpcode::ReturnVoid));
    assert_eq!(bytes, vec![0x0E, 0x00]);
}

#[test]
fn assembler_const16_encodes_literal() {
    let mut i = mk_instr(DalvikOpcode::Const16);
    i.regs = vec![3];
    i.literal = Some(0x1234);
    let bytes = DalvikAssembler::encode(&i);
    assert_eq!(bytes, vec![0x13, 0x03, 0x34, 0x12]);
}

#[test]
fn assembler_clamp_literal_overflow() {
    let mut i = mk_instr(DalvikOpcode::Const16);
    i.regs = vec![0];
    i.literal = Some(i64::MAX); // must clamp, not panic
    let bytes = DalvikAssembler::encode(&i);
    assert_eq!(bytes.len(), 4);
    // clamped to i16::MAX = 0x7fff
    assert_eq!(bytes[2], 0xff);
    assert_eq!(bytes[3], 0x7f);
}

#[test]
fn assembler_clamp_branch_overflow() {
    let mut i = mk_instr(DalvikOpcode::Goto16);
    i.branch_target = Some(i32::MIN);
    let bytes = DalvikAssembler::encode(&i);
    assert_eq!(bytes.len(), 4);
    // clamped to i16::MIN
    assert_eq!(bytes[2], 0x00);
    assert_eq!(bytes[3], 0x80);
}

#[test]
fn assembler_assemble_concatenates() {
    let v = vec![
        mk_instr(DalvikOpcode::Nop),
        mk_instr(DalvikOpcode::ReturnVoid),
        mk_instr(DalvikOpcode::Nop),
    ];
    let bytes = DalvikAssembler::assemble(&v);
    assert_eq!(bytes, vec![0x00, 0x00, 0x0E, 0x00, 0x00, 0x00]);
}

#[test]
fn assembler_fuzz_no_panic() {
    let mut g = lcg();
    for _ in 0..100 {
        let op = DalvikOpcode::from_byte(u64_to_u8(g()));
        let mut i = mk_instr(op);
        let nregs = (g() & 0x7) as usize;
        i.regs = (0..nregs).map(|_| u64_to_u8(g())).collect();
        i.literal = if g() & 1 == 0 { None } else { Some(u64_to_i64(g())) };
        i.branch_target = if g() & 1 == 0 { None } else { Some(u64_to_i32(g())) };
        i.type_idx = if g() & 1 == 0 { None } else { Some(u64_to_u32(g())) };
        i.method_idx = if g() & 1 == 0 { None } else { Some(u64_to_u32(g())) };
        i.field_idx = if g() & 1 == 0 { None } else { Some(u64_to_u32(g())) };
        i.string_idx = if g() & 1 == 0 { None } else { Some(u64_to_u32(g())) };
        let bytes = DalvikAssembler::encode(&i);
        assert!(!bytes.is_empty());
    }
}

#[test]
fn assembler_disassembler_roundtrip_nop_only() {
    // pure-NOP streams round-trip
    for n in 0..20 {
        let v: Vec<SmaliInstruction> = (0..n).map(|_| mk_instr(DalvikOpcode::Nop)).collect();
        let bytes = DalvikAssembler::assemble(&v);
        let back = SmaliDisassembler::disassemble_bytecode(&bytes, 0);
        assert_eq!(back.len(), n);
        for i in &back {
            assert_eq!(i.op, DalvikOpcode::Nop);
        }
    }
}

// ─── SmaliMethod / SmaliClass ────────────────────────────────────────────────

#[test]
fn method_is_constructor_recognizes_init_and_clinit() {
    let mut m = SmaliMethod {
        name: "<init>".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC,
        registers: 1,
        instructions: vec![],
    };
    assert!(m.is_constructor());
    assert_eq!(m.instr_count(), 0);
    m.name = "<clinit>".into();
    assert!(m.is_constructor());
    m.name = "other".into();
    assert!(!m.is_constructor());
}

#[test]
fn class_mock_invariants() {
    let c = SmaliClass::synthetic_fixture("LMy/Class;");
    assert_eq!(c.name, "LMy/Class;");
    assert_eq!(c.super_class, "Ljava/lang/Object;");
    assert!(c.find_method("<init>").is_some());
    assert!(c.find_method("execute").is_some());
    assert!(c.find_method("does_not_exist").is_none());
    let statics = c.static_methods();
    assert!(statics.iter().any(|m| m.name == "execute"));
}

#[test]
fn class_print_contains_basics() {
    let c = SmaliClass::synthetic_fixture("LFoo;");
    let txt = print_class(&c);
    assert!(txt.contains(".class"));
    assert!(txt.contains("LFoo;"));
    assert!(txt.contains(".super"));
}

#[test]
fn print_field_and_method_nonempty() {
    let c = SmaliClass::synthetic_fixture("LFoo;");
    let f = &c.fields[0];
    let m = &c.methods[0];
    assert!(!print_field(f).is_empty());
    assert!(!print_method(m).is_empty());
}

// ─── diff_classes ────────────────────────────────────────────────────────────

#[test]
fn diff_classes_identity_empty_diff() {
    let c = SmaliClass::synthetic_fixture("LFoo;");
    let d = diff_classes(&c, &c);
    assert!(d.added_methods.is_empty());
    assert!(d.removed_methods.is_empty());
    assert!(d.added_fields.is_empty());
    assert!(d.removed_fields.is_empty());
}

#[test]
fn diff_classes_detects_added_method() {
    let old = SmaliClass::synthetic_fixture("LFoo;");
    let mut new = old.clone();
    new.methods.push(SmaliMethod {
        name: "newMethod".into(),
        class: "LFoo;".into(),
        signature: "()V".into(),
        access: SmaliAccess::PUBLIC,
        registers: 0,
        instructions: vec![],
    });
    let d = diff_classes(&old, &new);
    assert!(d.added_methods.iter().any(|n| n == "newMethod"));
    assert!(d.removed_methods.is_empty());
}

#[test]
fn diff_classes_detects_removed_method() {
    let old = SmaliClass::synthetic_fixture("LFoo;");
    let mut new = old.clone();
    new.methods.retain(|m| m.name != "execute");
    let d = diff_classes(&old, &new);
    assert!(d.removed_methods.iter().any(|n| n == "execute"));
}

// ─── Serde round-trip ────────────────────────────────────────────────────────

#[test]
fn serde_smali_reg_roundtrip() {
    for n in 0u16..=255 {
        let r = SmaliReg { num: u16_to_u8(n) };
        let j = serde_json::to_string(&r).unwrap();
        let back: SmaliReg = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn serde_dalvik_opcode_roundtrip() {
    for b in 0u16..=255 {
        let op = DalvikOpcode::from_byte(u16_to_u8(b));
        let j = serde_json::to_string(&op).unwrap();
        let back: DalvikOpcode = serde_json::from_str(&j).unwrap();
        assert_eq!(op, back);
    }
}

#[test]
fn serde_class_roundtrip() {
    let c = SmaliClass::synthetic_fixture("LRoundTrip;");
    let j = serde_json::to_string(&c).unwrap();
    let back: SmaliClass = serde_json::from_str(&j).unwrap();
    assert_eq!(back.name, c.name);
    assert_eq!(back.methods.len(), c.methods.len());
    assert_eq!(back.fields.len(), c.fields.len());
}

// ─── Send/Sync threaded stress ───────────────────────────────────────────────

#[test]
fn threaded_stress_opcode_from_byte() {
    let handles: Vec<_> = (0..4u64)
        .map(|t| {
            thread::spawn(move || {
                let mut s = 0xDEAD_BEEFu64.wrapping_add(t);
                for _ in 0..100 {
                    s = s
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let op = DalvikOpcode::from_byte(u64_to_u8(s));
                    assert_eq!(op.as_byte(), u64_to_u8(s));
                    let _ = opcode_to_smali(op);
                    let _ = instruction_size_bytes(op);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_stress_class_clone_and_print() {
    let c = Arc::new(SmaliClass::synthetic_fixture("LShared;"));
    let handles: Vec<_> = (0..4u64)
        .map(|_| {
            let c = Arc::clone(&c);
            thread::spawn(move || {
                for _ in 0..100 {
                    let txt = print_class(&c);
                    assert!(txt.contains("LShared;"));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn threaded_stress_disassembler() {
    let bytes: Arc<Vec<u8>> = Arc::new((0..200u8).collect());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let bytes = Arc::clone(&bytes);
            thread::spawn(move || {
                for _ in 0..100 {
                    let v = SmaliDisassembler::disassemble_bytecode(&bytes, 0);
                    assert!(!v.is_empty());
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

// ─── SmaliError display ──────────────────────────────────────────────────────

#[test]
fn smali_error_display_messages() {
    let e = rustre_mobile_smali::SmaliError::ParseError("oops".into());
    assert!(e.to_string().contains("oops"));
    let e = rustre_mobile_smali::SmaliError::InvalidOp("bad".into());
    assert!(e.to_string().contains("bad"));
    let e = rustre_mobile_smali::SmaliError::InvalidReg(42);
    assert!(e.to_string().contains("42"));
}
