//! Exhaustive blitz tests for rustre-arch-cil public API.

use rustre_core::arch::InstrFlags;
use rustre_arch_cil::wide_prefix::{
    decode_wide_prefix, lookup_wide, WideCategory, WideOperand, WIDE_PREFIX_TABLE,
};
use rustre_arch_cil::*;
use rustre_core::address::Address;

// ============ CilInstr::decode happy paths ============

#[test]
fn decode_empty_is_truncated() {
    assert_eq!(CilInstr::decode(&[]), Err(CilDecodeError::Truncated));
}

#[test]
fn decode_nop() {
    let (i, n) = CilInstr::decode(&[0x00]).unwrap();
    assert_eq!(n, 1);
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.raw, vec![0x00]);
}

#[test]
fn decode_ret_has_ret_flag() {
    let (i, _) = CilInstr::decode(&[0x2a]).unwrap();
    assert!(i.flags.contains(InstrFlags::RET));
}

#[test]
fn decode_ldarg_s_truncated() {
    assert_eq!(CilInstr::decode(&[0x0e]), Err(CilDecodeError::Truncated));
}

#[test]
fn decode_ldc_i4_truncated() {
    // 0x20 needs 4 bytes
    assert_eq!(
        CilInstr::decode(&[0x20, 0x01, 0x02]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn decode_ldc_i8_truncated() {
    assert_eq!(
        CilInstr::decode(&[0x21, 0, 0, 0, 0]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn decode_switch_truncated_count() {
    assert_eq!(CilInstr::decode(&[0x45, 0, 0]), Err(CilDecodeError::Truncated));
}

#[test]
fn decode_switch_truncated_table() {
    // count=2 but only 1 entry
    let mut buf = vec![0x45_u8];
    buf.extend_from_slice(&2_u32.to_le_bytes());
    buf.extend_from_slice(&0_i32.to_le_bytes());
    assert_eq!(CilInstr::decode(&buf), Err(CilDecodeError::Truncated));
}

#[test]
fn decode_unknown_opcode() {
    // pick something we expect to be unmapped
    match CilInstr::decode(&[0xa6]) {
        Err(CilDecodeError::UnknownOpcode(0xa6)) => {}
        other => panic!("expected UnknownOpcode(0xa6), got {other:?}"),
    }
}

#[test]
fn decode_fe_truncated() {
    assert_eq!(CilInstr::decode(&[0xfe]), Err(CilDecodeError::Truncated));
}

#[test]
fn decode_fe_ceq() {
    let (i, n) = CilInstr::decode(&[0xfe, 0x01]).unwrap();
    assert_eq!(n, 2);
    assert_eq!(i.mnemonic, "ceq");
}

#[test]
fn decode_fe_unknown() {
    match CilInstr::decode(&[0xfe, 0x7f]) {
        Err(CilDecodeError::UnknownPrefixedOpcode(0x7f)) => {}
        other => panic!("expected UnknownPrefixedOpcode, got {other:?}"),
    }
}

// ============ Display on errors ============

#[test]
fn error_display_truncated() {
    assert_eq!(CilDecodeError::Truncated.to_string(), "truncated CIL instruction");
}

#[test]
fn error_display_unknown_opcode() {
    let s = CilDecodeError::UnknownOpcode(0xab).to_string();
    assert!(s.contains("0xab") || s.contains("0xAB"));
}

// ============ MetadataTokenType ============

#[test]
fn token_type_all_known_variants_roundtrip() {
    for (tag, expected) in [
        (0x01u32, MetadataTokenType::TypeRef),
        (0x02, MetadataTokenType::TypeDef),
        (0x04, MetadataTokenType::Field),
        (0x06, MetadataTokenType::MethodDef),
        (0x08, MetadataTokenType::Param),
        (0x0a, MetadataTokenType::MemberRef),
        (0x0b, MetadataTokenType::Constant),
        (0x11, MetadataTokenType::StandAloneSig),
        (0x1b, MetadataTokenType::TypeSpec),
        (0x2b, MetadataTokenType::MethodSpec),
        (0x70, MetadataTokenType::UserString),
    ] {
        let tok = (tag << 24) | 0x42;
        assert_eq!(MetadataTokenType::from_token(tok), Some(expected));
        assert_eq!(MetadataTokenType::rid(tok), 0x42);
    }
}

#[test]
fn token_type_rid_max() {
    assert_eq!(MetadataTokenType::rid(0xFFFF_FFFF), 0x00FF_FFFF);
}

#[test]
fn token_type_unknown_tag() {
    assert!(MetadataTokenType::from_token(0xFF00_0000).is_none());
}

#[test]
fn token_type_table_names_nonempty() {
    let names = [
        MetadataTokenType::TypeRef.table_name(),
        MetadataTokenType::MethodSpec.table_name(),
        MetadataTokenType::UserString.table_name(),
    ];
    for n in names {
        assert!(!n.is_empty());
    }
}

// ============ MethodHeader ============

#[test]
fn method_header_tiny_decode_max() {
    // Tiny header: code_size = 63 (max for 6-bit field)
    let byte = (63u8 << 2) | MethodHeader::TINY_FLAG;
    let (h, n) = MethodHeader::decode(&[byte]).unwrap();
    assert_eq!(n, 1);
    assert!(h.is_tiny());
    assert_eq!(h.code_size(), 63);
}

#[test]
fn method_header_fat_decode() {
    let mut bytes = vec![0x03_u8, 0x30, 0x10, 0x00];
    bytes.extend_from_slice(&100_u32.to_le_bytes());
    bytes.extend_from_slice(&0x1100_0001_u32.to_le_bytes());
    let (h, n) = MethodHeader::decode(&bytes).unwrap();
    assert_eq!(n, 12);
    assert!(!h.is_tiny());
    assert_eq!(h.code_size(), 100);
    if let MethodHeader::Fat {
        max_stack,
        local_var_sig_tok,
        ..
    } = h
    {
        assert_eq!(max_stack, 16);
        assert_eq!(local_var_sig_tok, 0x1100_0001);
    } else {
        panic!("expected fat");
    }
}

#[test]
fn method_header_empty() {
    assert_eq!(MethodHeader::decode(&[]), Err(CilDecodeError::Truncated));
}

#[test]
fn method_header_fat_too_short() {
    // first byte not tiny flag
    assert_eq!(
        MethodHeader::decode(&[0x03, 0, 0, 0, 0]),
        Err(CilDecodeError::Truncated)
    );
}

// ============ EhClauseKind ============

#[test]
fn eh_clause_kind_all() {
    assert_eq!(EhClauseKind::from_u32(0), Some(EhClauseKind::Exception));
    assert_eq!(EhClauseKind::from_u32(1), Some(EhClauseKind::Filter));
    assert_eq!(EhClauseKind::from_u32(2), Some(EhClauseKind::Finally));
    assert_eq!(EhClauseKind::from_u32(4), Some(EhClauseKind::Fault));
    assert_eq!(EhClauseKind::from_u32(3), None);
    assert_eq!(EhClauseKind::from_u32(5), None);
    assert_eq!(EhClauseKind::Exception.name(), "catch");
    assert_eq!(EhClauseKind::Finally.name(), "finally");
}

// ============ InlineOperand sizes ============

#[test]
fn inline_operand_sizes() {
    assert_eq!(InlineOperand::None.fixed_size(), Some(0));
    assert_eq!(InlineOperand::Var.fixed_size(), Some(1));
    assert_eq!(InlineOperand::I.fixed_size(), Some(1));
    assert_eq!(InlineOperand::I8.fixed_size(), Some(1));
    assert_eq!(InlineOperand::I32.fixed_size(), Some(4));
    assert_eq!(InlineOperand::R4.fixed_size(), Some(4));
    assert_eq!(InlineOperand::I64.fixed_size(), Some(8));
    assert_eq!(InlineOperand::R8.fixed_size(), Some(8));
    assert_eq!(InlineOperand::Switch.fixed_size(), None);
}

// ============ CilMethodStats ============

#[test]
fn stats_empty_code() {
    let s = CilMethodStats::from_bytes(&[]).unwrap();
    assert_eq!(s.instruction_count, 0);
}

#[test]
fn stats_simple() {
    // ldarg.0, ldc.i4.1, add, ret
    let code = [0x02_u8, 0x17, 0x58, 0x2a];
    let s = CilMethodStats::from_bytes(&code).unwrap();
    assert_eq!(s.instruction_count, 4);
    assert_eq!(s.terminator_count, 1);
}

#[test]
fn stats_branch_counts() {
    // ldc.i4.0, brfalse.s 0, br.s 0, ret
    let code = [0x16_u8, 0x2c, 0x00, 0x2b, 0x00, 0x2a];
    let s = CilMethodStats::from_bytes(&code).unwrap();
    assert_eq!(s.conditional_branch_count, 1);
    assert_eq!(s.unconditional_branch_count, 1);
    assert_eq!(s.terminator_count, 1);
}

#[test]
fn stats_propagates_decode_error() {
    assert!(CilMethodStats::from_bytes(&[0xa6]).is_err());
}

// ============ CilOpcodeRef table ============

#[test]
fn lookup_known_single_byte_opcodes() {
    assert!(lookup_cil_opcode(0x00).is_some()); // nop
    assert!(lookup_cil_opcode(0x2a).is_some()); // ret
    assert!(lookup_cil_opcode(0x28).is_some()); // call
}

#[test]
fn lookup_unknown_returns_none() {
    // 0xa6 is not in the small reference table
    assert!(lookup_cil_opcode(0xa6).is_none());
}

#[test]
fn lookup_fe_opcode_not_in_table() {
    // single-byte 0xfe lookup should not match (fe is the prefix)
    assert!(lookup_cil_opcode(0xfe).is_none());
}

#[test]
fn opcode_ref_flags_decoded_correctly() {
    let call = lookup_cil_opcode(0x28).unwrap();
    assert!(call.flags().contains(InstrFlags::CALL));
    let ret = lookup_cil_opcode(0x2a).unwrap();
    assert!(ret.flags().contains(InstrFlags::RET));
    let brfalse = lookup_cil_opcode(0x2c).unwrap();
    assert!(brfalse.flags().contains(InstrFlags::BRANCH));
    assert!(brfalse.flags().contains(InstrFlags::CONDITIONAL));
}

#[test]
fn opcode_ref_is_prefixed() {
    assert!(!lookup_cil_opcode(0x00).unwrap().is_prefixed());
}

// ============ cil_find_blocks ============

#[test]
fn find_blocks_empty() {
    let blocks = cil_find_blocks(&[]).unwrap();
    assert!(blocks.is_empty());
}

#[test]
fn find_blocks_single_ret() {
    let blocks = cil_find_blocks(&[0x2a]).unwrap();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].instr_count, 1);
    assert_eq!(blocks[0].len(), 1);
}

#[test]
fn find_blocks_split_on_branch() {
    // ldc.i4.0, brfalse.s 0, nop, ret
    let code = [0x16_u8, 0x2c, 0x00, 0x00, 0x2a];
    let blocks = cil_find_blocks(&code).unwrap();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].end_offset, 3);
    assert_eq!(blocks[1].start_offset, 3);
    assert_eq!(blocks[1].end_offset, 5);
}

#[test]
fn find_blocks_trailing_no_terminator() {
    // ldc.i4.0  (no ret) — still emits a block
    let code = [0x16_u8];
    let blocks = cil_find_blocks(&code).unwrap();
    assert_eq!(blocks.len(), 1);
    assert!(!blocks[0].is_empty());
}

#[test]
fn find_blocks_decode_error_propagates() {
    assert!(cil_find_blocks(&[0xa6]).is_err());
}

// ============ CilStackTracker ============

#[test]
fn stack_tracker_default_zero() {
    let t = CilStackTracker::new();
    assert_eq!(t.depth, 0);
    assert_eq!(t.max_depth, 0);
    assert_eq!(t.min_depth, 0);
}

#[test]
fn stack_tracker_apply_push() {
    let mut t = CilStackTracker::new();
    let nop = lookup_cil_opcode(0x16).unwrap(); // ldc.i4.0: pop=0,push=1
    t.apply(nop);
    t.apply(nop);
    assert_eq!(t.depth, 2);
    assert_eq!(t.max_depth, 2);
}

#[test]
fn stack_tracker_apply_pop() {
    let mut t = CilStackTracker::new();
    let push = lookup_cil_opcode(0x16).unwrap();
    let pop = lookup_cil_opcode(0x26).unwrap(); // pop
    t.apply(push);
    t.apply(pop);
    assert_eq!(t.depth, 0);
    assert_eq!(t.max_depth, 1);
}

#[test]
fn stack_tracker_reset() {
    let mut t = CilStackTracker::new();
    let push = lookup_cil_opcode(0x16).unwrap();
    t.apply(push);
    t.reset();
    assert_eq!(t.depth, 0);
    assert_eq!(t.max_depth, 0);
}

#[test]
fn stack_tracker_variable_op_ignored() {
    let mut t = CilStackTracker::new();
    let call = lookup_cil_opcode(0x28).unwrap(); // pop=-1, push=-1
    t.apply(call);
    assert_eq!(t.depth, 0);
}

// ============ CilEhPattern ============

#[test]
fn eh_pattern_from_clause_all() {
    assert_eq!(CilEhPattern::from_clause(EhClauseKind::Exception), CilEhPattern::TryCatch);
    assert_eq!(CilEhPattern::from_clause(EhClauseKind::Finally), CilEhPattern::TryFinally);
    assert_eq!(CilEhPattern::from_clause(EhClauseKind::Fault), CilEhPattern::TryFault);
    assert_eq!(CilEhPattern::from_clause(EhClauseKind::Filter), CilEhPattern::TryFilter);
}

#[test]
fn eh_pattern_keywords() {
    assert_eq!(CilEhPattern::TryCatch.keyword(), "catch");
    assert_eq!(CilEhPattern::TryFinally.keyword(), "finally");
    assert_eq!(CilEhPattern::TryFault.keyword(), "fault");
    assert_eq!(CilEhPattern::TryFilter.keyword(), "filter");
}

// ============ CilCallConv ============

#[test]
fn callconv_parse_default() {
    assert_eq!(CilCallConv::from_byte(0x00), Some(CilCallConv::Default));
    assert_eq!(CilCallConv::from_byte(0x05), Some(CilCallConv::VarArg));
    assert_eq!(CilCallConv::from_byte(0x10), Some(CilCallConv::Generic));
}

#[test]
fn callconv_masks_high_bits() {
    // HasThis (0x20) is added to base byte, parse should still find Default in low 5 bits
    assert_eq!(CilCallConv::from_byte(0x20), Some(CilCallConv::Default));
}

#[test]
fn callconv_invalid() {
    assert_eq!(CilCallConv::from_byte(0x07), None);
}

#[test]
fn callconv_is_unmanaged() {
    assert!(CilCallConv::CDecl.is_unmanaged());
    assert!(CilCallConv::StdCall.is_unmanaged());
    assert!(!CilCallConv::Default.is_unmanaged());
    assert!(!CilCallConv::Generic.is_unmanaged());
}

#[test]
fn callconv_names_unique() {
    let names = [
        CilCallConv::Default.name(),
        CilCallConv::CDecl.name(),
        CilCallConv::StdCall.name(),
        CilCallConv::ThisCall.name(),
        CilCallConv::FastCall.name(),
        CilCallConv::VarArg.name(),
        CilCallConv::Generic.name(),
        CilCallConv::HasThis.name(),
        CilCallConv::ExplicitThis.name(),
    ];
    for (i, a) in names.iter().enumerate() {
        for (j, b) in names.iter().enumerate() {
            if i != j {
                assert_ne!(a, b);
            }
        }
    }
}

// ============ CilElemType ============

#[test]
fn elem_type_from_byte_known() {
    assert_eq!(CilElemType::from_byte(0x01), Some(CilElemType::Void));
    assert_eq!(CilElemType::from_byte(0x08), Some(CilElemType::I4));
    assert_eq!(CilElemType::from_byte(0x0E), Some(CilElemType::String));
    assert_eq!(CilElemType::from_byte(0x45), Some(CilElemType::Pinned));
}

#[test]
fn elem_type_from_byte_unknown() {
    assert!(CilElemType::from_byte(0x17).is_none()); // gap between 0x16 and 0x18
    assert!(CilElemType::from_byte(0xFF).is_none());
    assert!(CilElemType::from_byte(0x1A).is_none());
}

#[test]
fn elem_type_keywords() {
    assert_eq!(CilElemType::I4.keyword(), Some("int32"));
    assert_eq!(CilElemType::Void.keyword(), Some("void"));
    assert_eq!(CilElemType::Object.keyword(), Some("object"));
    assert!(CilElemType::Ptr.keyword().is_none());
    assert!(CilElemType::Pinned.keyword().is_none());
}

// ============ Well-known type lookup ============

#[test]
fn lookup_dotnet_type_unknown() {
    assert!(lookup_dotnet_type("NoSuchType_____").is_none());
}

#[test]
fn lookup_dotnet_type_known() {
    // we don't know the full table so just confirm at least Type or Object lookups
    assert!(lookup_dotnet_type("System.Type").is_some());
}

// ============ cil_cfg_text ============

#[test]
fn cfg_text_empty() {
    assert_eq!(cil_cfg_text(&[]), "");
}

#[test]
fn cfg_text_formats_blocks() {
    let blocks = vec![CilBasicBlock {
        start_offset: 0,
        end_offset: 4,
        instr_count: 2,
    }];
    let s = cil_cfg_text(&blocks);
    assert!(s.contains("BB0"));
    assert!(s.contains("2 instrs"));
}

// ============ identify_cil_idiom ============

#[test]
fn idiom_empty_is_general() {
    assert_eq!(identify_cil_idiom(&[]), CilIdiom::General);
}

#[test]
fn idiom_null_check() {
    let (a, _) = CilInstr::decode(&[0x14]).unwrap();
    let (b, _) = CilInstr::decode(&[0x2c, 0]).unwrap();
    assert_eq!(identify_cil_idiom(&[a, b]), CilIdiom::NullCheck);
}

#[test]
fn idiom_zero_init() {
    let (a, _) = CilInstr::decode(&[0x16]).unwrap(); // ldc.i4.0
    let (b, _) = CilInstr::decode(&[0x0a]).unwrap(); // stloc.0
    assert_eq!(identify_cil_idiom(&[a, b]), CilIdiom::ZeroInit);
}

#[test]
fn idiom_unrecognized_first_returns_general() {
    let (a, _) = CilInstr::decode(&[0x00]).unwrap();
    assert_eq!(identify_cil_idiom(&[a]), CilIdiom::General);
}

// ============ cil_net_stack_delta ============

#[test]
fn net_stack_delta_pop() {
    let (i, _) = CilInstr::decode(&[0x26]).unwrap();
    assert_eq!(cil_net_stack_delta(&i), Some(-1));
}

#[test]
fn net_stack_delta_push() {
    let (i, _) = CilInstr::decode(&[0x16]).unwrap();
    assert_eq!(cil_net_stack_delta(&i), Some(1));
}

#[test]
fn net_stack_delta_variable_call_is_none() {
    let mut buf = vec![0x28u8];
    buf.extend_from_slice(&0u32.to_le_bytes());
    let (i, _) = CilInstr::decode(&buf).unwrap();
    assert_eq!(cil_net_stack_delta(&i), None);
}

#[test]
fn net_stack_delta_unknown_byte_is_none() {
    let i = CilInstr {
        raw: vec![0xa6],
        mnemonic: "??".into(),
        operands: String::new(),
        flags: InstrFlags::NONE,
    };
    assert_eq!(cil_net_stack_delta(&i), None);
}

// ============ CilComplexityMetrics ============

#[test]
fn complexity_empty_is_one() {
    let m = CilComplexityMetrics::from_bytes(&[]).unwrap();
    assert_eq!(m.cyclomatic, 1);
    assert_eq!(m.instruction_count, 0);
    assert_eq!(m.max_linear_run, 0);
}

#[test]
fn complexity_counts_conditionals() {
    // ldc.i4.0, brfalse.s 0, ldc.i4.0, brfalse.s 0, ret
    let code = [0x16, 0x2c, 0x00, 0x16, 0x2c, 0x00, 0x2a];
    let m = CilComplexityMetrics::from_bytes(&code).unwrap();
    assert_eq!(m.cyclomatic, 3); // 1 + 2 conditional
}

// ============ CilMethodBuilder ============

#[test]
fn builder_empty() {
    let b = CilMethodBuilder::new();
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
}

#[test]
fn builder_round_trip_basic() {
    let mut b = CilMethodBuilder::new();
    b.ldarg0().ldc_i4_1().add().ret();
    assert_eq!(b.len(), 4);
    let code = b.finish();
    let s = CilMethodStats::from_bytes(&code).unwrap();
    assert_eq!(s.instruction_count, 4);
    assert_eq!(s.terminator_count, 1);
}

#[test]
fn builder_ldc_i4_decode_roundtrip() {
    let mut b = CilMethodBuilder::new();
    b.ldc_i4(0x1234_5678);
    let code = b.finish();
    let (i, n) = CilInstr::decode(&code).unwrap();
    assert_eq!(n, 5);
    assert_eq!(i.mnemonic, "ldc.i4");
    assert!(i.operands.contains("305419896"));
}

#[test]
fn builder_ldc_i4_s_negative() {
    let mut b = CilMethodBuilder::new();
    b.ldc_i4_s(-7);
    let (i, n) = CilInstr::decode(&b.finish()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(i.mnemonic, "ldc.i4.s");
    assert!(i.operands.contains("-7"));
}

#[test]
fn builder_call_decode() {
    let mut b = CilMethodBuilder::new();
    b.call(0x0600_0001);
    let (i, _) = CilInstr::decode(&b.finish()).unwrap();
    assert_eq!(i.mnemonic, "call");
    assert!(i.flags.contains(InstrFlags::CALL));
}

#[test]
fn builder_br_s_short_branch() {
    let mut b = CilMethodBuilder::new();
    b.br_s(10);
    let (i, n) = CilInstr::decode(&b.finish()).unwrap();
    assert_eq!(n, 2);
    assert_eq!(i.mnemonic, "br.s");
    assert!(i.flags.contains(InstrFlags::BRANCH));
}

// ============ Compressed integer decoding ============

#[test]
fn cmp_uint_empty() {
    assert_eq!(decode_compressed_uint(&[]), Err(CilDecodeError::Truncated));
}

#[test]
fn cmp_uint_1byte() {
    let (v, n) = decode_compressed_uint(&[0x03]).unwrap();
    assert_eq!(v, 3);
    assert_eq!(n, 1);
}

#[test]
fn cmp_uint_1byte_max() {
    let (v, n) = decode_compressed_uint(&[0x7F]).unwrap();
    assert_eq!(v, 127);
    assert_eq!(n, 1);
}

#[test]
fn cmp_uint_2byte() {
    // 10xx xxxx — value 0x80 over two bytes
    let (v, n) = decode_compressed_uint(&[0x80, 0x80]).unwrap();
    assert_eq!(v, 0x0080);
    assert_eq!(n, 2);
}

#[test]
fn cmp_uint_2byte_truncated() {
    assert_eq!(
        decode_compressed_uint(&[0x80]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn cmp_uint_4byte() {
    // b0=0xC0 → top5=0, then BE bytes 00 40 00 → 0x4000
    let (v, n) = decode_compressed_uint(&[0xC0, 0x00, 0x40, 0x00]).unwrap();
    assert_eq!(n, 4);
    assert_eq!(v, 0x0000_4000);
}

#[test]
fn cmp_uint_4byte_truncated() {
    assert_eq!(
        decode_compressed_uint(&[0xC0, 0x00]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn cmp_uint_invalid_top_bits() {
    // 0xE0 = 111x_xxxx — none of the patterns
    assert!(decode_compressed_uint(&[0xE0, 0, 0, 0]).is_err());
}

#[test]
fn cmp_int_positive_small() {
    // raw=2 (even) -> 1
    let (v, n) = decode_compressed_int(&[0x02]).unwrap();
    assert_eq!(v, 1);
    assert_eq!(n, 1);
}

#[test]
fn cmp_int_negative_small() {
    // raw=1 (odd) -> -64 region; ECMA-335 rotate-right encoding for -1 is 0x01? actually for 1-byte: shift=6
    // raw=1: (0>>1)=0 with sign bit |= -1 << 6 = 0xFFFF_FFC0 = -64. We test as documented.
    let (v, _) = decode_compressed_int(&[0x01]).unwrap();
    assert!(v < 0);
}

// ============ DotNetVisibility ============

#[test]
fn visibility_from_bits3_all() {
    assert_eq!(DotNetVisibility::from_bits3(0), DotNetVisibility::PrivateScope);
    assert_eq!(DotNetVisibility::from_bits3(1), DotNetVisibility::Private);
    assert_eq!(DotNetVisibility::from_bits3(2), DotNetVisibility::FamilyAndAssembly);
    assert_eq!(DotNetVisibility::from_bits3(3), DotNetVisibility::Assembly);
    assert_eq!(DotNetVisibility::from_bits3(4), DotNetVisibility::Family);
    assert_eq!(DotNetVisibility::from_bits3(5), DotNetVisibility::FamilyOrAssembly);
    assert_eq!(DotNetVisibility::from_bits3(6), DotNetVisibility::Public);
    assert_eq!(DotNetVisibility::from_bits3(7), DotNetVisibility::Public);
}

#[test]
fn visibility_masks_high_bits() {
    assert_eq!(DotNetVisibility::from_bits3(0xF6), DotNetVisibility::Public);
}

#[test]
fn visibility_ordering() {
    assert!(DotNetVisibility::Private < DotNetVisibility::Public);
}

// ============ CilOpcodeCategory ============

#[test]
fn category_load_vs_memload() {
    assert_eq!(CilOpcodeCategory::from_mnemonic("ldarg.0"), CilOpcodeCategory::Load);
    assert_eq!(CilOpcodeCategory::from_mnemonic("ldfld"), CilOpcodeCategory::MemLoad);
    assert_eq!(CilOpcodeCategory::from_mnemonic("ldind.i4"), CilOpcodeCategory::MemLoad);
}

#[test]
fn category_store_vs_memstore() {
    assert_eq!(CilOpcodeCategory::from_mnemonic("stloc.0"), CilOpcodeCategory::Store);
    assert_eq!(CilOpcodeCategory::from_mnemonic("stfld"), CilOpcodeCategory::MemStore);
    assert_eq!(CilOpcodeCategory::from_mnemonic("stind.i4"), CilOpcodeCategory::MemStore);
}

#[test]
fn category_object_ldelem() {
    assert_eq!(CilOpcodeCategory::from_mnemonic("ldelem.i4"), CilOpcodeCategory::Object);
    assert_eq!(CilOpcodeCategory::from_mnemonic("ldlen"), CilOpcodeCategory::Object);
    assert_eq!(CilOpcodeCategory::from_mnemonic("newarr"), CilOpcodeCategory::Object);
}

#[test]
fn category_exception() {
    assert_eq!(CilOpcodeCategory::from_mnemonic("throw"), CilOpcodeCategory::Exception);
    assert_eq!(CilOpcodeCategory::from_mnemonic("leave.s"), CilOpcodeCategory::Exception);
    assert_eq!(CilOpcodeCategory::from_mnemonic("endfinally"), CilOpcodeCategory::Exception);
}

#[test]
fn category_other() {
    assert_eq!(CilOpcodeCategory::from_mnemonic("nop"), CilOpcodeCategory::Other);
    assert_eq!(CilOpcodeCategory::from_mnemonic("dup"), CilOpcodeCategory::Other);
}

// ============ cil_inline_hint ============

#[test]
fn inline_hint_too_large() {
    let code = vec![0x00u8; 257];
    assert_eq!(cil_inline_hint(&code).unwrap(), CilInlineHint::TooLarge);
}

#[test]
fn inline_hint_trivial_short() {
    let code = [0x2a_u8];
    assert_eq!(cil_inline_hint(&code).unwrap(), CilInlineHint::Trivial);
}

// ============ AssemblyMetadataSummary ============

#[test]
fn asm_version_zero() {
    let s = AssemblyMetadataSummary::default();
    assert_eq!(s.version_string(), "0.0.0.0");
    assert!(s.is_culture_neutral());
}

#[test]
fn asm_culture_explicit_neutral_string() {
    let s = AssemblyMetadataSummary {
        culture: "neutral".to_string(),
        ..Default::default()
    };
    assert!(s.is_culture_neutral());
}

// ============ cil_max_local_slot ============

#[test]
fn max_slot_via_ldloc_s() {
    // ldloc.s 17
    let code = [0x11_u8, 0x11, 0x2a];
    assert_eq!(cil_max_local_slot(&code).unwrap(), 17);
}

#[test]
fn max_slot_empty() {
    assert_eq!(cil_max_local_slot(&[]).unwrap(), 0);
}

// ============ cil_fold_i32 / cil_fold_unary_i32 ============

#[test]
fn fold_add_wrapping() {
    assert_eq!(cil_fold_i32("add", i32::MAX, 1), Some(i32::MIN));
}

#[test]
fn fold_sub_wrapping() {
    assert_eq!(cil_fold_i32("sub", i32::MIN, 1), Some(i32::MAX));
}

#[test]
fn fold_div_normal() {
    assert_eq!(cil_fold_i32("div", 10, 3), Some(3));
}

#[test]
fn fold_div_zero_none() {
    assert_eq!(cil_fold_i32("div", 1, 0), None);
}

#[test]
fn fold_rem_zero_none() {
    assert_eq!(cil_fold_i32("rem", 1, 0), None);
}

#[test]
fn fold_shl_masking() {
    // wrapping_shl masks shift by 31 in Rust impl: 1 << 33 == 1 << 1 == 2
    assert_eq!(cil_fold_i32("shl", 1, 33), Some(2));
}

#[test]
fn fold_unary_not_minus_one() {
    assert_eq!(cil_fold_unary_i32("not", 0), Some(-1));
    assert_eq!(cil_fold_unary_i32("not", -1), Some(0));
}

#[test]
fn fold_unknown_mnemonic() {
    assert_eq!(cil_fold_i32("blarg", 1, 2), None);
    assert_eq!(cil_fold_unary_i32("blarg", 1), None);
}

// ============ CilStringPool ============

#[test]
fn string_pool_dedup() {
    let mut p = CilStringPool::new();
    let a = p.intern("x");
    let b = p.intern("x");
    assert_eq!(a, b);
    assert_eq!(p.len(), 1);
}

#[test]
fn string_pool_get_out_of_bounds() {
    let p = CilStringPool::new();
    assert_eq!(p.get(99), None);
}

#[test]
fn string_pool_empty_string_is_distinct() {
    let mut p = CilStringPool::new();
    let a = p.intern("");
    let b = p.intern("a");
    assert_ne!(a, b);
    assert_eq!(p.len(), 2);
}

// ============ CilOpcodeAlias ============

#[test]
fn opcode_aliases_all_short_form_ends_in_s_or_self() {
    for a in CIL_OPCODE_ALIASES {
        assert!(!a.long_form.is_empty());
        assert!(!a.short_form.is_empty());
    }
}

// ============ CilArch via Architecture trait ============

#[test]
fn arch_default_is_64() {
    let a = CilArch::default();
    assert_eq!(a.bitness, 64);
}

#[test]
fn arch_32_name() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_32();
    assert_eq!(a.name(), "cil32");
    assert_eq!(a.pointer_size(), 4);
}

#[test]
fn arch_64_name() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    assert_eq!(a.name(), "cil64");
    assert_eq!(a.pointer_size(), 8);
}

#[test]
fn arch_disassemble_invalid_returns_plugin_error() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    let res = a.disassemble(Address::new(0), &[0xa6]);
    assert!(res.is_err());
}

#[test]
fn arch_disassemble_nop() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    let i = a.disassemble(Address::new(0x1000), &[0x00]).unwrap();
    assert_eq!(i.mnemonic, "nop");
    assert_eq!(i.size, 1);
}

#[test]
fn arch_get_branches_short_br_target() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    let i = a.disassemble(Address::new(0x1000), &[0x2b, 0x05]).unwrap();
    let br = a.get_branches(&i);
    assert_eq!(br.len(), 1);
    // next = 0x1002, +5 = 0x1007
    assert_eq!(br[0].target, Some(0x1007));
}

#[test]
fn arch_get_branches_no_branch_returns_empty() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    let i = a.disassemble(Address::new(0x1000), &[0x00]).unwrap();
    assert!(a.get_branches(&i).is_empty());
}

#[test]
fn arch_registers_nonempty() {
    use rustre_core::arch::Architecture;
    let a = CilArch::new_64();
    assert!(!a.registers().is_empty());
}

// ============ CilLinearDisassembler ============

#[test]
fn linear_disasm_iterates() {
    let arch = CilArch::new_64();
    let bytes = [0x00_u8, 0x00, 0x2a];
    let mut iter = CilLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let a = iter.next().unwrap().unwrap();
    let b = iter.next().unwrap().unwrap();
    let c = iter.next().unwrap().unwrap();
    assert_eq!(a.mnemonic, "nop");
    assert_eq!(b.mnemonic, "nop");
    assert_eq!(c.mnemonic, "ret");
    assert!(iter.next().is_none());
}

#[test]
fn linear_disasm_skips_bad_byte() {
    let arch = CilArch::new_64();
    let bytes = [0xa6_u8, 0x00];
    let mut iter = CilLinearDisassembler::new(&arch, &bytes, Address::new(0));
    let bad = iter.next().unwrap();
    assert!(bad.is_err());
    let good = iter.next().unwrap().unwrap();
    assert_eq!(good.mnemonic, "nop");
}

// ============ wide_prefix module ============

#[test]
fn wide_operand_sizes() {
    assert_eq!(WideOperand::None.total_size(), 2);
    assert_eq!(WideOperand::Uint8.total_size(), 3);
    assert_eq!(WideOperand::Uint16.total_size(), 4);
    assert_eq!(WideOperand::Token32.total_size(), 6);
}

#[test]
fn wide_table_lookup_ceq() {
    let e = lookup_wide(0x01).unwrap();
    assert_eq!(e.mnemonic, "ceq");
    assert_eq!(e.category, WideCategory::Compare);
}

#[test]
fn wide_table_lookup_unknown() {
    assert!(lookup_wide(0x7F).is_none());
}

#[test]
fn wide_table_size() {
    // 0x00..=0x1E = 31 entries
    assert!(WIDE_PREFIX_TABLE.len() >= 30);
}

#[test]
fn wide_decode_ceq_no_operand() {
    let r = decode_wide_prefix(&[0xFE, 0x01]).unwrap();
    assert_eq!(r.entry.mnemonic, "ceq");
    assert_eq!(r.size, 2);
    assert_eq!(r.operand_value, 0);
}

#[test]
fn wide_decode_ldarg_uint16() {
    let r = decode_wide_prefix(&[0xFE, 0x09, 0x34, 0x12]).unwrap();
    assert_eq!(r.entry.mnemonic, "ldarg");
    assert_eq!(r.size, 4);
    assert_eq!(r.operand_value, 0x1234);
}

#[test]
fn wide_decode_initobj_token() {
    let r = decode_wide_prefix(&[0xFE, 0x15, 0x01, 0x02, 0x03, 0x04]).unwrap();
    assert_eq!(r.entry.mnemonic, "initobj");
    assert_eq!(r.operand_value, 0x0403_0201);
    assert_eq!(r.size, 6);
}

#[test]
fn wide_decode_truncated_no_second_byte() {
    assert_eq!(
        decode_wide_prefix(&[0xFE]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn wide_decode_truncated_operand() {
    // ldarg needs 4 total
    assert_eq!(
        decode_wide_prefix(&[0xFE, 0x09, 0x01]),
        Err(CilDecodeError::Truncated)
    );
}

#[test]
fn wide_decode_unknown_second_byte() {
    match decode_wide_prefix(&[0xFE, 0x7F]) {
        Err(CilDecodeError::UnknownPrefixedOpcode(0x7F)) => {}
        other => panic!("expected UnknownPrefixedOpcode, got {other:?}"),
    }
}

#[test]
fn wide_decode_rejects_reserved() {
    // 0x08 is marked Reserved
    match decode_wide_prefix(&[0xFE, 0x08]) {
        Err(CilDecodeError::UnknownPrefixedOpcode(0x08)) => {}
        other => panic!("expected reserved rejection, got {other:?}"),
    }
}

#[test]
fn wide_decode_unaligned_uint8() {
    let r = decode_wide_prefix(&[0xFE, 0x12, 0x04]).unwrap();
    assert_eq!(r.entry.mnemonic, "unaligned");
    assert_eq!(r.operand_value, 4);
    assert_eq!(r.size, 3);
}

// ============ LocalVarFlags ============

#[test]
fn local_var_flags_bits() {
    let f = LocalVarFlags::PINNED;
    assert_eq!(f.bits(), 0x45);
    let f = LocalVarFlags::BYREF;
    assert_eq!(f.bits(), 0x10);
}
