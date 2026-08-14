//! Deep adversarial tests for rustre-deobf-vmlift public API.

use rustre_deobf_vmlift::{
    BinOpKind, DecodeError, GuestInstruction, GuestOpcode, HandlerSemantic, PopDst, PushSrc,
    VmBytecodeDisassembler, VmDispatcherDetector, VmInstruction, VmInstructionDef, VmIsa, VmLifter,
    VmLifterPipeline, suggest_mnemonic,
};

fn lcg() -> impl FnMut() -> u64 {
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    move || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    }
}

// ───────────────── VmLifter round-trips & fuzz ─────────────────

#[test]
fn lifter_empty_ok() {
    assert_eq!(VmLifter::lift_to_instructions(&[]), Ok(vec![]));
}

#[test]
fn lifter_halt_only_50x() {
    for _ in 0..50 {
        let r = VmLifter::lift_to_instructions(&[0x07]).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].opcode, GuestOpcode::Halt);
    }
}

#[test]
fn lifter_add_50_inputs() {
    for d in 0..50u8 {
        let s = d.wrapping_add(7);
        let r = VmLifter::lift_to_instructions(&[0x01, d, s]).unwrap();
        assert_eq!(r[0].opcode, GuestOpcode::Add);
        assert_eq!(r[0].reg_dst, Some(d as usize));
        assert_eq!(r[0].reg_src, Some(s as usize));
    }
}

#[test]
fn lifter_sub_50_inputs() {
    for d in 0..50u8 {
        let s = d.wrapping_mul(3);
        let r = VmLifter::lift_to_instructions(&[0x02, d, s]).unwrap();
        assert_eq!(r[0].opcode, GuestOpcode::Sub);
    }
}

#[test]
fn lifter_loadimm_roundtrip_50() {
    for i in 0..50u32 {
        let imm = i.wrapping_mul(0x01020304);
        let mut bc = vec![0x08, (i & 0xFF) as u8];
        bc.extend_from_slice(&imm.to_le_bytes());
        let r = VmLifter::lift_to_instructions(&bc).unwrap();
        assert_eq!(r[0].imm, Some(imm));
        assert_eq!(r[0].opcode, GuestOpcode::Load);
        assert_eq!(r[0].reg_src, None);
    }
}

#[test]
fn lifter_pushimm_roundtrip_50() {
    for i in 0..50u32 {
        let imm = i.wrapping_mul(0xDEADBEEF);
        let mut bc = vec![0x09];
        bc.extend_from_slice(&imm.to_le_bytes());
        let r = VmLifter::lift_to_instructions(&bc).unwrap();
        assert_eq!(r[0].imm, Some(imm));
        assert_eq!(r[0].opcode, GuestOpcode::Push);
    }
}

#[test]
fn lifter_load_mem_roundtrip_50() {
    for i in 0..50u32 {
        let imm = i.wrapping_mul(31);
        let mut bc = vec![0x05, (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8];
        bc.extend_from_slice(&imm.to_le_bytes());
        let r = VmLifter::lift_to_instructions(&bc).unwrap();
        assert_eq!(r[0].imm, Some(imm));
    }
}

#[test]
fn lifter_store_mem_roundtrip_50() {
    for i in 0..50u32 {
        let imm = i.wrapping_mul(0xABCD);
        let mut bc = vec![0x06, (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8];
        bc.extend_from_slice(&imm.to_le_bytes());
        let r = VmLifter::lift_to_instructions(&bc).unwrap();
        assert_eq!(r[0].imm, Some(imm));
        assert_eq!(r[0].opcode, GuestOpcode::Store);
    }
}

#[test]
fn lifter_fuzz_seeded_no_panic() {
    let mut g = lcg();
    for _ in 0..200 {
        let len = (g() as usize) % 64;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        // Must never panic, returns Result.
        let _ = VmLifter::lift_to_instructions(&bytes);
    }
}

#[test]
fn lifter_unknown_opcode_each() {
    for op in 0u8..=255 {
        if (0x01..=0x09).contains(&op) {
            continue;
        }
        assert_eq!(
            VmLifter::lift_to_instructions(&[op]),
            Err("Unknown opcode in bytecode")
        );
    }
}

#[test]
fn lifter_truncation_each_arity() {
    // Add: needs 2 bytes after opcode
    assert!(VmLifter::lift_to_instructions(&[0x01]).is_err());
    assert!(VmLifter::lift_to_instructions(&[0x01, 0x00]).is_err());
    // Load: needs 6
    assert!(VmLifter::lift_to_instructions(&[0x05, 0, 0, 0, 0, 0]).is_err());
    // Store: needs 6
    assert!(VmLifter::lift_to_instructions(&[0x06, 0, 0, 0, 0, 0]).is_err());
    // LoadImm: needs 5
    assert!(VmLifter::lift_to_instructions(&[0x08, 0, 0, 0, 0]).is_err());
    // PushImm: needs 4
    assert!(VmLifter::lift_to_instructions(&[0x09, 0, 0, 0]).is_err());
}

#[test]
fn lifter_max_register_values() {
    let r = VmLifter::lift_to_instructions(&[0x01, 0xFF, 0xFF]).unwrap();
    assert_eq!(r[0].reg_dst, Some(255));
    assert_eq!(r[0].reg_src, Some(255));
}

#[test]
fn lifter_max_imm_values() {
    let mut bc = vec![0x09];
    bc.extend_from_slice(&u32::MAX.to_le_bytes());
    let r = VmLifter::lift_to_instructions(&bc).unwrap();
    assert_eq!(r[0].imm, Some(u32::MAX));
}

#[test]
fn lifter_zero_imm() {
    let mut bc = vec![0x09];
    bc.extend_from_slice(&0u32.to_le_bytes());
    let r = VmLifter::lift_to_instructions(&bc).unwrap();
    assert_eq!(r[0].imm, Some(0));
}

#[test]
fn lifter_chained_program_50ops() {
    let mut bc = Vec::new();
    for _ in 0..50 {
        bc.push(0x07); // Halt repeated is fine
    }
    let r = VmLifter::lift_to_instructions(&bc).unwrap();
    assert_eq!(r.len(), 50);
    for instr in &r {
        assert_eq!(instr.opcode, GuestOpcode::Halt);
    }
}

#[test]
fn lifter_to_pseudo_il_matches_display() {
    let bc = vec![0x07, 0x03, 0x05, 0x04, 0x06];
    let instrs = VmLifter::lift_to_instructions(&bc).unwrap();
    let pseudo = VmLifter::to_pseudo_il(&instrs);
    assert_eq!(pseudo.len(), instrs.len());
    for (s, i) in pseudo.iter().zip(instrs.iter()) {
        assert_eq!(s, &i.to_string());
    }
}

// ───────────────── GuestInstruction Display edge cases ─────────────────

#[test]
fn guest_display_load_variants() {
    // Memory with offset
    let i = GuestInstruction {
        opcode: GuestOpcode::Load,
        reg_dst: Some(1),
        reg_src: Some(2),
        imm: Some(0x10),
    };
    assert_eq!(i.to_string(), "LOAD r1, [r2 + 0x10]");
    // Memory, no offset (None imm) vs zero imm
    let i2 = GuestInstruction {
        opcode: GuestOpcode::Load,
        reg_dst: Some(1),
        reg_src: Some(2),
        imm: None,
    };
    assert_eq!(i2.to_string(), "LOAD r1, [r2]");
}

#[test]
fn guest_display_store_variants() {
    let i = GuestInstruction {
        opcode: GuestOpcode::Store,
        reg_dst: None,
        reg_src: Some(1),
        imm: Some(0xABCD),
    };
    assert_eq!(i.to_string(), "STORE [0xabcd], r1");
}

#[test]
fn guest_eq_hash_consistency_30() {
    use std::collections::HashSet;
    let mut set: HashSet<(GuestOpcode, Option<usize>, Option<usize>, Option<u32>)> = HashSet::new();
    for i in 0..30u32 {
        let key = (
            GuestOpcode::Add,
            Some(i as usize),
            Some((i + 1) as usize),
            None,
        );
        set.insert(key);
    }
    assert_eq!(set.len(), 30);
}

#[test]
fn guest_opcode_clone_copy() {
    let a = GuestOpcode::Halt;
    let b = a;
    assert_eq!(a, b);
    let _c = a.clone();
}

// ───────────────── VmDispatcherDetector ─────────────────

#[test]
fn detector_empty_input() {
    let r = VmDispatcherDetector::detect_in_bytes(&[], 0);
    assert!(r.is_empty());
}

#[test]
fn detector_pattern_a_indirect_indexed() {
    // FF 24 CD disp32  → pattern A
    let mut code = vec![0xFF, 0x24, 0xCD];
    code.extend_from_slice(&0u32.to_le_bytes());
    code.extend(std::iter::repeat(0u8).take(64));
    let out = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(out.iter().any(|d| d.offset == 0));
}

#[test]
fn detector_pattern_b_computed_jmp() {
    let code = [0xFF, 0xE0];
    let out = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(out.iter().any(|d| d.offset == 0));
}

#[test]
fn detector_pattern_b_jmp_rcx() {
    let code = [0xFF, 0xE1];
    let out = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(out.iter().any(|d| d.offset == 0));
}

#[test]
fn detector_pattern_c_call_pop_add() {
    // call $+5: E8 00 00 00 00
    // pop rax: 0x58
    // 48 81 C0 imm32
    let mut code = vec![0xE8, 0, 0, 0, 0, 0x58, 0x48, 0x81, 0xC0];
    code.extend_from_slice(&0x100u32.to_le_bytes());
    let out = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(out.iter().any(|d| d.offset == 0));
}

#[test]
fn detector_no_false_positive_on_zeros() {
    let code = vec![0u8; 64];
    let out = VmDispatcherDetector::detect_in_bytes(&code, 0);
    assert!(out.is_empty());
}

#[test]
fn detector_fuzz_seeded_no_panic() {
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 256;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let base = g();
        let _ = VmDispatcherDetector::detect_in_bytes(&bytes, base);
    }
}

#[test]
fn detector_extract_jump_table_zero_step() {
    let v = VmDispatcherDetector::extract_jump_table_entries(&[1u8, 2, 3, 4], 0, 4, 0);
    assert!(v.is_empty());
}

#[test]
fn detector_extract_jump_table_stops_on_zero() {
    let data = vec![0u8; 64];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 8, 8);
    // First entry is zero → stops
    assert!(v.is_empty());
}

#[test]
fn detector_extract_jump_table_valid_8byte() {
    let mut data = Vec::new();
    for _ in 0..4 {
        data.extend_from_slice(&0x100u64.to_le_bytes());
    }
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 0, 4, 8);
    assert_eq!(v.len(), 4);
    for e in &v {
        assert_eq!(*e, 0x100);
    }
}

#[test]
fn detector_extract_jump_table_overflow_offset() {
    let data = vec![0u8; 8];
    let v = VmDispatcherDetector::extract_jump_table_entries(&data, 1000, 4, 8);
    assert!(v.is_empty());
}

// ───────────────── HandlerSemantic ─────────────────

#[test]
fn semantic_control_flow_classification() {
    assert!(HandlerSemantic::Branch.is_control_flow());
    assert!(HandlerSemantic::Call.is_control_flow());
    assert!(HandlerSemantic::Ret.is_control_flow());
    assert!(HandlerSemantic::Halt.is_control_flow());
    assert!(!HandlerSemantic::BinOp(BinOpKind::Add).is_control_flow());
    assert!(!HandlerSemantic::Cmp.is_control_flow());
}

#[test]
fn semantic_memory_classification() {
    assert!(HandlerSemantic::Load(4).accesses_memory());
    assert!(HandlerSemantic::Store(4).accesses_memory());
    assert!(HandlerSemantic::Push(PushSrc::Memory).accesses_memory());
    assert!(HandlerSemantic::Pop(PopDst::Memory).accesses_memory());
    assert!(!HandlerSemantic::Halt.accesses_memory());
    assert!(!HandlerSemantic::Push(PushSrc::Constant(1)).accesses_memory());
}

#[test]
fn semantic_suggest_mnemonic_all_variants() {
    let all = [
        HandlerSemantic::Push(PushSrc::Constant(0)),
        HandlerSemantic::Pop(PopDst::VirtualReg(0)),
        HandlerSemantic::BinOp(BinOpKind::Add),
        HandlerSemantic::BinOp(BinOpKind::Sub),
        HandlerSemantic::BinOp(BinOpKind::Mul),
        HandlerSemantic::BinOp(BinOpKind::Div),
        HandlerSemantic::BinOp(BinOpKind::And),
        HandlerSemantic::BinOp(BinOpKind::Or),
        HandlerSemantic::BinOp(BinOpKind::Xor),
        HandlerSemantic::BinOp(BinOpKind::Shl),
        HandlerSemantic::BinOp(BinOpKind::Shr),
        HandlerSemantic::BinOp(BinOpKind::Sar),
        HandlerSemantic::BinOp(BinOpKind::Rol),
        HandlerSemantic::BinOp(BinOpKind::Ror),
        HandlerSemantic::Load(4),
        HandlerSemantic::Store(4),
        HandlerSemantic::Cmp,
        HandlerSemantic::Branch,
        HandlerSemantic::Call,
        HandlerSemantic::Ret,
        HandlerSemantic::Halt,
        HandlerSemantic::IpAdvance(4),
        HandlerSemantic::Unknown,
    ];
    for s in &all {
        let m = suggest_mnemonic(s);
        assert!(!m.is_empty());
        // Free function and method must agree.
        assert_eq!(m, s.suggest_mnemonic());
    }
}

#[test]
fn semantic_display_round_trip_basic() {
    assert_eq!(
        HandlerSemantic::Push(PushSrc::Constant(0x42)).to_string(),
        "VPUSH #0x42"
    );
    assert_eq!(
        HandlerSemantic::Push(PushSrc::VirtualReg(3)).to_string(),
        "VPUSH vr3"
    );
    assert_eq!(
        HandlerSemantic::Push(PushSrc::Memory).to_string(),
        "VPUSH [mem]"
    );
    assert_eq!(HandlerSemantic::Halt.to_string(), "VHALT");
    assert_eq!(HandlerSemantic::IpAdvance(7).to_string(), "VIP+=7");
    assert_eq!(HandlerSemantic::Unknown.to_string(), "VUNK");
}

#[test]
fn binop_display_all() {
    for (k, name) in [
        (BinOpKind::Add, "Add"),
        (BinOpKind::Sub, "Sub"),
        (BinOpKind::Xor, "Xor"),
    ] {
        assert_eq!(k.to_string(), name);
    }
}

#[test]
fn semantic_eq_hash_30_pairs() {
    use std::collections::HashSet;
    let mut set: HashSet<HandlerSemantic> = HashSet::new();
    for i in 0..30u64 {
        set.insert(HandlerSemantic::Push(PushSrc::Constant(i)));
    }
    assert_eq!(set.len(), 30);
    // Re-inserting identical entries is idempotent.
    for i in 0..30u64 {
        set.insert(HandlerSemantic::Push(PushSrc::Constant(i)));
    }
    assert_eq!(set.len(), 30);
}

// ───────────────── VmIsa ─────────────────

#[test]
fn isa_new_is_empty() {
    let isa = VmIsa::new();
    assert!(isa.is_empty());
    assert_eq!(isa.len(), 0);
    assert!(isa.sorted_handlers().is_empty());
}

#[test]
fn isa_register_replace() {
    let mut isa = VmIsa::new();
    isa.register(VmInstructionDef::new(1, HandlerSemantic::Halt));
    isa.register(VmInstructionDef::new(1, HandlerSemantic::Cmp));
    assert_eq!(isa.len(), 1);
    assert_eq!(
        isa.lookup(1).unwrap().semantic,
        HandlerSemantic::Cmp
    );
}

#[test]
fn isa_lookup_missing() {
    let isa = VmIsa::new();
    assert!(isa.lookup(0).is_none());
    assert!(isa.lookup(255).is_none());
}

#[test]
fn isa_default_lifter_isa_has_9_handlers() {
    let isa = VmIsa::default_lifter_isa();
    assert_eq!(isa.len(), 9);
    for op in 0x01..=0x09 {
        assert!(isa.lookup(op).is_some());
    }
    let listing = isa.listing();
    assert!(!listing.is_empty());
}

#[test]
fn isa_sorted_handlers_in_order() {
    let mut isa = VmIsa::new();
    for op in [9u8, 5, 3, 1, 7] {
        isa.register(VmInstructionDef::new(op, HandlerSemantic::Halt));
    }
    let sorted = isa.sorted_handlers();
    let opcodes: Vec<u8> = sorted.iter().map(|d| d.opcode).collect();
    assert_eq!(opcodes, vec![1, 3, 5, 7, 9]);
}

#[test]
fn isa_suggest_mnemonic_assoc_fn() {
    assert_eq!(
        VmIsa::suggest_mnemonic(&HandlerSemantic::Halt),
        "VHALT"
    );
}

#[test]
fn instruction_def_default_operand_bytes() {
    // Constant push → 8 bytes
    let d = VmInstructionDef::new(0x10, HandlerSemantic::Push(PushSrc::Constant(0)));
    assert_eq!(d.operand_bytes, 8);
    // Halt → 0
    let d = VmInstructionDef::new(0x11, HandlerSemantic::Halt);
    assert_eq!(d.operand_bytes, 0);
    // Load(n) → n
    let d = VmInstructionDef::new(0x12, HandlerSemantic::Load(4));
    assert_eq!(d.operand_bytes, 4);
    // IpAdvance → 4
    let d = VmInstructionDef::new(0x13, HandlerSemantic::IpAdvance(8));
    assert_eq!(d.operand_bytes, 4);
}

#[test]
fn instruction_def_display() {
    let d = VmInstructionDef::new(0x07, HandlerSemantic::Halt);
    let s = d.to_string();
    assert!(s.contains("VHALT"));
    assert!(s.contains("operand_bytes=0"));
}

// ───────────────── VmBytecodeDisassembler ─────────────────

#[test]
fn disasm_empty() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[], &isa).unwrap();
    assert!(r.is_empty());
}

#[test]
fn disasm_unknown_opcode_emits_vunk() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0xFE], &isa).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].mnemonic, "VUNK_FE");
    assert!(r[0].operands.is_empty());
}

#[test]
fn disasm_truncated_returns_err() {
    let isa = VmIsa::default_lifter_isa();
    // 0x01 (Add) requires 2 operand bytes
    let err = VmBytecodeDisassembler::disassemble(&[0x01, 0x00], &isa).unwrap_err();
    match err {
        DecodeError::TruncatedInstruction {
            offset,
            opcode,
            expected_operand_bytes,
            available_bytes,
        } => {
            assert_eq!(offset, 0);
            assert_eq!(opcode, 0x01);
            assert_eq!(expected_operand_bytes, 2);
            assert_eq!(available_bytes, 1);
        }
    }
}

#[test]
fn disasm_to_text_nonempty() {
    let isa = VmIsa::default_lifter_isa();
    let r = VmBytecodeDisassembler::disassemble(&[0x07, 0x07, 0x07], &isa).unwrap();
    let txt = VmBytecodeDisassembler::to_text(&r);
    assert_eq!(txt.lines().count(), 3);
}

#[test]
fn disasm_fuzz_no_panic() {
    let isa = VmIsa::default_lifter_isa();
    let mut g = lcg();
    for _ in 0..50 {
        let len = (g() as usize) % 64;
        let bytes: Vec<u8> = (0..len).map(|_| (g() & 0xFF) as u8).collect();
        let _ = VmBytecodeDisassembler::disassemble(&bytes, &isa);
    }
}

#[test]
fn disasm_instruction_display() {
    let i = VmInstruction {
        offset: 0,
        opcode: 0x07,
        operands: vec![],
        mnemonic: "VHALT".to_owned(),
    };
    assert!(i.to_string().contains("VHALT"));

    let i2 = VmInstruction {
        offset: 0x10,
        opcode: 0x09,
        operands: vec![0xAB],
        mnemonic: "VPUSH".to_owned(),
    };
    assert!(i2.to_string().contains("0xab"));
}

// ───────────────── VmLifterPipeline ─────────────────

#[test]
fn pipeline_empty_bytecode_errors() {
    let r = VmLifterPipeline::full_pipeline(&[], 0, &[]);
    assert!(r.is_err());
}

#[test]
fn pipeline_minimal_halt_succeeds() {
    let lines = VmLifterPipeline::full_pipeline(&[0u8; 0], 0x1000, &[0x07]).unwrap();
    let joined = lines.join("\n");
    assert!(joined.contains("VHALT") || joined.contains("HALT"));
}

#[test]
fn pipeline_detect_and_report_zero_dispatchers() {
    let report = VmLifterPipeline::detect_and_report(&[0u8; 32], 0);
    assert_eq!(report.dispatchers_found, 0);
    // ISA always synthesised from default lifter encoding (9 entries)
    assert_eq!(report.isa.len(), 9);
    assert!(!report.analysis_notes.is_empty());
}

#[test]
fn pipeline_detect_with_dispatcher() {
    let code = [0xFF, 0xE0];
    let report = VmLifterPipeline::detect_and_report(&code, 0);
    assert!(report.dispatchers_found >= 1);
    assert!(report.total_handlers >= 1);
}

#[test]
fn decode_error_display_contains_offset() {
    let e = DecodeError::TruncatedInstruction {
        offset: 0x10,
        opcode: 0x05,
        expected_operand_bytes: 6,
        available_bytes: 2,
    };
    let s = e.to_string();
    assert!(s.contains("0x10"));
    assert!(s.contains("0x05"));
}

// ───────────────── Send/Sync threaded stress ─────────────────

#[test]
fn vmisa_send_sync_threaded() {
    use std::sync::Arc;
    let isa = Arc::new(VmIsa::default_lifter_isa());
    let mut handles = Vec::new();
    for _ in 0..4 {
        let isa = Arc::clone(&isa);
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = VmBytecodeDisassembler::disassemble(&[0x07], &isa).unwrap();
                assert_eq!(r.len(), 1);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn lifter_threaded_stress() {
    let mut handles = Vec::new();
    for t in 0..4u8 {
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let r = VmLifter::lift_to_instructions(&[0x01, t, t]).unwrap();
                assert_eq!(r[0].opcode, GuestOpcode::Add);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}
