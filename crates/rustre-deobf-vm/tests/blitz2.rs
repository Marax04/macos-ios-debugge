//! blitz2: deep adversarial coverage of rustre-deobf-vm public API.
//!
//! No external rand; uses a seeded LCG. No `std::time`. No #[allow], no #[ignore].

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use rustre_core::address::Address;
use rustre_deobf_vm::{
    read_u16_le, read_u32_le, read_u64_le, run_pass, BytecodeCandidate, HandlerCluster,
    HandlerClusterer, HandlerEdge, HandlerGraphBuilder, HandlerKind, HandlerNode, PcodeInsn,
    PcodeOp, PcodeVarnode, VirtualMachineState, VmArch, VmBytecode,
    VmBytecodeExtractor, VmDeobfPipeline, VmDetection, VmDetector, VmDispatcher,
    VmDispatcherDetector, VmHandler, VmLifter, VmLifterConfig, VmProtectorDetector, VmSemanticOp,
};

/// Seeded LCG; never use `std::time` or rand.
fn make_lcg(seed: u64) -> impl FnMut() -> u64 {
    let mut s: u64 = seed;
    move || {
        s = s
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        s
    }
}

// ─── helpers ───────────────────────────────────────────────────────────────

#[test]
fn read_u64_le_basic() {
    assert_eq!(read_u64_le(&[1, 0, 0, 0, 0, 0, 0, 0]), 1u64);
    assert_eq!(read_u64_le(&[0xff; 8]), u64::MAX);
    assert_eq!(read_u64_le(&[1, 2, 3]), 0);
    assert_eq!(read_u64_le(&[]), 0);
}

#[test]
fn read_u32_le_basic() {
    assert_eq!(read_u32_le(&[1, 0, 0, 0]), 1u32);
    assert_eq!(read_u32_le(&[0xff; 4]), u32::MAX);
    assert_eq!(read_u32_le(&[1, 2]), 0);
    assert_eq!(read_u32_le(&[]), 0);
}

#[test]
fn read_u16_le_basic() {
    assert_eq!(read_u16_le(&[1, 0]), 1u16);
    assert_eq!(read_u16_le(&[0xff, 0xff]), u16::MAX);
    assert_eq!(read_u16_le(&[5]), 0);
    assert_eq!(read_u16_le(&[]), 0);
}

#[test]
fn helpers_fuzz_never_panic() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let len = (g() as usize) % 16;
        let bytes: Vec<u8> = (0..len).map(|_| g() as u8).collect();
        let _ = read_u64_le(&bytes);
        let _ = read_u32_le(&bytes);
        let _ = read_u16_le(&bytes);
    }
}

// ─── VirtualMachineState ───────────────────────────────────────────────────

#[test]
fn vmstate_new_zero() {
    let s = VirtualMachineState::new();
    assert_eq!(s.regs, [0; 8]);
    assert_eq!(s.pc, 0);
    assert!(s.stack.is_empty());
    assert_eq!(s.flags, 0);
    assert!(s.memory.is_empty());
    assert_eq!(s, VirtualMachineState::default());
}

#[test]
fn vmstate_push_pop_round_trip() {
    let mut g = make_lcg(0x1234_5678_9ABC_DEF0);
    let mut s = VirtualMachineState::new();
    let mut vs = Vec::new();
    for _ in 0..60 {
        let v = g() as u32;
        s.push(v);
        vs.push(v);
    }
    while let Some(expected) = vs.pop() {
        assert_eq!(s.pop(), Some(expected));
    }
    assert_eq!(s.pop(), None);
}

#[test]
fn vmstate_mem_byte_round_trip() {
    let mut g = make_lcg(0xABCD);
    let mut s = VirtualMachineState::new();
    for _ in 0..50 {
        let addr = g();
        let byte = g() as u8;
        s.mem_write_byte(addr, byte);
        assert_eq!(s.mem_read_byte(addr), byte);
    }
    // unmapped reads return 0
    assert_eq!(s.mem_read_byte(0xDEADBEEF_CAFE_F00D), 0);
}

#[test]
fn vmstate_mem_u32_round_trip() {
    let mut g = make_lcg(0xFEED);
    let mut s = VirtualMachineState::new();
    for _ in 0..50 {
        let addr = g() & 0xFFFF_FFFF_0000_0000;
        let v = g() as u32;
        s.mem_write_u32(addr, v);
        assert_eq!(s.mem_read_u32(addr), v);
    }
}

#[test]
fn vmstate_flags() {
    let mut s = VirtualMachineState::new();
    assert!(!s.zero_flag());
    assert!(!s.carry_flag());
    s.set_zero_flag(0);
    assert!(s.zero_flag());
    s.set_zero_flag(1);
    assert!(!s.zero_flag());
    s.flags |= 2;
    assert!(s.carry_flag());
}

#[test]
fn vmstate_reset() {
    let mut s = VirtualMachineState::new();
    s.push(1);
    s.mem_write_byte(0, 0xAB);
    s.pc = 99;
    s.flags = 0xFF;
    s.regs[0] = 7;
    s.reset();
    assert_eq!(s, VirtualMachineState::new());
}

// ─── VmDispatcherDetector ──────────────────────────────────────────────────

#[test]
fn dispatcher_detector_finds_sig_a() {
    let mut block = vec![0u8; 64];
    block[0] = 0x31;
    block[1] = 0xC0;
    block[2] = 0xFF;
    block[3] = 0x24;
    // entry @ +4 as u64
    block[4..12].copy_from_slice(&0x1000u64.to_le_bytes());
    block[12..20].copy_from_slice(&0x2000u64.to_le_bytes());
    block[20..28].copy_from_slice(&10u64.to_le_bytes());
    let det = VmDispatcherDetector::new();
    let result = det.detect_dispatcher(&[block]).expect("should detect");
    assert_eq!(result.entry, Address::new(0x1000));
    assert_eq!(result.handler_table_base, Address::new(0x2000));
    assert_eq!(result.handler_count, 10);
}

#[test]
fn dispatcher_detector_finds_sig_b_caps_count() {
    let mut block = vec![0u8; 64];
    block[0] = 0x48;
    block[1] = 0x81;
    block[2] = 0xC3;
    block[3] = 0xFF;
    block[4..12].copy_from_slice(&0u64.to_le_bytes());
    block[12..20].copy_from_slice(&0u64.to_le_bytes());
    block[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
    let result = VmDispatcherDetector::detect(&[block]).expect("should detect");
    assert_eq!(result.handler_count, 65536); // capped
}

#[test]
fn dispatcher_detector_no_match() {
    let blocks: Vec<Vec<u8>> = vec![vec![0u8; 64]];
    assert!(VmDispatcherDetector::detect(&blocks).is_none());
    let empty: Vec<Vec<u8>> = vec![];
    assert!(VmDispatcherDetector::detect(&empty).is_none());
}

#[test]
fn dispatcher_detector_too_short() {
    // signature present, but block too small to read fields
    let mut block = vec![0u8; 20];
    block[0] = 0x31;
    block[1] = 0xC0;
    block[2] = 0xFF;
    block[3] = 0x24;
    assert!(VmDispatcherDetector::detect(&[block]).is_none());
}

#[test]
fn dispatcher_detector_fuzz_no_panic() {
    let mut g = make_lcg(0xDEAD_BEEF_CAFE_BABE);
    for _ in 0..200 {
        let n = (g() as usize) % 200;
        let block: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = VmDispatcherDetector::detect(&[block]);
    }
}

#[test]
fn vm_dispatcher_eq_copy() {
    let a = VmDispatcher {
        entry: Address::new(1),
        handler_table_base: Address::new(2),
        handler_count: 3,
    };
    let b = a;
    assert_eq!(a, b);
}

// ─── VmHandler ─────────────────────────────────────────────────────────────

#[test]
fn vm_handler_new_fields() {
    let h = VmHandler::new(
        7,
        Address::new(0x0040_0000),
        vec![0x55, 0x53, 0x48, 0x89],
        HandlerKind::Arithmetic,
        "ADD",
        2,
        1,
    );
    assert_eq!(h.index, 7);
    assert_eq!(h.address, Address::new(0x0040_0000));
    assert_eq!(h.kind, HandlerKind::Arithmetic);
    assert!(h.is_arithmetic());
    assert!(!h.is_control_flow());
    assert_eq!(h.stack_inputs, 2);
    assert_eq!(h.stack_outputs, 1);
    assert_eq!(h.description, "ADD");
}

#[test]
fn vm_handler_prologue_entropy() {
    let empty = VmHandler::new(0, Address::new(0), vec![], HandlerKind::Unknown, "", 0, 0);
    assert_eq!(empty.prologue_entropy(), 0.0);

    let uniform = VmHandler::new(
        0,
        Address::new(0),
        vec![0; 32],
        HandlerKind::Unknown,
        "",
        0,
        0,
    );
    assert!(uniform.prologue_entropy().abs() < 1e-9);

    let mixed = VmHandler::new(
        0,
        Address::new(0),
        (0..=255u8).collect(),
        HandlerKind::Unknown,
        "",
        0,
        0,
    );
    let e = mixed.prologue_entropy();
    assert!(e > 7.9 && e <= 8.0);
}

#[test]
fn vm_handler_control_flow_flag() {
    let h = VmHandler::new(
        0,
        Address::new(0),
        vec![],
        HandlerKind::ControlFlow,
        "JMP",
        1,
        0,
    );
    assert!(h.is_control_flow());
    assert!(!h.is_arithmetic());
}

// ─── VmDetector ────────────────────────────────────────────────────────────

#[test]
fn vm_detector_none() {
    let det = VmDetector::new();
    let r = det.detect(&[]);
    assert_eq!(r.dispatcher_count, 0);
    assert_eq!(r.handler_count, 0);
    assert!(r.arch_hints.is_empty());
}

#[test]
fn vm_detector_vmprotect_marker() {
    let det = VmDetector::new();
    let mut data = b"prefix_VMProtect_suffix".to_vec();
    data.extend(std::iter::repeat_n(0u8, 100));
    let r = det.detect(&data);
    assert!(r.arch_hints.iter().any(|s| s.contains("VMProtect")));
}

#[test]
fn vm_detector_cpuid_rdtsc() {
    let det = VmDetector::new();
    let mut data = vec![0u8; 100];
    data.extend(&[0x0F, 0xA2]); // CPUID
    data.extend(&[0x0F, 0x31]); // RDTSC
    let r = det.detect(&data);
    assert!(r.arch_hints.iter().any(|s| s.contains("CPUID")));
    assert!(r.arch_hints.iter().any(|s| s.contains("RDTSC")));
}

#[test]
fn vm_detector_dispatcher_pattern_found() {
    let det = VmDetector::new();
    let mut data = vec![0u8; 100];
    // FF E0 = indirect jump dynamic register
    data[50] = 0xFF;
    data[51] = 0xE0;
    let r = det.detect(&data);
    assert_eq!(r.dispatcher_offset, Some(50));
    assert!(r.dispatcher_count >= 1);
}

#[test]
fn vm_detector_fuzz_no_panic() {
    let det = VmDetector::new();
    let mut g = make_lcg(0xCAFE_F00D);
    for _ in 0..200 {
        let n = (g() as usize) % 512;
        let data: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = det.detect(&data);
    }
}

// ─── VmBytecode ────────────────────────────────────────────────────────────

#[test]
fn vm_bytecode_basic() {
    let bc = VmBytecode::new(vec![1, 2, 3, 4], 0x1000, 1);
    assert_eq!(bc.len(), 4);
    assert!(bc.is_non_empty());
    assert!(!bc.is_empty());
    assert_eq!(bc.start_address, 0x1000);
    assert_eq!(bc.distinct_opcodes, 4);
    assert!(!bc.looks_encrypted());
}

#[test]
fn vm_bytecode_empty() {
    let bc = VmBytecode::new(vec![], 0, 1);
    assert!(bc.is_empty());
    assert!(!bc.is_non_empty());
    assert_eq!(bc.len(), 0);
    assert_eq!(bc.entropy, 0.0);
    assert_eq!(bc.distinct_opcodes, 0);
}

#[test]
fn vm_bytecode_zero_width() {
    let bc = VmBytecode::new(vec![1, 2, 3], 0, 0);
    assert_eq!(bc.distinct_opcodes, 0);
}

#[test]
fn vm_bytecode_uniform_low_entropy() {
    let bc = VmBytecode::new(vec![0; 1024], 0, 1);
    assert!(bc.entropy.abs() < 1e-9);
    assert!(!bc.looks_encrypted());
}

#[test]
fn vm_bytecode_random_high_entropy() {
    let mut g = make_lcg(0x55);
    let data: Vec<u8> = (0..4096).map(|_| g() as u8).collect();
    let bc = VmBytecode::new(data, 0, 1);
    assert!(bc.entropy > 7.0);
    assert!(bc.looks_encrypted());
}

// ─── VmSemanticOp ──────────────────────────────────────────────────────────

#[test]
fn semantic_op_stack_deltas() {
    assert_eq!(VmSemanticOp::PushImm(5).stack_delta(), 1);
    assert_eq!(VmSemanticOp::PushReg(0).stack_delta(), 1);
    assert_eq!(VmSemanticOp::PopReg(0).stack_delta(), -1);
    assert_eq!(VmSemanticOp::Add.stack_delta(), -1);
    assert_eq!(VmSemanticOp::Store32.stack_delta(), -2);
    assert_eq!(VmSemanticOp::Not.stack_delta(), 0);
    assert_eq!(VmSemanticOp::Nop.stack_delta(), 0);
    assert_eq!(VmSemanticOp::Jmp.stack_delta(), -1);
    assert_eq!(VmSemanticOp::Jz.stack_delta(), -1);
    // Corrected 2026-07-29: this asserted -1, contradicting the crate's own
    // interpreter, which executes `Load32` as one pop (the address) followed by
    // one push (the loaded word) — a net delta of 0. `Store32` next to it does
    // two pops and no push and is correctly -2, which shows the intended
    // convention. The assertion crystallised the defect rather than stating a
    // contract, so it is the assertion that was wrong.
    assert_eq!(VmSemanticOp::Load32.stack_delta(), 0);
}

#[test]
fn semantic_op_classifications() {
    assert!(VmSemanticOp::Jmp.is_control_flow());
    assert!(VmSemanticOp::Ret.is_control_flow());
    assert!(VmSemanticOp::Halt.is_control_flow());
    assert!(!VmSemanticOp::Add.is_control_flow());

    assert!(VmSemanticOp::Add.is_alu());
    assert!(VmSemanticOp::Xor.is_alu());
    assert!(VmSemanticOp::Neg.is_alu());
    assert!(!VmSemanticOp::PushImm(0).is_alu());
    assert!(!VmSemanticOp::Nop.is_alu());
}

// ─── VmLifter ──────────────────────────────────────────────────────────────

#[test]
fn lifter_decodes_simple() {
    let lifter = VmLifter::new();
    // PushImm(7) ; PushImm(3) ; Add ; Halt
    let mut bc = Vec::new();
    bc.push(0x01);
    bc.extend(&7i32.to_le_bytes());
    bc.push(0x01);
    bc.extend(&3i32.to_le_bytes());
    bc.push(0x10);
    bc.push(0xFF);
    let ops = lifter.lift(&bc).unwrap();
    assert_eq!(
        ops,
        vec![
            VmSemanticOp::PushImm(7),
            VmSemanticOp::PushImm(3),
            VmSemanticOp::Add,
            VmSemanticOp::Halt
        ]
    );
}

#[test]
fn lifter_truncated_pushimm() {
    let lifter = VmLifter::new();
    let bc = vec![0x01, 0x00, 0x00]; // PushImm with only 2 bytes of operand
    let r = lifter.lift(&bc);
    assert!(r.is_err());
}

#[test]
fn lifter_truncated_pushreg() {
    let lifter = VmLifter::new();
    let bc = vec![0x02]; // PushReg, missing reg operand
    assert!(lifter.lift(&bc).is_err());
}

#[test]
fn lifter_truncated_popreg() {
    let lifter = VmLifter::new();
    assert!(lifter.lift(&[0x03]).is_err());
}

#[test]
fn lifter_unknown_opcode_yields_unknown() {
    let lifter = VmLifter::new();
    let ops = lifter.lift(&[0x77]).unwrap();
    assert_eq!(ops, vec![VmSemanticOp::Unknown(0x77)]);
}

#[test]
fn lifter_remapping() {
    let mut m = HashMap::new();
    m.insert(0xAA, 0x10); // alias for Add
    let lifter = VmLifter::new().with_opcode_map(m);
    assert_eq!(lifter.remap(0xAA), 0x10);
    assert_eq!(lifter.remap(0xBB), 0xBB);
    let ops = lifter.lift(&[0xAA, 0xFF]).unwrap();
    assert_eq!(ops, vec![VmSemanticOp::Add, VmSemanticOp::Halt]);
}

#[test]
fn lifter_fuzz_never_panic() {
    let lifter = VmLifter::new();
    let mut g = make_lcg(0xFADE);
    for _ in 0..200 {
        let n = (g() as usize) % 128;
        let bc: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = lifter.lift(&bc); // Ok or Err, never panic
    }
}

#[test]
fn lifter_simulate_arithmetic() {
    let lifter = VmLifter::new();
    let state = VirtualMachineState::new();
    let ops = vec![
        VmSemanticOp::PushImm(40),
        VmSemanticOp::PushImm(2),
        VmSemanticOp::Add,
        VmSemanticOp::Halt,
    ];
    let s = lifter.simulate(&ops, state).unwrap();
    assert_eq!(s.stack.last().copied(), Some(42));
}

#[test]
fn lifter_simulate_sub_xor_and_or() {
    let lifter = VmLifter::new();
    let state = VirtualMachineState::new();
    let ops = vec![
        VmSemanticOp::PushImm(10),
        VmSemanticOp::PushImm(3),
        VmSemanticOp::Sub, // 7
        VmSemanticOp::PushImm(0xF0),
        VmSemanticOp::Xor, // 7 ^ 0xF0
        VmSemanticOp::PushImm(0xFF),
        VmSemanticOp::And,
        VmSemanticOp::PushImm(0x100),
        VmSemanticOp::Or,
    ];
    let s = lifter.simulate(&ops, state).unwrap();
    let top = *s.stack.last().unwrap();
    let expected = (((10u32 - 3) ^ 0xF0) & 0xFF) | 0x100;
    assert_eq!(top, expected);
}

#[test]
fn lifter_simulate_underflow() {
    let lifter = VmLifter::new();
    let ops = vec![VmSemanticOp::Add];
    let err = lifter
        .simulate(&ops, VirtualMachineState::new())
        .unwrap_err();
    assert!(err.to_string().contains("underflow"));
}

#[test]
fn lifter_simulate_shl_shr_mask31() {
    let lifter = VmLifter::new();
    let ops = vec![
        VmSemanticOp::PushImm(1),
        VmSemanticOp::PushImm(33), // & 31 -> 1
        VmSemanticOp::Shl,
    ];
    let s = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
    assert_eq!(*s.stack.last().unwrap(), 2);
}

#[test]
fn lifter_simulate_load_store_round_trip() {
    let lifter = VmLifter::new();
    let mut state = VirtualMachineState::new();
    state.push(0xDEAD_BEEF); // value
    state.push(0x1000); // addr
    let ops = vec![VmSemanticOp::Store32];
    let state = lifter.simulate(&ops, state).unwrap();
    // Load it back
    let mut state2 = state;
    state2.push(0x1000);
    let ops = vec![VmSemanticOp::Load32];
    let s = lifter.simulate(&ops, state2).unwrap();
    assert_eq!(*s.stack.last().unwrap(), 0xDEAD_BEEF);
}

#[test]
fn lifter_simulate_not_neg() {
    let lifter = VmLifter::new();
    let ops = vec![
        VmSemanticOp::PushImm(5),
        VmSemanticOp::Not,
    ];
    let s = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
    assert_eq!(*s.stack.last().unwrap(), !5u32);

    let ops2 = vec![VmSemanticOp::PushImm(5), VmSemanticOp::Neg];
    let s2 = lifter.simulate(&ops2, VirtualMachineState::new()).unwrap();
    assert_eq!(*s2.stack.last().unwrap(), 5u32.wrapping_neg());
}

#[test]
fn lifter_simulate_jmp_sets_pc() {
    let lifter = VmLifter::new();
    let ops = vec![VmSemanticOp::PushImm(0x1234), VmSemanticOp::Jmp];
    let s = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
    assert_eq!(s.pc, 0x1234);
}

#[test]
fn lifter_config_default() {
    let cfg = VmLifterConfig::default();
    assert_eq!(cfg.opcode_width, 1);
    assert!(cfg.little_endian);
    assert_eq!(cfg.max_instructions, 65536);
}

// ─── HandlerCluster / HandlerClusterer ─────────────────────────────────────

#[test]
fn handler_cluster_add_size() {
    let mut c = HandlerCluster::new("arith", HandlerKind::Arithmetic);
    assert_eq!(c.size(), 0);
    c.add(1);
    c.add(2);
    assert_eq!(c.size(), 2);
    assert_eq!(c.handler_indices, vec![1, 2]);
    assert_eq!(c.primary_kind, HandlerKind::Arithmetic);
}

#[test]
fn handler_clusterer_groups_by_kind() {
    let handlers = vec![
        VmHandler::new(0, Address::new(0), vec![1; 4], HandlerKind::Arithmetic, "", 0, 0),
        VmHandler::new(1, Address::new(0), vec![2; 4], HandlerKind::Arithmetic, "", 0, 0),
        VmHandler::new(2, Address::new(0), vec![3; 4], HandlerKind::ControlFlow, "", 0, 0),
    ];
    let clusters = HandlerClusterer::new().cluster(&handlers);
    assert_eq!(clusters.len(), 2);
    // sorted by label
    for c in &clusters {
        match c.primary_kind {
            HandlerKind::Arithmetic => assert_eq!(c.size(), 2),
            HandlerKind::ControlFlow => assert_eq!(c.size(), 1),
            _ => panic!("unexpected kind"),
        }
    }
}

// ─── VmArch ────────────────────────────────────────────────────────────────

#[test]
fn vmarch_stack_machine() {
    let a = VmArch::stack_machine(10);
    assert_eq!(a.arch_type, "stack-machine");
    assert_eq!(a.register_count, 0);
    assert!(a.has_call_stack);
    assert_eq!(a.opcode_count, 10);
    assert_eq!(a.complexity_score, 30);
    assert!(a.summary().contains("stack-machine"));
}

#[test]
fn vmarch_register_machine() {
    let a = VmArch::register_machine(8, 64);
    assert_eq!(a.arch_type, "register-machine");
    assert_eq!(a.register_count, 8);
    assert!(!a.has_call_stack);
    assert_eq!(a.complexity_score, 64 * 2 + 8 * 4);
}

#[test]
fn vmarch_summary_be_le() {
    let mut a = VmArch::stack_machine(1);
    assert!(a.summary().contains("LE"));
    a.little_endian = false;
    assert!(a.summary().contains("BE"));
}

#[test]
fn vmarch_complexity_saturates() {
    // Pass a very large opcode_count and ensure no panic on saturating mul
    let a = VmArch::stack_machine(usize::MAX);
    let _ = a.complexity_score; // just must not panic
}

// ─── PCode ────────────────────────────────────────────────────────────────

#[test]
fn pcode_varnode_size() {
    assert_eq!(PcodeVarnode::Const(0, 4).size(), 4);
    assert_eq!(PcodeVarnode::Ram(0, 8).size(), 8);
    assert_eq!(PcodeVarnode::Register("rax".into(), 8).size(), 8);
    assert_eq!(PcodeVarnode::Unique(0, 1).size(), 1);
}

#[test]
fn pcode_insn_branch_classification() {
    let ins = PcodeInsn::new(PcodeOp::Branch, None, vec![], 0);
    assert!(ins.is_branch());
    let ins2 = PcodeInsn::new(
        PcodeOp::IntAdd,
        Some(PcodeVarnode::Const(0, 4)),
        vec![PcodeVarnode::Const(1, 4), PcodeVarnode::Const(2, 4)],
        1,
    );
    assert!(!ins2.is_branch());
    assert!(ins2.display().contains("IntAdd"));
}

#[test]
fn pcode_op_hash_eq() {
    use std::collections::HashSet;
    let mut s = HashSet::new();
    s.insert(PcodeOp::IntAdd);
    assert!(s.contains(&PcodeOp::IntAdd));
    assert!(!s.contains(&PcodeOp::IntSub));
}

// ─── VmBytecodeExtractor ──────────────────────────────────────────────────

#[test]
fn vm_bytecode_extractor_too_small() {
    let ex = VmBytecodeExtractor::new();
    assert!(ex.extract(&[1, 2, 3], 0, 0).is_none());
}

#[test]
fn vm_bytecode_extractor_offset_oob() {
    let ex = VmBytecodeExtractor::new();
    assert!(ex.extract(&[1, 2, 3], 100, 0).is_none());
}

#[test]
fn vm_bytecode_extractor_extracts() {
    let ex = VmBytecodeExtractor::new();
    let data: Vec<u8> = (0..200u8).collect();
    let bc = ex.extract(&data, 0, 0x4000).expect("extract should work");
    assert_eq!(bc.start_address, 0x4000);
    assert!(bc.len() >= 16);
}

#[test]
fn vm_bytecode_extractor_estimate_opcode_count() {
    let data = vec![0u8; 100];
    let n = VmBytecodeExtractor::estimate_opcode_count(&data);
    assert_eq!(n, 1);
    let n_empty = VmBytecodeExtractor::estimate_opcode_count(&[]);
    assert_eq!(n_empty, 0);
}

#[test]
fn vm_bytecode_extractor_fuzz_no_panic() {
    let ex = VmBytecodeExtractor::new();
    let mut g = make_lcg(0x5EED);
    for _ in 0..50 {
        let n = (g() as usize) % 4096;
        let data: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = ex.extract(&data, 0, 0);
        let _ = VmBytecodeExtractor::find_bytecode_regions(&data);
    }
}

// ─── VmProtectorDetector ──────────────────────────────────────────────────

#[test]
fn protector_detector_empty() {
    let r = VmProtectorDetector::detect(&[]);
    assert!(r.iter().all(|d| d.confidence <= 1.0));
}

#[test]
fn protector_detector_vmprotect_marker() {
    // Provide a marker string; non-PE so no section names.
    let mut data = vec![0u8; 200];
    data.extend(b"VMProtect");
    data.extend(b"VirtualProtect");
    let r = VmProtectorDetector::detect(&data);
    assert!(r.iter().any(|d| d.protector_name == "VMProtect"));
}

#[test]
fn protector_detection_with_evidence_builder() {
    let d = VmDetection::new("X", 0.5).with_evidence("foo");
    assert_eq!(d.evidence, vec!["foo".to_string()]);
    assert_eq!(d.protector_name, "X");
    assert_eq!(d.confidence, 0.5);
}

#[test]
fn protector_detection_add_evidence() {
    let mut d = VmDetection::new("X", 0.1);
    d.add_evidence("a");
    d.add_evidence("b");
    assert_eq!(d.evidence.len(), 2);
}

#[test]
fn protector_get_section_names_not_pe() {
    assert!(VmProtectorDetector::get_section_names(&[]).is_empty());
    assert!(VmProtectorDetector::get_section_names(&[0u8; 100]).is_empty());
    let mut data = vec![0u8; 100];
    data[0] = b'X';
    data[1] = b'Y';
    assert!(VmProtectorDetector::get_section_names(&data).is_empty());
}

#[test]
fn protector_fuzz_no_panic() {
    let mut g = make_lcg(0xBEEF_0001);
    for _ in 0..50 {
        let n = (g() as usize) % 4096;
        let data: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let _ = VmProtectorDetector::detect(&data);
        let _ = VmProtectorDetector::get_section_names(&data);
    }
}

// ─── BytecodeCandidate ────────────────────────────────────────────────────

#[test]
fn bytecode_candidate_new() {
    let data: Vec<u8> = (0..200u8).collect();
    let c = BytecodeCandidate::new(&data, 0x100);
    assert_eq!(c.offset, 0x100);
    assert_eq!(c.size, data.len());
    assert!(c.entropy > 0.0);
}

#[test]
fn bytecode_candidate_empty() {
    let c = BytecodeCandidate::new(&[], 0);
    assert_eq!(c.size, 0);
    assert_eq!(c.entropy, 0.0);
    assert_eq!(c.likely_handler_count, 0);
}

// ─── HandlerNode / HandlerEdge / HandlerGraphBuilder ──────────────────────

#[test]
fn handler_node_dispatcher_flag() {
    let d = HandlerNode::new(0x1000, 0, None, "dispatcher");
    assert!(d.is_dispatcher());
    let h = HandlerNode::new(0x2000, 32, Some(0x10), "arithmetic");
    assert!(!h.is_dispatcher());
}

#[test]
fn handler_edge_forward_back() {
    let f = HandlerEdge::forward(0x42);
    assert_eq!(f.opcode_value, Some(0x42));
    assert!(!f.is_back_edge);
    let b = HandlerEdge::back();
    assert!(b.is_back_edge);
    assert!(b.opcode_value.is_none());
}

#[test]
fn handler_graph_builder_dispatcher_only_on_empty() {
    let g = HandlerGraphBuilder::build_handler_graph(0x0040_1000, &[]);
    assert_eq!(g.node_count(), 1);
    assert_eq!(g.edge_count(), 0);
    let dot = HandlerGraphBuilder::export_dot(&g);
    assert!(dot.contains("digraph vm_handlers"));
    assert!(dot.contains("DISPATCHER"));
}

#[test]
fn handler_graph_builder_with_handler_pattern() {
    // PUSH rax (0x50) + indirect JMP (0xFF 0xE0) within 64 bytes
    let mut code = vec![0u8; 128];
    code[0] = 0x50;
    code[10] = 0xFF;
    code[11] = 0xE0;
    let g = HandlerGraphBuilder::build_handler_graph(0x1000, &code);
    assert!(g.node_count() >= 2);
    // forward + back edges
    assert!(g.edge_count() >= 2);
}

// ─── VmAnalysisReport / VmDeobfPipeline ──────────────────────────────────

#[test]
fn vm_deobf_pipeline_empty() {
    let r = VmDeobfPipeline::analyze(&[]);
    assert!(!r.recommendations().is_empty());
}

#[test]
fn vm_deobf_pipeline_with_marker() {
    let mut data = vec![0u8; 1024];
    data.extend(b"VMProtect");
    data.extend(b"VirtualProtect");
    let r = VmDeobfPipeline::analyze(&data);
    let recs = r.recommendations();
    assert!(recs.iter().any(|s| s.contains("VmLifterPipeline")));
}

#[test]
fn vm_deobf_pipeline_fuzz() {
    let mut g = make_lcg(0xABCD_EF01);
    for _ in 0..20 {
        let n = (g() as usize) % 2048;
        let data: Vec<u8> = (0..n).map(|_| g() as u8).collect();
        let r = VmDeobfPipeline::analyze(&data);
        let _ = r.recommendations();
    }
}

// ─── HandlerKind Hash/Eq pairs ────────────────────────────────────────────

#[test]
fn handler_kind_hash_eq_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let kinds = [
        HandlerKind::Arithmetic,
        HandlerKind::Logic,
        HandlerKind::Load,
        HandlerKind::Store,
        HandlerKind::ControlFlow,
        HandlerKind::StackOp,
        HandlerKind::Compare,
        HandlerKind::Unknown,
    ];
    for k in &kinds {
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        k.hash(&mut h1);
        k.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        assert_eq!(k, k);
    }
    // 30+ pair comparisons
    let mut g = make_lcg(0x77);
    for _ in 0..40 {
        let a = kinds[(g() as usize) % kinds.len()];
        let b = kinds[(g() as usize) % kinds.len()];
        if a == b {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            a.hash(&mut h1);
            b.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }
}

// ─── Send + Sync threaded stress ─────────────────────────────────────────

#[test]
fn vmlifter_send_sync_stress() {
    let lifter = Arc::new(VmLifter::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let lifter = Arc::clone(&lifter);
        handles.push(thread::spawn(move || {
            let mut g = make_lcg(0xABCD ^ (t * 0x1111));
            for _ in 0..100 {
                let n = (g() as usize) % 64;
                let bc: Vec<u8> = (0..n).map(|_| g() as u8).collect();
                let _ = lifter.lift(&bc);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn vmdetector_send_sync_stress() {
    let det = Arc::new(VmDetector::new());
    let mut handles = Vec::new();
    for t in 0..4u64 {
        let det = Arc::clone(&det);
        handles.push(thread::spawn(move || {
            let mut g = make_lcg(0xF0F0 ^ (t * 0x2222));
            for _ in 0..100 {
                let n = (g() as usize) % 128;
                let data: Vec<u8> = (0..n).map(|_| g() as u8).collect();
                let _ = det.detect(&data);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

// ─── misc compatibility ─────────────────────────────────────────────────

#[test]
fn run_pass_does_not_panic() {
    run_pass();
}
