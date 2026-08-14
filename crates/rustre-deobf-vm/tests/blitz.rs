//! Comprehensive integration tests for the `rustre-deobf-vm` public API.
//!
//! Focuses on the types and free functions re-exported from `lib.rs`.

use std::collections::HashMap;

use rustre_core::address::Address;
use rustre_deobf_vm::{
    deprotect_simple, read_u16_le, read_u32_le, read_u64_le, run_pass, BytecodeCandidate,
    HandlerCluster, HandlerClusterer, HandlerEdge, HandlerGraphBuilder, HandlerKind, HandlerNode,
    PcodeInsn, PcodeOp, PcodeVarnode, VirtualMachineState, VmAnalysisReport, VmArch, VmBytecode,
    VmBytecodeExtractor, VmConfidence, VmDeobfPipeline, VmDetection, VmDetectionResult, VmDetector,
    VmDispatcher, VmDispatcherDetector, VmHandler, VmLifter, VmLifterConfig, VmProtectorDetector,
    VmSemanticOp,
};

// ──────────────────────────────────────────────────────────────────────────
// Primitive helpers
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn read_u64_le_full() {
    let b = [1u8, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(read_u64_le(&b), 1);
}

#[test]
fn read_u64_le_short_returns_zero() {
    assert_eq!(read_u64_le(&[1, 2, 3]), 0);
    assert_eq!(read_u64_le(&[]), 0);
}

#[test]
fn read_u32_le_full() {
    assert_eq!(read_u32_le(&[0xEF, 0xBE, 0xAD, 0xDE]), 0xDEAD_BEEF);
}

#[test]
fn read_u32_le_short_returns_zero() {
    assert_eq!(read_u32_le(&[1, 2, 3]), 0);
}

#[test]
fn read_u16_le_full_and_short() {
    assert_eq!(read_u16_le(&[0x34, 0x12]), 0x1234);
    assert_eq!(read_u16_le(&[1]), 0);
    assert_eq!(read_u16_le(&[]), 0);
}

// ──────────────────────────────────────────────────────────────────────────
// VirtualMachineState
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn vm_state_new_defaults() {
    let s = VirtualMachineState::new();
    assert_eq!(s.regs, [0; 8]);
    assert_eq!(s.pc, 0);
    assert!(s.stack.is_empty());
    assert_eq!(s.flags, 0);
    assert!(s.memory.is_empty());
}

#[test]
fn vm_state_default_eq_new() {
    assert_eq!(VirtualMachineState::default(), VirtualMachineState::new());
}

#[test]
fn vm_state_reset_clears_all() {
    let mut s = VirtualMachineState::new();
    s.regs[3] = 7;
    s.pc = 0x40;
    s.push(5);
    s.flags = 0xF;
    s.mem_write_byte(0x100, 0xAB);
    s.reset();
    assert_eq!(s, VirtualMachineState::new());
}

#[test]
fn vm_state_push_pop_lifo() {
    let mut s = VirtualMachineState::new();
    s.push(1);
    s.push(2);
    s.push(3);
    assert_eq!(s.pop(), Some(3));
    assert_eq!(s.pop(), Some(2));
    assert_eq!(s.pop(), Some(1));
    assert_eq!(s.pop(), None);
}

#[test]
fn vm_state_mem_byte_unmapped_zero() {
    let s = VirtualMachineState::new();
    assert_eq!(s.mem_read_byte(0xDEAD), 0);
}

#[test]
fn vm_state_mem_u32_roundtrip() {
    let mut s = VirtualMachineState::new();
    s.mem_write_u32(0x10, 0xCAFE_BABE);
    assert_eq!(s.mem_read_u32(0x10), 0xCAFE_BABE);
    // Little-endian byte order check.
    assert_eq!(s.mem_read_byte(0x10), 0xBE);
    assert_eq!(s.mem_read_byte(0x11), 0xBA);
    assert_eq!(s.mem_read_byte(0x12), 0xFE);
    assert_eq!(s.mem_read_byte(0x13), 0xCA);
}

#[test]
fn vm_state_flags_zero_and_carry() {
    let mut s = VirtualMachineState::new();
    s.set_zero_flag(0);
    assert!(s.zero_flag());
    s.set_zero_flag(42);
    assert!(!s.zero_flag());
    assert!(!s.carry_flag());
    s.flags |= 2;
    assert!(s.carry_flag());
}

#[test]
fn vm_state_serde_roundtrip() {
    let mut s = VirtualMachineState::new();
    s.regs[0] = 1;
    s.pc = 0xAAAA;
    s.push(99);
    let j = serde_json::to_string(&s).unwrap();
    let back: VirtualMachineState = serde_json::from_str(&j).unwrap();
    assert_eq!(s, back);
}

// ──────────────────────────────────────────────────────────────────────────
// VmDispatcher / VmDispatcherDetector
// ──────────────────────────────────────────────────────────────────────────

fn make_dispatcher_block(sig: &[u8], entry: u64, table: u64, count: u64) -> Vec<u8> {
    let mut b = vec![0x90, 0x90];
    b.extend_from_slice(sig);
    b.extend_from_slice(&entry.to_le_bytes());
    b.extend_from_slice(&table.to_le_bytes());
    b.extend_from_slice(&count.to_le_bytes());
    b.push(0x90);
    b
}

#[test]
fn dispatcher_detector_sig_a() {
    let blk = make_dispatcher_block(&[0x31, 0xC0, 0xFF, 0x24], 0x100, 0x200, 7);
    let d = VmDispatcherDetector::new().detect_dispatcher(&[blk]).unwrap();
    assert_eq!(d.entry, Address::new(0x100));
    assert_eq!(d.handler_table_base, Address::new(0x200));
    assert_eq!(d.handler_count, 7);
}

#[test]
fn dispatcher_detector_sig_b() {
    let blk = make_dispatcher_block(&[0x48, 0x81, 0xC3, 0xFF], 0xAA, 0xBB, 3);
    let d = VmDispatcherDetector::detect(&[blk]).unwrap();
    assert_eq!(d.handler_count, 3);
}

#[test]
fn dispatcher_detector_none() {
    assert!(VmDispatcherDetector::detect(&[vec![0u8; 64]]).is_none());
}

#[test]
fn dispatcher_detector_empty_input() {
    let empty: [Vec<u8>; 0] = [];
    assert!(VmDispatcherDetector::new().detect_dispatcher(&empty).is_none());
}

#[test]
fn dispatcher_detector_too_short_block_rejected() {
    // Has signature but no following 24 bytes.
    let blk = vec![0x31, 0xC0, 0xFF, 0x24, 0x00];
    assert!(VmDispatcherDetector::detect(&[blk]).is_none());
}

#[test]
fn vm_dispatcher_copy_eq_hash() {
    let a = VmDispatcher {
        entry: Address::new(1),
        handler_table_base: Address::new(2),
        handler_count: 3,
    };
    let b = a;
    assert_eq!(a, b);
}

// ──────────────────────────────────────────────────────────────────────────
// VmHandler / HandlerKind / HandlerCluster(er)
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn handler_new_and_predicates() {
    let h = VmHandler::new(
        2,
        Address::new(0x400),
        vec![0x90, 0x90],
        HandlerKind::Arithmetic,
        "add",
        2,
        1,
    );
    assert_eq!(h.index, 2);
    assert!(h.is_arithmetic());
    assert!(!h.is_control_flow());
    assert_eq!(h.description, "add");
}

#[test]
fn handler_entropy_empty_is_zero() {
    let h = VmHandler::new(0, Address::new(0), vec![], HandlerKind::Unknown, "", 0, 0);
    assert_eq!(h.prologue_entropy(), 0.0);
}

#[test]
fn handler_entropy_uniform_is_zero() {
    let h = VmHandler::new(
        0,
        Address::new(0),
        vec![0x90; 32],
        HandlerKind::Unknown,
        "",
        0,
        0,
    );
    assert_eq!(h.prologue_entropy(), 0.0);
}

#[test]
fn handler_entropy_diverse_positive() {
    let h = VmHandler::new(
        0,
        Address::new(0),
        (0u8..=15).collect(),
        HandlerKind::Unknown,
        "",
        0,
        0,
    );
    assert!(h.prologue_entropy() > 3.9);
}

#[test]
fn handler_kind_hash_eq() {
    let mut m: HashMap<HandlerKind, u32> = HashMap::new();
    m.insert(HandlerKind::Arithmetic, 1);
    m.insert(HandlerKind::Arithmetic, 2);
    assert_eq!(m.len(), 1);
    assert_eq!(m[&HandlerKind::Arithmetic], 2);
}

#[test]
fn handler_cluster_new_and_add() {
    let mut c = HandlerCluster::new("arith", HandlerKind::Arithmetic);
    assert_eq!(c.size(), 0);
    c.add(1);
    c.add(2);
    assert_eq!(c.size(), 2);
    assert_eq!(c.handler_indices, vec![1, 2]);
    assert_eq!(c.label, "arith");
}

#[test]
fn handler_clusterer_groups_by_kind() {
    let h = |i, k| VmHandler::new(i, Address::new(0), vec![0x10, 0x20], k, "", 0, 0);
    let handlers = vec![
        h(0, HandlerKind::Arithmetic),
        h(1, HandlerKind::Arithmetic),
        h(2, HandlerKind::ControlFlow),
    ];
    let clusters = HandlerClusterer::new().cluster(&handlers);
    assert_eq!(clusters.len(), 2);
    // Sorted alphabetically by label.
    let total: usize = clusters.iter().map(|c| c.size()).sum();
    assert_eq!(total, 3);
}

#[test]
fn handler_clusterer_empty() {
    let clusters = HandlerClusterer::default().cluster(&[]);
    assert!(clusters.is_empty());
}

// ──────────────────────────────────────────────────────────────────────────
// VmDetector / VmDetectionResult / VmConfidence
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn vm_confidence_ordering() {
    assert!(VmConfidence::None < VmConfidence::Low);
    assert!(VmConfidence::Low < VmConfidence::Medium);
    assert!(VmConfidence::Medium < VmConfidence::High);
    assert!(VmConfidence::High < VmConfidence::Definitive);
}

#[test]
fn vm_detector_none_on_nops() {
    let r = VmDetector::new().detect(&[0x90u8; 64]);
    assert_eq!(r.confidence, VmConfidence::None);
    assert_eq!(r.dispatcher_count, 0);
    assert!(r.arch_hints.is_empty());
}

#[test]
fn vm_detector_finds_indirect_jmp() {
    let mut data = vec![0u8; 8];
    data.extend_from_slice(&[0xFF, 0xE0]); // jmp eax
    let r = VmDetector::new().detect(&data);
    assert_eq!(r.dispatcher_count, 1);
    assert!(r.dispatcher_offset.is_some());
}

#[test]
fn vm_detector_arch_hints_vmprotect() {
    let mut data = b"VMProtect".to_vec();
    data.extend_from_slice(&[0x90; 32]);
    let r = VmDetector::new().detect(&data);
    assert!(r
        .arch_hints
        .iter()
        .any(|h| h.contains("VMProtect")));
}

#[test]
fn vm_detector_cpuid_hint() {
    let data = vec![0x0F, 0xA2, 0, 0, 0];
    let r = VmDetector::new().detect(&data);
    assert!(r.arch_hints.iter().any(|h| h.contains("CPUID")));
}

// ──────────────────────────────────────────────────────────────────────────
// VmBytecode
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn bytecode_empty() {
    let bc = VmBytecode::new(vec![], 0, 1);
    assert!(bc.is_empty());
    assert!(!bc.is_non_empty());
    assert_eq!(bc.len(), 0);
    assert_eq!(bc.distinct_opcodes, 0);
    assert_eq!(bc.entropy, 0.0);
    assert!(!bc.looks_encrypted());
}

#[test]
fn bytecode_distinct_counts() {
    let bc = VmBytecode::new(vec![0xAA, 0xBB, 0xAA, 0xCC], 0x10, 1);
    assert_eq!(bc.len(), 4);
    assert_eq!(bc.distinct_opcodes, 3);
    assert!(bc.is_non_empty());
}

#[test]
fn bytecode_zero_width_handled() {
    let bc = VmBytecode::new(vec![1, 2, 3], 0, 0);
    assert_eq!(bc.distinct_opcodes, 0);
}

#[test]
fn bytecode_high_entropy_looks_encrypted() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    let bc = VmBytecode::new(bytes, 0, 1);
    assert!(bc.entropy > 7.9);
    assert!(bc.looks_encrypted());
}

#[test]
fn bytecode_uniform_low_entropy() {
    let bc = VmBytecode::new(vec![0u8; 1024], 0, 1);
    assert_eq!(bc.entropy, 0.0);
    assert!(!bc.looks_encrypted());
}

// ──────────────────────────────────────────────────────────────────────────
// VmSemanticOp
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn semantic_op_classifications() {
    assert!(VmSemanticOp::Jmp.is_control_flow());
    assert!(VmSemanticOp::Jz.is_control_flow());
    assert!(VmSemanticOp::Call.is_control_flow());
    assert!(VmSemanticOp::Ret.is_control_flow());
    assert!(VmSemanticOp::Halt.is_control_flow());
    assert!(!VmSemanticOp::Add.is_control_flow());
    assert!(VmSemanticOp::Add.is_alu());
    assert!(VmSemanticOp::Shl.is_alu());
    assert!(!VmSemanticOp::Nop.is_alu());
}

#[test]
fn semantic_op_stack_delta() {
    assert_eq!(VmSemanticOp::PushImm(0).stack_delta(), 1);
    assert_eq!(VmSemanticOp::PushReg(0).stack_delta(), 1);
    assert_eq!(VmSemanticOp::PopReg(0).stack_delta(), -1);
    assert_eq!(VmSemanticOp::Add.stack_delta(), -1);
    assert_eq!(VmSemanticOp::Store32.stack_delta(), -2);
    assert_eq!(VmSemanticOp::Nop.stack_delta(), 0);
    assert_eq!(VmSemanticOp::Not.stack_delta(), 0);
}

// ──────────────────────────────────────────────────────────────────────────
// VmLifter / VmLifterConfig
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn lifter_config_default() {
    let c = VmLifterConfig::default();
    assert_eq!(c.opcode_width, 1);
    assert!(c.little_endian);
    assert_eq!(c.max_instructions, 65536);
}

#[test]
fn lifter_lift_simple_program() {
    let lifter = VmLifter::new();
    let bc = vec![
        0x01, 5, 0, 0, 0, // PushImm(5)
        0x01, 7, 0, 0, 0, // PushImm(7)
        0x10, // Add
        0xFF, // Halt
    ];
    let ops = lifter.lift(&bc).unwrap();
    assert_eq!(ops.len(), 4);
    assert_eq!(ops[0], VmSemanticOp::PushImm(5));
    assert_eq!(ops[1], VmSemanticOp::PushImm(7));
    assert_eq!(ops[2], VmSemanticOp::Add);
    assert_eq!(ops[3], VmSemanticOp::Halt);
}

#[test]
fn lifter_truncated_pushimm_errors() {
    let lifter = VmLifter::new();
    let bc = vec![0x01, 1, 2]; // PushImm but only 2 of 4 bytes
    assert!(lifter.lift(&bc).is_err());
}

#[test]
fn lifter_truncated_pushreg_errors() {
    let lifter = VmLifter::new();
    assert!(lifter.lift(&[0x02]).is_err());
}

#[test]
fn lifter_truncated_popreg_errors() {
    let lifter = VmLifter::new();
    assert!(lifter.lift(&[0x03]).is_err());
}

#[test]
fn lifter_unknown_opcode() {
    let lifter = VmLifter::new();
    let ops = lifter.lift(&[0x77]).unwrap();
    assert_eq!(ops, vec![VmSemanticOp::Unknown(0x77)]);
}

#[test]
fn lifter_opcode_remap() {
    let mut map = HashMap::new();
    map.insert(0xAA, 0x10); // 0xAA -> Add
    let lifter = VmLifter::new().with_opcode_map(map);
    assert_eq!(lifter.remap(0xAA), 0x10);
    assert_eq!(lifter.remap(0x10), 0x10);
    let ops = lifter.lift(&[0xAA, 0xFF]).unwrap();
    assert_eq!(ops[0], VmSemanticOp::Add);
}

#[test]
fn lifter_simulate_add() {
    let lifter = VmLifter::new();
    let bc = vec![0x01, 10, 0, 0, 0, 0x01, 32, 0, 0, 0, 0x10, 0xFF];
    let ops = lifter.lift(&bc).unwrap();
    let s = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
    assert_eq!(s.stack.last().copied(), Some(42));
}

#[test]
fn lifter_simulate_xor_sets_zero_flag() {
    let lifter = VmLifter::new();
    let bc = vec![0x01, 5, 0, 0, 0, 0x01, 5, 0, 0, 0, 0x15, 0xFF];
    let ops = lifter.lift(&bc).unwrap();
    let s = lifter.simulate(&ops, VirtualMachineState::new()).unwrap();
    assert!(s.zero_flag());
    assert_eq!(s.stack.last().copied(), Some(0));
}

#[test]
fn lifter_simulate_stack_underflow_errors() {
    let lifter = VmLifter::new();
    let ops = vec![VmSemanticOp::Add];
    assert!(lifter
        .simulate(&ops, VirtualMachineState::new())
        .is_err());
}

#[test]
fn lifter_simulate_load_store() {
    let lifter = VmLifter::new();
    let mut s = VirtualMachineState::new();
    s.mem_write_u32(0x100, 0xDEAD_BEEF);
    let ops = vec![VmSemanticOp::PushImm(0x100), VmSemanticOp::Load32];
    let out = lifter.simulate(&ops, s).unwrap();
    assert_eq!(out.stack.last().copied(), Some(0xDEAD_BEEF));
}

// ──────────────────────────────────────────────────────────────────────────
// VmArch
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn vm_arch_stack_machine() {
    let a = VmArch::stack_machine(20);
    assert_eq!(a.arch_type, "stack-machine");
    assert_eq!(a.register_count, 0);
    assert!(a.has_call_stack);
    assert_eq!(a.opcode_count, 20);
    assert_eq!(a.complexity_score, 60);
}

#[test]
fn vm_arch_register_machine() {
    let a = VmArch::register_machine(8, 30);
    assert_eq!(a.arch_type, "register-machine");
    assert_eq!(a.register_count, 8);
    assert!(!a.has_call_stack);
    assert_eq!(a.complexity_score, 30 * 2 + 8 * 4);
}

#[test]
fn vm_arch_summary_contains_fields() {
    let s = VmArch::stack_machine(5).summary();
    assert!(s.contains("stack-machine"));
    assert!(s.contains("LE"));
}

// ──────────────────────────────────────────────────────────────────────────
// PcodeInsn / PcodeOp / PcodeVarnode
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn pcode_varnode_size() {
    assert_eq!(PcodeVarnode::Unique(0, 4).size(), 4);
    assert_eq!(PcodeVarnode::Register("rax".into(), 8).size(), 8);
    assert_eq!(PcodeVarnode::Const(0, 2).size(), 2);
    assert_eq!(PcodeVarnode::Ram(0, 1).size(), 1);
}

#[test]
fn pcode_insn_is_branch() {
    let i = PcodeInsn::new(PcodeOp::Branch, None, vec![], 0);
    assert!(i.is_branch());
    let i2 = PcodeInsn::new(PcodeOp::IntAdd, None, vec![], 1);
    assert!(!i2.is_branch());
}

#[test]
fn pcode_insn_display_nonempty() {
    let i = PcodeInsn::new(
        PcodeOp::IntAdd,
        Some(PcodeVarnode::Register("r1".into(), 4)),
        vec![PcodeVarnode::Const(1, 4), PcodeVarnode::Const(2, 4)],
        7,
    );
    let s = i.display();
    assert!(s.contains("IntAdd"));
}

// ──────────────────────────────────────────────────────────────────────────
// VmProtectorDetector / VmDetection
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn vm_detection_builder() {
    let d = VmDetection::new("X", 0.5).with_evidence("e1");
    assert_eq!(d.protector_name, "X");
    assert_eq!(d.confidence, 0.5);
    assert_eq!(d.evidence, vec!["e1".to_string()]);
}

#[test]
fn vm_detection_add_evidence_mut() {
    let mut d = VmDetection::new("Y", 0.0);
    d.add_evidence("hello");
    assert_eq!(d.evidence.len(), 1);
}

#[test]
fn protector_detector_section_names_non_pe_empty() {
    assert!(VmProtectorDetector::get_section_names(&[0u8; 4]).is_empty());
    assert!(VmProtectorDetector::get_section_names(b"not a pe ").is_empty());
}

#[test]
fn protector_detector_no_detections_on_zero() {
    let r = VmProtectorDetector::detect(&[0u8; 64]);
    assert!(r.is_empty());
}

#[test]
fn protector_detector_finds_vmprotect_marker() {
    let mut data = vec![0u8; 256];
    data.extend_from_slice(b"VMProtect");
    data.extend_from_slice(b"VirtualProtect");
    let r = VmProtectorDetector::detect(&data);
    assert!(r.iter().any(|d| d.protector_name == "VMProtect"));
}

#[test]
fn protector_detector_finds_themida_marker() {
    let mut data = vec![0u8; 64];
    data.extend_from_slice(b"Themida marker here");
    let r = VmProtectorDetector::detect(&data);
    assert!(r.iter().any(|d| d.protector_name == "Themida/WinLicense"));
}

// ──────────────────────────────────────────────────────────────────────────
// VmBytecodeExtractor / BytecodeCandidate
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn extractor_new_defaults() {
    let e = VmBytecodeExtractor::new();
    assert_eq!(e.min_length, 16);
    assert_eq!(e.max_length, 1024 * 1024);
}

#[test]
fn extractor_default_zero_min_length() {
    // Default::default() produces zero values.
    let e = VmBytecodeExtractor::default();
    assert_eq!(e.min_length, 0);
}

#[test]
fn extractor_extract_oob_returns_none() {
    let e = VmBytecodeExtractor::new();
    assert!(e.extract(&[1, 2, 3], 100, 0).is_none());
}

#[test]
fn extractor_extract_below_min_returns_none() {
    let e = VmBytecodeExtractor::new();
    // Only 8 bytes < min_length=16.
    let data = vec![0xAAu8; 8];
    assert!(e.extract(&data, 0, 0).is_none());
}

#[test]
fn extractor_extract_returns_bytecode() {
    let e = VmBytecodeExtractor::new();
    let data: Vec<u8> = (0u8..64).collect();
    let bc = e.extract(&data, 0, 0x1000).unwrap();
    assert!(bc.len() >= 16);
    assert_eq!(bc.start_address, 0x1000);
}

#[test]
fn extractor_estimate_opcode_count_empty() {
    assert_eq!(VmBytecodeExtractor::estimate_opcode_count(&[]), 0);
}

#[test]
fn extractor_estimate_opcode_count_uniform() {
    // A single byte repeated many times => 1 distinct opcode above threshold.
    let v = vec![0xAAu8; 100];
    assert_eq!(VmBytecodeExtractor::estimate_opcode_count(&v), 1);
}

#[test]
fn bytecode_candidate_new_computes_metadata() {
    let data: Vec<u8> = (0u8..64).cycle().take(512).collect();
    let c = BytecodeCandidate::new(&data, 0x42);
    assert_eq!(c.offset, 0x42);
    assert_eq!(c.size, 512);
    assert!(c.entropy > 0.0);
}

// ──────────────────────────────────────────────────────────────────────────
// HandlerNode / HandlerEdge / HandlerGraphBuilder
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn handler_node_new_and_is_dispatcher() {
    let n = HandlerNode::new(0x100, 32, Some(0x10), "dispatcher");
    assert!(n.is_dispatcher());
    let n2 = HandlerNode::new(0x200, 16, None, "arithmetic");
    assert!(!n2.is_dispatcher());
}

#[test]
fn handler_edge_forward_and_back() {
    let f = HandlerEdge::forward(0x12);
    assert_eq!(f.opcode_value, Some(0x12));
    assert!(!f.is_back_edge);
    let b = HandlerEdge::back();
    assert!(b.is_back_edge);
    assert!(b.opcode_value.is_none());
}

#[test]
fn graph_builder_dispatcher_only_when_empty_code() {
    let g = HandlerGraphBuilder::build_handler_graph(0x1000, &[]);
    assert_eq!(g.node_count(), 1);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn graph_builder_export_dot_has_header() {
    let g = HandlerGraphBuilder::build_handler_graph(0x1000, &[]);
    let dot = HandlerGraphBuilder::export_dot(&g);
    assert!(dot.starts_with("digraph"));
    assert!(dot.contains("DISPATCHER"));
}

#[test]
fn graph_builder_finds_handler_pattern() {
    // PUSH rax (0x50) ... FF E0 (jmp eax)
    let mut code = vec![0x50, 0x90, 0x90, 0xFF, 0xE0];
    code.extend_from_slice(&[0x90u8; 16]);
    let g = HandlerGraphBuilder::new();
    let _ = g; // also exercise constructor
    let g2 = HandlerGraphBuilder::build_handler_graph(0x2000, &code);
    // Dispatcher + at least one handler.
    assert!(g2.node_count() >= 2);
}

// ──────────────────────────────────────────────────────────────────────────
// VmDeobfPipeline / VmAnalysisReport
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn pipeline_analyze_empty() {
    let r = VmDeobfPipeline::analyze(&[]);
    assert!(r.detections.is_empty());
    assert!(r.bytecode_regions.is_empty());
    assert_eq!(r.estimated_isa_size, 0);
    assert!(!r.analysis_notes.is_empty());
}

#[test]
fn pipeline_analyze_random_data() {
    let data: Vec<u8> = (0..4096).map(|i| (i * 7) as u8).collect();
    let r = VmDeobfPipeline::analyze(&data);
    let _ = r.recommendations();
}

#[test]
fn analysis_report_recommendations_default_contains_lifter_hint() {
    let r = VmAnalysisReport {
        detections: vec![],
        bytecode_regions: vec![],
        estimated_isa_size: 0,
        analysis_notes: vec![],
    };
    let recs = r.recommendations();
    assert!(recs.iter().any(|r| r.contains("VmLifterPipeline")));
}

#[test]
fn analysis_report_recommendations_vmprotect_specific() {
    let r = VmAnalysisReport {
        detections: vec![VmDetection::new("VMProtect", 0.9)],
        bytecode_regions: vec![],
        estimated_isa_size: 0,
        analysis_notes: vec![],
    };
    let recs = r.recommendations();
    assert!(recs.iter().any(|r| r.contains("VMProtect")));
}

#[test]
fn detection_result_serde_roundtrip() {
    let r = VmDetectionResult {
        confidence: VmConfidence::Medium,
        dispatcher_count: 1,
        handler_count: 4,
        arch_hints: vec!["a".into()],
        dispatcher_offset: Some(0x10),
    };
    let j = serde_json::to_string(&r).unwrap();
    let back: VmDetectionResult = serde_json::from_str(&j).unwrap();
    assert_eq!(back.confidence, VmConfidence::Medium);
    assert_eq!(back.handler_count, 4);
}

// ──────────────────────────────────────────────────────────────────────────
// Miscellaneous
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn deprotect_simple_returns_none_for_plain_data() {
    assert!(deprotect_simple(&[0u8; 64]).is_none());
}

#[test]
fn deprotect_simple_upx_magic_returns_none() {
    let mut d = vec![0u8; 64];
    d.extend_from_slice(b"UPX!");
    assert!(deprotect_simple(&d).is_none());
}

#[test]
fn run_pass_does_not_panic() {
    run_pass();
}

// ──────────────────────────────────────────────────────────────────────────
// Send + Sync bounds
// ──────────────────────────────────────────────────────────────────────────

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_types_are_send_sync() {
    assert_send_sync::<VirtualMachineState>();
    assert_send_sync::<VmDispatcher>();
    assert_send_sync::<VmDispatcherDetector>();
    assert_send_sync::<VmHandler>();
    assert_send_sync::<HandlerKind>();
    assert_send_sync::<HandlerCluster>();
    assert_send_sync::<HandlerClusterer>();
    assert_send_sync::<VmDetector>();
    assert_send_sync::<VmDetectionResult>();
    assert_send_sync::<VmConfidence>();
    assert_send_sync::<VmBytecode>();
    assert_send_sync::<VmLifter>();
    assert_send_sync::<VmLifterConfig>();
    assert_send_sync::<VmSemanticOp>();
    assert_send_sync::<VmArch>();
    assert_send_sync::<PcodeInsn>();
    assert_send_sync::<PcodeOp>();
    assert_send_sync::<PcodeVarnode>();
    assert_send_sync::<VmDetection>();
    assert_send_sync::<VmProtectorDetector>();
    assert_send_sync::<VmBytecodeExtractor>();
    assert_send_sync::<BytecodeCandidate>();
    assert_send_sync::<HandlerNode>();
    assert_send_sync::<HandlerEdge>();
    assert_send_sync::<HandlerGraphBuilder>();
    assert_send_sync::<VmAnalysisReport>();
    assert_send_sync::<VmDeobfPipeline>();
}
