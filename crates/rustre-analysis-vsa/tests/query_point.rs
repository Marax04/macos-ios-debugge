use std::collections::HashMap;

use rustre_analysis_vsa::{
    PointConfidence, PointValueKind, RegisterState, StridedInterval, ValueSetResult, VsaResult,
    query_point,
};

fn make_result(reg: &str, si: StridedInterval, addr: u64) -> VsaResult {
    let mut rs = RegisterState::default();
    rs.set(reg, si);
    let inner = ValueSetResult {
        register_states: vec![rs],
        memory: Default::default(),
        converged: true,
        iterations: 0,
    };
    let mut addr_to_block = HashMap::new();
    addr_to_block.insert(addr, 0usize);
    VsaResult::new(inner, addr_to_block)
}

#[test]
fn query_point_register_singleton_is_const_high() {
    let addr = 0x401000u64;
    let result = make_result("rax", StridedInterval::singleton(0x42), addr);
    let q = query_point(&result, addr, "rax");
    assert_eq!(q.confidence, PointConfidence::High);
    assert_eq!(q.values.len(), 1);
    assert_eq!(q.values[0].kind, PointValueKind::Const);
    assert_eq!(q.values[0].repr, "0x42");
}

#[test]
fn query_point_register_range_is_range_medium() {
    let addr = 0x401000u64;
    let result = make_result("rcx", StridedInterval::new(0x10, 0x20, 4), addr);
    let q = query_point(&result, addr, "rcx");
    assert_eq!(q.confidence, PointConfidence::Medium);
    assert_eq!(q.values[0].kind, PointValueKind::Range);
    assert!(q.values[0].repr.starts_with('['));
}

#[test]
fn query_point_unknown_address_is_top() {
    let result = make_result("rax", StridedInterval::singleton(7), 0x1000);
    let q = query_point(&result, 0xDEAD, "rax");
    assert_eq!(q.confidence, PointConfidence::Low);
    assert_eq!(q.values[0].kind, PointValueKind::Unknown);
}

#[test]
fn query_point_memory_target_offsets_base_register() {
    let addr = 0x401000u64;
    let result = make_result("rsp", StridedInterval::singleton(0x7fff_0000), addr);
    let q = query_point(&result, addr, "[rsp+8]");
    assert_eq!(q.confidence, PointConfidence::Low);
    assert!(q.values[0].repr.starts_with("addr="));
    assert!(q.values[0].repr.contains("0x7fff0008"));
}

#[test]
fn query_point_memory_target_negative_offset() {
    let addr = 0x401000u64;
    let result = make_result("rbp", StridedInterval::singleton(0x7fff_0100), addr);
    let q = query_point(&result, addr, "[rbp-0x10]");
    assert!(q.values[0].repr.contains("0x7fff00f0"));
}
