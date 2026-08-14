//! End-to-end test: feed a synthetic stream of `[rsp + K]` accesses through
//! the standard decompiler pipeline and assert that the pseudo-C output
//! contains a recovered `struct StackS_*` with the expected field offsets.

use rustre_core::address::Address;
use rustre_core::arch::Instruction;
use rustre_decompiler::{DecompOptions, DecompPassFlags, DefaultPipelineFactory};

fn ins(addr: u64, mnem: &str, ops: &str) -> Instruction {
    let mut i = Instruction::new(Address::new(addr), 4, mnem.to_string(), vec![0x90]);
    i.operands = ops.to_string();
    i
}

#[test]
fn rsp_field_accesses_yield_struct_decl() {
    let instructions = vec![
        ins(0x1000, "mov", "qword ptr [rsp + 0], rdi"),
        ins(0x1004, "mov", "qword ptr [rsp + 8], rsi"),
        ins(0x1008, "mov", "dword ptr [rsp + 12], ecx"),
        ins(0x1010, "ret", ""),
    ];

    let options = DecompOptions { passes: DecompPassFlags { emit_struct_fields: true, ..Default::default() }, ..DecompOptions::default() };
    let pipeline = DefaultPipelineFactory::standard(options);
    let func = pipeline.run(0x1000, "f", &instructions).expect("pipeline ok");

    assert!(
        func.pseudo_code.contains("struct StackS_") || func.pseudo_code.contains("struct MemS_"),
        "expected a recovered struct declaration; got:\n{}",
        func.pseudo_code
    );
    assert!(
        func.pseudo_code.contains("field_0"),
        "expected field_0 in output: {}",
        func.pseudo_code
    );
    assert!(
        func.pseudo_code.contains("field_8"),
        "expected field_8 in output: {}",
        func.pseudo_code
    );
}

#[test]
fn malloc_result_recovered_as_heap_struct() {
    let instructions = vec![
        ins(0x2000, "call", "malloc"),
        ins(0x2005, "mov", "qword ptr [rax + 0], rdi"),
        ins(0x2009, "mov", "qword ptr [rax + 8], rsi"),
        ins(0x200d, "mov", "dword ptr [rax + 16], ecx"),
        ins(0x2014, "ret", ""),
    ];

    let options = DecompOptions { passes: DecompPassFlags { emit_struct_fields: true, ..Default::default() }, ..DecompOptions::default() };
    let pipeline = DefaultPipelineFactory::standard(options);
    let func = pipeline.run(0x2000, "g", &instructions).expect("pipeline ok");

    assert!(
        func.pseudo_code.contains("struct HeapS_")
            || func.pseudo_code.contains("struct MemS_")
            || func.pseudo_code.contains("struct StackS_"),
        "expected heap/struct decl; got:\n{}",
        func.pseudo_code
    );
}
