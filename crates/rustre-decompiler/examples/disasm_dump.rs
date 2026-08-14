//! Dump raw x86 disassembly (mnemonic + operands) for one function.
//! Usage: disasm_dump <binary_path> <hex_addr>
//! Used to inspect operand syntax feeding jump-table detection.

use std::path::Path;
use std::process::ExitCode;

use rustre_decompiler::binary_entry::{disassemble_function_x86, load_binary, slice_at_va};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <binary> <hex_addr>", args[0]);
        return ExitCode::from(2);
    }
    let addr = u64::from_str_radix(args[2].trim_start_matches("0x"), 16).expect("hex addr");
    let load = load_binary(Path::new(&args[1])).expect("load");
    let (base, slice) = slice_at_va(&load, addr).expect("addr mapped");
    let insns = disassemble_function_x86(slice, base, 64, 4096, 400).expect("disasm");
    for i in &insns {
        println!("{:#010x}  {:<10} {}", i.address.as_u64(), i.mnemonic, i.operands);
    }
    let tables = rustre_decompiler::jump_table::detect_all_jump_tables(&insns);
    println!("--- detected jump tables: {} ---", tables.len());
    for t in &tables {
        println!("detect: {t:?}");
        match rustre_decompiler::binary_entry::resolve_jump_table(&load, t) {
            Some(r) => println!("resolve: OK cases={:?} default={:?} arith={:?}", r.cases, r.default_target, r.arith_addrs),
            None => println!("resolve: NONE"),
        }
    }
    let lo = insns.first().map_or(0, |i| i.address.as_u64());
    let hi = insns.last().map_or(0, |i| i.address.as_u64());
    println!("--- fn instr range: {lo:#x}..={hi:#x} ---");
    ExitCode::SUCCESS
}
