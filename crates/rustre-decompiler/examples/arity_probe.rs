//! Diagnostic: print the recovered arity evidence for ONE function.
//!
//! Exists because the phantom-parameter investigation kept producing plausible
//! but wrong theories from reading code alone (a tail-call theory, an AT&T
//! operand-order theory, a stack-offset theory — all three were falsified).
//! This prints what the pipeline actually computes, so the next theory is
//! checked against evidence instead of inference.
//!
//! Usage: arity_probe <binary_path> <va-hex>

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <binary_path> <va-hex>", args[0]);
        return ExitCode::from(2);
    }
    let va = match u64::from_str_radix(args[2].trim_start_matches("0x"), 16) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bad va: {e}");
            return ExitCode::from(2);
        }
    };

    let load = match rustre_decompiler::binary_entry::load_binary(Path::new(&args[1])) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("load: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some((base, slice)) = rustre_decompiler::binary_entry::slice_at_va(&load, va) else {
        eprintln!("va not mapped");
        return ExitCode::FAILURE;
    };
    let instrs = match rustre_decompiler::binary_entry::disassemble_function_x86(slice, base, 64, 4096, 400) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("disassemble: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("instructions: {}", instrs.len());
    println!("--- first 6 raw (mnemonic | operands) ---");
    for ins in instrs.iter().take(6) {
        println!("  {:<10} | {}", ins.mnemonic, ins.operands);
    }

    println!("--- win64 register-arity path ---");
    println!("  win64_recovered_arity = {}", rustre_decompiler::win64_recovered_arity(&instrs));

    println!("--- callconv_bridge path ---");
    let lifted = rustre_decompiler::callconv_bridge::lift_instructions(&instrs);
    let stack_accesses: Vec<String> = lifted
        .iter()
        .filter_map(|d| format!("{d:?}").strip_prefix("StackArgAccess").map(|s| s.to_string()))
        .collect();
    println!("  StackArgAccess events: {} {:?}", stack_accesses.len(), stack_accesses);
    match rustre_decompiler::callconv_bridge::detect(
        &lifted,
        &rustre_analysis_callconv::Arch::X86_64,
        &rustre_analysis_callconv::Os::Windows,
    ) {
        Ok(inf) => {
            println!("  pattern     = {}", inf.pattern.name);
            println!("  confidence  = {}", inf.confidence);
            println!("  params      = {}", inf.params.len());
            for (i, p) in inf.params.iter().enumerate() {
                println!(
                    "    a{}: register={:?} stack_offset={:?}",
                    i + 1,
                    p.register,
                    p.stack_offset
                );
            }
        }
        Err(e) => println!("  detect error: {e:?}"),
    }
    ExitCode::SUCCESS
}
