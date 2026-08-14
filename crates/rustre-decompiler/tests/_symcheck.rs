use rustre_decompiler::binary_entry::{decompile_function_in_load, detect_functions_in_load, load_binary};
use rustre_decompiler::DecompOptions;
use std::path::Path;
#[test]
fn dbg() {
    let load = load_binary(Path::new("../../tests/decompiler_corpus/bin/sample1.exe")).expect("load");
    eprintln!("SYMCOUNT {}", load.symbols.len());
    for s in load.symbols.iter().filter(|s| s.name.contains("accumulate") || s.name.contains("find_max") || s.name == "main") {
        eprintln!("SYM {:x} {}", s.addr, s.name);
    }
    for fb in detect_functions_in_load(&load).iter() {
        if let Ok(d) = decompile_function_in_load(&load, fb.start.into(), DecompOptions::default()) {
            if d.name.contains("accumulate") || d.name.contains("find_max") || d.name == "main" {
                eprintln!("DECOMP name={} @ {:x}", d.name, fb.start);
            }
        }
    }
}
