//! How many prototype sources are there, and do they overlap? (Level 7 / T7)
//!
//! T7 calls `name_propagator` and `rename_propagator` "the name propagators", to
//! be collapsed into one. Measured first: they are not the same concept.
//! `name_propagator` walks the call graph propagating names between caller and
//! callee; `rename_propagator` carries **function signatures with C types** and
//! applies them. Collapsing them would merge two different jobs.
//!
//! The interesting part is the second one. `rename_propagator::builtin_signatures()`
//! returns prototypes — and Level 7's measured bottleneck is precisely that the
//! matched names have no prototype. So: is this a source the bridge does not
//! know about, and does it cover any of the names that are currently missing?

use std::collections::HashSet;

fn main() {
    let bridge: HashSet<String> = rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
        .into_iter()
        .map(|s| s.name)
        .collect();
    let builtin: HashSet<String> = rustre_flirt_apply::rename_propagator::builtin_signatures()
        .into_iter()
        .map(|s| s.name)
        .collect();

    println!("prototipi noti al ponte      : {}", bridge.len());
    println!("firme builtin del propagatore: {}", builtin.len());
    println!("  in comune                  : {}", bridge.intersection(&builtin).count());
    println!("  solo nel propagatore       : {}", builtin.difference(&bridge).count());

    let only: Vec<&String> = {
        let mut v: Vec<&String> = builtin.difference(&bridge).collect();
        v.sort();
        v
    };
    if !only.is_empty() {
        println!();
        println!("nomi che solo il propagatore conosce:");
        for n in only.iter().take(40) {
            println!("   {n}");
        }
        if only.len() > 40 {
            println!("   … e altri {}", only.len() - 40);
        }
    }

    // Do they cover the names our scan matched but could not publish?
    let sig_path = r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig";
    let bin_path = r"tests\decompiler_corpus\bin\sample1_c.exe";
    if let (Ok(sig), Ok(bin)) = (std::fs::read(sig_path), std::fs::read(bin_path)) {
        if let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) {
            let matched: HashSet<String> = scanner
                .scan_fast(&bin, 0)
                .into_iter()
                .map(|m| m.function_name)
                .filter(|n| !n.is_empty())
                .collect();
            let missing: HashSet<&String> = matched.difference(&bridge).collect();
            let rescued = missing.iter().filter(|n| builtin.contains(**n)).count();
            println!();
            println!("nomi combacianti senza prototipo nel ponte : {}", missing.len());
            println!("  di questi, coperti dal propagatore       : {rescued}");
        }
    }
}
