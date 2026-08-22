/// Quick diagnostic: scan a binary with the merged FLIRT DB and report matches.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).map_or("cargo-zyphora.exe", std::string::String::as_str);
    let bytes = std::fs::read(path).expect("cannot read binary");
    // Use a typical x64 PE base address
    let base_addr: u64 = 0x1400_0000_0;

    let mut db = rustre_flirt_apply::FlirtSigDb::load_demo_sigs();
    db.merge(rustre_flirt_apply::FlirtSigDb::load_extended_sigs());
    eprintln!("[SCAN_TEST] db patterns={}", db.pattern_count());

    let applier = rustre_flirt_apply::FlirtApplier::new(db);
    let matches = applier.scan(&bytes, base_addr);
    println!("Total matches: {}", matches.len());
    for m in &matches {
        println!("  0x{:x} {} [{}] conf={}", m.address, m.function_name, m.lib_name, m.confidence);
    }
}
