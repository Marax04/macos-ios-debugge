use std::path::Path;
fn main() {
    let load = rustre_decompiler::binary_entry::load_binary(Path::new(&std::env::args().nth(1).unwrap())).unwrap();
    println!("imports: {}", load.imports.len());
    for i in load.imports.iter().take(15) { println!("  {:#x} {} :: {}", i.addr, i.dll, i.name); }
}
