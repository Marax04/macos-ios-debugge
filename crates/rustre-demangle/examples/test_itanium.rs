use rustre_demangle::{Demangler2, ItaniumNativeDemangler};

fn main() {
    let symbol = "_ZN3fooEv";
    
    // Test ItaniumNativeDemangler directly
    println!("Testing ItaniumNativeDemangler::demangle('{symbol}')");
    match ItaniumNativeDemangler::demangle(symbol) {
        Some(s) => println!("  Result: Some(\"{s}\")"),
        None => println!("  Result: None"),
    }
    
    // Test Demangler2
    println!("\nTesting Demangler2::demangle('{symbol}')");
    let result = Demangler2::demangle(symbol);
    println!("  mangled: {}", result.mangled);
    println!("  demangled: \"{}\"", result.demangled);
    println!("  language: {:?}", result.language);
    println!("  kind: {:?}", result.kind);
    
    // Check if demangled is empty
    if result.demangled.is_empty() {
        println!("\n*** ERROR: demangled is EMPTY ***");
    } else {
        println!("\n*** demangled is: '{}' ***", result.demangled);
    }
}
