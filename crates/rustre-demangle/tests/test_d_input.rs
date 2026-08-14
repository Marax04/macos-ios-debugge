fn main() {
    use rustre_demangle::DDemangler;
    
    let input = "_D3foo3barFZi";
    println!("Input: {input}");
    println!("Detect: {}", DDemangler::detect(input));
    
    let result = DDemangler::demangle(input);
    println!("Demangle result: {result:?}");
    
    if let Some(s) = result {
        println!("Demangled: {s}");
    }
}
