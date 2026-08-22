//! Does a converted `RFLIRTBIN` asset load back as signatures? (T27)
//!
//! `assets/*.sig` are 13 MB of generated signatures in this project's own
//! `RFLIRTBIN` container, which nothing on the decompilation path reads. The
//! converter turns one into `IDASGN`. What matters is not that it writes a file
//! but that the file comes back with its contents intact — and the container
//! changed twice recently (masked tail in iteration 53, contiguous CRC window in
//! 54), so the number is worth re-measuring rather than carrying over.

use std::collections::HashSet;

use rustre_flirt_apply::usize_to_f64;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        r"C:\Users\Fra\AppData\Local\Temp\conv\rust-stdlib-ida.sig".to_string()
    });
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("impossibile leggere {path}");
        std::process::exit(2);
    };
    println!("file      : {path} ({} byte)", bytes.len());

    let sigs = match rustre_flirt_apply::load_sig_file(std::path::Path::new(&path)) {
        Ok(v) => v,
        Err(e) => {
            println!("load_sig_file: errore {e:?}");
            std::process::exit(1);
        }
    };
    let named: Vec<_> = sigs.iter().filter(|s| !s.name.is_empty()).collect();
    let distinct: HashSet<&str> = named.iter().map(|s| s.name.as_str()).collect();

    println!("firme lette          : {}", sigs.len());
    println!("  con nome           : {}", named.len());
    println!("  nomi distinti      : {}", distinct.len());

    let with_wc = named
        .iter()
        .filter(|s| s.mask.contains(&0))
        .count();
    let with_crc = named.iter().filter(|s| s.crc_len > 0).count();
    println!("  con wildcard       : {with_wc}");
    println!("  con CRC            : {with_crc}");

    let avg: f64 = if named.is_empty() {
        0.0
    } else {
        let t = usize_to_f64(named.iter().map(|s| s.bytes.len()).sum::<usize>());
        let n = usize_to_f64(named.len());
        t / n
    };
    println!("  lunghezza media    : {avg:.1} byte");
}
