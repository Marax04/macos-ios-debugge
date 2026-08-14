//! Two readers of the same `.sig` container, counted side by side.
//!
//! `FlirtScanner::from_sig_bytes` and `load_sig_file` both claim to read the
//! `IDASGN` container this workspace writes with `rustre_flirt_gen::SigWriter`.
//! This prints how many signatures each one actually recovers from the *same*
//! bytes, because "reads the file" and "recovers its contents" are different
//! claims and only one of them is useful.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

fn pattern(name: &str, first: u8) -> FlirtPattern {
    let bytes: Vec<PatternByte> = (0u8..24)
        .map(|i| PatternByte::Exact(first.wrapping_add(i)))
        .collect();
    let mut p = FlirtPattern::new(bytes);
    p.pattern_length = 24;
    p.names.push(FlirtName {
        offset: 0,
        name: name.to_string(),
        is_public: true,
        is_local: false,
    });
    p
}

fn main() {
    let pats = vec![
        pattern("alpha", 0x10),
        pattern("beta", 0x40),
        pattern("gamma", 0x80),
    ];
    let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "twin_readers");
    println!("pattern scritti : {}", pats.len());
    println!(".sig            : {} byte, magic {:?}", sig.len(), &sig[..6]);

    // Reader A: the one the decompiler and the round-trip use.
    match rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) {
        Ok(scanner) => {
            // Count by scanning a buffer containing every pattern's bytes.
            let mut hay = Vec::new();
            for p in &pats {
                for b in &p.initial_bytes {
                    hay.push(match b {
                        PatternByte::Exact(v) => *v,
                        PatternByte::Wildcard => 0,
                    });
                }
                hay.extend_from_slice(&[0u8; 8]);
            }
            let hits = scanner.scan_fast(&hay, 0);
            println!("from_sig_bytes  : {} match sui propri byte", hits.len());
        }
        Err(e) => println!("from_sig_bytes  : errore {e:?}"),
    }

    // Reader B: the public loader that returns the signatures themselves.
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let path = std::path::Path::new(&dir).join("rustre_two_readers.sig");
    std::fs::write(&path, &sig).expect("scrittura");
    match rustre_flirt_apply::load_sig_file(&path) {
        Ok(sigs) => println!("load_sig_file   : {} firme recuperate", sigs.len()),
        Err(e) => println!("load_sig_file   : errore {e:?}"),
    }
    let _ = std::fs::remove_file(&path);
}
