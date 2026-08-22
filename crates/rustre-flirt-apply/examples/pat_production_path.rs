//! Does the *production* `.pat` reader read what we write? (T4, correzione)
//!
//! Iteration 48 measured the writer × parser matrix at 0 of 6 and concluded the
//! `.pat` writers were "write-only". That covered the three **public** parsers.
//! It missed a fourth: a private `parse_pat_line` in `flirt-apply/src/lib.rs`,
//! reached through `load_pat_file` and `load_auto` — which is the path a real
//! caller actually takes.
//!
//! This measures that path, so the severity claim rests on the reader that ships
//! rather than on the ones that happen to be public.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

fn sample_patterns() -> Vec<FlirtPattern> {
    let mk = |name: &str, wildcards: &[usize], crc_len: u8| {
        let bytes: Vec<PatternByte> = (0u8..32)
            .map(|i| {
                if wildcards.contains(&(i as usize)) {
                    PatternByte::Wildcard
                } else {
                    PatternByte::Exact(0x40u8.wrapping_add(i))
                }
            })
            .collect();
        let mut p = FlirtPattern::new(bytes);
        p.crc_length = crc_len;
        p.crc16 = if crc_len > 0 { 0xBEEF } else { 0 };
        p.pattern_length = 64;
        p.names.push(FlirtName {
            offset: 0,
            name: name.to_string(),
            is_public: true,
            is_local: false,
        });
        p
    };
    vec![
        mk("exact_fn", &[], 0),
        mk("wildcard_fn", &[3, 4, 5, 6], 0),
        mk("crc_fn", &[], 8),
    ]
}

fn main() {
    let pats = sample_patterns();
    let dir = std::env::var("TEMP").unwrap_or_else(|_| ".".to_string());
    let out_path = std::path::Path::new(&dir).join("rustre_prod_path.pat");
    rustre_flirt_gen::pat_file_writer::write_pat_file(&pats, "prod", &out_path)
        .expect("scrittura .pat");

    println!("scritti      : {} pattern", pats.len());

    match rustre_flirt_apply::load_pat_file(&out_path) {
        Ok(sigs) => {
            println!("load_pat_file: {} firme recuperate", sigs.len());
            for s in &sigs {
                let wc = s.mask.iter().filter(|m| **m == 0).count();
                println!(
                    "   {:<14} {} byte, {} wildcard, crc_len={} crc={:04X}",
                    s.name,
                    s.bytes.len(),
                    wc,
                    s.crc_len,
                    s.crc
                );
            }
        }
        Err(e) => println!("load_pat_file: errore {e:?}"),
    }

    // The canonical parser, for comparison on the same bytes.
    let text = std::fs::read_to_string(&out_path).expect("rilettura");
    let (canon, errs) = rustre_flirt::pat_canonical::parse_text(&text);
    println!("pat_canonical: {} pattern, {} errori", canon.len(), errs.len());

    let _ = std::fs::remove_file(&out_path);
}
