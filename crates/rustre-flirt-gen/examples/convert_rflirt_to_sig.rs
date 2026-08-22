//! Convert an `RFLIRTBIN` database into a loadable `IDASGN` `.sig`.
//!
//! `assets/rust-stdlib.sig` is 10.8 MB of generated signatures in this
//! project's own container format, read by nothing on the decompilation path.
//! This turns it into a `.sig` that `rustre_flirt_apply::FlirtScanner` loads.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-gen --example `convert_rflirt_to_sig` \
//!       <input.rflirtbin> <output.sig> [`lib_name`] [arch]
//!
//! With no arguments it reports what it would do against the repo's assets.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "uso: convert_rflirt_to_sig <input> <output.sig> [lib_name] [arch]\n\
             \n\
             Esempio:\n  \
             cargo run --release -p rustre-flirt-gen --example convert_rflirt_to_sig -- \\\n    \
             assets/rust-stdlib.sig assets/rust-stdlib-ida.sig rust-stdlib 75"
        );
        std::process::exit(2);
    }
    let src = Path::new(&args[1]);
    let dst = Path::new(&args[2]);
    let lib = args.get(3).map_or("converted", String::as_str);
    let arch: u8 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(75);

    match rustre_flirt_gen::rflirt_bin::convert_file(src, dst, lib, arch) {
        Ok(n) => {
            let in_size = std::fs::metadata(src).map_or(0, |m| m.len());
            let out_size = std::fs::metadata(dst).map_or(0, |m| m.len());
            println!(
                "convertiti {n} pattern\n  {} ({in_size} byte)\n  -> {} ({out_size} byte)",
                src.display(),
                dst.display()
            );
        }
        Err(e) => {
            eprintln!("conversione fallita: {e:?}");
            std::process::exit(1);
        }
    }
}
