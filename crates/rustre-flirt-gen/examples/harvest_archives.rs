//! Harvest classic FLIRT signatures from every `.rlib`/`.lib` in the given
//! directories, dedup them, and emit one IDA-compatible `.sig` v9 file.
//!
//! Usage: `harvest_archives` <out.sig> <archive-dir> [<archive-dir> ...]

use rustre_flirt_gen::coff_archive::{
    ArchiveHarvestOptions, dedup_discriminative, harvest_archive_file,
};

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(out) = args.next() else {
        eprintln!("usage: harvest_archives <out.sig> <archive-dir>...");
        std::process::exit(2);
    };
    let opts = ArchiveHarvestOptions::default();
    let mut all = Vec::new();
    let mut files = 0usize;
    for dir in args {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            eprintln!("skip unreadable dir {dir}");
            continue;
        };
        for e in rd.filter_map(Result::ok) {
            let p = e.path();
            // `.a` was missing, and it is the extension of the entire GNU/mingw
            // runtime — `libmingw32.a`, `libmsvcrt.a`, `libgcc.a`. Measured in
            // iteration 56: those are exactly the archives the corpus's C
            // binaries link, so the harvester could not see the one runtime that
            // mattered.
            let ok_ext = p.extension().is_some_and(|x| {
                x.eq_ignore_ascii_case("rlib")
                    || x.eq_ignore_ascii_case("lib")
                    || x.eq_ignore_ascii_case("a")
            });
            if !ok_ext {
                continue;
            }
            match harvest_archive_file(&p, &opts) {
                Ok((pats, stats)) => {
                    files += 1;
                    println!(
                        "{}: {} members, {} objects, {} funcs -> {} patterns",
                        p.file_name().unwrap().to_string_lossy(),
                        stats.members,
                        stats.objects_parsed,
                        stats.functions_seen,
                        pats.len()
                    );
                    all.extend(pats);
                }
                Err(e) => println!("{}: skipped ({e})", p.display()),
            }
        }
    }
    println!("== {files} archives, {} raw patterns", all.len());
    let (deduped, report) = dedup_discriminative(all);
    println!(
        "== deduped: {} kept | {} discriminative (single-name) | {} ambiguous keys | {} exact dups dropped",
        deduped.len(),
        report.discriminative,
        report.ambiguous_keys,
        report.exact_duplicates
    );
    rustre_flirt_gen::write_sig_file(&deduped, "rust-stdlib", 75, std::path::Path::new(&out))
        .expect("write .sig");
    println!("wrote {out}");
}
