//! Measure FLIRT match precision against a PDB, **at the address level**.
//!
//! # Why this is the measurement that matters
//!
//! Enabling the 67 168-signature database took `sample3_rust.exe` from 0 to 240
//! raw matches. More matches is not automatically better: a **false positive
//! renames a function wrongly**, which is worse for a decompiler than leaving it
//! as `sub_140002620`. A wrong name propagates into every caller's reasoning and
//! looks entirely healthy.
//!
//! An earlier version of this tool only asked "does this name exist anywhere in
//! the PDB?". That is a lower bound: a *correct* name attached to the *wrong*
//! address passes it, and attaching a real name to the wrong function is exactly
//! the failure mode worth catching. This version asks the sharper question:
//!
//! > at the address FLIRT matched, what does the PDB say is actually there?
//!
//! Verdicts:
//! * **AGREE**    — PDB has a symbol at that address and the names correspond.
//! * **DISAGREE** — PDB has a *different* symbol there. A real false positive.
//! * **UNKNOWN**  — PDB has nothing at that address (static/inlined/thunk), so
//!                  the match can be neither confirmed nor refuted.
//!
//! `UNKNOWN` is reported separately and never folded into either side: counting
//! it as success would fabricate precision, counting it as failure would invent
//! defects.
//!
//! Usage:
//!   cargo run --release -p rustre-flirt-apply --example `match_precision_vs_pdb` \
//!       -- <binary.exe> <symbols.pdb> <database.sig>

use std::collections::BTreeMap;

use rustre_flirt_apply::usize_to_f64;

/// Strip the parts of a Rust symbol that differ between builds, so two
/// spellings of the same function compare equal.
///
/// Rust legacy mangling ends in `::h<16 hex>` — a *build* hash, different in
/// every compilation. Comparing it is comparing the build, not the function; an
/// earlier pass at this reported a bogus 11.1% precision by doing exactly that.
fn normalise(name: &str) -> String {
    let mut s = name;
    if let Some((head, tail)) = s.rsplit_once("::") {
        let is_hash = tail.len() == 17
            && tail.starts_with('h')
            && tail[1..].bytes().all(|b| b.is_ascii_hexdigit());
        if is_hash {
            s = head;
        }
    }
    // Crate-disambiguator hashes, e.g. `__rustc[d9b87f19e823c0ef]::foo`.
    let mut out = String::with_capacity(s.len());
    let mut skip = false;
    for c in s.chars() {
        match c {
            '[' => skip = true,
            ']' => skip = false,
            _ if !skip => out.push(c),
            _ => {}
        }
    }
    out.to_ascii_lowercase()
}

/// Do two symbol spellings plausibly name the same function?
fn same_function(a: &str, b: &str) -> bool {
    let (a, b) = (normalise(a), normalise(b));
    if a == b {
        return true;
    }
    // One side may be mangled and the other demangled; require a shared tail
    // identifier long enough that agreement is not coincidence.
    let tail = |s: &str| -> Option<String> {
        s.rsplit("::")
            .next()
            .map(|t| {
                t.trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
                    .to_string()
            })
            .filter(|t| t.len() >= 6)
    };
    match (tail(&a), tail(&b)) {
        (Some(ta), Some(tb)) => ta == tb || a.contains(&tb) || b.contains(&ta),
        _ => false,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("uso: match_precision_vs_pdb <binary.exe> <symbols.pdb> <database.sig>");
        std::process::exit(2);
    }

    let bin = std::fs::read(&args[1]).expect("lettura binario");
    let pdb = std::fs::read(&args[2]).expect("lettura pdb");
    let sig = std::fs::read(&args[3]).expect("lettura .sig");

    let pe = rustre_pe_tools::PeFile::parse(&bin).expect("parse PE");

    let scanner =
        rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).expect("scanner dal .sig");
    // Soglia opzionale via env, per misurare il compromesso senza ricompilare.
    let min_bytes: usize = std::env::var("FLIRT_MIN_BYTES_NO_CRC")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut scanner = scanner;
    scanner.set_min_bytes_without_crc(min_bytes);
    println!("firme nello scanner : {}", scanner.signature_count());
    println!("soglia byte senza crc: {min_bytes}");

    // Scan each executable section at its real virtual address, so match
    // addresses are VAs the PDB can be queried with. Scanning the raw file at
    // base 0 would produce file offsets, which no symbol source understands.
    let mut matches = Vec::new();
    for s in &pe.sections {
        let executable = s.characteristics & 0x2000_0000 != 0;
        if !executable || s.data.is_empty() {
            continue;
        }
        let va = pe.image_base + u64::from(s.virtual_address);
        matches.extend(scanner.scan_fast(&s.data, va));
    }
    println!("match grezzi        : {}", matches.len());

    let (renames, _stats) = rustre_flirt_apply::resolve_renames(&matches, 0);
    println!("dopo resolve        : {}", renames.len());

    let mut by_addr: BTreeMap<u64, String> = BTreeMap::new();
    for r in &renames {
        by_addr.insert(r.address, r.name.clone());
    }

    // Ground truth: address -> symbol, built from the PDB's public-symbol
    // records.
    //
    // NOTE: `rustre_symbols_pdb::resolve_name_for_address` looks like the right
    // helper but returns `None` even for an address derived directly from a PDB
    // record (verified on 0x1400010a0 of sample3_rust). So the map is built here
    // from `scan_public_symbols`, which does work. That helper's defect belongs
    // to `rustre-symbols-pdb` and is recorded rather than patched from here.
    let mut truth: BTreeMap<u64, String> = BTreeMap::new();
    for p in rustre_symbols_pdb::PdbPublicSymbolScanner::scan_public_symbols(&pdb) {
        // `section` is 1-based into the PE section table.
        let Some(sec) = pe.sections.get((p.section as usize).saturating_sub(1)) else {
            continue;
        };
        let va = pe.image_base + u64::from(sec.virtual_address) + u64::from(p.offset);
        // Demangle the PDB side: it carries v0-mangled names
        // (`_RNvNtCs…_3std7process4exit`) while FLIRT carries the demangled
        // form (`std::process::exit::h44a…`). Comparing them raw reports the
        // *same function* as a false positive — which a first pass at this did,
        // for `std::process::exit` among others.
        let demangled = rustre_demangle::demangler_dispatcher::auto_demangle(&p.name);
        let name = if demangled.is_empty() { p.name.clone() } else { demangled };
        truth.insert(va, name);
    }
    println!("simboli pubblici PDB: {}", truth.len());

    let mut agree = 0usize;
    let mut disagree: Vec<(u64, String, String)> = Vec::new();
    let mut unknown = 0usize;

    let mut empty_names = 0usize;
    for (&addr, name) in &by_addr {
        if name.trim().is_empty() {
            // FLIRT assigned an *empty* name. Renaming a function to "" is a
            // defect in its own right, not a precision question, so it is
            // counted separately instead of being scored.
            empty_names += 1;
            continue;
        }
        match truth.get(&addr) {
            None => unknown += 1,
            Some(real) => {
                if same_function(name, real) {
                    agree += 1;
                } else {
                    disagree.push((addr, name.clone(), real.clone()));
                }
            }
        }
    }

    let decided = agree + disagree.len();
    println!();
    println!("indirizzi distinti rinominati : {}", by_addr.len());
    println!("  AGREE     (nome giusto)     : {agree}");
    println!("  DISAGREE  (falso positivo)  : {}", disagree.len());
    println!("  UNKNOWN   (PDB non sa)      : {unknown}");
    println!("  NOME VUOTO (difetto a se')  : {empty_names}");
    if decided > 0 {
        let pct = usize_to_f64(agree) * 100.0 / usize_to_f64(decided);
        println!("  precisione sui decidibili   : {pct:.1}%  ({agree}/{decided})");
    } else {
        println!("  precisione                  : non misurabile (0 indirizzi decidibili)");
    }

    if std::env::var_os("FLIRT_DUMP_ADDRS").is_some() {
        let mut h: u64 = 1469598103934665603;
        for (&a, n) in &by_addr {
            for b in a.to_le_bytes().iter().chain(n.as_bytes()) {
                h ^= u64::from(*b); h = h.wrapping_mul(1099511628211);
            }
        }
        println!("impronta indirizzi+nomi: {h:#018x}");
    }

    if !disagree.is_empty() {
        println!("\nfalsi positivi (FLIRT dice / il PDB dice):");
        for (a, got, want) in disagree.iter().take(20) {
            println!("  {a:#012x}\n    FLIRT: {got}\n    PDB  : {want}");
        }
    }
}
