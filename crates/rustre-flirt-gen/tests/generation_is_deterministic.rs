//! Signature generation must be reproducible byte for byte.
//!
//! # Why this matters beyond tidiness
//!
//! If two runs over the same input produce different `.sig` bytes, then:
//!
//! * a database cannot be checksummed or cached — every rebuild looks like a
//!   change;
//! * a regression cannot be bisected, because "the output differs" stops being
//!   evidence of anything;
//! * two agents regenerating the corpus produce diffs that mean nothing, which
//!   is exactly the trap `measure.sh` was built to escape.
//!
//! The usual cause is iterating a `HashMap`: Rust randomises its hasher per
//! process, so the order changes between runs of the *same binary* on the *same
//! input*. That is invisible in a single run and only shows up as unexplained
//! churn later.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

fn patterns(n: usize) -> Vec<FlirtPattern> {
    (0..n)
        .map(|i| {
            let mut p = FlirtPattern::new(
                (0..16u8)
                    .map(|b| PatternByte::Exact(b.wrapping_mul(3).wrapping_add(i as u8)))
                    .collect(),
            );
            p.crc16 = (i as u16).wrapping_mul(7919);
            p.crc_length = 8;
            p.pattern_length = 32 + i as u16;
            p.names.push(FlirtName {
                name: format!("function_{i:04}"),
                offset: 0,
                is_public: i % 2 == 0,
                is_local: i % 2 == 1,
            });
            p
        })
        .collect()
}

fn rflirt_container(pats: &[FlirtPattern]) -> Vec<u8> {
    let mut f = b"RFLIRTBIN\0".to_vec();
    f.extend_from_slice(&u32::try_from(pats.len()).unwrap().to_le_bytes());
    for p in pats {
        let mut prefix = Vec::new();
        let mut mask = Vec::new();
        for b in &p.initial_bytes {
            match b {
                PatternByte::Exact(v) => {
                    prefix.push(*v);
                    mask.push(0xff);
                }
                PatternByte::Wildcard => {
                    prefix.push(0);
                    mask.push(0);
                }
            }
        }
        f.extend_from_slice(&u16::try_from(prefix.len()).unwrap().to_le_bytes());
        f.extend_from_slice(&prefix);
        f.extend_from_slice(&u16::try_from(mask.len()).unwrap().to_le_bytes());
        f.extend_from_slice(&mask);
        f.extend_from_slice(&p.crc16.to_le_bytes());
        f.push(p.crc_length);
        f.extend_from_slice(&p.pattern_length.to_le_bytes());
        f.push(u8::try_from(p.names.len()).unwrap());
        for n in &p.names {
            let mut flags = 0u8;
            if n.is_public {
                flags |= 0x01;
            }
            if n.is_local {
                flags |= 0x02;
            }
            f.push(flags);
            f.extend_from_slice(&n.offset.to_le_bytes());
            f.extend_from_slice(&u16::try_from(n.name.len()).unwrap().to_le_bytes());
            f.extend_from_slice(n.name.as_bytes());
        }
    }
    f
}

#[test]
fn the_sig_writer_is_byte_identical_across_runs() {
    let pats = patterns(200);
    let first = rustre_flirt_gen::SigWriter::default().build(&pats, "determinism");
    for run in 1..8 {
        let again = rustre_flirt_gen::SigWriter::default().build(&pats, "determinism");
        assert_eq!(
            first, again,
            "esecuzione {run}: il .sig differisce dalla prima a parità di input"
        );
    }
    assert!(!first.is_empty(), "il corpus deve produrre output non vuoto");
}

#[test]
fn rflirt_to_sig_conversion_is_byte_identical_across_runs() {
    let raw = rflirt_container(&patterns(150));
    let first = rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "determinism", 75)
        .expect("conversione");
    for run in 1..8 {
        let again = rustre_flirt_gen::rflirt_bin::to_sig_bytes(&raw, "determinism", 75)
            .expect("conversione");
        assert_eq!(first, again, "esecuzione {run}: conversione non deterministica");
    }
}

#[test]
fn the_public_only_filter_is_also_deterministic() {
    // The filter uses `retain`, which preserves order — but a future
    // implementation reaching for a set would not, and this catches that.
    let raw = rflirt_container(&patterns(150));
    let first =
        rustre_flirt_gen::rflirt_bin::to_sig_bytes_filtered(&raw, "det", 75, true).unwrap();
    for _ in 0..5 {
        let again =
            rustre_flirt_gen::rflirt_bin::to_sig_bytes_filtered(&raw, "det", 75, true).unwrap();
        assert_eq!(first, again);
    }
}

#[test]
fn parsing_preserves_input_order() {
    // Determinism of the *writer* is worthless if the *reader* shuffles.
    // Names must come back in the order they were written.
    let pats = patterns(50);
    let raw = rflirt_container(&pats);
    let back = rustre_flirt_gen::rflirt_bin::parse(&raw).expect("parse");
    let got: Vec<&str> = back.iter().filter_map(FlirtPattern::primary_name).collect();
    let want: Vec<&str> = pats.iter().filter_map(FlirtPattern::primary_name).collect();
    assert_eq!(got, want, "l'ordine dei pattern non è preservato");
}

#[test]
fn identical_inputs_hash_identically() {
    // The property a build system actually depends on: same input, same digest.
    // Stated separately from byte equality because this is the form a cache or
    // a `diff -rq` check relies on.
    let pats = patterns(100);
    let digest = |b: &[u8]| -> u64 {
        let mut h = 1469598103934665603u64;
        for x in b {
            h ^= u64::from(*x);
            h = h.wrapping_mul(1099511628211);
        }
        h
    };
    let a = digest(&rustre_flirt_gen::SigWriter::default().build(&pats, "lib"));
    let b = digest(&rustre_flirt_gen::SigWriter::default().build(&pats, "lib"));
    assert_eq!(a, b, "digest diversi per lo stesso input");
}

// ─── harvesting a real archive ───────────────────────────────────────────────

/// Locate an archive that actually contains compiled objects.
///
/// The corpus `.lib` files are C# `NativeAOT` **import** libraries: one member,
/// zero objects, zero patterns. Harvesting them exercises none of the
/// section-walking code, so a determinism test built on them would pass while
/// testing nothing — the vacuity guard below caught exactly that.
///
/// `libz.a` from the mingw toolchain yields 15 objects and 132 patterns.
fn archive_with_objects() -> Option<Vec<u8>> {
    for path in [
        r"C:\msys64\mingw64\lib\libz.a",
        r"C:\msys64\mingw64\lib\libgmon.a",
        "/usr/lib/x86_64-linux-gnu/libz.a",
    ] {
        if let Ok(b) = std::fs::read(path) {
            return Some(b);
        }
    }
    None
}

/// The synthetic archives above hold non-object blobs, so they never reach the
/// section-walking code where the `HashMap` ordering lived. This uses a real
/// `.lib` so the test is not vacuous — the trap this project keeps finding.
#[test]
fn harvesting_a_real_archive_is_deterministic() {
    let Some(data) = archive_with_objects() else {
        eprintln!("nessun archivio con oggetti disponibile — test saltato");
        return;
    };

    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (first, stats) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts)
        .expect("l'archivio del corpus deve essere analizzabile");

    // Guard against a vacuous pass: if nothing is parsed, repeated runs agree
    // trivially and the test proves nothing.
    assert!(
        stats.objects_parsed > 0,
        "nessun oggetto analizzato: il test non esercita il codice che intende testare"
    );

    let names = |v: &[rustre_flirt::FlirtPattern]| -> Vec<String> {
        v.iter()
            .map(|p| p.primary_name().unwrap_or("").to_string())
            .collect()
    };
    let baseline = names(&first);

    for run in 1..5 {
        let (again, _) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts)
            .expect("harvest ripetuto");
        assert_eq!(
            names(&again),
            baseline,
            "esecuzione {run}: l'ordine dei pattern raccolti è cambiato a parità di input"
        );
    }
}

/// End to end: a real archive must produce a byte-identical `.sig` every time.
#[test]
fn a_sig_built_from_a_real_archive_is_byte_identical_across_runs() {
    let Some(data) = archive_with_objects() else { return };
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();

    let build = || {
        let (pats, _) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts)
            .expect("harvest");
        rustre_flirt_gen::SigWriter::default().build(&pats, "corpus")
    };

    let first = build();
    for run in 1..4 {
        assert_eq!(first, build(), "esecuzione {run}: .sig non riproducibile");
    }
}
