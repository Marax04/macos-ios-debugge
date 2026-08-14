//! The CRC field confirms matches instead of rejecting them (T3c, chiuso).
//!
//! # The defect, and the measurement that closed it
//!
//! The generator used to compute the CRC over `crc_length` **non-contiguous**
//! surviving bytes — skipping masked offsets anywhere in the window — while the
//! scanner hashes `crc_len` **contiguous** bytes starting after the pattern. The
//! two definitions coincide only when nothing in the window is masked, so a
//! signature over relocated code stored a CRC nothing could reproduce.
//!
//! Measured with `examples/self_match_experiment.rs`, self-match on `libz.a`:
//!
//! | | with CRC | CRC field cleared |
//! |---|---|---|
//! | before (iter. 38) | 65.2% | 97.0% |
//! | after the tail mask (iter. 53) | 73.5% | 97.0% |
//! | **after this fix (iter. 54)** | **97.0%** | 97.0% |
//!
//! The two columns are now identical: the field costs nothing. On the
//! wildcard-free subset it is 100.0%.
//!
//! The window now stops at the first masked byte, so `crc_len` means the same
//! thing on both sides — "this many contiguous bytes after the pattern". A
//! function whose next byte is relocated gets `crc_len == 0`: no CRC, which is
//! honest rather than storing one the scanner cannot recompute.

use rustre_flirt::PatternByte;

fn harvest() -> Option<Vec<rustre_flirt::FlirtPattern>> {
    let data = std::fs::read(r"C:\msys64\mingw64\lib\libz.a").ok()?;
    let opts = rustre_flirt_gen::coff_archive::ArchiveHarvestOptions::default();
    let (pats, _) = rustre_flirt_gen::coff_archive::harvest_archive_bytes(&data, &opts).ok()?;
    (!pats.is_empty()).then_some(pats)
}

fn self_match_count(pats: &[rustre_flirt::FlirtPattern], haystack: &[u8]) -> usize {
    let sig = rustre_flirt_gen::SigWriter::default().build(pats, "crc_check");
    let Ok(scanner) = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig) else {
        return 0;
    };
    let names: std::collections::HashSet<String> = scanner
        .scan_fast(haystack, 0)
        .into_iter()
        .map(|m| m.function_name)
        .collect();
    pats.iter()
        .filter_map(rustre_flirt::FlirtPattern::primary_name)
        .filter(|n| names.contains(*n))
        .count()
}

/// The property, stated as the thing that matters: carrying a CRC must not lose
/// a single match relative to carrying none.
#[test]
fn the_crc_field_costs_no_matches() {
    let Ok(data) = std::fs::read(r"C:\msys64\mingw64\lib\libz.a") else {
        eprintln!("SKIP: mingw assente");
        return;
    };
    let Some(pats) = harvest() else {
        eprintln!("SKIP: nessun pattern");
        return;
    };
    assert!(pats.len() > 50, "corpus troppo piccolo: {}", pats.len());

    let with_crc = self_match_count(&pats, &data);

    let without: Vec<_> = pats
        .iter()
        .map(|p| {
            let mut q = p.clone();
            q.crc16 = 0;
            q.crc_length = 0;
            q
        })
        .collect();
    let no_crc = self_match_count(&without, &data);

    assert!(no_crc > 0, "baseline senza CRC vuota: la misura non dice nulla");
    assert_eq!(
        with_crc, no_crc,
        "il CRC costa {} match: e' tornato a rifiutare invece di confermare, \
         probabilmente perche' la finestra non e' piu' contigua",
        no_crc - with_crc
    );
}

/// Wildcard-free signatures must recognise themselves completely. Anything less
/// is a defect somewhere else in the chain, and separating the two makes that
/// visible instead of hidden in an aggregate.
#[test]
fn wildcard_free_signatures_match_themselves_completely() {
    let Ok(data) = std::fs::read(r"C:\msys64\mingw64\lib\libz.a") else {
        eprintln!("SKIP: mingw assente");
        return;
    };
    let Some(pats) = harvest() else { return };

    let exact: Vec<_> = pats
        .iter()
        .filter(|p| !p.initial_bytes.iter().any(|b| matches!(b, PatternByte::Wildcard)))
        .cloned()
        .collect();
    assert!(exact.len() > 50, "servono abbastanza pattern esatti");

    let found = self_match_count(&exact, &data);
    assert_eq!(
        found,
        exact.len(),
        "{found} su {} pattern senza wildcard si ritrovano: senza wildcard e con \
         una finestra CRC contigua devono ritrovarsi tutti",
        exact.len()
    );
}
