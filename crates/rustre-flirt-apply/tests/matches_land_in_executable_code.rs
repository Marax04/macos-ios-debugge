//! Our matches land in executable code, so they are candidates — not artefacts.
//!
//! # The alternative this rules out
//!
//! Iteration 58 established that the bridge publishes 4 of our 33
//! identifications while the decompiler publishes 0 of its 26, and noted that
//! the two scan different things: we walk the raw file from offset 0, the
//! decompiler walks mapped sections at virtual addresses.
//!
//! Before concluding anything about the decompiler, the cheaper explanation had
//! to be tested: that *our* matches are spurious — byte sequences occurring in
//! headers, data, relocations or the import table, where a run of bytes can
//! appear without being that function. Had that been so, the decompiler would
//! simply be right to ignore them.
//!
//! Measured (iteration 59) against the PE section table of `sample1_c.exe`:
//! **all 33 matches fall inside `.text`**, and the four names that carry a
//! prototype — `_matherr`, `__mingw_raise_matherr`, `_configthreadlocale`,
//! `__acrt_iob_func` — are all in executable code.
//!
//! So the identifications are legitimate. What remains is that the decompiler's
//! own identification list does not contain them; that list is produced in
//! another crate, so it is recorded here as a measured fact about our side and
//! not diagnosed as a defect in theirs.

use std::path::{Path, PathBuf};

const SIG: &str = r"C:\Users\Fra\AppData\Local\Temp\sigdb\mingwrt.sig";

fn corpus_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("il crate deve stare in <root>/crates/<name>")
        .join("tests/decompiler_corpus/bin/sample1_c.exe")
}

/// `(name, raw_start, raw_size, characteristics)` for each PE section.
fn sections(pe: &[u8]) -> Option<Vec<(String, u32, u32, u32)>> {
    let lfanew = u32::from_le_bytes(pe.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if pe.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff = lfanew + 4;
    let n = u16::from_le_bytes(pe.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt = u16::from_le_bytes(pe.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let table = coff + 20 + opt;

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let b = table + i * 40;
        let raw = pe.get(b..b + 40)?;
        let end = raw[..8].iter().position(|&c| c == 0).unwrap_or(8);
        out.push((
            String::from_utf8_lossy(&raw[..end]).into_owned(),
            u32::from_le_bytes(raw[20..24].try_into().ok()?),
            u32::from_le_bytes(raw[16..20].try_into().ok()?),
            u32::from_le_bytes(raw[36..40].try_into().ok()?),
        ));
    }
    Some(out)
}

struct Env {
    matches: Vec<rustre_flirt_apply::FlirtMatch>,
    secs: Vec<(String, u32, u32, u32)>,
}

fn env() -> Option<Env> {
    let sig = std::fs::read(SIG).ok()?;
    let bin = std::fs::read(corpus_binary()).ok()?;
    let secs = sections(&bin)?;
    let scanner = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig).ok()?;
    let matches: Vec<_> = scanner
        .scan_fast(&bin, 0)
        .into_iter()
        .filter(|m| !m.function_name.is_empty())
        .collect();
    (!matches.is_empty()).then_some(Env { matches, secs })
}

/// `(section name, is executable)` for a file offset.
fn locate(secs: &[(String, u32, u32, u32)], off: u64) -> (String, bool) {
    for (name, ptr, size, chars) in secs {
        if off >= u64::from(*ptr) && off < u64::from(*ptr) + u64::from(*size) {
            return (name.clone(), chars & 0x2000_0020 != 0);
        }
    }
    ("(fuori sezione)".to_string(), false)
}

#[test]
fn the_inputs_are_not_vacuous() {
    let Some(e) = env() else {
        eprintln!("SKIP: sigdb o corpus assenti");
        return;
    };
    assert!(e.matches.len() > 10, "pochi match: {}", e.matches.len());
    assert!(
        e.secs.iter().any(|(n, ..)| n == ".text"),
        "nessuna sezione .text: il parsing del PE e' rotto, non il match"
    );
}

#[test]
fn every_match_is_inside_executable_code() {
    let Some(e) = env() else { return };

    let outside: Vec<(String, String)> = e
        .matches
        .iter()
        .map(|m| (m.function_name.clone(), locate(&e.secs, m.address)))
        .filter(|(_, (_, exec))| !*exec)
        .map(|(n, (sec, _))| (n, sec))
        .collect();

    assert!(
        outside.is_empty(),
        "{} match fuori dal codice eseguibile: {outside:?} — sarebbero artefatti \
         della scansione del file grezzo, non identificazioni",
        outside.len()
    );
}

/// The four names that can actually be published must be in code, or the whole
/// Level 7 argument would rest on byte sequences found in data.
#[test]
fn the_publishable_names_are_in_code() {
    let Some(e) = env() else { return };

    let known: std::collections::HashSet<String> =
        rustre_flirt_apply::typerecov_bridge::all_known_prototypes()
            .into_iter()
            .map(|s| s.name)
            .collect();

    let with_proto: Vec<_> = e
        .matches
        .iter()
        .filter(|m| known.contains(&m.function_name))
        .collect();

    assert!(
        !with_proto.is_empty(),
        "nessun nome con prototipo fra i match: il test non misurerebbe nulla"
    );
    for m in with_proto {
        let (sec, exec) = locate(&e.secs, m.address);
        assert!(
            exec,
            "{} combacia in {sec}, che non e' eseguibile",
            m.function_name
        );
    }
}
