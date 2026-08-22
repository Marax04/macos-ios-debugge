//! Termination and output-bound properties for byte-slice entry points.
//!
//! Motivated by a real defect found the same way in `rustre-trace-pt`: a decoder
//! rewound its position on a truncated packet but still reported progress, so
//! the collector looped forever and the process died allocating 40 GiB from 54
//! random bytes. Nothing panicked and no test went red — the process simply
//! aborted.
//!
//! The invariant used here is deliberately cheap and safe: **a parser cannot
//! emit more items than the input has bytes**. Every region, section or record
//! must be backed by at least one byte, so a result larger than the input is
//! proof of a loop that is not consuming anything — and it fails the assertion
//! long before memory runs out.

use rustre_loader::overlay_detector::detect_overlay;

/// Deterministic small PRNG — no external crates, reproducible failures.
struct Lcg(u64);

impl Lcg {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

/// Inputs that look like the start of a real format, plus pure noise. Magic
/// bytes matter: they push the detector down the parsing paths that loop,
/// rather than being rejected immediately.
fn corpus() -> Vec<Vec<u8>> {
    let mut lcg = Lcg(0x0BAD_C0DE_DEAD_BEEF);
    let mut out = vec![
        Vec::new(),
        vec![0u8],
        b"MZ".to_vec(),
        b"\x7fELF".to_vec(),
        b"MZ\x90\x00\x03\x00\x00\x00".to_vec(),
    ];
    for n in [1usize, 2, 7, 16, 33, 64] {
        for _ in 0..12 {
            out.push(lcg.bytes(n));
            // Same length, but prefixed with a PE magic so detection proceeds.
            let mut with_magic = b"MZ".to_vec();
            with_magic.extend(lcg.bytes(n));
            out.push(with_magic);
        }
    }
    out
}

/// `detect_overlay` must terminate and cannot report more regions than bytes.
#[test]
fn detect_overlay_terminates_and_is_bounded_by_input() {
    for data in corpus() {
        let Ok(regions) = detect_overlay(&data) else {
            continue;
        };
        assert!(
            regions.len() <= data.len(),
            "detect_overlay returned {} regions for {} bytes — more items than \
             input means nothing is being consumed",
            regions.len(),
            data.len()
        );
        // Every reported region must lie inside the input it came from.
        for r in &regions {
            let end = r.offset.saturating_add(r.size);
            assert!(
                end <= data.len(),
                "region [{}, {}) runs past the {}-byte input",
                r.offset,
                end,
                data.len()
            );
        }
    }
}

/// Guards the test above against passing vacuously: if every input were
/// rejected outright, the bound would hold without the parser ever running.
#[test]
fn the_corpus_actually_reaches_the_parser() {
    let parsed = corpus()
        .into_iter()
        .filter(|d| detect_overlay(d).is_ok())
        .count();
    assert!(
        parsed >= 8,
        "only {parsed} inputs were accepted — the termination property would be \
         holding without exercising the parsing paths"
    );
}
