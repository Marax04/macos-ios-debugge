//! Both matchers find the same planted occurrences (T5).
//!
//! # Why correctness belongs in the benchmark's file, not after it
//!
//! T5 asks to choose the winning matcher with a benchmark. A speed ranking is
//! only meaningful between implementations that return the same answer, so this
//! pins the answer while `examples/matcher_benchmark.rs` measures the speed.
//!
//! Measured there (2 MB buffer, one planted occurrence per signature):
//!
//! | signatures | linear | `scan_fast` | ratio |
//! |---|---|---|---|
//! | 16 | 21.9 ms | 0.49 ms | 44× |
//! | 128 | 174 ms | 0.76 ms | 229× |
//! | 1024 | 1.46 s | 6.95 ms | 209× |
//!
//! Hit counts agree exactly at every size.
//!
//! # A generator bug the benchmark caught in itself
//!
//! The first version seeded each pattern from `i as u8`, which wraps at 256: 1024
//! requested patterns were 256 distinct ones repeated, and the linear matcher
//! reported 4128 hits against 1024. The benchmark was fabricating the divergence
//! it appeared to measure. Two seed bytes fixed it, and the counts then matched.
//! Recorded because a benchmark's own inputs need the same scrutiny as the code
//! under test.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte, signature_matcher::PatternMatcher};

fn distinct_patterns(n: usize) -> Vec<FlirtPattern> {
    (0..n)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            let (hi, lo) = ((i >> 8) as u8, i as u8);
            let bytes: Vec<PatternByte> = (0u8..24)
                .map(|k| match k {
                    0 => PatternByte::Exact(hi),
                    1 => PatternByte::Exact(lo),
                    _ => PatternByte::Exact(lo.wrapping_mul(31).wrapping_add(k ^ hi)),
                })
                .collect();
            let mut p = FlirtPattern::new(bytes);
            p.pattern_length = 24;
            p.names.push(FlirtName {
                offset: 0,
                name: format!("fn_{i}"),
                is_public: true,
                is_local: false,
            });
            p
        })
        .collect()
}

/// A buffer with one occurrence of each pattern planted at a known offset.
fn haystack_with(pats: &[FlirtPattern]) -> Vec<u8> {
    let mut hay: Vec<u8> = (0..200_000u32)
        .map(|i| {
            #[allow(clippy::cast_possible_truncation)]
            let v = (i.wrapping_mul(2_654_435_761) >> 13) as u8;
            v
        })
        .collect();
    for (i, p) in pats.iter().enumerate() {
        let at = (i + 1) * 131 % (hay.len() - 64);
        for (k, pb) in p.initial_bytes.iter().enumerate() {
            if let PatternByte::Exact(b) = pb {
                hay[at + k] = *b;
            }
        }
    }
    hay
}

#[test]
fn the_generator_produces_distinct_patterns() {
    // The guard for the bug described above: if the patterns repeat, every count
    // below becomes meaningless and the benchmark measures its own generator.
    let pats = distinct_patterns(1024);
    let mut seen = std::collections::HashSet::new();
    for p in &pats {
        let key: Vec<u8> = p
            .initial_bytes
            .iter()
            .map(|b| match b {
                PatternByte::Exact(v) => *v,
                PatternByte::Wildcard => 0,
            })
            .collect();
        assert!(seen.insert(key), "pattern duplicato: il seed satura");
    }
}

#[test]
fn both_matchers_find_every_planted_occurrence() {
    for n in [16usize, 128] {
        let pats = distinct_patterns(n);
        let hay = haystack_with(&pats);

        let linear: usize = pats
            .iter()
            .map(|p| PatternMatcher::find_all(&p.initial_bytes, &hay).len())
            .sum();

        let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "agree");
        let fast = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
            .expect("il .sig deve essere leggibile")
            .scan_fast(&hay, 0)
            .len();

        assert_eq!(
            linear, n,
            "il matcher lineare trova {linear} occorrenze su {n} piantate"
        );
        assert_eq!(
            fast, n,
            "scan_fast trova {fast} occorrenze su {n} piantate"
        );
    }
}
