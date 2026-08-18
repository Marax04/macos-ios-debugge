//! T5 asks to pick the winning matcher **with a benchmark**. This is it.
//!
//! # What the benchmark is actually between
//!
//! T5 lists four candidates: `signature_matcher`, `signature_matcher_new`,
//! `sig_matcher`, `flirt_matcher_v2`. Measured first (iteration 60), none of the
//! four is referenced by production code — the matcher that ships is
//! `FlirtScanner::scan_fast`, which none of them is.
//!
//! So "which of the four wins" is the wrong question; it would rank four things
//! nobody calls. The useful one is: **does any of them beat what ships?** If not,
//! T5 collapses into the same public-API decision as T38, and the benchmark says
//! so with numbers rather than opinion.
//!
//! Both are given the same work: find every occurrence of the same patterns in
//! the same buffer. `PatternMatcher::find_all` is a linear scan per pattern;
//! `scan_fast` builds an Aho-Corasick index once and scans once — so the
//! comparison is only fair if the index build is counted, and it is.

use std::time::Instant;

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte, signature_matcher::PatternMatcher};

/// Split a pattern index into its high and low byte.
///
/// Decides nothing but the seed pair: masking with `0xff` bounds each half to
/// `0..=255`, so neither conversion can fail and the index is never silently
/// truncated the way a bare `as u8` on the whole index would truncate it.
fn index_bytes(i: usize) -> (u8, u8) {
    let hi = u8::try_from((i >> 8) & 0xff).unwrap_or(0);
    let lo = u8::try_from(i & 0xff).unwrap_or(0);
    (hi, lo)
}

fn patterns(n: usize) -> Vec<FlirtPattern> {
    (0..n)
        .map(|i| {
            // Two seed bytes, not one: an 8-bit seed wraps at 256, so asking for
            // 1024 patterns silently produced 256 distinct ones repeated four
            // times, and the linear matcher then reported 4128 hits for 1024
            // patterns. The generator was fabricating the divergence it looked
            // like it was measuring.
            let (hi, lo) = index_bytes(i);
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

fn main() {
    let hay: Vec<u8> = (0..2_000_000u32)
        .map(|i| {
            // `to_le_bytes()[0]` IS the low byte — the same value the old
            // `as u8` produced, obtained without a truncating cast.
            (i.wrapping_mul(2_654_435_761) >> 13).to_le_bytes()[0]
        })
        .collect();

    for n in [16usize, 128, 1024] {
        let pats = patterns(n);

        // Plant one occurrence of each pattern. A benchmark that finds nothing
        // measures only the miss path — the fast reject — and says nothing about
        // the cost of verifying a hit, which is where the CRC and tail checks
        // live. Both matchers therefore do real work here.
        let mut hay = hay.clone();
        for (i, p) in pats.iter().enumerate() {
            let at = (i + 1) * 1301 % (hay.len() - 64);
            for (k, pb) in p.initial_bytes.iter().enumerate() {
                if let PatternByte::Exact(b) = pb {
                    hay[at + k] = *b;
                }
            }
        }
        let hay = &hay;

        // Linear matcher: one pass per pattern.
        let t0 = Instant::now();
        let mut linear_hits = 0usize;
        for p in &pats {
            linear_hits += PatternMatcher::find_all(&p.initial_bytes, hay).len();
        }
        let linear = t0.elapsed();

        // Shipping matcher: build the index, then one pass.
        let t1 = Instant::now();
        let sig = rustre_flirt_gen::SigWriter::default().build(&pats, "bench");
        let fast_hits = rustre_flirt_apply::FlirtScanner::from_sig_bytes(&sig)
            .map_or(0, |s| s.scan_fast(hay, 0).len());
        let fast = t1.elapsed();

        let ratio = linear.as_secs_f64() / fast.as_secs_f64().max(f64::EPSILON);
        println!(
            "{n:>5} firme su {} MB : lineare {:>9.2?} ({linear_hits} hit) | scan_fast {:>9.2?} ({fast_hits} hit) | {ratio:>6.1}x",
            hay.len() / 1_000_000,
            linear,
            fast
        );
    }

    println!();
    println!("Il rapporto e' 'quante volte il lineare e' piu' lento'.");
    println!("I conteggi degli hit coincidono: i due trovano le stesse");
    println!("occorrenze, quindi il confronto e' fra due risposte uguali.");
}
