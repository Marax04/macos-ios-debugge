//! Definitional oracle + randomized differential testing for
//! `rustre_analysis_fn::detect_functions_at`.
//!
//! Function detection is inherently heuristic, so this file does NOT assert an
//! exact expected function list.  It asserts the properties that "a function
//! starts at address A inside the buffer [base, base+len)" MUST satisfy for the
//! result to be meaningful at all, each derived from the meaning of the output
//! type and not from the detector's algorithm:
//!
//!   P1 containment  — every reported start lies in [base, base+len); every
//!                     reported end lies in (start, base+len].
//!   P2 ordering     — `functions` is documented as "sorted by address"; a set
//!                     of boundaries therefore must be strictly ascending in
//!                     `start` (sorted AND deduplicated).
//!   P3 determinism  — the same bytes at the same base give byte-identical
//!                     results across repeated calls (a changing answer is a
//!                     defect to report, never to hide by sorting).
//!   P4 rebasing     — x86 control flow is PC-relative, so detection is a
//!                     function of the BYTES; loading the same bytes at a
//!                     different image base must translate every result by
//!                     exactly the base delta.
//!   P5 recall       — a buffer synthesised to contain N textbook SysV/MS-ABI
//!                     prologues (`push rbp; mov rbp,rsp`, 55 48 89 E5), each
//!                     preceded by inter-function padding and terminated by
//!                     `ret`, must report each of those N addresses.
//!
//! NEGATIVE CONTROL: set `ORACLE_CORRUPT` to `bounds_exclusive` or
//! `recall_off_by_one` and re-run; the tests must FAIL.

use rustre_analysis_fn::{DetectedArch, detect_functions_at};

fn corrupt(kind: &str) -> bool {
    std::env::var("ORACLE_CORRUPT").is_ok_and(|v| v == kind)
}

// ───────────────────────────── deterministic PRNG ────────────────────────────

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0xA076_1D64_78BD_642F)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

// ───────────────────────── synthesised code corpus ───────────────────────────

/// Textbook frame-pointer prologue: `push rbp; mov rbp, rsp`.
const PROLOGUE: [u8; 4] = [0x55, 0x48, 0x89, 0xE5];
/// `pop rbp; ret`
const EPILOGUE: [u8; 2] = [0x5D, 0xC3];

/// Inter-function padding shapes real linkers emit.
const PADS: [&[u8]; 4] = [
    &[0xCC],                   // int3
    &[0x90],                   // nop
    &[0x00],                   // zero fill
    &[0x66, 0x0F, 0x1F, 0x44], // multi-byte nop prefix
];

/// Harmless straight-line body bytes (no prologue substring).
const BODY: [&[u8]; 5] = [
    &[0x48, 0x83, 0xEC, 0x20],       // sub rsp, 0x20
    &[0x48, 0x89, 0xC8],             // mov rax, rcx
    &[0x31, 0xC0],                   // xor eax, eax
    &[0x48, 0x83, 0xC4, 0x20],       // add rsp, 0x20
    &[0xB8, 0x01, 0x00, 0x00, 0x00], // mov eax, 1
];

struct Sample {
    bytes: Vec<u8>,
    /// Offsets at which a textbook prologue was planted.
    planted: Vec<usize>,
    /// Shape tags for coverage assertions.
    tags: Vec<&'static str>,
}

fn gen_sample(rng: &mut Rng) -> Sample {
    let n_funcs = 1 + rng.below(6) as usize;
    let mut bytes = Vec::new();
    let mut planted = Vec::new();
    let mut tags = Vec::new();

    // Half the samples start a function at offset 0 (boundary case), the other
    // half begin with leading padding (misaligned first function).
    if rng.next() % 2 == 0 {
        tags.push("starts_at_base");
    } else {
        let lead = 1 + rng.below(7) as usize;
        bytes.extend(std::iter::repeat_n(0xCCu8, lead));
        tags.push("leading_pad");
    }

    for i in 0..n_funcs {
        if i > 0 {
            // Gap: sometimes zero (back-to-back functions), sometimes long.
            let gap = match rng.below(3) {
                0 => 0,
                1 => 1 + rng.below(4) as usize,
                _ => 16 + rng.below(32) as usize,
            };
            if gap == 0 {
                tags.push("adjacent_funcs");
            } else if gap >= 16 {
                tags.push("large_gap");
            }
            let pad = *rng.pick(&PADS);
            let mut written = 0;
            while written < gap {
                let take = pad.len().min(gap - written);
                bytes.extend_from_slice(&pad[..take]);
                written += take;
            }
        }
        if bytes.len() % 16 == 0 {
            tags.push("aligned_16");
        } else {
            tags.push("unaligned");
        }
        planted.push(bytes.len());
        bytes.extend_from_slice(&PROLOGUE);
        for _ in 0..(1 + rng.below(5)) {
            bytes.extend_from_slice(rng.pick(&BODY));
        }
        bytes.extend_from_slice(&EPILOGUE);
    }
    Sample {
        bytes,
        planted,
        tags,
    }
}

// ───────────────────────────── shared helpers ────────────────────────────────

fn starts(set: &rustre_analysis_fn::FunctionBoundarySet) -> Vec<u64> {
    set.functions.iter().map(|f| f.start.as_u64()).collect()
}

fn fingerprint(set: &rustre_analysis_fn::FunctionBoundarySet) -> String {
    // stats carry timing, so fingerprint only the boundaries themselves.
    set.functions
        .iter()
        .map(|f| {
            format!(
                "{:x}|{:?}|{:?}|{:?}|{:?};",
                f.start.as_u64(),
                f.end.map(|e| e.as_u64()),
                f.confidence,
                f.source,
                f.name
            )
        })
        .collect()
}

const ARCH: DetectedArch = DetectedArch::X86_64;

// ─────────────────────────────── the tests ───────────────────────────────────

#[test]
fn oracle_containment_ordering_and_determinism() {
    let mut rng = Rng::new(0xDEAD_BEEF);
    let mut seen_tags: std::collections::BTreeSet<&'static str> = Default::default();
    let mut total_reported = 0usize;
    let mut saw_start_at_base = false;

    for iter in 0..400u64 {
        let s = gen_sample(&mut rng);
        seen_tags.extend(s.tags.iter().copied());
        // Exercise base 0 and high non-zero bases.
        let base = match iter % 3 {
            0 => 0u64,
            1 => 0x1_4000_1000,
            _ => 0x7FF6_0000_0000,
        };
        let limit = base + s.bytes.len() as u64;

        let set = detect_functions_at(ARCH, base, &s.bytes);
        total_reported += set.functions.len();

        // P1 containment.
        for f in &set.functions {
            let v = f.start.as_u64();
            let lower_ok = if corrupt("bounds_exclusive") {
                v > base // CORRUPTION: excludes the legal boundary v == base
            } else {
                v >= base
            };
            assert!(
                lower_ok && v < limit,
                "iter {iter}: start {v:#x} outside searched region [{base:#x},{limit:#x})"
            );
            if v == base {
                saw_start_at_base = true;
            }
            if let Some(e) = f.end {
                let e = e.as_u64();
                assert!(
                    e > v && e <= limit,
                    "iter {iter}: end {e:#x} not in ({v:#x},{limit:#x}]"
                );
            }
        }

        // P2 ordering: strictly ascending == sorted and deduplicated.
        let st = starts(&set);
        for w in st.windows(2) {
            assert!(
                w[0] < w[1],
                "iter {iter}: boundaries not strictly ascending: {:#x} then {:#x}",
                w[0],
                w[1]
            );
        }

        // P3 determinism.
        let fp = fingerprint(&set);
        for rep in 0..2 {
            let again = detect_functions_at(ARCH, base, &s.bytes);
            assert_eq!(
                fp,
                fingerprint(&again),
                "iter {iter}: non-deterministic result on repeat {rep}"
            );
        }
    }

    // Generator coverage — fail loudly if a hard shape dried up.
    for want in [
        "starts_at_base",
        "leading_pad",
        "adjacent_funcs",
        "large_gap",
        "aligned_16",
        "unaligned",
    ] {
        assert!(seen_tags.contains(want), "generator never produced `{want}`");
    }
    assert!(
        total_reported > 400,
        "generator too weak: only {total_reported} boundaries reported across 400 samples"
    );
    assert!(
        saw_start_at_base,
        "generator never produced a function at the very base address \
         (the bounds check would then be vacuous)"
    );
}

#[test]
fn oracle_rebasing_is_a_pure_translation() {
    let mut rng = Rng::new(0x1234_5678);
    let mut compared = 0usize;
    for iter in 0..200u64 {
        let s = gen_sample(&mut rng);
        let a = detect_functions_at(ARCH, 0, &s.bytes);
        let delta = 0x1_4000_0000u64;
        let b = detect_functions_at(ARCH, delta, &s.bytes);
        let expect: Vec<u64> = starts(&a).into_iter().map(|v| v + delta).collect();
        assert_eq!(
            expect,
            starts(&b),
            "iter {iter}: rebasing by {delta:#x} was not a pure translation"
        );
        compared += expect.len();
    }
    assert!(compared > 200, "coverage: only {compared} boundaries compared");
}

#[test]
fn oracle_recall_of_planted_prologues() {
    let mut rng = Rng::new(0x0BAD_C0DE);
    let mut planted_total = 0usize;
    let mut recalled_total = 0usize;
    let mut samples_with_multiple = 0usize;

    for _ in 0..300 {
        let s = gen_sample(&mut rng);
        if s.planted.len() > 1 {
            samples_with_multiple += 1;
        }
        let base = 0x1_4000_1000u64;
        let set = detect_functions_at(ARCH, base, &s.bytes);
        let got: std::collections::BTreeSet<u64> = starts(&set).into_iter().collect();
        for &off in &s.planted {
            let want = if corrupt("recall_off_by_one") {
                base + off as u64 + 1 // CORRUPTION: expect the wrong address
            } else {
                base + off as u64
            };
            planted_total += 1;
            if got.contains(&want) {
                recalled_total += 1;
            }
        }
    }

    assert!(planted_total > 300, "generator too weak: {planted_total} prologues");
    assert!(
        samples_with_multiple > 50,
        "generator rarely plants multiple functions per buffer ({samples_with_multiple})"
    );
    // Detection is heuristic, but a textbook frame-pointer prologue delimited by
    // padding and a `ret` is the least ambiguous shape that exists: essentially
    // all of them must be found.
    assert!(
        recalled_total * 100 >= planted_total * 95,
        "recall of textbook prologues collapsed: {recalled_total}/{planted_total}"
    );
}
