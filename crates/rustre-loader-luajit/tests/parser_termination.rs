//! Termination and output-bound properties for the LuaJIT bytecode loader.
//!
//! Same shape as `rustre-loader/tests/parser_termination.rs`, and motivated by
//! the same real defect: in `rustre-trace-pt` a decoder rewound its position on
//! a truncated packet yet still reported progress, so the collector looped and
//! the process died allocating 40 GiB from 54 random bytes. No test went red —
//! the process simply aborted.
//!
//! Bytecode is length-prefixed at every level (constants, upvalues, prototypes),
//! so a hostile or truncated file is exactly where a count can be believed
//! without being checked against the bytes actually present.

use rustre_loader_luajit::{read_sleb128, read_uleb128, LuaJitLoader};

/// Deterministic PRNG — no external crates, reproducible failures.
struct Lcg(u64);

impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() >> 24) as u8).collect()
    }
}

/// LuaJIT bytecode magic: ESC 'L' 'J'. Without it the loader rejects the input
/// immediately and never reaches the length-prefixed parsing paths.
const LJ_MAGIC: [u8; 3] = [0x1B, 0x4C, 0x4A];

fn corpus() -> Vec<Vec<u8>> {
    let mut lcg = Lcg(0xFEED_FACE_C0FF_EE00);
    let mut out = vec![Vec::new(), LJ_MAGIC.to_vec()];
    for n in [1usize, 4, 9, 17, 40, 96] {
        for _ in 0..12 {
            out.push(lcg.bytes(n));
            let mut with_magic = LJ_MAGIC.to_vec();
            with_magic.push(0x02); // plausible version byte
            with_magic.extend(lcg.bytes(n));
            out.push(with_magic);
        }
    }
    out
}

/// Loading arbitrary bytes must terminate and must not invent prototypes.
#[test]
fn load_terminates_and_cannot_exceed_the_input() {
    for data in corpus() {
        let Ok(module) = LuaJitLoader::load(&data) else {
            continue;
        };
        let protos = module.all_protos().len();
        assert!(
            protos <= data.len().max(1),
            "loaded {protos} prototypes from {} bytes — more items than input \
             means something is not consuming",
            data.len()
        );
    }
}

/// `read_uleb128` must never loop forever and never consume past the end.
///
/// A 9-byte all-continuation sequence is the shape that overruns a naive
/// decoder: every byte says "more follows" and the shift walks past 64.
#[test]
fn uleb128_is_bounded_on_hostile_input() {
    let all_continuation = vec![0xFFu8; 32];
    assert_eq!(
        read_uleb128(&all_continuation, 0),
        None,
        "a sequence that never terminates must be rejected, not decoded"
    );

    // Truncated: continuation bit set on the final byte.
    assert_eq!(read_uleb128(&[0x80], 0), None);
    assert_eq!(read_uleb128(&[], 0), None);

    // Well-formed values still decode, and never report consuming past the end.
    for (bytes, want) in [(vec![0x00u8], 0u64), (vec![0x7F], 127), (vec![0x80, 0x01], 128)] {
        let (v, pos) = read_uleb128(&bytes, 0).expect("well-formed");
        assert_eq!(v, want);
        assert!(pos <= bytes.len(), "consumed {pos} of {} bytes", bytes.len());
    }
}

/// The signed decoder must obey the same bounds.
#[test]
fn sleb128_is_bounded_on_hostile_input() {
    assert_eq!(read_sleb128(&vec![0xFFu8; 32], 0), None);
    assert_eq!(read_sleb128(&[], 0), None);

    for bytes in [vec![0x00u8], vec![0x3F], vec![0x40], vec![0xFF, 0x00]] {
        if let Some((_, pos)) = read_sleb128(&bytes, 0) {
            assert!(pos <= bytes.len(), "consumed {pos} of {} bytes", bytes.len());
        }
    }
}

/// Guards the load property against passing vacuously.
#[test]
fn the_corpus_actually_reaches_the_loader() {
    let accepted = corpus().iter().filter(|d| LuaJitLoader::can_load(d)).count();
    assert!(
        accepted >= 8,
        "only {accepted} inputs were even recognised as LuaJIT bytecode — the \
         termination property would hold without the parser running"
    );
}
