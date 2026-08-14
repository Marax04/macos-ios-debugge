//! A patch over an opaque predicate must cover the branch it neutralises.
//!
//! Each detected predicate reports an `offset` and a `patch_length`, and callers
//! use the pair as the region to overwrite (`lib.rs` builds a patch region from
//! it and also sums the lengths as "bytes removed"). The point of the patch is to
//! remove a conditional branch whose outcome is fixed. If the length stops short
//! of the jump opcode, the branch survives the patch — the deobfuscator reports
//! the predicate as handled while the control flow it was supposed to straighten
//! is still there.
//!
//! The property is derived from what the patch is *for*, not copied from the
//! table: whatever bytes a pattern matches, the jump opcode inside it must fall
//! within `offset .. offset + patch_length`.

use rustre_deobf_mhcde::{OpaquePredicateDetector, OpaquePredicateType};

/// x86 conditional-jump opcodes used by the patterns in this detector.
const JUMP_OPCODES: &[u8] = &[
    0x74, // jz / je
    0x75, // jnz / jne
    0x72, // jc / jb
    0x73, // jnc / jae
    0xE3, // jecxz
];

/// All twelve byte sequences the detector recognises, each followed by a jump
/// displacement.
///
/// The displacement is deliberately `0x10` — not itself a jump opcode — so that
/// finding a jump opcode past the patch means the *pattern's* jump survived,
/// rather than the displacement byte being misread.
///
/// The list must stay complete. A first pass covered only seven of the twelve,
/// and the two patterns with a wrong `patch_length` fell one either side of that
/// split: the sampled version found one defect and missed its twin. A property
/// is only as good as the inputs it is applied to.
fn patterns() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("1: xor eax,eax; test eax,eax; jz", vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x10]),
        ("2: xor eax,eax; test eax,eax; jnz", vec![0x31, 0xC0, 0x85, 0xC0, 0x75, 0x10]),
        ("3: mov al,1; test al,al; jz", vec![0xB0, 0x01, 0x84, 0xC0, 0x74, 0x10]),
        ("4: or eax,-1; test eax,eax; jnz", vec![0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x10]),
        ("5: and eax,0; test eax,eax; jz", vec![0x83, 0xE0, 0x00, 0x85, 0xC0, 0x74, 0x10]),
        ("6: xor eax,eax; jz (condensed)", vec![0x33, 0xC0, 0x74, 0x10]),
        ("7: xor ecx,ecx; jecxz", vec![0x33, 0xC9, 0xE3, 0x10]),
        ("8: xor eax,eax; cmp eax,eax; jz", vec![0x31, 0xC0, 0x39, 0xC0, 0x74, 0x10]),
        ("9: mov eax,0; test eax,eax; jz", vec![0xB8, 0, 0, 0, 0, 0x85, 0xC0, 0x74, 0x10]),
        ("10: stc; jc", vec![0xF9, 0x72, 0x10]),
        ("11: clc; jnc", vec![0xF8, 0x73, 0x10]),
        (
            "12: xor eax,eax; or eax,1; test eax,eax; jnz",
            vec![0x31, 0xC0, 0x83, 0xC8, 0x01, 0x85, 0xC0, 0x75, 0x10],
        ),
    ]
}

/// Every reported patch must extend past the jump opcode it neutralises.
#[test]
fn a_patch_covers_the_branch_it_neutralises() {
    let detector = OpaquePredicateDetector::default();
    let mut checked = 0usize;

    for (name, bytes) in patterns() {
        for predicate in detector.detect(&bytes) {
            // Where is the jump opcode inside the matched sequence? It is the
            // last opcode of the pattern, immediately before the displacement.
            let jump_index = bytes.len() - 2;
            assert!(
                JUMP_OPCODES.contains(&bytes[jump_index]),
                "{name}: fixture is malformed — byte {jump_index} is not a jump opcode"
            );

            let patch_end = predicate.offset + predicate.patch_length;
            assert!(
                patch_end > jump_index,
                "{name}: patch covers bytes {}..{patch_end} but the jump opcode \
                 {:#04x} sits at {jump_index}, so the branch survives the patch",
                predicate.offset,
                bytes[jump_index]
            );
            checked += 1;
        }
    }

    // Anti-vacuity: if the detector recognised nothing, every assertion above
    // would hold without a single patch being examined.
    assert!(
        checked >= patterns().len(),
        "only {checked} predicates were detected across {} fixtures — every pattern \
         must match its own byte sequence, so a shortfall means the detector stopped \
         recognising one",
        patterns().len()
    );
}

/// A patch must never claim more bytes than the sequence it matched.
///
/// The opposite error: overwriting past the predicate would destroy an unrelated
/// instruction that follows it.
#[test]
fn a_patch_stays_inside_the_pattern() {
    let detector = OpaquePredicateDetector::default();

    for (name, bytes) in patterns() {
        for predicate in detector.detect(&bytes) {
            let patch_end = predicate.offset + predicate.patch_length;
            assert!(
                patch_end <= bytes.len(),
                "{name}: patch ends at {patch_end}, past the {}-byte sequence",
                bytes.len()
            );
        }
    }
}

/// The reported truth value must match what the instructions actually do.
///
/// Derived from the semantics rather than from the table: `xor r,r` and `mov r,0`
/// leave ZF set, `mov al,1` and `or eax,-1` leave it clear, and `stc`/`clc` set
/// and clear CF. Whether the branch is taken then follows from the jump opcode.
#[test]
fn the_reported_outcome_matches_the_instructions() {
    let detector = OpaquePredicateDetector::default();
    let mut checked = 0usize;

    // (fixture, zero-flag after the setup, carry flag after the setup)
    let cases: Vec<(&str, Vec<u8>, Option<bool>, Option<bool>)> = vec![
        ("xor/jz", vec![0x31, 0xC0, 0x85, 0xC0, 0x74, 0x10], Some(true), None),
        ("xor/jnz", vec![0x31, 0xC0, 0x85, 0xC0, 0x75, 0x10], Some(true), None),
        ("mov al,1/jz", vec![0xB0, 0x01, 0x84, 0xC0, 0x74, 0x10], Some(false), None),
        ("or -1/jnz", vec![0x83, 0xC8, 0xFF, 0x85, 0xC0, 0x75, 0x10], Some(false), None),
        ("mov eax,0/jz", vec![0xB8, 0, 0, 0, 0, 0x85, 0xC0, 0x74, 0x10], Some(true), None),
        ("stc/jc", vec![0xF9, 0x72, 0x10], None, Some(true)),
        ("clc/jnc", vec![0xF8, 0x73, 0x10], None, Some(false)),
    ];

    for (name, bytes, zf, cf) in cases {
        let jump = bytes[bytes.len() - 2];
        let taken = match jump {
            0x74 => zf.expect("jz needs ZF"),
            0x75 => !zf.expect("jnz needs ZF"),
            0x72 => cf.expect("jc needs CF"),
            0x73 => !cf.expect("jnc needs CF"),
            other => panic!("{name}: unhandled jump opcode {other:#04x}"),
        };

        for predicate in detector.detect(&bytes) {
            let reported = matches!(predicate.predicate_type, OpaquePredicateType::AlwaysTrue);
            assert_eq!(
                reported, taken,
                "{name}: the flags say the branch is {}taken, but it is reported as {:?}",
                if taken { "" } else { "not " },
                predicate.predicate_type
            );
            checked += 1;
        }
    }

    assert!(checked >= 6, "only {checked} predicates checked against the flags");
}

/// The description and the typed field are two records of one fact.
#[test]
fn the_description_agrees_with_the_type() {
    let detector = OpaquePredicateDetector::default();
    let mut checked = 0usize;

    for (_, bytes) in patterns() {
        for predicate in detector.detect(&bytes) {
            let says_always = predicate.description.contains("always taken");
            let says_never = predicate.description.contains("never taken");
            assert!(
                says_always ^ says_never,
                "description {:?} states neither or both outcomes",
                predicate.description
            );
            assert_eq!(
                says_always,
                matches!(predicate.predicate_type, OpaquePredicateType::AlwaysTrue),
                "description {:?} disagrees with predicate_type {:?}",
                predicate.description,
                predicate.predicate_type
            );
            checked += 1;
        }
    }

    assert!(checked >= 12, "only {checked} descriptions checked");
}
