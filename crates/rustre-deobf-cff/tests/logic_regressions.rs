//! Regression tests for logic defects found by the wave-2 semantic audit.
//!
//! Written BEFORE their fixes and confirmed to fail against the then-current
//! code, with the exact symptom the audit predicted.

use rustre_core::address::Address;
use rustre_deobf_cff::{CffDetector, EdgeType, SimpleBb, SimpleCfg, StateVariable};

fn bb(address: u64, sets_register: Option<&str>) -> SimpleBb {
    SimpleBb {
        address: Address::from(address),
        successor_count: 1,
        predecessor_count: 1,
        instr_count: 4,
        ends_with_indirect_jump: false,
        ends_with_conditional: false,
        sets_register: sets_register.map(std::string::ToString::to_string),
        state_const: None,
    }
}

/// A CFG whose dispatcher (index 0) is reached from four predecessors: two set
/// `eax`, two set `ecx`. The frequencies tie at 2–2.
fn tied_cfg() -> SimpleCfg {
    let mut cfg = SimpleCfg {
        blocks: vec![
            bb(0x1000, None),          // 0: dispatcher
            bb(0x1010, Some("eax")),   // 1
            bb(0x1020, Some("ecx")),   // 2
            bb(0x1030, Some("eax")),   // 3
            bb(0x1040, Some("ecx")),   // 4
        ],
        edges: vec![
            (1, 0, EdgeType::Unconditional),
            (2, 0, EdgeType::Unconditional),
            (3, 0, EdgeType::Unconditional),
            (4, 0, EdgeType::Unconditional),
        ],
    };
    cfg.recompute_predecessor_counts();
    cfg
}

/// `identify_state_variable` picks the most frequent register with
/// `reg_freq.into_iter().max_by_key(..)`. On a tie `max_by_key` returns an
/// ARBITRARY winner, and the iteration order of a `HashMap` differs from run to
/// run — so the same function, analysed twice, reports `eax` once and `ecx` the
/// next time.
///
/// A deobfuscator whose answer changes between runs cannot be compared against
/// itself, and nothing in the test suite notices.
#[test]
fn the_state_variable_is_the_same_on_every_run() {
    let detector = CffDetector::new();
    let first = detector.identify_state_variable(&tied_cfg(), 0);

    for _ in 0..64 {
        let again = detector.identify_state_variable(&tied_cfg(), 0);
        assert_eq!(
            first, again,
            "a 2-2 tie between eax and ecx resolves differently across runs"
        );
    }
}

/// A clear majority must still win — the tie-break must not override the
/// frequency it is supposed to break ties in.
#[test]
fn a_clear_majority_still_wins() {
    let mut cfg = tied_cfg();
    // Make eax 3, ecx 1.
    cfg.blocks[4].sets_register = Some("eax".to_string());

    let detector = CffDetector::new();
    assert_eq!(
        detector.identify_state_variable(&cfg, 0),
        StateVariable::Register("eax".to_string())
    );
}

/// With no predecessor writing a register there is nothing to identify.
#[test]
fn no_candidate_yields_unknown() {
    let mut cfg = tied_cfg();
    for b in &mut cfg.blocks {
        b.sets_register = None;
    }
    let detector = CffDetector::new();
    assert_eq!(
        detector.identify_state_variable(&cfg, 0),
        StateVariable::Unknown
    );
}
