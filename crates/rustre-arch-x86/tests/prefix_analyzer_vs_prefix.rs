//! Differential cross-check: `x86_prefix_analyzer` vs the live `prefix` module.
//!
//! # Why this file exists
//!
//! `src/prefix.rs::PrefixSet::consume` is the prefix scanner the crate actually
//! runs. `src/x86_prefix_analyzer.rs` is a second, larger implementation of the
//! same job whose doc comment claims the two are "complementary, not
//! duplicates" — the 2026-07-23 wiring audit found that claim is FALSE: the
//! lean one runs, this one has no callers at all. Its doc concealed the gap
//! instead of stating it.
//!
//! So this is the same situation as `branch.rs`, and gets the same treatment:
//! demote it to a differential ORACLE. Two independently-written descriptions
//! of one machine fact — "which leading bytes are prefixes, and what do they
//! say":
//!   * `prefix::PrefixSet::consume(bytes, is_64bit)`;
//!   * `X86PrefixAnalyzer::new_64bit().parse(bytes)`.
//! Where they disagree at least one is wrong, and nothing could say so before.
//!
//! # Deliberate scope
//!
//! Legacy prefixes and REX only. The analyzer additionally recognises
//! VEX/EVEX/XOP encoding headers, which `consume` deliberately does not treat
//! as prefixes at all — that is a documented difference in what the two set out
//! to do, not a disagreement about the same question, so those bytes are
//! excluded rather than counted as failures.
//!
//! The corpus is every sequence of up to three prefix bytes drawn from the full
//! legacy set plus a representative REX, followed by a plain opcode. Generated,
//! not hand-written: hand-built encodings were the single largest source of
//! DEFECTIVE TESTS found in this workspace on 2026-07-23.

use rustre_arch_x86::prefix::PrefixSet as LivePrefixSet;
use rustre_arch_x86::x86_prefix_analyzer::X86PrefixAnalyzer;

/// Every legacy prefix byte, plus REX forms that exercise each of W/R/X/B.
const PREFIX_BYTES: &[u8] = &[
    0xF0, // LOCK
    0xF2, // REPNE
    0xF3, // REP
    0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, // segment overrides
    0x66, // operand-size
    0x67, // address-size
    0x40, 0x48, 0x44, 0x42, 0x41, 0x4F, // REX (none/W/R/X/B/all)
];

/// `0x90` (NOP) — a one-byte opcode with no ModRM, so nothing after the
/// prefixes can be mistaken for one.
const OPCODE: u8 = 0x90;

fn seg_name<T: std::fmt::Debug>(s: Option<T>) -> String {
    s.map_or_else(|| "none".to_string(), |v| format!("{v:?}").to_uppercase())
}

#[test]
fn prefix_analyzer_agrees_with_live_prefix_scanner() {
    let analyzer = X86PrefixAnalyzer::new_64bit();
    let mut compared = 0usize;
    let mut disagreements = Vec::new();
    let mut by_field: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    // Sequences of length 0..=3, exhaustive over PREFIX_BYTES.
    let mut sequences: Vec<Vec<u8>> = vec![Vec::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for s in &sequences {
            for &b in PREFIX_BYTES {
                let mut v = s.clone();
                v.push(b);
                next.push(v);
            }
        }
        sequences.extend(next);
    }

    for seq in &sequences {
        let mut bytes = seq.clone();
        bytes.push(OPCODE);
        bytes.extend_from_slice(&[0u8; 4]);

        let live = LivePrefixSet::consume(&bytes, true);
        let (an, _) = analyzer.parse(&bytes);
        compared += 1;

        let mut diffs: Vec<String> = Vec::new();
        if live.count != an.prefix_bytes {
            diffs.push(format!("count {} vs {}", live.count, an.prefix_bytes));
        }
        if live.lock != an.lock {
            diffs.push(format!("lock {} vs {}", live.lock, an.lock));
        }
        if live.rep != an.rep {
            diffs.push(format!("rep {} vs {}", live.rep, an.rep));
        }
        if live.repne != an.repne {
            diffs.push(format!("repne {} vs {}", live.repne, an.repne));
        }
        if live.op_size != an.operand_size_override {
            diffs.push(format!(
                "op_size {} vs {}",
                live.op_size, an.operand_size_override
            ));
        }
        if live.addr_size != an.address_size_override {
            diffs.push(format!(
                "addr_size {} vs {}",
                live.addr_size, an.address_size_override
            ));
        }
        let (ls, as_) = (seg_name(live.segment), seg_name(an.segment_override));
        if ls != as_ {
            diffs.push(format!("segment {ls} vs {as_}"));
        }
        // REX: `present` on one side, a non-zero byte on the other. This is the
        // field most likely to differ, because the SDM (§2.2.1) says a REX is
        // effective only when it IMMEDIATELY precedes the opcode — a legacy
        // prefix after it nullifies it. `consume` models that explicitly.
        if live.rex.present != (an.rex != 0) {
            diffs.push(format!(
                "rex present {} vs {} (byte {:#04x})",
                live.rex.present,
                an.rex != 0,
                an.rex
            ));
        }
        if live.rex.present && an.rex != 0 {
            for (name, l, a) in [
                ("rex.w", live.rex.w, an.rex_w),
                ("rex.r", live.rex.r, an.rex_r),
                ("rex.x", live.rex.x, an.rex_x),
                ("rex.b", live.rex.b, an.rex_b),
            ] {
                if l != a {
                    diffs.push(format!("{name} {l} vs {a}"));
                }
            }
        }

        if !diffs.is_empty() {
            for d in &diffs {
                // Field name only — the histogram below must not be diluted by
                // per-sequence values, or "2046 disagreements" hides whether
                // that is ONE rule applied 2046 times or many distinct bugs.
                let field = d.split_whitespace().next().unwrap_or("?").to_string();
                *by_field.entry(field).or_insert(0usize) += 1;
            }
            disagreements.push(format!("{seq:02x?}: {}", diffs.join(", ")));
        }
    }

    // Anti-degeneracy: a cross-check over a handful of sequences passes while
    // proving nothing.
    assert!(
        compared >= 1000,
        "cross-check degenerated: only {compared} sequences compared"
    );

    assert!(
        disagreements.is_empty(),
        "prefix analyzer and live scanner disagree on {} of {compared} sequences\n\
         \nBY FIELD (is this ONE rule applied many times, or many distinct bugs?):\n  {}\n\
         \nEXAMPLES:\n  {}",
        disagreements.len(),
        by_field
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect::<Vec<_>>()
            .join("\n  "),
        disagreements.iter().take(10).cloned().collect::<Vec<_>>().join("\n  ")
    );

    println!("prefix analyzer vs live scanner: {compared} sequences agree");
}
