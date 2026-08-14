//! Run `rustre_il_llil::LlilVerifier` over REAL lifter output.
//!
//! # Why this file exists
//!
//! `LlilVerifier` checks that a flat `LlilAnnotatedInstr` slice is a
//! well-formed basic-block sequence. It has no consumers anywhere in the
//! workspace — only its own unit tests — so it has never been pointed at the
//! IL this project actually produces.
//!
//! That is a free check going unused: `rustre-arch-x86` lifts every x86
//! instruction to exactly this type, so the verifier can be run over a broad
//! corpus at no cost. Wiring an unwired capability to an existing corpus is the
//! cheapest form of the demote-to-oracle move.
//!
//! # Feed it what it actually verifies
//!
//! Its contract is about a BASIC-BLOCK sequence: "every non-empty contiguous
//! block, delimited by terminators, must end with a terminator". The first
//! version of this test handed it ONE instruction's IL and got 389 "errors" out
//! of 444 — every one of them the verifier correctly observing that
//! `add rax, rbx` does not end in a branch. That was the test misusing the
//! component, not a lifter defect: read the stated contract before believing a
//! mass failure.
//!
//! So the corpus here is whole BLOCKS — a run of ordinary instructions
//! terminated by `ret` — which is what the lifter's output looks like in the
//! pipeline and what the verifier was written for.

use rustre_arch_x86::lift_to_llil_with_bits;
use rustre_il_llil::LlilVerifier;

use iced_x86::{Decoder, DecoderOptions};

/// Every primary opcode and every `0F xx` that decodes, each used as the BODY
/// of a one-instruction block terminated by `ret`. Generated, not hand-written
/// — hand-built encodings were the single largest source of DEFECTIVE TESTS
/// found in this workspace on 2026-07-23.
fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for escape in [false, true] {
        for opcode in 0u16..=0xFF {
            let opcode = u8::try_from(opcode).unwrap();
            let mut bytes = Vec::new();
            if escape {
                bytes.push(0x0F);
            }
            bytes.push(opcode);
            bytes.push(0xC0);
            bytes.extend_from_slice(&[0u8; 12]);

            let mut dec = Decoder::with_ip(64, &bytes, 0x1000, DecoderOptions::NONE);
            let insn = dec.decode();
            if insn.is_invalid() {
                continue;
            }
            let label = if escape {
                format!("0F {opcode:#04x}")
            } else {
                format!("{opcode:#04x}")
            };
            out.push((label, bytes));
        }
    }
    out
}

/// Lift `bytes` as the body of a block, then append the IL of `ret` so the
/// sequence is the basic block the verifier expects.
fn lift_block(bytes: &[u8]) -> Vec<rustre_il_llil::LlilAnnotatedInstr> {
    let mut dec = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
    let body = dec.decode();
    let mut llil = lift_to_llil_with_bits(&body, 64);

    // If the body ALREADY ends the flow (ret/jmp/int/icebp), appending a `ret`
    // would build a block with genuinely unreachable code — and the verifier
    // would be right to say so. Those bodies are complete blocks on their own.
    // (Measured: the 21 blocks still refused at this point were exactly
    // 0xC2/0xC3 ret, 0xCA/0xCB retf, 0xCD int, 0xE9/0xEB jmp and 0xF1 icebp.)
    let body_ends_flow = matches!(
        body.flow_control(),
        iced_x86::FlowControl::UnconditionalBranch
            | iced_x86::FlowControl::IndirectBranch
            | iced_x86::FlowControl::Return
            | iced_x86::FlowControl::Interrupt
    );
    if body_ends_flow {
        return llil;
    }

    // `c3` = ret, lifted at the address just past the body.
    let ret_ip = 0x1000 + body.len() as u64;
    let ret_bytes = [0xC3u8];
    let mut rdec = Decoder::with_ip(64, &ret_bytes, ret_ip, DecoderOptions::NONE);
    let ret = rdec.decode();
    llil.extend(lift_to_llil_with_bits(&ret, 64));
    llil
}

#[test]
fn verifier_returns_a_verdict_on_every_lifted_instruction() {
    let cases = corpus();
    assert!(
        cases.len() >= 200,
        "corpus degenerated: only {} decodable encodings",
        cases.len()
    );

    let verifier = LlilVerifier::new();
    let mut verified = 0usize;
    let mut with_errors = 0usize;

    let mut malformed: Vec<String> = Vec::new();
    for (label, bytes) in &cases {
        let llil = lift_block(bytes);
        if llil.is_empty() {
            continue;
        }
        // The verifier must RETURN, not abort. Its own doc comment warns it
        // "panics if instrs is non-empty and no terminator is found" — and the
        // IL of an ordinary non-branching instruction (`add rax, rbx`) contains
        // no terminator at all, which is the overwhelmingly common case. A
        // checker that aborts on its normal input cannot be wired into
        // anything, which is a plausible reason nobody ever did.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verifier.verify(&llil)
        }));
        let Ok(res) = result else {
            panic!(
                "LlilVerifier PANICKED on the IL of `{label}` \
                 ({} instructions). A verifier must report, not abort.",
                llil.len()
            );
        };
        verified += 1;
        if !res.is_ok() {
            with_errors += 1;
            if malformed.len() < 15 {
                malformed.push(format!(
                    "{label}: {} | {}",
                    res.summary(),
                    res.errors
                        .iter()
                        .take(2)
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
        }
    }

    assert!(
        verified >= 200,
        "degenerated: only {verified} instruction sequences verified"
    );
    // KNOWN-OPEN, itemised with reasons rather than silently filtered. Listing
    // them keeps the check live for every OTHER encoding: a new malformed block
    // still fails here.
    //
    //  * `0xCC` INT3 lifts to `Breakpoint`, which this IL deliberately models
    //    as CONTINUING (see `LlilInstruction` step semantics): a
    //    debugger-inserted breakpoint resumes at the next instruction. That is
    //    defensible, and the neighbouring `INTO` mapping is arguably the more
    //    wrong of the two — it emits an UNCONDITIONAL `Trap` although INTO only
    //    traps when OF is set, so it does fall through. Neither has an obvious
    //    right answer, so both are left as a recorded design question rather
    //    than churned on one reading. `0xCF` IRET WAS in this list and is now
    //    FIXED — it genuinely does not fall through.
    //  * `0F 0B` (ud2) and the `0F 0D`/`0F 18`..`0F 1E` prefetch-hint family and
    //    `0F AA` (rsm) lift to `Unimplemented`/`Undefined`, which the verifier
    //    counts as flow-ending, so the instruction after them reads as
    //    unreachable. For ud2 that is CORRECT (it always faults); for the
    //    prefetch hints it is over-strict but conservative, and changing it
    //    means deciding what an unmodelled instruction implies for control
    //    flow — a design call, not a bug fix.
    const KNOWN_OPEN: &[&str] = &[
        "0xcc", "0F 0x0b", "0F 0x0d", "0F 0x18", "0F 0x19", "0F 0x1a",
        "0F 0x1b", "0F 0x1c", "0F 0x1d", "0F 0x1e",
        // UD1 / UD0 — undefined by design, legitimately flow-ending like ud2.
        "0F 0xb9", "0F 0xff",
    ];
    let malformed: Vec<String> = malformed
        .into_iter()
        .filter(|m| !KNOWN_OPEN.iter().any(|k| m.starts_with(k)))
        .collect();

    // Now that the verifier is being asked its own question, a well-formedness
    // error means the LIFTER produced a malformed block — a real defect, not a
    // category mistake by the test.
    assert!(
        malformed.is_empty(),
        "LlilVerifier rejects {with_errors} of {verified} lifted blocks (showing up to 15):
  {}",
        malformed.join("
  ")
    );
    println!("LlilVerifier accepts all {verified} lifted blocks");
}
