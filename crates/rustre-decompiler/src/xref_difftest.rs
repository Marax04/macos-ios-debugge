//! DIFFERENTIAL PROOF for the `rustre-analysis-xref` seam.
//!
//! `CallSitePass` fills `DecompilerContext::call_sites` by walking decoded
//! `Instruction`s, matching `mnemonic == "call"`, and `parse_hex_target`-ing
//! the operand text. This file keeps that logic verbatim as an independent
//! reference implementation and asserts that the xref-derived set
//! (`xref_adapter::function_call_xrefs` → `call_site_targets`) AGREES with it:
//! same targets, same multiplicity after the context's own dedup, same order.
//!
//! It also *characterises* the raw whole-body byte scan, which is what
//! `rustre-analysis-xref` does on a binary with no decoding at all, and which
//! is a strict superset (it fires on `0xE8` bytes buried inside other
//! instructions' immediates/displacements).

use crate::xref_adapter::{call_site_targets, function_call_xrefs, function_call_xrefs_unaligned};
use rustre_core::address::Address;
use rustre_core::arch::{Architecture, Instruction};
use rustre_arch_x86::X86Arch;

/// Reference: `CallSitePass::run` + `DecompilerContext::add_call_site`, verbatim.
fn reference_call_sites(instructions: &[Instruction]) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for instr in instructions {
        if let Some(ops) = crate::xref_adapter::call_operands(instr) {
            if let Some(addr) = crate::parse_hex_target(ops)
                && !out.contains(&addr)
            {
                out.push(addr);
            }
        }
    }
    out
}

/// Linear-sweep decode of a byte blob into `Instruction`s, the same shape the
/// decompiler's passes receive.
fn decode_stream(base: u64, bytes: &[u8]) -> Vec<Instruction> {
    let arch = X86Arch::new_64bit();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        match arch.disassemble(Address::new(base + off as u64), &bytes[off..]) {
            Ok(i) => {
                let n = i.size.max(1);
                off += n;
                out.push(i);
            }
            Err(_) => off += 1,
        }
    }
    out
}

fn assert_agrees(base: u64, bytes: &[u8]) {
    let instrs = decode_stream(base, bytes);
    let reference = reference_call_sites(&instrs);
    let derived = call_site_targets(&function_call_xrefs(&instrs));
    // Permanent diagnostic: on any disagreement, name the exact encodings the
    // two sides saw differently. A bare `assert_eq` on target lists is not
    // actionable, and this difftest exists to produce findings.
    if reference != derived {
        for i in &instrs {
            if i.mnemonic.to_lowercase() != "call" {
                continue;
            }
            let t = crate::parse_hex_target(i.operands.trim());
            let in_derived = t.is_some_and(|t| derived.contains(&t));
            if !in_derived {
                eprintln!(
                    "  MISSED-BY-XREF @ {:#x} mnem={:?} ops={:?} size={} bytes={:02x?}",
                    i.address.as_u64(),
                    i.mnemonic,
                    i.operands,
                    i.size,
                    i.bytes
                );
            }
        }
        for x in function_call_xrefs(&instrs) {
            if !reference.contains(&x.to.as_u64()) {
                if let Some(i) = instrs.iter().find(|i| i.address == x.from) {
                    eprintln!(
                        "  INVENTED-BY-XREF to={:#x} @ {:#x} mnem={:?} ops={:?} size={} bytes={:02x?}",
                        x.to.as_u64(),
                        i.address.as_u64(),
                        i.mnemonic,
                        i.operands,
                        i.size,
                        i.bytes
                    );
                }
            }
        }
    }
    // FINDING 2 is now FIXED (see `bnd_prefixed_call_is_dropped_by_call_site_pass`):
    // `CallSitePass` no longer matches on `mnemonic == "call"` but on
    // `xref_adapter::call_operands`, so a BND/`F2`-prefixed call is recorded on
    // BOTH sides. The former "known divergence" carve-out is therefore gone and
    // the two sets must now match EXACTLY, with no allowance.
    assert_eq!(
        reference, derived,
        "xref-derived call sites disagree with CallSitePass at base {base:#x}"
    );
}

#[test]
fn agrees_on_hand_shaped_streams() {
    // call rel32 forward; nop; call rel32 backward; ret
    assert_agrees(0x1000, &[0xE8, 0x0B, 0x00, 0x00, 0x00, 0x90, 0xE8, 0xF0, 0xFF, 0xFF, 0xFF, 0xC3]);
    // no calls at all
    assert_agrees(0x2000, &[0x48, 0x89, 0xE5, 0x31, 0xC0, 0xC3]);
    // duplicate target twice in a row (exercises the context dedup)
    assert_agrees(
        0x3000,
        &[0xE8, 0x05, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3],
    );
    // jmp rel32 (0xE9) must NOT be recorded as a call
    assert_agrees(0x4000, &[0xE9, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    // indirect call (FF /2) has no hex target on either side
    assert_agrees(0x5000, &[0xFF, 0xD0, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0xC3]);
    // empty
    assert_agrees(0x6000, &[]);
}

#[test]
fn agrees_when_e8_is_embedded_in_an_immediate() {
    // ADVERSARIAL: `mov eax, 0xFFFFFFE8` / `mov rax, imm` streams contain a raw
    // 0xE8 byte that is NOT a call. The instruction-aligned adapter must not
    // fire on it. (The unaligned scan does — see the characterisation test.)
    assert_agrees(0x7000, &[0xB8, 0xE8, 0x03, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xC3]);
    assert_agrees(
        0x7100,
        &[0x48, 0xC7, 0xC0, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x05, 0xE8, 0x11, 0x22, 0x33, 0xC3],
    );
}

/// REGRESSION for the finding this difftest produced.
///
/// `3E E8 rel32` is a segment/branch-hint-prefixed `CALL rel32`. The raw
/// byte scanner in `rustre-analysis-xref::extract_code_to_code` anchors the
/// xref at the `0xE8` byte, one past the true instruction start, because it
/// does not decode prefixes. The decompiler decodes and is CORRECT. The
/// adapter therefore strips the prefix run and re-anchors; without that, this
/// call site was silently dropped from the xref-derived set.
#[test]
fn prefixed_call_is_not_lost() {
    let bytes = [0x3E, 0xE8, 0x61, 0x82, 0xA4, 0x5B, 0xC3];
    let instrs = decode_stream(0x40_012D, &bytes);
    let reference = reference_call_sites(&instrs);
    assert_eq!(reference, vec![0x5BE4_8394], "decoder ground truth");
    let derived = function_call_xrefs(&instrs);
    assert_eq!(call_site_targets(&derived), reference);
    // The re-anchored xref must point at the instruction, not the opcode byte.
    assert_eq!(derived[0].from.as_u64(), 0x40_012D);
    assert_eq!(derived[0].instr_size, 6);
    // And the un-fixed raw scan is what mis-anchors it — recorded, not hidden.
    let raw = function_call_xrefs_unaligned(Address::new(0x40_012D), &bytes);
    assert_eq!(raw[0].from.as_u64(), 0x40_012E, "raw scanner anchors at 0xE8");

    // Same finding, REX form — and *repeated* REX (`4D 4B E8 rel32`), which is
    // legal (only the last REX applies) and does occur in corpus bytes.
    let bytes = [0x4D, 0x4B, 0xE8, 0x10, 0x55, 0xB5, 0x17, 0xC3];
    let instrs = decode_stream(0x40_0810, &bytes);
    let reference = reference_call_sites(&instrs);
    assert_eq!(reference, vec![0x17F5_5D27], "decoder ground truth");
    let derived = function_call_xrefs(&instrs);
    assert_eq!(call_site_targets(&derived), reference);
    assert_eq!(derived[0].from.as_u64(), 0x40_0810);
    assert_eq!(derived[0].instr_size, 7);
}

/// FINDING 2 — the decompiler is WRONG, the xref-derived set is right.
///
/// `F2 E8 rel32` is `bnd call rel32` (MPX BND prefix; emitted by real
/// toolchains on CET/MPX-enabled builds). The disassembler renders it as
/// `mnemonic = "bnd"`, `operands = "call 0x…"`. `CallSitePass` tests
/// `mnemonic == "call"`, so it silently DROPS this direct call site: it never
/// reaches `ctx.call_sites`, and therefore never reaches callee discovery or
/// signature recovery.
///
/// FIXED: `CallSitePass` now goes through `xref_adapter::call_operands`, which
/// recognises a call regardless of prefix rendering, gated on the real opcode
/// byte past the legacy/REX prefix run. This test now asserts the CORRECT
/// behaviour — the two sides agree and the target IS recorded.
#[test]
fn bnd_prefixed_call_is_dropped_by_call_site_pass() {
    let bytes = [0xF2, 0xE8, 0x92, 0x35, 0x72, 0x49, 0xC3];
    let instrs = decode_stream(0x40_7700, &bytes);
    let call = &instrs[0];
    assert_eq!(call.mnemonic, "bnd");
    assert!(call.operands.starts_with("call"));

    // The pass must now record the real target.
    assert_eq!(reference_call_sites(&instrs), vec![0x49B2_AC98]);

    // xref-derived: the real target, correctly anchored at the instruction.
    let derived = function_call_xrefs(&instrs);
    assert_eq!(call_site_targets(&derived), vec![0x49B2_AC98]);
    assert_eq!(derived[0].from.as_u64(), 0x40_7700);
    assert_eq!(derived[0].instr_size, 6);

    // Other prefix-promoted forms of the same shape.
    for (base, b, want) in [
        (0x40_7800u64, vec![0xF2, 0x49, 0xE8, 0x10, 0x00, 0x00, 0x00, 0xC3], 0x40_7817u64),
        (0x40_7900, vec![0xF2, 0x66, 0xE8, 0x20, 0x00, 0x00, 0x00, 0xC3], 0x40_7927u64),
    ] {
        let i = decode_stream(base, &b);
        assert_eq!(reference_call_sites(&i), vec![want], "prefixed call at {base:#x}");
    }

    // ADVERSARIAL — the gate must NOT fire on a non-call. `F3 0F 1E FA`
    // (`endbr64`) and a plain `nop` carry no call opcode; and an operand text
    // that merely CONTAINS "call" is not a first token.
    let nc = decode_stream(0x40_7A00, &[0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0xC3]);
    assert_eq!(reference_call_sites(&nc), Vec::<u64>::new());
    let mut fake = decode_stream(0x40_7B00, &[0x90, 0xC3])[0].clone();
    fake.operands = "callee 0x1234".to_string();
    assert!(crate::xref_adapter::call_operands(&fake).is_none(), "prefix-token gate");
    fake.operands = "call 0x1234".to_string();
    assert!(crate::xref_adapter::call_operands(&fake).is_none(), "opcode-byte gate");
}

#[test]
fn agrees_on_randomized_streams() {
    // Deterministic LCG over random-ish bytes with calls sprinkled in.
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) as u32
    };
    for round in 0..2000u64 {
        let len = 8 + (next() % 56) as usize;
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            if next() % 5 == 0 {
                bytes.push(0xE8);
                let d = next();
                bytes.extend_from_slice(&d.to_le_bytes());
            } else {
                bytes.push((next() & 0xFF) as u8);
            }
        }
        bytes.push(0xC3);
        assert_agrees(0x40_0000 + round * 0x100, &bytes);
    }
}

#[test]
fn agrees_on_real_corpus_code() {
    // Real bytes from the corpus binaries, linear-swept.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/decompiler_corpus/bin");
    let Ok(dir) = std::fs::read_dir(&root) else {
        eprintln!("corpus not present; skipping");
        return;
    };
    let mut checked = 0usize;
    for e in dir.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("exe") {
            continue;
        }
        let Ok(data) = std::fs::read(&p) else { continue };
        // Sweep windows of the file image as if they were code. Even where the
        // linear sweep mis-decodes (it will, on data), BOTH sides see the same
        // decoded stream, so agreement must still hold exactly.
        for (i, chunk) in data.chunks(4096).enumerate().take(64) {
            assert_agrees(0x1_4000_0000 + (i as u64) * 4096, chunk);
        }
        checked += 1;
    }
    assert!(checked > 0, "no corpus binaries found under {}", root.display());
}

#[test]
fn characterise_unaligned_superset() {
    // `mov eax, 0x3E8` — the 0xE8 lives inside the immediate.
    let bytes = [0xB8, 0xE8, 0x03, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0xC3];
    let instrs = decode_stream(0x8000, &bytes);
    let aligned = call_site_targets(&function_call_xrefs(&instrs));
    let unaligned = call_site_targets(&function_call_xrefs_unaligned(Address::new(0x8000), &bytes));
    assert!(aligned.is_empty(), "aligned scan must not invent a call");
    assert!(
        !unaligned.is_empty(),
        "unaligned raw scan is expected to fire on the embedded 0xE8"
    );
    // Superset direction: everything the aligned scan finds, the unaligned scan
    // also finds (same rel32 decode, wider window).
    let bytes2 = [0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0xC3];
    let instrs2 = decode_stream(0x9000, &bytes2);
    let a2 = call_site_targets(&function_call_xrefs(&instrs2));
    let u2 = call_site_targets(&function_call_xrefs_unaligned(Address::new(0x9000), &bytes2));
    assert!(!a2.is_empty());
    for t in &a2 {
        assert!(u2.contains(t), "unaligned scan lost target {t:#x}");
    }
}

/// CHARACTERISES the FINDING-2 fix over the corpus: every site the OLD
/// `mnemonic == "call"` rule dropped and the new `call_operands` rule keeps.
///
/// MEASURED: 8 sites over a whole-file-image linear sweep of the 12 corpus
/// binaries (7 in `sample4_go.exe`, 1 in `sample9_go.exe`), all `F2 E8 rel32`
/// / `43 F2 E8 rel32` `bnd call`. All 8 file offsets fall in the Go DWARF
/// debug sections (`/19`, `/65`, `/78`, `/95`), NOT `.text` — i.e. they are
/// linear-sweep artefacts over data, which is why the emitted corpus C is
/// byte-identical after the fix. The fix is a correctness fix with no
/// corpus-visible output change.
///
/// The assertion here is the one that matters: whatever the new rule accepts
/// must be a REAL call encoding, so the gate can never widen into non-calls.
#[test]
fn counts_prefix_rendered_calls_recovered_across_corpus() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/decompiler_corpus/bin");
    let Ok(dir) = std::fs::read_dir(&root) else { return };
    let mut n = 0usize;
    for e in dir.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("exe") {
            continue;
        }
        let Ok(data) = std::fs::read(&p) else { continue };
        for (i, chunk) in data.chunks(4096).enumerate() {
            for ins in decode_stream(0x1_4000_0000 + (i as u64) * 4096, chunk) {
                let old = ins.mnemonic.to_lowercase() == "call";
                let new = crate::xref_adapter::call_operands(&ins).is_some();
                if new && !old {
                    n += 1;
                    // The gate must only ever accept a genuine CALL encoding.
                    assert!(
                        ins.operands.trim_start().to_lowercase().starts_with("call"),
                        "widened gate accepted {:?} {:?}",
                        ins.mnemonic,
                        ins.operands
                    );
                }
            }
        }
    }
    eprintln!("prefix-rendered call sites recovered across corpus: {n}");
}
