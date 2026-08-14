//! Output-neutral seam onto `rustre-analysis-xref`.
//!
//! `rustre-analysis-xref` owns cross-reference extraction, but until now it was
//! the one analysis crate `rustre-decompiler` did not even declare as a
//! dependency. The decompiler's cross-reference equivalent is
//! `DecompilerContext::call_sites: Vec<u64>`, filled by `CallSitePass` from
//! already-decoded `Instruction`s.
//!
//! The two are at different levels: xref scans **raw bytes**, `CallSitePass`
//! reads **decoded mnemonics**. This module bridges them without changing any
//! emitted output — nothing consumes it yet.
//!
//! Two scan modes are exposed deliberately, because they differ and the
//! difference is the point:
//!
//! * [`function_call_xrefs`] — *instruction-aligned*: each decoded
//!   instruction's own bytes are handed to
//!   [`rustre_analysis_xref::extract_code_to_code`] at that instruction's own
//!   address. Because the window is exactly one instruction, an `0xE8` byte
//!   that is really a displacement or immediate inside some other instruction
//!   can never be mistaken for a `CALL rel32`. This is the mode that agrees
//!   with `CallSitePass`.
//! * [`function_call_xrefs_unaligned`] — the raw whole-body scan xref performs
//!   on a binary with no decode at all. It is a strict superset in practice:
//!   it also fires on `0xE8` bytes embedded mid-instruction.

use rustre_analysis_xref::{Xref, XrefIndex, XrefKind, extract_code_to_code};
use rustre_core::address::Address;
use rustre_core::arch::Instruction;

/// Direct-call xrefs for a function, derived instruction-by-instruction.
///
/// Emitted in stream order, one per `CALL rel32`, with full multiplicity
/// (repeat calls to the same target appear once each).
/// Length of the legacy/REX prefix run at the head of an x86-64 encoding.
///
/// FINDING (see `xref_difftest`): `extract_code_to_code` is a decode-free byte
/// scanner and therefore treats the first `0xE8` it sees as the start of a
/// `CALL rel32`. Real encoders emit prefixed calls — `3E E8 rel32` (a
/// `ds:`/branch-hint prefix) occurs in the corpus — for which the scanner
/// anchors `from` at the `0xE8` byte rather than at the instruction start.
/// The decompiler, which decodes, is correct there. The adapter owns the
/// decoded instruction, so it strips the prefix run itself and re-anchors the
/// resulting xref to the true instruction address.
fn prefix_len(bytes: &[u8]) -> usize {
    let mut n = 0usize;
    while n < bytes.len() {
        match bytes[n] {
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => n += 1,
            // In 64-bit mode 0x40..=0x4F is always REX, never an opcode. The
            // encoding may carry more than one (only the last one applies), so
            // consume the whole run rather than stopping at the first.
            0x40..=0x4F => n += 1,
            _ => break,
        }
    }
    n
}

#[must_use]
pub fn function_call_xrefs(instructions: &[Instruction]) -> Vec<Xref> {
    let mut out = Vec::new();
    for instr in instructions {
        if instr.bytes.is_empty() {
            continue;
        }
        let p = prefix_len(&instr.bytes);
        if p >= instr.bytes.len() {
            continue;
        }
        let opcode_addr = Address::new(instr.address.as_u64().wrapping_add(p as u64));
        for x in extract_code_to_code(opcode_addr, &instr.bytes[p..]) {
            // Only a `CALL` whose opcode is the instruction's own opcode byte
            // is a real call site; anything later in the window is a
            // coincidence (an `0xE8` inside a displacement or immediate).
            if x.kind == XrefKind::CodeCall && x.from == opcode_addr {
                out.push(Xref::new(
                    instr.address,
                    x.to,
                    XrefKind::CodeCall,
                    u8::try_from(instr.size).unwrap_or(u8::MAX),
                ));
            }
        }
    }
    out
}

/// The raw, decode-free whole-body scan, for characterising the superset.
///
/// `body_base` is the address of `body[0]`.
#[must_use]
pub fn function_call_xrefs_unaligned(body_base: Address, body: &[u8]) -> Vec<Xref> {
    extract_code_to_code(body_base, body)
        .into_iter()
        .filter(|x| x.kind == XrefKind::CodeCall)
        .collect()
}

/// Build an [`XrefIndex`] (xref's own store) for a function's call sites.
///
/// This is the shape a later switch would adopt: the decompiler stops keeping
/// a private `Vec<u64>` and asks the xref DB instead.
#[must_use]
pub fn function_xref_index(instructions: &[Instruction]) -> XrefIndex {
    XrefIndex::build(&function_call_xrefs(instructions))
}

/// Project xref records down onto exactly the shape
/// `DecompilerContext::call_sites` has today: **targets only**, deduplicated,
/// in first-occurrence order.
#[must_use]
pub fn call_site_targets(xrefs: &[Xref]) -> Vec<u64> {
    let mut out: Vec<u64> = Vec::new();
    for x in xrefs {
        let t = x.to.as_u64();
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// Operand text of a decoded `CALL`, regardless of how the disassembler chose
/// to render the instruction's prefixes.
///
/// FINDING 2 (see `xref_difftest::bnd_prefixed_call_is_dropped_by_call_site_pass`):
/// for a BND/`F2`-prefixed call (`F2 E8 rel32`, also `F2 49 E8 …`,
/// `F2 66 E8 …`) the disassembler renders `mnemonic = "bnd"` and
/// `operands = "call 0x…"`. A pass that tests `mnemonic == "call"` therefore
/// silently drops a REAL direct call site. The same shape occurs for any
/// prefix the renderer promotes to the mnemonic slot (`lock`, `notrack`,
/// `rep`, …), so this is deliberately a general rule and not a `bnd` special
/// case.
///
/// GATING — it must never fire on a non-call whose operand text merely
/// contains the word "call". Two independent conditions, both required:
///  1. the operand text's FIRST whitespace-delimited token is exactly `call`
///     (not "contains"), and
///  2. the encoding's own opcode byte — the first byte past the legacy/REX
///     prefix run, reusing [`prefix_len`], the same re-anchoring reasoning
///     `function_call_xrefs` uses — is an actual CALL opcode: `E8` (direct
///     rel32), `FF` (the /2 //3 indirect forms) or `9A` (far).
///
/// Returns the operand text with the promoted `call` token removed, i.e. the
/// same string a non-prefixed `call` would have carried.
#[must_use]
pub fn call_operands(instr: &Instruction) -> Option<&str> {
    if instr.mnemonic.trim().eq_ignore_ascii_case("call") {
        return Some(instr.operands.trim());
    }
    let rest = instr.operands.trim_start();
    let (head, tail) = match rest.find(char::is_whitespace) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    if !head.eq_ignore_ascii_case("call") {
        return None;
    }
    match instr.bytes.get(prefix_len(&instr.bytes)) {
        Some(0xE8 | 0xFF | 0x9A) => Some(tail.trim()),
        _ => None,
    }
}
