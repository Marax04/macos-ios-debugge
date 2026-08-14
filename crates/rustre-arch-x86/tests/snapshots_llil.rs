//! Snapshot tests capturing the lifted LLIL for a curated x86 instruction
//! corpus. Any change to the lifter surfaces here as a reviewable insta diff.
//!
//! All instructions are decoded at ip = 0x1000 for deterministic output.
//!
//! To re-baseline after an intentional lifter change:
//!   cargo insta test --accept   (or INSTA_UPDATE=always cargo test)
//
// SUSPECT LIFT: (recorded per task rules; snapshots below capture CURRENT
// behavior as baseline, no src fixes were made)
//   1. mov eax, ecx / xor eax, eax / cmovne eax, ecx (64-bit mode): lifted as
//      "eax.4 = ..." with NO explicit zero-extension of the upper 32 bits of
//      rax. x86-64 semantics require a 32-bit register write to zero-extend
//      to the full 64-bit register.
//   2. adc/sbb: flag(cf) is written FIRST, but the subsequent flag(of)/flag(af)
//      expressions still reference flag(cf) — they read the freshly written
//      carry-out instead of the carry-in. Also adc's cf formula
//      (tmp0 <u rax) misses the carry when (src + cf) itself wraps.
//   3. idiv rcx: dividend is modeled as rax only, not rdx:rax; and the
//      remainder line "rdx.8 = (rax.8 %s rcx.8)" reads rax AFTER it was
//      overwritten by the quotient on the previous line.
//   4. mul rbx: "rdx:rax = (rax.8 * rbx.8).8" — the 128-bit product is
//      truncated to 8 bytes; the high half deposited into rdx is not computed.
//   5. rep/repne prefixes are ignored: "rep movsb" lifts identically to
//      "movsb" (no rcx decrement / loop semantics).
//   6. ret 8 (ret imm16): the extra rsp += 8 stack adjustment is not emitted
//      (lifts identically to plain ret).
//   7. scasb/cmpsb: flag(af) is not emitted although scas/cmps set AF.

use iced_x86::{Decoder, DecoderOptions};
use rustre_arch_x86::lift_to_llil_with_bits;
use std::fmt::Write as _;

/// Decode every instruction in `bytes` at ip 0x1000 in `bits`-bit mode, lift
/// each, and render a stable multi-line string.
fn lift_render(label: &str, bytes: &[u8], bits: u32) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "== {label} (bits={bits}) ==");
    let mut decoder = Decoder::with_ip(bits, bytes, 0x1000, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.is_invalid() {
            let _ = writeln!(out, "<invalid encoding at 0x{:X}>", instr.ip());
            break;
        }
        let start = (instr.ip() - 0x1000) as usize;
        let insn_bytes: Vec<String> = bytes[start..start + instr.len()]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let _ = writeln!(out, "-- {instr} [{}]", insn_bytes.join(" "));
        let lifted = lift_to_llil_with_bits(&instr, bits);
        if lifted.is_empty() {
            let _ = writeln!(out, "   <no llil emitted>");
        }
        for l in &lifted {
            let _ = writeln!(out, "   {l}");
        }
    }
    out
}

/// A corpus entry: (label, encoded bytes).
type Entry<'a> = (&'a str, &'a [u8]);

fn render_corpus(title: &str, bits: u32, entries: &[Entry]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# {title}");
    for (label, bytes) in entries {
        out.push('\n');
        out.push_str(&lift_render(label, bytes, bits));
    }
    out
}

// ---------------------------------------------------------------------------
// arithmetic + flags
// ---------------------------------------------------------------------------

#[test]
fn snap_arith_flags_64() {
    let corpus: &[Entry] = &[
        ("add rax, rbx", &[0x48, 0x01, 0xD8]),
        ("add eax, 1", &[0x83, 0xC0, 0x01]),
        ("sub rcx, rdx", &[0x48, 0x29, 0xD1]),
        ("adc rax, rbx", &[0x48, 0x11, 0xD8]),
        ("sbb rax, rbx", &[0x48, 0x19, 0xD8]),
        ("inc rax", &[0x48, 0xFF, 0xC0]),
        ("dec ecx", &[0xFF, 0xC9]),
        ("neg rax", &[0x48, 0xF7, 0xD8]),
        ("cmp rax, rbx", &[0x48, 0x39, 0xD8]),
        ("cmp eax, 0x10", &[0x83, 0xF8, 0x10]),
        ("test eax, eax", &[0x85, 0xC0]),
        ("test al, 1", &[0xA8, 0x01]),
        ("imul rax, rbx", &[0x48, 0x0F, 0xAF, 0xC3]),
        ("mul rbx", &[0x48, 0xF7, 0xE3]),
        ("idiv rcx", &[0x48, 0xF7, 0xF9]),
    ];
    insta::assert_snapshot!(
        "arith_flags_64",
        render_corpus("arithmetic + flags (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// logic + shifts
// ---------------------------------------------------------------------------

#[test]
fn snap_logic_shifts_64() {
    let corpus: &[Entry] = &[
        ("and rax, rbx", &[0x48, 0x21, 0xD8]),
        ("or eax, 0xff", &[0x0D, 0xFF, 0x00, 0x00, 0x00]),
        ("xor eax, eax (zero idiom)", &[0x31, 0xC0]),
        ("xor rax, rbx", &[0x48, 0x31, 0xD8]),
        ("not rax", &[0x48, 0xF7, 0xD0]),
        ("shl rax, 4", &[0x48, 0xC1, 0xE0, 0x04]),
        ("shl rax, cl", &[0x48, 0xD3, 0xE0]),
        ("shr rax, 1", &[0x48, 0xD1, 0xE8]),
        ("sar eax, 2", &[0xC1, 0xF8, 0x02]),
        ("rol eax, 3", &[0xC1, 0xC0, 0x03]),
        ("ror rax, 7", &[0x48, 0xC1, 0xC8, 0x07]),
    ];
    insta::assert_snapshot!(
        "logic_shifts_64",
        render_corpus("logic + shifts (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// data movement
// ---------------------------------------------------------------------------

#[test]
fn snap_data_movement_64() {
    let corpus: &[Entry] = &[
        ("mov rax, rbx", &[0x48, 0x89, 0xD8]),
        ("mov eax, 0x12345678", &[0xB8, 0x78, 0x56, 0x34, 0x12]),
        (
            "mov rax, 0x1122334455667788",
            &[0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        ),
        ("mov rax, [rbx]", &[0x48, 0x8B, 0x03]),
        ("mov [rbx+8], rax", &[0x48, 0x89, 0x43, 0x08]),
        ("mov eax, [rbx+rcx*4+0x10]", &[0x8B, 0x44, 0x8B, 0x10]),
        ("movzx eax, bl", &[0x0F, 0xB6, 0xC3]),
        ("movzx eax, word [rbx]", &[0x0F, 0xB7, 0x03]),
        ("movsx rax, bl", &[0x48, 0x0F, 0xBE, 0xC3]),
        ("movsxd rax, ecx", &[0x48, 0x63, 0xC1]),
        ("lea rax, [rbx+rcx*4+8]", &[0x48, 0x8D, 0x44, 0x8B, 0x08]),
        ("lea rax, [rip+0x100]", &[0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00]),
        ("xchg rax, rbx", &[0x48, 0x87, 0xD8]),
        ("push rax", &[0x50]),
        ("push 0x55", &[0x6A, 0x55]),
        ("pop rbx", &[0x5B]),
        ("push qword [rax]", &[0xFF, 0x30]),
    ];
    insta::assert_snapshot!(
        "data_movement_64",
        render_corpus("data movement (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// partial registers
// ---------------------------------------------------------------------------

#[test]
fn snap_partial_registers_64() {
    let corpus: &[Entry] = &[
        // 32-bit write in 64-bit mode must zero-extend to full 64-bit reg
        ("mov eax, ecx (zero-extends rax)", &[0x89, 0xC8]),
        ("mov al, bl (low-8 merge)", &[0x88, 0xD8]),
        ("mov ah, bl (high-8 merge)", &[0x88, 0xDC]),
        ("mov ax, cx (16-bit merge)", &[0x66, 0x89, 0xC8]),
        ("mov r8d, r9d (zero-extends r8)", &[0x45, 0x89, 0xC8]),
        ("add al, 1", &[0x04, 0x01]),
        ("inc ax", &[0x66, 0xFF, 0xC0]),
        ("movzx eax, al", &[0x0F, 0xB6, 0xC0]),
    ];
    insta::assert_snapshot!(
        "partial_registers_64",
        render_corpus("partial registers (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// control flow
// ---------------------------------------------------------------------------

#[test]
fn snap_control_flow_64() {
    let corpus: &[Entry] = &[
        ("jmp +0x10 (rel8)", &[0xEB, 0x10]),
        ("jmp rax", &[0xFF, 0xE0]),
        ("je +0x20", &[0x74, 0x20]),
        ("jne +0x20", &[0x75, 0x20]),
        ("jl +5", &[0x7C, 0x05]),
        ("ja +5", &[0x77, 0x05]),
        ("js +5", &[0x78, 0x05]),
        ("jo +5", &[0x70, 0x05]),
        ("call +0x100 (rel32)", &[0xE8, 0x00, 0x01, 0x00, 0x00]),
        ("call rax", &[0xFF, 0xD0]),
        ("ret", &[0xC3]),
        ("ret 8", &[0xC2, 0x08, 0x00]),
        ("loop -2", &[0xE2, 0xFE]),
        ("sete al", &[0x0F, 0x94, 0xC0]),
        ("setg cl", &[0x0F, 0x9F, 0xC1]),
        ("cmove rax, rbx", &[0x48, 0x0F, 0x44, 0xC3]),
        ("cmovne eax, ecx", &[0x0F, 0x45, 0xC1]),
    ];
    insta::assert_snapshot!(
        "control_flow_64",
        render_corpus("control flow (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// string operations
// ---------------------------------------------------------------------------

#[test]
fn snap_string_ops_64() {
    let corpus: &[Entry] = &[
        ("movsb", &[0xA4]),
        ("movsq", &[0x48, 0xA5]),
        ("rep movsb", &[0xF3, 0xA4]),
        ("rep movsq", &[0xF3, 0x48, 0xA5]),
        ("stosb", &[0xAA]),
        ("rep stosd", &[0xF3, 0xAB]),
        ("lodsb", &[0xAC]),
        ("scasb", &[0xAE]),
        ("repne scasb", &[0xF2, 0xAE]),
        ("cmpsb", &[0xA6]),
        ("repe cmpsb", &[0xF3, 0xA6]),
    ];
    insta::assert_snapshot!(
        "string_ops_64",
        render_corpus("string operations (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// SSE / x87
// ---------------------------------------------------------------------------

#[test]
fn snap_sse_x87_64() {
    let corpus: &[Entry] = &[
        ("movaps xmm0, xmm1", &[0x0F, 0x28, 0xC1]),
        ("movaps xmm0, [rax]", &[0x0F, 0x28, 0x00]),
        ("movd xmm0, eax", &[0x66, 0x0F, 0x6E, 0xC0]),
        ("movq xmm0, rax", &[0x66, 0x48, 0x0F, 0x6E, 0xC0]),
        ("addss xmm0, xmm1", &[0xF3, 0x0F, 0x58, 0xC1]),
        ("addsd xmm0, xmm1", &[0xF2, 0x0F, 0x58, 0xC1]),
        ("mulsd xmm2, xmm3", &[0xF2, 0x0F, 0x59, 0xD3]),
        ("xorps xmm0, xmm0", &[0x0F, 0x57, 0xC0]),
        ("fld qword [rax]", &[0xDD, 0x00]),
        ("fld st(1)", &[0xD9, 0xC1]),
        ("fadd st(0), st(1)", &[0xD8, 0xC1]),
        ("faddp st(1), st(0)", &[0xDE, 0xC1]),
        ("fstp qword [rax]", &[0xDD, 0x18]),
    ];
    insta::assert_snapshot!(
        "sse_x87_64",
        render_corpus("SSE / x87 (64-bit)", 64, corpus)
    );
}

// ---------------------------------------------------------------------------
// bitness: identical bytes lifted in 32-bit vs 64-bit mode
// ---------------------------------------------------------------------------

#[test]
fn snap_bitness_32() {
    let corpus: &[Entry] = &[
        ("push 0x55", &[0x6A, 0x55]),
        ("push eax", &[0x50]),
        ("pop ebx", &[0x5B]),
        ("mov eax, ecx", &[0x89, 0xC8]),
        ("add eax, ebx", &[0x01, 0xD8]),
        ("call +0x100", &[0xE8, 0x00, 0x01, 0x00, 0x00]),
        ("ret", &[0xC3]),
        ("mov eax, [ebx]", &[0x8B, 0x03]),
        ("lea eax, [ebx+ecx*4+8]", &[0x8D, 0x44, 0x8B, 0x08]),
        ("xor eax, eax", &[0x31, 0xC0]),
    ];
    insta::assert_snapshot!(
        "bitness_32",
        render_corpus("bitness corpus lifted in 32-bit mode", 32, corpus)
    );
}

#[test]
fn snap_bitness_64() {
    // Same encodings as snap_bitness_32, decoded/lifted in 64-bit mode.
    let corpus: &[Entry] = &[
        ("push 0x55", &[0x6A, 0x55]),
        ("push rax", &[0x50]),
        ("pop rbx", &[0x5B]),
        ("mov eax, ecx", &[0x89, 0xC8]),
        ("add eax, ebx", &[0x01, 0xD8]),
        ("call +0x100", &[0xE8, 0x00, 0x01, 0x00, 0x00]),
        ("ret", &[0xC3]),
        ("mov eax, [rbx]", &[0x8B, 0x03]),
        ("lea eax, [rbx+rcx*4+8]", &[0x8D, 0x44, 0x8B, 0x08]),
        ("xor eax, eax", &[0x31, 0xC0]),
    ];
    insta::assert_snapshot!(
        "bitness_64",
        render_corpus("bitness corpus lifted in 64-bit mode", 64, corpus)
    );
}
