//! Instruction rendering with selectable AT&T or Intel syntax.
//!
//! # Entry points
//! - [`render_instruction`] — renders with the default syntax (AT&T).
//! - [`render_instruction_with_syntax`] — renders with an explicit [`Syntax`].

use iced_x86::{
    Formatter, GasFormatter, Instruction as IcedInstruction, IntelFormatter,
};

use crate::StringOutput;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Disassembly output syntax.
///
/// Defaults to [`Syntax::Att`] (GAS / AT&T notation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Syntax {
    /// AT&T / GAS syntax: `movq %rax, %rbx`, `$0x10`, `(%rax)`.
    #[default]
    Att,
    /// Intel (NASM-style) syntax: `mov rbx, rax`, `10h`, `[rax]`.
    Intel,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render `insn` with the default AT&T syntax.
///
/// Equivalent to `render_instruction_with_syntax(insn, Syntax::Att)`.
#[must_use]
pub fn render_instruction(insn: &IcedInstruction) -> String {
    render_instruction_with_syntax(insn, Syntax::Att)
}

/// Render `insn` with the requested [`Syntax`].
///
/// Returns the full formatted string (mnemonic + operands, space-separated).
///
/// # Intel rules applied
/// * Destination operand first.
/// * No `%` prefix on register names.
/// * No `$` prefix on immediates.
/// * Memory references use `[base + disp]` notation.
/// * Size keywords (`qword ptr`, `dword ptr`, `word ptr`, `byte ptr`) are
///   emitted by iced-x86's [`IntelFormatter`] whenever the size would
///   otherwise be ambiguous.
/// * Plain mnemonic: `mov`, never the size-tagged GAS variant `movq`.
#[must_use]
pub fn render_instruction_with_syntax(insn: &IcedInstruction, syntax: Syntax) -> String {
    match syntax {
        Syntax::Att => render_att(insn),
        Syntax::Intel => render_intel(insn),
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn render_att(insn: &IcedInstruction) -> String {
    let mut fmt = GasFormatter::new();
    fmt.options_mut().set_space_after_operand_separator(true);
    fmt.options_mut().set_rip_relative_addresses(true);
    // Force GAS size suffix: `movq`, `addl`, `pushq`, ...
    fmt.options_mut().set_gas_show_mnemonic_size_suffix(true);
    let mut out = StringOutput::new();
    fmt.format(insn, &mut out);
    out.0
}

fn render_intel(insn: &IcedInstruction) -> String {
    let mut fmt = IntelFormatter::new();
    // Emit "word ptr" / "dword ptr" / etc. where needed (iced default is true,
    // but we make it explicit so the behaviour is stable across iced versions).
    // Always show size qualifiers (qword ptr / dword ptr / etc.) so
    // disassembly is unambiguous even without context.
    fmt.options_mut().set_memory_size_options(
        iced_x86::MemorySizeOptions::Always,
    );
    // Use hex numbers without trailing 'h' so output looks like:
    //   mov rax, 0xff   rather than   mov rax, 0FFh
    fmt.options_mut().set_number_base(iced_x86::NumberBase::Hexadecimal);
    fmt.options_mut().set_uppercase_hex(false);
    fmt.options_mut().set_hex_prefix("0x");
    fmt.options_mut().set_hex_suffix("");
    fmt.options_mut().set_space_after_operand_separator(true);
    fmt.options_mut().set_rip_relative_addresses(true);
    let mut out = StringOutput::new();
    fmt.format(insn, &mut out);
    out.0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8], ip: u64) -> IcedInstruction {
        let mut dec = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        dec.decode()
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn att(bytes: &[u8]) -> String {
        render_instruction_with_syntax(&decode(bytes, 0x1000), Syntax::Att)
    }

    fn intel(bytes: &[u8]) -> String {
        render_instruction_with_syntax(&decode(bytes, 0x1000), Syntax::Intel)
    }

    // ── MOV rbx, rax  (48 89 C3) ─────────────────────────────────────────────
    // Intel:  mov rbx, rax
    // AT&T:   movq %rax, %rbx

    #[test]
    fn test_mov_reg_reg_att() {
        // 48 89 C3 = MOV rbx, rax  (Intel dst-first)
        // GasFormatter does not add a size suffix by default.
        let s = att(&[0x48, 0x89, 0xc3]);
        assert!(s.starts_with("mov"), "expected mov prefix, got: {s}");
        assert!(s.contains("%rax"), "expected %rax in: {s}");
        assert!(s.contains("%rbx"), "expected %rbx in: {s}");
        // AT&T: src before dst
        assert!(s.find("%rax").unwrap() < s.find("%rbx").unwrap(),
            "AT&T must list src (%rax) before dst (%rbx): {s}");
    }

    #[test]
    fn test_mov_reg_reg_intel() {
        let s = intel(&[0x48, 0x89, 0xc3]);
        // dst first, no % sigils, plain "mov"
        assert_eq!(s, "mov rbx, rax");
    }

    // ── MOV [rbp-8], rax  (48 89 45 F8) ─────────────────────────────────────
    // Intel:  mov qword ptr [rbp-0x8], rax
    // AT&T:   movq %rax, -0x8(%rbp)

    #[test]
    fn test_mov_mem_write_att() {
        let s = att(&[0x48, 0x89, 0x45, 0xf8]);
        assert!(s.starts_with("mov"), "expected mov prefix, got: {s}");
        assert!(s.contains("%rax"), "expected %rax in: {s}");
        assert!(s.contains("%rbp"), "expected %rbp in: {s}");
        // AT&T: src (%rax) before dst (memory using %rbp)
        assert!(s.find("%rax").unwrap() < s.find("%rbp").unwrap(),
            "AT&T must list src before dst: {s}");
    }

    #[test]
    fn test_mov_mem_write_intel() {
        let s = intel(&[0x48, 0x89, 0x45, 0xf8]);
        // dst first, bracket memory, size hint, no sigils
        assert!(s.starts_with("mov "), "expected 'mov ', got: {s}");
        assert!(s.contains("qword ptr"), "expected 'qword ptr' in: {s}");
        assert!(s.contains('['), "expected '[' in: {s}");
        assert!(s.contains("rbp"), "expected 'rbp' in: {s}");
        assert!(s.contains("rax"), "expected 'rax' in: {s}");
        assert!(!s.contains('%'), "no % sigils in Intel: {s}");
    }

    // ── MOV rax, [rbp-8]  (48 8B 45 F8) ─────────────────────────────────────
    // Intel:  mov rax, qword ptr [rbp-0x8]
    // AT&T:   movq -0x8(%rbp), %rax

    #[test]
    fn test_mov_mem_read_intel() {
        let s = intel(&[0x48, 0x8b, 0x45, 0xf8]);
        assert!(s.starts_with("mov "), "got: {s}");
        assert!(s.contains('['), "expected '[' in: {s}");
        assert!(!s.contains('%'), "no % sigils in Intel: {s}");
        // destination (rax) comes first, before memory ref using rbp
        assert!(s.find("rax").unwrap() < s.find("rbp").unwrap(),
            "dst (rax) must precede src (rbp) in: {s}");
    }

    // ── ADD rax, 0x42  (48 83 C0 42) ─────────────────────────────────────────
    // Intel:  add rax, 0x42
    // AT&T:   addq $0x42, %rax

    #[test]
    fn test_add_imm_att() {
        let s = att(&[0x48, 0x83, 0xc0, 0x42]);
        // AT&T renders the immediate with a `$` prefix, in hex or decimal.
        // The third alternative used to repeat the first verbatim
        // (`$0x42 || $66 || $0x42`), so the assertion had two real branches,
        // not three — a copy-paste slip that silently narrowed the check.
        assert!(
            s.contains("$0x42") || s.contains("$66"),
            "expected a $-prefixed immediate (hex $0x42 or decimal $66): {s}"
        );
        assert!(s.contains("%rax"), "expected %rax in: {s}");
    }

    #[test]
    fn test_add_imm_intel() {
        let s = intel(&[0x48, 0x83, 0xc0, 0x42]);
        assert!(s.starts_with("add "), "expected 'add', got: {s}");
        assert!(!s.contains('$'), "no $ in Intel: {s}");
        assert!(!s.contains('%'), "no % in Intel: {s}");
        // rax appears before the immediate
        assert!(s.contains("rax"), "expected rax in: {s}");
    }

    // ── NOP  (90) ─────────────────────────────────────────────────────────────

    #[test]
    fn test_nop_att() {
        assert_eq!(att(&[0x90]), "nop");
    }

    #[test]
    fn test_nop_intel() {
        assert_eq!(intel(&[0x90]), "nop");
    }

    // ── PUSH rbp  (55) ───────────────────────────────────────────────────────
    // AT&T:   pushq %rbp
    // Intel:  push rbp

    #[test]
    fn test_push_att() {
        let s = att(&[0x55]);
        assert!(s.contains("%rbp"), "expected %rbp in: {s}");
        assert!(s.starts_with("push"), "expected push, got: {s}");
    }

    #[test]
    fn test_push_intel() {
        let s = intel(&[0x55]);
        assert_eq!(s, "push rbp");
    }

    // ── XOR eax, eax  (31 C0) ────────────────────────────────────────────────
    // AT&T:  xorl %eax, %eax
    // Intel: xor eax, eax

    #[test]
    fn test_xor_att() {
        let s = att(&[0x31, 0xc0]);
        assert!(s.starts_with("xor"), "got: {s}");
        assert!(s.contains("%eax"), "expected %eax: {s}");
    }

    #[test]
    fn test_xor_intel() {
        let s = intel(&[0x31, 0xc0]);
        assert_eq!(s, "xor eax, eax");
    }

    // ── Default syntax is AT&T ────────────────────────────────────────────────

    #[test]
    fn test_default_syntax_is_att() {
        let insn = decode(&[0x90], 0x1000);
        // render_instruction uses the Default variant
        assert_eq!(render_instruction(&insn), render_instruction_with_syntax(&insn, Syntax::Att));
    }

    // ── Syntax default derivation ─────────────────────────────────────────────

    #[test]
    fn test_syntax_default() {
        assert_eq!(Syntax::default(), Syntax::Att);
    }
}
