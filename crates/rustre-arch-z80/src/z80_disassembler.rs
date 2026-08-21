//! Z80 disassembler: produces formatted assembly listing lines.
use std::fmt::Write as _;


use crate::z80_decoder::{Z80Decoder, Z80Instr, Z80Operand, Z80Prefix};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Assembly syntax dialect.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Z80Syntax {
    /// Zilog standard syntax (default): `LD A,(IX+3)`, `IN A,(0x3E)`.
    #[default]
    Zilog,
    /// Intel / NASM-like hex notation: `LD A,(IX+03H)`.
    Intel,
    /// GNU gas Z80 syntax (used with binutils): lowercase mnemonics.
    Gas,
}

/// Configuration for the Z80 disassembler.
#[derive(Clone, Debug)]
pub struct Z80DisasmConfig {
    /// Assembly syntax variant.
    pub syntax: Z80Syntax,
    /// Show raw hex bytes next to each instruction.
    pub show_bytes: bool,
    /// Column width reserved for the hex dump (bytes column).
    pub hex_column_width: usize,
    /// Show PC address prefix on each line.
    pub show_address: bool,
    /// Show cycle count estimate after each instruction (if available).
    pub show_cycles: bool,
    /// Column width for the address field.
    pub addr_width: usize,
    /// Number of chars to pad for the mnemonic field.
    pub mnemonic_width: usize,
    /// Resolve branch targets to labels if supplied.
    pub label_resolver: Option<fn(u16) -> Option<String>>,
}

impl Default for Z80DisasmConfig {
    fn default() -> Self {
        Self {
            syntax: Z80Syntax::Zilog,
            show_bytes: true,
            hex_column_width: 12,
            show_address: true,
            show_cycles: false,
            addr_width: 4,
            mnemonic_width: 6,
            label_resolver: None,
        }
    }
}

impl Z80DisasmConfig {
    #[must_use]
    pub fn new() -> Self { Self::default() }
    #[must_use]
    pub const fn with_syntax(mut self, s: Z80Syntax) -> Self { self.syntax = s; self }
    #[must_use]
    pub const fn with_bytes(mut self, b: bool) -> Self { self.show_bytes = b; self }
    #[must_use]
    pub const fn with_address(mut self, a: bool) -> Self { self.show_address = a; self }
    #[must_use]
    pub const fn with_cycles(mut self, c: bool) -> Self { self.show_cycles = c; self }
}

// ── Listing line ──────────────────────────────────────────────────────────────

/// A single disassembled line ready for display.
#[derive(Clone, Debug)]
pub struct DisasmLine {
    /// Virtual address of the instruction.
    pub address: u16,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic string (uppercased for Zilog/Intel, lowercased for Gas).
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Full formatted output line.
    pub text: String,
    /// Branch target address if this is a branch.
    pub branch_target: Option<u16>,
    /// True if this is a terminator (RET / JP without condition / HALT).
    pub is_terminator: bool,
    /// Estimated T-states (0 = unknown).
    pub cycles: u8,
}

impl DisasmLine {
    /// Render to a single-line string using the embedded `text` field.
    #[must_use]
    pub fn as_str(&self) -> &str { &self.text }

    /// True if this instruction ends control flow without a fallthrough.
    #[must_use]
    pub const fn is_unconditional_branch(&self) -> bool {
        self.is_terminator
    }
}

impl core::fmt::Display for DisasmLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

// ── Listing line (with optional label) ────────────────────────────────────────

/// Extended listing line including an optional label.
#[derive(Clone, Debug)]
pub struct ListingLine {
    pub label: Option<String>,
    pub line: DisasmLine,
    /// Source offset within the input byte slice.
    pub offset: usize,
}

impl core::fmt::Display for ListingLine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(lbl) = &self.label {
            writeln!(f, "{lbl}:")?;
        }
        write!(f, "{}", self.line)
    }
}

// ── Disassembler ──────────────────────────────────────────────────────────────

/// Z80 disassembler.
pub struct Z80Disassembler {
    decoder: Z80Decoder,
    pub config: Z80DisasmConfig,
}

impl Z80Disassembler {
    #[must_use]
    pub const fn new(config: Z80DisasmConfig) -> Self {
        Self { decoder: Z80Decoder::new(), config }
    }

    #[must_use]
    pub fn with_defaults() -> Self { Self::new(Z80DisasmConfig::default()) }

    /// Disassemble a single instruction at virtual address `pc`.
    /// Returns `None` if bytes is empty or truncated.
    #[must_use]
    pub fn disasm_one(&self, pc: u16, bytes: &[u8]) -> Option<DisasmLine> {
        let instr = self.decoder.decode(pc, bytes)?;
        Some(self.format_instr(pc, &instr, bytes))
    }

    /// Disassemble `max_instrs` instructions starting at `pc`.
    #[must_use]
    pub fn disasm_n(&self, pc: u16, bytes: &[u8], max_instrs: usize) -> Vec<DisasmLine> {
        let cap = max_instrs.min(bytes.len() + 1);
        let mut out = Vec::with_capacity(cap);
        let mut offset = 0usize;
        let mut cur_pc = pc;
        while offset < bytes.len() && out.len() < max_instrs {
            let slice = &bytes[offset..];
            if let Some(instr) = self.decoder.decode(cur_pc, slice) {
                let len = instr.len as usize;
                out.push(self.format_instr(cur_pc, &instr, slice));
                offset += len;
                cur_pc = cur_pc.wrapping_add(u16::from(instr.len));
            } else {
                // Emit a single invalid byte.
                let line = self.make_invalid(cur_pc, bytes[offset]);
                out.push(line);
                offset += 1;
                cur_pc = cur_pc.wrapping_add(1);
            }
        }
        out
    }

    /// Disassemble all bytes until end of slice.
    #[must_use]
    pub fn disasm_all(&self, pc: u16, bytes: &[u8]) -> Vec<DisasmLine> {
        self.disasm_n(pc, bytes, usize::MAX)
    }

    /// Build a listing with optional auto-labels for branch targets.
    #[must_use]
    pub fn listing(&self, pc: u16, bytes: &[u8]) -> Vec<ListingLine> {
        let lines = self.disasm_all(pc, bytes);
        // Collect all targets to create labels
        let mut targets: std::collections::BTreeSet<u16> = std::collections::BTreeSet::new();
        for line in &lines {
            if let Some(t) = line.branch_target { targets.insert(t); }
        }
        let mut offset = 0usize;
        lines.into_iter().map(|line| {
            let label = if targets.contains(&line.address) {
                if let Some(resolver) = self.config.label_resolver {
                    resolver(line.address)
                } else {
                    Some(format!("loc_{:04x}", line.address))
                }
            } else {
                None
            };
            let len = line.bytes.len();
            let ll = ListingLine { label, line, offset };
            offset += len;
            ll
        }).collect()
    }

    // ── Internal formatters ──────────────────────────────────────────────────

    fn format_instr(&self, pc: u16, instr: &Z80Instr, bytes: &[u8]) -> DisasmLine {
        let len = instr.len as usize;
        let raw: Vec<u8> = bytes[..len.min(bytes.len())].to_vec();

        let mnemonic = self.format_mnemonic(instr.mnemonic);
        let operands = self.format_operands(instr, pc);

        let is_terminator = instr.is_halt
            || (instr.is_branch && !instr.is_conditional && !instr.is_call);

        let cycles = estimate_cycles(instr);

        let text = self.build_text(pc, &raw, &mnemonic, &operands, instr.branch_target, cycles);

        DisasmLine {
            address: pc,
            bytes: raw,
            mnemonic,
            operands,
            text,
            branch_target: instr.branch_target,
            is_terminator,
            cycles,
        }
    }

    fn format_mnemonic(&self, m: &str) -> String {
        match self.config.syntax {
            Z80Syntax::Gas => m.to_ascii_lowercase(),
            _              => m.to_ascii_uppercase(),
        }
    }

    fn format_operands(&self, instr: &Z80Instr, pc: u16) -> String {
        let parts: Vec<String> = instr.operands.iter()
            .filter_map(|o| o.as_ref())
            .map(|o| self.format_operand(o, pc, instr.len))
            .collect();
        parts.join(",")
    }

    fn format_operand(&self, op: &Z80Operand, pc: u16, instr_len: u8) -> String {
        match op {
            Z80Operand::Rel8(d) => {
                let target = pc.wrapping_add(u16::from(instr_len)).wrapping_add(i16::from(*d).cast_unsigned());
                if let Some(resolver) = self.config.label_resolver
                    && let Some(lbl) = resolver(target) {
                        return lbl;
                    }
                self.format_addr(target)
            }
            Z80Operand::Abs16(a) => {
                if let Some(resolver) = self.config.label_resolver
                    && let Some(lbl) = resolver(*a) {
                        return lbl;
                    }
                self.format_addr(*a)
            }
            _ => match self.config.syntax {
                Z80Syntax::Intel => format_op_intel(op),
                _ => format!("{op}"),
            }
        }
    }

    fn format_addr(&self, addr: u16) -> String {
        match self.config.syntax {
            Z80Syntax::Intel => format!("{addr:04X}H"),
            // Gas and Zilog both spell addresses `0x….`
            Z80Syntax::Gas | Z80Syntax::Zilog => format!("0x{addr:04x}"),
        }
    }

    fn build_text(&self, pc: u16, raw: &[u8], mne: &str, ops: &str,
                  _target: Option<u16>, cycles: u8) -> String {
        let mut s = String::with_capacity(64);

        if self.config.show_address {
            let _ = write!(s, "{:0width$x}  ", pc, width = self.config.addr_width);
        }

        if self.config.show_bytes {
            let hex = raw.iter().fold(String::new(), |mut acc, b| {
                let _ = write!(acc, "{b:02x} ");
                acc
            });
            let hex = format!("{:<width$}", hex, width = self.config.hex_column_width);
            s.push_str(&hex);
        }

        let mne_padded = format!("{:<width$}", mne, width = self.config.mnemonic_width);
        s.push_str(&mne_padded);

        if !ops.is_empty() {
            s.push(' ');
            s.push_str(ops);
        }

        if self.config.show_cycles && cycles > 0 {
            let _ = write!(s, "  ; {cycles}T");
        }

        s
    }

    fn make_invalid(&self, pc: u16, byte: u8) -> DisasmLine {
        let raw = vec![byte];
        let mnemonic = self.format_mnemonic("DB");
        let operands = format!("0x{byte:02x}");
        let text = self.build_text(pc, &raw, &mnemonic, &operands, None, 0);
        DisasmLine {
            address: pc,
            bytes: raw,
            mnemonic,
            operands,
            text,
            branch_target: None,
            is_terminator: false,
            cycles: 0,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn format_op_intel(op: &Z80Operand) -> String {
    match op {
        Z80Operand::Imm8(v)    => format!("{v:02X}H"),
        Z80Operand::Imm16(v)   => format!("{v:04X}H"),
        Z80Operand::MemNN(n)   => format!("({n:04X}H)"),
        Z80Operand::PortImm(p) => format!("({p:02X}H)"),
        Z80Operand::MemIXd(d)  => format!("(IX{d:+02X}H)"),
        Z80Operand::MemIYd(d)  => format!("(IY{d:+02X}H)"),
        _ => format!("{op}"),
    }
}

/// Rough T-state estimates for common instructions.
fn estimate_cycles(instr: &Z80Instr) -> u8 {
    match instr.prefix {
        Z80Prefix::None => match instr.mnemonic {
            // 4 T-states: no operand fetch, register-only ALU, or rotates on A.
            "NOP" | "HALT"
            | "ADD" | "ADC" | "SUB" | "SBC" | "AND" | "OR" | "XOR" | "CP"
            | "INC" | "DEC"
            | "RLCA" | "RRCA" | "RLA" | "RRA" => 4,
            "LD"   => 7,
            // 11 T-states: a 16-bit stack access, or an I/O cycle.
            "PUSH" | "POP" | "IN" | "OUT" => 11,
            "CALL" => 17,
            // 10 T-states: pop/push a return address, or fetch a 16-bit target.
            "RET" | "JP" => 10,
            "JR"   => 12,
            "DJNZ" => 13,
            _      => 0,
        },
        Z80Prefix::Cb | Z80Prefix::Ed => 8,
        Z80Prefix::Dd | Z80Prefix::Fd => 15,
        Z80Prefix::DdCb | Z80Prefix::FdCb => 23,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn disasm() -> Z80Disassembler {
        Z80Disassembler::with_defaults()
    }

    #[test]
    fn disasm_nop() {
        let line = disasm().disasm_one(0x0000, &[0x00]).unwrap();
        assert_eq!(line.mnemonic, "NOP");
        assert!(line.text.contains("NOP"));
        assert!(line.text.contains("0000"));
    }

    #[test]
    fn disasm_ld_hl() {
        let line = disasm().disasm_one(0x0000, &[0x21, 0x34, 0x12]).unwrap();
        assert_eq!(line.mnemonic, "LD");
        assert!(line.text.contains("1234"));
    }

    #[test]
    fn disasm_jp() {
        let line = disasm().disasm_one(0x0100, &[0xC3, 0x00, 0x80]).unwrap();
        assert!(line.is_terminator);
        assert_eq!(line.branch_target, Some(0x8000));
    }

    #[test]
    fn disasm_jr_nz() {
        let line = disasm().disasm_one(0x0100, &[0x20, 0xFE]).unwrap();
        assert!(!line.is_terminator); // conditional
        assert_eq!(line.branch_target, Some(0x0100));
    }

    #[test]
    fn disasm_halt_is_terminator() {
        let line = disasm().disasm_one(0, &[0x76]).unwrap();
        assert!(line.is_terminator);
    }

    #[test]
    fn disasm_n_multiple() {
        let bytes = [0x00u8, 0x00, 0x76];
        let lines = disasm().disasm_n(0, &bytes, 10);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2].mnemonic, "HALT");
    }

    #[test]
    fn disasm_all_count() {
        let bytes = [0x00u8, 0x00, 0x00, 0xC9]; // NOP×3 RET
        let lines = disasm().disasm_all(0, &bytes);
        assert_eq!(lines.len(), 4);
    }

    #[test]
    fn listing_labels() {
        // JR to itself: target = 0
        let bytes = [0x18u8, 0xFE]; // JR -2 → target 0x0000
        let listing = disasm().listing(0, &bytes);
        assert_eq!(listing.len(), 1);
        assert!(listing[0].label.as_deref().unwrap_or("").contains("0000"));
    }

    #[test]
    fn gas_syntax_lowercase() {
        let cfg = Z80DisasmConfig::new().with_syntax(Z80Syntax::Gas);
        let d = Z80Disassembler::new(cfg);
        let line = d.disasm_one(0, &[0x00]).unwrap();
        assert_eq!(line.mnemonic, "nop");
    }

    #[test]
    fn cycles_nop() {
        let cfg = Z80DisasmConfig { show_cycles: true, ..Default::default() };
        let d = Z80Disassembler::new(cfg);
        let line = d.disasm_one(0, &[0x00]).unwrap();
        assert_eq!(line.cycles, 4);
        assert!(line.text.contains("4T"));
    }

    #[test]
    fn dd_ix_instr() {
        let line = disasm().disasm_one(0, &[0xDD, 0x21, 0xFF, 0x00]).unwrap();
        assert_eq!(line.mnemonic, "LD");
        assert!(line.text.contains("IX") || line.text.contains("ix"));
    }
}
