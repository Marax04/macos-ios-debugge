// m68k_disassembler.rs — M68000 disassembler with Motorola syntax
//
// Types: M68kDisasmConfig, DisasmLine, M68kDisassembler, EaFormatter, BranchTarget.
//
// Only std is used; no external crates.

use std::collections::HashMap;
use std::fmt;

use crate::m68k_decoder::{M68kDecoder, M68kEa, M68kInstr, M68kSize};

// ────────────────────────────────────────────────────────────────────────────
// BranchTarget
// ────────────────────────────────────────────────────────────────────────────

/// A resolved branch target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchTarget {
    /// Absolute address of the target.
    pub address: u32,
    /// Optional name/label for the target.
    pub label: Option<String>,
    /// True if this is a call (JSR/BSR).
    pub is_call: bool,
    /// True if conditional.
    pub is_conditional: bool,
}

impl BranchTarget {
    #[must_use]
    pub const fn new(address: u32, label: Option<String>, is_call: bool, is_conditional: bool) -> Self {
        Self { address, label, is_call, is_conditional }
    }

    #[must_use]
    pub fn label_or_addr(&self) -> String {
        self.label.as_ref().map_or_else(|| format!("loc_{:08X}", self.address), std::clone::Clone::clone)
    }
}

impl fmt::Display for BranchTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label_or_addr())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kDisasmConfig
// ────────────────────────────────────────────────────────────────────────────

/// Boolean rendering options for [`M68kDisasmConfig`], packed as one bit set.
///
/// Bit layout (LSB first): `SHOW_BYTES | SHOW_ADDRESS | USE_LABELS |
/// UPPERCASE | RESOLVE_PCREL`.  Packing them removes the risk of transposing
/// same-typed `bool` fields at a construction site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisasmFlags(u8);

impl DisasmFlags {
    /// Show hex bytes alongside each instruction.
    pub const SHOW_BYTES: u8 = 1 << 0;
    /// Show absolute addresses.
    pub const SHOW_ADDRESS: u8 = 1 << 1;
    /// Replace branch target addresses with labels where known.
    pub const USE_LABELS: u8 = 1 << 2;
    /// Use uppercase mnemonics (Motorola style).
    pub const UPPERCASE: u8 = 1 << 3;
    /// Show PC-relative operands as absolute addresses.
    pub const RESOLVE_PCREL: u8 = 1 << 4;

    /// Every bit this type tracks.
    pub const MASK: u8 = Self::SHOW_BYTES
        | Self::SHOW_ADDRESS
        | Self::USE_LABELS
        | Self::UPPERCASE
        | Self::RESOLVE_PCREL;

    /// No options enabled.
    pub const NONE: Self = Self(0);
    /// The default rendering: everything on.
    pub const ALL: Self = Self(Self::MASK);

    /// Keep only the bits this type tracks.
    #[must_use]
    pub const fn from_bits(v: u8) -> Self {
        Self(v & Self::MASK)
    }

    /// The raw bit image.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// True when `bit` (one of the associated constants) is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// A copy with `bit` set (`on`) or cleared.
    #[must_use]
    pub const fn with(self, bit: u8, on: bool) -> Self {
        if on { Self(self.0 | (bit & Self::MASK)) } else { Self(self.0 & !bit) }
    }
}

impl core::ops::BitOr for DisasmFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Configuration for the M68k disassembler.
#[derive(Clone, Debug)]
pub struct M68kDisasmConfig {
    /// Boolean rendering options, packed in bit order.
    pub flags: DisasmFlags,
    /// Column width for the mnemonic field.
    pub mnemonic_width: usize,
    /// Column width for the address field.
    pub address_width: usize,
    /// Column width for hex bytes field.
    pub bytes_width: usize,
    /// Maximum bytes to show in the bytes column.
    pub max_bytes_shown: usize,
}

impl M68kDisasmConfig {
    /// Show hex bytes alongside each instruction.
    #[must_use]
    pub const fn show_bytes(&self) -> bool { self.flags.has(DisasmFlags::SHOW_BYTES) }
    /// Show absolute addresses.
    #[must_use]
    pub const fn show_address(&self) -> bool { self.flags.has(DisasmFlags::SHOW_ADDRESS) }
    /// Replace branch target addresses with labels where known.
    #[must_use]
    pub const fn use_labels(&self) -> bool { self.flags.has(DisasmFlags::USE_LABELS) }
    /// Use uppercase mnemonics.
    #[must_use]
    pub const fn uppercase(&self) -> bool { self.flags.has(DisasmFlags::UPPERCASE) }
    /// Show PC-relative operands as absolute addresses.
    #[must_use]
    pub const fn resolve_pcrel(&self) -> bool { self.flags.has(DisasmFlags::RESOLVE_PCREL) }
}

impl Default for M68kDisasmConfig {
    fn default() -> Self {
        Self {
            flags: DisasmFlags::ALL,
            mnemonic_width: 8,
            address_width: 8,
            bytes_width: 20,
            max_bytes_shown: 10,
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// DisasmLine
// ────────────────────────────────────────────────────────────────────────────

/// A single disassembled line.
#[derive(Clone, Debug)]
pub struct DisasmLine {
    /// Virtual address.
    pub address: u32,
    /// Raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// Full text of the disassembled line (as formatted by the disassembler).
    pub text: String,
    /// Optional label at this address.
    pub label: Option<String>,
    /// Branch target if this is a branch/call.
    pub branch_target: Option<BranchTarget>,
    /// True if this is a call.
    pub is_call: bool,
    /// True if this terminates basic-block flow.
    pub is_terminator: bool,
    /// True if the instruction was not decodeable.
    pub is_illegal: bool,
}

impl DisasmLine {
    #[must_use]
    pub fn end_address(&self) -> u32 {
        // An instruction is a handful of bytes; the length can never overflow
        // `u32`, and saturating keeps a corrupt buffer from wrapping the PC.
        self.address.wrapping_add(u32::try_from(self.bytes.len()).unwrap_or(u32::MAX))
    }
}

impl fmt::Display for DisasmLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(lbl) = &self.label {
            writeln!(f, "{lbl}:")?;
        }
        write!(f, "{}", self.text)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// EaFormatter
// ────────────────────────────────────────────────────────────────────────────

/// Formats effective addresses in Motorola syntax, optionally resolving
/// labels, PC-relative expressions, and immediate values.
pub struct EaFormatter<'a> {
    /// Labels table: address → name.
    pub labels: &'a HashMap<u32, String>,
    /// Current instruction PC (for `DispPc` resolution).
    pub instr_pc: u32,
    /// Whether to use uppercase.
    pub uppercase: bool,
    /// Whether to resolve PC-relative as absolute.
    pub resolve_pcrel: bool,
}

impl<'a> EaFormatter<'a> {
    #[must_use]
    pub const fn new(labels: &'a HashMap<u32, String>, instr_pc: u32) -> Self {
        EaFormatter { labels, instr_pc, uppercase: true, resolve_pcrel: true }
    }

    /// Format an effective address to a string.
    #[must_use]
    pub fn format(&self, ea: &M68kEa, sz: M68kSize) -> String {
        match ea {
            M68kEa::DataReg(n) => self.case(&format!("D{n}")),
            M68kEa::AddrReg(n) => self.case(&format!("A{n}")),
            M68kEa::AddrInd(n) => format!("({})", self.case(&format!("A{n}"))),
            M68kEa::PostInc(n) => format!("({})+", self.case(&format!("A{n}"))),
            M68kEa::PreDec(n)  => format!("-({})", self.case(&format!("A{n}"))),
            M68kEa::DispAn(an, d) => format!("({},{})", d, self.case(&format!("A{an}"))),
            M68kEa::IdxAn { an, xn, xn_is_addr, xn_size, disp } => {
                let xreg = if *xn_is_addr { self.case(&format!("A{xn}")) } else { self.case(&format!("D{xn}")) };
                format!("({},{},{}.{})", disp, self.case(&format!("A{an}")), xreg,
                    if self.uppercase { xn_size.suffix().to_uppercase().trim_start_matches('.').to_string() }
                    else { xn_size.suffix().trim_start_matches('.').to_string() })
            }
            M68kEa::AbsShort(a) => self.format_addr(*a, ".W"),
            M68kEa::AbsLong(a)  => self.format_addr(*a, ".L"),
            M68kEa::DispPc(d) => {
                if self.resolve_pcrel {
                    // PC at end of instruction word = instr_pc + 2
                    // 68k PC-relative targets wrap inside the 32-bit address space;
                    // doing the arithmetic in `u32` reproduces that exactly
                    // instead of narrowing a wider intermediate.
                    let target = self.instr_pc.wrapping_add(2).wrapping_add_signed(i32::from(*d));
                    self.format_addr(target, "")
                } else {
                    format!("({d},PC)")
                }
            }
            M68kEa::IdxPc { xn, xn_is_addr, xn_size, disp } => {
                let xreg = if *xn_is_addr { self.case(&format!("A{xn}")) } else { self.case(&format!("D{xn}")) };
                if self.resolve_pcrel {
                    let base = self.instr_pc.wrapping_add(2).wrapping_add_signed(i32::from(*disp));
                    format!("({},{},PC)", self.format_addr(base, ""), xreg)
                } else {
                    format!("({},PC,{}.{})", disp, xreg,
                        xn_size.suffix().trim_start_matches('.'))
                }
            }
            M68kEa::Imm(v) => Self::format_imm(*v, sz),
            M68kEa::Ccr => self.case("CCR"),
            M68kEa::Sr  => self.case("SR"),
            M68kEa::Usp => self.case("USP"),
            M68kEa::RegList(mask) => self.format_reglist(*mask),
        }
    }

    fn case(&self, s: &str) -> String {
        if self.uppercase { s.to_uppercase() } else { s.to_lowercase() }
    }

    fn format_addr(&self, addr: u32, suffix: &str) -> String {
        if let Some(lbl) = self.labels.get(&addr) {
            return lbl.clone();
        }
        if suffix.is_empty() {
            format!("${addr:X}")
        } else {
            format!("${addr:X}{suffix}")
        }
    }

    fn format_imm(v: u32, sz: M68kSize) -> String {
        match sz {
            M68kSize::Byte => format!("#${:02X}", v & 0xFF),
            M68kSize::Word => format!("#${:04X}", v & 0xFFFF),
            M68kSize::Long => format!("#${v:08X}"),
            _              => format!("#${v:X}"),
        }
    }

    fn format_reglist(&self, mask: u16) -> String {
        let mut parts = Vec::with_capacity(mask.count_ones() as usize);
        for i in 0..8u8 {
            if (mask >> i) & 1 == 1 {
                parts.push(format!("D{i}"));
            }
        }
        for i in 0..8u8 {
            if (mask >> (i + 8)) & 1 == 1 {
                parts.push(format!("A{i}"));
            }
        }
        let joined = parts.join("/");
        if self.uppercase { joined.to_uppercase() } else { joined.to_lowercase() }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kDisassembler
// ────────────────────────────────────────────────────────────────────────────

/// M68000 disassembler.
///
/// Wraps `M68kDecoder` and applies formatting with Motorola syntax.
/// Maintains a label table for symbolic name resolution.
pub struct M68kDisassembler {
    config: M68kDisasmConfig,
    decoder: M68kDecoder,
    /// Labels: address → name.
    pub labels: HashMap<u32, String>,
}

impl M68kDisassembler {
    #[must_use]
    pub fn new(config: M68kDisasmConfig) -> Self {
        Self {
            config,
            decoder: M68kDecoder::new(),
            labels: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_default_config() -> Self {
        Self::new(M68kDisasmConfig::default())
    }

    /// Add a label for an address.
    pub fn add_label(&mut self, address: u32, name: impl Into<String>) {
        self.labels.insert(address, name.into());
    }

    /// Remove a label.
    pub fn remove_label(&mut self, address: u32) {
        self.labels.remove(&address);
    }

    /// Disassemble a single instruction.
    #[must_use]
    pub fn disassemble_one(&self, data: &[u8], address: u32) -> DisasmLine {
        let instr_result = self.decoder.decode(data, address);
        match instr_result {
            Ok(instr) => self.format_instr(&instr, data),
            Err(e) => {
                let bytes = data.get(..2).unwrap_or(&[0, 0]).to_vec();
                DisasmLine {
                    address,
                    bytes,
                    text: format!("{:08X}  {:04X}                  DC.W    ${:04X}",
                        address, e.opcode, e.opcode),
                    label: self.labels.get(&address).cloned(),
                    branch_target: None,
                    is_call: false,
                    is_terminator: false,
                    is_illegal: true,
                }
            }
        }
    }

    fn format_instr(&self, instr: &M68kInstr, data: &[u8]) -> DisasmLine {
        let len = instr.length.max(2) as usize;
        let bytes: Vec<u8> = data.get(..len).unwrap_or(&[]).to_vec();

        let ea_fmt = EaFormatter {
            labels: &self.labels,
            instr_pc: instr.address,
            uppercase: self.config.uppercase(),
            resolve_pcrel: self.config.resolve_pcrel(),
        };

        // Format operands
        let operands = self.format_operands(instr, &ea_fmt);

        // Format mnemonic with size suffix
        let mut mnem = instr.mnemonic.clone();
        if self.config.uppercase() { mnem = mnem.to_uppercase(); }
        else { mnem = mnem.to_lowercase(); }
        let sz_str = if instr.size == M68kSize::Unsized { String::new() }
                     else { instr.size.suffix().to_string() };
        let full_mnem = format!("{}{}", mnem, if self.config.uppercase() { sz_str.to_uppercase() } else { sz_str });

        // Build text line
        let text = self.build_line(instr.address, &bytes, &full_mnem, &operands);

        // Build branch target
        let branch_target = instr.branch_target.map(|addr| {
            BranchTarget::new(
                addr,
                self.labels.get(&addr).cloned(),
                instr.is_call,
                instr.cond.is_some(),
            )
        });

        DisasmLine {
            address: instr.address,
            bytes,
            text,
            label: self.labels.get(&instr.address).cloned(),
            branch_target,
            is_call: instr.is_call,
            is_terminator: instr.is_terminator,
            is_illegal: instr.is_illegal,
        }
    }

    fn format_operands(&self, instr: &M68kInstr, fmt: &EaFormatter<'_>) -> String {
        match (&instr.src, &instr.dst) {
            (Some(src), Some(dst)) => format!("{},{}",
                fmt.format(src, instr.size), fmt.format(dst, instr.size)),
            (Some(src), None) => fmt.format(src, instr.size),
            (None, Some(dst)) => {
                // For branches: show target
                if let Some(target) = instr.branch_target {
                    if let Some(lbl) = self.labels.get(&target) {
                        return lbl.clone();
                    }
                    return format!("${target:X}");
                }
                fmt.format(dst, instr.size)
            }
            (None, None) => {
                // Branch with no EA in dst
                if let Some(target) = instr.branch_target {
                    if let Some(lbl) = self.labels.get(&target) {
                        return lbl.clone();
                    }
                    return format!("${target:X}");
                }
                String::new()
            }
        }
    }

    fn build_line(&self, addr: u32, bytes: &[u8], mnem: &str, operands: &str) -> String {
        use core::fmt::Write as _;
        let mut s = String::new();

        if self.config.show_address() {
            let _ = write!(s, "{:0width$X}  ", addr, width = self.config.address_width);
        }
        if self.config.show_bytes() {
            let mut hex_bytes = String::with_capacity(self.config.max_bytes_shown * 3);
            for (i, b) in bytes.iter().take(self.config.max_bytes_shown).enumerate() {
                if i > 0 { hex_bytes.push(' '); }
                let _ = std::fmt::Write::write_fmt(&mut hex_bytes, format_args!("{b:02X}"));
            }
            let _ = write!(s, "{:<width$}  ", hex_bytes, width = self.config.bytes_width);
        }

        let mnem_field = format!("{:<width$}", mnem, width = self.config.mnemonic_width);
        s.push_str(&mnem_field);
        if !operands.is_empty() {
            s.push_str(operands);
        }
        s
    }

    /// Disassemble a block of bytes.
    #[must_use]
    pub fn disassemble(&self, data: &[u8], base_address: u32) -> Vec<DisasmLine> {
        let mut lines = Vec::new();
        let mut off = 0usize;
        while off + 2 <= data.len() {
            // The 68k address space is 32 bits wide, so a sweep offset cannot
            // legitimately exceed `u32::MAX`.
            let addr = base_address.wrapping_add(u32::try_from(off).unwrap_or(u32::MAX));
            let line = self.disassemble_one(&data[off..], addr);
            let consumed = line.bytes.len().max(2);
            off += consumed;
            lines.push(line);
        }
        lines
    }

    /// Disassemble until a terminator is reached (or limit is hit).
    #[must_use]
    pub fn disassemble_flow(&self, data: &[u8], base_address: u32, max_instrs: usize) -> Vec<DisasmLine> {
        let mut lines = Vec::new();
        let mut off = 0usize;
        while off + 2 <= data.len() && lines.len() < max_instrs {
            // The 68k address space is 32 bits wide, so a sweep offset cannot
            // legitimately exceed `u32::MAX`.
            let addr = base_address.wrapping_add(u32::try_from(off).unwrap_or(u32::MAX));
            let line = self.disassemble_one(&data[off..], addr);
            let consumed = line.bytes.len().max(2);
            let is_term = line.is_terminator;
            off += consumed;
            lines.push(line);
            if is_term { break; }
        }
        lines
    }

    /// Format a full disassembly listing as a string.
    #[must_use]
    pub fn listing(&self, data: &[u8], base_address: u32) -> String {
        let lines = self.disassemble(data, base_address);
        let mut out = String::new();
        for line in &lines {
            if let Some(lbl) = &line.label {
                out.push_str(lbl);
                out.push_str(":\n");
            }
            out.push_str(&line.text);
            out.push('\n');
        }
        out
    }

    /// Auto-generate labels for all branch targets in a listing.
    /// Returns number of labels created.
    pub fn auto_label(&mut self, data: &[u8], base_address: u32) -> usize {
        // First pass: collect all branch targets
        let instrs = self.decoder.decode_all(data, base_address);
        let mut targets: Vec<(u32, bool)> = Vec::with_capacity(instrs.len());
        for instr in &instrs {
            if let Some(target) = instr.branch_target {
                targets.push((target, instr.is_call));
            }
        }
        // Second pass: assign labels
        let mut count = 0;
        for (addr, is_call) in targets {
            if let std::collections::hash_map::Entry::Vacant(slot) = self.labels.entry(addr) {
                let prefix = if is_call { "sub" } else { "loc" };
                slot.insert(format!("{prefix}_{addr:08X}"));
                count += 1;
            }
        }
        count
    }

    /// Get config reference.
    #[must_use]
    pub const fn config(&self) -> &M68kDisasmConfig { &self.config }
    /// Get mutable config reference.
    pub const fn config_mut(&mut self) -> &mut M68kDisasmConfig { &mut self.config }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn disasm() -> M68kDisassembler {
        M68kDisassembler::with_default_config()
    }

    #[test]
    fn test_disasm_nop() {
        let d = disasm();
        let line = d.disassemble_one(&[0x4E, 0x71], 0x1000);
        assert!(line.text.contains("NOP"));
        assert_eq!(line.bytes, vec![0x4E, 0x71]);
        assert!(!line.is_illegal);
    }

    #[test]
    fn test_disasm_rts() {
        let d = disasm();
        let line = d.disassemble_one(&[0x4E, 0x75], 0x1000);
        assert!(line.text.contains("RTS"));
        assert!(line.is_terminator);
    }

    #[test]
    fn test_disasm_moveq() {
        let d = disasm();
        let line = d.disassemble_one(&[0x70, 0x05], 0x0);
        assert!(line.text.contains("MOVEQ"));
        assert!(line.text.contains("D0"));
    }

    #[test]
    fn test_disasm_bra_label() {
        let mut d = disasm();
        d.add_label(0x1006, "target".to_string());
        // BRA.B +4 from 0x1000 → target = 0x1006
        let line = d.disassemble_one(&[0x60, 0x04], 0x1000);
        assert!(line.text.contains("BRA"));
        assert!(line.text.contains("target"), "text: {}", line.text);
        assert!(line.is_terminator);
    }

    #[test]
    fn test_disasm_block() {
        let d = disasm();
        let data = [0x70, 0x01, 0x4E, 0x75u8]; // MOVEQ + RTS
        let lines = d.disassemble(&data, 0);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].text.contains("MOVEQ"));
        assert!(lines[1].text.contains("RTS"));
    }

    #[test]
    fn test_disasm_flow_stops_at_terminator() {
        let d = disasm();
        let data = [0x4E, 0x75, 0x70, 0x01]; // RTS, MOVEQ (should stop)
        let lines = d.disassemble_flow(&data, 0, 100);
        assert_eq!(lines.len(), 1); // stops at RTS
        assert!(lines[0].is_terminator);
    }

    #[test]
    fn test_listing() {
        let d = disasm();
        let data = [0x4E, 0x71, 0x4E, 0x75];
        let s = d.listing(&data, 0x1000);
        assert!(s.contains("NOP"));
        assert!(s.contains("RTS"));
    }

    #[test]
    fn test_auto_label() {
        let mut d = disasm();
        // BRA.B +0 → 0x1002
        let data = [0x60, 0x00, 0x60, 0xfe]; // two BRA
        d.auto_label(&data, 0x1000);
        // loc_00001002 should have been created
        assert!(d.labels.values().any(|v| v.starts_with("loc_")));
    }

    #[test]
    fn test_branch_target() {
        let mut d = disasm();
        d.add_label(0x1006, "loop".to_string());
        let data = [0x60, 0x04]; // BRA.B +4
        let line = d.disassemble_one(&data, 0x1000);
        let bt = line.branch_target.expect("branch target");
        assert_eq!(bt.address, 0x1006);
        assert_eq!(bt.label, Some("loop".to_string()));
    }

    #[test]
    fn test_ea_formatter_imm() {
        let labels = HashMap::new();
        let fmt = EaFormatter::new(&labels, 0x1000);
        let ea = M68kEa::Imm(0xABCD);
        let s = fmt.format(&ea, M68kSize::Word);
        assert!(s.contains("$ABCD"), "got: {s}");
    }

    #[test]
    fn test_ea_formatter_dispan() {
        let labels = HashMap::new();
        let fmt = EaFormatter::new(&labels, 0x1000);
        let ea = M68kEa::DispAn(6, -4);
        let s = fmt.format(&ea, M68kSize::Long);
        assert!(s.contains("A6"), "got: {s}");
        assert!(s.contains("-4"), "got: {s}");
    }
}
