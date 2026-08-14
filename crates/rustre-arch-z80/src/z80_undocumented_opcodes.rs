//! `z80_undocumented_opcodes` — Z80 undocumented opcode decoding and detection.
//!
//! The Zilog Z80 has a number of opcodes that are not documented in the official
//! User Manual but are consistently implemented across all Z80 silicon.
//!
//! The primary categories are:
//!
//! 1. **IXH / IXL / IYH / IYL** — the high and low bytes of the IX and IY
//!    registers can be accessed individually using DD/FD-prefix + register
//!    instructions where `H` (0x04) and `L` (0x05) would normally appear.
//!
//! 2. **SLL / SL1** — opcode `CB 36` rotates left and inserts a 1 in bit 0.
//!    Documented in the Z80 CPU User Manual as reserved but universally
//!    implemented.
//!
//! 3. **DDCB / FDCB combined bit + load instructions** — `DD CB d op` / `FD CB d op`
//!    where the result is both stored in `(IX+d)` AND copied to a register.
//!
//! 4. **SLI / SLS** variants and assorted ED-prefix undocumented operations.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── UndocInsn ───────────────────────────────────────────────────────────────

/// Category of an undocumented Z80 instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UndocInsn {
    /// Access to IXH (high byte of IX) via `DD` prefix.
    IxHigh,
    /// Access to IXL (low byte of IX) via `DD` prefix.
    IxLow,
    /// Access to IYH (high byte of IY) via `FD` prefix.
    IyHigh,
    /// Access to IYL (low byte of IY) via `FD` prefix.
    IyLow,
    /// SLL / SL1: shift left, insert 1 in bit 0 (CB 36).
    Sll,
    /// DDCB/FDCB combined bit-manipulation + register load.
    DdCbLoad,
    /// Undocumented ED-prefix opcode (e.g. ED 63..66 variants).
    EdUndoc,
    /// NOP aliases (opcode 0x00 duplicates such as ED 77, ED 7F, etc.).
    NopAlias,
    /// Undocumented OUT(C), 0 — outputs 0 on bus (ED 71).
    OutC0,
    /// Undocumented IN F,(C) — reads port but discards to F (ED 70).
    InFC,
}

impl UndocInsn {
    /// Human-readable description.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::IxHigh => "IXH register access (DD prefix + H encoding)",
            Self::IxLow => "IXL register access (DD prefix + L encoding)",
            Self::IyHigh => "IYH register access (FD prefix + H encoding)",
            Self::IyLow => "IYL register access (FD prefix + L encoding)",
            Self::Sll => "SLL/SL1: shift left logical, set bit 0 (CB 36)",
            Self::DdCbLoad => "DDCB/FDCB combined bit-op + register load",
            Self::EdUndoc => "Undocumented ED-prefix opcode",
            Self::NopAlias => "NOP alias (ignored opcode)",
            Self::OutC0 => "OUT (C),0 — undocumented output 0 (ED 71)",
            Self::InFC => "IN F,(C) — read port, set flags, discard result (ED 70)",
        }
    }

    /// Whether this instruction is widely supported (NMOS/CMOS).
    #[must_use]
    pub const fn is_widely_supported(self) -> bool {
        matches!(
            self,
            Self::IxHigh
                | Self::IxLow
                | Self::IyHigh
                | Self::IyLow
                | Self::Sll
                | Self::DdCbLoad
                | Self::InFC
                | Self::OutC0
        )
    }

    /// Whether this instruction is CMOS-only (may behave differently on NMOS).
    #[must_use]
    pub const fn is_cmos_only(self) -> bool {
        matches!(self, Self::NopAlias)
    }
}

impl fmt::Display for UndocInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

// ─── Z80UndocumentedOpcode ───────────────────────────────────────────────────

/// A decoded undocumented Z80 instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Z80UndocumentedOpcode {
    /// Address at which this instruction was found.
    pub address: u64,
    /// Raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// Instruction size in bytes.
    pub size: usize,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Operand string.
    pub operands: String,
    /// Category.
    pub category: UndocInsn,
    /// Confidence that this is intentional usage [0, 100].
    pub confidence: u8,
}

impl Z80UndocumentedOpcode {
    /// Returns the full disassembly text.
    #[must_use]
    pub fn disassembly(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }

    /// Returns the hex representation of the raw bytes.
    #[must_use]
    pub fn hex_bytes(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for Z80UndocumentedOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04X}: {:12} {}",
            self.address,
            self.hex_bytes(),
            self.disassembly()
        )
    }
}

// ─── is_undocumented ─────────────────────────────────────────────────────────

/// Returns `true` when the given byte sequence starts with an undocumented
/// Z80 opcode.
///
/// Checks only the first prefix byte(s); does not decode the full instruction.
#[must_use]
pub fn is_undocumented(bytes: &[u8]) -> bool {
    decode_undocumented(bytes, 0).is_some()
}

/// Try to decode an undocumented Z80 instruction from `bytes` at `address`.
///
/// Returns `Some(Z80UndocumentedOpcode)` when an undocumented pattern is
/// detected, `None` otherwise.
#[must_use]
pub fn decode_undocumented(bytes: &[u8], address: u64) -> Option<Z80UndocumentedOpcode> {
    if bytes.is_empty() {
        return None;
    }
    match bytes[0] {
        // ── DD prefix ────────────────────────────────────────────────────────
        0xDD => {
            if bytes.len() < 2 {
                return None;
            }
            decode_dd_undoc(bytes, address)
        }
        // ── FD prefix ────────────────────────────────────────────────────────
        0xFD => {
            if bytes.len() < 2 {
                return None;
            }
            decode_fd_undoc(bytes, address)
        }
        // ── CB prefix ────────────────────────────────────────────────────────
        0xCB => {
            if bytes.len() < 2 {
                return None;
            }
            decode_cb_undoc(bytes, address)
        }
        // ── ED prefix ────────────────────────────────────────────────────────
        0xED => {
            if bytes.len() < 2 {
                return None;
            }
            decode_ed_undoc(bytes, address)
        }
        _ => None,
    }
}

// ── DD-prefix undocumented instructions ──────────────────────────────────────

fn decode_dd_undoc(bytes: &[u8], address: u64) -> Option<Z80UndocumentedOpcode> {
    let op = bytes[1];
    // DDCB combined bit/load instructions
    if op == 0xCB && bytes.len() >= 4 {
        return decode_ddcb_load(bytes, address, "IX");
    }
    // IXH/IXL register accesses via H/L encodings
    let (mnemonic, operands, cat) = decode_ix_reg_op(op, "IX", "IXH", "IXL")?;
    Some(Z80UndocumentedOpcode {
        address,
        bytes: bytes[..2.min(bytes.len())].to_vec(),
        size: 2,
        mnemonic,
        operands,
        category: cat,
        confidence: 90,
    })
}

fn decode_fd_undoc(bytes: &[u8], address: u64) -> Option<Z80UndocumentedOpcode> {
    let op = bytes[1];
    // FDCB combined bit/load instructions
    if op == 0xCB && bytes.len() >= 4 {
        return decode_ddcb_load(bytes, address, "IY");
    }
    // IYH/IYL register accesses via H/L encodings
    let (mnemonic, operands, cat) = decode_ix_reg_op(op, "IY", "IYH", "IYL")?;
    Some(Z80UndocumentedOpcode {
        address,
        bytes: bytes[..2.min(bytes.len())].to_vec(),
        size: 2,
        mnemonic,
        operands,
        category: cat,
        confidence: 90,
    })
}

/// Decode IXH/IXL or IYH/IYL operations from the secondary opcode byte.
fn decode_ix_reg_op(
    op: u8,
    idx: &str,
    hi_name: &str,
    lo_name: &str,
) -> Option<(String, String, UndocInsn)> {
    let hi = hi_name;
    let lo = lo_name;
    let cat_hi = if idx == "IX" { UndocInsn::IxHigh } else { UndocInsn::IyHigh };
    let cat_lo = if idx == "IX" { UndocInsn::IxLow } else { UndocInsn::IyLow };
    match op {
        // LD r, IXH — 8 opcodes (reg = B,C,D,E,A)
        0x44 => Some(("LD".into(), format!("B,{hi}"), cat_hi)),
        0x4C => Some(("LD".into(), format!("C,{hi}"), cat_hi)),
        0x54 => Some(("LD".into(), format!("D,{hi}"), cat_hi)),
        0x5C => Some(("LD".into(), format!("E,{hi}"), cat_hi)),
        0x7C => Some(("LD".into(), format!("A,{hi}"), cat_hi)),
        // LD r, IXL
        0x45 => Some(("LD".into(), format!("B,{lo}"), cat_lo)),
        0x4D => Some(("LD".into(), format!("C,{lo}"), cat_lo)),
        0x55 => Some(("LD".into(), format!("D,{lo}"), cat_lo)),
        0x5D => Some(("LD".into(), format!("E,{lo}"), cat_lo)),
        0x7D => Some(("LD".into(), format!("A,{lo}"), cat_lo)),
        // LD IXH, r
        0x60 => Some(("LD".into(), format!("{hi},B"), cat_hi)),
        0x61 => Some(("LD".into(), format!("{hi},C"), cat_hi)),
        0x62 => Some(("LD".into(), format!("{hi},D"), cat_hi)),
        0x63 => Some(("LD".into(), format!("{hi},E"), cat_hi)),
        0x64 => Some(("LD".into(), format!("{hi},{hi}"), cat_hi)),
        0x65 => Some(("LD".into(), format!("{hi},{lo}"), cat_lo)),
        0x67 => Some(("LD".into(), format!("{hi},A"), cat_hi)),
        // LD IXL, r
        0x68 => Some(("LD".into(), format!("{lo},B"), cat_lo)),
        0x69 => Some(("LD".into(), format!("{lo},C"), cat_lo)),
        0x6A => Some(("LD".into(), format!("{lo},D"), cat_lo)),
        0x6B => Some(("LD".into(), format!("{lo},E"), cat_lo)),
        0x6C => Some(("LD".into(), format!("{lo},{hi}"), cat_hi)),
        0x6D => Some(("LD".into(), format!("{lo},{lo}"), cat_lo)),
        0x6F => Some(("LD".into(), format!("{lo},A"), cat_lo)),
        // ADD/ADC/SUB/SBC/AND/XOR/OR/CP with IXH / IXL
        0x84 => Some(("ADD".into(), format!("A,{hi}"), cat_hi)),
        0x85 => Some(("ADD".into(), format!("A,{lo}"), cat_lo)),
        0x8C => Some(("ADC".into(), format!("A,{hi}"), cat_hi)),
        0x8D => Some(("ADC".into(), format!("A,{lo}"), cat_lo)),
        0x94 => Some(("SUB".into(), hi.to_string(), cat_hi)),
        0x95 => Some(("SUB".into(), lo.to_string(), cat_lo)),
        0x9C => Some(("SBC".into(), format!("A,{hi}"), cat_hi)),
        0x9D => Some(("SBC".into(), format!("A,{lo}"), cat_lo)),
        0xA4 => Some(("AND".into(), hi.to_string(), cat_hi)),
        0xA5 => Some(("AND".into(), lo.to_string(), cat_lo)),
        0xAC => Some(("XOR".into(), hi.to_string(), cat_hi)),
        0xAD => Some(("XOR".into(), lo.to_string(), cat_lo)),
        0xB4 => Some(("OR".into(), hi.to_string(), cat_hi)),
        0xB5 => Some(("OR".into(), lo.to_string(), cat_lo)),
        0xBC => Some(("CP".into(), hi.to_string(), cat_hi)),
        0xBD => Some(("CP".into(), lo.to_string(), cat_lo)),
        // INC/DEC IXH / IXL
        0x24 => Some(("INC".into(), hi.to_string(), cat_hi)),
        0x25 => Some(("DEC".into(), hi.to_string(), cat_hi)),
        0x2C => Some(("INC".into(), lo.to_string(), cat_lo)),
        0x2D => Some(("DEC".into(), lo.to_string(), cat_lo)),
        // LD IXH / IXL, n
        0x26 => Some(("LD".into(), format!("{hi},n"), cat_hi)),
        0x2E => Some(("LD".into(), format!("{lo},n"), cat_lo)),
        _ => None,
    }
}

// ── CB-prefix undocumented: SLL (0x30..0x37) ────────────────────────────────

fn decode_cb_undoc(bytes: &[u8], address: u64) -> Option<Z80UndocumentedOpcode> {
    let op = bytes[1];
    // SLL: CB 30..37 (shifts left and sets bit 0)
    if (0x30..=0x37).contains(&op) {
        let reg = match op & 7 {
            0 => "B",
            1 => "C",
            2 => "D",
            3 => "E",
            4 => "H",
            5 => "L",
            6 => "(HL)",
            _ => "A",
        };
        return Some(Z80UndocumentedOpcode {
            address,
            bytes: bytes[..2].to_vec(),
            size: 2,
            mnemonic: "SLL".to_string(),
            operands: reg.to_string(),
            category: UndocInsn::Sll,
            confidence: 95,
        });
    }
    None
}

// ── DDCB/FDCB combined bit-op + register load ────────────────────────────────

fn decode_ddcb_load(bytes: &[u8], address: u64, idx: &str) -> Option<Z80UndocumentedOpcode> {
    if bytes.len() < 4 {
        return None;
    }
    let disp = i8::from_ne_bytes([bytes[2]]);
    let op = bytes[3];
    let disp_str = if disp >= 0 {
        format!("{idx}+{disp}")
    } else {
        format!("{idx}{disp}")
    };
    let xb = (op >> 6) & 3;
    let yb = (op >> 3) & 7;
    let zb = op & 7;
    if zb == 6 {
        // Standard DDCB — not undocumented if destination is (IX+d)
        return None;
    }
    let dest_reg = match zb {
        0 => "B",
        1 => "C",
        2 => "D",
        3 => "E",
        4 => "H",
        5 => "L",
        7 => "A",
        _ => return None,
    };
    let (mnemonic, operands) = match xb {
        0 => {
            let mn = match yb {
                0 => "RLC",
                1 => "RRC",
                2 => "RL",
                3 => "RR",
                4 => "SLA",
                5 => "SRA",
                6 => "SLL",
                _ => "SRL",
            };
            (mn.to_string(), format!("{dest_reg},({disp_str})"))
        }
        1 => return None, // BIT — no load form
        2 => ("RES".to_string(), format!("{dest_reg},({disp_str}),$yb={yb}")),
        3 => ("SET".to_string(), format!("{dest_reg},({disp_str}),$yb={yb}")),
        _ => return None,
    };
    Some(Z80UndocumentedOpcode {
        address,
        bytes: bytes[..4].to_vec(),
        size: 4,
        mnemonic,
        operands,
        category: UndocInsn::DdCbLoad,
        confidence: 85,
    })
}

// ── ED-prefix undocumented ────────────────────────────────────────────────────

fn decode_ed_undoc(bytes: &[u8], address: u64) -> Option<Z80UndocumentedOpcode> {
    let op = bytes[1];
    match op {
        0x70 => Some(Z80UndocumentedOpcode {
            address,
            bytes: vec![0xED, 0x70],
            size: 2,
            mnemonic: "IN".to_string(),
            operands: "F,(C)".to_string(),
            category: UndocInsn::InFC,
            confidence: 88,
        }),
        0x71 => Some(Z80UndocumentedOpcode {
            address,
            bytes: vec![0xED, 0x71],
            size: 2,
            mnemonic: "OUT".to_string(),
            operands: "(C),0".to_string(),
            category: UndocInsn::OutC0,
            confidence: 88,
        }),
        // ED NOP aliases (0x00..0x3F, 0xA4..0xA7, etc.)
        0x00..=0x3F | 0x80..=0x9F | 0xC0..=0xFF => Some(Z80UndocumentedOpcode {
            address,
            bytes: vec![0xED, op],
            size: 2,
            mnemonic: "NOP".to_string(),
            operands: format!("ED,${op:02X}"),
            category: UndocInsn::NopAlias,
            confidence: 70,
        }),
        _ => None,
    }
}

// ─── Batch scanner ────────────────────────────────────────────────────────────

/// Scan a binary blob for undocumented Z80 instructions.
///
/// Returns all found [`Z80UndocumentedOpcode`]s in order of their address.
///
/// `base_address` is added to each offset to compute the virtual address.
#[must_use]
pub fn scan_for_undocumented(binary: &[u8], base_address: u64) -> Vec<Z80UndocumentedOpcode> {
    let mut results = Vec::new();
    let mut offset = 0usize;
    while offset < binary.len() {
        let remaining = &binary[offset..];
        if let Some(insn) = decode_undocumented(remaining, base_address + offset as u64) {
            offset += insn.size;
            results.push(insn);
        } else {
            offset += 1;
        }
    }
    results
}

/// Returns a summary of how many undocumented instructions were found per category.
#[must_use]
pub fn category_summary(
    insns: &[Z80UndocumentedOpcode],
) -> std::collections::HashMap<String, usize> {
    let mut map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for insn in insns {
        *map.entry(insn.category.description().to_string()).or_default() += 1;
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_undocumented_dd_ixh() {
        // DD 44 = LD B, IXH
        assert!(is_undocumented(&[0xDD, 0x44]));
    }

    #[test]
    fn test_is_undocumented_sll() {
        // CB 30 = SLL B
        assert!(is_undocumented(&[0xCB, 0x30]));
    }

    #[test]
    fn test_is_undocumented_ed70_in_f_c() {
        assert!(is_undocumented(&[0xED, 0x70]));
    }

    #[test]
    fn test_is_undocumented_ed71_out_c_0() {
        assert!(is_undocumented(&[0xED, 0x71]));
    }

    #[test]
    fn test_is_not_undocumented_nop() {
        assert!(!is_undocumented(&[0x00])); // NOP
    }

    #[test]
    fn test_is_not_undocumented_halt() {
        assert!(!is_undocumented(&[0x76])); // HALT
    }

    #[test]
    fn test_decode_ixh_ld_b() {
        let insn = decode_undocumented(&[0xDD, 0x44], 0x1000).unwrap();
        assert_eq!(insn.mnemonic, "LD");
        assert!(insn.operands.contains("IXH"));
        assert_eq!(insn.category, UndocInsn::IxHigh);
        assert_eq!(insn.address, 0x1000);
        assert_eq!(insn.size, 2);
    }

    #[test]
    fn test_decode_ixl_ld_a() {
        let insn = decode_undocumented(&[0xDD, 0x7D], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::IxLow);
        assert!(insn.operands.contains("IXL"));
    }

    #[test]
    fn test_decode_iyh() {
        let insn = decode_undocumented(&[0xFD, 0x44], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::IyHigh);
    }

    #[test]
    fn test_decode_iyl() {
        let insn = decode_undocumented(&[0xFD, 0x45], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::IyLow);
    }

    #[test]
    fn test_decode_sll_b() {
        let insn = decode_undocumented(&[0xCB, 0x30], 0).unwrap();
        assert_eq!(insn.mnemonic, "SLL");
        assert_eq!(insn.operands, "B");
        assert_eq!(insn.category, UndocInsn::Sll);
    }

    #[test]
    fn test_decode_sll_a() {
        let insn = decode_undocumented(&[0xCB, 0x37], 0).unwrap();
        assert_eq!(insn.mnemonic, "SLL");
        assert_eq!(insn.operands, "A");
    }

    #[test]
    fn test_decode_in_f_c() {
        let insn = decode_undocumented(&[0xED, 0x70], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::InFC);
        assert_eq!(insn.mnemonic, "IN");
    }

    #[test]
    fn test_decode_out_c_0() {
        let insn = decode_undocumented(&[0xED, 0x71], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::OutC0);
        assert_eq!(insn.mnemonic, "OUT");
    }

    #[test]
    fn test_decode_nop_alias_ed00() {
        let insn = decode_undocumented(&[0xED, 0x00], 0).unwrap();
        assert_eq!(insn.category, UndocInsn::NopAlias);
    }

    #[test]
    fn test_ddcb_load_rl_b() {
        // DD CB disp RL_into_B: op = 0x10 with z=0
        let bytes = [0xDD, 0xCB, 0x02, 0x10]; // RLC B,(IX+2)
        let insn = decode_undocumented(&bytes, 0x2000);
        assert!(insn.is_some());
        let i = insn.unwrap();
        assert_eq!(i.category, UndocInsn::DdCbLoad);
        assert_eq!(i.size, 4);
    }

    #[test]
    fn test_scan_for_undocumented() {
        // Two undocumented instructions embedded in normal code
        let binary = [
            0x00,       // NOP (normal)
            0xDD, 0x44, // LD B, IXH (undocumented)
            0x76,       // HALT (normal)
            0xCB, 0x30, // SLL B (undocumented)
        ];
        let found = scan_for_undocumented(&binary, 0);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].address, 1);
        assert_eq!(found[1].address, 4);
    }

    #[test]
    fn test_category_summary() {
        let binary = [0xDD, 0x44, 0xDD, 0x45, 0xCB, 0x30];
        let found = scan_for_undocumented(&binary, 0);
        let summary = category_summary(&found);
        assert!(!summary.is_empty());
    }

    #[test]
    fn test_undoc_insn_widely_supported() {
        assert!(UndocInsn::IxHigh.is_widely_supported());
        assert!(UndocInsn::Sll.is_widely_supported());
    }

    #[test]
    fn test_undoc_insn_cmos_only() {
        assert!(UndocInsn::NopAlias.is_cmos_only());
        assert!(!UndocInsn::Sll.is_cmos_only());
    }

    #[test]
    fn test_disassembly_string() {
        let insn = decode_undocumented(&[0xDD, 0x44], 0x1000).unwrap();
        let s = insn.disassembly();
        assert!(s.contains("LD"));
        assert!(s.contains("IXH"));
    }

    #[test]
    fn test_hex_bytes() {
        let insn = decode_undocumented(&[0xDD, 0x44], 0x1000).unwrap();
        assert_eq!(insn.hex_bytes(), "DD 44");
    }

    #[test]
    fn test_display_impl() {
        let insn = decode_undocumented(&[0xCB, 0x30], 0x0100).unwrap();
        let s = format!("{insn}");
        assert!(s.contains("0100"));
        assert!(s.contains("SLL"));
    }

    #[test]
    fn test_empty_slice_returns_none() {
        assert!(decode_undocumented(&[], 0).is_none());
        assert!(!is_undocumented(&[]));
    }

    #[test]
    fn test_truncated_dd_returns_none() {
        assert!(decode_undocumented(&[0xDD], 0).is_none());
    }
}
