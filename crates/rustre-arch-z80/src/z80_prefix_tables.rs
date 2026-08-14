//! Complete Z80 prefix instruction tables: CB, DD, ED, FD, DDCB, FDCB.
//!
//! Provides:
//! - [`decode_cb_prefix`]    — CB-prefix bit/rotate/shift/set/res for all 8 regs
//! - [`decode_dd_prefix`]    — DD-prefix IX register operations with displacement
//! - [`decode_ed_prefix`]    — ED-prefix extended opcodes (I/O, block moves, 16-bit arith, etc.)
//! - [`decode_fd_prefix`]    — FD-prefix IY operations
//! - [`decode_ddcb_prefix`]  — DDCB: IX+d bit operations
//! - [`decode_fdcb_prefix`]  — FDCB: IY+d bit operations
//! - [`decode_z80_prefixed`] — top-level dispatcher

// Re-use the Decoded type from the parent crate
use crate::Decoded;
use rustre_core::arch::InstrFlags;

// ---------------------------------------------------------------------------
// Register / condition name tables
// ---------------------------------------------------------------------------

const REG8: [&str; 8] = ["B", "C", "D", "E", "H", "L", "(HL)", "A"];

#[inline]
fn reg8(r: u8) -> &'static str {
    REG8[(r & 7) as usize]
}

#[inline]
pub fn cc(c: u8) -> &'static str {
    match c & 7 {
        0 => "NZ",
        1 => "Z",
        2 => "NC",
        3 => "C",
        4 => "PO",
        5 => "PE",
        6 => "P",
        _ => "M",
    }
}

// ---------------------------------------------------------------------------
// CB-prefix table: 0xCB 0xNN
// ---------------------------------------------------------------------------

/// Decode a CB-prefixed instruction (2 bytes total).
///
/// `op2` is the byte after `0xCB`.
#[must_use]
pub fn decode_cb_prefix(op2: u8) -> Decoded {
    let x = (op2 >> 6) & 3;
    let y = (op2 >> 3) & 7;
    let z = op2 & 7;
    let reg = reg8(z);
    let (mnemonic, operands) = match x {
        0 => {
            let mn = match y {
                0 => "RLC",
                1 => "RRC",
                2 => "RL",
                3 => "RR",
                4 => "SLA",
                5 => "SRA",
                6 => "SLL",
                _ => "SRL",
            };
            (mn.to_string(), reg.to_string())
        }
        1 => ("BIT".to_string(), format!("{y},{reg}")),
        2 => ("RES".to_string(), format!("{y},{reg}")),
        _ => ("SET".to_string(), format!("{y},{reg}")),
    };
    Decoded {
        mnemonic,
        operands,
        size: 2,
        flags: InstrFlags::NONE,
    }
}

// ---------------------------------------------------------------------------
// Displacement formatting helper
// ---------------------------------------------------------------------------

fn disp_str(idx: &str, d: i8) -> String {
    if d >= 0 {
        format!("{idx}+{d}")
    } else {
        format!("{idx}{d}")
    }
}

// ---------------------------------------------------------------------------
// DD-prefix table: 0xDD 0xNN [0xdd] [0xNN]
// ---------------------------------------------------------------------------

/// Decode a DD-prefixed instruction (IX operations).
///
/// `bytes` starts at the `0xDD` byte.  Returns a decoded instruction.
#[must_use]
pub fn decode_dd_prefix(bytes: &[u8]) -> Decoded {
    decode_index_prefix(bytes, "IX")
}

/// Decode an FD-prefixed instruction (IY operations).
///
/// `bytes` starts at the `0xFD` byte.
#[must_use]
pub fn decode_fd_prefix(bytes: &[u8]) -> Decoded {
    decode_index_prefix(bytes, "IY")
}

fn decode_index_prefix(bytes: &[u8], idx: &str) -> Decoded {
    let op2 = if bytes.len() >= 2 { bytes[1] } else { 0 };
    let disp_raw = if bytes.len() >= 3 {
        bytes[2] as i8
    } else {
        0i8
    };
    let disp = disp_str(idx, disp_raw);

    let (mnemonic, operands, size, flags) = match op2 {
        0x09 => ("ADD".into(), format!("{idx},BC"), 2, InstrFlags::NONE),
        0x19 => ("ADD".into(), format!("{idx},DE"), 2, InstrFlags::NONE),
        0x21 => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".into(),
                format!("{idx},#${nn:04X}"),
                4,
                InstrFlags::NONE,
            )
        }
        0x22 => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".into(),
                format!("(${nn:04X}),{idx}"),
                4,
                InstrFlags::WRITE_MEM,
            )
        }
        0x23 => ("INC".into(), idx.into(), 2, InstrFlags::NONE),
        0x24 => (format!("INC {idx}H"), String::new(), 2, InstrFlags::NONE),
        0x25 => (format!("DEC {idx}H"), String::new(), 2, InstrFlags::NONE),
        0x26 => {
            let n = if bytes.len() >= 3 { bytes[2] } else { 0 };
            (
                "LD".into(),
                format!("{idx}H,#${n:02X}"),
                3,
                InstrFlags::NONE,
            )
        }
        0x29 => ("ADD".into(), format!("{idx},{idx}"), 2, InstrFlags::NONE),
        0x2A => {
            let nn = if bytes.len() >= 4 {
                u16::from_le_bytes([bytes[2], bytes[3]])
            } else {
                0
            };
            (
                "LD".into(),
                format!("{idx},(${nn:04X})"),
                4,
                InstrFlags::READ_MEM,
            )
        }
        0x2B => ("DEC".into(), idx.into(), 2, InstrFlags::NONE),
        0x2C => (format!("INC {idx}L"), String::new(), 2, InstrFlags::NONE),
        0x2D => (format!("DEC {idx}L"), String::new(), 2, InstrFlags::NONE),
        0x2E => {
            let n = if bytes.len() >= 3 { bytes[2] } else { 0 };
            (
                "LD".into(),
                format!("{idx}L,#${n:02X}"),
                3,
                InstrFlags::NONE,
            )
        }
        0x34 => (
            "INC".into(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0x35 => (
            "DEC".into(),
            format!("({disp})"),
            3,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0x36 => {
            let n = if bytes.len() >= 4 { bytes[3] } else { 0 };
            (
                "LD".into(),
                format!("({disp}),${n:02X}"),
                4,
                InstrFlags::WRITE_MEM,
            )
        }
        0x39 => ("ADD".into(), format!("{idx},SP"), 2, InstrFlags::NONE),
        // LD r,(IX+d)
        0x46 => ("LD".into(), format!("B,({disp})"), 3, InstrFlags::READ_MEM),
        0x4E => ("LD".into(), format!("C,({disp})"), 3, InstrFlags::READ_MEM),
        0x56 => ("LD".into(), format!("D,({disp})"), 3, InstrFlags::READ_MEM),
        0x5E => ("LD".into(), format!("E,({disp})"), 3, InstrFlags::READ_MEM),
        0x66 => ("LD".into(), format!("H,({disp})"), 3, InstrFlags::READ_MEM),
        0x6E => ("LD".into(), format!("L,({disp})"), 3, InstrFlags::READ_MEM),
        0x7E => ("LD".into(), format!("A,({disp})"), 3, InstrFlags::READ_MEM),
        // LD (IX+d),r
        0x70 => ("LD".into(), format!("({disp}),B"), 3, InstrFlags::WRITE_MEM),
        0x71 => ("LD".into(), format!("({disp}),C"), 3, InstrFlags::WRITE_MEM),
        0x72 => ("LD".into(), format!("({disp}),D"), 3, InstrFlags::WRITE_MEM),
        0x73 => ("LD".into(), format!("({disp}),E"), 3, InstrFlags::WRITE_MEM),
        0x74 => ("LD".into(), format!("({disp}),H"), 3, InstrFlags::WRITE_MEM),
        0x75 => ("LD".into(), format!("({disp}),L"), 3, InstrFlags::WRITE_MEM),
        0x77 => ("LD".into(), format!("({disp}),A"), 3, InstrFlags::WRITE_MEM),
        // ALU A,(IX+d)
        0x86 => ("ADD".into(), format!("A,({disp})"), 3, InstrFlags::READ_MEM),
        0x8E => ("ADC".into(), format!("A,({disp})"), 3, InstrFlags::READ_MEM),
        0x96 => ("SUB".into(), format!("({disp})"), 3, InstrFlags::READ_MEM),
        0x9E => ("SBC".into(), format!("A,({disp})"), 3, InstrFlags::READ_MEM),
        0xA6 => ("AND".into(), format!("({disp})"), 3, InstrFlags::READ_MEM),
        0xAE => ("XOR".into(), format!("({disp})"), 3, InstrFlags::READ_MEM),
        0xB6 => ("OR".into(), format!("({disp})"), 3, InstrFlags::READ_MEM),
        0xBE => ("CP".into(), format!("({disp})"), 3, InstrFlags::READ_MEM),
        // Stack
        0xE1 => ("POP".into(), idx.into(), 2, InstrFlags::READ_MEM),
        0xE3 => (
            "EX".into(),
            format!("(SP),{idx}"),
            2,
            InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
        ),
        0xE5 => ("PUSH".into(), idx.into(), 2, InstrFlags::WRITE_MEM),
        0xE9 => (
            "JP".into(),
            format!("({idx})"),
            2,
            InstrFlags::BRANCH.union(InstrFlags::INDIRECT),
        ),
        0xF9 => ("LD".into(), format!("SP,{idx}"), 2, InstrFlags::NONE),
        // DDCB/FDCB sub-dispatch
        0xCB => return decode_ddcb_or_fdcb(bytes, idx),
        _ => ("DB".into(), format!("${op2:02X}"), 2, InstrFlags::NONE),
    };
    Decoded {
        mnemonic,
        operands,
        size,
        flags,
    }
}

// ---------------------------------------------------------------------------
// DDCB / FDCB prefix: DD CB <disp> <op>  or  FD CB <disp> <op>
// ---------------------------------------------------------------------------

/// Decode a DDCB-prefixed instruction: `0xDD 0xCB <disp> <op>`.
#[must_use]
pub fn decode_ddcb_prefix(bytes: &[u8]) -> Decoded {
    decode_ddcb_or_fdcb(bytes, "IX")
}

/// Decode an FDCB-prefixed instruction: `0xFD 0xCB <disp> <op>`.
#[must_use]
pub fn decode_fdcb_prefix(bytes: &[u8]) -> Decoded {
    decode_ddcb_or_fdcb(bytes, "IY")
}

fn decode_ddcb_or_fdcb(bytes: &[u8], idx: &str) -> Decoded {
    // Format: [prefix] [CB] [disp] [op]  → bytes[0]=prefix, bytes[1]=CB, bytes[2]=disp, bytes[3]=op
    let disp_raw = if bytes.len() >= 3 {
        bytes[2] as i8
    } else {
        0i8
    };
    let op = if bytes.len() >= 4 { bytes[3] } else { 0 };
    let disp = disp_str(idx, disp_raw);

    let x = (op >> 6) & 3;
    let y = (op >> 3) & 7;
    let z = op & 7;

    let (mnemonic, operands) = match x {
        0 => {
            let mn = match y {
                0 => "RLC",
                1 => "RRC",
                2 => "RL",
                3 => "RR",
                4 => "SLA",
                5 => "SRA",
                6 => "SLL",
                _ => "SRL",
            };
            if z == 6 {
                (mn.to_string(), format!("({disp})"))
            } else {
                (mn.to_string(), format!("({disp}),{}", reg8(z)))
            }
        }
        1 => ("BIT".to_string(), format!("{y},({disp})")),
        2 => {
            if z == 6 {
                ("RES".to_string(), format!("{y},({disp})"))
            } else {
                ("RES".to_string(), format!("{y},({disp}),{}", reg8(z)))
            }
        }
        _ => {
            if z == 6 {
                ("SET".to_string(), format!("{y},({disp})"))
            } else {
                ("SET".to_string(), format!("{y},({disp}),{}", reg8(z)))
            }
        }
    };
    Decoded {
        mnemonic,
        operands,
        size: 4,
        flags: InstrFlags::READ_MEM.union(InstrFlags::WRITE_MEM),
    }
}

// ---------------------------------------------------------------------------
// ED-prefix table: 0xED 0xNN [...]
// ---------------------------------------------------------------------------

/// Decode an ED-prefixed instruction.
///
/// `bytes` starts at the `0xED` byte.
#[must_use]
pub fn decode_ed_prefix(bytes: &[u8]) -> Decoded {
    let op2 = if bytes.len() >= 2 { bytes[1] } else { 0 };
    let mut size = 2usize;

    let addr_at = |off: usize| -> u16 {
        if bytes.len() >= off + 2 {
            u16::from_le_bytes([bytes[off], bytes[off + 1]])
        } else {
            0
        }
    };

    let (mnemonic, operands, flags) = match op2 {
        // IN r,(C)
        0x40 => ("IN".into(), "B,(C)".into(), InstrFlags::NONE),
        0x48 => ("IN".into(), "C,(C)".into(), InstrFlags::NONE),
        0x50 => ("IN".into(), "D,(C)".into(), InstrFlags::NONE),
        0x58 => ("IN".into(), "E,(C)".into(), InstrFlags::NONE),
        0x60 => ("IN".into(), "H,(C)".into(), InstrFlags::NONE),
        0x68 => ("IN".into(), "L,(C)".into(), InstrFlags::NONE),
        0x70 => ("IN".into(), "F,(C)".into(), InstrFlags::NONE),
        0x78 => ("IN".into(), "A,(C)".into(), InstrFlags::NONE),
        // OUT (C),r
        0x41 => ("OUT".into(), "(C),B".into(), InstrFlags::NONE),
        0x49 => ("OUT".into(), "(C),C".into(), InstrFlags::NONE),
        0x51 => ("OUT".into(), "(C),D".into(), InstrFlags::NONE),
        0x59 => ("OUT".into(), "(C),E".into(), InstrFlags::NONE),
        0x61 => ("OUT".into(), "(C),H".into(), InstrFlags::NONE),
        0x69 => ("OUT".into(), "(C),L".into(), InstrFlags::NONE),
        0x71 => ("OUT".into(), "(C),0".into(), InstrFlags::NONE),
        0x79 => ("OUT".into(), "(C),A".into(), InstrFlags::NONE),
        // SBC/ADC HL,rp
        0x42 => ("SBC".into(), "HL,BC".into(), InstrFlags::NONE),
        0x52 => ("SBC".into(), "HL,DE".into(), InstrFlags::NONE),
        0x62 => ("SBC".into(), "HL,HL".into(), InstrFlags::NONE),
        0x72 => ("SBC".into(), "HL,SP".into(), InstrFlags::NONE),
        0x4A => ("ADC".into(), "HL,BC".into(), InstrFlags::NONE),
        0x5A => ("ADC".into(), "HL,DE".into(), InstrFlags::NONE),
        0x6A => ("ADC".into(), "HL,HL".into(), InstrFlags::NONE),
        0x7A => ("ADC".into(), "HL,SP".into(), InstrFlags::NONE),
        // LD (nn),rp
        0x43 => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("(${a:04X}),BC"), InstrFlags::WRITE_MEM)
        }
        0x53 => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("(${a:04X}),DE"), InstrFlags::WRITE_MEM)
        }
        0x63 => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("(${a:04X}),HL"), InstrFlags::WRITE_MEM)
        }
        0x73 => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("(${a:04X}),SP"), InstrFlags::WRITE_MEM)
        }
        // LD rp,(nn)
        0x4B => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("BC,(${a:04X})"), InstrFlags::READ_MEM)
        }
        0x5B => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("DE,(${a:04X})"), InstrFlags::READ_MEM)
        }
        0x6B => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("HL,(${a:04X})"), InstrFlags::READ_MEM)
        }
        0x7B => {
            size = 4;
            let a = addr_at(2);
            ("LD".into(), format!("SP,(${a:04X})"), InstrFlags::READ_MEM)
        }
        // NEG / RETN / RETI / IM
        0x44 | 0x4C | 0x54 | 0x5C | 0x64 | 0x6C | 0x74 | 0x7C => {
            ("NEG".into(), String::new(), InstrFlags::NONE)
        }
        0x45 | 0x55 | 0x5D | 0x65 | 0x6D | 0x75 | 0x7D => {
            ("RETN".into(), String::new(), InstrFlags::RET)
        }
        0x4D => ("RETI".into(), String::new(), InstrFlags::RET),
        0x46 | 0x66 => ("IM".into(), "0".into(), InstrFlags::NONE),
        0x56 | 0x76 => ("IM".into(), "1".into(), InstrFlags::NONE),
        0x5E | 0x7E => ("IM".into(), "2".into(), InstrFlags::NONE),
        // LD I/R
        0x47 => ("LD".into(), "I,A".into(), InstrFlags::NONE),
        0x4F => ("LD".into(), "R,A".into(), InstrFlags::NONE),
        0x57 => ("LD".into(), "A,I".into(), InstrFlags::NONE),
        0x5F => ("LD".into(), "A,R".into(), InstrFlags::NONE),
        // RLD / RRD
        0x6F => ("RLD".into(), String::new(), InstrFlags::NONE),
        0x67 => ("RRD".into(), String::new(), InstrFlags::NONE),
        // Block moves / searches
        0xA0 => ("LDI".into(), String::new(), InstrFlags::NONE),
        0xA8 => ("LDD".into(), String::new(), InstrFlags::NONE),
        0xB0 => ("LDIR".into(), String::new(), InstrFlags::NONE),
        0xB8 => ("LDDR".into(), String::new(), InstrFlags::NONE),
        0xA1 => ("CPI".into(), String::new(), InstrFlags::NONE),
        0xA9 => ("CPD".into(), String::new(), InstrFlags::NONE),
        0xB1 => ("CPIR".into(), String::new(), InstrFlags::NONE),
        0xB9 => ("CPDR".into(), String::new(), InstrFlags::NONE),
        // Block I/O
        0xA2 => ("INI".into(), String::new(), InstrFlags::NONE),
        0xAA => ("IND".into(), String::new(), InstrFlags::NONE),
        0xB2 => ("INIR".into(), String::new(), InstrFlags::NONE),
        0xBA => ("INDR".into(), String::new(), InstrFlags::NONE),
        0xA3 => ("OUTI".into(), String::new(), InstrFlags::NONE),
        0xAB => ("OUTD".into(), String::new(), InstrFlags::NONE),
        0xB3 => ("OTIR".into(), String::new(), InstrFlags::NONE),
        0xBB => ("OTDR".into(), String::new(), InstrFlags::NONE),
        _ => ("DB".into(), format!("ED,${op2:02X}"), InstrFlags::NONE),
    };
    Decoded {
        mnemonic,
        operands,
        size,
        flags,
    }
}

// ---------------------------------------------------------------------------
// Top-level dispatcher
// ---------------------------------------------------------------------------

/// Decode errors for the prefix decoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrefixDecodeError {
    /// Not enough bytes.
    Truncated,
    /// The first byte is not a recognised prefix (`CB`/`DD`/`ED`/`FD`).
    NotAPrefixByte(u8),
}

impl std::fmt::Display for PrefixDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated Z80 prefixed instruction"),
            Self::NotAPrefixByte(b) => write!(f, "byte 0x{b:02X} is not a Z80 prefix"),
        }
    }
}

impl std::error::Error for PrefixDecodeError {}

/// Decode a Z80 prefixed instruction from the given byte slice.
///
/// The first byte must be `0xCB`, `0xDD`, `0xED`, or `0xFD`.
///
/// # Errors
/// Returns [`PrefixDecodeError::Truncated`] for short slices and
/// [`PrefixDecodeError::NotAPrefixByte`] for non-prefix first bytes.
pub fn decode_z80_prefixed(bytes: &[u8]) -> Result<Decoded, PrefixDecodeError> {
    if bytes.is_empty() {
        return Err(PrefixDecodeError::Truncated);
    }
    match bytes[0] {
        0xCB => {
            if bytes.len() < 2 {
                return Err(PrefixDecodeError::Truncated);
            }
            Ok(decode_cb_prefix(bytes[1]))
        }
        0xDD => {
            if bytes.len() < 2 {
                return Err(PrefixDecodeError::Truncated);
            }
            Ok(decode_dd_prefix(bytes))
        }
        0xED => {
            if bytes.len() < 2 {
                return Err(PrefixDecodeError::Truncated);
            }
            Ok(decode_ed_prefix(bytes))
        }
        0xFD => {
            if bytes.len() < 2 {
                return Err(PrefixDecodeError::Truncated);
            }
            Ok(decode_fd_prefix(bytes))
        }
        b => Err(PrefixDecodeError::NotAPrefixByte(b)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CB prefix ---

    #[test]
    fn test_cb_rlc_b() {
        let d = decode_cb_prefix(0x00);
        assert_eq!(d.mnemonic, "RLC");
        assert_eq!(d.operands, "B");
        assert_eq!(d.size, 2);
    }

    #[test]
    fn test_cb_rrc_c() {
        let d = decode_cb_prefix(0x09);
        assert_eq!(d.mnemonic, "RRC");
        assert_eq!(d.operands, "C");
    }

    #[test]
    fn test_cb_rl_hl() {
        let d = decode_cb_prefix(0x16);
        assert_eq!(d.mnemonic, "RL");
        assert_eq!(d.operands, "(HL)");
    }

    #[test]
    fn test_cb_bit_3_e() {
        let d = decode_cb_prefix(0x5B); // BIT 3,E → x=1, y=3, z=3
        assert_eq!(d.mnemonic, "BIT");
        assert!(d.operands.contains('3'));
        assert!(d.operands.contains('E'));
    }

    #[test]
    fn test_cb_res_7_a() {
        let d = decode_cb_prefix(0xBF); // RES 7,A → x=2, y=7, z=7
        assert_eq!(d.mnemonic, "RES");
        assert!(d.operands.contains('7'));
        assert!(d.operands.contains('A'));
    }

    #[test]
    fn test_cb_set_0_b() {
        let d = decode_cb_prefix(0xC0); // SET 0,B
        assert_eq!(d.mnemonic, "SET");
        assert!(d.operands.contains('0'));
        assert!(d.operands.contains('B'));
    }

    #[test]
    fn test_cb_sla_d() {
        let d = decode_cb_prefix(0x22); // SLA D → x=0, y=4, z=2
        assert_eq!(d.mnemonic, "SLA");
        assert_eq!(d.operands, "D");
    }

    #[test]
    fn test_cb_srl_h() {
        let d = decode_cb_prefix(0x3C); // SRL H → x=0, y=7, z=4
        assert_eq!(d.mnemonic, "SRL");
    }

    // --- DD prefix ---

    #[test]
    fn test_dd_add_ix_bc() {
        let d = decode_dd_prefix(&[0xDD, 0x09]);
        assert_eq!(d.mnemonic, "ADD");
        assert_eq!(d.operands, "IX,BC");
    }

    #[test]
    fn test_dd_ld_ix_imm() {
        let d = decode_dd_prefix(&[0xDD, 0x21, 0x34, 0x12]);
        assert_eq!(d.mnemonic, "LD");
        assert_eq!(d.operands, "IX,#$1234");
        assert_eq!(d.size, 4);
    }

    #[test]
    fn test_dd_ld_b_ix_disp() {
        // LD B,(IX+5)
        let d = decode_dd_prefix(&[0xDD, 0x46, 0x05]);
        assert_eq!(d.mnemonic, "LD");
        assert!(d.operands.contains("IX+5"));
        assert!(d.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_dd_ld_ix_disp_a() {
        // LD (IX-2),A
        let d = decode_dd_prefix(&[0xDD, 0x77, 0xFE]); // 0xFE as i8 = -2
        assert_eq!(d.mnemonic, "LD");
        assert!(d.operands.contains("IX-2"));
        assert!(d.flags.contains(InstrFlags::WRITE_MEM));
    }

    #[test]
    fn test_dd_jp_ix() {
        let d = decode_dd_prefix(&[0xDD, 0xE9]);
        assert_eq!(d.mnemonic, "JP");
        assert!(d.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_dd_push_pop_ix() {
        let push = decode_dd_prefix(&[0xDD, 0xE5]);
        assert_eq!(push.mnemonic, "PUSH");
        let pop = decode_dd_prefix(&[0xDD, 0xE1]);
        assert_eq!(pop.mnemonic, "POP");
    }

    // --- FD prefix ---

    #[test]
    fn test_fd_add_iy_de() {
        let d = decode_fd_prefix(&[0xFD, 0x19]);
        assert_eq!(d.mnemonic, "ADD");
        assert_eq!(d.operands, "IY,DE");
    }

    #[test]
    fn test_fd_ld_iy_imm() {
        let d = decode_fd_prefix(&[0xFD, 0x21, 0x00, 0x10]);
        assert_eq!(d.mnemonic, "LD");
        assert_eq!(d.operands, "IY,#$1000");
    }

    #[test]
    fn test_fd_ld_l_iy_disp() {
        let d = decode_fd_prefix(&[0xFD, 0x6E, 0x03]);
        assert_eq!(d.mnemonic, "LD");
        assert!(d.operands.contains("IY+3"));
    }

    // --- ED prefix ---

    #[test]
    fn test_ed_in_b_c() {
        let d = decode_ed_prefix(&[0xED, 0x40]);
        assert_eq!(d.mnemonic, "IN");
        assert_eq!(d.operands, "B,(C)");
    }

    #[test]
    fn test_ed_out_c_a() {
        let d = decode_ed_prefix(&[0xED, 0x79]);
        assert_eq!(d.mnemonic, "OUT");
        assert_eq!(d.operands, "(C),A");
    }

    #[test]
    fn test_ed_sbc_hl_de() {
        let d = decode_ed_prefix(&[0xED, 0x52]);
        assert_eq!(d.mnemonic, "SBC");
        assert_eq!(d.operands, "HL,DE");
    }

    #[test]
    fn test_ed_adc_hl_sp() {
        let d = decode_ed_prefix(&[0xED, 0x7A]);
        assert_eq!(d.mnemonic, "ADC");
        assert_eq!(d.operands, "HL,SP");
    }

    #[test]
    fn test_ed_ld_nn_bc() {
        let d = decode_ed_prefix(&[0xED, 0x43, 0x00, 0x10]);
        assert_eq!(d.mnemonic, "LD");
        assert_eq!(d.operands, "($1000),BC");
        assert_eq!(d.size, 4);
    }

    #[test]
    fn test_ed_ld_hl_nn() {
        let d = decode_ed_prefix(&[0xED, 0x6B, 0x50, 0x00]);
        assert_eq!(d.mnemonic, "LD");
        assert_eq!(d.operands, "HL,($0050)");
        assert!(d.flags.contains(InstrFlags::READ_MEM));
    }

    #[test]
    fn test_ed_neg() {
        let d = decode_ed_prefix(&[0xED, 0x44]);
        assert_eq!(d.mnemonic, "NEG");
    }

    #[test]
    fn test_ed_reti() {
        let d = decode_ed_prefix(&[0xED, 0x4D]);
        assert_eq!(d.mnemonic, "RETI");
        assert!(d.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_ed_im0_im1_im2() {
        assert_eq!(decode_ed_prefix(&[0xED, 0x46]).mnemonic, "IM");
        assert_eq!(decode_ed_prefix(&[0xED, 0x56]).operands, "1");
        assert_eq!(decode_ed_prefix(&[0xED, 0x5E]).operands, "2");
    }

    #[test]
    fn test_ed_ldi_ldir() {
        let d = decode_ed_prefix(&[0xED, 0xA0]);
        assert_eq!(d.mnemonic, "LDI");
        let d2 = decode_ed_prefix(&[0xED, 0xB0]);
        assert_eq!(d2.mnemonic, "LDIR");
    }

    #[test]
    fn test_ed_ldd_lddr() {
        assert_eq!(decode_ed_prefix(&[0xED, 0xA8]).mnemonic, "LDD");
        assert_eq!(decode_ed_prefix(&[0xED, 0xB8]).mnemonic, "LDDR");
    }

    #[test]
    fn test_ed_cpir_cpdr() {
        assert_eq!(decode_ed_prefix(&[0xED, 0xB1]).mnemonic, "CPIR");
        assert_eq!(decode_ed_prefix(&[0xED, 0xB9]).mnemonic, "CPDR");
    }

    // --- DDCB / FDCB prefix ---

    #[test]
    fn test_ddcb_rlc_ix_d() {
        let d = decode_ddcb_prefix(&[0xDD, 0xCB, 0x02, 0x06]); // RLC (IX+2)
        assert_eq!(d.mnemonic, "RLC");
        assert!(d.operands.contains("IX+2"));
        assert_eq!(d.size, 4);
    }

    #[test]
    fn test_ddcb_bit_3_ix_d() {
        let d = decode_ddcb_prefix(&[0xDD, 0xCB, 0x05, 0x5E]); // BIT 3,(IX+5) → x=1,y=3,z=6
        assert_eq!(d.mnemonic, "BIT");
        assert!(d.operands.contains("IX+5"));
    }

    #[test]
    fn test_ddcb_set_0_ix_d() {
        let d = decode_ddcb_prefix(&[0xDD, 0xCB, 0x00, 0xC6]); // SET 0,(IX+0) → x=3,y=0,z=6
        assert_eq!(d.mnemonic, "SET");
        assert!(d.operands.contains("IX"));
    }

    #[test]
    fn test_fdcb_res_7_iy_d() {
        let d = decode_fdcb_prefix(&[0xFD, 0xCB, 0x03, 0xBE]); // RES 7,(IY+3) → x=2,y=7,z=6
        assert_eq!(d.mnemonic, "RES");
        assert!(d.operands.contains("IY+3"));
    }

    // --- Top-level dispatcher ---

    #[test]
    fn test_decode_z80_prefixed_cb() {
        let d = decode_z80_prefixed(&[0xCB, 0x00]).unwrap();
        assert_eq!(d.mnemonic, "RLC");
    }

    #[test]
    fn test_decode_z80_prefixed_dd() {
        let d = decode_z80_prefixed(&[0xDD, 0x09]).unwrap();
        assert_eq!(d.mnemonic, "ADD");
    }

    #[test]
    fn test_decode_z80_prefixed_ed() {
        let d = decode_z80_prefixed(&[0xED, 0x44]).unwrap();
        assert_eq!(d.mnemonic, "NEG");
    }

    #[test]
    fn test_decode_z80_prefixed_fd() {
        let d = decode_z80_prefixed(&[0xFD, 0x19]).unwrap();
        assert_eq!(d.mnemonic, "ADD");
    }

    #[test]
    fn test_decode_z80_prefixed_truncated() {
        let err = decode_z80_prefixed(&[0xCB]).unwrap_err();
        assert_eq!(err, PrefixDecodeError::Truncated);
    }

    #[test]
    fn test_decode_z80_prefixed_empty() {
        let err = decode_z80_prefixed(&[]).unwrap_err();
        assert_eq!(err, PrefixDecodeError::Truncated);
    }

    #[test]
    fn test_decode_z80_prefixed_not_prefix() {
        let err = decode_z80_prefixed(&[0x00]).unwrap_err();
        assert_eq!(err, PrefixDecodeError::NotAPrefixByte(0x00));
    }
}
